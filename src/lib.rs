use std::time::Duration;

use bytes::Bytes;
use iroh::PublicKey;

type Entry = (PublicKey, Bytes, SignedValue);

pub mod proto {
    //! Gossip protocol messages and helpers
    use std::time::SystemTime;

    use bytes::Bytes;
    use iroh::PublicKey;
    use serde::{Deserialize, Serialize};
    use serde_big_array::BigArray;

    use crate::util::{DD, from_nanos};
    #[derive(Clone, Serialize, Deserialize)]
    pub struct SignedValue {
        /// Timestamp in nanoseconds since epoch
        pub timestamp: u64,
        /// The actual value
        pub value: Bytes,
        /// Signature over (key, timestamp, value)
        #[serde(with = "BigArray")]
        pub signature: [u8; 64],
    }

    impl std::fmt::Debug for SignedValue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("SignedValue")
                .field(&self.timestamp)
                .field(&self.value)
                .field(&DD(hex::encode(self.signature)))
                .finish()
        }
    }

    impl SignedValue {
        pub fn system_time(&self) -> SystemTime {
            from_nanos(self.timestamp)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum GossipMessage {
        SignedValue(PublicKey, Bytes, SignedValue),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub(crate) struct SigningData<'a> {
        pub key: &'a [u8],
        pub timestamp: u64,
        pub value: &'a [u8],
    }
}

use proto::{GossipMessage, SignedValue};

pub mod api {
    //! API to interact with the gossip-based key-value store.
    use std::{
        collections::HashSet,
        ops::{Bound, RangeBounds},
        time::{Duration, SystemTime},
    };

    use bytes::{Bytes, BytesMut};
    use iroh::{NodeId, PublicKey, SecretKey};
    use iroh_gossip::api::{Event, GossipReceiver, GossipSender, GossipTopic};
    use irpc::{
        channel::{mpsc, oneshot},
        rpc_requests,
    };
    use n0_future::{FuturesUnordered, StreamExt, TryFutureExt, TryStreamExt, boxed::BoxFuture};
    use rand::seq::SliceRandom;
    use serde::{Deserialize, Serialize};
    use snafu::Snafu;
    use tokio::sync::broadcast;
    use tracing::{error, trace};

    pub use crate::proto::SignedValue;
    use crate::{
        Config, Entry, GossipMessage,
        proto::SigningData,
        util::{current_timestamp, next_prefix, postcard_ser, to_nanos},
    };

    #[derive(Debug, Snafu)]
    #[snafu(visibility(pub(crate)))]
    #[snafu(module)]
    pub enum InsertError {
        #[snafu(transparent)]
        Signature {
            source: ed25519_dalek::SignatureError,
        },
        #[snafu(display("Value too old: existing timestamp {}, new timestamp {}", old, new))]
        ValueTooOld { old: u64, new: u64 },
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Put {
        pub scope: PublicKey,
        pub key: Bytes,
        pub value: SignedValue,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Get {
        pub scope: PublicKey,
        pub key: Bytes,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub enum SubscribeMode {
        /// Only send current values that match the filter
        Current,
        /// Send future values that match the filter
        Future,
        /// Send both current and future values that match the filter
        Both,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum SubscribeItem {
        /// A matching entry (scope, key, value)
        Entry(Entry),
        /// Marker that all current entries have been sent, and future entries will follow.
        ///
        /// You will get at most one CurrentDone message per subscription.
        CurrentDone,
        /// An entry that has expired (removed). The u64 is the timestamp when it was last modified.
        Expired((PublicKey, Bytes, u64)),
    }

    #[derive(Clone)]
    pub enum BroadcastItem {
        /// A matching entry (scope, key, value)
        Entry(Entry),
        /// An entry that has expired (removed)
        Expired((PublicKey, Bytes, u64)),
    }

    impl From<BroadcastItem> for SubscribeItem {
        fn from(item: BroadcastItem) -> Self {
            match item {
                BroadcastItem::Entry(entry) => SubscribeItem::Entry(entry),
                BroadcastItem::Expired(entry) => SubscribeItem::Expired(entry),
            }
        }
    }

    impl BroadcastItem {
        fn contained_in(&self, filter: &crate::api::Filter) -> bool {
            match self {
                BroadcastItem::Entry((scope, key, value)) => {
                    filter.contains(scope, key, value.timestamp)
                }
                BroadcastItem::Expired((scope, key, _)) => filter.contains_key(scope, key),
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Subscribe {
        pub mode: SubscribeMode,
        pub filter: Filter,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct JoinPeers {
        pub peers: Vec<NodeId>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[rpc_requests(message = Message)]
    enum Proto {
        #[rpc(tx = oneshot::Sender<()>)]
        Put(Put),
        #[rpc(tx = oneshot::Sender<Option<SignedValue>>)]
        Get(Get),
        #[rpc(tx = mpsc::Sender<SubscribeItem>)]
        Subscribe(Subscribe),
        #[rpc(tx = oneshot::Sender<()>)]
        JoinPeers(JoinPeers),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Filter {
        /// None means no filtering by scope
        pub scope: Option<HashSet<PublicKey>>,
        /// Range of keys to include
        pub key: (Bound<Bytes>, Bound<Bytes>),
        /// Range of timestamps (in nanoseconds since epoch) to include
        pub timestamp: (Bound<u64>, Bound<u64>),
    }

    impl Filter {
        pub const ALL: Self = Self {
            scope: None,
            key: (Bound::Unbounded, Bound::Unbounded),
            timestamp: (Bound::Unbounded, Bound::Unbounded),
        };
        pub const EMPTY: Self = Self {
            scope: None,
            key: (Bound::Unbounded, Bound::Excluded(Bytes::new())),
            timestamp: (Bound::Unbounded, Bound::Excluded(0)),
        };
        /// Sets the scope filter to a single public key.
        pub fn scope(self, scope: PublicKey) -> Self {
            self.scopes(Some(scope))
        }
        /// Sets the scope filter to a set of public keys.
        pub fn scopes(self, scope: impl IntoIterator<Item = PublicKey>) -> Self {
            let scope = scope.into_iter().collect();
            Self {
                scope: Some(scope),
                key: self.key,
                timestamp: self.timestamp,
            }
        }
        /// Sets the key filter to a single key.
        pub fn key(self, key: impl Into<Bytes>) -> Self {
            let key = key.into();
            Self {
                scope: self.scope,
                key: (Bound::Included(key.clone()), Bound::Included(key)),
                timestamp: self.timestamp,
            }
        }
        /// Sets the key filter to a range of keys.
        pub fn keys<I, V>(self, range: I) -> Self
        where
            I: RangeBounds<V>,
            V: Clone + Into<Bytes>,
        {
            let start = range.start_bound().map(|x| x.clone().into());
            let end = range.end_bound().map(|x| x.clone().into());
            Self {
                scope: self.scope,
                key: (start, end),
                timestamp: self.timestamp,
            }
        }
        /// Sets the key filter to all keys with the given prefix.
        pub fn key_prefix(self, prefix: impl Into<Bytes>) -> Self {
            let prefix = prefix.into();
            let mut end = prefix.to_vec();
            let start = Bound::Included(prefix);
            let end = if next_prefix(&mut end) {
                Bound::Excluded(end.into())
            } else {
                Bound::Unbounded
            };
            Self {
                scope: self.scope,
                key: (start, end),
                timestamp: self.timestamp,
            }
        }
        /// Sets the timestamp filter to a range of system times.
        pub fn timestamps(self, range: impl RangeBounds<SystemTime>) -> Self {
            let start = range.start_bound().map(to_nanos);
            let end = range.end_bound().map(to_nanos);
            Self {
                scope: self.scope,
                key: self.key,
                timestamp: (start, end),
            }
        }
        /// Checks if the given entry matches the filter.
        pub fn contains(&self, scope: &PublicKey, key: &[u8], timestamp: u64) -> bool {
            self.contains_key(scope, key) && self.timestamp.contains(&timestamp)
        }

        /// Checks if the given scope and key match the filter, excluding timestamp.
        pub fn contains_key(&self, scope: &PublicKey, key: &[u8]) -> bool {
            if let Some(scopes) = &self.scope
                && !scopes.contains(scope)
            {
                return false;
            }
            self.key.contains(key)
        }
    }

    pub struct IterResult(BoxFuture<Result<mpsc::Receiver<SubscribeItem>, irpc::Error>>);

    impl IterResult {
        pub async fn collect<C: Default + Extend<(PublicKey, Bytes, Bytes)>>(
            self,
        ) -> Result<C, irpc::Error> {
            let mut rx = self.0.await?;
            let mut items = C::default();
            while let Some(SubscribeItem::Entry((scope, key, value))) = rx.recv().await? {
                items.extend(Some((scope, key, value.value)));
            }
            Ok(items)
        }
    }

    pub struct SubscribeResult(BoxFuture<Result<mpsc::Receiver<SubscribeItem>, irpc::Error>>);

    impl SubscribeResult {
        /// Stream of entries from the subscription, as raw SubscribeResponse values.
        pub fn stream_raw(
            self,
        ) -> impl n0_future::Stream<Item = Result<SubscribeItem, irpc::Error>> + Send + 'static
        {
            async move {
                let rx = self.0.await?;
                Ok(rx.into_stream().map_err(irpc::Error::from))
            }
            .try_flatten_stream()
        }

        /// Stream of entries from the subscription, without distinguishing current vs future.
        pub fn stream(
            self,
        ) -> impl n0_future::Stream<Item = Result<Entry, irpc::Error>> + Send + 'static {
            async move {
                let rx = self.0.await?;
                Ok(rx
                    .into_stream()
                    .try_filter_map(|res| async move {
                        match res {
                            SubscribeItem::Entry(entry) => Ok(Some(entry)),
                            SubscribeItem::Expired((_, _, _)) => Ok(None),
                            SubscribeItem::CurrentDone => Ok(None),
                        }
                    })
                    .map_err(irpc::Error::from))
            }
            .try_flatten_stream()
        }
    }

    #[derive(Debug, Clone)]
    pub struct Client(irpc::Client<Proto>);

    #[derive(Debug, Clone)]
    pub struct WriteScope {
        api: Client,
        secret: SecretKey,
        public: PublicKey,
    }

    impl WriteScope {
        pub async fn put(
            &self,
            key: impl Into<Bytes>,
            value: impl Into<Bytes>,
        ) -> Result<(), irpc::Error> {
            let key = key.into();
            let value = value.into();
            let timestamp = current_timestamp();
            let signing_data = SigningData {
                key: &key,
                timestamp,
                value: &value,
            };
            let signing_data_bytes =
                postcard::to_stdvec(&signing_data).expect("signing data to vec");
            let signature = self.secret.sign(&signing_data_bytes);
            let signed_value = SignedValue {
                timestamp,
                value: value.clone(),
                signature: signature.to_bytes(),
            };
            self.api.put(self.public, key, signed_value).await
        }
    }

    impl Client {
        pub fn local(topic: GossipTopic, config: Config) -> Self {
            let (tx, rx) = tokio::sync::mpsc::channel(32);
            let actor = Actor::new(topic, rx, config);
            tokio::spawn(actor.run());
            Self(tx.into())
        }

        /// This isn't public because it does not verify the signature on the value.
        async fn put(
            &self,
            scope: PublicKey,
            key: Bytes,
            value: SignedValue,
        ) -> Result<(), irpc::Error> {
            self.0.rpc(Put { scope, key, value }).await
        }

        /// Create a write scope that can put values signed by the given secret key.
        pub fn write(&self, secret: SecretKey) -> WriteScope {
            WriteScope {
                api: self.clone(),
                public: secret.public(),
                secret,
            }
        }

        pub async fn get(
            &self,
            scope: PublicKey,
            key: impl Into<Bytes>,
        ) -> Result<Option<Bytes>, irpc::Error> {
            let value = self
                .0
                .rpc(Get {
                    scope,
                    key: key.into(),
                })
                .await?;
            Ok(value.map(|sv| sv.value))
        }

        pub fn subscribe(&self) -> SubscribeResult {
            self.subscribe_with_opts(Subscribe {
                mode: SubscribeMode::Both,
                filter: Filter::ALL,
            })
        }

        pub fn subscribe_with_opts(&self, subscribe: Subscribe) -> SubscribeResult {
            SubscribeResult(Box::pin(self.0.server_streaming(subscribe, 32)))
        }

        pub fn iter_with_opts(&self, filter: Filter) -> IterResult {
            let subscribe = Subscribe {
                mode: SubscribeMode::Current,
                filter,
            };
            IterResult(Box::pin(self.0.server_streaming(subscribe, 32)))
        }

        pub fn iter(&self) -> IterResult {
            let subscribe = Subscribe {
                mode: SubscribeMode::Current,
                filter: Filter::ALL,
            };
            IterResult(Box::pin(self.0.server_streaming(subscribe, 32)))
        }

        pub fn join_peers(
            &self,
            peers: impl IntoIterator<Item = NodeId>,
        ) -> impl n0_future::Future<Output = Result<(), irpc::Error>> {
            let peers = JoinPeers {
                peers: peers.into_iter().collect(),
            };
            self.0.rpc(peers)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    struct State {
        current: rpds::HashTrieMapSync<PublicKey, rpds::RedBlackTreeMapSync<Bytes, SignedValue>>,
    }

    impl State {
        fn new() -> Self {
            Self::default()
        }

        fn snapshot(&self) -> Self {
            self.clone()
        }

        fn insert_signed_value(
            &mut self,
            scope: PublicKey,
            key: Bytes,
            value: SignedValue,
        ) -> Result<(), InsertError> {
            let signing_data = SigningData {
                key: &key,
                timestamp: value.timestamp,
                value: &value.value,
            };
            let signing_data_bytes =
                postcard::to_stdvec(&signing_data).expect("signing data to vec");
            let signature = ed25519_dalek::Signature::from_bytes(&value.signature);
            scope.verify(&signing_data_bytes, &signature)?;
            self.insert_signed_value_unverified(scope, key, value)
        }

        fn insert_signed_value_unverified(
            &mut self,
            scope: PublicKey,
            key: Bytes,
            value: SignedValue,
        ) -> Result<(), InsertError> {
            let per_node = if let Some(current) = self.current.get_mut(&scope) {
                current
            } else {
                self.current.insert_mut(scope, Default::default());
                self.current.get_mut(&scope).expect("just inserted")
            };
            match per_node.get_mut(&key) {
                Some(existing) if existing.timestamp >= value.timestamp => {
                    return Err(insert_error::ValueTooOldSnafu {
                        old: existing.timestamp,
                        new: value.timestamp,
                    }
                    .build());
                }
                _ => {
                    per_node.insert_mut(key, value);
                }
            }
            Ok(())
        }

        fn get(&self, scope: &PublicKey, key: &Bytes) -> Option<&SignedValue> {
            self.current.get(scope).and_then(|m| m.get(key))
        }

        fn flatten_filtered(
            &self,
            filter: &Filter,
        ) -> impl Iterator<Item = (&PublicKey, &Bytes, &SignedValue)> {
            // first filter by scope using a full scan
            let filtered_by_scope = self.current.iter().filter(|(scope, _)| {
                filter
                    .scope
                    .as_ref()
                    .map(|scopes| scopes.contains(*scope))
                    .unwrap_or(true)
            });
            filtered_by_scope.flat_map(move |(scope, map)| {
                // filter by key range using the tree structure
                let filtered_by_key =
                    map.range(filter.key.clone())
                        .filter(move |(_, signed_value)| {
                            filter.timestamp.contains(&signed_value.timestamp)
                        });
                // filter by timestamp using a full scan of the remaining items
                let filtered_by_timestamp = filtered_by_key.filter(move |(_, signed_value)| {
                    filter.timestamp.contains(&signed_value.timestamp)
                });
                // add the scope
                filtered_by_timestamp.map(move |(key, signed_value)| (scope, key, signed_value))
            })
        }

        fn flatten(&self) -> impl Iterator<Item = (&PublicKey, &Bytes, &SignedValue)> {
            self.current.iter().flat_map(|(scope, map)| {
                map.iter()
                    .map(move |(key, signed_value)| (scope, key, signed_value))
            })
        }
    }

    struct Actor {
        sender: GossipSender,
        receiver: GossipReceiver,
        rx: tokio::sync::mpsc::Receiver<Message>,
        config: Config,
        state: State,
        broadcast_tx: broadcast::Sender<BroadcastItem>,
    }

    impl Actor {
        fn new(
            topic: GossipTopic,
            rx: tokio::sync::mpsc::Receiver<Message>,
            config: Config,
        ) -> Self {
            let (sender, receiver) = topic.split();
            let (broadcast_tx, _) = tokio::sync::broadcast::channel(32);
            Self {
                state: State::new(),
                sender,
                receiver,
                rx,
                broadcast_tx,
                config,
            }
        }

        fn horizon(&self) -> Option<u64> {
            self.config
                .expiry
                .as_ref()
                .map(|d| current_timestamp() - d.horizon.as_nanos() as u64)
        }

        fn apply_horizon(&mut self) -> Vec<(PublicKey, Bytes, u64)> {
            let mut expired = Vec::new();
            let Some(horizon) = self.horizon() else {
                return expired;
            };
            for (scope, map) in self.state.current.iter() {
                for (key, value) in map.iter() {
                    if value.timestamp < horizon {
                        expired.push((*scope, key.clone(), value.timestamp));
                    }
                }
            }
            let mut expired_scopes = HashSet::new();
            for (scope, key, _) in &expired {
                let entry = self.state.current.get_mut(scope).expect("just checked");
                entry.remove_mut(key);
                if entry.is_empty() {
                    expired_scopes.insert(*scope);
                }
            }
            for scope in expired_scopes {
                self.state.current.remove_mut(&scope);
            }
            expired
        }

        /// Publish all known values in random order over the gossip network, spaced out evenly over the given total duration.
        async fn anti_entropy(
            snapshot: State,
            sender: GossipSender,
            total: Duration,
        ) -> Result<(), iroh_gossip::api::ApiError> {
            trace!(
                "Starting anti-entropy with {} items for {:?}",
                snapshot.flatten().count(),
                total
            );
            let mut rng = rand::rngs::OsRng;
            let mut to_publish = snapshot.flatten().collect::<Vec<_>>();
            to_publish.shuffle(&mut rng);
            let n = to_publish.len();
            if n == 0 {
                tokio::time::sleep(total).await;
                return Ok(());
            }
            let delay = total / (n as u32);
            let mut buf = BytesMut::with_capacity(4096);
            for (scope, key, signed_value) in to_publish {
                let gossip_msg =
                    GossipMessage::SignedValue(*scope, key.clone(), signed_value.clone());
                let gossip_msg = postcard_ser(&gossip_msg, &mut buf);
                trace!(
                    "Anti-entropy publishing key={:?} at={:?}",
                    key,
                    signed_value.timestamp / 1_000_000_000
                );
                sender.broadcast_neighbors(gossip_msg).await?;
                tokio::time::sleep(delay).await;
            }
            Ok(())
        }

        async fn iter_current(
            tx: &irpc::channel::mpsc::Sender<SubscribeItem>,
            snapshot: &State,
            filter: &Filter,
        ) -> Result<(), irpc::Error> {
            for (scope, key, signed_value) in snapshot.flatten_filtered(filter) {
                tx.send(SubscribeItem::Entry((
                    *scope,
                    key.clone(),
                    signed_value.clone(),
                )))
                .await?;
            }
            Ok(())
        }

        async fn handle_subscribe(
            tx: mpsc::Sender<SubscribeItem>,
            filter: Filter,
            current: Option<State>,
            future: Option<tokio::sync::broadcast::Receiver<BroadcastItem>>,
        ) {
            if let Some(snapshot) = current
                && Self::iter_current(&tx, &snapshot, &filter).await.is_err()
            {
                return;
            }
            let Some(mut broadcast_rx) = future else {
                return;
            };
            // Indicate that current values are done, and we are now sending future values.
            if tx.send(SubscribeItem::CurrentDone).await.is_err() {
                return;
            }
            loop {
                tokio::select! {
                    item = broadcast_rx.recv() => {
                        let Ok(item) = item else {
                            break;
                        };
                        if !item.contained_in(&filter) {
                            continue;
                        }
                        if tx.send(item.into()).await.is_err() {
                            break;
                        }
                    }
                    _ = tx.closed() => {
                        break;
                    }
                }
            }
        }

        async fn run(mut self) {
            let mut tasks = FuturesUnordered::<n0_future::boxed::BoxFuture<()>>::new();
            let mut buf = bytes::BytesMut::with_capacity(4096);
            let anti_entropy = Self::anti_entropy(
                self.state.snapshot(),
                self.sender.clone(),
                self.config.anti_entropy_interval,
            );
            let horizon_period = match self.horizon() {
                Some(_) => Duration::from_secs(30),
                None => Duration::MAX,
            };
            let apply_horizon = Box::pin(tokio::time::sleep(horizon_period));
            tokio::pin!(anti_entropy, apply_horizon);
            loop {
                tokio::select! {
                    msg = self.rx.recv() => {
                        trace!("Received local message {:?}", msg);
                        let Some(msg) = msg else {
                            break;
                        };
                        match msg {
                            Message::Put(msg) => {
                                self.state.insert_signed_value_unverified(msg.scope, msg.key.clone(), msg.value.clone())
                                    .expect("inserting local value should always work");
                                let gossip_msg = GossipMessage::SignedValue(msg.scope, msg.key.clone(), msg.value.clone());
                                let gossip_msg = postcard_ser(&gossip_msg, &mut buf);
                                self.sender.broadcast(gossip_msg).await.ok();
                                self.broadcast_tx.send(BroadcastItem::Entry((msg.scope, msg.key.clone(), msg.value.clone()))).ok();
                                msg.tx.send(()).await.ok();
                            }
                            Message::Get(msg) => {
                                let res = self.state.get(&msg.scope, &msg.key);
                                msg.tx.send(res.cloned()).await.ok();
                            }
                            Message::Subscribe(msg) => {
                                let broadcast_rx = self.broadcast_tx.subscribe();
                                let filter = msg.filter.clone();
                                let (current, future) = match msg.mode {
                                    SubscribeMode::Current => (Some(self.state.snapshot()), None),
                                    SubscribeMode::Future => (None, Some(broadcast_rx)),
                                    SubscribeMode::Both => (Some(self.state.snapshot()), Some(broadcast_rx)),
                                };
                                tasks.push(Box::pin(Self::handle_subscribe(msg.tx, filter, current, future)));
                            }
                            Message::JoinPeers(msg) => {
                                let res = self.sender.join_peers(msg.peers.clone()).await;
                                msg.tx.send(()).await.ok();
                                if let Err(e) = res {
                                    error!("Error joining peers: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                    msg = self.receiver.next() => {
                        trace!("Received gossip message {:?}", msg);
                        let Some(msg) = msg else {
                            error!("Gossip receiver closed");
                            break;
                        };
                        let msg = match msg {
                            Ok(msg) => msg,
                            Err(cause) => {
                                error!("Error receiving message: {:?}", cause);
                                break;
                            }
                        };
                        let msg = match msg {
                            Event::Received(msg) => msg,
                            Event::NeighborUp(peer) => {
                                trace!("New peer {}, starting fast anti-entropy", peer.fmt_short());
                                anti_entropy.set(Self::anti_entropy(self.state.snapshot(), self.sender.clone(), self.config.fast_anti_entropy_interval));
                                continue;
                            },
                            Event::NeighborDown(peer) => {
                                trace!("Peer down: {}, goodbye!", peer.fmt_short());
                                continue;
                            },
                            e => {
                                trace!("Ignoring event: {:?}", e);
                                continue
                            },
                        };
                        let msg = match postcard::from_bytes::<GossipMessage>(&msg.content) {
                            Ok(msg) => msg,
                            Err(e) => {
                                trace!("Error deserializing gossip message: {:?}", e);
                                continue;
                            }
                        };
                        match msg {
                            GossipMessage::SignedValue(scope, key, value) => {
                                if let Some(horizon) = self.horizon()
                                    && value.timestamp < horizon {
                                        trace!("Ignoring value key={:?} epoch={} below horizon", key, value.timestamp);
                                        continue;
                                    }
                                let id = scope.fmt_short();
                                trace!(%id, "Received signed value key={:?} epoch={}", key, value.timestamp);
                                let Ok(_) = self.state.insert_signed_value(scope, key.clone(), value.clone()) else {
                                    continue;
                                };
                                trace!(%id, "Broadcasting internally");
                                self.broadcast_tx.send(BroadcastItem::Entry((scope, key, value))).ok();
                            }
                        }
                    }
                    res = &mut anti_entropy => {
                        if let Err(e) = res {
                            error!("Error in anti-entropy: {:?}", e);
                            break;
                        }
                        // anti-entropy finished, start a new one
                        anti_entropy.set(Self::anti_entropy(self.state.snapshot(), self.sender.clone(), self.config.anti_entropy_interval));
                    }
                    _ = &mut apply_horizon => {
                        let expired = self.apply_horizon();
                        for entry in expired {
                            self.broadcast_tx.send(BroadcastItem::Expired(entry)).ok();
                        }
                        // schedule next horizon application
                        apply_horizon.set(Box::pin(tokio::time::sleep(horizon_period)));
                    }
                    _ = tasks.next(), if !tasks.is_empty() => {}
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub anti_entropy_interval: Duration,
    pub fast_anti_entropy_interval: Duration,
    /// Optional horizon duration. Values older than now - horizon are removed,
    /// and will not be re-added.
    pub expiry: Option<ExpiryConfig>,
}

#[derive(Debug, Clone)]
pub struct ExpiryConfig {
    /// Duration after which values expire.
    pub horizon: Duration,
    /// How often to check for expired values.
    pub check_interval: Duration,
}

impl Config {
    pub const DEBUG: Self = Self {
        anti_entropy_interval: Duration::from_secs(30),
        fast_anti_entropy_interval: Duration::from_secs(5),
        expiry: Some(ExpiryConfig {
            horizon: Duration::from_secs(30),
            check_interval: Duration::from_secs(10),
        }),
    };
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // republish all known values every 5 minutes
            anti_entropy_interval: Duration::from_secs(300),
            // republish all known values every 10 seconds when we get a new peer
            fast_anti_entropy_interval: Duration::from_secs(10),
            // keep values for 24 hours, purge every hour
            expiry: Some(ExpiryConfig {
                horizon: Duration::from_secs(3600 * 24),
                check_interval: Duration::from_secs(3600),
            }),
        }
    }
}

pub mod util {
    use std::{
        fmt,
        time::{Duration, SystemTime},
    };

    use bytes::{Bytes, BytesMut};
    use serde::Serialize;

    /// We use nanoseconds since epoch for timestamps.
    ///
    /// This will overflow in the year 2554. If that ever becomes a problem, we can
    /// switch to u128.
    ///
    /// It will also not work for dates before the unix epoch, but that's not a
    /// problem for our use case.
    pub fn to_nanos(t: &SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos()
            .try_into()
            .expect("u64 nanos")
    }

    pub fn current_timestamp() -> u64 {
        to_nanos(&SystemTime::now())
    }

    pub fn from_nanos(nanos: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
    }

    pub(crate) fn postcard_ser<T: Serialize>(value: &T, buf: &mut BytesMut) -> Bytes {
        buf.clear();
        postcard::to_extend(value, ExtendBytesMut(buf)).expect("value to buf");
        buf.split().into()
    }

    struct ExtendBytesMut<'a>(&'a mut BytesMut);

    impl<'a> Extend<u8> for ExtendBytesMut<'a> {
        fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
            for b in iter {
                self.0.extend_from_slice(&[b]);
            }
        }
    }

    pub fn next_prefix(bytes: &mut [u8]) -> bool {
        for byte in bytes.iter_mut().rev() {
            if *byte < 255 {
                *byte += 1;
                return true;
            }
            *byte = 0;
        }
        false
    }

    pub fn format_bytes(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return "\"\"".to_string();
        }
        let Ok(s) = std::str::from_utf8(bytes) else {
            return hex::encode(bytes);
        };
        if s.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r')
        {
            return hex::encode(bytes);
        }
        format!("\"{}\"", escape_string(s))
    }

    pub fn escape_string(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                '"' => "\\\"".to_string(),
                '\\' => "\\\\".to_string(),
                '\n' => "\\n".to_string(),
                '\t' => "\\t".to_string(),
                '\r' => "\\r".to_string(),
                c => c.to_string(),
            })
            .collect()
    }
    pub(crate) struct DD<T: fmt::Display>(pub T);

    impl<T: fmt::Display> fmt::Debug for DD<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            fmt::Display::fmt(&self.0, f)
        }
    }
}

#[cfg(feature = "filter-parser")]
mod peg_parser {
    use std::{
        collections::HashSet,
        fmt::{self, Display},
        ops::Bound,
        str::FromStr,
        time::SystemTime,
    };

    use bytes::Bytes;
    use iroh::PublicKey;

    use crate::{
        api::Filter,
        util::{format_bytes, from_nanos},
    };

    impl Display for Filter {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut parts = Vec::new();

            // Handle scope
            if let Some(scopes) = &self.scope
                && !scopes.is_empty()
            {
                let scope_list: Vec<String> = scopes.iter().map(|k| k.to_string()).collect();
                parts.push(format!("scope={{{}}}", scope_list.join(",")));
            }

            // Handle key range
            match &self.key {
                (Bound::Unbounded, Bound::Unbounded) => {} // No key filter
                (Bound::Included(start), Bound::Included(end)) if start == end => {
                    // Single key
                    parts.push(format!("key={}", format_bytes(start)));
                }
                (start_bound, end_bound) => {
                    // Range
                    let start_str = match start_bound {
                        Bound::Unbounded => String::new(),
                        Bound::Included(bytes) | Bound::Excluded(bytes) => format_bytes(bytes),
                    };

                    let end_str = match end_bound {
                        Bound::Unbounded => String::new(),
                        Bound::Included(bytes) | Bound::Excluded(bytes) => format_bytes(bytes),
                    };

                    let op = match end_bound {
                        Bound::Included(_) => "..=",
                        _ => "..",
                    };

                    parts.push(format!("key={start_str}{op}{end_str}"));
                }
            }

            // Handle timestamp range
            match &self.timestamp {
                (Bound::Unbounded, Bound::Unbounded) => {} // No time filter
                (start_bound, end_bound) => {
                    let start_str = match start_bound {
                        Bound::Unbounded => String::new(),
                        Bound::Included(time) | Bound::Excluded(time) => {
                            use chrono::{DateTime, Utc};
                            let dt: DateTime<Utc> = (from_nanos(*time)).into();
                            dt.to_rfc3339()
                        }
                    };

                    let end_str = match end_bound {
                        Bound::Unbounded => String::new(),
                        Bound::Included(time) | Bound::Excluded(time) => {
                            use chrono::{DateTime, Utc};
                            let dt: DateTime<Utc> = (from_nanos(*time)).into();
                            dt.to_rfc3339()
                        }
                    };

                    let op = match end_bound {
                        Bound::Included(_) => "..=",
                        _ => "..",
                    };

                    parts.push(format!("time={start_str}{op}{end_str}"));
                }
            }

            write!(f, "{}", parts.join(" & "))
        }
    }

    impl FromStr for Filter {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            parse_filter(s)
        }
    }

    peg::parser! {
        grammar filter_parser() for str {
            pub rule filter() -> Filter
                = _ parts:(filter_part() ** (_ "&" _)) _ {
                    let mut filter = Filter::ALL;
                    for part in parts {
                        match part {
                            FilterPart::Scope(keys) => filter = filter.scopes(keys),
                            FilterPart::Key(range) => filter = filter.keys(range),
                            FilterPart::KeyPrefix(prefix) => filter = filter.key_prefix(prefix),
                            FilterPart::Time(range) => filter = filter.timestamps(range),
                        }
                    }
                    filter
                }

            rule filter_part() -> FilterPart
                = scope_part() / key_part() / time_part()

            rule scope_part() -> FilterPart
                = "scope" _ "=" _ "{" _ keys:(hex_value() ** (_ "," _)) _ "}" {
                    let keys = keys.into_iter()
                        .filter_map(|s| PublicKey::from_str(&s).ok())
                        .collect();
                    FilterPart::Scope(keys)
                }

            rule key_part() -> FilterPart
                = "key" _ "=" _ result:(key_prefix() / key_range() / key_single()) { result }

            rule key_prefix() -> FilterPart
                = v:value() _ "*" { FilterPart::KeyPrefix(v) }

            rule key_range() -> FilterPart
                = start:value()? _ op:range_op() _ end:value()? {
                    let start_bound = start.map_or(Bound::Unbounded, Bound::Included);
                    let end_bound = end.map_or(Bound::Unbounded, |v| {
                        if op { Bound::Included(v) } else { Bound::Excluded(v) }
                    });
                    FilterPart::Key((start_bound, end_bound))
                }

            rule key_single() -> FilterPart
                = v:value() { FilterPart::Key((Bound::Included(v.clone()), Bound::Included(v))) }

            rule time_part() -> FilterPart
                = "time" _ "=" _ range:time_range() { FilterPart::Time(range) }

            rule time_range() -> (Bound<SystemTime>, Bound<SystemTime>)
                = start:timestamp()? _ op:range_op() _ end:timestamp()? {
                    let start_bound = start.flatten().map_or(Bound::Unbounded, Bound::Included);
                    let end_bound = end.flatten().map_or(Bound::Unbounded, |v| {
                        if op { Bound::Included(v) } else { Bound::Excluded(v) }
                    });
                    (start_bound, end_bound)
                }

            rule range_op() -> bool
                = "..=" { true } / ".." { false }

            rule value() -> Bytes
                = quoted_string() / hex_bytes()

            rule quoted_string() -> Bytes
                = "\"" s:string_content() "\"" { Bytes::from(s) }

            rule string_content() -> String
                = chars:string_char()* { chars.into_iter().collect() }

            rule string_char() -> char
                = "\\\\" { '\\' }
                / "\\\"" { '"' }
                / "\\n" { '\n' }
                / "\\t" { '\t' }
                / "\\r" { '\r' }
                / c:$(!['\"' | '\\'] [_]) { c.chars().next().unwrap() }

            rule hex_bytes() -> Bytes
                = s:$(['0'..='9' | 'a'..='f' | 'A'..='F']+) {?
                    hex::decode(s)
                        .map(Bytes::from)
                        .map_err(|_| "invalid hex")
                }

            rule hex_value() -> String
                = s:$(['0'..='9' | 'a'..='f' | 'A'..='F']+) { s.to_string() }

            rule timestamp() -> Option<SystemTime>
                = s:timestamp_chars() {
                    use chrono::{DateTime, Utc};
                    DateTime::parse_from_rfc3339(s.trim())
                        .map(|dt| dt.with_timezone(&Utc).into()).ok()
                }

            rule timestamp_chars() -> &'input str
                = $([^ '&' | ' ' | '\t' | '\n' | '\r' | '.']+)

            rule _() = [' ' | '\t' | '\n' | '\r']*
        }
    }

    #[derive(Debug)]
    enum FilterPart {
        Scope(HashSet<PublicKey>),
        Key((Bound<Bytes>, Bound<Bytes>)),
        KeyPrefix(Bytes),
        Time((Bound<SystemTime>, Bound<SystemTime>)),
    }

    pub fn parse_filter(input: &str) -> Result<Filter, String> {
        filter_parser::filter(input).map_err(|e| e.to_string())
    }
}
