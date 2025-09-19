use std::{
    collections::HashSet,
    ops::{Bound, RangeBounds},
    time::{Duration, SystemTime},
};

use bytes::{Bytes, BytesMut};
use clap::Parser;
use iroh::{PublicKey, SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender, GossipTopic},
    net::Gossip,
    proto::TopicId,
};
use irpc::{
    channel::{mpsc, oneshot},
    rpc_requests,
};
use n0_future::{FuturesUnordered, StreamExt, TryFutureExt, TryStreamExt, boxed::BoxFuture};
use n0_snafu::ResultExt;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use snafu::Snafu;
use tracing::trace;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedValue {
    timestamp: u64,
    value: Bytes,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
}

impl SignedValue {
    pub fn system_time(&self) -> SystemTime {
        from_nanos(self.timestamp)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningData<'a> {
    key: &'a [u8],
    epoch: u64,
    value: &'a [u8],
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct State {
    current: rpds::HashTrieMapSync<PublicKey, rpds::RedBlackTreeMapSync<Bytes, SignedValue>>,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
enum InsertError {
    #[snafu(transparent)]
    Signature {
        source: ed25519_dalek::SignatureError,
    },
    #[snafu(display("Value too old: existing epoch {}, new epoch {}", old, new))]
    ValueTooOld { old: u64, new: u64 },
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
            epoch: value.timestamp,
            value: &value.value,
        };
        let signing_data_bytes = postcard::to_stdvec(&signing_data).expect("signing data to vec");
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

    fn get_signed_value(&self, scope: &PublicKey, key: &Bytes) -> Option<&SignedValue> {
        self.current.get(scope).and_then(|m| m.get(key))
    }

    fn get(&self, scope: &PublicKey, key: &Bytes) -> Option<&Bytes> {
        self.get_signed_value(scope, key).map(|sv| &sv.value)
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
            let filtered_by_key = map
                .range(filter.key.clone())
                .filter(move |(_, signed_value)| filter.timestamp.contains(&signed_value.timestamp));
            // filter by timestamp using a full scan of the remaining items
            let filtered_by_timestamp = filtered_by_key
                .filter(move |(_, signed_value)| filter.timestamp.contains(&signed_value.timestamp));
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

#[derive(Debug, Serialize, Deserialize)]
struct Put {
    scope: PublicKey,
    key: Bytes,
    value: SignedValue,
}

#[derive(Debug, Serialize, Deserialize)]
struct Get {
    scope: PublicKey,
    key: Bytes,
}

#[derive(Debug, Serialize, Deserialize)]
struct Iter {
    filter: Filter,
}

#[derive(Debug, Serialize, Deserialize)]
struct Subscribe {
    include_existing: bool,
    filter: Filter,
}

#[derive(Debug, Serialize, Deserialize)]
#[rpc_requests(message = Message)]
enum Proto {
    #[rpc(tx = oneshot::Sender<()>)]
    Put(Put),
    #[rpc(tx = oneshot::Sender<Option<Bytes>>)]
    Get(Get),
    #[rpc(tx = mpsc::Sender<(PublicKey, Bytes, u64, Bytes)>)]
    Iter(Iter),
    #[rpc(tx = mpsc::Sender<(PublicKey, Bytes, u64, Bytes)>)]
    Subscribe(Subscribe),
}

#[derive(Debug, Serialize, Deserialize)]
enum GossipMessage {
    SignedValue(PublicKey, Bytes, SignedValue),
}

pub struct Config {
    pub anti_entropy_interval: Duration,
    pub fast_anti_entropy_interval: Duration,
}

impl Config {
    pub const DEBUG: Self = Self {
        anti_entropy_interval: Duration::from_secs(30),
        fast_anti_entropy_interval: Duration::from_secs(5),
    };
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // republish all known values every 5 minutes
            anti_entropy_interval: Duration::from_secs(300),
            // republish all known values every 10 seconds when we get a new peer
            fast_anti_entropy_interval: Duration::from_secs(10),
        }
    }
}

struct Actor {
    state: State,
    sender: GossipSender,
    receiver: GossipReceiver,
    broadcast_tx: tokio::sync::broadcast::Sender<(PublicKey, Bytes, u64, Bytes)>,
    rx: tokio::sync::mpsc::Receiver<Message>,
    config: Config,
}

#[derive(Debug, Clone)]
struct Api(irpc::Client<Proto>);

struct WriteScope {
    api: Api,
    secret: SecretKey,
}

impl WriteScope {
    async fn put(&self, key: impl Into<Bytes>, value: impl Into<Bytes>) -> Result<(), irpc::Error> {
        let key = key.into();
        let value = value.into();
        let epoch = epoch();
        let signing_data = SigningData {
            key: &key,
            epoch,
            value: &value,
        };
        let signing_data_bytes = postcard::to_stdvec(&signing_data).expect("signing data to vec");
        let signature = self.secret.sign(&signing_data_bytes);
        let signed_value = SignedValue {
            timestamp: epoch,
            value: value.clone(),
            signature: signature.to_bytes(),
        };
        self.api.put(self.secret.public(), key, signed_value).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    /// None means no filtering by scope
    scope: Option<HashSet<PublicKey>>,
    /// Range of keys to include
    key: (Bound<Bytes>, Bound<Bytes>),
    /// Range of timestamps (in nanoseconds since epoch) to include
    timestamp: (Bound<u64>, Bound<u64>),
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
    pub fn scope(self, scope: impl IntoIterator<Item = PublicKey>) -> Self {
        let scope = scope.into_iter().collect();
        Self {
            scope: Some(scope),
            key: self.key,
            timestamp: self.timestamp,
        }
    }
    pub fn key(self, key: impl Into<Bytes>) -> Self {
        let key = key.into();
        Self {
            scope: self.scope,
            key: (Bound::Included(key.clone()), Bound::Included(key)),
            timestamp: self.timestamp,
        }
    }
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
    pub fn timestamp(self, range: impl RangeBounds<SystemTime>) -> Self {
        let start = range.start_bound().map(to_nanos);
        let end = range.end_bound().map(to_nanos);
        Self {
            scope: self.scope,
            key: self.key,
            timestamp: (start, end),
        }
    }
    pub fn contains(&self, scope: &PublicKey, key: &[u8], timestamp: u64) -> bool {
        if let Some(scopes) = &self.scope {
            if !scopes.contains(scope) {
                return false;
            }
        }
        self.key.contains(key) && self.timestamp.contains(&timestamp)
    }
}

struct IterResult(BoxFuture<Result<mpsc::Receiver<(PublicKey, Bytes, u64, Bytes)>, irpc::Error>>);

impl IterResult {
    async fn collect<C: Default + Extend<(PublicKey, Bytes, u64, Bytes)>>(
        self,
    ) -> Result<C, irpc::Error> {
        let mut rx = self.0.await?;
        let mut items = C::default();
        while let Some(item) = rx.recv().await? {
            items.extend(Some(item));
        }
        Ok(items)
    }
}

struct SubscribeResult(
    BoxFuture<Result<mpsc::Receiver<(PublicKey, Bytes, u64, Bytes)>, irpc::Error>>,
);

impl SubscribeResult {
    fn stream(
        self,
    ) -> impl n0_future::Stream<Item = Result<(PublicKey, Bytes, u64, Bytes), irpc::Error>> {
        async move {
            let rx = self.0.await?;
            Ok(rx.into_stream().map_err(|e| irpc::Error::from(e)))
        }
        .try_flatten_stream()
    }
}

impl Api {
    pub fn local(topic: GossipTopic, config: Config) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let actor = Actor::new(topic, rx, config);
        tokio::spawn(actor.run());
        Self(tx.into())
    }

    async fn put(
        &self,
        scope: PublicKey,
        key: Bytes,
        value: SignedValue,
    ) -> Result<(), irpc::Error> {
        self.0.rpc(Put { scope, key, value }).await
    }

    pub fn write(&self, secret: SecretKey) -> WriteScope {
        WriteScope {
            api: self.clone(),
            secret,
        }
    }

    pub async fn get(
        &self,
        scope: PublicKey,
        key: impl Into<Bytes>,
    ) -> Result<Option<Bytes>, irpc::Error> {
        self.0
            .rpc(Get {
                scope,
                key: key.into(),
            })
            .await
    }

    pub fn subscribe(&self) -> SubscribeResult {
        self.subscribe_with_opts(Subscribe {
            include_existing: true,
            filter: Filter::ALL,
        })
    }

    pub fn subscribe_with_opts(&self, subscribe: Subscribe) -> SubscribeResult {
        SubscribeResult(Box::pin(self.0.server_streaming(subscribe, 32)))
    }

    pub fn iter(&self) -> IterResult {
        self.iter_with_opts(Iter {
            filter: Filter::ALL,
        })
    }

    pub fn iter_with_opts(&self, iter: Iter) -> IterResult {
        IterResult(Box::pin(self.0.server_streaming(iter, 32)))
    }
}

/// We use nanoseconds since epoch for timestamps.
///
/// This will overflow in the year 2554. If that ever becomes a problem, we can
/// switch to u128.
/// 
/// It will also not work for dates before the unix epoch, but that's not a
/// problem for our use case.
fn to_nanos(t: &SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos()
        .try_into()
        .expect("u64 nanos")
}

fn epoch() -> u64 {
    to_nanos(&SystemTime::now())
}

fn from_nanos(nanos: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
}

fn postcard_ser<T: Serialize>(value: &T, buf: &mut BytesMut) -> Bytes {
    buf.clear();
    postcard::to_extend(value, ExtendBytesMut(buf)).expect("value to buf");
    buf.split().into()
}

impl Actor {
    fn new(topic: GossipTopic, rx: tokio::sync::mpsc::Receiver<Message>, config: Config) -> Self {
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

    /// Publish all known values in random order over the gossip network, spaced out evenly over the given total duration.
    async fn anti_entropy(
        snapshot: State,
        sender: GossipSender,
        total: Duration,
    ) -> Result<(), iroh_gossip::api::ApiError> {
        trace!("Starting anti-entropy with {} items for {:?}", snapshot.flatten().count(), total);
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
                GossipMessage::SignedValue(scope.clone(), key.clone(), signed_value.clone());
            let gossip_msg = postcard_ser(&gossip_msg, &mut buf);
            trace!("Anti-entropy publishing key={:?} at={:?}", key, signed_value.system_time());
            sender.broadcast_neighbors(gossip_msg).await?;
            tokio::time::sleep(delay).await;
        }
        Ok(())
    }

    async fn handle_iter(
        tx: irpc::channel::mpsc::Sender<(PublicKey, Bytes, u64, Bytes)>,
        snapshot: State,
        filter: Filter,
    ) {
        Self::handle_iter_impl(&tx, &snapshot, &filter).await.ok();
    }

    async fn handle_iter_impl(
        tx: &irpc::channel::mpsc::Sender<(PublicKey, Bytes, u64, Bytes)>,
        snapshot: &State,
        filter: &Filter,
    ) -> Result<(), irpc::Error> {
        for (scope, key, signed_value) in snapshot.flatten_filtered(filter) {
            tx.send((
                scope.clone(),
                key.to_vec().into(),
                signed_value.timestamp,
                signed_value.value.clone(),
            ))
            .await?;
        }
        Ok(())
    }

    async fn handle_subscribe(
        tx: irpc::channel::mpsc::Sender<(PublicKey, Bytes, u64, Bytes)>,
        mut broadcast_rx: tokio::sync::broadcast::Receiver<(PublicKey, Bytes, u64, Bytes)>,
        filter: Filter,
        snapshot: Option<State>,
    ) {
        if let Some(snapshot) = snapshot {
            if Self::handle_iter_impl(&tx, &snapshot, &filter)
                .await
                .is_err()
            {
                return;
            }
        }
        loop {
            tokio::select! {
                item = broadcast_rx.recv() => {
                    let Ok(item) = item else {
                        break;
                    };
                    let (scope, key, timestamp, _) = &item;
                    if !filter.contains(scope, key, *timestamp) {
                        continue;
                    }
                    if tx.send(item).await.is_err() {
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
        tokio::pin!(anti_entropy);
        loop {
            println!("tick");
            tokio::select! {
                msg = self.rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    match msg {
                        Message::Put(msg) => {
                            self.state.insert_signed_value_unverified(msg.scope, msg.key.clone(), msg.value.clone())
                                .expect("inserting local value should always work");
                            let gossip_msg = GossipMessage::SignedValue(msg.scope.clone(), msg.key.clone(), msg.value.clone());
                            let gossip_msg = postcard_ser(&gossip_msg, &mut buf);
                            self.sender.broadcast(gossip_msg).await.ok();
                            msg.tx.send(()).await.ok();
                        }
                        Message::Get(msg) => {
                            let res = self.state.get(&msg.scope, &msg.key);
                            msg.tx.send(res.cloned()).await.ok();
                        }
                        Message::Iter(msg) => {
                            let state = self.state.snapshot();
                            let filter = msg.filter.clone();
                            tasks.push(Box::pin(Self::handle_iter(msg.tx, state, filter)));
                        }
                        Message::Subscribe(msg) => {
                            let broadcast_rx = self.broadcast_tx.subscribe();
                            let filter = msg.filter.clone();
                            let snapshot = if msg.include_existing {
                                Some(self.state.snapshot())
                            } else {
                                None
                            };
                            tasks.push(Box::pin(Self::handle_subscribe(msg.tx, broadcast_rx, filter, snapshot)));
                        }
                    }
                }
                msg = self.receiver.next() => {
                    let Some(msg) = msg else {
                        trace!("Gossip receiver closed");
                        break;
                    };
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(cause) => {
                            trace!("Error receiving message: {:?}", cause);
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
                        GossipMessage::SignedValue(scope, key, signed_value) => {
                            let id = scope.fmt_short();
                            trace!(%id, "Received signed value key={:?} epoch={}", key, signed_value.timestamp);
                            let value = signed_value.value.clone();
                            let timestamp = signed_value.timestamp;
                            let Ok(_) = self.state.insert_signed_value(scope, key.clone(), signed_value) else {
                                continue;
                            };
                            trace!(%id, "Broadcasting internally");
                            self.broadcast_tx.send((scope, key, timestamp, value)).ok();
                        }
                    }
                }
                res = &mut anti_entropy => {
                    if let Err(e) = res {
                        trace!("Error in anti-entropy: {:?}", e);
                        break;
                    }
                    // anti-entropy finished, start a new one
                    anti_entropy.set(Self::anti_entropy(self.state.snapshot(), self.sender.clone(), self.config.anti_entropy_interval));
                }
                _ = tasks.next(), if !tasks.is_empty() => {}
            }
        }
    }
}

struct ExtendBytesMut<'a>(&'a mut BytesMut);

impl<'a> Extend<u8> for ExtendBytesMut<'a> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        for b in iter {
            self.0.extend_from_slice(&[b]);
        }
    }
}

#[derive(Debug, Parser)]
struct Args {
    bootstrap: Vec<NodeTicket>,
}

#[tokio::main]
async fn main() -> n0_snafu::Result<()> {
    tracing_subscriber::fmt::init();
    trace!("Starting iroh-gossip example");
    let args = Args::parse();
    let mut rng = rand::rngs::OsRng;
    let key = SecretKey::generate(&mut rng);
    let node_id = key.public();
    let endpoint = iroh::Endpoint::builder()
        .secret_key(key.clone())
        .bind()
        .await
        .e()?;
    let _ = endpoint.home_relay().initialized().await;
    let addr = endpoint.node_addr().initialized().await;
    let ticket = NodeTicket::from(addr);
    for bootstrap in &args.bootstrap {
        endpoint.add_node_addr(bootstrap.node_addr().clone()).ok();
    }
    let bootstrap_ids = args
        .bootstrap
        .iter()
        .map(|t| t.node_addr().node_id)
        .collect::<Vec<_>>();
    println!("Node ID: {node_id}");
    println!("Bootstrap IDs: {bootstrap_ids:#?}");
    println!("Ticket: {ticket}");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let topic = TopicId::from_bytes([0; 32]);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();
    let topic = if args.bootstrap.is_empty() {
        gossip.subscribe(topic, bootstrap_ids).await.e()?
    } else {
        gossip.subscribe_and_join(topic, bootstrap_ids).await.e()?
    };
    let api = Api::local(topic, Config::DEBUG);
    let ws = api.write(key.clone());
    ws.put("hello", "world").await.e()?;
    let res = api.get(node_id, "hello").await.e()?;
    assert_eq!(res, Some("world".into()));
    let items = api.iter().collect::<Vec<_>>().await.e()?;
    println!("Items: {items:#?}");
    tokio::time::sleep(Duration::from_secs(10)).await;
    ws.put("foo", "bar").await.e()?;
    let res = api.get(node_id, "foo").await.e()?;
    assert_eq!(res, Some("bar".into()));
    let items = api.iter().collect::<Vec<_>>().await.e()?;
    println!("Items: {items:#?}");
    let sub = api.subscribe().stream();
    tokio::spawn(async move {
        tokio::pin!(sub);
        while let Some(item) = sub.next().await {
            match item {
                Ok((scope, key, _, value)) => {
                    println!("Update from {scope}: key={:?} value={:?}", key, value);
                }
                Err(e) => {
                    println!("Error in subscription: {:?}", e);
                    break;
                }
            }
        }
        println!("Subscription ended");
    });
    tokio::signal::ctrl_c().await.e()?;
    router.shutdown().await.e()?;
    Ok(())
}
