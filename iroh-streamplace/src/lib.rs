use core::fmt;
use std::{
    collections::HashSet,
    ops::Bound,
    pin::Pin,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use iroh::{SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use n0_future::{Stream, StreamExt};
use snafu::Snafu;
use tokio::sync::Mutex;

mod kv {

    mod public_key;
    pub use public_key::PublicKey;
    mod time_bound;
    pub use time_bound::TimeBound;
    mod subscribe_mode;
    pub use subscribe_mode::SubscribeMode;
}
use kv::{PublicKey, SubscribeMode, TimeBound};

#[derive(uniffi::Object)]
#[uniffi::export(Debug)]
pub struct Db {
    router: iroh::protocol::Router,
    client: iroh_smol_kv::Client,
    write: iroh_smol_kv::WriteScope,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Db")
            .field("id", &self.router.endpoint().node_id())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum CreateError {
    Key { size: u64 },
    Bind { message: String },
    Subscribe { message: String },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum JoinPeersError {
    Ticket { message: String },
    Irpc { message: String },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum PutError {
    Irpc { message: String },
}

#[derive(uniffi::Record)]
pub struct Config {
    key: Vec<u8>,
}

#[derive(uniffi::Enum, Debug, Clone)]
enum StreamFilter {
    All,
    Global,
    Stream(Vec<u8>),
}

#[derive(uniffi::Object, Debug, Clone)]
pub struct Filter {
    scope: Option<Vec<Arc<PublicKey>>>,
    stream: StreamFilter,
    min_time: TimeBound,
    max_time: TimeBound,
}

#[uniffi::export]
impl Filter {
    /// Creates a new filter that matches everything.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            scope: None,
            stream: StreamFilter::All,
            min_time: TimeBound::Unbounded,
            max_time: TimeBound::Unbounded,
        })
    }

    /// Restrict to the global namespace, no per stream data.
    pub fn global(mut self: Arc<Self>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.stream = StreamFilter::Global;
        self
    }

    /// Restrict to one specific stream, no global data.
    pub fn stream(mut self: Arc<Self>, stream: Vec<u8>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.stream = StreamFilter::Stream(stream);
        self
    }

    /// Restrict to a set of scopes.
    pub fn scopes(mut self: Arc<Self>, scopes: Vec<Arc<PublicKey>>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.scope = Some(scopes);
        self
    }

    /// Restrict to a single scope.
    pub fn scope(self: Arc<Self>, scope: Arc<PublicKey>) -> Arc<Self> {
        self.scopes(vec![scope])
    }

    /// Restrict to a time range.
    pub fn timestamps(mut self: Arc<Self>, min: TimeBound, max: TimeBound) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.min_time = min;
        this.max_time = max;
        self
    }

    /// Restrict to a time range given in nanoseconds since unix epoch.
    pub fn time_range(self: Arc<Self>, min: u64, max: u64) -> Arc<Self> {
        self.timestamps(TimeBound::Included(min), TimeBound::Excluded(max))
    }

    /// Restrict to a time range starting at min, unbounded at the top.
    pub fn time_from(self: Arc<Self>, min: u64) -> Arc<Self> {
        self.timestamps(TimeBound::Included(min), TimeBound::Unbounded)
    }
}

impl From<Filter> for iroh_smol_kv::Filter {
    fn from(value: Filter) -> Self {
        let mut filter = iroh_smol_kv::Filter::ALL;
        match value.stream {
            // everything
            StreamFilter::All => {}
            // everything starting with 'g', for the global namespace
            StreamFilter::Global => {
                filter = filter.key_prefix(b"g".as_ref());
            }
            // a specific stream, everything starting with 's' + escaped stream name
            StreamFilter::Stream(t) => {
                let prefix = util::encode_stream_and_key(Some(&t), &[]);
                filter = filter.key_prefix(prefix);
            }
        };
        filter = filter.timestamps_nanos((
            Bound::<u64>::from(value.min_time),
            Bound::<u64>::from(value.max_time),
        ));
        if let Some(scopes) = value.scope {
            let keys = scopes.iter().map(|k| iroh::PublicKey::from(k.as_ref()));
            filter = filter.scopes(keys);
        }
        filter
    }
}

static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

#[derive(uniffi::Enum, Snafu, Debug)]
#[snafu(module)]
pub enum SubscribeNextError {
    Irpc { message: String },
}

#[derive(uniffi::Record, Debug, PartialEq, Eq)]
pub struct Entry {
    scope: Arc<PublicKey>,
    stream: Option<Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
    timestamp: u64,
}

#[derive(uniffi::Enum, Debug)]
pub enum SubscribeItem {
    Entry {
        scope: Arc<PublicKey>,
        stream: Option<Vec<u8>>,
        key: Vec<u8>,
        value: Vec<u8>,
        timestamp: u64,
    },
    CurrentDone,
    Expired {
        scope: Arc<PublicKey>,
        stream: Option<Vec<u8>>,
        key: Vec<u8>,
        timestamp: u64,
    },
    Other,
}

impl From<iroh_smol_kv::SubscribeItem> for SubscribeItem {
    fn from(item: iroh_smol_kv::SubscribeItem) -> Self {
        match &item {
            iroh_smol_kv::SubscribeItem::Entry((scope, key, value)) => {
                let Some((stream, key)) = util::decode_stream_and_key(key) else {
                    return Self::Other;
                };
                Self::Entry {
                    scope: Arc::new((*scope).into()),
                    stream,
                    key,
                    value: value.value.to_vec(),
                    timestamp: value.timestamp,
                }
            }
            iroh_smol_kv::SubscribeItem::CurrentDone => Self::CurrentDone,
            iroh_smol_kv::SubscribeItem::Expired((scope, topic, timestamp)) => {
                let (stream, key) = util::decode_stream_and_key(topic).unwrap();
                Self::Expired {
                    scope: Arc::new((*scope).into()),
                    stream,
                    key,
                    timestamp: *timestamp,
                }
            }
        }
    }
}

#[derive(uniffi::Object)]
#[uniffi::export(Debug)]
#[allow(clippy::type_complexity)]
pub struct SubscribeResponse {
    inner: Mutex<
        Pin<
            Box<
                dyn Stream<Item = Result<iroh_smol_kv::SubscribeItem, irpc::Error>>
                    + Send
                    + Sync
                    + 'static,
            >,
        >,
    >,
}

impl std::fmt::Debug for SubscribeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscribeResponse").finish_non_exhaustive()
    }
}

#[uniffi::export]
impl SubscribeResponse {
    pub async fn next_raw(&self) -> Result<Option<SubscribeItem>, SubscribeNextError> {
        let mut this = self.inner.lock().await;
        match this.as_mut().next().await {
            None => Ok(None),
            Some(Ok(item)) => Ok(Some(item.into())),
            Some(Err(e)) => Err(SubscribeNextError::Irpc {
                message: e.to_string(),
            }),
        }
    }
}

#[derive(uniffi::Record)]
pub struct SubscribeOpts {
    filter: Arc<Filter>,
    mode: SubscribeMode,
}

impl From<SubscribeOpts> for iroh_smol_kv::Subscribe {
    fn from(opts: SubscribeOpts) -> Self {
        iroh_smol_kv::Subscribe {
            filter: opts.filter.as_ref().clone().into(),
            mode: opts.mode.into(),
        }
    }
}

#[uniffi::export]
impl Db {
    /// Create a new database node with the given configuration.
    #[uniffi::constructor]
    pub async fn new(config: Config) -> Result<Arc<Self>, CreateError> {
        // block on the runtime, since we need one for iroh
        RUNTIME.block_on(Self::new_in_runtime(config))
    }

    /// Put a value into the database, optionally in a specific stream.
    pub async fn put(
        &self,
        stream: Option<Vec<u8>>,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), PutError> {
        let encoded = util::encode_stream_and_key(stream.as_deref(), &key);
        self.write
            .put(encoded, value)
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })?;
        Ok(())
    }

    pub async fn iter_with_opts(
        &self,
        filter: Arc<Filter>,
    ) -> Result<Vec<Entry>, SubscribeNextError> {
        let sub = self.subscribe_with_opts(SubscribeOpts {
            filter,
            mode: SubscribeMode::Current,
        });
        let mut items = Vec::new();
        while let Some(item) = sub.next_raw().await? {
            match item {
                SubscribeItem::Entry {
                    scope,
                    stream,
                    key,
                    value,
                    timestamp,
                } => {
                    items.push(Entry {
                        scope,
                        stream,
                        key,
                        value,
                        timestamp,
                    });
                }
                _ => unreachable!("we used SubscribeMode::Current, so we should only get entries"),
            }
        }
        Ok(items)
    }

    pub fn subscribe(&self, filter: Arc<Filter>) -> Arc<SubscribeResponse> {
        self.subscribe_with_opts(SubscribeOpts {
            filter,
            mode: SubscribeMode::Both,
        })
    }

    /// Subscribe with options.
    pub fn subscribe_with_opts(&self, opts: SubscribeOpts) -> Arc<SubscribeResponse> {
        Arc::new(SubscribeResponse {
            inner: Mutex::new(Box::pin(
                self.client.subscribe_with_opts(opts.into()).stream_raw(),
            )),
        })
    }

    /// Get the node ticket for this node.
    pub async fn ticket(&self) -> String {
        self.router.endpoint().home_relay().initialized().await;
        let addr = self.router.endpoint().node_addr().initialized().await;
        let ticket = NodeTicket::from(addr);
        ticket.to_string()
    }

    /// Join a set of peers given their tickets.
    pub async fn join_peers(&self, peers: Vec<String>) -> Result<(), JoinPeersError> {
        let keys: Vec<NodeTicket> = peers
            .into_iter()
            .map(|s| NodeTicket::from_str(&s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JoinPeersError::Ticket {
                message: e.to_string(),
            })?;
        let ids = keys
            .iter()
            .map(|k| k.node_addr().node_id)
            .collect::<HashSet<_>>();
        for ticket in keys {
            self.router
                .endpoint()
                .add_node_addr(ticket.node_addr().clone())
                .ok();
        }
        self.client
            .join_peers(ids)
            .await
            .map_err(|e| JoinPeersError::Irpc {
                message: e.to_string(),
            })?;
        Ok(())
    }

    /// Get the public key of this node.
    pub fn public(&self) -> Arc<PublicKey> {
        Arc::new(self.router.endpoint().node_id().into())
    }
}

impl Db {
    /// Internal function to create a new Db instance in the tokio runtime.
    pub(crate) async fn new_in_runtime(config: Config) -> Result<Arc<Self>, CreateError> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_thread_ids(true)
            .with_thread_names(true)
            .init();
        let key = SecretKey::from_bytes(&<[u8; 32]>::try_from(config.key).map_err(|e| {
            CreateError::Key {
                size: e.len() as u64,
            }
        })?);
        let endpoint = iroh::Endpoint::builder()
            .secret_key(key.clone())
            .bind()
            .await
            .map_err(|e| CreateError::Bind {
                message: e.to_string(),
            })?;
        let _ = endpoint.home_relay().initialized().await;
        let _ = endpoint.node_addr().initialized().await;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let topic = TopicId::from_bytes([0; 32]);
        let router = iroh::protocol::Router::builder(endpoint)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();
        let topic = gossip
            .subscribe(topic, vec![])
            .await
            .map_err(|e| CreateError::Subscribe {
                message: e.to_string(),
            })?;
        let client = iroh_smol_kv::Client::local(topic, Default::default());
        let write = client.write(key);
        Ok(Arc::new(Self {
            router,
            client,
            write,
        }))
    }
}

uniffi::setup_scaffolding!();

mod util {

    pub fn encode_stream_and_key(stream: Option<&[u8]>, key: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        if let Some(s) = stream {
            result.push(b's');
            escape_into([s], &mut result);
        } else {
            result.push(b'g');
        }
        result.extend(key);
        result
    }

    pub fn decode_stream_and_key(encoded: &[u8]) -> Option<(Option<Vec<u8>>, Vec<u8>)> {
        match encoded.split_first() {
            Some((b's', mut rest)) => {
                let stream = unescape_one(&mut rest)?;
                Some((Some(stream), rest.to_vec()))
            }
            Some((b'g', rest)) => Some((None, rest.to_vec())),
            _ => None,
        }
    }

    // these values are needed to keep the order preserved
    const ESCAPE: u8 = 1;
    const SEPARATOR: u8 = 0;

    /// Escape into an existing vec.
    fn escape_into<I, C>(components: I, result: &mut Vec<u8>)
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        for segment in components.into_iter() {
            for &byte in segment.as_ref() {
                match byte {
                    ESCAPE => result.extend([ESCAPE, ESCAPE]),
                    SEPARATOR => result.extend([ESCAPE, SEPARATOR]),
                    _ => result.push(byte),
                }
            }
            result.push(SEPARATOR);
        }
        // you might think that the trailing separator is unnecessary, but it is needed
        // to distinguish between the empty path and the path with one empty component
    }

    fn unescape_one(path: &mut &[u8]) -> Option<Vec<u8>> {
        let mut segment = Vec::new();
        let mut escape = false;
        for (i, &byte) in path.iter().enumerate() {
            if escape {
                segment.push(byte);
                escape = false;
            } else {
                match byte {
                    ESCAPE => escape = true,
                    SEPARATOR => {
                        *path = &path[i + 1..];
                        return Some(segment);
                    }
                    _ => segment.push(byte),
                }
            }
        }
        None
    }

    /// A simple version of unescape.
    #[allow(dead_code)]
    fn unescape(path: &[u8]) -> Vec<Vec<u8>> {
        let mut components = Vec::new();
        let mut segment = Vec::new();
        let mut escape = false;
        for &byte in path {
            if escape {
                segment.push(byte);
                escape = false;
            } else {
                match byte {
                    ESCAPE => escape = true,
                    SEPARATOR => {
                        components.push(segment);
                        segment = Vec::new();
                    }
                    _ => segment.push(byte),
                }
            }
        }
        components
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_unescape() {
        let cases: Vec<(Option<&[u8]>, &[u8])> = vec![
            (None, b"key1"),
            (Some(b""), b""),
            (Some(b""), b"a"),
            (Some(b"a"), b""),
        ];
        for (stream, key) in cases {
            let encoded = super::util::encode_stream_and_key(stream, key);
            let (decoded_stream, decoded_key) =
                super::util::decode_stream_and_key(&encoded).unwrap();
            assert_eq!(decoded_stream.as_deref(), stream);
            assert_eq!(decoded_key.as_slice(), key);
        }
    }

    #[tokio::test]
    async fn one_node() -> testresult::TestResult<()> {
        let config = Config { key: vec![0; 32] };
        let node = Db::new_in_runtime(config).await?;
        println!("Node ID: {}", node.public());
        println!("Ticket: {}", node.ticket().await);
        node.put(Some(b"stream1".to_vec()), b"s".to_vec(), b"y".to_vec())
            .await?;
        node.put(Some(b"stream2".to_vec()), b"s".to_vec(), b"y".to_vec())
            .await?;
        let res = node.subscribe_with_opts(SubscribeOpts {
            filter: Filter::new(),
            mode: SubscribeMode::Both,
        });
        while let Some(item) = res.next_raw().await? {
            if let SubscribeItem::CurrentDone = item {
                break;
            }
            println!("Got item: {item:?}");
        }
        let res = node
            .iter_with_opts(
                Filter::new()
                    .stream(b"stream1".to_vec())
                    .scope(node.public()),
            )
            .await?;
        println!("Iter result: {res:?}");
        Ok(())
    }
}
