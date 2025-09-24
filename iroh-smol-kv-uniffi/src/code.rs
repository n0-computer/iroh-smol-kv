use std::{collections::HashSet, ops::Bound, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::api::GossipTopic;
use iroh_smol_kv::{self as w};
use n0_future::{Stream, StreamExt};
use snafu::Snafu;
use tokio::sync::Mutex;

#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum SubscribeMode {
    Current,
    Future,
    Both,
}

impl From<w::SubscribeMode> for SubscribeMode {
    fn from(m: w::SubscribeMode) -> Self {
        match m {
            w::SubscribeMode::Current => SubscribeMode::Current,
            w::SubscribeMode::Future => SubscribeMode::Future,
            w::SubscribeMode::Both => SubscribeMode::Both,
        }
    }
}

impl From<SubscribeMode> for w::SubscribeMode {
    fn from(m: SubscribeMode) -> Self {
        match m {
            SubscribeMode::Current => w::SubscribeMode::Current,
            SubscribeMode::Future => w::SubscribeMode::Future,
            SubscribeMode::Both => w::SubscribeMode::Both,
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone)]
pub enum KeyBound {
    Unbounded,
    Included(Vec<u8>),
    Excluded(Vec<u8>),
}

impl From<Bound<Bytes>> for KeyBound {
    fn from(b: Bound<Bytes>) -> Self {
        match b {
            Bound::Unbounded => KeyBound::Unbounded,
            Bound::Included(b) => KeyBound::Included(b.into()),
            Bound::Excluded(b) => KeyBound::Excluded(b.into()),
        }
    }
}

impl From<KeyBound> for Bound<Bytes> {
    fn from(b: KeyBound) -> Self {
        match b {
            KeyBound::Unbounded => Bound::Unbounded,
            KeyBound::Included(b) => Bound::Included(b.into()),
            KeyBound::Excluded(b) => Bound::Excluded(b.into()),
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy)]
pub enum TimeBound {
    Unbounded,
    Included(u64),
    Excluded(u64),
}

impl From<Bound<u64>> for TimeBound {
    fn from(b: Bound<u64>) -> Self {
        match b {
            Bound::Unbounded => TimeBound::Unbounded,
            Bound::Included(t) => TimeBound::Included(t),
            Bound::Excluded(t) => TimeBound::Excluded(t),
        }
    }
}

impl From<TimeBound> for Bound<u64> {
    fn from(b: TimeBound) -> Self {
        match b {
            TimeBound::Unbounded => Bound::Unbounded,
            TimeBound::Included(t) => Bound::Included(t),
            TimeBound::Excluded(t) => Bound::Excluded(t),
        }
    }
}

#[derive(uniffi::Object, Debug, Clone)]
pub struct Filter {
    min_key: KeyBound,
    max_key: KeyBound,
    min_time: TimeBound,
    max_time: TimeBound,
    scope: Vec<Vec<u8>>,
}

impl From<w::Filter> for Filter {
    fn from(f: w::Filter) -> Self {
        let min_key = f.key.0.into();
        let max_key = f.key.1.into();
        let min_time = f.timestamp.0.into();
        let max_time = f.timestamp.1.into();
        let scope = f
            .scope
            .map(|s| s.into_iter().map(|k| k.as_ref().to_vec()).collect())
            .unwrap_or_default();
        Self {
            min_key,
            max_key,
            min_time,
            max_time,
            scope,
        }
    }
}

impl TryFrom<Filter> for w::Filter {
    type Error = PublicKeyError;

    fn try_from(f: Filter) -> Result<Self, Self::Error> {
        let min_key = f.min_key.into();
        let max_key = f.max_key.into();
        let min_time = f.min_time.into();
        let max_time = f.max_time.into();
        let scope = if f.scope.is_empty() {
            None
        } else {
            let mut set = HashSet::with_capacity(f.scope.len());
            for k in f.scope {
                let pk = parse_public_key(&k)?;
                set.insert(pk);
            }
            Some(set)
        };
        Ok(w::Filter {
            key: (min_key, max_key),
            timestamp: (min_time, max_time),
            scope,
        })
    }
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum PublicKeyError {
    Length { size: u64 },
    Invalid { message: String },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum PrivateKeyError {
    Length { size: u64 },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum SignatureError {
    Length { size: u64 },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum TryFromSubscribeItemError {
    #[snafu(transparent)]
    PublicKey { source: PublicKeyError },
    #[snafu(transparent)]
    Signature { source: SignatureError },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum FilterParseError {
    Invalid { message: String },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum PutError {
    PutFailed { message: String },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum JoinPeersError {
    #[snafu(transparent)]
    Key {
        source: PublicKeyError,
    },
    Irpc {
        message: String,
    },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum GetError {
    #[snafu(transparent)]
    InvalidKey {
        source: PublicKeyError,
    },
    Irpc {
        message: String,
    },
}

fn parse_public_key(key: &[u8]) -> Result<PublicKey, PublicKeyError> {
    if key.len() != 32 {
        return Err(PublicKeyError::Length {
            size: key.len() as u64,
        });
    }
    PublicKey::from_bytes(&key.try_into().expect("len checked")).map_err(|e| {
        PublicKeyError::Invalid {
            message: e.to_string(),
        }
    })
}

#[uniffi::export]
pub fn parse_filter(text: String) -> Result<Arc<Filter>, FilterParseError> {
    use std::str::FromStr;

    iroh_smol_kv::Filter::from_str(&text)
        .map_err(|e| FilterParseError::Invalid {
            message: e.to_string(),
        })
        .map(Into::into)
        .map(Arc::new)
}

#[uniffi::export]
impl Filter {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            min_key: KeyBound::Unbounded,
            max_key: KeyBound::Unbounded,
            min_time: TimeBound::Unbounded,
            max_time: TimeBound::Unbounded,
            scope: Vec::new(),
        })
    }

    pub fn scopes(mut self: Arc<Self>, scopes: Vec<Vec<u8>>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.scope = scopes;
        self
    }

    pub fn scope(self: Arc<Self>, scope: Vec<u8>) -> Arc<Self> {
        self.scopes(vec![scope])
    }

    pub fn keys(mut self: Arc<Self>, min: KeyBound, max: KeyBound) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.min_key = min;
        this.max_key = max;
        self
    }

    pub fn key_range(self: Arc<Self>, min: Vec<u8>, max: Vec<u8>) -> Arc<Self> {
        self.keys(KeyBound::Included(min), KeyBound::Excluded(max))
    }

    pub fn key_prefix(mut self: Arc<Self>, prefix: Vec<u8>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        let mut end = prefix.clone();
        if iroh_smol_kv::util::next_prefix(&mut end) {
            this.min_key = KeyBound::Included(prefix);
            this.max_key = KeyBound::Excluded(end);
        } else {
            this.min_key = KeyBound::Included(prefix);
            this.max_key = KeyBound::Unbounded;
        }
        self
    }

    pub fn timestamps(mut self: Arc<Self>, min: TimeBound, max: TimeBound) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.min_time = min;
        this.max_time = max;
        self
    }

    pub fn time_range(self: Arc<Self>, min: u64, max: u64) -> Arc<Self> {
        self.timestamps(TimeBound::Included(min), TimeBound::Excluded(max))
    }
}

#[derive(uniffi::Enum, Snafu, Debug)]
#[snafu(module)]
pub enum SubscribeNextError {
    Irpc { message: String },
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignedValue {
    pub timestamp: u64,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
}

impl From<w::SignedValue> for SignedValue {
    fn from(v: w::SignedValue) -> Self {
        Self {
            timestamp: v.timestamp,
            value: v.value.to_vec(),
            signature: v.signature.to_vec(),
        }
    }
}

impl TryFrom<SignedValue> for w::SignedValue {
    type Error = SignatureError;

    fn try_from(v: SignedValue) -> Result<Self, Self::Error> {
        Ok(Self {
            timestamp: v.timestamp,
            value: v.value.into(),
            signature: v
                .signature
                .try_into()
                .map_err(|e: Vec<u8>| SignatureError::Length {
                    size: e.len() as u64,
                })?,
        })
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum SubscribeItem {
    Entry {
        scope: Vec<u8>,
        key: Vec<u8>,
        value: SignedValue,
    },
    CurrentDone,
    Expired {
        scope: Vec<u8>,
        key: Vec<u8>,
        timestamp: u64,
    },
}

impl std::fmt::Debug for SubscribeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match w::SubscribeItem::try_from(self.clone()) {
            Ok(item) => write!(f, "{item:?}"),
            Err(e) => write!(f, "Invalid({e})"),
        }
    }
}

impl TryFrom<SubscribeItem> for w::SubscribeItem {
    type Error = TryFromSubscribeItemError;

    fn try_from(item: SubscribeItem) -> Result<Self, Self::Error> {
        match item {
            SubscribeItem::Entry { scope, key, value } => Ok(w::SubscribeItem::Entry((
                parse_public_key(&scope)?,
                key.into(),
                value.try_into()?,
            ))),
            SubscribeItem::CurrentDone => Ok(w::SubscribeItem::CurrentDone),
            SubscribeItem::Expired {
                scope,
                key,
                timestamp,
            } => Ok(w::SubscribeItem::Expired((
                parse_public_key(&scope)?,
                key.into(),
                timestamp,
            ))),
        }
    }
}

impl From<w::SubscribeItem> for SubscribeItem {
    fn from(item: w::SubscribeItem) -> Self {
        match item {
            w::SubscribeItem::Entry((scope, key, value)) => SubscribeItem::Entry {
                scope: scope.as_ref().to_vec(),
                key: key.to_vec(),
                value: value.into(),
            },
            w::SubscribeItem::CurrentDone => SubscribeItem::CurrentDone,
            w::SubscribeItem::Expired((scope, key, timestamp)) => SubscribeItem::Expired {
                scope: scope.as_ref().to_vec(),
                key: key.to_vec(),
                timestamp,
            },
        }
    }
}

#[uniffi::export]
pub fn subscribe_item_debug(item: &SubscribeItem) -> String {
    // By reference
    format!("{:?}", item)
}

#[derive(uniffi::Object)]
#[uniffi::export(Debug)]
#[allow(clippy::type_complexity)]
pub struct SubscribeResponse {
    inner: Mutex<
        Pin<Box<dyn Stream<Item = Result<w::SubscribeItem, irpc::Error>> + Send + Sync + 'static>>,
    >,
}

impl std::fmt::Debug for SubscribeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscribeResponse").finish_non_exhaustive()
    }
}

#[uniffi::export]
impl SubscribeResponse {
    pub async fn next_raw(self: Arc<Self>) -> Result<Option<SubscribeItem>, SubscribeNextError> {
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

#[derive(uniffi::Record, Clone)]
pub struct Config {
    pub anti_entropy_interval: Duration,
    pub fast_anti_entropy_interval: Duration,
    /// Optional horizon duration. Values older than now - horizon are removed,
    /// and will not be re-added.
    pub expiry: Option<ExpiryConfig>,
}

#[uniffi::export]
fn new_config() -> Config {
    iroh_smol_kv::Config::default().into()
}

impl From<iroh_smol_kv::Config> for Config {
    fn from(c: iroh_smol_kv::Config) -> Self {
        Self {
            anti_entropy_interval: c.anti_entropy_interval,
            fast_anti_entropy_interval: c.fast_anti_entropy_interval,
            expiry: c.expiry.map(Into::into),
        }
    }
}

impl From<Config> for iroh_smol_kv::Config {
    fn from(c: Config) -> Self {
        Self {
            anti_entropy_interval: c.anti_entropy_interval,
            fast_anti_entropy_interval: c.fast_anti_entropy_interval,
            expiry: c.expiry.map(Into::into),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct ExpiryConfig {
    /// Duration after which values expire.
    pub horizon: Duration,
    /// How often to check for expired values.
    pub check_interval: Duration,
}

impl From<iroh_smol_kv::ExpiryConfig> for ExpiryConfig {
    fn from(c: iroh_smol_kv::ExpiryConfig) -> Self {
        Self {
            horizon: c.horizon,
            check_interval: c.check_interval,
        }
    }
}

impl From<ExpiryConfig> for iroh_smol_kv::ExpiryConfig {
    fn from(c: ExpiryConfig) -> Self {
        Self {
            horizon: c.horizon,
            check_interval: c.check_interval,
        }
    }
}

#[derive(uniffi::Object, Clone)]
#[uniffi::export(Debug)]
pub struct Client {
    client: w::Client,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// This can not be called from uniffi, since we can't make GossipTopic support uniffi.
    pub fn local(topic: GossipTopic, config: Config) -> Self {
        let client = w::Client::local(topic, config.into());
        Self { client }
    }
}

#[uniffi::export]
impl Client {
    pub fn write_scope(&self, secret: Vec<u8>) -> Result<Arc<WriteScope>, PrivateKeyError> {
        let secret = SecretKey::from_bytes(&secret.try_into().map_err(|e: Vec<u8>| {
            PrivateKeyError::Length {
                size: e.len() as u64,
            }
        })?);
        let write = self.client.write(secret);
        Ok(Arc::new(WriteScope { write }))
    }

    pub async fn get(&self, scope: Vec<u8>, key: Vec<u8>) -> Result<Option<Vec<u8>>, GetError> {
        let scope = parse_public_key(&scope)?;
        let res = self
            .client
            .get(scope, key)
            .await
            .map_err(|e| GetError::Irpc {
                message: e.to_string(),
            })?;
        Ok(res.map(|v| v.to_vec()))
    }

    pub fn subscribe(
        &self,
        filter: Arc<Filter>,
        mode: SubscribeMode,
    ) -> Result<Arc<SubscribeResponse>, PublicKeyError> {
        let filter: w::Filter = (*filter).clone().try_into()?;
        let stream = self
            .client
            .subscribe_with_opts(w::Subscribe {
                filter,
                mode: mode.into(),
            })
            .stream_raw();
        Ok(Arc::new(SubscribeResponse {
            inner: Mutex::new(Box::pin(stream)),
        }))
    }

    pub async fn join_peers(&self, peers: Vec<Vec<u8>>) -> Result<(), JoinPeersError> {
        let peers = peers
            .into_iter()
            .map(|p| parse_public_key(&p))
            .collect::<Result<Vec<_>, _>>()?;

        self.client
            .join_peers(peers)
            .await
            .map_err(|e| JoinPeersError::Irpc {
                message: e.to_string(),
            })?;
        Ok(())
    }
}

#[derive(uniffi::Object, Clone)]
#[uniffi::export(Debug)]
pub struct WriteScope {
    write: w::WriteScope,
}

impl std::fmt::Debug for WriteScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteScope")
            .field("scope", &self.write.scope())
            .finish_non_exhaustive()
    }
}

#[uniffi::export]
impl WriteScope {
    pub async fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), PutError> {
        self.write
            .put(key, value)
            .await
            .map_err(|e| PutError::PutFailed {
                message: e.to_string(),
            })
    }
}
