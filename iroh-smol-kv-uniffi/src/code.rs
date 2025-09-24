use std::{collections::HashSet, ops::{Bound}, pin::Pin, str::FromStr, sync::Arc, time::Duration};

use bytes::Bytes;
use iroh::{SecretKey};
use iroh_gossip::api::GossipTopic;
use iroh_smol_kv::{self as w};
use n0_future::{Stream, StreamExt};
use snafu::Snafu;
use tokio::sync::Mutex;

/// A public key.
///
/// The key itself is just a 32 byte array, but a key has associated crypto
/// information that is cached for performance reasons.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialOrd, uniffi::Object)]
#[uniffi::export(Display)]
pub struct PublicKey {
    pub(crate) key: [u8; 32],
}

impl From<iroh::PublicKey> for PublicKey {
    fn from(key: iroh::PublicKey) -> Self {
        PublicKey {
            key: *key.as_bytes(),
        }
    }
}

impl From<&PublicKey> for iroh::PublicKey {
    fn from(key: &PublicKey) -> Self {
        iroh::PublicKey::from_bytes(&key.key).unwrap()
    }
}

#[uniffi::export]
impl PublicKey {
    /// Returns true if the PublicKeys are equal
    pub fn equal(&self, other: &PublicKey) -> bool {
        *self == *other
    }

    /// Express the PublicKey as a byte array
    pub fn to_bytes(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    /// Make a PublicKey from base32 string
    #[uniffi::constructor]
    #[allow(clippy::result_large_err)]
    pub fn from_string(s: String) -> Result<Self, PublicKeyError> {
        if s.len() != 64 {
            return Err(PublicKeyError::Length {
                size: s.len() as u64,
            });
        }
        let key = iroh::PublicKey::from_str(&s).map_err(|e| PublicKeyError::Invalid {
            message: e.to_string(),
        })?;
        Ok(key.into())
    }

    /// Make a PublicKey from byte array
    #[uniffi::constructor]
    #[allow(clippy::result_large_err)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PublicKeyError> {
        if bytes.len() != 32 {
            return Err(PublicKeyError::Length {
                size: bytes.len() as u64,
            });
        }
        let bytes: [u8; 32] = bytes.try_into().expect("checked above");
        let key = iroh::PublicKey::from_bytes(&bytes).map_err(|e| PublicKeyError::Invalid { message: e.to_string() })?;
        Ok(key.into())
    }

    /// Convert to a base32 string limited to the first 10 bytes for a friendly string
    /// representation of the key.
    pub fn fmt_short(&self) -> String {
        iroh::PublicKey::from(self).fmt_short()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.key == other.key
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        iroh::PublicKey::from(self).fmt(f)
    }
}

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
    scope: Vec<Arc<PublicKey>>,
}

impl From<w::Filter> for Filter {
    fn from(f: w::Filter) -> Self {
        let min_key = f.key.0.into();
        let max_key = f.key.1.into();
        let min_time = f.timestamp.0.into();
        let max_time = f.timestamp.1.into();
        let scope = f
            .scope
            .map(|s| s.into_iter().map(|k| Arc::new(PublicKey::from(k))).collect())
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

impl From<Filter> for w::Filter {

    fn from(f: Filter) -> Self {
        let min_key = f.min_key.into();
        let max_key = f.max_key.into();
        let min_time = f.min_time.into();
        let max_time = f.max_time.into();
        let scope = if f.scope.is_empty() {
            None
        } else {
            let mut set = HashSet::with_capacity(f.scope.len());
            for k in f.scope {
                set.insert(iroh::PublicKey::from(k.as_ref()));
            }
            Some(set)
        };
        w::Filter {
            key: (min_key, max_key),
            timestamp: (min_time, max_time),
            scope,
        }
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
    Irpc {
        message: String,
    },
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum GetError {
    Irpc {
        message: String,
    },
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

    #[uniffi::constructor]
    pub fn parse(text: String) -> Result<Arc<Self>, FilterParseError> {
        use std::str::FromStr;

        iroh_smol_kv::Filter::from_str(&text)
            .map_err(|e| FilterParseError::Invalid {
                message: e.to_string(),
            })
            .map(Into::into)
            .map(Arc::new)
    }


    pub fn scopes(mut self: Arc<Self>, scopes: Vec<Arc<PublicKey>>) -> Arc<Self> {
        let this = Arc::make_mut(&mut self);
        this.scope = scopes;
        self
    }

    pub fn scope(self: Arc<Self>, scope: Arc<PublicKey>) -> Arc<Self> {
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

#[derive(Debug, Clone, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct SignedValue(w::SignedValue);

impl From<w::SignedValue> for SignedValue {
    fn from(v: w::SignedValue) -> Self {
        Self(v)
    }
}

impl From<SignedValue> for w::SignedValue {

    fn from(v: SignedValue) -> Self {
        v.0
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum SubscribeItem {
    Entry {
        scope: Arc<PublicKey>,
        key: Vec<u8>,
        value: Arc<SignedValue>,
    },
    CurrentDone,
    Expired {
        scope: Arc<PublicKey>,
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

impl From<SubscribeItem> for w::SubscribeItem {

    fn from(item: SubscribeItem) -> Self {
        match item {
            SubscribeItem::Entry { scope, key, value } => w::SubscribeItem::Entry((
                iroh::PublicKey::from(scope.as_ref()),
                key.into(),
                w::SignedValue::from(value.as_ref().clone()),
            )),
            SubscribeItem::CurrentDone => w::SubscribeItem::CurrentDone,
            SubscribeItem::Expired {
                scope,
                key,
                timestamp,
            } => w::SubscribeItem::Expired((
                iroh::PublicKey::from(scope.as_ref()),
                key.into(),
                timestamp,
            )),
        }
    }
}

impl From<w::SubscribeItem> for SubscribeItem {
    fn from(item: w::SubscribeItem) -> Self {
        match item {
            w::SubscribeItem::Entry((scope, key, value)) => SubscribeItem::Entry {
                scope: Arc::new(PublicKey::from(scope)),
                key: key.to_vec(),
                value: Arc::new(SignedValue::from(value)),
            },
            w::SubscribeItem::CurrentDone => SubscribeItem::CurrentDone,
            w::SubscribeItem::Expired((scope, key, timestamp)) => SubscribeItem::Expired {
                scope: Arc::new(PublicKey::from(scope)),
                key: key.to_vec(),
                timestamp,
            },
        }
    }
}

#[uniffi::export]
pub fn subscribe_item_debug(item: &SubscribeItem) -> String {
    // By reference
    format!("{item:?}")
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

    pub async fn get(&self, scope: Arc<PublicKey>, key: Vec<u8>) -> Result<Option<Vec<u8>>, GetError> {
        let res = self
            .client
            .get(iroh::PublicKey::from(scope.as_ref()), key)
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
        let filter: w::Filter = (*filter).clone().into();
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

    pub async fn join_peers(&self, peers: Vec<Arc<PublicKey>>) -> Result<(), JoinPeersError> {
        let peers = peers
            .into_iter()
            .map(|p| iroh::PublicKey::from(p.as_ref()))
            .collect::<Vec<_>>();

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
