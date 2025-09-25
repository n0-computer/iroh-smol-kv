use std::{pin::Pin, sync::Arc, time::Duration};

use iroh::SecretKey;
use iroh_gossip::api::GossipTopic;
use iroh_smol_kv::{self as w};
use n0_future::{Stream, StreamExt};
use snafu::Snafu;
use tokio::sync::Mutex;

use super::{Filter, PublicKey, PublicKeyError, SubscribeItem, SubscribeMode};

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
pub enum PutError {
    Irpc { message: String },
}

impl From<irpc::Error> for PutError {
    fn from(e: irpc::Error) -> Self {
        PutError::Irpc {
            message: e.to_string(),
        }
    }
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum JoinPeersError {
    Irpc { message: String },
}

impl From<irpc::Error> for JoinPeersError {
    fn from(e: irpc::Error) -> Self {
        JoinPeersError::Irpc {
            message: e.to_string(),
        }
    }
}

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum GetError {
    Irpc { message: String },
}

#[derive(uniffi::Error, Snafu, Debug)]
#[snafu(module)]
pub enum SubscribeNextError {
    Irpc { message: String },
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

impl Default for Config {
    fn default() -> Self {
        iroh_smol_kv::Config::default().into()
    }
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
    pub fn write(&self, secret: Vec<u8>) -> Result<Arc<WriteScope>, PrivateKeyError> {
        let secret = SecretKey::from_bytes(&secret.try_into().map_err(|e: Vec<u8>| {
            PrivateKeyError::Length {
                size: e.len() as u64,
            }
        })?);
        let write = self.client.write(secret);
        Ok(Arc::new(WriteScope { write }))
    }

    pub async fn get(
        &self,
        scope: Arc<PublicKey>,
        key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, GetError> {
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

        self.client.join_peers(peers).await?;
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
        Ok(self.write.put(key, value).await?)
    }
}
