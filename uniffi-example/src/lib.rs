use core::fmt;
use std::sync::{Arc, LazyLock};

use iroh::{SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_smol_kv::Config;
use snafu::Snafu;

pub mod kv {
    iroh_smol_kv_uniffi::generate_uniffi_support!();
}

#[derive(uniffi::Object)]
pub struct Db {
    router: iroh::protocol::Router,
    client: Arc<kv::Client>,
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
    Bind { message: String },
    Subscribe { message: String },
}

static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

#[uniffi::export]
impl Db {
    #[uniffi::constructor]
    pub async fn new() -> Result<Arc<Self>, CreateError> {
        // block on the runtime, since we need one for iroh
        RUNTIME.block_on(Self::new_impl())
    }

    pub fn client(&self) -> Arc<kv::Client> {
        self.client.clone()
    }

    pub fn write_scope(&self) -> Result<Arc<kv::WriteScope>, kv::PrivateKeyError> {
        self.client.write_scope(self.secret())
    }

    pub fn secret(&self) -> Vec<u8> {
        self.router.endpoint().secret_key().to_bytes().to_vec()
    }

    pub fn public(&self) -> Vec<u8> {
        self.router.endpoint().node_id().as_ref().to_vec()
    }

    pub fn debug(&self) -> String {
        format!("{:?}", self)
    }
}

impl Db {
    async fn new_impl() -> Result<Arc<Self>, CreateError> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_thread_ids(true)
            .with_thread_names(true)
            .init();
        let mut rng = rand::rngs::OsRng;
        let key = SecretKey::generate(&mut rng);
        let node_id = key.public();
        let endpoint = iroh::Endpoint::builder()
            .secret_key(key.clone())
            .bind()
            .await
            .map_err(|e| CreateError::Bind {
                message: e.to_string(),
            })?;
        let _ = endpoint.home_relay().initialized().await;
        let addr = endpoint.node_addr().initialized().await;
        let ticket = NodeTicket::from(addr);
        println!("Node ID: {node_id}");
        println!("Ticket: {ticket}");
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
        let api = kv::Client::local(topic, Config::default());
        Ok(Arc::new(Self {
            router,
            client: Arc::new(api),
        }))
    }
}

#[uniffi::export]
pub async fn hello(name: &str) -> String {
    format!("Hello, {}!", name)
}

// Add functions that use the types
#[uniffi::export]
pub fn create_filter() -> Arc<kv::Filter> {
    kv::Filter::new()
}

uniffi::setup_scaffolding!();
