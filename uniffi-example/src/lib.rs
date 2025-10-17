use core::fmt;
use std::{
    str::FromStr,
    sync::{Arc, LazyLock},
};

use iroh::{discovery::static_provider::StaticProvider, SecretKey};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use snafu::Snafu;

mod kv {
    iroh_smol_kv_uniffi::generate_uniffi_support!();
}

#[derive(uniffi::Object)]
#[uniffi::export(Debug)]
pub struct Db {
    router: iroh::protocol::Router,
    sp: StaticProvider,
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

#[derive(Debug, Snafu, uniffi::Error)]
#[snafu(module)]
pub enum DbJoinPeersError {
    Ticket {
        message: String,
    },
    #[snafu(transparent)]
    JoinPeers {
        source: kv::JoinPeersError,
    },
}

static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

#[uniffi::export]
impl Db {
    #[uniffi::constructor]
    pub async fn new(config: kv::Config) -> Result<Arc<Self>, CreateError> {
        // block on the runtime, since we need one for iroh
        RUNTIME.block_on(Self::new_impl(config))
    }

    pub fn client(&self) -> Arc<kv::Client> {
        self.client.clone()
    }

    pub async fn join_peers(&self, peers: Vec<String>) -> Result<(), DbJoinPeersError> {
        let keys: Vec<NodeTicket> = peers
            .into_iter()
            .map(|s| NodeTicket::from_str(&s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DbJoinPeersError::Ticket {
                message: e.to_string(),
            })?;
        let ids = keys
            .iter()
            .map(|k| Arc::new(k.node_addr().node_id.into()))
            .collect::<Vec<_>>();
        for ticket in keys {
            self.sp.add_node_info(ticket.node_addr().clone());
        }
        self.client.join_peers(ids).await?;
        Ok(())
    }

    pub fn write(&self) -> Result<Arc<kv::WriteScope>, kv::PrivateKeyError> {
        self.client.write(self.secret())
    }

    pub fn secret(&self) -> Vec<u8> {
        self.router.endpoint().secret_key().to_bytes().to_vec()
    }

    pub fn public(&self) -> Arc<kv::PublicKey> {
        Arc::new(self.router.endpoint().node_id().into())
    }
}

impl Db {
    async fn new_impl(config: kv::Config) -> Result<Arc<Self>, CreateError> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_thread_ids(true)
            .with_thread_names(true)
            .init();
        let key = SecretKey::generate(&mut rand::rng());
        let node_id = key.public();
        let sp = StaticProvider::new();
        let endpoint = iroh::Endpoint::builder()
            .secret_key(key.clone())
            .discovery(sp.clone())
            .bind()
            .await
            .map_err(|e| CreateError::Bind {
                message: e.to_string(),
            })?;
        let _ = endpoint.online().await;
        let addr = endpoint.node_addr();
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
        let api = kv::Client::local(topic, config);
        Ok(Arc::new(Self {
            router,
            sp,
            client: Arc::new(api),
        }))
    }
}

uniffi::setup_scaffolding!();
