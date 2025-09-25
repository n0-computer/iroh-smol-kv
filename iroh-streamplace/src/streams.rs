use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    str::FromStr,
    sync::Arc,
};

use iroh::{NodeId, PublicKey, SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use irpc::{WithChannels, rpc::RemoteService};
use irpc_iroh::{IrohProtocol, IrohRemoteConnection};
use n0_future::future::Boxed;

mod rpc {
    //! Protocol API
    use bytes::Bytes;
    use iroh::NodeId;
    use irpc::{channel::oneshot, rpc_requests};
    use serde::{Deserialize, Serialize};

    pub const ALPN: &[u8] = b"/iroh/streamplace/1";

    /// Subscribe to the given `key`
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Subscribe {
        pub key: String,
        // TODO: verify
        pub remote_id: NodeId,
    }

    /// Unsubscribe from the given `key`
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Unsubscribe {
        pub key: String,
        // TODO: verify
        pub remote_id: NodeId,
    }

    // #[derive(Debug, Serialize, Deserialize)]
    // pub struct SendSegment {
    //     pub key: String,
    //     pub data: Bytes,
    // }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RecvSegment {
        pub key: String,
        pub data: Bytes,
    }

    // Use the macro to generate both the Protocol and Message enums
    // plus implement Channels for each type
    #[rpc_requests(message = Message)]
    #[derive(Serialize, Deserialize, Debug)]
    pub enum Protocol {
        #[rpc(tx=oneshot::Sender<()>)]
        Subscribe(Subscribe),
        #[rpc(tx=oneshot::Sender<()>)]
        Unsubscribe(Unsubscribe),
        #[rpc(tx=oneshot::Sender<()>)]
        RecvSegment(RecvSegment),
    }
}

mod api {
    //! Protocol API
    use bytes::Bytes;
    use iroh::{NodeAddr, NodeId};
    use irpc::{channel::oneshot, rpc_requests};
    use serde::{Deserialize, Serialize};

    /// Subscribe to the given `key`
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Subscribe {
        pub key: String,
        // TODO: verify
        pub remote_id: NodeId,
    }

    /// Unsubscribe from the given `key`
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Unsubscribe {
        pub key: String,
        // TODO: verify
        pub remote_id: NodeId,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct SendSegment {
        pub key: String,
        pub data: Bytes,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct JoinPeers {
        pub peers: Vec<NodeAddr>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct GetNodeAddr;

    // Use the macro to generate both the Protocol and Message enums
    // plus implement Channels for each type
    #[rpc_requests(message = Message)]
    #[derive(Serialize, Deserialize, Debug)]
    pub enum Protocol {
        #[rpc(tx=oneshot::Sender<()>)]
        Subscribe(Subscribe),
        #[rpc(tx=oneshot::Sender<()>)]
        Unsubscribe(Unsubscribe),
        #[rpc(tx=oneshot::Sender<()>)]
        SendSegment(SendSegment),
        #[rpc(tx=oneshot::Sender<()>)]
        JoinPeers(JoinPeers),
        #[rpc(tx=oneshot::Sender<NodeAddr>)]
        GetNodeAddr(GetNodeAddr),
    }
}
pub use api::{Message as ApiMessage, Protocol as ApiProtocol};
use n0_future::{FuturesUnordered, StreamExt};
use rpc::{Message as RpcMessage, Protocol as RpcProtocol};
use tracing::{debug, trace, warn};

use crate::{CreateError, JoinPeersError, PutError};

pub enum HandlerMode {
    Sender,
    Receiver(Box<dyn Fn(String, Vec<u8>) -> Boxed<()> + Send + Sync + 'static>),
    Forwarder,
}

impl HandlerMode {
    pub fn receiver_fn(f: impl Fn(String, Vec<u8>) -> Boxed<()> + Send + Sync + 'static) -> Self {
        Self::Receiver(Box::new(f))
    }

    pub fn receiver(handler: Arc<dyn DataHandler>) -> Self {
        Self::receiver_fn(move |id, data| {
            let handler = handler.clone();
            Box::pin(async move {
                handler.handle_data(id, data).await;
            })
        })
    }
}

/// Actor that contains both a kv db for metadata and a handler for the rpc protocol.
///
/// This can be used both for sender and receiver nodes. Sender nodes will just set the
/// handler to None.
struct Actor {
    endpoint: iroh::Endpoint,
    rpc_rx: tokio::sync::mpsc::Receiver<RpcMessage>,
    api_rx: tokio::sync::mpsc::Receiver<ApiMessage>,
    subscriptions: BTreeMap<String, BTreeSet<NodeId>>,
    connections: BTreeMap<NodeId, Connection>,
    handler: HandlerMode,
    router: iroh::protocol::Router,
    client: crate::Client,
    write: crate::WriteScope,
    tasks: FuturesUnordered<Boxed<()>>,
}

#[derive(Debug, Clone)]
struct Connection {
    _id: NodeId,
    rpc: irpc::Client<RpcProtocol>,
}

impl Actor {
    pub async fn spawn(
        endpoint: iroh::Endpoint,
        config: iroh_smol_kv::Config,
        handler: HandlerMode,
    ) -> Result<(Api, impl Future<Output = ()>), iroh_gossip::api::ApiError> {
        let (rpc_tx, rpc_rx) = tokio::sync::mpsc::channel::<RpcMessage>(32);
        let (api_tx, api_rx) = tokio::sync::mpsc::channel::<ApiMessage>(32);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let topic = TopicId::from_bytes([0; 32]);
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(
                rpc::ALPN,
                IrohProtocol::new(rpc::Protocol::remote_handler(rpc_tx.into())),
            )
            .spawn();
        let topic = gossip.subscribe(topic, vec![]).await?;
        let secret = router.endpoint().secret_key().clone();
        let client = iroh_smol_kv::Client::local(topic, config);
        let write = crate::WriteScope::new(client.write(secret.clone()));
        let client = crate::Client::new(client);
        let actor = Self {
            endpoint: endpoint.clone(),
            rpc_rx,
            api_rx,
            subscriptions: BTreeMap::new(),
            connections: BTreeMap::new(),
            handler,
            router,
            write: write.clone(),
            client: client.clone(),
            tasks: FuturesUnordered::new(),
        };
        let api = Api {
            client: Arc::new(client),
            write: Arc::new(write),
            api: irpc::Client::local(api_tx),
        };
        Ok((api, actor.run()))
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                msg = self.rpc_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    self.handle_rpc(msg).await;
                }
                msg = self.api_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    self.handle_api(msg).await;
                }
                _ = self.tasks.next(), if !self.tasks.is_empty() => {
                    // task completed
                }
            }
        }
    }

    async fn update_subscriptions(&mut self, key: &str) {
        let n = self
            .subscriptions
            .get(key)
            .map(|s| s.len())
            .unwrap_or_default();
        let v = if n > 0 { b"t".to_vec() } else { b"f".to_vec() };
        self.write
            .put_impl(Some(key.as_bytes().to_vec()), b"s", v.into())
            .await
            .ok();
    }

    /// Requests from remote nodes
    async fn handle_rpc(&mut self, msg: RpcMessage) {
        match msg {
            RpcMessage::Subscribe(sub) => {
                debug!("subscribe {:?}", sub);
                let WithChannels {
                    tx,
                    inner: rpc::Subscribe { key, remote_id },
                    ..
                } = sub;
                self.subscriptions
                    .entry(key.clone())
                    .or_default()
                    .insert(remote_id);
                self.update_subscriptions(&key).await;
                tx.send(()).await.ok();
            }
            RpcMessage::Unsubscribe(sub) => {
                debug!("unsubscribe {:?}", sub);
                let WithChannels {
                    tx,
                    inner: rpc::Unsubscribe { key, remote_id },
                    ..
                } = sub;
                if let Some(e) = self.subscriptions.get_mut(&key) {
                    if !e.remove(&remote_id) {
                        warn!(
                            "unsubscribe: no subscription for {} from {}",
                            key, remote_id
                        );
                    }
                }
                if let Some(subscriptions) = self.subscriptions.get(&key) {
                    if subscriptions.is_empty() {
                        self.subscriptions.remove(&key);
                    }
                }
                self.update_subscriptions(&key).await;
                tx.send(()).await.ok();
            }
            RpcMessage::RecvSegment(segment) => {
                debug!("recv segment {:?}", segment);
                let WithChannels {
                    tx,
                    inner: rpc::RecvSegment { key, data },
                    ..
                } = segment;
                match &self.handler {
                    HandlerMode::Sender => {
                        warn!("received segment but in sender mode");
                    }
                    HandlerMode::Forwarder => {
                        todo!()
                    }
                    HandlerMode::Receiver(handler) => {
                        if self.subscriptions.contains_key(&key) {
                            handler(key, data.to_vec()).await;
                        } else {
                            warn!("received segment for unsubscribed key: {}", key);
                        }
                    }
                };
                tx.send(()).await.ok();
            }
        }
    }

    async fn handle_api(&mut self, msg: ApiMessage) {
        match msg {
            ApiMessage::SendSegment(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::SendSegment { key, data },
                    ..
                } = msg;
                let msg = rpc::RecvSegment {
                    key: key.clone(),
                    data: data.clone(),
                };

                if let Some(remotes) = self.subscriptions.get(&key) {
                    for remote in remotes {
                        debug!("sending to topic {}: {}", key, remote);

                        let conn =
                            Self::get_connection(&self.endpoint, &mut self.connections, remote);
                        // todo: move to tasks
                        // todo: send timeout
                        if let Err(err) = conn.rpc.rpc(msg.clone()).await {
                            warn!("failed to send to {}: {:?}", remote, err);
                            // remove conn
                            self.connections.remove(remote);
                        }
                    }
                }

                tx.send(()).await.ok();
            }
            ApiMessage::Subscribe(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::Subscribe { key, remote_id },
                    ..
                } = msg;
                let conn = Self::get_connection(&self.endpoint, &mut self.connections, &remote_id);
                conn.rpc
                    .rpc(rpc::Subscribe {
                        key,
                        remote_id: self.node_id(),
                    })
                    .await
                    .ok();
                tx.send(()).await.ok();
            }
            ApiMessage::Unsubscribe(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::Unsubscribe { key, remote_id },
                    ..
                } = msg;
                if let Some(conn) = self.connections.get(&remote_id) {
                    conn.rpc
                        .rpc(rpc::Unsubscribe {
                            key,
                            remote_id: self.node_id(),
                        })
                        .await
                        .ok();
                }
                tx.send(()).await.ok();
            }
            ApiMessage::JoinPeers(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::JoinPeers { peers },
                    ..
                } = msg;
                let ids = peers.iter().map(|a| a.node_id).collect::<HashSet<_>>();
                for addr in &peers {
                    self.router.endpoint().add_node_addr(addr.clone()).ok();
                }
                self.client.inner().join_peers(ids).await.ok();
                tx.send(()).await.ok();
            }
            ApiMessage::GetNodeAddr(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels { tx, .. } = msg;
                self.router.endpoint().home_relay().initialized().await;
                let addr = self.router.endpoint().node_addr().initialized().await;
                tx.send(addr).await.ok();
            }
        }
    }

    /// Cheap conn pool hack
    fn get_connection(
        endpoint: &iroh::Endpoint,
        connections: &mut BTreeMap<NodeId, Connection>,
        remote: &NodeId,
    ) -> Connection {
        if !connections.contains_key(remote) {
            let conn =
                IrohRemoteConnection::new(endpoint.clone(), (*remote).into(), rpc::ALPN.to_vec());

            let conn = Connection {
                rpc: irpc::Client::boxed(conn),
                _id: *remote,
            };
            connections.insert(*remote, conn);
        }
        connections.get_mut(remote).expect("just inserted").clone()
    }

    fn node_id(&self) -> PublicKey {
        self.endpoint.node_id()
    }
}

#[derive(Clone, uniffi::Object)]
pub struct Api {
    client: Arc<crate::Client>,
    write: Arc<crate::WriteScope>,
    api: irpc::Client<ApiProtocol>,
}

impl Api {
    pub(crate) async fn new_in_runtime(
        config: crate::Config,
        handler: HandlerMode,
    ) -> Result<Arc<Self>, CreateError> {
        let secret_key = SecretKey::from_bytes(&<[u8; 32]>::try_from(config.key).map_err(|e| {
            CreateError::PrivateKey {
                size: e.len() as u64,
            }
        })?);
        let endpoint = iroh::Endpoint::builder()
            .secret_key(secret_key)
            .bind()
            .await
            .map_err(|e| CreateError::Bind {
                message: e.to_string(),
            })?;
        let (api, actor) = Actor::spawn(endpoint, Default::default(), handler)
            .await
            .map_err(|e| CreateError::Subscribe {
                message: e.to_string(),
            })?;
        println!("Spawning actor");
        tokio::spawn(actor);
        Ok(Arc::new(api))
    }
}
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait DataHandler: Send + Sync {
    async fn handle_data(&self, topic: String, data: Vec<u8>);
}

#[uniffi::export]
impl Api {
    /// Create a new streamplace client node.
    #[uniffi::constructor]
    pub async fn sender(config: crate::Config) -> Result<Arc<Self>, CreateError> {
        crate::RUNTIME.block_on(Self::new_in_runtime(config, HandlerMode::Sender))
    }

    #[uniffi::constructor]
    pub async fn receiver(
        config: crate::Config,
        handler: Arc<dyn DataHandler>,
    ) -> Result<Arc<Self>, CreateError> {
        crate::RUNTIME.block_on(Self::new_in_runtime(config, HandlerMode::receiver(handler)))
    }

    /// Get a handle to the db to watch for changes locally or globally.
    pub fn db(&self) -> Arc<crate::Client> {
        self.client.clone()
    }

    /// Get a handle to the write scope for this node.
    ///
    /// This is equivalent to calling `db.write(...)` with the secret key used to create the node.
    pub fn node_scope(&self) -> Arc<crate::WriteScope> {
        self.write.clone()
    }

    /// Subscribe to updates for a given stream from a remote node.
    pub async fn subscribe(
        &self,
        key: String,
        remote_id: Arc<crate::PublicKey>,
    ) -> Result<(), PutError> {
        self.api
            .rpc(api::Subscribe {
                key,
                remote_id: remote_id.as_ref().into(),
            })
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })
    }

    /// Unsubscribe from updates for a given stream from a remote node.
    pub async fn unsubscribe(
        &self,
        key: String,
        remote_id: Arc<crate::PublicKey>,
    ) -> Result<(), PutError> {
        self.api
            .rpc(api::Unsubscribe {
                key,
                remote_id: remote_id.as_ref().into(),
            })
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })
    }

    /// Send a segment to all subscribers of the given stream.
    pub async fn send_segment(&self, key: String, data: Vec<u8>) -> Result<(), PutError> {
        self.api
            .rpc(api::SendSegment {
                key,
                data: data.into(),
            })
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })
    }

    /// Join peers by their node tickets.
    pub async fn join_peers(&self, peers: Vec<String>) -> Result<(), JoinPeersError> {
        let peers = peers
            .iter()
            .map(|p| NodeTicket::from_str(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JoinPeersError::Ticket {
                message: e.to_string(),
            })?;
        let addrs = peers
            .iter()
            .map(|t| t.node_addr().clone())
            .collect::<Vec<_>>();
        self.api
            .rpc(api::JoinPeers { peers: addrs })
            .await
            .map_err(|e| JoinPeersError::Irpc {
                message: e.to_string(),
            })
    }

    /// Get this node's ticket.
    pub async fn ticket(&self) -> Result<String, PutError> {
        let addr = self
            .api
            .rpc(api::GetNodeAddr)
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })?;
        Ok(NodeTicket::from(addr).to_string())
    }

    /// Get this node's node ID.
    pub async fn node_id(&self) -> Result<Arc<crate::PublicKey>, PutError> {
        let addr = self
            .api
            .rpc(api::GetNodeAddr)
            .await
            .map_err(|e| PutError::Irpc {
                message: e.to_string(),
            })?;
        Ok(Arc::new(addr.node_id.into()))
    }
}
