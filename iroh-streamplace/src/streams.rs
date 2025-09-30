use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    str::FromStr,
    sync::Arc,
};

use bytes::Bytes;
use iroh::{NodeId, PublicKey, RelayMode, SecretKey, Watcher};
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
use api::{Message as ApiMessage, Protocol as ApiProtocol};
use n0_future::{FuturesUnordered, StreamExt};
use rpc::{Message as RpcMessage, Protocol as RpcProtocol};
use snafu::Snafu;
use tracing::{Instrument, debug, error, trace, trace_span, warn};

use crate::{Config, CreateError, JoinPeersError, PutError, db, streams::rpc::RecvSegment};

pub(crate) enum HandlerMode {
    Sender,
    Forwarder,
    Receiver(Box<dyn Fn(String, Vec<u8>) -> Boxed<()> + Send + Sync + 'static>),
}

impl HandlerMode {
    pub fn receiver_fn<F, Fut>(f: F) -> Self
    where
        F: Fn(String, Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        Self::Receiver(Box::new(move |name, data| Box::pin(f(name, data))))
    }

    pub fn receiver(handler: Arc<dyn DataHandler>) -> Self {
        Self::receiver_fn(move |id, data| {
            let handler = handler.clone();
            async move {
                handler.handle_data(id, data).await;
            }
        })
    }

    pub fn mode_str(&self) -> &'static str {
        match self {
            HandlerMode::Sender => "sender",
            HandlerMode::Forwarder => "forwarder",
            HandlerMode::Receiver(_) => "receiver",
        }
    }
}

type Tasks = FuturesUnordered<Boxed<(NodeId, Result<(), RpcTaskError>)>>;

/// Actor that contains both a kv db for metadata and a handler for the rpc protocol.
///
/// This can be used both for sender and receiver nodes. Sender nodes will just set the
/// handler to None.
struct Actor {
    /// Receiver for rpc messages from remote nodes
    rpc_rx: tokio::sync::mpsc::Receiver<RpcMessage>,
    /// Receiver for API messages from the user
    api_rx: tokio::sync::mpsc::Receiver<ApiMessage>,
    /// nodes I need to send to for each stream
    subscribers: BTreeMap<String, BTreeSet<NodeId>>,
    /// nodes I am subscribed to
    subscriptions: BTreeMap<String, NodeId>,
    /// lightweight typed connection pool
    connections: ConnectionPool,
    /// How to handle incoming data
    handler: HandlerMode,
    /// Iroh protocol router, I need to keep it around to keep the protocol alive
    router: iroh::protocol::Router,
    /// Metadata db
    client: db::Db,
    /// Write scope for this node for the metadata db
    write: db::WriteScope,
    /// Ongoing tasks
    tasks: Tasks,
    /// Configuration, needed for timeouts etc.
    config: Arc<crate::Config>,
}

#[derive(Debug, Clone)]
struct Connection {
    id: NodeId,
    rpc: irpc::Client<RpcProtocol>,
}

#[derive(Debug, Snafu)]
enum RpcTaskError {
    #[snafu(transparent)]
    Task { source: irpc::Error },
    #[snafu(transparent)]
    Timeout { source: tokio::time::error::Elapsed },
}

struct ConnectionPool {
    endpoint: iroh::Endpoint,
    connections: BTreeMap<NodeId, Connection>,
}

impl ConnectionPool {
    fn new(endpoint: iroh::Endpoint) -> Self {
        Self {
            endpoint,
            connections: BTreeMap::new(),
        }
    }

    /// Cheap conn pool hack
    fn get(&mut self, remote: &NodeId) -> Connection {
        if !self.connections.contains_key(remote) {
            let conn = IrohRemoteConnection::new(
                self.endpoint.clone(),
                (*remote).into(),
                rpc::ALPN.to_vec(),
            );
            let conn = Connection {
                rpc: irpc::Client::boxed(conn),
                id: *remote,
            };
            self.connections.insert(*remote, conn);
        }
        self.connections
            .get_mut(remote)
            .expect("just inserted")
            .clone()
    }

    fn remove(&mut self, remote: &NodeId) {
        self.connections.remove(remote);
    }
}

impl Actor {
    pub async fn spawn(
        endpoint: iroh::Endpoint,
        topic: iroh_gossip::proto::TopicId,
        config: crate::Config,
        handler: HandlerMode,
    ) -> Result<(Node, impl Future<Output = ()>), iroh_gossip::api::ApiError> {
        let (rpc_tx, rpc_rx) = tokio::sync::mpsc::channel::<RpcMessage>(32);
        let (api_tx, api_rx) = tokio::sync::mpsc::channel::<ApiMessage>(32);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let id = endpoint.node_id();
        let router = iroh::protocol::Router::builder(endpoint.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(
                rpc::ALPN,
                IrohProtocol::new(rpc::Protocol::remote_handler(rpc_tx.into())),
            )
            .spawn();
        let topic = gossip.subscribe(topic, vec![]).await?;
        let secret = router.endpoint().secret_key().clone();
        let db_config = Default::default();
        let client = iroh_smol_kv::Client::local(topic, db_config);
        let write = db::WriteScope::new(client.write(secret.clone()));
        let client = db::Db::new(client);
        let actor = Self {
            rpc_rx,
            api_rx,
            subscribers: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            connections: ConnectionPool::new(router.endpoint().clone()),
            handler,
            router,
            write: write.clone(),
            client: client.clone(),
            tasks: FuturesUnordered::new(),
            config: Arc::new(config),
        };
        let api = Node {
            client: Arc::new(client),
            write: Arc::new(write),
            api: irpc::Client::local(api_tx),
        };
        Ok((
            api,
            actor
                .run()
                .instrument(trace_span!("actor", id=%id.fmt_short())),
        ))
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                msg = self.rpc_rx.recv() => {
                    let Some(msg) = msg else {
                        error!("rpc channel closed");
                        break;
                    };
                    self.handle_rpc(msg).instrument(trace_span!("rpc")).await;
                }
                msg = self.api_rx.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    self.handle_api(msg).instrument(trace_span!("api")).await;
                }
                res = self.tasks.next(), if !self.tasks.is_empty() => {
                    let Some((remote_id, res)) = res else {
                        error!("task finished but no result");
                        break;
                    };
                    match res {
                        Ok(()) => {}
                        Err(RpcTaskError::Timeout { source }) => {
                            warn!("call to {remote_id} timed out: {source}");
                        }
                        Err(RpcTaskError::Task { source }) => {
                            warn!("call to {remote_id} failed: {source}");
                        }
                    }
                    self.connections.remove(&remote_id);
                }
            }
        }
    }

    async fn update_subscriber_meta(&mut self, key: &str) {
        let n = self
            .subscribers
            .get(key)
            .map(|s| s.len())
            .unwrap_or_default();
        let v = n.to_string().into_bytes();
        self.write
            .put_impl(Some(key.as_bytes().to_vec()), b"subscribers", v.into())
            .await
            .ok();
    }

    /// Requests from remote nodes
    async fn handle_rpc(&mut self, msg: RpcMessage) {
        match msg {
            RpcMessage::Subscribe(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: rpc::Subscribe { key, remote_id },
                    ..
                } = msg;
                self.subscribers
                    .entry(key.clone())
                    .or_default()
                    .insert(remote_id);
                self.update_subscriber_meta(&key).await;
                tx.send(()).await.ok();
            }
            RpcMessage::Unsubscribe(msg) => {
                debug!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: rpc::Unsubscribe { key, remote_id },
                    ..
                } = msg;
                if let Some(e) = self.subscribers.get_mut(&key)
                    && !e.remove(&remote_id)
                {
                    warn!(
                        "unsubscribe: no subscription for {} from {}",
                        key, remote_id
                    );
                }
                if let Some(subscriptions) = self.subscribers.get(&key)
                    && subscriptions.is_empty()
                {
                    self.subscribers.remove(&key);
                }
                self.update_subscriber_meta(&key).await;
                tx.send(()).await.ok();
            }
            RpcMessage::RecvSegment(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: rpc::RecvSegment { key, data },
                    ..
                } = msg;
                match &self.handler {
                    HandlerMode::Sender => {
                        warn!("received segment but in sender mode");
                    }
                    HandlerMode::Forwarder => {
                        if let Some(remotes) = self.subscribers.get(&key) {
                            Self::handle_send(
                                &mut self.tasks,
                                &mut self.connections,
                                &self.config,
                                key,
                                data,
                                remotes,
                            );
                        } else {
                            trace!("no subscribers for stream {}", key);
                        }
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
                if let Some(remotes) = self.subscribers.get(&key) {
                    Self::handle_send(
                        &mut self.tasks,
                        &mut self.connections,
                        &self.config,
                        key,
                        data,
                        remotes,
                    );
                } else {
                    trace!("no subscribers for stream {}", key);
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
                let conn = self.connections.get(&remote_id);
                conn.rpc
                    .rpc(rpc::Subscribe {
                        key: key.clone(),
                        remote_id: self.node_id(),
                    })
                    .await
                    .ok();
                self.subscriptions.insert(key, remote_id);
                tx.send(()).await.ok();
            }
            ApiMessage::Unsubscribe(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::Unsubscribe { key, remote_id },
                    ..
                } = msg;
                let conn = self.connections.get(&remote_id);
                conn.rpc
                    .rpc(rpc::Unsubscribe {
                        key: key.clone(),
                        remote_id: self.node_id(),
                    })
                    .await
                    .ok();
                self.subscriptions.remove(&key);
                tx.send(()).await.ok();
            }
            ApiMessage::JoinPeers(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels {
                    tx,
                    inner: api::JoinPeers { peers },
                    ..
                } = msg;
                let ids = peers.iter().map(|a| a.node_id)
                    .filter(|id| *id != self.node_id())
                    .collect::<HashSet<_>>();
                for addr in &peers {
                    self.router.endpoint().add_node_addr(addr.clone()).ok();
                }
                self.client.inner().join_peers(ids).await.ok();
                tx.send(()).await.ok();
            }
            ApiMessage::GetNodeAddr(msg) => {
                trace!("{:?}", msg.inner);
                let WithChannels { tx, .. } = msg;
                if !self.config.disable_relay {
                    // don't await home relay if we have disabled relays, this will hang forever
                    self.router.endpoint().home_relay().initialized().await;
                }
                let addr = self.router.endpoint().node_addr().initialized().await;
                tx.send(addr).await.ok();
            }
        }
    }

    fn handle_send(
        tasks: &mut Tasks,
        connections: &mut ConnectionPool,
        config: &Arc<Config>,
        key: String,
        data: Bytes,
        remotes: &BTreeSet<NodeId>,
    ) {
        let msg = rpc::RecvSegment { key, data };
        for remote in remotes {
            trace!("sending to stream {}: {}", msg.key, remote);
            let conn = connections.get(&remote);
            tasks.push(Box::pin(Self::forward_task(
                config.clone(),
                conn,
                msg.clone(),
            )));
        }
    }

    async fn forward_task(
        config: Arc<crate::Config>,
        conn: Connection,
        msg: RecvSegment,
    ) -> (NodeId, Result<(), RpcTaskError>) {
        let id = conn.id;
        let res = async move {
            tokio::time::timeout(config.max_send_duration, conn.rpc.rpc(msg)).await??;
            Ok(())
        }
        .await;
        (id, res)
    }

    fn node_id(&self) -> PublicKey {
        self.router.endpoint().node_id()
    }
}

/// Iroh-streamplace node that can send, forward or receive stream segments.
#[derive(Clone, uniffi::Object)]
pub struct Node {
    client: Arc<crate::Db>,
    write: Arc<crate::WriteScope>,
    api: irpc::Client<ApiProtocol>,
}

impl Node {
    pub(crate) async fn new_in_runtime(
        config: crate::Config,
        handler: HandlerMode,
    ) -> Result<Arc<Self>, CreateError> {
        let mode_str = Bytes::from(handler.mode_str());
        let secret_key =
            SecretKey::from_bytes(&<[u8; 32]>::try_from(config.key.clone()).map_err(|e| {
                CreateError::PrivateKey {
                    size: e.len() as u64,
                }
            })?);
        let topic =
            TopicId::from_bytes(<[u8; 32]>::try_from(config.topic.clone()).map_err(|e| {
                CreateError::Topic {
                    size: e.len() as u64,
                }
            })?);
        let relay_mode = if config.disable_relay {
            RelayMode::Disabled
        } else {
            RelayMode::Default
        };
        let endpoint = iroh::Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(relay_mode)
            .bind()
            .await
            .map_err(|e| CreateError::Bind {
                message: e.to_string(),
            })?;
        let (api, actor) = Actor::spawn(endpoint, topic, config, handler)
            .await
            .map_err(|e| CreateError::Subscribe {
                message: e.to_string(),
            })?;
        api.node_scope()
            .put_impl(Option::<Vec<u8>>::None, b"mode", mode_str)
            .await
            .ok();
        tokio::spawn(actor);
        Ok(Arc::new(api))
    }
}

/// DataHandler trait that is exported to go for receiving data callbacks.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait DataHandler: Send + Sync {
    async fn handle_data(&self, topic: String, data: Vec<u8>);
}

#[uniffi::export]
impl Node {
    /// Create a new streamplace client node.
    #[uniffi::constructor]
    pub async fn sender(config: crate::Config) -> Result<Arc<Self>, CreateError> {
        crate::RUNTIME.block_on(Self::new_in_runtime(config, HandlerMode::Sender))
    }

    #[uniffi::constructor]
    pub async fn forwarder(config: crate::Config) -> Result<Arc<Self>, CreateError> {
        crate::RUNTIME.block_on(Self::new_in_runtime(config, HandlerMode::Forwarder))
    }

    #[uniffi::constructor]
    pub async fn receiver(
        config: crate::Config,
        handler: Arc<dyn DataHandler>,
    ) -> Result<Arc<Self>, CreateError> {
        crate::RUNTIME.block_on(Self::new_in_runtime(config, HandlerMode::receiver(handler)))
    }

    /// Get a handle to the db to watch for changes locally or globally.
    pub fn db(&self) -> Arc<crate::Db> {
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
