use std::time::Duration;

use clap::Parser;
use iroh::{SecretKey, discovery::static_provider::StaticProvider};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_smol_kv::{Client, Config};
use n0_future::StreamExt;
use n0_snafu::ResultExt;
use tracing::trace;

#[derive(Debug, Parser)]
struct Args {
    bootstrap: Vec<NodeTicket>,
}

#[tokio::main]
async fn main() -> n0_snafu::Result<()> {
    tracing_subscriber::fmt::init();
    trace!("Starting iroh-gossip example");
    let args = Args::parse();
    let key = SecretKey::generate(&mut rand::rng());
    let node_id = key.public();
    let sp = StaticProvider::new();
    let endpoint = iroh::Endpoint::builder()
        .secret_key(key.clone())
        .discovery(sp.clone())
        .bind()
        .await
        .e()?;
    let _ = endpoint.online().await;
    let addr = endpoint.node_addr();
    let ticket = NodeTicket::from(addr);
    for bootstrap in &args.bootstrap {
        sp.add_node_info(bootstrap.node_addr().clone());
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
    let api = Client::local(topic, Config::DEBUG);
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
                Ok((scope, key, value)) => {
                    println!("Update from {scope}: key={key:?} value={value:?}");
                }
                Err(e) => {
                    println!("Error in subscription: {e:?}");
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
