use std::time::Duration;

use clap::Parser;
use iroh::{SecretKey, address_lookup::MemoryLookup, endpoint::presets};
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_smol_kv::{Client, Config};
use iroh_tickets::endpoint::EndpointTicket;
use n0_error::{Result, StdResultExt};
use n0_future::StreamExt;
use tracing::trace;

#[derive(Debug, Parser)]
struct Args {
    bootstrap: Vec<EndpointTicket>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    trace!("Starting iroh-gossip example");
    let args = Args::parse();
    let key = SecretKey::generate(&mut rand::rng());
    let node_id = key.public();
    let sp = MemoryLookup::new();
    let endpoint = iroh::Endpoint::builder(presets::N0)
        .secret_key(key.clone())
        .address_lookup(sp.clone())
        .bind()
        .await?;
    let _ = endpoint.online().await;
    let addr = endpoint.addr();
    let ticket = EndpointTicket::from(addr);
    for bootstrap in &args.bootstrap {
        sp.add_endpoint_info(bootstrap.endpoint_addr().clone());
    }
    let bootstrap_ids = args
        .bootstrap
        .iter()
        .map(|t| t.endpoint_addr().id)
        .collect::<Vec<_>>();
    println!("Endpoint ID: {node_id}");
    println!("Bootstrap IDs: {bootstrap_ids:#?}");
    println!("Ticket: {ticket}");
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let topic = TopicId::from_bytes([0; 32]);
    let router = iroh::protocol::Router::builder(endpoint)
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();
    let topic = if args.bootstrap.is_empty() {
        gossip.subscribe(topic, bootstrap_ids).await?
    } else {
        gossip.subscribe_and_join(topic, bootstrap_ids).await?
    };
    let api = Client::local(topic, Config::DEBUG);
    let ws = api.write(key.clone());
    ws.put("hello", "world").await?;
    let res = api.get(node_id, "hello").await?;
    assert_eq!(res, Some("world".into()));
    let items = api.iter().collect::<Vec<_>>().await?;
    println!("Items: {items:#?}");
    tokio::time::sleep(Duration::from_secs(10)).await;
    ws.put("foo", "bar").await?;
    let res = api.get(node_id, "foo").await?;
    assert_eq!(res, Some("bar".into()));
    let items = api.iter().collect::<Vec<_>>().await?;
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
    tokio::signal::ctrl_c().await?;
    router.shutdown().await.anyerr()?;
    Ok(())
}
