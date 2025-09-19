use std::str::FromStr;

use clap::Parser;
use iroh::{SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_docs_mini::{Config, api};
use iroh_gossip::{net::Gossip, proto::TopicId};
use n0_snafu::ResultExt;
use tokio::{
    io::{self, AsyncBufReadExt, BufReader},
    signal,
};

#[derive(Debug, Parser)]
struct Args {
    bootstrap: Vec<NodeTicket>,
}

#[derive(Debug)]
enum Command {
    /// /put key value
    Put { key: String, value: String },
    /// /get key
    Get { key: String },
    /// /peers node_ticket*
    JoinPeers { peers: Vec<NodeTicket> },
    /// /iter prefix?
    Iter,
    /// /quit
    Quit,
    /// Nothing of the above
    Other { raw: String },
}

impl Command {
    fn parse(line: &str) -> Self {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        let other = || Command::Other {
            raw: line.to_string(),
        };

        match parts.as_slice() {
            ["/put", key, value] => Command::Put {
                key: key.to_string(),
                value: value.to_string(),
            },
            ["/get", key] => Command::Get {
                key: key.to_string(),
            },
            ["/join_peers", peers @ ..] => {
                if let Ok(peers) = peers
                    .iter()
                    .map(|s| NodeTicket::from_str(s))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Command::JoinPeers { peers }
                } else {
                    other()
                }
            }
            ["/iter"] => Command::Iter,
            ["/quit"] => Command::Quit,
            _ => other(),
        }
    }
}

fn utf8_or_hex(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        format!("\"{s}\"")
    } else {
        hex::encode(bytes)
    }
}

#[tokio::main]
async fn main() -> n0_snafu::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut rng = rand::rngs::OsRng;
    let key = SecretKey::generate(&mut rng);
    let node_id = key.public();
    let endpoint = iroh::Endpoint::builder()
        .secret_key(key.clone())
        .bind()
        .await
        .e()?;
    let _ = endpoint.home_relay().initialized().await;
    let addr = endpoint.node_addr().initialized().await;
    let ticket = NodeTicket::from(addr);
    for bootstrap in &args.bootstrap {
        endpoint.add_node_addr(bootstrap.node_addr().clone()).ok();
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
    let api = api::Client::local(topic, Config::DEBUG);
    let ws = api.write(key.clone());
    // Create a reader for stdin
    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    println!("Reading from stdin... Press Ctrl+C to exit.");

    loop {
        tokio::select! {
            // Handle Ctrl+C signal
            _ = signal::ctrl_c() => {
                break;
            }
            // Read the next line from stdin
            line = lines.next_line() => {
                let Some(line) = line.e()? else {
                    break;
                };
                match Command::parse(&line) {
                    Command::Put { key, value } => {
                        println!("Put key: {}, value: {}", key, value);
                        ws.put(key, value).await.e()?;
                    }
                    Command::Get { key } => {
                        let res = api.get(node_id, key.clone()).await.e()?;
                        println!("Get key: {}, value: {:?}", key, res);
                    }
                    Command::JoinPeers { peers } => {
                        let ids = peers.iter().map(|p| p.node_addr().node_id).collect::<Vec<_>>();
                        for addr in peers {
                            router.endpoint().add_node_addr(addr.node_addr().clone()).ok();
                        }
                        api.join_peers(ids).await.e()?;
                    }
                    Command::Iter => {
                        let items = api.iter().collect::<Vec<_>>().await.e()?;
                        for (s, k, v) in items {
                            println!("{} {}=>{}", s.fmt_short(), utf8_or_hex(&k), utf8_or_hex(&v));
                        }
                    }
                    Command::Quit => {
                        println!("Bye!");
                        break;
                    }
                    Command::Other { raw } => {
                        println!("Unrecognized command: {}", raw);
                    }
                }
            }
        }
    }
    // we need to exit because next_line hangs forever otherwise.
    std::process::exit(0);
}
