use std::{collections::BTreeMap, str::FromStr};

use clap::Parser;
use iroh::{SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_docs_mini::{
    Config,
    api::{self, Filter, Subscribe, SubscribeResult},
};
use iroh_gossip::{net::Gossip, proto::TopicId};
use n0_future::{StreamExt, task::AbortOnDropHandle};
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
    Join { peers: Vec<NodeTicket> },
    /// /iter
    Iter { filter: Filter },
    /// /subscribe
    Subscribe { filter: Filter },
    /// /subscribe
    Unsubscribe { id: usize },
    /// /quit
    Quit,
    /// /help
    Help,
    /// Nothing of the above
    Other { raw: String },
}

impl Command {
    fn parse(line: &str) -> Self {
        Self::parse_impl(line).unwrap_or(Command::Other {
            raw: line.to_string(),
        })
    }
    fn parse_impl(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        Some(match parts.as_slice() {
            ["/put", key, value] => Command::Put {
                key: key.to_string(),
                value: value.to_string(),
            },
            ["/get", key] => Command::Get {
                key: key.to_string(),
            },
            ["/join", peers @ ..] => {
                let peers = peers
                    .iter()
                    .map(|s| NodeTicket::from_str(s))
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                Command::Join { peers }
            }
            ["/iter", filter @ ..] => Command::Iter {
                filter: Filter::from_str(&filter.join(" ")).ok()?,
            },
            ["/subscribe", filter @ ..] => Command::Subscribe {
                filter: Filter::from_str(&filter.join(" ")).ok()?,
            },
            ["/unsubscribe", id] => Command::Unsubscribe {
                id: id.parse().ok()?,
            },
            ["/quit"] => Command::Quit,
            ["/help"] => Command::Help,
            _ => return None,
        })
    }
}

fn utf8_or_hex(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        format!("\"{s}\"")
    } else {
        hex::encode(bytes)
    }
}

async fn handle_subscription(id: usize, sub: SubscribeResult) {
    let stream = sub.stream();
    tokio::pin!(stream);
    while let Some(item) = stream.next().await {
        match item {
            Ok((scope, key, value)) => {
                println!(
                    "#{}: ({},{},{})",
                    id,
                    scope.fmt_short(),
                    utf8_or_hex(&key),
                    utf8_or_hex(&value.value)
                );
            }
            Err(e) => {
                println!("#{}: Error in subscription: {:?}", id, e);
                break;
            }
        }
    }
    println!("#{} ended", id);
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
    let mut op_id = 0;
    let mut subscribers = BTreeMap::new();
    let mut next_op_id = || {
        let id = op_id;
        op_id += 1;
        id
    };

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
                    Command::Join { peers } => {
                        let ids = peers.iter().map(|p| p.node_addr().node_id).collect::<Vec<_>>();
                        for addr in peers {
                            router.endpoint().add_node_addr(addr.node_addr().clone()).ok();
                        }
                        api.join_peers(ids).await.e()?;
                    }
                    Command::Iter { filter } => {
                        let id = next_op_id();
                        println!("#{id} Iter {filter}");
                        let items = api.iter_with_opts(filter).collect::<Vec<_>>().await.e()?;
                        for (s, k, v) in items {
                            println!("#{id} ({},{},{})", s.fmt_short(), utf8_or_hex(&k), utf8_or_hex(&v));
                        }
                    }
                    Command::Subscribe { filter } => {
                        let id = next_op_id();
                        println!("#{id} Subscribe {filter}");
                        let sub = api.subscribe_with_opts(Subscribe {
                            filter,
                            mode: api::SubscribeMode::Both,
                        });
                        let task = tokio::spawn(handle_subscription(id, sub));
                        subscribers.insert(id, AbortOnDropHandle::new(task));
                    }
                    Command::Unsubscribe { id } => {
                        if let Some(handle) = subscribers.remove(&id) {
                            drop(handle); // Dropping the handle will abort the task
                            println!("#{} unsubscribed", id);
                        } else {
                            println!("#{} does not exist", id);
                        }
                    }
                    Command::Quit => {
                        println!("Bye!");
                        break;
                    }
                    Command::Help => {
                        println!(
r#"Available commands:
/put <key> <value>       - Store a key-value pair
/get <key>               - Retrieve the value for a key
/join <node_ticket>*     - Join peers by their node tickets
/iter [filter]           - Iterate over key-value pairs with an optional filter
/subscribe [filter]      - Subscribe to updates with an optional filter
/unsubscribe <id>        - Unsubscribe from a subscription by its ID
/quit                    - Exit the program
/help                    - Show this help message

filter syntax:
    You can filter by scope, key and timestamp.

    Key filters:
        key="a"      // string literals
        key=FEDA     // hex literals
        key="a".."b" // key range, can be open on either side, or inclusive with ..=
        key="a"*     // prefix match

    Timestamp filters:
        time=2023-01-01T00:00:00Z.. // open time range
    
    Scope filters:
        scope={{76dbdc2a2fbeace1986f7c48e33963c08086fc980ff6bd84070cf98887df6b8d}} // comma separated list of public keys

    Filters can only be combined with AND (&). You can have only one filter of each type.
        key="a"* & time=2023-01-01T00:00:00Z..
"#
                        );
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
