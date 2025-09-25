use std::{collections::BTreeMap, str::FromStr};

use bytes::Bytes;
use clap::Parser;
use iroh::{PublicKey, SecretKey, Watcher};
use iroh_base::ticket::NodeTicket;
use iroh_gossip::{net::Gossip, proto::TopicId};
use iroh_smol_kv::{
    Client, Config, Filter, Subscribe, SubscribeItem, SubscribeMode, SubscribeResponse,
    util::format_bytes,
};
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
    Put { key: Bytes, value: Bytes },
    /// /get key
    Get {
        scope: Option<PublicKey>,
        key: Bytes,
    },
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

async fn handle_subscription(id: usize, sub: SubscribeResponse) {
    let stream = sub.stream_raw();
    tokio::pin!(stream);
    while let Some(item) = stream.next().await {
        match item {
            Ok(SubscribeItem::Entry((scope, key, value))) => {
                println!(
                    "#{}: ({},{},{})",
                    id,
                    scope.fmt_short(),
                    format_bytes(&key),
                    format_bytes(&value.value)
                );
            }
            Ok(SubscribeItem::Expired((scope, key, timestamp))) => {
                println!(
                    "#{}: expired ({},{},{})",
                    id,
                    scope.fmt_short(),
                    format_bytes(&key),
                    timestamp,
                );
            }
            Ok(SubscribeItem::CurrentDone) => {}
            Err(e) => {
                println!("#{id}: Error in subscription: {e:?}");
                break;
            }
        }
    }
    println!("#{id} ended");
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
    println!("Joined the network, you can start issuing commands.");
    let api = Client::local(topic, Config::DEBUG);
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
                match Command::from_str(&line).unwrap_or(Command::Other { raw: line.clone() }) {
                    Command::Put { key, value } => {
                        println!("Put key: {}, value: {}", format_bytes(&key), format_bytes(&value));
                        ws.put(key, value).await.e()?;
                    }
                    Command::Get { scope, key } => {
                        let scope = scope.unwrap_or(node_id);
                        let res = api.get(scope, key.clone()).await.e()?;
                        println!("Get key: {} {}, value: {:?}", scope.fmt_short(), format_bytes(&key), res);
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
                            println!("#{id} ({},{},{})", s.fmt_short(), format_bytes(&k), format_bytes(&v));
                        }
                    }
                    Command::Subscribe { filter } => {
                        let id = next_op_id();
                        println!("#{id} Subscribe {filter}");
                        let sub = api.subscribe_with_opts(Subscribe {
                            filter,
                            mode: SubscribeMode::Both,
                        });
                        let task = tokio::spawn(handle_subscription(id, sub));
                        subscribers.insert(id, AbortOnDropHandle::new(task));
                    }
                    Command::Unsubscribe { id } => {
                        if let Some(handle) = subscribers.remove(&id) {
                            drop(handle); // Dropping the handle will abort the task
                            println!("#{id} unsubscribed");
                        } else {
                            println!("#{id} does not exist");
                        }
                    }
                    Command::Quit => {
                        println!("Bye!");
                        break;
                    }
                    Command::Help => {
                        println!(
r#"Available commands:
/set <key>=<value>       - Store a key-value pair
/get <key>               - Retrieve the value for a key in your own scope
/get <scope> <key>       - Retrieve the value for a key in a specific scope
/join <node_ticket>*     - Join peers by their node tickets
/iter <filter>?          - Iterate over key-value pairs with an optional filter
/subscribe <filter>?     - Subscribe to updates with an optional filter
/unsubscribe <id>        - Unsubscribe from a subscription by its ID
/quit                    - Exit the program
/help                    - Show this help message

Key and values can be specified as either:
    - String literals enclosed in double quotes (e.g., "my_key"), with support for escape sequences (\n, \t, \", \\)
    - Hexadecimal literals (e.g., FEDA)

Filter syntax:
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
                        println!("Unrecognized command: {raw}");
                    }
                }
            }
        }
    }
    // we need to exit because next_line hangs forever otherwise.
    std::process::exit(0);
}

mod command_parser {
    use std::str::FromStr;

    use bytes::Bytes;
    use iroh::PublicKey;
    use iroh_base::ticket::NodeTicket;
    use iroh_smol_kv::Filter;

    use super::Command;

    peg::parser! {
        grammar cmd_parser() for str {
            pub rule command() -> Command
                = _ cmd:(
                    set_cmd() / get_cmd() / join_cmd() / iter_cmd() /
                    subscribe_cmd() / unsubscribe_cmd() / quit_cmd() / help_cmd()
                ) _ { cmd }

            rule set_cmd() -> Command
                = "/set" _ key:key_value() _ "=" _ value:key_value() {
                    Command::Put {
                        key,
                        value,
                    }
                }

            rule get_cmd() -> Command
                = "/get" _ scope:public_key()? _ key:key_value() {
                    Command::Get {
                        scope,
                        key,
                    }
                }

            rule join_cmd() -> Command
                = "/join" _ peers:(peer_ticket() ** _) {
                    Command::Join { peers }
                }

            rule iter_cmd() -> Command
                = "/iter" _ filter_str:$([^'\n']*) {?
                    let filter = if filter_str.trim().is_empty() {
                        Filter::ALL
                    } else {
                        Filter::from_str(filter_str).map_err(|_| "invalid filter")?
                    };
                    Ok(Command::Iter { filter })
                }

            rule subscribe_cmd() -> Command
                = "/subscribe" _ filter_str:$([^'\n']*) {?
                    let filter = if filter_str.trim().is_empty() {
                        Filter::ALL
                    } else {
                        Filter::from_str(filter_str).map_err(|_| "invalid filter")?
                    };
                    Ok(Command::Subscribe { filter })
                }

            rule unsubscribe_cmd() -> Command
                = "/unsubscribe" _ id:number() { Command::Unsubscribe { id } }

            rule quit_cmd() -> Command
                = "/quit" { Command::Quit }

            rule help_cmd() -> Command
                = "/help" { Command::Help }

            // Reused string parsing from filter parser
            rule key_value() -> Bytes
                = quoted_string() / hex_bytes()

            rule quoted_string() -> Bytes
                = "\"" s:string_content() "\"" { Bytes::from(s) }

            rule string_content() -> String
                = chars:string_char()* { chars.into_iter().collect() }

            rule string_char() -> char
                = "\\\\" { '\\' }
                / "\\\"" { '"' }
                / "\\n" { '\n' }
                / "\\t" { '\t' }
                / "\\r" { '\r' }
                / c:$([_]) {?
                    let ch = c.chars().next().unwrap();
                    if ch == '"' || ch == '\\' {
                        Err("quote or backslash")
                    } else {
                        Ok(ch)
                    }
                }

            rule hex_bytes() -> Bytes
                = s:$(['0'..='9' | 'a'..='f' | 'A'..='F']+) {?
                    hex::decode(s)
                        .map(Bytes::from)
                        .map_err(|_| "invalid hex")
                }

            rule peer_ticket() -> NodeTicket
                = s:$([^ ' ' | '\t' | '\n' | '\r']+) {?
                    NodeTicket::from_str(s).map_err(|_| "invalid node ticket")
                }

            rule public_key() -> PublicKey
                = s:$([^ ' ' | '\t' | '\n' | '\r']+) {?
                    PublicKey::from_str(s).map_err(|_| "invalid public key")
                }

            rule number() -> usize
                = n:$(['0'..='9']+) {?
                    n.parse().map_err(|_| "invalid number")
                }

            rule _() = [' ' | '\t' | '\n' | '\r']*
        }
    }

    impl FromStr for Command {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            cmd_parser::command(s).map_err(|e| format!("Parse error: {e}"))
        }
    }
}
