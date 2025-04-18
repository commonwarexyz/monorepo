use clap::{value_parser, Arg, Command};
use commonware_bridge::{
    types::{
        block::BlockFormat,
        inbound::{self, Inbound},
        outbound::Outbound,
    },
    APPLICATION_NAMESPACE, CONSENSUS_SUFFIX, INDEXER_NAMESPACE,
};
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::threshold_simplex::types::{Finalization, Viewable};
use commonware_cryptography::{
    bls12381::primitives::group::{self, Element, G1},
    sha256::Digest as Sha256Digest,
    Digest, Ed25519, Hasher, Sha256, Signer,
};
use commonware_runtime::{tokio::Executor, Listener, Metrics, Network, Runner, Spawner};
use commonware_stream::{
    public_key::{Config, Connection, IncomingConnection},
    Receiver, Sender,
};
use commonware_utils::{from_hex, union};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::{debug, info};

#[allow(clippy::large_enum_variant)]
enum Message<D: Digest> {
    PutBlock {
        incoming: inbound::PutBlock<D>,
        response: oneshot::Sender<bool>, // wait to broadcast consensus message
    },
    GetBlock {
        incoming: inbound::GetBlock<D>,
        response: oneshot::Sender<Option<BlockFormat<D>>>,
    },
    PutFinalization {
        incoming: inbound::PutFinalization<D>,
        response: oneshot::Sender<bool>, // wait to delete from validator storage
    },
    GetFinalization {
        incoming: inbound::GetFinalization,
        response: oneshot::Sender<Option<Finalization<D>>>,
    },
}

fn main() {
    // Parse arguments
    let matches = Command::new("indexer")
        .about("collect blocks and finality certificates")
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants"),
        )
        .arg(
            Arg::new("networks")
                .long("networks")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String))
                .help("All networks"),
        )
        .get_matches();

    // Create logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // Configure my identity
    let me = matches
        .get_one::<String>("me")
        .expect("Please provide identity");
    let parts = me.split('@').collect::<Vec<&str>>();
    if parts.len() != 2 {
        panic!("Identity not well-formed");
    }
    let key = parts[0].parse::<u64>().expect("Key not well-formed");
    let signer = Ed25519::from_seed(key);
    tracing::info!(key = ?signer.public_key(), "loaded signer");

    // Configure my port
    let port = parts[1].parse::<u16>().expect("Port not well-formed");
    tracing::info!(port, "loaded port");
    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    // Configure allowed peers
    let mut validators = HashSet::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide allowed keys")
        .copied();
    if participants.len() == 0 {
        panic!("Please provide at least one participant");
    }
    for peer in participants {
        let verifier = Ed25519::from_seed(peer).public_key();
        tracing::info!(key = ?verifier, "registered authorized key");
        validators.insert(verifier);
    }

    // Configure networks
    let mut namespaces: HashMap<G1, (G1, Vec<u8>)> = HashMap::new();
    let mut blocks: HashMap<G1, HashMap<Sha256Digest, BlockFormat<Sha256Digest>>> = HashMap::new();
    let mut finalizations: HashMap<G1, BTreeMap<u64, Finalization<Sha256Digest>>> = HashMap::new();
    let networks = matches
        .get_many::<String>("networks")
        .expect("Please provide networks");
    if networks.len() == 0 {
        panic!("Please provide at least one network");
    }
    for network in networks {
        let network = from_hex(network).expect("Network not well-formed");
        let public = group::Public::deserialize(&network).expect("Network not well-formed");
        let namespace = union(APPLICATION_NAMESPACE, CONSENSUS_SUFFIX);
        namespaces.insert(public, (public, namespace));
        blocks.insert(public, HashMap::new());
        finalizations.insert(public, BTreeMap::new());
    }

    // Create context
    let (executor, context) = Executor::default();
    executor.start(async move {
        // Create message handler
        let (handler, mut receiver) = mpsc::unbounded();

        // Start handler
        let mut hasher = Sha256::new();
        context.with_label("handler").spawn(|_| async move {
            while let Some(msg) = receiver.next().await {
                match msg {
                    Message::PutBlock { incoming, response } => {
                        // Ensure we care
                        let Some(network) = blocks.get_mut(&incoming.network) else {
                            let _ = response.send(false);
                            continue;
                        };

                        // Compute digest
                        hasher.update(&incoming.block.encode());
                        let digest = hasher.finalize();

                        // Store block
                        network.insert(digest, incoming.block);
                        let _ = response.send(true);
                        info!(
                            network = ?incoming.network,
                            block = ?digest,
                            "stored block"
                        );
                    }
                    Message::GetBlock { incoming, response } => {
                        let Some(network) = blocks.get(&incoming.network) else {
                            let _ = response.send(None);
                            continue;
                        };
                        let data = network.get(&incoming.digest);
                        let _ = response.send(data.cloned());
                    }
                    Message::PutFinalization { incoming, response } => {
                        // Ensure we care
                        let Some(network) = finalizations.get_mut(&incoming.network) else {
                            let _ = response.send(false);
                            continue;
                        };

                        // Verify signature
                        let Some((public, namespace)) = namespaces.get(&incoming.network) else {
                            let _ = response.send(false);
                            continue;
                        };
                        if !incoming.finalization.verify(namespace, public) {
                            let _ = response.send(false);
                            continue;
                        }

                        // Store finalization
                        let view = incoming.finalization.view();
                        network.insert(view, incoming.finalization);
                        let _ = response.send(true);
                        info!(
                            network = ?incoming.network,
                            view = view,
                            "stored finalization"
                        );
                    }
                    Message::GetFinalization { incoming, response } => {
                        // Ensure we care
                        let Some(network) = finalizations.get(&incoming.network) else {
                            let _ = response.send(None);
                            continue;
                        };

                        // Get latest finalization
                        let Some(data) = network.iter().next_back().map(|(_, data)| data.clone())
                        else {
                            let _ = response.send(None);
                            continue;
                        };
                        let _ = response.send(Some(data));
                    }
                }
            }
        });

        // Start listener
        let mut listener = context.bind(socket).await.expect("failed to bind listener");
        let config = Config {
            crypto: signer,
            namespace: INDEXER_NAMESPACE.to_vec(),
            max_message_size: 1024 * 1024,
            synchrony_bound: Duration::from_secs(1),
            max_handshake_age: Duration::from_secs(60),
            handshake_timeout: Duration::from_secs(5),
        };
        loop {
            // Listen for connection
            let Ok((_, sink, stream)) = listener.accept().await else {
                debug!("failed to accept connection");
                continue;
            };

            // Handshake
            let incoming =
                match IncomingConnection::verify(&context, config.clone(), sink, stream).await {
                    Ok(partial) => partial,
                    Err(e) => {
                        debug!(error = ?e, "failed to verify incoming handshake");
                        continue;
                    }
                };
            let peer = incoming.peer();
            if !validators.contains(&peer) {
                debug!(?peer, "unauthorized peer");
                continue;
            }
            let stream = match Connection::upgrade_listener(context.clone(), incoming).await {
                Ok(connection) => connection,
                Err(e) => {
                    debug!(error = ?e, ?peer, "failed to upgrade connection");
                    continue;
                }
            };
            info!(?peer, "upgraded connection");

            // Spawn message handler
            context.with_label("connection").spawn({
                let mut handler = handler.clone();
                move |_| async move {
                    // Split stream
                    let (mut sender, mut receiver) = stream.split();

                    // Handle messages
                    while let Ok(msg) = receiver.receive().await {
                        // Decode message
                        let msg = match Inbound::decode(msg) {
                            Ok(msg) => msg,
                            Err(err) => {
                                debug!(?err, ?peer, "failed to decode message");
                                return;
                            }
                        };

                        // Handle message
                        match msg {
                            Inbound::PutBlock(msg) => {
                                let (response, receiver) = oneshot::channel();
                                handler
                                    .send(Message::PutBlock {
                                        incoming: msg,
                                        response,
                                    })
                                    .await
                                    .expect("failed to send message");
                                let success = receiver.await.expect("failed to receive response");
                                let msg = Outbound::<Sha256Digest>::Success(success).encode();
                                if sender.send(&msg).await.is_err() {
                                    debug!(?peer, "failed to send message");
                                    return;
                                }
                            }
                            Inbound::GetBlock(msg) => {
                                let (response, receiver) = oneshot::channel();
                                handler
                                    .send(Message::GetBlock {
                                        incoming: msg,
                                        response,
                                    })
                                    .await
                                    .expect("failed to send message");
                                let response = receiver.await.expect("failed to receive response");
                                match response {
                                    Some(block) => {
                                        let msg = Outbound::Block(block).encode();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(?peer, "failed to send message");
                                            return;
                                        }
                                    }
                                    None => {
                                        let msg = Outbound::<Sha256Digest>::Success(false).encode();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(?peer, "failed to send message");
                                            return;
                                        }
                                    }
                                }
                            }
                            Inbound::PutFinalization(msg) => {
                                let (response, receiver) = oneshot::channel();
                                handler
                                    .send(Message::PutFinalization {
                                        incoming: msg,
                                        response,
                                    })
                                    .await
                                    .expect("failed to send message");
                                let success = receiver.await.expect("failed to receive response");
                                let msg = Outbound::<Sha256Digest>::Success(success).encode();
                                if sender.send(&msg).await.is_err() {
                                    debug!(?peer, "failed to send message");
                                    return;
                                }
                            }
                            Inbound::GetFinalization(msg) => {
                                let (response, receiver) = oneshot::channel();
                                handler
                                    .send(Message::GetFinalization {
                                        incoming: msg,
                                        response,
                                    })
                                    .await
                                    .expect("failed to send message");
                                let response = receiver.await.expect("failed to receive response");
                                match response {
                                    Some(data) => {
                                        let msg = Outbound::Finalization(data).encode();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(?peer, "failed to send message");
                                            return;
                                        }
                                    }
                                    None => {
                                        let msg = Outbound::<Sha256Digest>::Success(false).encode();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(?peer, "failed to send message");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
    });
}
