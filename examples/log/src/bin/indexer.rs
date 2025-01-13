use bytes::Bytes;
use clap::{value_parser, Arg, Command};
use commonware_cryptography::{
    bls12381::primitives::group::{self, Element},
    Ed25519, Hasher, Scheme, Sha256,
};
use commonware_log::wire;
use commonware_runtime::{
    tokio::{Executor, Sink, Stream},
    Listener, Network, Runner, Spawner,
};
use commonware_stream::{
    public_key::{Config, Connection, IncomingConnection},
    Receiver, Sender,
};
use commonware_utils::{from_hex, hex};
use core::hash;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use prost::Message as _;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tracing::debug;

enum Message {
    PutBlock {
        incoming: wire::PutBlock,
        response: oneshot::Sender<bool>, // wait to broadcast consensus message
    },
    GetBlock {
        incoming: wire::GetBlock,
        response: oneshot::Sender<Bytes>,
    },
    PutFinalization {
        incoming: wire::PutFinalization,
        response: oneshot::Sender<bool>, // wait to delete from validator storage
    },
    GetFinalization {
        incoming: wire::GetFinalization,
        response: oneshot::Sender<Bytes>,
    },
}

fn main() {
    // Parse arguments
    let matches = Command::new("indexer")
        .about("collect blocks and signatures")
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
    tracing::info!(key = hex(&signer.public_key()), "loaded signer");

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
        tracing::info!(key = hex(&verifier), "registered authorized key",);
        validators.insert(verifier);
    }

    // Configure networks
    let mut blocks = HashMap::new();
    let mut finalizations = HashMap::new();
    let networks = matches
        .get_many::<String>("networks")
        .expect("Please provide networks");
    if networks.len() == 0 {
        panic!("Please provide at least one network");
    }
    for network in networks {
        let network = from_hex(network).expect("Network not well-formed");
        group::Public::deserialize(&network).expect("Network not well-formed");
        blocks.insert(network, HashMap::new());
        finalizations.insert(network, HashMap::new());
    }

    // Create runtime
    let hasher = Sha256::new();
    let (executor, runtime) = Executor::default();
    executor.start(async move {
        // Create message handler
        let (handler, mut receiver) = mpsc::unbounded();

        // Start handler
        runtime.spawn("handler", async move {
            while let Some(msg) = receiver.next().await {
                match msg {
                    Message::PutBlock { incoming, response } => {
                        let Some(network) = blocks.get_mut(&incoming.network) else {
                            let _ = response.send(false);
                            continue;
                        };
                        hasher.update(&incoming.data);
                        let digest = hasher.finalize();
                        network.insert(digest, incoming.data);
                        let _ = response.send(true);
                        debug!(
                            network = hex(&incoming.network),
                            block = hex(&digest),
                            "stored"
                        );
                    }
                    Message::GetBlock { incoming, response } => {
                        debug!("received GetBlock");
                        let msg = Bytes::from("block");
                        let _ = response.send(msg);
                    }
                    Message::PutFinalization { incoming, response } => {
                        debug!("received PutFinalization");
                    }
                    Message::GetFinalization { incoming, response } => {
                        debug!("received GetFinalization");
                        let msg = Bytes::from("finalization");
                        let _ = response.send(msg);
                    }
                }
            }
        });

        // Start listener
        runtime.spawn("listener", {
            let runtime = runtime.clone();
            async move {
                let mut listener = runtime.bind(socket).await.expect("failed to bind listener");
                let config = Config {
                    crypto: signer,
                    namespace: b"INDEXER".to_vec(),
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
                        match IncomingConnection::verify(&runtime, config.clone(), sink, stream)
                            .await
                        {
                            Ok(partial) => partial,
                            Err(e) => {
                                debug!(error = ?e, "failed to verify incoming handshake");
                                continue;
                            }
                        };
                    let peer = incoming.peer();
                    if !validators.contains(&peer) {
                        debug!(peer = hex(&peer), "unauthorized peer");
                        continue;
                    }
                    let stream = match Connection::upgrade_listener(runtime.clone(), incoming).await
                    {
                        Ok(connection) => connection,
                        Err(e) => {
                            debug!(error = ?e, peer=hex(&peer), "failed to upgrade connection");
                            continue;
                        }
                    };
                    debug!(peer = hex(&peer), "upgraded connection");

                    // Spawn message handler
                    runtime.spawn("connection", {
                        let handler = handler.clone();
                        async move {
                            // Split stream
                            let (sender, mut receiver) = stream.split();

                            // Handle messages
                            while let Ok(msg) = receiver.receive().await {
                                // Decode message
                                let Ok(msg) = wire::Inbound::decode(msg) else {
                                    debug!(peer = hex(&peer), "failed to decode message");
                                    return;
                                };
                                let Some(payload) = msg.payload else {
                                    debug!(peer = hex(&peer), "failed to decode payload");
                                    return;
                                };

                                // Handle message
                                match payload {
                                    wire::inbound::Payload::PutBlock(msg) => {
                                        let (response, receiver) = oneshot::channel();
                                        handler
                                            .send(Message::PutBlock {
                                                incoming: msg,
                                                response,
                                            })
                                            .await
                                            .expect("failed to send message");
                                        let success =
                                            receiver.await.expect("failed to receive response");
                                        let msg = wire::Outbound {
                                            payload: Some(wire::outbound::Payload::Success(
                                                success,
                                            )),
                                        }
                                        .encode_to_vec();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(peer = hex(&peer), "failed to send message");
                                            return;
                                        }
                                    }
                                    wire::inbound::Payload::GetBlock(msg) => {
                                        let (response, receiver) = oneshot::channel();
                                        handler
                                            .send(Message::GetBlock {
                                                incoming: msg,
                                                response,
                                            })
                                            .await
                                            .expect("failed to send message");
                                        let response =
                                            receiver.await.expect("failed to receive response");
                                        let msg = wire::Outbound {
                                            payload: Some(wire::outbound::Payload::Block(
                                                response.into(),
                                            )),
                                        }
                                        .encode_to_vec();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(peer = hex(&peer), "failed to send message");
                                            return;
                                        }
                                    }
                                    wire::inbound::Payload::PutFinalization(msg) => {
                                        let (response, receiver) = oneshot::channel();
                                        handler
                                            .send(Message::PutFinalization {
                                                incoming: msg,
                                                response,
                                            })
                                            .await
                                            .expect("failed to send message");
                                        let success =
                                            receiver.await.expect("failed to receive response");
                                        let msg = wire::Outbound {
                                            payload: Some(wire::outbound::Payload::Success(
                                                success,
                                            )),
                                        }
                                        .encode_to_vec();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(peer = hex(&peer), "failed to send message");
                                            return;
                                        }
                                    }
                                    wire::inbound::Payload::GetFinalization(msg) => {
                                        let (response, receiver) = oneshot::channel();
                                        handler
                                            .send(Message::GetFinalization {
                                                incoming: msg,
                                                response,
                                            })
                                            .await
                                            .expect("failed to send message");
                                        let response =
                                            receiver.await.expect("failed to receive response");
                                        let msg = wire::Outbound {
                                            payload: Some(wire::outbound::Payload::Finalization(
                                                response.into(),
                                            )),
                                        }
                                        .encode_to_vec();
                                        if sender.send(&msg).await.is_err() {
                                            debug!(peer = hex(&peer), "failed to send message");
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        });
    });
}
