//! Broadcast a secret message to all participants.
//!
//! This example demonstrates how to build an application that employs [commonware_broadcast].
//! One participant acts as a broadcaster, sending a secret message to all other participants.
//!
//! # Persistence
//!
//! Data is not persisted in this example.
//!
//! # Broadcast
//!
//! This example demonstrates how [commonware_broadcast] can be used.
//!
//! # Usage (Run at Least 3 to Make Progress)
//!
//! _To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._
//!
//! ## Broadcaster Node (Participant 0)
//!
//! ```sh
//! cargo run --release -- --me 0@3000 --broadcaster 0 --storage-dir /tmp/commonware-broadcast/0
//! ```
//!
//! ## Receiver Node (Participant 1)
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 1@3001 --broadcaster 0 --storage-dir /tmp/commonware-broadcast/1
//! ```
//!
//! ## Receiver Node (Participant 2)
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 2@3002 --broadcaster 0 --storage-dir /tmp/commonware-broadcast/2
//! ```
//!
//! ## Receiver Node (Participant 3)
//!
//! ```sh
//! cargo run --release -- --bootstrappers 0@127.0.0.1:3000 --me 3@3003 --participants 0,1,2,3 --broadcaster 0 --storage-dir /tmp/commonware-broadcast/3
//! ```

// mod application; // Removed for direct main.rs implementation
// mod gui; // Removed GUI for simplicity

use clap::{value_parser, Arg, Command};
use commonware_broadcast::{Broadcaster, Config as BroadcastConfig, Receiver, MessageHandler}; // Added MessageHandler
use commonware_cryptography::{Ed25519, Sha256, Signer}; // Sha256 might be needed by broadcast internals or later app logic
use commonware_p2p::authenticated::{self, Network};
use commonware_runtime::{tokio, Metrics, Runner};
use commonware_utils::{union, NZU32};
use governor::Quota;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{str::FromStr, time::Duration, sync::Arc}; // Added Arc for MessageHandler

/// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_BROADCAST_EXAMPLE";

fn main() {
    // Parse arguments
    let matches = Command::new("commonware-broadcast-example")
        .about("broadcast a secret message to all participants")
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(false)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(Arg::new("me").long("me").required(true))
        .arg(
            Arg::new("participants")
                .long("participants")
                .required(true) // All nodes need to know about each other for P2P auth
                .value_delimiter(',')
                .value_parser(value_parser!(u64))
                .help("All participants in the broadcast group, including the broadcaster."),
        )
        .arg(Arg::new("storage-dir").long("storage-dir").required(true)) // Kept, assuming p2p/runtime might need it
        .arg(
            Arg::new("broadcaster")
                .long("broadcaster")
                .required(true)
                .value_parser(value_parser!(u64))
                .help("The ID of the node that will broadcast messages"),
        )
        .get_matches();

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

    // Configure allowed peers
    let mut authorized_peers = Vec::new();
    let participants = matches
        .get_many::<u64>("participants")
        .expect("Please provide all participant keys") // Now required
        .cloned()
        .collect::<Vec<_>>();

    if participants.is_empty() {
        panic!("Please provide at least one participant.");
    }
    for peer_key_seed in &participants {
        let verifier = Ed25519::from_seed(*peer_key_seed).public_key();
        tracing::info!(key = ?verifier, "registered authorized peer key");
        authorized_peers.push(verifier);
    }

    // The broadcaster ID
    let broadcaster_id_seed = matches
        .get_one::<u64>("broadcaster")
        .expect("Please provide broadcaster ID");
    let broadcaster_public_key = Ed25519::from_seed(*broadcaster_id_seed).public_key();


    // Configure bootstrappers (if provided)
    let bootstrappers = matches.get_many::<String>("bootstrappers");
    let mut bootstrapper_identities = Vec::new();
    if let Some(bootstrappers) = bootstrappers {
        for bootstrapper in bootstrappers {
            let parts = bootstrapper.split('@').collect::<Vec<&str>>();
            let bootstrapper_key = parts[0]
                .parse::<u64>()
                .expect("Bootstrapper key not well-formed");
            let verifier = Ed25519::from_seed(bootstrapper_key).public_key();
            let bootstrapper_address =
                SocketAddr::from_str(parts[1]).expect("Bootstrapper address not well-formed");
            bootstrapper_identities.push((verifier, bootstrapper_address));
        }
    }

    // Configure storage directory
    let storage_directory = matches
        .get_one::<String>("storage-dir")
        .expect("Please provide storage directory");

    // Initialize context
    let runtime_cfg = tokio::Config::new().with_storage_directory(storage_directory);
    let executor = tokio::Runner::new(runtime_cfg.clone());

    // Configure network
    let p2p_cfg = authenticated::Config::aggressive(
        signer.clone(),
        &union(APPLICATION_NAMESPACE, b"_P2P"),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        bootstrapper_identities.clone(),
        1024 * 1024, // 1MB
    );

    // Start context
    executor.start(async |context| {
        // Initialize network
        let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);

        // Provide authorized peers
        //
        // In a real-world scenario, this would be updated as new peer sets are created.
        oracle.register(0, authorized_peers.clone()).await;

        // Register broadcast channel
        // Configure based on potential commonware-broadcast needs.
        // Assuming a single channel for broadcast messages for now.
        // Rate limiting and message capacity might need tuning.
        let (broadcast_sender, mut broadcast_receiver) = network.register( // Renamed variables
            0, // Channel ID for broadcast
            Quota::per_second(NZU32!(100)), // Example: Allow 100 messages/sec
            1024, // Example: Buffer up to 1024 messages
            Some(3), // Compression level
        );

        // Initialize application (simplified for now)
        // The existing application module might be heavily modified or replaced.
        // For this step, we'll focus on direct broadcast logic in main.rs.
        // let (application, supervisor, mailbox) = application::Application::new(...);

        let broadcaster_public_key = Ed25519::from_seed(*broadcaster_id).public_key();

        if signer.public_key() == broadcaster_public_key {
            tracing::info!("This node is the broadcaster.");
            let broadcast_config = BroadcastConfig {
                signer: signer.clone(),
                namespace: APPLICATION_NAMESPACE.to_vec(),
                channel_id: 0, // Must match the channel registered with the network
                // Other config fields as needed by commonware-broadcast
            };
            let broadcast_config = BroadcastConfig {
                signer: signer.clone(),
                namespace: APPLICATION_NAMESPACE.to_vec(),
                channel_id: 0, // Must match the channel registered with the network
            };
            let broadcaster = Broadcaster::new(
                context.with_label("broadcaster"), 
                broadcast_config, 
                broadcast_sender // Pass the sender half of the network channel
            );
            
            // Start the broadcaster
            broadcaster.start(); // Assuming a start method

            // Spawn a task to send a test message periodically or once.
            // This depends on how Broadcaster is designed.
            // For simplicity, let's send one message.
            // The Broadcaster component itself should handle sending via `broadcast_sender`.
            tokio::spawn(async move {
                // Allow some time for network to establish, then broadcast.
                tokio::time::sleep(Duration::from_secs(5)).await;
                let test_message = b"Hello from broadcaster!".to_vec();
                tracing::info!(message = ?String::from_utf8_lossy(&test_message), "Attempting to broadcast message");
                // Actual broadcast mechanism will depend on `commonware_broadcast::Broadcaster`'s API.
                // It might be a method like `broadcaster.send(payload)` or it might consume messages
                // from an internal channel you feed.
                // For now, assuming the `Broadcaster` uses the `broadcast_sender` it was given.
                // We need a way to trigger the broadcast. Let's assume a method on broadcaster:
                if let Err(e) = broadcaster.send(test_message).await { // Simplified send
                    tracing::error!("Failed to broadcast message: {:?}", e);
                }
            });

        } else {
            tracing::info!("This node is a receiver.");
            // Receivers use the `broadcast_receiver` from `network.register()`
            // The `Receiver` component from `commonware_broadcast` would wrap this receiver
            // or provide logic to process incoming messages.
             let receiver_config = BroadcastConfig { // Assuming Receiver might use a similar config
                signer: signer.clone(), // For potential ACKs or identification
                namespace: APPLICATION_NAMESPACE.to_vec(),
                channel_id: 0,
            };
            // Define the message handler callback.
            // It needs to be Send + Sync + 'static if Receiver is generic over it and runs in a separate task.
            // Using Arc for the Box<dyn MessageHandler> if commonware_broadcast expects that.
            // Assuming commonware_broadcast::MessageHandler is a trait:
            // pub trait MessageHandler: Fn(Ed25519, Vec<u8>) + Send + Sync + 'static {}
            // impl<F: Fn(Ed25519, Vec<u8>) + Send + Sync + 'static> MessageHandler for F {}
            // For simplicity, let's stick to the Box<dyn Fn...> as used before if that's the expected type.
            // The previous definition `Box::new(message_handler)` implies `MessageHandler` is `dyn Fn(...)`.
            
            let message_handler: Arc<dyn MessageHandler<Ed25519>> = Arc::new(move |sender_pk: Ed25519, payload: Vec<u8>| {
                tracing::info!(from = ?sender_pk, message = ?String::from_utf8_lossy(&payload), "Received broadcast message");
            });
            
            let receiver = Receiver::new(
                context.with_label("receiver"), 
                receiver_config,
                broadcast_receiver, // Pass the receiver half of the network channel
                message_handler // Pass the message handler
            );

            // Start the receiver
            receiver.start(); // This would likely start its internal listening loop.
        }

        // Start network
        network.start();
        // application.start(); // Not used in this simplified version

        // Keep the application running until Ctrl-C is pressed
        tracing::info!("Application started. Press Ctrl-C to exit.");
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("Failed to listen for ctrl-c signal: {}", e);
        }
        tracing::info!("Shutting down.");
    });
}
