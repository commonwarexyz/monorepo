//! Communicate with a fixed set of authenticated peers without known addresses over encrypted connections.
//!
//! `discovery` provides multiplexed communication between fully-connected peers
//! identified by a developer-specified cryptographic identity (i.e. BLS, ed25519, etc.).
//! Peer discovery occurs automatically using ordered bit vectors (sorted by authorized
//! cryptographic identities) to efficiently communicate knowledge of dialable peers.
//!
//! # Features
//!
//! - Configurable Cryptography Scheme for Peer Identities (BLS, ed25519, etc.)
//! - Automatic Peer Discovery Using Bit Vectors (Also Used as Ping Messages)
//! - Multiplexing With Configurable Rate Limiting Per Channel and Send Prioritization
//!
//! # Design
//!
//! ## Discovery
//!
//! Peer discovery operates under the assumption that all peers are aware of and synchronized on
//! the composition of peer sets at specific, user-provided indices (`u64`). Each index maps to a
//! list of authorized `PublicKey`s (`(u64, Vec<PublicKey>)`). Based on this shared knowledge, each
//! peer can construct a sorted bit vector message (`BitVec`) representing its knowledge of the
//! dialable addresses [std::net::SocketAddr] for the peers in that set.
//! The `BitVec` message contains:
//! - `index`: The `u64` index the bit vector applies to.
//! - `bits`: The bit vector itself, where a '1' signifies knowledge of the corresponding
//!   peer's address in the sorted list for that index.
//!
//! Even if a peer has some knowledge of the address of a peer in the set, if they fail to dial that
//! peer a (configurable) number of times, they will assume that information is stale and mark it as
//! '0' (unknown) in the bit vector. This is done to prevent peers from being "stuck" with outdated
//! information about other peers.
//!
//! _Warning: If peers are not synchronized on the peer set composition at a given index,
//! discovery messages can be misinterpreted. A peer might associate a bit vector index with the
//! wrong peer or fail to parse the vector if its length doesn't match the expected set size. The
//! application layer is responsible for ensuring peer set synchronization._
//!
//! Due to their small size, these `BitVec` messages are exchanged periodically (configured by
//! `gossip_bit_vec_frequency` in the [Config]) between connected peers. This serves as both a
//! peer discovery mechanism and a keep-alive "ping" message to maintain the underlying
//! connection, especially during periods of low application-level traffic. The protocol supports
//! tracking multiple peer sets concurrently (up to `tracked_peer_sets`), each identified by its
//! `index`. This is useful, for instance, during transitions like distributed key generation
//! (DKG) where connections to both old and new peer sets are needed simultaneously.
//!
//! Upon receiving a `BitVec` message, a peer compares it against its own knowledge for the same
//! index. If the receiving peer knows addresses that the sender marked as '0' (unknown), it
//! selects a random subset of these known `Info` structures (up to `peer_gossip_max_count`)
//! and sends them back in a `Payload::Peers` message. To save bandwidth, peers will only gossip
//! `Info` for peers that they currently have a connection with. This prevents them from
//! repeatedly sending `Info` that they cannot verify is still valid. Each `Info` contains:
//! - `socket`: The [std::net::SocketAddr] of the peer.
//! - `timestamp`: A `u64` timestamp indicating when the address was attested.
//! - `public_key`: The peer's public key.
//! - `signature`: The peer's cryptographic signature over the `socket` and `timestamp`.
//!
//! If the receiver doesn't know any addresses the sender is unaware of, it sends no
//! `Payload::Peers` response; the received `BitVec` implicitly acts as a "pong".
//!
//! If a peer receives a `Info` message (either directly or through gossip) containing a more
//! recent timestamp for a known peer's address, it updates its local `Record`. This updated
//! `Info` is also used in future gossip messages. Each peer generates its own signed
//! `Info` upon startup and sends it immediately after establishing a connection (following
//! the cryptographic handshake). This ensures that if a peer connects using an outdated address
//! record, it will be corrected promptly by the peer being dialed.
//!
//! To initiate the discovery process, a peer needs a list of `bootstrappers` (defined in
//! [Config]) - known peer public keys and their corresponding socket addresses. The peer
//! attempts to dial these bootstrappers, performs the handshake, sends its own `Info`, and
//! then sends a `BitVec` for the relevant peer set(s) (initially only knowing its own address,
//! marked as '1'). It then waits for responses, learning about other peers through the
//! `Payload::Peers` messages received. Bootstrapper information is persisted, and connections to
//! them are maintained even if they aren't part of any currently tracked peer sets. Different
//! peers can have different bootstrapper lists.
//!
//! _Note: If a peer (listener) receives a connection request from another peer (dialer) that
//! belongs to a registered peer set, the listener will accept the connection, even if the
//! listener itself hasn't yet learned about that specific peer set (or has an older version). The
//! core requirement is that the listener recognizes the *dialer's public key* as belonging to
//! *some* authorized set it tracks (see `actors::tracker::Actor`). This mechanism allows peers
//! with more up-to-date peer set information to connect and propagate that information, enabling
//! the listener to potentially learn about newer sets it is part of._
//!
//! ## Messages
//!
//! Application-level data is exchanged using the `Payload::Data` message type, which wraps an
//! internal `Data` structure. This structure contains:
//! - `channel`: A `u32` identifier used to route the message to the correct application handler.
//! - `message`: The arbitrary application payload as `Bytes`.
//!
//! The size of the `message` bytes must not exceed the configured
//! `max_message_size`. If it does, the sending operation will fail with
//! [Error::MessageTooLarge]. Messages can be sent with `priority`, allowing certain
//! communications to potentially bypass lower-priority messages waiting in send queues across all
//! channels. Each registered channel ([Sender], [Receiver]) handles its own message queuing
//! and rate limiting.
//!
//! ## Compression
//!
//! Stream compression is not provided at the transport layer to avoid inadvertently
//! enabling known attacks such as BREACH and CRIME. These attacks exploit the interaction
//! between compression and encryption by analyzing patterns in the resulting data.
//! By compressing secrets alongside attacker-controlled content, these attacks can infer
//! sensitive information through compression ratio analysis. Applications that choose
//! to compress data should do so with full awareness of these risks and implement
//! appropriate mitigations (such as ensuring no attacker-controlled data is compressed
//! alongside sensitive information).
//!
//! ## Rate Limiting
//!
//! There are five primary rate limits:
//!
//! - `max_concurrent_handshakes`: The maximum number of concurrent handshake attempts allowed.
//! - `allowed_handshake_rate_per_ip`: The rate limit for handshake attempts originating from a single IP address.
//! - `allowed_handshake_rate_per_subnet`: The rate limit for handshake attempts originating from a single IP subnet.
//! - `allowed_connection_rate_per_peer`: The rate limit for connections to a single peer (incoming or outgoing).
//! - `rate` (per channel): The rate limit for messages sent on a single channel.
//!
//! _Users should consider these rate limits as best-effort protection against moderate abuse. Targeted abuse (e.g. DDoS)
//! must be mitigated with an external proxy (that limits inbound connection attempts to authorized IPs)._
//!
//! # Example
//!
//! ```rust
//! use commonware_p2p::{authenticated::discovery::{self, Network}, Manager, Sender, Recipients};
//! use commonware_cryptography::{ed25519, Signer, PrivateKey as _, PublicKey as _, PrivateKeyExt as _};
//! use commonware_runtime::{deterministic, Spawner, Runner, Metrics};
//! use commonware_utils::NZU32;
//! use governor::Quota;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//!
//! // Configure context
//! let runtime_cfg = deterministic::Config::default();
//! let runner = deterministic::Runner::new(runtime_cfg.clone());
//!
//! // Generate identity
//! //
//! // In production, the signer should be generated from a secure source of entropy.
//! let signer = ed25519::PrivateKey::from_seed(0);
//!
//! // Generate peers
//! //
//! // In production, peer identities will be provided by some external source of truth
//! // (like the staking set of a blockchain).
//! let peer1 = ed25519::PrivateKey::from_seed(1).public_key();
//! let peer2 = ed25519::PrivateKey::from_seed(2).public_key();
//! let peer3 = ed25519::PrivateKey::from_seed(3).public_key();
//!
//! // Configure bootstrappers
//! //
//! // In production, it is likely that the address of bootstrappers will be some public address.
//! let bootstrappers = vec![(peer1.clone(), SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001))];
//!
//! // Configure namespace
//! //
//! // In production, use a unique application namespace to prevent cryptographic replay attacks.
//! let application_namespace = b"my-app-namespace";
//!
//! // Configure network
//! //
//! // In production, use a more conservative configuration like `Config::recommended`.
//! const MAX_MESSAGE_SIZE: usize = 1_024; // 1KB
//! let p2p_cfg = discovery::Config::local(
//!     signer.clone(),
//!     application_namespace,
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
//!     SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3000), // Use a specific dialable addr
//!     bootstrappers,
//!     MAX_MESSAGE_SIZE,
//! );
//!
//! // Start context
//! runner.start(|context| async move {
//!     // Initialize network
//!     let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);
//!
//!     // Register authorized peers
//!     //
//!     // In production, this would be updated as new peer sets are created (like when
//!     // the composition of a validator set changes).
//!     oracle.update(0, [signer.public_key(), peer1, peer2, peer3].try_into().unwrap()).await;
//!
//!     // Register some channel
//!     const MAX_MESSAGE_BACKLOG: usize = 128;
//!     let (mut sender, receiver) = network.register(
//!         0,
//!         Quota::per_second(NZU32!(1)),
//!         MAX_MESSAGE_BACKLOG,
//!     );
//!
//!     // Run network
//!     network.start();
//!
//!     // Example: Use sender
//!     let _ = sender.send(Recipients::All, bytes::Bytes::from_static(b"hello"), false).await;
//!
//!     // Graceful shutdown (stops all spawned tasks)
//!     context.stop(0, None).await.unwrap();
//! });
//! ```

mod actors;
mod channels;
mod config;
mod metrics;
mod network;
mod types;

use thiserror::Error;

/// Errors that can occur when interacting with the network.
#[derive(Error, Debug)]
pub enum Error {
    #[error("message too large: {0}")]
    MessageTooLarge(usize),
    #[error("network closed")]
    NetworkClosed,
}

pub use actors::tracker::Oracle;
pub use channels::{Receiver, Sender};
pub use config::{Bootstrapper, Config};
pub use network::Network;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Manager, Receiver, Recipients, Sender};
    use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
    use commonware_macros::{select, select_loop, test_group, test_traced};
    use commonware_runtime::{
        deterministic, tokio, Clock, Metrics, Network as RNetwork, Runner, Spawner,
    };
    use commonware_utils::{ordered::Set, TryCollect, NZU32};
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use governor::{clock::ReasonablyRealtime, Quota};
    use rand::{CryptoRng, Rng};
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    #[derive(Copy, Clone)]
    enum Mode {
        All,
        Some,
        One,
    }

    const DEFAULT_MESSAGE_BACKLOG: usize = 128;

    /// Ensure no message rate limiting occurred.
    ///
    /// If a message is rate limited, it would be formatted as:
    ///
    /// ```text
    /// peer-9_network_spawner_messages_rate_limited_total{peer="e2e8aa145e1ec5cb01ebfaa40e10e12f0230c832fd8135470c001cb86d77de00",message="data_0"} 1
    /// peer-9_network_spawner_messages_rate_limited_total{peer="e2e8aa145e1ec5cb01ebfaa40e10e12f0230c832fd8135470c001cb86d77de00",message="ping"} 1
    /// ```
    fn assert_no_rate_limiting(context: &impl Metrics) {
        let metrics = context.encode();
        assert!(
            !metrics.contains("messages_rate_limited_total{"),
            "no messages should be rate limited: {metrics}"
        );
    }

    /// Test connectivity between `n` peers.
    ///
    /// We set a unique `base_port` for each test to avoid "address already in use"
    /// errors when tests are run immediately after each other.
    async fn run_network(
        context: impl Spawner + Clock + ReasonablyRealtime + Rng + CryptoRng + RNetwork + Metrics,
        max_message_size: usize,
        base_port: u16,
        n: usize,
        mode: Mode,
    ) {
        // Create peers
        let mut peers = Vec::new();
        for i in 0..n {
            peers.push(ed25519::PrivateKey::from_seed(i as u64));
        }
        let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

        // Create networks
        let (complete_sender, mut complete_receiver) = mpsc::channel(peers.len());
        for (i, peer) in peers.iter().enumerate() {
            // Create peer context
            let context = context.with_label(&format!("peer-{i}"));

            // Derive port
            let port = base_port + i as u16;

            // Create bootstrappers
            let mut bootstrappers = Vec::new();
            if i > 0 {
                bootstrappers.push((
                    addresses[0].clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                ));
            }

            // Create network
            let signer = peer.clone();
            let config = Config::test(
                signer.clone(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                bootstrappers,
                max_message_size,
            );
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

            // Register peers
            oracle
                .update(0, addresses.clone().try_into().unwrap())
                .await;

            // Register basic application
            let (mut sender, mut receiver) =
                network.register(0, Quota::per_second(NZU32!(100)), DEFAULT_MESSAGE_BACKLOG);

            // Wait to connect to all peers, and then send messages to everyone
            network.start();

            // Send/Receive messages
            context.with_label("agent").spawn({
                let mut complete_sender = complete_sender.clone();
                let addresses = addresses.clone();
                move |context| async move {
                    // Wait for all peers to send their identity
                    let receiver = context.with_label("receiver").spawn(move |_| async move {
                        // Wait for all peers to send their identity
                        let mut received = HashSet::new();
                        while received.len() < n - 1 {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender.as_ref(), message.as_ref());

                            // Add to received set
                            received.insert(sender);
                        }
                        complete_sender.send(()).await.unwrap();

                        // Process messages until all finished (or else sender loops could get stuck as a peer may drop)
                        loop {
                            receiver.recv().await.unwrap();
                        }
                    });

                    // Send identity to all peers
                    let msg = signer.public_key();
                    let sender = context
                        .with_label("sender")
                        .spawn(move |context| async move {
                            // Loop forever to account for unexpected message drops
                            loop {
                                match mode {
                                    Mode::One => {
                                        for (j, recipient) in addresses.iter().enumerate() {
                                            // Don't send message to self
                                            if i == j {
                                                continue;
                                            }

                                            // Loop until success
                                            loop {
                                                let sent = sender
                                                    .send(
                                                        Recipients::One(recipient.clone()),
                                                        msg.to_vec().into(),
                                                        true,
                                                    )
                                                    .await
                                                    .unwrap();
                                                if sent.len() != 1 {
                                                    context.sleep(Duration::from_millis(100)).await;
                                                    continue;
                                                }
                                                assert_eq!(&sent[0], recipient);
                                                break;
                                            }
                                        }
                                    }
                                    Mode::Some => {
                                        // Get all peers not including self
                                        let mut recipients = addresses.clone();
                                        recipients.remove(i);
                                        recipients.sort();

                                        // Loop until all peer sends successful
                                        loop {
                                            let mut sent = sender
                                                .send(
                                                    Recipients::Some(recipients.clone()),
                                                    msg.to_vec().into(),
                                                    true,
                                                )
                                                .await
                                                .unwrap();
                                            if sent.len() != n - 1 {
                                                context.sleep(Duration::from_millis(100)).await;
                                                continue;
                                            }

                                            // Compare to expected
                                            sent.sort();
                                            assert_eq!(sent, recipients);
                                            break;
                                        }
                                    }
                                    Mode::All => {
                                        // Get all peers not including self
                                        let mut recipients = addresses.clone();
                                        recipients.remove(i);
                                        recipients.sort();

                                        // Loop until all peer sends successful
                                        loop {
                                            let mut sent = sender
                                                .send(Recipients::All, msg.to_vec().into(), true)
                                                .await
                                                .unwrap();
                                            if sent.len() != n - 1 {
                                                context.sleep(Duration::from_millis(100)).await;
                                                continue;
                                            }

                                            // Compare to expected
                                            sent.sort();
                                            assert_eq!(sent, recipients);
                                            break;
                                        }
                                    }
                                };

                                // Sleep to avoid busy loop
                                context.sleep(Duration::from_secs(10)).await;
                            }
                        });

                    // Neither task should exit
                    select! {
                        receiver = receiver => {
                            panic!("receiver exited: {receiver:?}");
                        },
                        sender = sender => {
                            panic!("sender exited: {sender:?}");
                        },
                    }
                }
            });
        }

        // Wait for all peers to finish
        for _ in 0..n {
            complete_receiver.next().await.unwrap();
        }

        // Ensure no message rate limiting occurred
        assert_no_rate_limiting(&context);
    }

    fn run_deterministic_test(seed: u64, mode: Mode) {
        // Configure test
        const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
        const NUM_PEERS: usize = 25;
        const BASE_PORT: u16 = 3000;

        // Run first instance
        let executor = deterministic::Runner::seeded(seed);
        let state = executor.start(|context| async move {
            run_network(
                context.clone(),
                MAX_MESSAGE_SIZE,
                BASE_PORT,
                NUM_PEERS,
                mode,
            )
            .await;
            context.auditor().state()
        });

        // Compare result to second instance
        let executor = deterministic::Runner::seeded(seed);
        let state2 = executor.start(|context| async move {
            run_network(
                context.clone(),
                MAX_MESSAGE_SIZE,
                BASE_PORT,
                NUM_PEERS,
                mode,
            )
            .await;
            context.auditor().state()
        });
        assert_eq!(state, state2);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism_one() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::One);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism_some() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::Some);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism_all() {
        for i in 0..10 {
            run_deterministic_test(i, Mode::All);
        }
    }

    #[test_traced]
    fn test_tokio_connectivity() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            const MAX_MESSAGE_SIZE: usize = 1_024 * 1_024; // 1MB
            let base_port = 3000;
            let n = 10;
            run_network(context, MAX_MESSAGE_SIZE, base_port, n, Mode::One).await;
        });
    }

    #[test_traced]
    fn test_multi_index_oracle() {
        // Configure test
        let base_port = 3000;
        let n: usize = 100;

        // Initialize context
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(ed25519::PrivateKey::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create networks
            let mut waiters = Vec::new();
            for (i, peer) in peers.iter().enumerate() {
                // Create peer context
                let context = context.with_label(&format!("peer-{i}"));

                // Derive port
                let port = base_port + i as u16;

                // Create bootstrappers
                let mut bootstrappers = Vec::new();
                if i > 0 {
                    bootstrappers.push((
                        addresses[0].clone(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                    ));
                }

                // Create network
                let signer = peer.clone();
                let config = Config::test(
                    signer.clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    bootstrappers,
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

                // Register peers at separate indices
                oracle
                    .update(0, [addresses[0].clone()].try_into().unwrap())
                    .await;
                oracle
                    .update(
                        1,
                        [addresses[1].clone(), addresses[2].clone()]
                            .try_into()
                            .unwrap(),
                    )
                    .await;
                oracle
                    .update(2, addresses.iter().skip(2).cloned().try_collect().unwrap())
                    .await;

                // Register basic application
                let (mut sender, mut receiver) =
                    network.register(0, Quota::per_second(NZU32!(10)), DEFAULT_MESSAGE_BACKLOG);

                // Wait to connect to all peers, and then send messages to everyone
                network.start();

                // Send/Receive messages
                let handler = context
                    .with_label("agent")
                    .spawn(move |context| async move {
                        if i == 0 {
                            // Loop until success
                            let msg = signer.public_key();
                            loop {
                                if sender
                                    .send(Recipients::All, msg.to_vec().into(), true)
                                    .await
                                    .unwrap()
                                    .len()
                                    == n - 1
                                {
                                    break;
                                }

                                // Sleep and try again (avoid busy loop)
                                context.sleep(Duration::from_millis(100)).await;
                            }
                        } else {
                            // Ensure message equals sender identity
                            let (sender, message) = receiver.recv().await.unwrap();
                            assert_eq!(sender.as_ref(), message.as_ref());
                        }
                    });

                // Add to waiters
                waiters.push(handler);
            }

            // Wait for waiters to finish (receiver before sender)
            for waiter in waiters.into_iter().rev() {
                waiter.await.unwrap();
            }

            // Ensure no message rate limiting occurred
            assert_no_rate_limiting(&context);
        });
    }

    #[test_traced]
    fn test_message_too_large() {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize context
        let executor = deterministic::Runner::seeded(0);
        executor.start(|mut context| async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(ed25519::PrivateKey::from_seed(i as u64));
            }
            let addresses: Set<_> = peers.iter().map(|p| p.public_key()).try_collect().unwrap();

            // Create network
            let signer = peers[0].clone();
            let config = Config::test(
                signer.clone(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                Vec::new(),
                1_024 * 1_024, // 1MB
            );
            let (mut network, mut oracle) = Network::new(context.with_label("network"), config);

            // Register peers
            oracle.update(0, addresses.clone()).await;

            // Register basic application
            let (mut sender, _) =
                network.register(0, Quota::per_second(NZU32!(10)), DEFAULT_MESSAGE_BACKLOG);

            // Wait to connect to all peers, and then send messages to everyone
            network.start();

            // Crate random message
            let mut msg = vec![0u8; 10 * 1024 * 1024]; // 10MB (greater than frame capacity)
            context.fill(&mut msg[..]);

            // Send message
            let recipient = Recipients::One(addresses[1].clone());
            let result = sender.send(recipient, msg.into(), true).await;
            assert!(matches!(result, Err(Error::MessageTooLarge(_))));
        });
    }

    #[test_traced]
    #[should_panic(expected = "no messages should be rate limited")]
    fn test_rate_limiting() {
        // Configure test
        let base_port = 3000;
        let n: usize = 2;

        // Initialize context
        let executor = deterministic::Runner::seeded(0);
        executor.start(|context| async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(ed25519::PrivateKey::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();
            let socket0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port);
            let socket1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + 1);

            // Create network for peer 0
            let signer0 = peers[0].clone();
            let config0 = Config::test(
                signer0.clone(),
                socket0,
                vec![(peers[1].public_key(), socket1)],
                1_024 * 1_024, // 1MB
            );
            let (mut network0, mut oracle0) = Network::new(context.with_label("peer-0"), config0);
            oracle0
                .update(0, addresses.clone().try_into().unwrap())
                .await;
            let (mut sender0, _receiver0) =
                network0.register(0, Quota::per_hour(NZU32!(1)), DEFAULT_MESSAGE_BACKLOG);
            network0.start();

            // Create network for peer 1
            let signer1 = peers[1].clone();
            let config1 = Config::test(
                signer1.clone(),
                socket1,
                vec![(peers[0].public_key(), socket0)],
                1_024 * 1_024, // 1MB
            );
            let (mut network1, mut oracle1) = Network::new(context.with_label("peer-1"), config1);
            oracle1
                .update(0, addresses.clone().try_into().unwrap())
                .await;
            let (_sender1, _receiver1) =
                network1.register(0, Quota::per_hour(NZU32!(1)), DEFAULT_MESSAGE_BACKLOG);
            network1.start();

            // Send first message, which should be allowed and consume the quota.
            let msg = vec![0u8; 1024]; // 1KB
            loop {
                // Confirm message is sent to peer
                let sent = sender0
                    .send(
                        Recipients::One(addresses[1].clone()),
                        msg.clone().into(),
                        true,
                    )
                    .await
                    .unwrap();
                if !sent.is_empty() {
                    break;
                }

                // Sleep and try again (avoid busy loop)
                context.sleep(Duration::from_millis(100)).await;
            }

            // Immediately send the second message to trigger the rate limit.
            let sent = sender0
                .send(Recipients::One(addresses[1].clone()), msg.into(), true)
                .await
                .unwrap();
            assert!(!sent.is_empty());

            // Loop until the metrics reflect the rate-limited message.
            for _ in 0..10 {
                assert_no_rate_limiting(&context);
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    #[test_traced]
    fn test_unordered_peer_sets() {
        let (n, base_port) = (10, 3000);
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create peers
            let mut peers_and_sks = Vec::new();
            for i in 0..n {
                let sk = ed25519::PrivateKey::from_seed(i as u64);
                let pk = sk.public_key();
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + i as u16);
                peers_and_sks.push((sk, pk, addr));
            }
            let peer0 = peers_and_sks[0].clone();
            let config = Config::test(
                peer0.0,
                peer0.2,
                vec![(peer0.1.clone(), peer0.2)],
                1_024 * 1_024,
            );
            let (network, mut oracle) = Network::new(context.with_label("network"), config);
            network.start();

            // Subscribe to peer sets
            let mut subscription = oracle.subscribe().await;

            // Register initial peer set
            let set10: Set<_> = peers_and_sks
                .iter()
                .take(2)
                .map(|(_, pk, _)| pk.clone())
                .try_collect()
                .unwrap();
            oracle.update(10, set10.clone()).await;
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 10);
            assert_eq!(new, set10);
            assert_eq!(all, set10);

            // Register old peer sets (ignored)
            let set9: Set<_> = peers_and_sks
                .iter()
                .skip(2)
                .map(|(_, pk, _)| pk.clone())
                .try_collect()
                .unwrap();
            oracle.update(9, set9.clone()).await;

            // Add new peer set
            let set11: Set<_> = peers_and_sks
                .iter()
                .skip(4)
                .map(|(_, pk, _)| pk.clone())
                .try_collect()
                .unwrap();
            oracle.update(11, set11.clone()).await;
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 11);
            assert_eq!(new, set11);
            let all_keys: Set<_> = set10
                .into_iter()
                .chain(set11.into_iter())
                .try_collect()
                .unwrap();
            assert_eq!(all, all_keys);
        });
    }

    #[test_traced]
    fn test_graceful_shutdown() {
        let base_port = 3000;
        let n: usize = 5;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create peers
            let mut peers = Vec::new();
            for i in 0..n {
                peers.push(ed25519::PrivateKey::from_seed(i as u64));
            }
            let addresses = peers.iter().map(|p| p.public_key()).collect::<Vec<_>>();

            // Create networks for all peers
            let (complete_sender, mut complete_receiver) = mpsc::channel(n);
            for (i, peer) in peers.iter().enumerate() {
                let peer_context = context.with_label(&format!("peer-{i}"));
                let port = base_port + i as u16;

                // Create bootstrappers (everyone connects to peer 0)
                let mut bootstrappers = Vec::new();
                if i > 0 {
                    bootstrappers.push((
                        addresses[0].clone(),
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port),
                    ));
                }

                let signer = peer.clone();
                let config = Config::test(
                    signer.clone(),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                    bootstrappers,
                    1_024 * 1_024, // 1MB
                );
                let (mut network, mut oracle) =
                    Network::new(peer_context.with_label("network"), config);

                // Register peer set
                oracle
                    .update(0, addresses.clone().try_into().unwrap())
                    .await;

                let (mut sender, mut receiver) =
                    network.register(0, Quota::per_second(NZU32!(100)), DEFAULT_MESSAGE_BACKLOG);
                network.start();

                peer_context.with_label("agent").spawn({
                    let mut complete_sender = complete_sender.clone();
                    move |context| async move {
                        // Wait to connect to at least one other peer (except for peer 0 which is the bootstrapper)
                        let expected_connections = if i == 0 { n - 1 } else { 1 };

                        // Send a message
                        let msg = signer.public_key();
                        loop {
                            let sent = sender
                                .send(Recipients::All, msg.to_vec().into(), true)
                                .await
                                .unwrap();
                            if sent.len() >= expected_connections {
                                break;
                            }
                            context.sleep(Duration::from_millis(100)).await;
                        }

                        // Signal that this peer is connected
                        complete_sender.send(()).await.unwrap();

                        // Keep receiving messages until shutdown
                        select_loop! {
                            context,
                            on_stopped => {},
                            result = receiver.recv() => {
                                if result.is_err() {
                                    // Channel closed due to shutdown
                                    break;
                                }
                            }
                        }
                    }
                });
            }

            // Wait for all peers to establish connectivity
            for _ in 0..n {
                complete_receiver.next().await.unwrap();
            }

            // Verify that network actors started for all peers
            let metrics_before = context.encode();
            let is_running = |name: &str| -> bool {
                metrics_before.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{name}\""))
                        && line.contains("kind=\"Task\"")
                        && line.trim_end().ends_with(" 1")
                })
            };
            for i in 0..n {
                let prefix = format!("peer-{i}_network");
                assert!(
                    is_running(&format!("{prefix}_tracker")),
                    "peer-{i} tracker should be running"
                );
                assert!(
                    is_running(&format!("{prefix}_router")),
                    "peer-{i} router should be running"
                );
                assert!(
                    is_running(&format!("{prefix}_spawner")),
                    "peer-{i} spawner should be running"
                );
                assert!(
                    is_running(&format!("{prefix}_listener")),
                    "peer-{i} listener should be running"
                );
                assert!(
                    is_running(&format!("{prefix}_dialer")),
                    "peer-{i} dialer should be running"
                );
            }

            // All peers are connected - now trigger graceful shutdown
            // by stopping the context
            let shutdown_context = context.clone();
            context.with_label("shutdown").spawn(move |_| async move {
                // Trigger graceful shutdown
                let result = shutdown_context.stop(0, Some(Duration::from_secs(5))).await;

                // Shutdown should complete successfully without timeout
                assert!(
                    result.is_ok(),
                    "graceful shutdown should complete: {result:?}"
                );
            });

            // Wait for shutdown to complete
            context.stopped().await.unwrap();

            // Give the runtime a tick to process task completions and update metrics
            context.sleep(Duration::from_millis(100)).await;

            // Verify that all network actors stopped
            let metrics_after = context.encode();
            let is_stopped = |name: &str| -> bool {
                metrics_after.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{name}\""))
                        && line.contains("kind=\"Task\"")
                        && line.trim_end().ends_with(" 0")
                })
            };
            for i in 0..n {
                let prefix = format!("peer-{i}_network");
                assert!(
                    is_stopped(&format!("{prefix}_tracker")),
                    "peer-{i} tracker should be stopped"
                );
                assert!(
                    is_stopped(&format!("{prefix}_router")),
                    "peer-{i} router should be stopped"
                );
                assert!(
                    is_stopped(&format!("{prefix}_spawner")),
                    "peer-{i} spawner should be stopped"
                );
                assert!(
                    is_stopped(&format!("{prefix}_listener")),
                    "peer-{i} listener should be stopped"
                );
                assert!(
                    is_stopped(&format!("{prefix}_dialer")),
                    "peer-{i} dialer should be stopped"
                );
            }
        });
    }

    #[test_traced]
    fn test_subscription_includes_self_when_registered() {
        let base_port = 3000;
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create self (peer0) and other peers
            let self_sk = ed25519::PrivateKey::from_seed(0);
            let self_pk = self_sk.public_key();
            let self_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port);

            let other_pk = ed25519::PrivateKey::from_seed(1).public_key();

            // Create network for peer0 (self)
            let config = Config::test(
                self_sk,
                self_addr,
                vec![], // No bootstrappers
                1_024 * 1_024,
            );
            let (network, mut oracle) = Network::new(context.with_label("network"), config);
            network.start();

            // Subscribe to peer sets
            let mut subscription = oracle.subscribe().await;

            // Register a peer set that does NOT include self
            let peer_set: Set<_> = [other_pk.clone()].try_into().unwrap();
            oracle.update(1, peer_set.clone()).await;

            // Receive subscription notification
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 1);
            assert_eq!(new.len(), 1);
            assert_eq!(all.len(), 1);

            // Self should NOT be in the new set
            assert!(
                new.position(&self_pk).is_none(),
                "new set should not include self"
            );
            assert!(
                new.position(&other_pk).is_some(),
                "new set should include other"
            );

            // Self should NOT be in the tracked set (not registered)
            assert!(
                all.position(&self_pk).is_none(),
                "tracked peers should not include self"
            );
            assert!(
                all.position(&other_pk).is_some(),
                "tracked peers should include other"
            );

            // Now register a peer set that DOES include self
            let peer_set: Set<_> = [self_pk.clone(), other_pk.clone()].try_into().unwrap();
            oracle.update(2, peer_set.clone()).await;

            // Receive subscription notification
            let (id, new, all) = subscription.next().await.unwrap();
            assert_eq!(id, 2);
            assert_eq!(new.len(), 2);
            assert_eq!(all.len(), 2);

            // Both peers should be in the new set
            assert!(
                new.position(&self_pk).is_some(),
                "new set should include self"
            );
            assert!(
                new.position(&other_pk).is_some(),
                "new set should include other"
            );

            // Both peers should be in the tracked set
            assert!(
                all.position(&self_pk).is_some(),
                "tracked peers should include self"
            );
            assert!(
                all.position(&other_pk).is_some(),
                "tracked peers should include other"
            );
        });
    }
}
