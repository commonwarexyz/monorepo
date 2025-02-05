//! Secure, ordered broadcast protocol with linked messages for consistent network
//! dissemination using cryptographic proofs, sequential linking, and robust state
//! management.
//!
//! # Core Concepts
//!
//! - **Sequential Linking**: Every broadcast message contains a cryptographic reference
//!   to the previous message, forming an immutable chain.
//!
//! - **Threshold Signatures**: Validators produce partial signatures that combine into a
//!   threshold signature, ensuring a quorum verifies each message.
//!
//! - **Epochs**: The protocol is divided into epochs. Each epoch defines the active set of
//!   signers and sequencers for orderly transitions and consensus.
//!
//! - **Storage**: Nodes persist state changes (links, acknowledgements) to a journal.
//!   This enables reliable recovery and prevents conflicts like duplicate messages.
//!
//! # Design
//!
//! The system has two sets of nodes: Sequencers and Validators. The sets may overlap.
//! Sequencers link messages, while Validators verify and sign them. Each message includes a
//! threshold signature over its predecessor for an unbroken, verifiable chain.
//!
//! # Actor Overview and Design
//!
//! The core of the protocol is the `Signer` actor. It manages the lifecycle of a secure,
//! ordered broadcast by:
//!
//! 1. **Initializing** storage, networking, and cryptographic settings.
//! 2. **Processing** incoming messages by validating data and signatures.
//! 3. **Broadcasting** signed messages to all nodes.
//! 4. **Verifying** message integrity and order.
//! 5. **Updating Epochs** based on consensus.
//!
//! ## Key Design Principles
//!
//! - **Actor-Based Model**:  
//!   The `Signer` (see `actor.rs`) encapsulates all functions, handling network I/O,
//!   verification, timeouts, and state updates concurrently.
//!
//! - **Event Sourcing & Journaling**:  
//!   Each new message is logged to a persistent journal. This maintains chain integrity and
//!   enables reliable recovery after crashes.
//!
//! - **Asynchronous Processing**:  
//!   Using Rust’s async/await, the actor processes tasks simultaneously, including epoch
//!   refreshes, message rebroadcasts, and verification requests.
//!
//! ## Operational Flow
//!
//! 1. **Message Chaining**:  
//!    Each new message includes a threshold signature over the previous message, forming an
//!    immutable, verifiable chain.
//!
//! 2. **Signature Aggregation**:  
//!    Validators produce partial signatures that combine into a threshold signature,
//!    ensuring quorum endorsement.
//!
//! 3. **Epoch Management**:  
//!    Epochs define the active set of signers and sequencers. The actor refreshes its epoch and
//!    enforces strict bounds on accepted messages.
//!
//! 4. **Reliable Recovery**:  
//!    Storage logs all sequencer messages, allowing nodes to replay messages after shutdown.
//!
//! 5. **Concurrent Operations**:  
//!    The actor listens for network events, dispatches verification tasks, and manages timeouts
//!    for efficient operation.
//!
//! # Public Modules
//!
//! - **`signer`**: Contains the actor that validates messages, links them, and handles threshold
//!   signatures.
//! - **`prover`**: Generates and verifies "proofs" (i.e. threshold signatures over messages).
//!
//! # Internal Modules
//!
//! - **`namespace`**: Generates namespace IDs for different signature types.
//! - **`serializer`**: Serializes and deserializes messages.
//! - **`wire`**: Contains the protocol buffer-generated message definitions.
//! - **`mocks`**: Provides mock implementations for testing.

use commonware_cryptography::PublicKey;

mod namespace;
mod serializer;

#[cfg(test)]
pub mod mocks;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

pub mod prover;
pub mod signer;

/// `Epoch` is used as the `Index` type for the `Coordinator` trait.
/// Defines the current set of sequencers and signers.
pub type Epoch = u64;

/// `Context` is used as the `Context` type for the `Application` and `Collector` traits.
/// Stores a sequencer’s public key and sequential height, defining its unique position in the broadcast chain.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context {
    pub sequencer: PublicKey,
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::{mocks, signer};
    use bytes::Bytes;
    use commonware_cryptography::{
        bls12381::dkg::ops, sha256::Digest as Sha256Digest, Ed25519, Hasher, PublicKey, Scheme,
        Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic::Executor, Clock, Runner, Spawner};
    use commonware_utils::hex;
    use prometheus_client::registry::Registry;
    use rand::Rng;
    use tracing::debug;

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle,
        validators: &[PublicKey],
    ) -> HashMap<PublicKey, ((Sender, Receiver), (Sender, Receiver))> {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (a1, a2) = oracle.register(validator.clone(), 0).await.unwrap();
            let (b1, b2) = oracle.register(validator.clone(), 1).await.unwrap();
            registrations.insert(validator.clone(), ((a1, a2), (b1, b2)));
        }
        registrations
    }

    /// Enum to describe the action to take when linking validators.
    #[allow(dead_code)] // TODO: remove when used
    enum Action {
        Link(Link),
        Update(Link), // Unlink and then link
        Unlink,
    }
    /// Links (or unlinks) validators using the oracle.
    ///
    /// The `action` parameter determines the action (e.g. link, unlink) to take.
    /// The `restrict_to` function can be used to restrict the linking to certain connections,
    /// otherwise all validators will be linked to all other validators.
    async fn link_validators(
        oracle: &mut Oracle,
        validators: &[PublicKey],
        action: Action,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                // Ignore self
                if v2 == v1 {
                    continue;
                }

                // Restrict to certain connections
                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }

                // Do any unlinking first
                match action {
                    Action::Update(_) | Action::Unlink => {
                        oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                    }
                    _ => {}
                }

                // Do any linking after
                match action {
                    Action::Link(ref link) | Action::Update(ref link) => {
                        oracle
                            .add_link(v1.clone(), v2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }

    #[test_traced]
    fn test_all_online() {
        let num_validators = 4;
        let quorum = 3;
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut runtime, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        executor.start({
            let runtime = runtime.clone();
            async move {
                // Create network
                let (network, mut oracle) = Network::new(
                    runtime.clone(),
                    commonware_p2p::simulated::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        max_size: 1024 * 1024,
                    },
                );
                runtime.spawn("network", network.run());

                // Create validators
                let mut validators = (0..num_validators)
                    .map(|i| Ed25519::from_seed(i as u64))
                    .collect::<Vec<_>>();
                validators.sort_by_key(|s| s.public_key());
                let validators = validators
                    .iter()
                    .enumerate()
                    .map(|(i, scheme)| {
                        let pk = scheme.public_key();
                        let share = shares_vec[i];
                        (pk, scheme.clone(), share)
                    })
                    .collect::<Vec<_>>();
                let pks = validators
                    .iter()
                    .map(|(pk, _, _)| pk.clone())
                    .collect::<Vec<_>>();
                let mut registrations = register_validators(&mut oracle, &pks).await;
                let link = Link {
                    latency: 10.0,
                    jitter: 1.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &pks, Action::Link(link), None).await;

                // Create engines
                let mut mailboxes = HashMap::new();
                let mut collectors = HashMap::new();
                for (validator, scheme, share) in validators.iter() {
                    // Coordinator
                    let mut coordinator =
                        mocks::coordinator::Coordinator::new(identity.clone(), pks.clone(), *share);
                    debug!("Share index: {}", share.index);
                    coordinator.set_view(111);

                    // Application
                    let (mut app, app_mailbox) = mocks::application::Application::new();
                    mailboxes.insert(validator.clone(), app_mailbox.clone());

                    // Collector
                    let (collector, collector_mailbox) =
                        mocks::collector::Collector::<Sha256Digest>::new();
                    runtime.spawn("collector", collector.run());
                    collectors.insert(validator.clone(), collector_mailbox.clone());

                    // Signer
                    let hex_validator = hex(validator);
                    let (signer, signer_mailbox) = signer::Actor::new(
                        runtime.clone(),
                        signer::Config {
                            crypto: scheme.clone(),
                            application: app_mailbox.clone(),
                            collector: collector_mailbox.clone(),
                            coordinator,
                            mailbox_size: 1024,
                            pending_verify_size: 1024,
                            namespace: b"test".to_vec(),
                            epoch_bounds: (1, 1),
                            height_bound: 2,
                            refresh_epoch_timeout: Duration::from_millis(100),
                            rebroadcast_timeout: Duration::from_secs(5),
                            journal_heights_per_section: 10,
                            journal_replay_concurrency: 1,
                            journal_naming_fn: move |v| format!("seq/{}/{}", hex_validator, hex(v)),
                        },
                    );

                    // Run the actors
                    runtime.spawn("app", async move { app.run(signer_mailbox).await });
                    let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                    runtime.spawn(
                        "signer",
                        async move { signer.run((a1, a2), (b1, b2)).await },
                    );
                }

                // For each validator, attempt to propose a payload every 250ms
                runtime.spawn("proposer", {
                    let runtime = runtime.clone();
                    async move {
                        let mut iter = 0;
                        let mut hasher = Sha256::default();
                        loop {
                            iter += 1;
                            for (validator, mailbox) in mailboxes.iter_mut() {
                                let payload = Bytes::from(format!(
                                    "hello world from validator {}, iter {}",
                                    hex(validator),
                                    iter
                                ));
                                hasher.update(&payload);
                                let digest = hasher.finalize();
                                mailbox.broadcast(digest).await;
                            }
                            runtime.sleep(Duration::from_millis(250)).await;
                        }
                    }
                });

                // For each node, wait for the acknowledged height of each sequencer to reach 100
                // Put the validator in completed
                let completed = Arc::new(Mutex::new(HashSet::new()));
                for (validator, collector_mailbox) in collectors.iter() {
                    runtime.spawn("collector", {
                        let mut collector = collector_mailbox.clone();
                        let runtime = runtime.clone();
                        let completed = completed.clone();
                        let validator = validator.clone();
                        async move {
                            loop {
                                let tip = collector.get_tip(validator.clone()).await.unwrap_or(0);
                                debug!("Collector: tip {}", tip);

                                // We are done!
                                if tip >= 100 {
                                    completed.lock().unwrap().insert(validator.clone());
                                    break;
                                }

                                // Sleep for a bit
                                runtime.sleep(Duration::from_millis(100)).await;
                            }
                        }
                    });
                }

                // Wait for all validators to complete
                while completed.lock().unwrap().len() != num_validators as usize {
                    runtime.sleep(Duration::from_secs(1)).await;
                }
            }
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        let num_validators = 4;
        let quorum = 3;
        let (mut executor, mut runtime, _) = Executor::timed(Duration::from_secs(45));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut runtime, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        let completed = Arc::new(Mutex::new(HashSet::new()));
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

        while completed.lock().unwrap().len() != num_validators as usize {
            executor.start({
                let mut runtime = runtime.clone();
                let completed = completed.clone();
                let shares_vec = shares_vec.clone();
                let shutdowns = shutdowns.clone();
                let identity = identity.clone();
                async move {
                    // Create network
                    let (network, mut oracle) = Network::new(
                        runtime.clone(),
                        commonware_p2p::simulated::Config {
                            registry: Arc::new(Mutex::new(Registry::default())),
                            max_size: 1024 * 1024,
                        },
                    );
                    runtime.spawn("network", network.run());

                    // Create validators
                    let mut validators = (0..num_validators)
                        .map(|i| Ed25519::from_seed(i as u64))
                        .collect::<Vec<_>>();
                    validators.sort_by_key(|s| s.public_key());
                    let validators = validators
                        .iter()
                        .enumerate()
                        .map(|(i, scheme)| {
                            let pk = scheme.public_key();
                            let share = shares_vec[i];
                            (pk, scheme.clone(), share)
                        })
                        .collect::<Vec<_>>();
                    let pks = validators
                        .iter()
                        .map(|(pk, _, _)| pk.clone())
                        .collect::<Vec<_>>();
                    let mut registrations = register_validators(&mut oracle, &pks).await;
                    let link = Link {
                        latency: 10.0,
                        jitter: 1.0,
                        success_rate: 1.0,
                    };
                    link_validators(&mut oracle, &pks, Action::Link(link), None).await;

                    // Create engines
                    let mut mailboxes = HashMap::new();
                    let mut collectors = HashMap::new();
                    for (validator, scheme, share) in validators.iter() {
                        // Coordinator
                        let mut coordinator = mocks::coordinator::Coordinator::new(
                            identity.clone(),
                            pks.clone(),
                            *share,
                        );
                        debug!("Share index: {}", share.index);
                        coordinator.set_view(111);

                        // Application
                        let (mut app, app_mailbox) = mocks::application::Application::new();
                        mailboxes.insert(validator.clone(), app_mailbox.clone());

                        // Collector
                        let (collector, collector_mailbox) =
                            mocks::collector::Collector::<Sha256Digest>::new();
                        runtime.spawn("collector", collector.run());
                        collectors.insert(validator.clone(), collector_mailbox.clone());

                        // Signer
                        let hex_validator = hex(validator);
                        let (signer, signer_mailbox) = signer::Actor::new(
                            runtime.clone(),
                            signer::Config {
                                crypto: scheme.clone(),
                                application: app_mailbox.clone(),
                                collector: collector_mailbox.clone(),
                                coordinator,
                                mailbox_size: 1024,
                                pending_verify_size: 1024,
                                namespace: b"test".to_vec(),
                                epoch_bounds: (1, 1),
                                height_bound: 2,
                                refresh_epoch_timeout: Duration::from_millis(100),
                                rebroadcast_timeout: Duration::from_millis(1_000),
                                journal_heights_per_section: 10,
                                journal_replay_concurrency: 1,
                                journal_naming_fn: move |v| {
                                    format!("seq/{}/{}", hex_validator, hex(v))
                                },
                            },
                        );

                        // Run the actors
                        runtime.spawn("app", async move { app.run(signer_mailbox).await });
                        let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                        runtime.spawn(
                            "signer",
                            async move { signer.run((a1, a2), (b1, b2)).await },
                        );
                    }

                    // For each validator, attempt to propose a payload every 250ms
                    runtime.spawn("proposer", {
                        let runtime = runtime.clone();
                        async move {
                            let mut iter = 0;
                            let mut hasher = Sha256::default();
                            loop {
                                iter += 1;
                                for (validator, mailbox) in mailboxes.iter_mut() {
                                    let payload = Bytes::from(format!(
                                        "hello world from validator {}, iter {}",
                                        hex(validator),
                                        iter
                                    ));
                                    hasher.update(&payload);
                                    let digest = hasher.finalize();
                                    mailbox.broadcast(digest).await;
                                }
                                runtime.sleep(Duration::from_millis(250)).await;
                            }
                        }
                    });

                    // For each node, wait for the acknowledged height of each sequencer to reach 100
                    // Put the validator in completed
                    for (validator, collector_mailbox) in collectors.iter() {
                        runtime.spawn("collector", {
                            let mut collector = collector_mailbox.clone();
                            let runtime = runtime.clone();
                            let completed = completed.clone();
                            let validator = validator.clone();
                            async move {
                                loop {
                                    let tip =
                                        collector.get_tip(validator.clone()).await.unwrap_or(0);
                                    debug!("Collector: tip {}", tip);

                                    // We are done!
                                    if tip >= 100 {
                                        completed.lock().unwrap().insert(validator.clone());
                                        break;
                                    }

                                    // Sleep for a bit
                                    runtime.sleep(Duration::from_millis(100)).await;
                                }
                            }
                        });
                    }

                    // Exit at random points for unclean shutdown of entire set
                    let wait = runtime
                        .gen_range(Duration::from_millis(1_000)..Duration::from_millis(10_000));
                    runtime.sleep(wait).await;
                    {
                        let mut shutdowns = shutdowns.lock().unwrap();
                        debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                        *shutdowns += 1;
                    }
                }
            });

            // Recover runtime
            (executor, runtime, _) = runtime.recover();
        }
    }
}
