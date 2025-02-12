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
//! - **`safe`**: Provides parsed wrappers around wire types.
//! - **`mocks`**: Provides mock implementations for testing.

use commonware_cryptography::Array;

mod namespace;
mod safe;
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context<P: Array> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: u64,
}

#[cfg(test)]
mod tests {
    use super::{mocks, signer};
    use bytes::Bytes;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{group::Share, poly},
        },
        ed25519::PublicKey,
        sha256::{Digest as Sha256Digest, Sha256},
        Ed25519, Hasher, Scheme,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::deterministic::{self, Context, Executor};
    use commonware_runtime::{Clock, Runner, Spawner};
    use commonware_utils::hex;
    use prometheus_client::registry::Registry;
    use std::sync::{Arc, Mutex};
    use std::{
        collections::{BTreeMap, HashSet},
        time::Duration,
    };
    use tracing::debug;

    type Registrations<P> = BTreeMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))>;

    async fn register_validators(
        oracle: &mut Oracle<PublicKey>,
        validators: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for validator in validators.iter() {
            let (a1, a2) = oracle.register(validator.clone(), 0).await.unwrap();
            let (b1, b2) = oracle.register(validator.clone(), 1).await.unwrap();
            registrations.insert(validator.clone(), ((a1, a2), (b1, b2)));
        }
        registrations
    }

    #[allow(dead_code)]
    enum Action {
        Link(Link),
        Update(Link),
        Unlink,
    }

    async fn link_validators(
        oracle: &mut Oracle<PublicKey>,
        validators: &[PublicKey],
        action: Action,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                if v2 == v1 {
                    continue;
                }
                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }
                if matches!(action, Action::Update(_) | Action::Unlink) {
                    oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                }
                if let Action::Link(ref link) | Action::Update(ref link) = action {
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }
        }
    }

    async fn initialize_simulation(
        runtime: &Context,
        num_validators: u32,
        shares_vec: &mut [Share],
    ) -> (
        Oracle<PublicKey>,
        Vec<(PublicKey, Ed25519, Share)>,
        Vec<PublicKey>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new(
            runtime.clone(),
            commonware_p2p::simulated::Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                max_size: 1024 * 1024,
            },
        );
        runtime.clone().spawn("network", network.run());

        let mut schemes = (0..num_validators)
            .map(|i| Ed25519::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let validators: Vec<(PublicKey, Ed25519, Share)> = schemes
            .iter()
            .enumerate()
            .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i]))
            .collect();
        let pks = validators
            .iter()
            .map(|(pk, _, _)| pk.clone())
            .collect::<Vec<_>>();

        let registrations = register_validators(&mut oracle, &pks).await;
        let link = Link {
            latency: 10.0,
            jitter: 1.0,
            success_rate: 1.0,
        };
        link_validators(&mut oracle, &pks, Action::Link(link), None).await;
        (oracle, validators, pks, registrations)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_validator_engines(
        runtime: &Context,
        identity: poly::Public,
        pks: &[PublicKey],
        validators: &[(PublicKey, Ed25519, Share)],
        registrations: &mut Registrations<PublicKey>,
        mailboxes: &mut BTreeMap<PublicKey, mocks::application::Mailbox<Sha256Digest, PublicKey>>,
        collectors: &mut BTreeMap<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>,
        refresh_epoch_timeout: Duration,
        rebroadcast_timeout: Duration,
    ) {
        let namespace = b"my testing namespace";
        for (validator, scheme, share) in validators.iter() {
            let mut coordinator = mocks::coordinator::Coordinator::<PublicKey>::new(
                identity.clone(),
                pks.to_vec(),
                *share,
            );
            coordinator.set_view(111);

            let (mut app, app_mailbox) =
                mocks::application::Application::<Sha256Digest, PublicKey>::new();
            mailboxes.insert(validator.clone(), app_mailbox.clone());

            let (collector, collector_mailbox) =
                mocks::collector::Collector::<Ed25519, Sha256Digest>::new(
                    namespace,
                    poly::public(&identity),
                );
            runtime.clone().spawn("collector", collector.run());
            collectors.insert(validator.clone(), collector_mailbox);

            let hex_validator = hex(validator);
            let (signer, signer_mailbox) = signer::Actor::new(
                runtime.clone(),
                signer::Config {
                    crypto: scheme.clone(),
                    application: app_mailbox.clone(),
                    collector: collectors.get(validator).unwrap().clone(),
                    coordinator,
                    mailbox_size: 1024,
                    pending_verify_size: 1024,
                    namespace: namespace.to_vec(),
                    epoch_bounds: (1, 1),
                    height_bound: 2,
                    refresh_epoch_timeout,
                    rebroadcast_timeout,
                    journal_heights_per_section: 10,
                    journal_replay_concurrency: 1,
                    journal_naming_fn: move |v| format!("seq/{}/{}", hex_validator, hex(v)),
                },
            );

            runtime
                .clone()
                .spawn("app", async move { app.run(signer_mailbox).await });
            let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
            runtime.clone().spawn(
                "signer",
                async move { signer.run((a1, a2), (b1, b2)).await },
            );
        }
    }

    fn spawn_proposer(
        runtime: &Context,
        mailboxes: Arc<
            Mutex<BTreeMap<PublicKey, mocks::application::Mailbox<Sha256Digest, PublicKey>>>,
        >,
        invalid_when: fn(u64) -> bool,
    ) {
        runtime.clone().spawn("invalid signature proposer", {
            let runtime = runtime.clone();
            async move {
                let mut iter = 0;
                loop {
                    iter += 1;
                    let mailbox_vec: Vec<mocks::application::Mailbox<Sha256Digest, PublicKey>> = {
                        let guard = mailboxes.lock().unwrap();
                        guard.values().cloned().collect()
                    };
                    for mut mailbox in mailbox_vec {
                        let payload = Bytes::from(format!("hello world, iter {}", iter));
                        let mut hasher = Sha256::default();
                        hasher.update(&payload);

                        // Inject an invalid digest by updating with the payload again.
                        if invalid_when(iter) {
                            hasher.update(&payload);
                        }

                        let digest = hasher.finalize();
                        mailbox.broadcast(digest).await;
                    }
                    runtime.sleep(Duration::from_millis(250)).await;
                }
            }
        });
    }

    async fn await_collectors(
        runtime: &Context,
        collectors: &BTreeMap<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>,
        threshold: u64,
        num_validators: usize,
    ) {
        let completed = Arc::new(Mutex::new(HashSet::new()));
        for (validator, mailbox) in collectors.iter() {
            let validator_cloned = validator.clone();
            let mut mailbox_cloned = mailbox.clone();
            let runtime_cloned = runtime.clone();
            let runtime_for_sleep = runtime_cloned.clone();
            let completed_clone = completed.clone();
            runtime_cloned.spawn("collector_watcher", async move {
                loop {
                    let tip = mailbox_cloned
                        .get_tip(validator_cloned.clone())
                        .await
                        .unwrap_or(0);
                    debug!("Collector tip: {}", tip);
                    if tip >= threshold {
                        completed_clone
                            .lock()
                            .unwrap()
                            .insert(validator_cloned.clone());
                        break;
                    }
                    runtime_for_sleep.sleep(Duration::from_millis(100)).await;
                }
            });
        }
        while completed.lock().unwrap().len() != num_validators {
            runtime.sleep(Duration::from_secs(1)).await;
        }
    }
    #[test]
    fn test_all_online() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let (runner, mut context, _) = Executor::timed(Duration::from_secs(30));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut context, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        runner.start({
            let context = context.clone();
            async move {
                let (_oracle, validators, pks, mut registrations) =
                    initialize_simulation(&context, num_validators, &mut shares_vec).await;
                let mailboxes = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::application::Mailbox<Sha256Digest, PublicKey>,
                >::new()));
                let mut collectors =
                    BTreeMap::<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>::new();
                spawn_validator_engines(
                    &context,
                    identity.clone(),
                    &pks,
                    &validators,
                    &mut registrations,
                    &mut mailboxes.lock().unwrap(),
                    &mut collectors,
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                );
                spawn_proposer(&context, mailboxes.clone(), |_| false);
                await_collectors(&context, &collectors, 100, num_validators as usize).await;
            }
        });
    }

    #[test]
    fn test_unclean_shutdown() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let (mut runner, mut context, _) = Executor::timed(Duration::from_secs(45));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut context, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        let shutdowns = Arc::new(Mutex::new(0u64));

        while completed.lock().unwrap().len() != num_validators as usize {
            runner.start({
                let context = context.clone();
                let completed = completed.clone();
                let shares_vec = shares_vec.clone();
                let shutdowns = shutdowns.clone();
                let identity = identity.clone();
                async move {
                    let (network, mut oracle) = Network::new(
                        context.clone(),
                        commonware_p2p::simulated::Config {
                            registry: Arc::new(Mutex::new(Registry::default())),
                            max_size: 1024 * 1024,
                        },
                    );
                    context.clone().spawn("network", network.run());

                    let mut schemes = (0..num_validators)
                        .map(|i| Ed25519::from_seed(i as u64))
                        .collect::<Vec<_>>();
                    schemes.sort_by_key(|s| s.public_key());
                    let validators: Vec<(PublicKey, Ed25519, Share)> = schemes
                        .iter()
                        .enumerate()
                        .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i]))
                        .collect();
                    let pks = validators
                        .iter()
                        .map(|(pk, _, _)| pk.clone())
                        .collect::<Vec<_>>();

                    let mut registrations = register_validators(&mut oracle, &pks).await;
                    let link = commonware_p2p::simulated::Link {
                        latency: 10.0,
                        jitter: 1.0,
                        success_rate: 1.0,
                    };
                    link_validators(&mut oracle, &pks, Action::Link(link), None).await;

                    let mailboxes = Arc::new(Mutex::new(BTreeMap::<
                        PublicKey,
                        mocks::application::Mailbox<Sha256Digest, PublicKey>,
                    >::new()));
                    let mut collectors = BTreeMap::<
                        PublicKey,
                        mocks::collector::Mailbox<Ed25519, Sha256Digest>,
                    >::new();
                    spawn_validator_engines(
                        &context,
                        identity.clone(),
                        &pks,
                        &validators,
                        &mut registrations,
                        &mut mailboxes.lock().unwrap(),
                        &mut collectors,
                        Duration::from_millis(100),
                        Duration::from_secs(5),
                    );
                    spawn_proposer(&context, mailboxes.clone(), |_| false);

                    let collector_pairs: Vec<(
                        PublicKey,
                        mocks::collector::Mailbox<Ed25519, Sha256Digest>,
                    )> = collectors
                        .iter()
                        .map(|(v, m)| (v.clone(), m.clone()))
                        .collect();
                    for (validator, mut mailbox) in collector_pairs {
                        let context_cloned = context.clone();
                        let completed_clone = completed.clone();
                        context.clone().spawn("collector_unclean", async move {
                            loop {
                                let tip = mailbox.get_tip(validator.clone()).await.unwrap_or(0);
                                if tip >= 100 {
                                    completed_clone.lock().unwrap().insert(validator.clone());
                                    break;
                                }
                                context_cloned.sleep(Duration::from_millis(100)).await;
                            }
                        });
                    }
                    context.sleep(Duration::from_millis(1000)).await;
                    *shutdowns.lock().unwrap() += 1;
                }
            });
            let recovered = context.recover();
            runner = recovered.0;
            context = recovered.1;
        }
    }

    #[test]
    fn test_network_partition() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let (runner, mut context, _) = Executor::timed(Duration::from_secs(60));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut context, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        runner.start({
            let context = context.clone();
            async move {
                let (mut oracle, validators, pks, mut registrations) =
                    initialize_simulation(&context, num_validators, &mut shares_vec).await;
                let mailboxes = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::application::Mailbox<Sha256Digest, PublicKey>,
                >::new()));
                let mut collectors =
                    BTreeMap::<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>::new();
                spawn_validator_engines(
                    &context,
                    identity.clone(),
                    &pks,
                    &validators,
                    &mut registrations,
                    &mut mailboxes.lock().unwrap(),
                    &mut collectors,
                    Duration::from_millis(100),
                    Duration::from_secs(1),
                );
                spawn_proposer(&context, mailboxes.clone(), |_| false);
                // Simulate partition by removing all links.
                link_validators(&mut oracle, &pks, Action::Unlink, None).await;
                context.sleep(Duration::from_secs(5)).await;
                // Heal the partition by re-adding links.
                let link = Link {
                    latency: 10.0,
                    jitter: 1.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &pks, Action::Link(link), None).await;
                await_collectors(&context, &collectors, 100, num_validators as usize).await;
            }
        });
    }

    fn slow_and_lossy_links(seed: u64) -> String {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let cfg = deterministic::Config {
            seed,
            timeout: Some(Duration::from_secs(40)),
            ..deterministic::Config::default()
        };
        let (runner, mut context, auditor) = Executor::init(cfg);
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut context, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        runner.start({
            let context = context.clone();
            async move {
                let (oracle, validators, pks, mut registrations) =
                    initialize_simulation(&context, num_validators, &mut shares_vec).await;
                let delayed_link = Link {
                    latency: 50.0,
                    jitter: 40.0,
                    success_rate: 0.5,
                };
                let mut oracle_clone = oracle.clone();
                link_validators(&mut oracle_clone, &pks, Action::Update(delayed_link), None).await;

                let mailboxes = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::application::Mailbox<Sha256Digest, PublicKey>,
                >::new()));
                let mut collectors =
                    BTreeMap::<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>::new();
                spawn_validator_engines(
                    &context,
                    identity.clone(),
                    &pks,
                    &validators,
                    &mut registrations,
                    &mut mailboxes.lock().unwrap(),
                    &mut collectors,
                    Duration::from_millis(100),
                    Duration::from_millis(150),
                );

                spawn_proposer(&context, mailboxes.clone(), |_| false);
                await_collectors(&context, &collectors, 40, num_validators as usize).await;
            }
        });
        auditor.state()
    }

    #[test]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links(0);
    }

    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            let state_1 = slow_and_lossy_links(seed);
            let state_2 = slow_and_lossy_links(seed);
            assert_eq!(state_1, state_2);
        }
    }

    #[test]
    fn test_invalid_signature_injection() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let (runner, mut context, _) = Executor::timed(Duration::from_secs(30));
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut context, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        runner.start({
            let context = context.clone();
            async move {
                let (_oracle, validators, pks, mut registrations) =
                    initialize_simulation(&context, num_validators, &mut shares_vec).await;
                let mailboxes = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::application::Mailbox<Sha256Digest, PublicKey>,
                >::new()));
                let mut collectors =
                    BTreeMap::<PublicKey, mocks::collector::Mailbox<Ed25519, Sha256Digest>>::new();
                spawn_validator_engines(
                    &context,
                    identity.clone(),
                    &pks,
                    &validators,
                    &mut registrations,
                    &mut mailboxes.lock().unwrap(),
                    &mut collectors,
                    Duration::from_millis(100),
                    Duration::from_secs(5),
                );

                spawn_proposer(&context, mailboxes.clone(), |i| i % 10 == 0);
                await_collectors(&context, &collectors, 100, num_validators as usize).await;
            }
        });
    }
}
