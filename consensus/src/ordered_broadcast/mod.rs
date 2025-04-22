//! Ordered, reliable broadcast across reconfigurable participants.
//!
//! # Concepts
//!
//! The system has two types of network participants: `sequencers` and `validators`. Their sets may
//! overlap and are defined by the current `epoch`, a monotonically increasing integer. This module
//! can handle reconfiguration of these sets across different epochs.
//!
//! Sequencers broadcast data. The smallest unit of data is a `chunk`. Sequencers broadcast `node`s
//! that contain a chunk and a threshold signature over the previous chunk, forming a linked chain
//! of nodes from each sequencer.
//!
//! Validators verify and sign chunks using partial signatures. These can be combined to recover a
//! threshold signature, ensuring a quorum verifies each chunk. The threshold signature allows
//! external parties to confirm that the chunk was reliably broadcast.
//!
//! Network participants persist any new nodes to a journal. This enables recovery from crashes and
//! ensures that sequencers do not broadcast conflicting chunks and that validators do not sign
//! them. "Conflicting" chunks are chunks from the same sequencer at the same height with different
//! payloads.
//!
//! # Design
//!
//! The core of the module is the [`Engine`]. It is responsible for:
//! - Broadcasting nodes (if a sequencer)
//! - Signing chunks (if a validator)
//! - Tracking the latest chunk in each sequencer’s chain
//! - Recovering threshold signatures from partial signatures for each chunk
//! - Notifying other actors of new chunks and threshold signatures
//!
//! # Acknowledgements
//!
//! [Autobahn](https://arxiv.org/abs/2401.10369) provided the insight that a succinct
//! proof-of-availability could be produced by linking sequencer broadcasts.

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod ack_manager;
        use ack_manager::AckManager;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod tip_manager;
        use tip_manager::TipManager;
    }
}

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
mod tests {
    use super::{mocks, types::Epoch, Config, Engine};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{group::Share, poly},
        },
        ed25519::PublicKey,
        sha256::Digest as Sha256Digest,
        Ed25519, Signer,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics,
    };
    use commonware_runtime::{Clock, Runner, Spawner};
    use futures::channel::oneshot;
    use futures::future::join_all;
    use rand::{rngs::StdRng, SeedableRng as _};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
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
        context: Context,
        num_validators: u32,
        shares_vec: &mut [Share],
    ) -> (
        Oracle<PublicKey>,
        Vec<(PublicKey, Ed25519, Share)>,
        Vec<PublicKey>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
            },
        );
        network.start();

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
        context: Context,
        identity: poly::Public,
        pks: &[PublicKey],
        validators: &[(PublicKey, Ed25519, Share)],
        registrations: &mut Registrations<PublicKey>,
        automatons: &mut BTreeMap<PublicKey, mocks::Automaton<PublicKey>>,
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>,
        rebroadcast_timeout: Duration,
        invalid_when: fn(u64) -> bool,
        misses_allowed: Option<usize>,
    ) -> HashMap<PublicKey, mocks::Monitor> {
        let mut monitors = HashMap::new();
        let namespace = b"my testing namespace";
        for (validator, scheme, share) in validators.iter() {
            let context = context.with_label(&validator.to_string());
            let monitor = mocks::Monitor::new(111);
            monitors.insert(validator.clone(), monitor.clone());
            let sequencers = mocks::Sequencers::<PublicKey>::new(pks.to_vec());
            let validators =
                mocks::Validators::<PublicKey>::new(identity.clone(), pks.to_vec(), *share);

            let automaton = mocks::Automaton::<PublicKey>::new(invalid_when);
            automatons.insert(validator.clone(), automaton.clone());

            let (reporter, reporter_mailbox) = mocks::Reporter::<Ed25519, Sha256Digest>::new(
                namespace,
                *poly::public(&identity),
                misses_allowed,
            );
            context.with_label("reporter").spawn(|_| reporter.run());
            reporters.insert(validator.clone(), reporter_mailbox);

            let engine = Engine::new(
                context.with_label("engine"),
                Config {
                    crypto: scheme.clone(),
                    relay: automaton.clone(),
                    automaton: automaton.clone(),
                    reporter: reporters.get(validator).unwrap().clone(),
                    monitor,
                    sequencers,
                    validators,
                    namespace: namespace.to_vec(),
                    epoch_bounds: (1, 1),
                    height_bound: 2,
                    rebroadcast_timeout,
                    priority_acks: false,
                    priority_proposals: false,
                    journal_heights_per_section: 10,
                    journal_replay_concurrency: 1,
                    journal_name_prefix: format!("ordered-broadcast-seq/{}/", validator),
                },
            );

            let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
            engine.start((a1, a2), (b1, b2));
        }
        monitors
    }

    async fn await_reporters(
        context: Context,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>,
        threshold: (u64, Epoch),
    ) {
        let mut receivers = Vec::new();
        for (sequencer, mailbox) in reporters.iter() {
            // Create a oneshot channel to signal when the reporter has reached the threshold.
            let (tx, rx) = oneshot::channel();
            receivers.push(rx);

            // Spawn a watcher for the reporter.
            context.with_label("reporter_watcher").spawn({
                let sequencer = sequencer.clone();
                let mut mailbox = mailbox.clone();
                move |context| async move {
                    loop {
                        let (height, epoch) =
                            mailbox.get_tip(sequencer.clone()).await.unwrap_or((0, 0));
                        debug!(height, epoch, ?sequencer, "reporter");
                        if height >= threshold.0 && epoch >= threshold.1 {
                            let _ = tx.send(sequencer.clone());
                            break;
                        }
                        context.sleep(Duration::from_millis(100)).await;
                    }
                }
            });
        }

        // Wait for all oneshot receivers to complete.
        let results = join_all(receivers).await;
        assert_eq!(results.len(), reporters.len());
    }

    async fn get_max_height(
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>,
    ) -> u64 {
        let mut max_height = 0;
        for (sequencer, mailbox) in reporters.iter_mut() {
            let (height, _) = mailbox.get_tip(sequencer.clone()).await.unwrap_or((0, 0));
            if height > max_height {
                max_height = height;
            }
        }
        max_height
    }

    #[test_traced]
    fn test_all_online() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (identity, mut shares_vec) =
                ops::generate_shares(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                identity.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                Some(5),
            );
            await_reporters(context.with_label("reporter"), &reporters, (100, 111)).await;
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let mut rng = StdRng::seed_from_u64(0);
        let (identity, mut shares_vec) =
            ops::generate_shares(&mut rng, None, num_validators, quorum);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        let shutdowns = Arc::new(Mutex::new(0u64));
        let mut prev_ctx = None;

        while completed.lock().unwrap().len() != num_validators as usize {
            let runner = deterministic::Runner::timed(Duration::from_secs(45));
            let completed = completed.clone();
            let shares_vec = shares_vec.clone();
            let shutdowns = shutdowns.clone();
            let identity = identity.clone();
            let context = runner.start(|mut context| async move {
                // Print the time on the context's clock:
                println!("time: {:?}", context.current());

                if let Some(prev_ctx) = prev_ctx {
                    context = prev_ctx;
                }

                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                    },
                );
                network.start();

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

                let automatons = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::Automaton<PublicKey>,
                >::new()));
                let mut reporters =
                    BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
                spawn_validator_engines(
                    context.with_label("validator"),
                    identity.clone(),
                    &pks,
                    &validators,
                    &mut registrations,
                    &mut automatons.lock().unwrap(),
                    &mut reporters,
                    Duration::from_secs(5),
                    |_| false,
                    None,
                );

                let reporter_pairs: Vec<(
                    PublicKey,
                    mocks::ReporterMailbox<Ed25519, Sha256Digest>,
                )> = reporters
                    .iter()
                    .map(|(v, m)| (v.clone(), m.clone()))
                    .collect();
                for (validator, mut mailbox) in reporter_pairs {
                    let completed_clone = completed.clone();
                    context
                        .with_label("reporter_unclean")
                        .spawn(|context| async move {
                            loop {
                                let (height, _) =
                                    mailbox.get_tip(validator.clone()).await.unwrap_or((0, 0));
                                if height >= 100 {
                                    completed_clone.lock().unwrap().insert(validator.clone());
                                    break;
                                }
                                context.sleep(Duration::from_millis(100)).await;
                            }
                        });
                }
                context.sleep(Duration::from_millis(1000)).await;
                *shutdowns.lock().unwrap() += 1;

                context
            });
            prev_ctx = Some(context.recover());
            // let recovered = context.recover();
            // runner = recovered.0;
            // context = recovered.1;
        }
    }

    #[test_traced]
    fn test_network_partition() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (identity, mut shares_vec) =
                ops::generate_shares(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            // Configure the network
            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                identity.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(1),
                |_| false,
                None,
            );

            // Simulate partition by removing all links.
            link_validators(&mut oracle, &pks, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Heal the partition by re-adding links.
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &pks, Action::Link(link), None).await;
            await_reporters(
                context.with_label("reporter"),
                &reporters,
                (max_height + 100, 111),
            )
            .await;
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
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let (identity, mut shares_vec) =
                ops::generate_shares(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let delayed_link = Link {
                latency: 50.0,
                jitter: 40.0,
                success_rate: 0.5,
            };
            let mut oracle_clone = oracle.clone();
            link_validators(&mut oracle_clone, &pks, Action::Update(delayed_link), None).await;

            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                identity.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_millis(150),
                |_| false,
                None,
            );

            await_reporters(context.with_label("reporter"), &reporters, (40, 111)).await;

            context.auditor().state()
        })
    }

    #[test_traced]
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

    #[test_traced]
    fn test_invalid_signature_injection() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (identity, mut shares_vec) =
                ops::generate_shares(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (_oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                identity.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |i| i % 10 == 0,
                None,
            );

            await_reporters(context.with_label("reporter"), &reporters, (100, 111)).await;
        });
    }

    #[test_traced]
    fn test_updated_epoch() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (identity, mut shares_vec) =
                ops::generate_shares(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            // Setup network
            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<Ed25519, Sha256Digest>>::new();
            let monitors = spawn_validator_engines(
                context.with_label("validator"),
                identity.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(1),
                |_| false,
                Some(5),
            );

            // Perform some work
            await_reporters(context.with_label("reporter"), &reporters, (100, 111)).await;

            // Simulate partition by removing all links.
            link_validators(&mut oracle, &pks, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Update the epoch
            for monitor in monitors.values() {
                monitor.update(112);
            }

            // Heal the partition by re-adding links.
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &pks, Action::Link(link), None).await;
            await_reporters(
                context.with_label("reporter"),
                &reporters,
                (max_height + 100, 112),
            )
            .await;
        });
    }
}
