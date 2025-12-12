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
//! The core of the module is the [Engine]. It is responsible for:
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
    use super::{mocks, Config, Engine};
    use crate::types::{Epoch, EpochDelta};
    use commonware_cryptography::{
        bls12381::{
            dkg,
            primitives::{
                group::Share,
                poly,
                variant::{MinPk, MinSig, Variant},
            },
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        PrivateKeyExt as _, Signer as _,
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Clock, Metrics, Runner, Spawner,
    };
    use commonware_utils::{NZUsize, NZU32};
    use futures::{channel::oneshot, future::join_all};
    use governor::Quota;
    use rand::{rngs::StdRng, SeedableRng as _};
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::{NonZeroU32, NonZeroUsize},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    type Registrations<P> = BTreeMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))>;

    async fn register_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let mut control = oracle.control(participant.clone());
            let (a1, a2) = control.register(0, TEST_QUOTA).await.unwrap();
            let (b1, b2) = control.register(1, TEST_QUOTA).await.unwrap();
            registrations.insert(participant.clone(), ((a1, a2), (b1, b2)));
        }
        registrations
    }

    enum Action {
        Link(Link),
        Update(Link),
        Unlink,
    }

    async fn link_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
        action: Action,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in participants.iter().enumerate() {
            for (i2, v2) in participants.iter().enumerate() {
                if v2 == v1 {
                    continue;
                }
                if let Some(f) = restrict_to {
                    if !f(participants.len(), i1, i2) {
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
        Vec<(PublicKey, PrivateKey, Share)>,
        Vec<PublicKey>,
        Registrations<PublicKey>,
    ) {
        let (network, mut oracle) = Network::new(
            context.with_label("network"),
            commonware_p2p::simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
            },
        );
        network.start();

        let mut schemes = (0..num_validators)
            .map(|i| PrivateKey::from_seed(i as u64))
            .collect::<Vec<_>>();
        schemes.sort_by_key(|s| s.public_key());
        let validators: Vec<(PublicKey, PrivateKey, Share)> = schemes
            .iter()
            .enumerate()
            .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i].clone()))
            .collect();
        let pks = validators
            .iter()
            .map(|(pk, _, _)| pk.clone())
            .collect::<Vec<_>>();

        let registrations = register_participants(&mut oracle, &pks).await;
        let link = Link {
            latency: Duration::from_millis(10),
            jitter: Duration::from_millis(1),
            success_rate: 1.0,
        };
        link_participants(&mut oracle, &pks, Action::Link(link), None).await;
        (oracle, validators, pks, registrations)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_validator_engines<V: Variant>(
        context: Context,
        polynomial: poly::Public<V>,
        sequencer_pks: &[PublicKey],
        validator_pks: &[PublicKey],
        validators: &[(PublicKey, PrivateKey, Share)],
        registrations: &mut Registrations<PublicKey>,
        automatons: &mut BTreeMap<PublicKey, mocks::Automaton<PublicKey>>,
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>,
        rebroadcast_timeout: Duration,
        invalid_when: fn(u64) -> bool,
        misses_allowed: Option<usize>,
    ) -> HashMap<PublicKey, mocks::Monitor> {
        let mut monitors = HashMap::new();
        let namespace = b"my testing namespace";
        for (validator, scheme, share) in validators.iter() {
            let context = context.with_label(&validator.to_string());
            let monitor = mocks::Monitor::new(Epoch::new(111));
            monitors.insert(validator.clone(), monitor.clone());
            let sequencers = mocks::Sequencers::<PublicKey>::new(sequencer_pks.to_vec());
            let validators = mocks::Validators::<PublicKey, V>::new(
                polynomial.clone(),
                validator_pks.to_vec(),
                Some(share.clone()),
            );

            let automaton = mocks::Automaton::<PublicKey>::new(invalid_when);
            automatons.insert(validator.clone(), automaton.clone());

            let (reporter, reporter_mailbox) = mocks::Reporter::<PublicKey, V, Sha256Digest>::new(
                namespace,
                *poly::public::<V>(&polynomial),
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
                    epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                    height_bound: 2,
                    rebroadcast_timeout,
                    priority_acks: false,
                    priority_proposals: false,
                    journal_heights_per_section: 10,
                    journal_replay_buffer: NZUsize!(4096),
                    journal_write_buffer: NZUsize!(4096),
                    journal_name_prefix: format!("ordered-broadcast-seq-{validator}-"),
                    journal_compression: Some(3),
                    journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            );

            let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
            engine.start((a1, a2), (b1, b2));
        }
        monitors
    }

    async fn await_reporters<V: Variant>(
        context: Context,
        sequencers: Vec<PublicKey>,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>,
        threshold: (u64, Epoch, bool),
    ) {
        let (threshold_height, threshold_epoch, require_contiguous) =
            (threshold.0, threshold.1, threshold.2);
        let mut receivers = Vec::new();
        for (reporter, mailbox) in reporters.iter() {
            // Spawn a watcher for the reporter.
            for sequencer in sequencers.iter() {
                // Create a oneshot channel to signal when the reporter has reached the threshold.
                let (tx, rx) = oneshot::channel();
                receivers.push(rx);

                context.with_label("reporter_watcher").spawn({
                    let reporter = reporter.clone();
                    let sequencer = sequencer.clone();
                    let mut mailbox = mailbox.clone();
                    move |context| async move {
                        loop {
                            let (height, epoch) = mailbox
                                .get_tip(sequencer.clone())
                                .await
                                .unwrap_or((0, Epoch::zero()));
                            debug!(height, epoch = %epoch, ?sequencer, ?reporter, "reporter");
                            let contiguous_height = mailbox
                                .get_contiguous_tip(sequencer.clone())
                                .await
                                .unwrap_or(0);
                            if height >= threshold_height
                                && epoch >= threshold_epoch
                                && (!require_contiguous || contiguous_height >= threshold_height)
                            {
                                let _ = tx.send(sequencer.clone());
                                break;
                            }
                            context.sleep(Duration::from_millis(100)).await;
                        }
                    }
                });
            }
        }

        // Wait for all oneshot receivers to complete.
        let results = join_all(receivers).await;
        assert_eq!(results.len(), sequencers.len() * reporters.len());

        // Check that none were cancelled.
        for result in results {
            assert!(result.is_ok(), "reporter was cancelled");
        }
    }

    async fn get_max_height<V: Variant>(
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>,
    ) -> u64 {
        let mut max_height = 0;
        for (sequencer, mailbox) in reporters.iter_mut() {
            let (height, _) = mailbox
                .get_tip(sequencer.clone())
                .await
                .unwrap_or((0, Epoch::zero()));
            if height > max_height {
                max_height = height;
            }
        }
        max_height
    }

    fn all_online<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
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
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |_| false,
                Some(5),
            );
            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (100, Epoch::new(111), true),
            )
            .await;
        });
    }

    #[test_traced]
    fn test_all_online() {
        all_online::<MinPk>();
        all_online::<MinSig>();
    }

    fn unclean_shutdown<V: Variant>() {
        let num_validators: u32 = 4;
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, mut shares_vec) =
            dkg::deal_anonymous::<V>(&mut rng, NZU32!(num_validators));
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        let shutdowns = Arc::new(Mutex::new(0u64));
        let mut prev_checkpoint = None;

        while completed.lock().unwrap().len() != num_validators as usize {
            let completed = completed.clone();
            let shares_vec = shares_vec.clone();
            let shutdowns = shutdowns.clone();
            let polynomial = polynomial.clone();

            let f = |context: deterministic::Context| async move {
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    commonware_p2p::simulated::Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: None,
                    },
                );
                network.start();

                let mut schemes = (0..num_validators)
                    .map(|i| PrivateKey::from_seed(i as u64))
                    .collect::<Vec<_>>();
                schemes.sort_by_key(|s| s.public_key());
                let validators: Vec<(PublicKey, PrivateKey, Share)> = schemes
                    .iter()
                    .enumerate()
                    .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares_vec[i].clone()))
                    .collect();
                let pks = validators
                    .iter()
                    .map(|(pk, _, _)| pk.clone())
                    .collect::<Vec<_>>();

                let mut registrations = register_participants(&mut oracle, &pks).await;
                let link = commonware_p2p::simulated::Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: 1.0,
                };
                link_participants(&mut oracle, &pks, Action::Link(link), None).await;

                let automatons = Arc::new(Mutex::new(BTreeMap::<
                    PublicKey,
                    mocks::Automaton<PublicKey>,
                >::new()));
                let mut reporters =
                    BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new(
                    );
                spawn_validator_engines(
                    context.with_label("validator"),
                    polynomial.clone(),
                    &pks,
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
                    mocks::ReporterMailbox<PublicKey, V, Sha256Digest>,
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
                                let (height, _) = mailbox
                                    .get_tip(validator.clone())
                                    .await
                                    .unwrap_or((0, Epoch::zero()));
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
            };

            let (_, checkpoint) = prev_checkpoint
                .map_or_else(
                    || deterministic::Runner::timed(Duration::from_secs(45)),
                    deterministic::Runner::from,
                )
                .start_and_recover(f);

            prev_checkpoint = Some(checkpoint);
        }
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown::<MinPk>();
        unclean_shutdown::<MinSig>();
    }

    fn network_partition<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
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
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
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
            link_participants(&mut oracle, &pks, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Heal the partition by re-adding links.
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_participants(&mut oracle, &pks, Action::Link(link), None).await;
            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (max_height + 100, Epoch::new(111), false),
            )
            .await;
        });
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_network_partition() {
        network_partition::<MinPk>();
        network_partition::<MinSig>();
    }

    fn slow_and_lossy_links<V: Variant>(seed: u64) -> String {
        let num_validators: u32 = 4;
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(40)));
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let delayed_link = Link {
                latency: Duration::from_millis(50),
                jitter: Duration::from_millis(40),
                success_rate: 0.5,
            };
            let mut oracle_clone = oracle.clone();
            link_participants(&mut oracle_clone, &pks, Action::Update(delayed_link), None).await;

            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            spawn_validator_engines(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_millis(150),
                |_| false,
                None,
            );

            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (40, Epoch::new(111), false),
            )
            .await;

            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links::<MinPk>(0);
        slow_and_lossy_links::<MinSig>(0);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            let pk_state_1 = slow_and_lossy_links::<MinPk>(seed);
            let pk_state_2 = slow_and_lossy_links::<MinPk>(seed);
            assert_eq!(pk_state_1, pk_state_2);

            let sig_state_1 = slow_and_lossy_links::<MinSig>(seed);
            let sig_state_2 = slow_and_lossy_links::<MinSig>(seed);
            assert_eq!(sig_state_1, sig_state_2);

            // Sanity check that different types can't be identical.
            assert_ne!(pk_state_1, sig_state_1);
        }
    }

    fn invalid_signature_injection<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
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
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_secs(5),
                |i| i % 10 == 0,
                None,
            );

            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (100, Epoch::new(111), true),
            )
            .await;
        });
    }

    #[test_traced]
    fn test_invalid_signature_injection() {
        invalid_signature_injection::<MinPk>();
        invalid_signature_injection::<MinSig>();
    }

    fn updated_epoch<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
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
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            let monitors = spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
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
            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (100, Epoch::new(111), true),
            )
            .await;

            // Simulate partition by removing all links.
            link_participants(&mut oracle, &pks, Action::Unlink, None).await;
            context.sleep(Duration::from_secs(30)).await;

            // Get the maximum height from all reporters.
            let max_height = get_max_height(&mut reporters).await;

            // Update the epoch
            for monitor in monitors.values() {
                monitor.update(Epoch::new(112));
            }

            // Heal the partition by re-adding links.
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_participants(&mut oracle, &pks, Action::Link(link), None).await;
            await_reporters(
                context.with_label("reporter"),
                reporters.keys().cloned().collect::<Vec<_>>(),
                &reporters,
                (max_height + 100, Epoch::new(112), true),
            )
            .await;
        });
    }

    #[test_traced]
    fn test_updated_epoch() {
        updated_epoch::<MinPk>();
        updated_epoch::<MinSig>();
    }

    fn external_sequencer<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));
        runner.start(|mut context| async move {
            // Generate validator shares
            let (polynomial, shares) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));

            // Generate validator schemes
            let mut schemes = (0..num_validators)
                .map(|i| PrivateKey::from_seed(i as u64))
                .collect::<Vec<_>>();
            schemes.sort_by_key(|s| s.public_key());

            // Generate validators
            let validators: Vec<(PublicKey, PrivateKey, Share)> = schemes
                .iter()
                .enumerate()
                .map(|(i, scheme)| (scheme.public_key(), scheme.clone(), shares[i].clone()))
                .collect();
            let validator_pks = validators
                .iter()
                .map(|(pk, _, _)| pk.clone())
                .collect::<Vec<_>>();

            // Generate sequencer
            let sequencer = PrivateKey::from_seed(u64::MAX);

            // Generate network participants
            let mut participants = validators
                .iter()
                .map(|(pk, _, _)| pk.clone())
                .collect::<Vec<_>>();
            participants.push(sequencer.public_key()); // as long as external participants are in same position for all, it is safe

            // Create network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                commonware_p2p::simulated::Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Register all participants
            let mut registrations = register_participants(&mut oracle, &participants).await;
            let link = commonware_p2p::simulated::Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_participants(&mut oracle, &participants, Action::Link(link), None).await;

            // Setup engines
            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            let mut monitors = HashMap::new();
            let namespace = b"my testing namespace";

            // Spawn validator engines
            for (validator, scheme, share) in validators.iter() {
                let context = context.with_label(&validator.to_string());
                let monitor = mocks::Monitor::new(Epoch::new(111));
                monitors.insert(validator.clone(), monitor.clone());
                let sequencers = mocks::Sequencers::<PublicKey>::new(vec![sequencer.public_key()]);
                let validators = mocks::Validators::<PublicKey, V>::new(
                    polynomial.clone(),
                    validator_pks.clone(),
                    Some(share.clone()),
                );

                let automaton = mocks::Automaton::<PublicKey>::new(|_| false);
                automatons
                    .lock()
                    .unwrap()
                    .insert(validator.clone(), automaton.clone());

                let (reporter, reporter_mailbox) =
                    mocks::Reporter::<PublicKey, V, Sha256Digest>::new(
                        namespace,
                        *poly::public::<V>(&polynomial),
                        Some(5),
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
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        height_bound: 2,
                        rebroadcast_timeout: Duration::from_secs(5),
                        priority_acks: false,
                        priority_proposals: false,
                        journal_heights_per_section: 10,
                        journal_replay_buffer: NZUsize!(4096),
                        journal_write_buffer: NZUsize!(4096),
                        journal_name_prefix: format!("ordered-broadcast-seq-{validator}-"),
                        journal_compression: Some(3),
                        journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    },
                );

                let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
                engine.start((a1, a2), (b1, b2));
            }

            // Spawn sequencer engine
            {
                let context = context.with_label("sequencer");
                let automaton = mocks::Automaton::<PublicKey>::new(|_| false);
                automatons
                    .lock()
                    .unwrap()
                    .insert(sequencer.public_key(), automaton.clone());
                let (reporter, reporter_mailbox) =
                    mocks::Reporter::<PublicKey, V, Sha256Digest>::new(
                        namespace,
                        *poly::public::<V>(&polynomial),
                        Some(5),
                    );
                context.with_label("reporter").spawn(|_| reporter.run());
                reporters.insert(sequencer.public_key(), reporter_mailbox);
                let engine = Engine::new(
                    context.with_label("engine"),
                    Config {
                        crypto: sequencer.clone(),
                        relay: automaton.clone(),
                        automaton,
                        reporter: reporters.get(&sequencer.public_key()).unwrap().clone(),
                        monitor: mocks::Monitor::new(Epoch::new(111)),
                        sequencers: mocks::Sequencers::<PublicKey>::new(vec![
                            sequencer.public_key()
                        ]),
                        validators: mocks::Validators::<PublicKey, V>::new(
                            polynomial.clone(),
                            validator_pks,
                            None,
                        ),
                        namespace: namespace.to_vec(),
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        height_bound: 2,
                        rebroadcast_timeout: Duration::from_secs(5),
                        priority_acks: false,
                        priority_proposals: false,
                        journal_heights_per_section: 10,
                        journal_replay_buffer: NZUsize!(4096),
                        journal_write_buffer: NZUsize!(4096),
                        journal_name_prefix: format!(
                            "ordered-broadcast-seq-{}-",
                            sequencer.public_key()
                        ),
                        journal_compression: Some(3),
                        journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    },
                );

                let ((a1, a2), (b1, b2)) = registrations.remove(&sequencer.public_key()).unwrap();
                engine.start((a1, a2), (b1, b2));
            }

            // Await reporters
            await_reporters(
                context.with_label("reporter"),
                vec![sequencer.public_key()],
                &reporters,
                (100, Epoch::new(111), true),
            )
            .await;
        });
    }

    #[test_traced]
    fn test_external_sequencer() {
        external_sequencer::<MinPk>();
        external_sequencer::<MinSig>();
    }

    fn run_1k<V: Variant>() {
        let num_validators: u32 = 10;
        let cfg = deterministic::Config::new();
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
            )
            .await;
            let delayed_link = Link {
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };
            let mut oracle_clone = oracle.clone();
            link_participants(&mut oracle_clone, &pks, Action::Update(delayed_link), None).await;

            let automatons = Arc::new(Mutex::new(
                BTreeMap::<PublicKey, mocks::Automaton<PublicKey>>::new(),
            ));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<PublicKey, V, Sha256Digest>>::new();
            let sequencers = &pks[0..pks.len() / 2];
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                sequencers,
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                Duration::from_millis(150),
                |_| false,
                None,
            );

            await_reporters(
                context.with_label("reporter"),
                sequencers.to_vec(),
                &reporters,
                (1_000, Epoch::new(111), false),
            )
            .await;
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_min_pk() {
        run_1k::<MinPk>();
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_min_sig() {
        run_1k::<MinSig>();
    }
}
