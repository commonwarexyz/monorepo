//! Recover threshold signatures over an externally synchronized sequencer of items.
//!
//! This module allows a dynamic set of participants to collectively produce threshold signatures
//! for any ordered sequence of items.
//!
//! The primary use case for this primitive is to allow blockchain validators to agree on a series
//! of state roots emitted from an opaque consensus process. Because some chains may finalize transaction
//! data but not the output of said transactions during consensus, agreement must be achieved asynchronously
//! over the output of consensus to support state sync and client balance proofs.
//!
//! _For applications that want to collect threshold signatures over concurrent, sequencer-driven broadcast,
//! _check out [crate::ordered_broadcast]._
//!
//! # Architecture
//!
//! The core of the module is the [Engine]. It manages the agreement process by:
//! - Requesting externally synchronized [commonware_cryptography::Digest]s
//! - Signing said digests with BLS [commonware_cryptography::bls12381::primitives::poly::PartialSignature]
//! - Multicasting partial signatures to other validators
//! - Recovering [commonware_cryptography::bls12381::primitives::poly::Signature]s from a quorum of partial signatures
//! - Monitoring recovery progress and notifying the application layer of recoveries
//!
//! The engine interacts with four main components:
//! - [crate::Automaton]: Provides external digests
//! - [crate::Reporter]: Receives agreement confirmations
//! - [crate::Monitor]: Tracks epoch transitions
//! - [crate::ThresholdSupervisor]: Manages validator sets and network identities
//!
//! # Design Decisions
//!
//! ## Missing Signature Resolution
//!
//! The engine does not try to "fill gaps" when threshold signatures are missing. When validators
//! fall behind or miss signatures for certain indices, the tip may skip ahead and those
//! signatures may never be emitted by the local engine. Before skipping ahead, we ensure that
//! at-least-one honest validator has the threshold signature for any skipped index.
//!
//! Like other consensus primitives, aggregation's design prioritizes doing useful work at tip and
//! minimal complexity over providing a comprehensive recovery mechanism. As a result, applications that need
//! to build a complete history of all formed [types::Certificate]s must implement their own mechanism to synchronize
//! historical results.
//!
//! ## Recovering Threshold Signatures
//!
//! In aggregation, participants never gossip recovered threshold signatures. Rather, they gossip [types::TipAck]s
//! with partial signatures over some index and their latest tip. This approach reduces the overhead of running aggregation
//! concurrently with a consensus mechanism and consistently results in local recovery on stable networks. To increase
//! the likelihood of local recovery, participants should tune the [Config::activity_timeout] to a value larger than the expected
//! drift of online participants (even if all participants are synchronous the tip advancement logic will advance to the `f+1`th highest
//! reported tip and drop all work below that tip minus the [Config::activity_timeout]).

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod safe_tip;

        #[cfg(test)]
        pub mod mocks;
    }
}

#[cfg(test)]
mod tests {
    use super::{mocks, Config, Engine};
    use crate::{
        aggregation::mocks::Strategy,
        types::{Epoch, EpochDelta},
    };
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
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Clock, Metrics, Runner, Spawner,
    };
    use commonware_utils::{NZUsize, NonZeroDuration, NZU32};
    use futures::{channel::oneshot, future::join_all};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{
        collections::{BTreeMap, HashMap},
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;

    type Registrations<P> = BTreeMap<P, (Sender<P>, Receiver<P>)>;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    /// Reliable network link configuration for testing.
    const RELIABLE_LINK: Link = Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    };

    /// Register all participants with the network oracle.
    async fn register_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let (sender, receiver) = oracle
                .control(participant.clone())
                .register(0)
                .await
                .unwrap();
            registrations.insert(participant.clone(), (sender, receiver));
        }
        registrations
    }

    /// Establish network links between all participants.
    async fn link_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
        link: Link,
    ) {
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v2 == v1 {
                    continue;
                }
                oracle
                    .add_link(v1.clone(), v2.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }

    /// Initialize a simulated network environment.
    async fn initialize_simulation(
        context: Context,
        num_validators: u32,
        shares_vec: &mut [Share],
        link: Link,
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
        link_participants(&mut oracle, &pks, link).await;
        (oracle, validators, pks, registrations)
    }

    /// Spawn aggregation engines for all validators.
    #[allow(clippy::too_many_arguments)]
    fn spawn_validator_engines<V: Variant>(
        context: Context,
        polynomial: poly::Public<V>,
        all_validators: &[PublicKey], // All validators in the system
        online_validators: &[(PublicKey, PrivateKey, Share)], // Only the validators to spawn
        registrations: &mut Registrations<PublicKey>,
        automatons: &mut BTreeMap<PublicKey, mocks::Application>,
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>,
        oracle: &mut Oracle<PublicKey>,
        rebroadcast_timeout: Duration,
        incorrect: Vec<usize>,
    ) -> HashMap<PublicKey, mocks::Monitor> {
        let mut monitors = HashMap::new();
        let namespace = b"my testing namespace";

        for (i, (validator, _, share)) in online_validators.iter().enumerate() {
            let context = context.with_label(&validator.to_string());
            let monitor = mocks::Monitor::new(Epoch::new(111));
            monitors.insert(validator.clone(), monitor.clone());
            let supervisor = {
                let identity = *poly::public::<V>(&polynomial);
                let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                s.add_epoch(
                    Epoch::new(111),
                    share.clone(),
                    polynomial.clone(),
                    all_validators.to_vec(), // Use all validators, not just online ones
                );
                s
            };

            let blocker = oracle.control(validator.clone());

            let automaton = mocks::Application::new(if incorrect.contains(&i) {
                Strategy::Incorrect
            } else {
                Strategy::Correct
            });
            automatons.insert(validator.clone(), automaton.clone());

            let (reporter, reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                namespace,
                all_validators.len() as u32,
                polynomial.clone(),
            );
            context.with_label("reporter").spawn(|_| reporter.run());
            reporters.insert(validator.clone(), reporter_mailbox);

            let engine = Engine::new(
                context.with_label("engine"),
                Config {
                    monitor,
                    validators: supervisor,
                    automaton: automaton.clone(),
                    reporter: reporters.get(validator).unwrap().clone(),
                    blocker,
                    namespace: namespace.to_vec(),
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(rebroadcast_timeout),
                    epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                    window: std::num::NonZeroU64::new(10).unwrap(),
                    activity_timeout: 100,
                    journal_partition: format!("aggregation/{validator}"),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                    journal_compression: Some(3),
                    journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            );

            let (sender, receiver) = registrations.remove(validator).unwrap();
            engine.start((sender, receiver));
        }
        monitors
    }

    /// Wait for all reporters to reach the specified consensus threshold.
    async fn await_reporters<V: Variant>(
        context: Context,
        reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>,
        threshold_index: u64,
        threshold_epoch: Epoch,
    ) {
        let mut receivers = Vec::new();
        for (reporter, mailbox) in reporters.iter() {
            // Create a oneshot channel to signal when the reporter has reached the threshold.
            let (tx, rx) = oneshot::channel();
            receivers.push(rx);

            context.with_label("reporter_watcher").spawn({
                let reporter = reporter.clone();
                let mut mailbox = mailbox.clone();
                move |context| async move {
                    loop {
                        let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, Epoch::zero()));
                        debug!(
                            index,
                            epoch = %epoch,
                            threshold_index,
                            threshold_epoch = %threshold_epoch,
                            ?reporter,
                            "reporter status"
                        );
                        if index >= threshold_index && epoch >= threshold_epoch {
                            debug!(
                                ?reporter,
                                "reporter reached threshold, signaling completion"
                            );
                            let _ = tx.send(reporter.clone());
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

        // Check that none were cancelled.
        for result in results {
            assert!(result.is_ok(), "reporter was cancelled");
        }
    }

    /// Test aggregation consensus with all validators online.
    fn all_online<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                RELIABLE_LINK,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();
            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(5),
                vec![],
            );
            await_reporters(
                context.with_label("reporter"),
                &reporters,
                100,
                Epoch::new(111),
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_all_online() {
        all_online::<MinPk>();
        all_online::<MinSig>();
    }

    /// Test consensus resilience to Byzantine behavior.
    fn byzantine_proposer<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                RELIABLE_LINK,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(5),
                vec![0],
            );

            await_reporters(
                context.with_label("reporter"),
                &reporters,
                100,
                Epoch::new(111),
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_byzantine_proposer() {
        byzantine_proposer::<MinPk>();
        byzantine_proposer::<MinSig>();
    }

    fn unclean_byzantine_shutdown<V: Variant>() {
        // Test parameters
        let num_validators: u32 = 4;
        let target_index = 200; // Target multiple rounds of signing
        let min_shutdowns = 4; // Minimum number of shutdowns per validator
        let max_shutdowns = 10; // Maximum number of shutdowns per validator
        let shutdown_range_min = Duration::from_millis(100);
        let shutdown_range_max = Duration::from_millis(1_000);

        // Must be shorter than the maximum shutdown range to make progress after restarting
        let rebroadcast_timeout = NonZeroDuration::new_panic(Duration::from_millis(20));

        let mut prev_checkpoint = None;
        let all_validators = Arc::new(Mutex::new(Vec::new()));

        // Generate shares once
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, mut shares_vec) =
            dkg::deal_anonymous::<V>(&mut rng, NZU32!(num_validators));
        let identity = *poly::public::<V>(&polynomial);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        // Continue until shared reporter reaches target or max shutdowns exceeded
        let mut shutdown_count = 0;
        while shutdown_count < max_shutdowns {
            let all_validators = all_validators.clone();
            let mut shares_vec = shares_vec.clone();
            let polynomial = polynomial.clone();
            let f = move |mut context: Context| {
                async move {
                    let (oracle, validators, pks, mut registrations) = initialize_simulation(
                        context.with_label("simulation"),
                        num_validators,
                        &mut shares_vec,
                        RELIABLE_LINK,
                    )
                    .await;
                    // Store all validator public keys if not already done
                    if all_validators.lock().unwrap().is_empty() {
                        let mut pks_lock = all_validators.lock().unwrap();
                        *pks_lock = pks.clone();
                    }
                    let automatons =
                        Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));

                    // Use unique journal partitions for each validator to enable restart recovery
                    let mut engine_monitors = HashMap::new();
                    let namespace = b"my testing namespace";

                    // Create a shared reporter
                    //
                    // We rely on replay to populate this reporter with a contiguous history of certificates.
                    let (reporter, mut reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                        namespace,
                        num_validators,
                        polynomial.clone(),
                    );
                    context.with_label("reporter").spawn(|_| reporter.run());

                    // Start validator engines
                    for (i, (validator, _, share)) in validators.iter().enumerate() {
                        let validator_context = context.with_label(&validator.to_string());
                        let monitor = mocks::Monitor::new(Epoch::new(111));
                        engine_monitors.insert(validator.clone(), monitor.clone());
                        let supervisor = {
                            let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                            s.add_epoch(
                                Epoch::new(111),
                                share.clone(),
                                polynomial.clone(),
                                pks.to_vec(),
                            );
                            s
                        };

                        let blocker = oracle.control(validator.clone());
                        let automaton = mocks::Application::new(if i == 0 {
                            Strategy::Incorrect
                        } else {
                            Strategy::Correct
                        });
                        automatons
                            .lock()
                            .unwrap()
                            .insert(validator.clone(), automaton.clone());

                        let engine = Engine::new(
                            validator_context.with_label("engine"),
                            Config {
                                monitor,
                                validators: supervisor,
                                automaton,
                                reporter: reporter_mailbox.clone(),
                                blocker,
                                namespace: namespace.to_vec(),
                                priority_acks: false,
                                rebroadcast_timeout,
                                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                                window: std::num::NonZeroU64::new(10).unwrap(),
                                activity_timeout: 1_024, // ensure we don't drop any certificates
                                journal_partition: format!("unclean_shutdown_test/{validator}"),
                                journal_write_buffer: NZUsize!(4096),
                                journal_replay_buffer: NZUsize!(4096),
                                journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                                journal_compression: Some(3),
                                journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                            },
                        );

                        let (sender, receiver) = registrations.remove(validator).unwrap();
                        engine.start((sender, receiver));
                    }

                    // Create a single completion watcher for the shared reporter
                    let completion =
                        context
                            .with_label("completion_watcher")
                            .spawn(move |context| async move {
                                loop {
                                    if let Some(tip_index) =
                                        reporter_mailbox.get_contiguous_tip().await
                                    {
                                        if tip_index >= target_index {
                                            break;
                                        }
                                    }
                                    context.sleep(Duration::from_millis(50)).await;
                                }
                            });

                    // Random shutdown timing to simulate unclean shutdown
                    let shutdown_wait = context.gen_range(shutdown_range_min..shutdown_range_max);
                    select! {
                        _ = context.sleep(shutdown_wait) => {
                            debug!(shutdown_wait = ?shutdown_wait, "Simulating unclean shutdown");
                            false // Unclean shutdown
                        },
                        _ = completion => {
                            debug!("Shared reporter completed normally");
                            true // Clean completion
                        },
                    }
                }
            };

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || {
                        debug!("Starting initial run");
                        deterministic::Runner::timed(Duration::from_secs(45))
                    },
                    |prev_checkpoint| {
                        debug!(shutdown_count, "Restarting from previous context");
                        deterministic::Runner::from(prev_checkpoint)
                    },
                )
                .start_and_recover(f);
            if complete && shutdown_count >= min_shutdowns {
                debug!("Test completed successfully");
                break;
            }

            prev_checkpoint = Some(checkpoint);
            shutdown_count += 1;
        }
    }

    #[test_traced("INFO")]
    fn test_unclean_byzantine_shutdown() {
        unclean_byzantine_shutdown::<MinPk>();
        unclean_byzantine_shutdown::<MinSig>();
    }

    fn unclean_shutdown_with_unsigned_index<V: Variant>() {
        // Test parameters
        let num_validators: u32 = 4;
        let skip_index = 50u64; // Index where no one will sign
        let window = 10u64;
        let target_index = 100u64;
        let namespace = b"my testing namespace";

        // Generate shares once
        let all_validators = Arc::new(Mutex::new(Vec::new()));
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, mut shares_vec) =
            dkg::deal_anonymous::<V>(&mut rng, NZU32!(num_validators));
        let identity = *poly::public::<V>(&polynomial);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        // First run: let validators skip signing at skip_index and reach beyond it
        let f = |context: Context| {
            let all_validators_clone = all_validators.clone();
            let mut shares_vec_clone = shares_vec.clone();
            let polynomial_clone = polynomial.clone();
            async move {
                let (oracle, validators, pks, mut registrations) = initialize_simulation(
                    context.with_label("simulation"),
                    num_validators,
                    &mut shares_vec_clone,
                    RELIABLE_LINK,
                )
                .await;

                // Store all validator public keys
                {
                    let mut pks_lock = all_validators_clone.lock().unwrap();
                    *pks_lock = pks.clone();
                }

                // Create a shared reporter
                let (reporter, mut reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                    namespace,
                    num_validators,
                    polynomial_clone.clone(),
                );
                context.with_label("reporter").spawn(|_| reporter.run());

                // Start validator engines with NoSignature strategy for skip_index
                let mut engine_monitors = HashMap::new();
                let automatons =
                    Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
                for (validator, _, share) in validators.iter() {
                    let validator_context = context.with_label(&validator.to_string());
                    let monitor = mocks::Monitor::new(Epoch::new(111));
                    engine_monitors.insert(validator.clone(), monitor.clone());
                    let supervisor = {
                        let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                        s.add_epoch(
                            Epoch::new(111),
                            share.clone(),
                            polynomial_clone.clone(),
                            pks.to_vec(),
                        );
                        s
                    };
                    let blocker = oracle.control(validator.clone());

                    // All validators use NoSignature strategy for skip_index
                    let automaton = mocks::Application::new(Strategy::Skip { index: skip_index });
                    automatons
                        .lock()
                        .unwrap()
                        .insert(validator.clone(), automaton.clone());

                    let engine = Engine::new(
                        validator_context.with_label("engine"),
                        Config {
                            monitor,
                            validators: supervisor,
                            automaton,
                            reporter: reporter_mailbox.clone(),
                            blocker,
                            namespace: namespace.to_vec(),
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
                                100,
                            )),
                            epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                            window: std::num::NonZeroU64::new(window).unwrap(),
                            activity_timeout: 100,
                            journal_partition: format!("unsigned_index_test/{validator}"),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                            journal_compression: Some(3),
                            journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                        },
                    );

                    let (sender, receiver) = registrations.remove(validator).unwrap();
                    engine.start((sender, receiver));
                }

                // Wait for validators to reach target_index (past skip_index)
                loop {
                    if let Some((tip_index, _)) = reporter_mailbox.get_tip().await {
                        debug!(tip_index, skip_index, target_index, "reporter status");
                        if tip_index >= skip_index + window - 1 {
                            // max we can proceed before item confirmed
                            return;
                        }
                    }
                    context.sleep(Duration::from_millis(50)).await;
                }
            }
        };
        let (_, checkpoint) =
            deterministic::Runner::timed(Duration::from_secs(60)).start_and_recover(f);

        // Second run: restart and verify the skip_index gets confirmed
        let f2 = move |context: Context| {
            async move {
                let (oracle, validators, pks, mut registrations) = initialize_simulation(
                    context.with_label("simulation"),
                    num_validators,
                    &mut shares_vec,
                    RELIABLE_LINK,
                )
                .await;

                // Create a shared reporter
                let (reporter, mut reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                    namespace,
                    num_validators,
                    polynomial.clone(),
                );
                context.with_label("reporter").spawn(|_| reporter.run());

                // Start validator engines with Correct strategy (will sign everything now)
                let automatons =
                    Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
                for (validator, _, share) in validators.iter() {
                    let validator_context = context.with_label(&validator.to_string());
                    let monitor = mocks::Monitor::new(Epoch::new(111));
                    let supervisor = {
                        let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                        s.add_epoch(
                            Epoch::new(111),
                            share.clone(),
                            polynomial.clone(),
                            pks.to_vec(),
                        );
                        s
                    };

                    let blocker = oracle.control(validator.clone());

                    // Now all validators use Correct strategy
                    let automaton = mocks::Application::new(Strategy::Correct);
                    automatons
                        .lock()
                        .unwrap()
                        .insert(validator.clone(), automaton.clone());

                    let engine = Engine::new(
                        validator_context.with_label("engine"),
                        Config {
                            monitor,
                            validators: supervisor,
                            automaton,
                            reporter: reporter_mailbox.clone(),
                            blocker,
                            namespace: namespace.to_vec(),
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
                                100,
                            )),
                            epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                            window: std::num::NonZeroU64::new(10).unwrap(),
                            activity_timeout: 100,
                            journal_partition: format!("unsigned_index_test/{validator}"),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                            journal_compression: Some(3),
                            journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                        },
                    );

                    let (sender, receiver) = registrations.remove(validator).unwrap();
                    engine.start((sender, receiver));
                }

                // Wait for skip_index to be confirmed (should happen on replay)
                loop {
                    if let Some(tip_index) = reporter_mailbox.get_contiguous_tip().await {
                        debug!(
                            tip_index,
                            skip_index, target_index, "reporter status on restart",
                        );
                        if tip_index >= target_index {
                            break;
                        }
                    }
                    context.sleep(Duration::from_millis(50)).await;
                }
            }
        };
        deterministic::Runner::from(checkpoint).start(f2);
    }

    #[test_traced("INFO")]
    fn test_unclean_shutdown_with_unsigned_index() {
        unclean_shutdown_with_unsigned_index::<MinPk>();
        unclean_shutdown_with_unsigned_index::<MinSig>();
    }

    fn slow_and_lossy_links<V: Variant>(seed: u64) -> String {
        let num_validators: u32 = 4;
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            // Use degraded network links with realistic conditions
            let degraded_link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.5,
            };

            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                degraded_link,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(2),
                vec![],
            );

            await_reporters(
                context.with_label("reporter"),
                &reporters,
                100,
                Epoch::new(111),
            )
            .await;

            context.auditor().state()
        })
    }

    #[test_traced("INFO")]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links::<MinPk>(0);
        slow_and_lossy_links::<MinSig>(0);
    }

    #[test_traced("INFO")]
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

    fn one_offline<V: Variant>() {
        let num_validators: u32 = 5;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (mut oracle, validators, all_validators, mut registrations) =
                initialize_simulation(
                    context.with_label("simulation"),
                    num_validators,
                    &mut shares_vec,
                    RELIABLE_LINK,
                )
                .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            // Start only 4 out of 5 validators (one offline)
            let online_validators: Vec<_> = validators.iter().take(4).cloned().collect();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &all_validators,    // All validators (5)
                &online_validators, // Online validators to spawn (4)
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(5),
                vec![],
            );
            await_reporters(
                context.with_label("reporter"),
                &reporters,
                100,
                Epoch::new(111),
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_one_offline() {
        one_offline::<MinPk>();
        one_offline::<MinSig>();
    }

    /// Test consensus recovery after a network partition.
    fn network_partition<V: Variant>() {
        let num_validators: u32 = 4;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            let (mut oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                RELIABLE_LINK,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(5),
                vec![],
            );

            for v1 in pks.iter() {
                for v2 in pks.iter() {
                    if v2 == v1 {
                        continue;
                    }
                    oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                }
            }
            context.sleep(Duration::from_secs(20)).await;

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            for v1 in pks.iter() {
                for v2 in pks.iter() {
                    if v2 == v1 {
                        continue;
                    }
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
            }

            await_reporters(
                context.with_label("reporter"),
                &reporters,
                100,
                Epoch::new(111),
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_network_partition() {
        network_partition::<MinPk>();
        network_partition::<MinSig>();
    }

    /// Test insufficient validator participation (below quorum).
    fn insufficient_validators<V: Variant>() {
        let num_validators: u32 = 5;
        let runner = deterministic::Runner::timed(Duration::from_secs(15));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                dkg::deal_anonymous::<V>(&mut context, NZU32!(num_validators));
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));
            let identity = *poly::public::<V>(&polynomial);

            let (oracle, validators, pks, mut registrations) = initialize_simulation(
                context.with_label("simulation"),
                num_validators,
                &mut shares_vec,
                RELIABLE_LINK,
            )
            .await;
            let automatons = Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
            let mut reporters =
                BTreeMap::<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>::new();

            // Start only 2 out of 5 validators (below quorum of 3)
            let namespace = b"my testing namespace";
            for (validator, _scheme, share) in validators.iter().take(2) {
                let context = context.with_label(&validator.to_string());
                let monitor = mocks::Monitor::new(Epoch::new(111));
                let supervisor = {
                    let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                    s.add_epoch(
                        Epoch::new(111),
                        share.clone(),
                        polynomial.clone(),
                        pks.to_vec(),
                    );
                    s
                };

                let blocker = oracle.control(validator.clone());

                let automaton = mocks::Application::new(Strategy::Correct);
                automatons.lock().unwrap().insert(validator.clone(), automaton.clone());

                let (reporter, reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
                    namespace,
                    pks.len() as u32,
                    polynomial.clone(),
                );
                context.with_label("reporter").spawn(|_| reporter.run());
                reporters.insert(validator.clone(), reporter_mailbox);

                let engine = Engine::new(
                    context.with_label("engine"),
                    Config {
                        monitor,
                        validators: supervisor,
                        automaton: automaton.clone(),
                        reporter: reporters.get(validator).unwrap().clone(),
                        blocker,
                        namespace: namespace.to_vec(),
                        priority_acks: false,
                        rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(3)),
                        epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                        window: std::num::NonZeroU64::new(10).unwrap(),
                        activity_timeout: 100,
                        journal_partition: format!("aggregation/{validator}"),
                        journal_write_buffer: NZUsize!(4096),
                        journal_replay_buffer: NZUsize!(4096),
                        journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
                        journal_compression: Some(3),
                        journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    },
                );

                let (sender, receiver) = registrations.remove(validator).unwrap();
                engine.start((sender, receiver));
            }

            // With insufficient validators, consensus should not be achievable
            // Wait long enough for any potential consensus attempts to complete
            context.sleep(Duration::from_secs(12)).await;

            // Check that no validator achieved consensus through verified threshold signatures
            let mut any_consensus = false;
            for (validator_pk, mut reporter_mailbox) in reporters {
                let (tip, _) = reporter_mailbox
                    .get_tip()
                    .await
                    .unwrap_or((0, Epoch::zero()));
                if tip > 0 {
                    any_consensus = true;
                    tracing::warn!(
                        ?validator_pk,
                        tip,
                        "Unexpected threshold signature consensus with insufficient validators"
                    );
                }
            }

            // With only 2 out of 5 validators (below quorum of 3), consensus should not succeed
            assert!(
                !any_consensus,
                "Consensus should not be achieved with insufficient validator participation (below quorum)"
            );
        });
    }

    #[test_traced("INFO")]
    fn test_insufficient_validators() {
        insufficient_validators::<MinPk>();
        insufficient_validators::<MinSig>();
    }
}
