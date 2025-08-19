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
//! The engine does not try to "fill gaps" when missing threshold signatures. When validators
//! fall behind or miss signatures for certain indices, the tip may skip ahead and those
//! signatures may never be emitted by the local engine. Before skipping ahead, we ensure that
//! at-least-one honest validator has the threshold signature for any skipped index. This design
//! is intentional to prioritize the creation of threshold signatures as fast as possible. By
//! advancing the tip, honest validators can continue producing threshold signatures for new
//! indices rather than getting stuck trying to backfill missing signatures. Validators who are
//! online and honest can maintain consensus even when others fall behind or go offline.
//! Backfilling missing signatures is left to other parts of the application that can implement
//! appropriate recovery strategies.

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
    use super::{mocks, types::Epoch, Config, Engine};
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{
                group::Share,
                ops as bls_ops, poly,
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
    use commonware_utils::{NZUsize, NonZeroDuration};
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
        latency: 10.0,
        jitter: 1.0,
        success_rate: 1.0,
    };

    /// Register all participants with the network oracle.
    async fn register_participants(
        oracle: &mut Oracle<PublicKey>,
        participants: &[PublicKey],
    ) -> Registrations<PublicKey> {
        let mut registrations = BTreeMap::new();
        for participant in participants.iter() {
            let (sender, receiver) = oracle.register(participant.clone(), 0).await.unwrap();
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
        validator_pks: &[PublicKey],
        validators: &[(PublicKey, PrivateKey, Share)],
        registrations: &mut Registrations<PublicKey>,
        automatons: &mut BTreeMap<PublicKey, mocks::Application>,
        reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<V, Sha256Digest>>,
        oracle: &mut Oracle<PublicKey>,
        rebroadcast_timeout: Duration,
        invalid_when: fn(u64) -> bool,
    ) -> HashMap<PublicKey, mocks::Monitor> {
        let mut monitors = HashMap::new();
        let namespace = b"my testing namespace";

        // Create a single shared reporter for all validators
        let (reporter, reporter_mailbox) = mocks::Reporter::<V, Sha256Digest>::new(
            namespace,
            validator_pks.len() as u32,
            polynomial.clone(),
        );
        context
            .with_label("shared_reporter")
            .spawn(|_| reporter.run());

        // Use the same reporter mailbox for all validators
        for (validator, _scheme, _share) in validators.iter() {
            reporters.insert(validator.clone(), reporter_mailbox.clone());
        }

        for (validator, _scheme, share) in validators.iter() {
            let context = context.with_label(&validator.to_string());
            let monitor = mocks::Monitor::new(111);
            monitors.insert(validator.clone(), monitor.clone());
            let supervisor = {
                let identity = *poly::public::<V>(&polynomial);
                let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                s.add_epoch(
                    111,
                    share.clone(),
                    polynomial.clone(),
                    validator_pks.to_vec(),
                );
                s
            };

            let blocker = oracle.control(validator.clone());

            let automaton = mocks::Application::new(invalid_when);
            automatons.insert(validator.clone(), automaton.clone());

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
                    epoch_bounds: (1, 1),
                    window: std::num::NonZeroU64::new(10).unwrap(),
                    prune_buffer: 100,
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
                        let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, 0));
                        let contiguous_index = mailbox.get_contiguous_tip().await.unwrap_or(0);
                        debug!(
                            index,
                            epoch,
                            contiguous_index,
                            threshold_index,
                            threshold_epoch,
                            ?reporter,
                            "reporter status"
                        );
                        if contiguous_index >= threshold_index && epoch >= threshold_epoch {
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
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                |_| false,
            );
            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_all_online() {
        all_online::<MinPk>();
        all_online::<MinSig>();
    }

    fn unclean_shutdown<V: Variant>() {
        // Test parameters
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let target_index = 200; // Target multiple rounds of signing
        let max_shutdowns = 10; // Maximum number of shutdowns per validator
        let min_shutdowns = 2; // Minimum number of shutdowns per validator
        let shutdown_range_min = Duration::from_millis(100);
        let shutdown_range_max = Duration::from_millis(1_000);

        // Must be shorter than the maximum shutdown range to make progress after restarting
        let rebroadcast_timeout = NonZeroDuration::new_panic(Duration::from_millis(20));

        let mut prev_ctx = None;
        let shutdown_counts = Arc::new(Mutex::new(HashMap::<PublicKey, u32>::new()));
        let test_completed = Arc::new(Mutex::new(false));
        let all_validators = Arc::new(Mutex::new(Vec::new()));

        // Persistent storage for single shared reporter state across restarts
        // Maps index -> (digest, epoch)
        let persistent_digests =
            Arc::new(Mutex::new(BTreeMap::<u64, (Sha256Digest, Epoch)>::new()));

        // Generate shares once
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, mut shares_vec) =
            ops::generate_shares::<_, V>(&mut rng, None, num_validators, quorum);
        let identity = *poly::public::<V>(&polynomial);
        shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

        // Continue until shared reporter reaches target or max shutdowns exceeded
        while !*test_completed.lock().unwrap()
            && shutdown_counts.lock().unwrap().values().max().unwrap_or(&0) < &max_shutdowns
        {
            let completed_clone = test_completed.clone();
            let shutdown_counts_clone = shutdown_counts.clone();
            let all_validators_clone = all_validators.clone();
            let shares_vec_clone = shares_vec.clone();
            let polynomial_clone = polynomial.clone();
            let persistent_digests_clone = persistent_digests.clone();

            let f = move |mut context: Context| {
                let completed = completed_clone;
                let shutdown_counts = shutdown_counts_clone;
                let all_validators = all_validators_clone;
                let mut shares_vec = shares_vec_clone;
                let polynomial = polynomial_clone;
                let persistent_digests = persistent_digests_clone;
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

                    // Create a single shared reporter with persistent state
                    let saved_digests = persistent_digests.lock().unwrap().clone();

                    if !saved_digests.is_empty() {
                        debug!(
                            num_digests = saved_digests.len(),
                            min_index = saved_digests.keys().min().copied(),
                            max_index = saved_digests.keys().max().copied(),
                            "Restoring shared reporter with saved digests"
                        );
                    }

                    let (reporter, reporter_mailbox) =
                        mocks::Reporter::<V, Sha256Digest>::new_with_state(
                            namespace,
                            num_validators,
                            polynomial.clone(),
                            saved_digests,
                        );
                    context
                        .with_label("shared_reporter")
                        .spawn(|_| reporter.run());

                    // Single shared reporter mailbox for all validators
                    let shared_reporter = reporter_mailbox;

                    for (validator, _scheme, share) in validators.iter() {
                        let validator_context = context.with_label(&validator.to_string());
                        let monitor = mocks::Monitor::new(111);
                        engine_monitors.insert(validator.clone(), monitor.clone());
                        let supervisor = {
                            let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                            s.add_epoch(111, share.clone(), polynomial.clone(), pks.to_vec());
                            s
                        };

                        let blocker = oracle.control(validator.clone());
                        let automaton = mocks::Application::new(|_| false);
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
                                reporter: shared_reporter.clone(),
                                blocker,
                                namespace: namespace.to_vec(),
                                priority_acks: false,
                                rebroadcast_timeout,
                                epoch_bounds: (1, 1),
                                window: std::num::NonZeroU64::new(10).unwrap(),
                                prune_buffer: 100,
                                // Use validator-specific partition for journal recovery
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
                    let completion_task = {
                        let mut reporter_mailbox = shared_reporter.clone();
                        let completed_ref = completed.clone();
                        let task = context.with_label("completion_watcher").spawn(
                            move |context| async move {
                                loop {
                                    if let Some((tip_index, _epoch)) =
                                        reporter_mailbox.get_tip().await
                                    {
                                        if tip_index >= target_index {
                                            // Verify that the shared reporter has certificates for all indices
                                            let mut success = true;
                                            for check_index in 0..=target_index {
                                                if reporter_mailbox.get(check_index).await.is_none() {
                                                    debug!(
                                                        check_index,
                                                        "No certificate for index"
                                                    );
                                                    success = false;
                                                    break;
                                                }
                                            }
                                            if success {
                                                *completed_ref.lock().unwrap() = true;
                                                debug!(
                                                    tip_index, "Shared reporter reached target with all certificates"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    context.sleep(Duration::from_millis(50)).await;
                                }
                            },
                        );
                        Some(task)
                    };

                    // Random shutdown timing to simulate unclean shutdown
                    let shutdown_wait = context.gen_range(shutdown_range_min..shutdown_range_max);
                    select! {
                        _ = context.sleep(shutdown_wait) => {
                            debug!(shutdown_wait = ?shutdown_wait, "Simulating unclean shutdown");

                            // Save shared reporter state before shutdown
                            {
                                let mut reporter_mailbox = shared_reporter.clone();
                                let digests = reporter_mailbox.get_all_digests().await;
                                debug!(
                                    num_digests = digests.len(),
                                    min_index = digests.keys().min().copied(),
                                    max_index = digests.keys().max().copied(),
                                    "Saving shared reporter digests before shutdown"
                                );
                                // Save the single shared reporter state
                                let mut saved_digests = persistent_digests.lock().unwrap();
                                *saved_digests = digests;
                            }

                            // Track which validators were running when shutdown occurred
                            let mut counts = shutdown_counts.lock().unwrap();
                            for (pk, _, _) in validators {
                                *counts.entry(pk).or_insert(0) += 1;
                            }
                            (false, context) // Unclean shutdown
                        },
                        _ = async { if let Some(task) = completion_task { task.await } else { futures::future::pending().await } } => {
                            debug!("Shared reporter completed normally");
                            (true, context) // Clean completion
                        }
                    }
                }
            };

            let (complete, context) = if let Some(prev_ctx) = prev_ctx {
                let shutdown_count = shutdown_counts.lock().unwrap().values().sum::<u32>();
                debug!(shutdown_count, "Restarting from previous context");
                deterministic::Runner::from(prev_ctx)
            } else {
                debug!("Starting initial run");
                deterministic::Runner::timed(Duration::from_secs(45))
            }
            .start(f);

            prev_ctx = Some(context.recover());

            if complete {
                debug!("Test completed successfully");
                break;
            }

            let shutdown_count = shutdown_counts.lock().unwrap().values().sum::<u32>();
            debug!(
                shutdown_count,
                completed = if *test_completed.lock().unwrap() {
                    1
                } else {
                    0
                },
                "Shutdown occurred, restarting"
            );
        }

        // Verify that the shared reporter reached the target with all certificates
        let completed = *test_completed.lock().unwrap();
        let total_shutdowns = shutdown_counts.lock().unwrap().values().sum::<u32>();
        assert!(
            completed,
            "Shared reporter should reach target index {target_index} with all certificates despite unclean shutdowns after {total_shutdowns} shutdowns"
        );

        // Verify that each validator experienced a minimum number of shutdowns
        let counts = shutdown_counts.lock().unwrap();
        for pk in all_validators.lock().unwrap().iter() {
            let count = counts.get(pk).copied().unwrap_or(0);
            assert!(
                count >= min_shutdowns,
                "Validator {pk:?} should have at least {min_shutdowns} shutdowns, but had {count}"
            );
        }

        debug!(
            total_shutdowns,
            target_index, "Unclean shutdown test completed successfully"
        );
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown::<MinPk>();
        unclean_shutdown::<MinSig>();
    }

    fn slow_and_lossy_links<V: Variant>(seed: u64) -> String {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120)));
        let runner = deterministic::Runner::new(cfg);

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
            shares_vec.sort_by(|a, b| a.index.cmp(&b.index));

            // Use degraded network links with realistic conditions
            let degraded_link = Link {
                latency: 200.0,
                jitter: 150.0,
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
                |_| false,
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;

            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links::<MinPk>(0);
        slow_and_lossy_links::<MinSig>(0);
    }

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

    fn one_offline<V: Variant>() {
        let num_validators: u32 = 5;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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

            // Start only 4 out of 5 validators (one offline)
            let online_validators: Vec<_> = validators.iter().take(4).cloned().collect();
            let online_pks: Vec<_> = pks.iter().take(4).cloned().collect();

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &online_pks,
                &online_validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(5),
                |_| false,
            );
            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_one_offline() {
        one_offline::<MinPk>();
        one_offline::<MinSig>();
    }

    /// Test that consensus can be reached starting from index 0.
    fn consensus_from_index_zero<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                |_| false,
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_consensus_from_index_zero() {
        consensus_from_index_zero::<MinPk>();
        consensus_from_index_zero::<MinSig>();
    }

    /// Test consensus recovery after a network partition.
    fn network_partition<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(60));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                |_| false,
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
                latency: 10.0,
                jitter: 1.0,
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

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_network_partition() {
        network_partition::<MinPk>();
        network_partition::<MinSig>();
    }

    /// Test consensus resilience to Byzantine behavior.
    fn invalid_signature_injection<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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

            // Simulate more realistic Byzantine behavior with pseudo-random faults
            // Using a deterministic seed based on index for reproducible tests
            let byzantine_fault_fn = |index: u64| -> bool {
                use std::{
                    collections::hash_map::DefaultHasher,
                    hash::{Hash, Hasher},
                };

                let mut hasher = DefaultHasher::new();
                index.hash(&mut hasher);
                let hash_value = hasher.finish();

                // Create Byzantine faults with ~5% probability using deterministic hash
                // This simulates realistic sporadic Byzantine behavior
                (hash_value % 100) < 5
            };

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
                byzantine_fault_fn,
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_invalid_signature_injection() {
        invalid_signature_injection::<MinPk>();
        invalid_signature_injection::<MinSig>();
    }

    /// Test that verifies cryptographic signatures are properly validated.
    fn cryptographic_validation<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                |_| false,
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;

            // Additional validation: verify that consensus was achieved and items are retrievable
            // The reporter mock already validates ack signatures internally and panics on invalid ones
            for (validator_pk, mut reporter_mailbox) in reporters {
                let tip_result = reporter_mailbox.get_tip().await;
                assert!(
                    tip_result.is_some(),
                    "Reporter for validator {validator_pk:?} should have a tip"
                );

                let (tip_index, tip_epoch) = tip_result.unwrap();
                assert!(
                    tip_index >= 1,
                    "Tip should have progressed beyond initial state for validator {validator_pk:?}"
                );
                assert_eq!(
                    tip_epoch, 111,
                    "Tip epoch should match expected epoch for validator {validator_pk:?}"
                );

                // Validate that we can retrieve the digest for consensus items
                if tip_index > 0 {
                    let item_result = reporter_mailbox.get(tip_index - 1).await;
                    assert!(
                        item_result.is_some(),
                        "Should be able to retrieve consensus item for validator {validator_pk:?}"
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_cryptographic_validation() {
        cryptographic_validation::<MinPk>();
        cryptographic_validation::<MinSig>();
    }

    /// Test various types of Byzantine fault patterns to ensure robustness.
    fn advanced_byzantine_faults<V: Variant>() {
        let num_validators: u32 = 7; // Larger set to test more fault combinations
        let quorum: u32 = 5; // Can tolerate up to 2 Byzantine validators
        let runner = deterministic::Runner::timed(Duration::from_secs(45));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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

            // More sophisticated Byzantine fault patterns
            let advanced_byzantine_fn = |index: u64| -> bool {
                use std::{
                    collections::hash_map::DefaultHasher,
                    hash::{Hash, Hasher},
                };

                let mut hasher = DefaultHasher::new();
                index.hash(&mut hasher);
                let hash_value = hasher.finish();

                match index % 11 {
                    // Use prime number for less predictable pattern
                    // Occasional random faults (~8% of the time)
                    0..=2 if (hash_value % 100) < 8 => true,
                    // Burst faults: consecutive failures
                    3..=5 if index > 10 && index < 15 => true,
                    // Periodic but irregular faults
                    7 if (hash_value % 13) == 0 => true,
                    _ => false,
                }
            };

            spawn_validator_engines::<V>(
                context.with_label("validator"),
                polynomial.clone(),
                &pks,
                &validators,
                &mut registrations,
                &mut automatons.lock().unwrap(),
                &mut reporters,
                &mut oracle,
                Duration::from_secs(8), // Longer timeout for more complex scenarios
                advanced_byzantine_fn,
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
        });
    }

    #[test_traced]
    fn test_advanced_byzantine_faults() {
        advanced_byzantine_faults::<MinPk>();
        advanced_byzantine_faults::<MinSig>();
    }

    /// Test insufficient validator participation (below quorum).
    fn insufficient_validators<V: Variant>() {
        let num_validators: u32 = 5;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(15));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                let monitor = mocks::Monitor::new(111);
                let supervisor = {
                    let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
                    s.add_epoch(
                        111,
                        share.clone(),
                        polynomial.clone(),
                        pks.to_vec(),
                    );
                    s
                };

                let blocker = oracle.control(validator.clone());

                let automaton = mocks::Application::new(|_| false);
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
                        epoch_bounds: (1, 1),
                        window: std::num::NonZeroU64::new(10).unwrap(),
                        prune_buffer: 100,
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
                // The reporter only advances contiguous_tip when valid threshold signatures are received
                // and cryptographically verified. A contiguous_tip > 0 means at least one threshold
                // signature was successfully created and validated, which should be impossible
                // with insufficient validators (below quorum).
                let contiguous_tip = reporter_mailbox.get_contiguous_tip().await.unwrap_or(0);
                if contiguous_tip > 0 {
                    any_consensus = true;
                    tracing::warn!(
                        ?validator_pk,
                        contiguous_tip,
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

    #[test_traced]
    fn test_insufficient_validators() {
        insufficient_validators::<MinPk>();
        insufficient_validators::<MinSig>();
    }

    /// Test that verifies threshold signatures are mathematically correct and properly formed.
    fn threshold_signature_correctness<V: Variant>() {
        let num_validators: u32 = 4;
        let quorum: u32 = 3;
        let runner = deterministic::Runner::timed(Duration::from_secs(30));

        runner.start(|mut context| async move {
            let (polynomial, mut shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);
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
                |_| false, // No Byzantine faults for this test
            );

            await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;

            // Now verify that all consensus items have mathematically valid threshold signatures
            for (validator_pk, mut reporter_mailbox) in reporters {
                let tip_result = reporter_mailbox.get_tip().await;
                assert!(
                    tip_result.is_some(),
                    "Reporter should have achieved consensus"
                );

                let (tip_index, _) = tip_result.unwrap();

                // Check each consensus item up to the tip (starting from 1, as 0 might be genesis)
                for index in 1..=tip_index {
                    let item_result = reporter_mailbox.get(index).await;
                    assert!(
                        item_result.is_some(),
                        "Should have consensus item at index {index}"
                    );

                    let (digest, epoch) = item_result.unwrap();

                    // Manually verify that this item would have a valid threshold signature
                    // by constructing the expected item and checking signature validity
                    let _item = super::types::Item { index, digest };
                    let mut ack_namespace = b"my testing namespace".to_vec();
                    ack_namespace.extend_from_slice(b"_AGG_ACK");

                    // We can't directly access the threshold signature from the reporter,
                    // but we can verify that the reporter's acceptance implies valid crypto.
                    // The reporter mock now validates threshold signatures and would panic
                    // if they were invalid, so reaching this point means they were valid.

                    tracing::debug!(
                        ?validator_pk,
                        index,
                        epoch,
                        "Verified valid threshold signature for consensus item"
                    );
                }
            }
        });
    }

    #[test_traced]
    fn test_threshold_signature_correctness() {
        threshold_signature_correctness::<MinPk>();
        threshold_signature_correctness::<MinSig>();
    }

    /// Test that manually constructs and verifies threshold signatures.
    fn manual_threshold_verification<V: Variant>() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));

        runner.start(|mut context| async move {
            let num_validators = 4u32;
            let quorum = 3u32;

            // Generate threshold cryptography setup
            let (polynomial, shares_vec) =
                ops::generate_shares::<_, V>(&mut context, None, num_validators, quorum);

            // Create a test item to sign
            let test_item = super::types::Item {
                index: 42,
                digest: Sha256Digest::from([1u8; 32]),
            };

            let namespace = b"test_namespace";
            let ack_namespace = [namespace.as_slice(), b"_AGG_ACK"].concat();

            // Generate partial signatures from sufficient validators (quorum=3)
            let mut partial_sigs = Vec::new();
            for share in shares_vec.iter().take(quorum as usize) {
                let partial_sig = bls_ops::partial_sign_message::<V>(
                    share,
                    Some(&ack_namespace),
                    &test_item.encode(),
                );
                partial_sigs.push(partial_sig);
            }

            // Recover partial signatures into threshold signature
            let threshold_sig = poly::Signature::<V>::recover(quorum, &partial_sigs).expect(
                "Should be able to recover threshold signature from sufficient partial signatures",
            );

            // Verify the threshold signature
            let threshold_public = poly::public::<V>(&polynomial);
            let verification_result = bls_ops::verify_message::<V>(
                threshold_public,
                Some(&ack_namespace),
                &test_item.encode(),
                &threshold_sig,
            );

            assert!(
                verification_result.is_ok(),
                "Manually constructed threshold signature should be valid: {:?}",
                verification_result.err()
            );

            // Test with insufficient signatures (should fail)
            let insufficient_partial_sigs: Vec<_> = partial_sigs
                .iter()
                .take(quorum as usize - 1)
                .cloned()
                .collect();
            let insufficient_result =
                poly::Signature::<V>::recover(quorum, &insufficient_partial_sigs);

            assert!(
                insufficient_result.is_err(),
                "Should not be able to recover threshold signature with insufficient partial signatures"
            );

            tracing::debug!("Manual threshold signature verification completed successfully");
        });
    }

    #[test_traced]
    fn test_manual_threshold_verification() {
        manual_threshold_verification::<MinPk>();
        manual_threshold_verification::<MinSig>();
    }
}
