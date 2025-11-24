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

pub mod signing_scheme;
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

// #[cfg(test)]
// mod tests {
//     use super::{mocks, Config, Engine};
// <<<<<<< HEAD
//     use crate::aggregation::{
//         mocks::fixtures::{bls12381_multisig, bls12381_threshold, ed25519, Fixture},
//         signing_scheme::AggregationScheme,
//     };
// ||||||| fe23fd2b5
//     use crate::{aggregation::mocks::Strategy, types::Epoch};
// =======
//     use crate::{
//         aggregation::mocks::Strategy,
//         types::{Epoch, EpochDelta},
//     };
// >>>>>>> main
//     use commonware_cryptography::{
//         bls12381::primitives::variant::{MinPk, MinSig},
//         ed25519::PublicKey,
//         sha256::Digest as Sha256Digest,
//     };
//     use commonware_macros::{select, test_traced};
//     use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
//     use commonware_runtime::{
//         buffer::PoolRef,
//         deterministic::{self, Context},
//         Clock, Metrics, Runner, Spawner,
//     };
//     use commonware_utils::{NZUsize, NonZeroDuration};
//     use futures::{channel::oneshot, future::join_all};
//     use rand::{rngs::StdRng, Rng, SeedableRng};
//     use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};
//     use tracing::debug;

//     type Registrations<P> = BTreeMap<P, (Sender<P>, Receiver<P>)>;

//     const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
//     const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

//     /// Reliable network link configuration for testing.
//     const RELIABLE_LINK: Link = Link {
//         latency: Duration::from_millis(10),
//         jitter: Duration::from_millis(1),
//         success_rate: 1.0,
//     };

//     /// Register all participants with the network oracle.
//     async fn register_participants(
//         oracle: &mut Oracle<PublicKey>,
//         participants: &[PublicKey],
//     ) -> Registrations<PublicKey> {
//         let mut registrations = BTreeMap::new();
//         for participant in participants.iter() {
//             let (sender, receiver) = oracle
//                 .control(participant.clone())
//                 .register(0)
//                 .await
//                 .unwrap();
//             registrations.insert(participant.clone(), (sender, receiver));
//         }
//         registrations
//     }

//     /// Establish network links between all participants.
//     async fn link_participants(
//         oracle: &mut Oracle<PublicKey>,
//         participants: &[PublicKey],
//         link: Link,
//     ) {
//         for v1 in participants.iter() {
//             for v2 in participants.iter() {
//                 if v2 == v1 {
//                     continue;
//                 }
//                 oracle
//                     .add_link(v1.clone(), v2.clone(), link.clone())
//                     .await
//                     .unwrap();
//             }
//         }
//     }

//     /// Initialize a simulated network environment.
//     async fn initialize_simulation<S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>>(
//         context: Context,
//         fixture: &Fixture<S>,
//         link: Link,
//     ) -> (Oracle<PublicKey>, Registrations<PublicKey>) {
//         let (network, mut oracle) = Network::new(
//             context.with_label("network"),
//             commonware_p2p::simulated::Config {
//                 max_size: 1024 * 1024,
//                 disconnect_on_block: true,
//                 tracked_peer_sets: None,
//             },
//         );
//         network.start();

//         let registrations = register_participants(&mut oracle, &fixture.participants).await;
//         link_participants(&mut oracle, &fixture.participants, link).await;

//         (oracle, registrations)
//     }

//     /// Spawn aggregation engines for all validators.
//     #[allow(clippy::too_many_arguments)]
//     fn spawn_validator_engines<S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>>(
//         context: Context,
//         fixture: &Fixture<S>,
//         registrations: &mut Registrations<PublicKey>,
//         reporters: &mut BTreeMap<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>,
//         oracle: &mut Oracle<PublicKey>,
//         namespace: &[u8],
//         epoch: u64,
//         rebroadcast_timeout: Duration,
//         incorrect: Vec<usize>,
//         journal_prefix: &str,
//     ) {
//         for (idx, participant) in fixture.participants.iter().enumerate() {
//             let validator_context = context.with_label(&participant.to_string());

// <<<<<<< HEAD
//             // Create SchemeProvider and register scheme for epoch
//             let scheme_provider = mocks::SchemeProvider::new();
//             assert!(scheme_provider.register(epoch, fixture.schemes[idx].clone()));
// ||||||| fe23fd2b5
//         for (i, (validator, _, share)) in validators.iter().enumerate() {
//             let context = context.with_label(&validator.to_string());
//             let monitor = mocks::Monitor::new(111);
//             monitors.insert(validator.clone(), monitor.clone());
//             let supervisor = {
//                 let identity = *poly::public::<V>(&polynomial);
//                 let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                 s.add_epoch(
//                     111,
//                     share.clone(),
//                     polynomial.clone(),
//                     validator_pks.to_vec(),
//                 );
//                 s
//             };
// =======
//         for (i, (validator, _, share)) in validators.iter().enumerate() {
//             let context = context.with_label(&validator.to_string());
//             let monitor = mocks::Monitor::new(Epoch::new(111));
//             monitors.insert(validator.clone(), monitor.clone());
//             let supervisor = {
//                 let identity = *poly::public::<V>(&polynomial);
//                 let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                 s.add_epoch(
//                     Epoch::new(111),
//                     share.clone(),
//                     polynomial.clone(),
//                     validator_pks.to_vec(),
//                 );
//                 s
//             };
// >>>>>>> main

//             // Create monitor
//             let monitor = mocks::Monitor::new(epoch);

//             // Create automaton with Incorrect strategy for byzantine validators
//             let strategy = if incorrect.contains(&idx) {
//                 mocks::Strategy::Incorrect
//             } else {
//                 mocks::Strategy::Correct
//             };
//             let automaton = mocks::Application::new(strategy);

//             // Create reporter with verifier scheme
//             let (reporter, reporter_mailbox) =
//                 mocks::Reporter::new(context.clone(), namespace, fixture.verifier.clone());
//             validator_context
//                 .with_label("reporter")
//                 .spawn(|_| reporter.run());
//             reporters.insert(participant.clone(), reporter_mailbox.clone());

//             // Create blocker
//             let blocker = oracle.control(participant.clone());

//             // Create and start engine
//             let engine = Engine::new(
//                 validator_context.with_label("engine"),
//                 Config {
//                     monitor,
//                     scheme_provider,
//                     automaton,
//                     reporter: reporter_mailbox,
//                     blocker,
//                     namespace: namespace.to_vec(),
//                     priority_acks: false,
//                     rebroadcast_timeout: NonZeroDuration::new_panic(rebroadcast_timeout),
//                     epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
//                     window: std::num::NonZeroU64::new(10).unwrap(),
//                     activity_timeout: 100,
//                     journal_partition: format!("{journal_prefix}/{participant}"),
//                     journal_write_buffer: NZUsize!(4096),
//                     journal_replay_buffer: NZUsize!(4096),
//                     journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
//                     journal_compression: Some(3),
//                     journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
//                 },
//             );

//             let (sender, receiver) = registrations.remove(participant).unwrap();
//             engine.start((sender, receiver));
//         }
//     }

//     /// Wait for all reporters to reach the specified consensus threshold.
//     async fn await_reporters<S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>>(
//         context: Context,
//         reporters: &BTreeMap<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>,
//         threshold_index: u64,
//     ) {
//         let mut receivers = Vec::new();
//         for (reporter, mailbox) in reporters.iter() {
//             let (tx, rx) = oneshot::channel();
//             receivers.push(rx);

//             context.with_label("reporter_watcher").spawn({
//                 let reporter = reporter.clone();
//                 let mut mailbox = mailbox.clone();
//                 move |context| async move {
//                     loop {
// <<<<<<< HEAD
//                         let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, 0));
//                         debug!(index, epoch, threshold_index, ?reporter, "reporter status");
//                         if index >= threshold_index {
// ||||||| fe23fd2b5
//                         let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, 0));
//                         debug!(
//                             index,
//                             epoch,
//                             threshold_index,
//                             threshold_epoch,
//                             ?reporter,
//                             "reporter status"
//                         );
//                         if index >= threshold_index && epoch >= threshold_epoch {
// =======
//                         let (index, epoch) = mailbox.get_tip().await.unwrap_or((0, Epoch::zero()));
//                         debug!(
//                             index,
//                             epoch = %epoch,
//                             threshold_index,
//                             threshold_epoch = %threshold_epoch,
//                             ?reporter,
//                             "reporter status"
//                         );
//                         if index >= threshold_index && epoch >= threshold_epoch {
// >>>>>>> main
//                             debug!(
//                                 ?reporter,
//                                 "reporter reached threshold, signaling completion"
//                             );
//                             let _ = tx.send(reporter.clone());
//                             break;
//                         }
//                         context.sleep(Duration::from_millis(100)).await;
//                     }
//                 }
//             });
//         }

//         // Wait for all oneshot receivers to complete.
//         let results = join_all(receivers).await;
//         assert_eq!(results.len(), reporters.len());

//         // Check that none were cancelled.
//         for result in results {
//             assert!(result.is_ok(), "reporter was cancelled");
//         }
//     }

//     /// Test aggregation consensus with all validators online.
//     fn all_online<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 4u32;
//         let runner = deterministic::Runner::timed(Duration::from_secs(30));

//         runner.start(|mut context| async move {
//             let fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             let (mut oracle, mut registrations) =
//                 initialize_simulation(context.with_label("simulation"), &fixture, RELIABLE_LINK)
//                     .await;
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             spawn_validator_engines(
//                 context.with_label("validator"),
//                 &fixture,
//                 &mut registrations,
//                 &mut reporters,
//                 &mut oracle,
//                 namespace,
//                 epoch,
//                 Duration::from_secs(5),
//                 vec![],
//                 "aggregation",
//             );
// <<<<<<< HEAD

//             await_reporters(context.with_label("reporter"), &reporters, 100).await;
// ||||||| fe23fd2b5
//             await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
// =======
//             await_reporters(
//                 context.with_label("reporter"),
//                 &reporters,
//                 100,
//                 Epoch::new(111),
//             )
//             .await;
// >>>>>>> main
//         });
//     }

//     #[test_traced("INFO")]
//     fn test_all_online() {
//         all_online(bls12381_threshold::<MinPk, _>);
//         all_online(bls12381_threshold::<MinSig, _>);
//         all_online(bls12381_multisig::<MinPk, _>);
//         all_online(bls12381_multisig::<MinSig, _>);
//         all_online(ed25519);
//     }

//     /// Test consensus resilience to Byzantine behavior.
//     fn byzantine_proposer<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 4u32;
//         let runner = deterministic::Runner::timed(Duration::from_secs(30));

//         runner.start(|mut context| async move {
//             let fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             let (mut oracle, mut registrations) =
//                 initialize_simulation(context.with_label("simulation"), &fixture, RELIABLE_LINK)
//                     .await;
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             spawn_validator_engines(
//                 context.with_label("validator"),
//                 &fixture,
//                 &mut registrations,
//                 &mut reporters,
//                 &mut oracle,
//                 namespace,
//                 epoch,
//                 Duration::from_secs(5),
//                 vec![0],
//                 "aggregation",
//             );

// <<<<<<< HEAD
//             await_reporters(context.with_label("reporter"), &reporters, 100).await;
// ||||||| fe23fd2b5
//             await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
// =======
//             await_reporters(
//                 context.with_label("reporter"),
//                 &reporters,
//                 100,
//                 Epoch::new(111),
//             )
//             .await;
// >>>>>>> main
//         });
//     }

//     #[test_traced("INFO")]
//     fn test_byzantine_proposer() {
//         byzantine_proposer(bls12381_threshold::<MinPk, _>);
//         byzantine_proposer(bls12381_threshold::<MinSig, _>);
//         byzantine_proposer(bls12381_multisig::<MinPk, _>);
//         byzantine_proposer(bls12381_multisig::<MinSig, _>);
//         byzantine_proposer(ed25519);
//     }

//     /// Test unclean shutdown with Byzantine behavior.
//     fn unclean_byzantine_shutdown<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: Fn(&mut StdRng, u32) -> Fixture<S>,
//     {
//         // Test parameters
//         let num_validators: u32 = 4;
//         let target_index = 200u64;
//         let min_shutdowns = 4;
//         let max_shutdowns = 10;
//         let shutdown_range_min = Duration::from_millis(100);
//         let shutdown_range_max = Duration::from_millis(1_000);
//         let rebroadcast_timeout = NonZeroDuration::new_panic(Duration::from_millis(20));

//         let mut prev_checkpoint = None;

//         // Generate fixture once (persists across restarts)
//         let mut rng = StdRng::seed_from_u64(0);
//         let Fixture {
//             participants,
//             schemes,
//             verifier,
//             ..
//         } = fixture(&mut rng, num_validators);

//         // Continue until shared reporter reaches target or max shutdowns exceeded
//         let mut shutdown_count = 0;
//         while shutdown_count < max_shutdowns {
//             let participants = participants.clone();
//             let schemes = schemes.clone();
//             let verifier = verifier.clone();
//             let f = move |mut context: Context| {
//                 async move {
//                     let namespace = b"my testing namespace";
//                     let epoch = 111u64;

//                     // Set up simulated network
//                     let (network, mut oracle) = Network::new(
//                         context.with_label("network"),
//                         commonware_p2p::simulated::Config {
//                             max_size: 1024 * 1024,
//                             disconnect_on_block: true,
//                             tracked_peer_sets: None,
//                         },
//                     );
//                     network.start();

//                     let mut registrations = register_participants(&mut oracle, &participants).await;
//                     link_participants(&mut oracle, &participants, RELIABLE_LINK).await;

//                     // Create a shared reporter (all validators use the same reporter)
//                     let (reporter, mut reporter_mailbox) =
//                         mocks::Reporter::new(context.clone(), namespace, verifier.clone());
//                     context.with_label("reporter").spawn(|_| reporter.run());

// <<<<<<< HEAD
//                     // Spawn validator engines
//                     for (idx, participant) in participants.iter().enumerate() {
//                         let validator_context = context.with_label(&participant.to_string());
// ||||||| fe23fd2b5
//                     // Start validator engines
//                     for (i, (validator, _, share)) in validators.iter().enumerate() {
//                         let validator_context = context.with_label(&validator.to_string());
//                         let monitor = mocks::Monitor::new(111);
//                         engine_monitors.insert(validator.clone(), monitor.clone());
//                         let supervisor = {
//                             let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                             s.add_epoch(111, share.clone(), polynomial.clone(), pks.to_vec());
//                             s
//                         };
// =======
//                     // Start validator engines
//                     for (i, (validator, _, share)) in validators.iter().enumerate() {
//                         let validator_context = context.with_label(&validator.to_string());
//                         let monitor = mocks::Monitor::new(Epoch::new(111));
//                         engine_monitors.insert(validator.clone(), monitor.clone());
//                         let supervisor = {
//                             let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                             s.add_epoch(
//                                 Epoch::new(111),
//                                 share.clone(),
//                                 polynomial.clone(),
//                                 pks.to_vec(),
//                             );
//                             s
//                         };
// >>>>>>> main

//                         // Create SchemeProvider and register scheme for epoch
//                         let scheme_provider = mocks::SchemeProvider::new();
//                         assert!(scheme_provider.register(epoch, schemes[idx].clone()));

//                         // Create monitor
//                         let monitor = mocks::Monitor::new(epoch);

//                         // Create automaton (validator 0 is Byzantine)
//                         let strategy = if idx == 0 {
//                             mocks::Strategy::Incorrect
//                         } else {
//                             mocks::Strategy::Correct
//                         };
//                         let automaton = mocks::Application::new(strategy);

//                         // Create blocker
//                         let blocker = oracle.control(participant.clone());

//                         // Create and start engine
//                         let engine = Engine::new(
//                             validator_context.with_label("engine"),
//                             Config {
//                                 monitor,
//                                 scheme_provider,
//                                 automaton,
//                                 reporter: reporter_mailbox.clone(),
//                                 blocker,
//                                 namespace: namespace.to_vec(),
//                                 priority_acks: false,
//                                 rebroadcast_timeout,
//                                 epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
//                                 window: std::num::NonZeroU64::new(10).unwrap(),
//                                 activity_timeout: 1_024, // ensure we don't drop any certificates
//                                 journal_partition: format!("unclean_shutdown_test/{participant}"),
//                                 journal_write_buffer: NZUsize!(4096),
//                                 journal_replay_buffer: NZUsize!(4096),
//                                 journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
//                                 journal_compression: Some(3),
//                                 journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
//                             },
//                         );

//                         let (sender, receiver) = registrations.remove(participant).unwrap();
//                         engine.start((sender, receiver));
//                     }

//                     // Create a completion watcher for the shared reporter
//                     let completion =
//                         context
//                             .with_label("completion_watcher")
//                             .spawn(move |context| async move {
//                                 loop {
//                                     if let Some(tip_index) =
//                                         reporter_mailbox.get_contiguous_tip().await
//                                     {
//                                         if tip_index >= target_index {
//                                             break;
//                                         }
//                                     }
//                                     context.sleep(Duration::from_millis(50)).await;
//                                 }
//                             });

//                     // Random shutdown timing to simulate unclean shutdown
//                     let shutdown_wait = context.gen_range(shutdown_range_min..shutdown_range_max);
//                     select! {
//                         _ = context.sleep(shutdown_wait) => {
//                             debug!(shutdown_wait = ?shutdown_wait, "Simulating unclean shutdown");
//                             false // Unclean shutdown
//                         },
//                         _ = completion => {
//                             debug!("Shared reporter completed normally");
//                             true // Clean completion
//                         },
//                     }
//                 }
//             };

//             let (complete, checkpoint) = if let Some(prev_checkpoint) = prev_checkpoint {
//                 debug!(shutdown_count, "Restarting from previous context");
//                 deterministic::Runner::from(prev_checkpoint)
//             } else {
//                 debug!("Starting initial run");
//                 deterministic::Runner::timed(Duration::from_secs(45))
//             }
//             .start_and_recover(f);

//             if complete && shutdown_count >= min_shutdowns {
//                 debug!("Test completed successfully");
//                 break;
//             }

//             prev_checkpoint = Some(checkpoint);
//             shutdown_count += 1;
//         }
//     }

//     #[test_traced("INFO")]
//     fn test_unclean_byzantine_shutdown() {
//         unclean_byzantine_shutdown(bls12381_threshold::<MinPk, _>);
//         unclean_byzantine_shutdown(bls12381_threshold::<MinSig, _>);
//         unclean_byzantine_shutdown(bls12381_multisig::<MinPk, _>);
//         unclean_byzantine_shutdown(bls12381_multisig::<MinSig, _>);
//         unclean_byzantine_shutdown(ed25519);
//     }

//     /// Test unclean shutdown with unsigned index that gets signed after restart.
//     fn unclean_shutdown_with_unsigned_index<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: Fn(&mut StdRng, u32) -> Fixture<S>,
//     {
//         // Test parameters
//         let num_validators: u32 = 4;
//         let skip_index = 50u64;
//         let window = 10u64;
//         let target_index = 100u64;
//         let namespace = b"my testing namespace";

//         // Generate fixture once (persists across restarts)
//         let mut rng = StdRng::seed_from_u64(0);
//         let Fixture {
//             participants,
//             schemes,
//             verifier,
//             ..
//         } = fixture(&mut rng, num_validators);

//         // First run: let validators skip signing at skip_index and reach beyond it
//         let f = |context: Context| {
//             let participants = participants.clone();
//             let schemes = schemes.clone();
//             let verifier = verifier.clone();
//             async move {
//                 let epoch = 111u64;

//                 // Set up simulated network
//                 let (network, mut oracle) = Network::new(
//                     context.with_label("network"),
//                     commonware_p2p::simulated::Config {
//                         max_size: 1024 * 1024,
//                         disconnect_on_block: true,
//                         tracked_peer_sets: None,
//                     },
//                 );
//                 network.start();

//                 let mut registrations = register_participants(&mut oracle, &participants).await;
//                 link_participants(&mut oracle, &participants, RELIABLE_LINK).await;

//                 // Create a shared reporter
//                 let (reporter, mut reporter_mailbox) =
//                     mocks::Reporter::new(context.clone(), namespace, verifier.clone());
//                 context.with_label("reporter").spawn(|_| reporter.run());

// <<<<<<< HEAD
//                 // Start validator engines with Skip strategy for skip_index
//                 for (idx, participant) in participants.iter().enumerate() {
//                     let validator_context = context.with_label(&participant.to_string());
// ||||||| fe23fd2b5
//                 // Start validator engines with NoSignature strategy for skip_index
//                 let mut engine_monitors = HashMap::new();
//                 let automatons =
//                     Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
//                 for (validator, _, share) in validators.iter() {
//                     let validator_context = context.with_label(&validator.to_string());
//                     let monitor = mocks::Monitor::new(111);
//                     engine_monitors.insert(validator.clone(), monitor.clone());
//                     let supervisor = {
//                         let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                         s.add_epoch(111, share.clone(), polynomial_clone.clone(), pks.to_vec());
//                         s
//                     };
//                     let blocker = oracle.control(validator.clone());
// =======
//                 // Start validator engines with NoSignature strategy for skip_index
//                 let mut engine_monitors = HashMap::new();
//                 let automatons =
//                     Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
//                 for (validator, _, share) in validators.iter() {
//                     let validator_context = context.with_label(&validator.to_string());
//                     let monitor = mocks::Monitor::new(Epoch::new(111));
//                     engine_monitors.insert(validator.clone(), monitor.clone());
//                     let supervisor = {
//                         let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                         s.add_epoch(
//                             Epoch::new(111),
//                             share.clone(),
//                             polynomial_clone.clone(),
//                             pks.to_vec(),
//                         );
//                         s
//                     };
//                     let blocker = oracle.control(validator.clone());
// >>>>>>> main

//                     // Create SchemeProvider and register scheme for epoch
//                     let scheme_provider = mocks::SchemeProvider::new();
//                     assert!(scheme_provider.register(epoch, schemes[idx].clone()));

//                     // Create monitor
//                     let monitor = mocks::Monitor::new(epoch);

//                     // All validators use Skip strategy for skip_index
//                     let automaton =
//                         mocks::Application::new(mocks::Strategy::Skip { index: skip_index });

//                     // Create blocker
//                     let blocker = oracle.control(participant.clone());

//                     // Create and start engine
//                     let engine = Engine::new(
//                         validator_context.with_label("engine"),
//                         Config {
//                             monitor,
//                             scheme_provider,
//                             automaton,
//                             reporter: reporter_mailbox.clone(),
//                             blocker,
//                             namespace: namespace.to_vec(),
//                             priority_acks: false,
//                             rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
//                                 100,
//                             )),
//                             epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
//                             window: std::num::NonZeroU64::new(window).unwrap(),
//                             activity_timeout: 100,
//                             journal_partition: format!("unsigned_index_test/{participant}"),
//                             journal_write_buffer: NZUsize!(4096),
//                             journal_replay_buffer: NZUsize!(4096),
//                             journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
//                             journal_compression: Some(3),
//                             journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
//                         },
//                     );

//                     let (sender, receiver) = registrations.remove(participant).unwrap();
//                     engine.start((sender, receiver));
//                 }

//                 // Wait for validators to reach past skip_index
//                 loop {
//                     if let Some((tip_index, _)) = reporter_mailbox.get_tip().await {
//                         debug!(tip_index, skip_index, target_index, "reporter status");
//                         if tip_index >= skip_index + window - 1 {
//                             // max we can proceed before item confirmed
//                             return;
//                         }
//                     }
//                     context.sleep(Duration::from_millis(50)).await;
//                 }
//             }
//         };

//         let (_, checkpoint) =
//             deterministic::Runner::timed(Duration::from_secs(60)).start_and_recover(f);

//         // Second run: restart and verify the skip_index gets confirmed
//         let f2 = |context: Context| {
//             let participants = participants.clone();
//             let schemes = schemes.clone();
//             let verifier = verifier.clone();
//             async move {
//                 let epoch = 111u64;

//                 // Set up simulated network
//                 let (network, mut oracle) = Network::new(
//                     context.with_label("network"),
//                     commonware_p2p::simulated::Config {
//                         max_size: 1024 * 1024,
//                         disconnect_on_block: true,
//                         tracked_peer_sets: None,
//                     },
//                 );
//                 network.start();

//                 let mut registrations = register_participants(&mut oracle, &participants).await;
//                 link_participants(&mut oracle, &participants, RELIABLE_LINK).await;

//                 // Create a shared reporter
//                 let (reporter, mut reporter_mailbox) =
//                     mocks::Reporter::new(context.clone(), namespace, verifier.clone());
//                 context.with_label("reporter").spawn(|_| reporter.run());

//                 // Start validator engines with Correct strategy (will sign everything now)
// <<<<<<< HEAD
//                 for (idx, participant) in participants.iter().enumerate() {
//                     let validator_context = context.with_label(&participant.to_string());
// ||||||| fe23fd2b5
//                 let automatons =
//                     Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
//                 for (validator, _, share) in validators.iter() {
//                     let validator_context = context.with_label(&validator.to_string());
//                     let monitor = mocks::Monitor::new(111);
//                     let supervisor = {
//                         let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                         s.add_epoch(111, share.clone(), polynomial.clone(), pks.to_vec());
//                         s
//                     };
// =======
//                 let automatons =
//                     Arc::new(Mutex::new(BTreeMap::<PublicKey, mocks::Application>::new()));
//                 for (validator, _, share) in validators.iter() {
//                     let validator_context = context.with_label(&validator.to_string());
//                     let monitor = mocks::Monitor::new(Epoch::new(111));
//                     let supervisor = {
//                         let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                         s.add_epoch(
//                             Epoch::new(111),
//                             share.clone(),
//                             polynomial.clone(),
//                             pks.to_vec(),
//                         );
//                         s
//                     };
// >>>>>>> main

//                     // Create SchemeProvider and register scheme for epoch
//                     let scheme_provider = mocks::SchemeProvider::new();
//                     assert!(scheme_provider.register(epoch, schemes[idx].clone()));

//                     // Create monitor
//                     let monitor = mocks::Monitor::new(epoch);

//                     // Now all validators use Correct strategy
//                     let automaton = mocks::Application::new(mocks::Strategy::Correct);

//                     // Create blocker
//                     let blocker = oracle.control(participant.clone());

//                     // Create and start engine
//                     let engine = Engine::new(
//                         validator_context.with_label("engine"),
//                         Config {
//                             monitor,
//                             scheme_provider,
//                             automaton,
//                             reporter: reporter_mailbox.clone(),
//                             blocker,
//                             namespace: namespace.to_vec(),
//                             priority_acks: false,
//                             rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(
//                                 100,
//                             )),
//                             epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
//                             window: std::num::NonZeroU64::new(10).unwrap(),
//                             activity_timeout: 100,
//                             journal_partition: format!("unsigned_index_test/{participant}"),
//                             journal_write_buffer: NZUsize!(4096),
//                             journal_replay_buffer: NZUsize!(4096),
//                             journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
//                             journal_compression: Some(3),
//                             journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
//                         },
//                     );

//                     let (sender, receiver) = registrations.remove(participant).unwrap();
//                     engine.start((sender, receiver));
//                 }

//                 // Wait for skip_index to be confirmed (should happen on replay)
//                 loop {
//                     if let Some(tip_index) = reporter_mailbox.get_contiguous_tip().await {
//                         debug!(
//                             tip_index,
//                             skip_index, target_index, "reporter status on restart"
//                         );
//                         if tip_index >= target_index {
//                             break;
//                         }
//                     }
//                     context.sleep(Duration::from_millis(50)).await;
//                 }
//             }
//         };

//         deterministic::Runner::from(checkpoint).start(f2);
//     }

//     #[test_traced("INFO")]
//     fn test_unclean_shutdown_with_unsigned_index() {
//         unclean_shutdown_with_unsigned_index(bls12381_threshold::<MinPk, _>);
//         unclean_shutdown_with_unsigned_index(bls12381_threshold::<MinSig, _>);
//         unclean_shutdown_with_unsigned_index(bls12381_multisig::<MinPk, _>);
//         unclean_shutdown_with_unsigned_index(bls12381_multisig::<MinSig, _>);
//         unclean_shutdown_with_unsigned_index(ed25519);
//     }

//     /// Test consensus with slow and lossy network links.
//     fn slow_and_lossy_links<S, F>(fixture: F, seed: u64) -> String
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 4u32;
//         let cfg = deterministic::Config::new()
//             .with_seed(seed)
//             .with_timeout(Some(Duration::from_secs(120)));
//         let runner = deterministic::Runner::new(cfg);

//         runner.start(|mut context| async move {
//             let fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             // Use degraded network links with realistic conditions
//             let degraded_link = Link {
//                 latency: Duration::from_millis(200),
//                 jitter: Duration::from_millis(150),
//                 success_rate: 0.5,
//             };

//             let (mut oracle, mut registrations) =
//                 initialize_simulation(context.with_label("simulation"), &fixture, degraded_link)
//                     .await;
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             spawn_validator_engines(
//                 context.with_label("validator"),
//                 &fixture,
//                 &mut registrations,
//                 &mut reporters,
//                 &mut oracle,
//                 namespace,
//                 epoch,
//                 Duration::from_secs(2),
//                 vec![],
//                 "aggregation",
//             );

// <<<<<<< HEAD
//             await_reporters(context.with_label("reporter"), &reporters, 100).await;
// ||||||| fe23fd2b5
//             await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
// =======
//             await_reporters(
//                 context.with_label("reporter"),
//                 &reporters,
//                 100,
//                 Epoch::new(111),
//             )
//             .await;
// >>>>>>> main

//             context.auditor().state()
//         })
//     }

//     #[test_traced("INFO")]
//     fn test_slow_and_lossy_links() {
//         slow_and_lossy_links(bls12381_threshold::<MinPk, _>, 0);
//         slow_and_lossy_links(bls12381_threshold::<MinSig, _>, 0);
//         slow_and_lossy_links(bls12381_multisig::<MinPk, _>, 0);
//         slow_and_lossy_links(bls12381_multisig::<MinSig, _>, 0);
//         slow_and_lossy_links(ed25519, 0);
//     }

//     #[test_traced("INFO")]
//     fn test_determinism() {
//         // We use slow and lossy links as the deterministic test
//         // because it is the most complex test.
//         for seed in 1..6 {
//             // Test ed25519
//             let ed_state_1 = slow_and_lossy_links(ed25519, seed);
//             let ed_state_2 = slow_and_lossy_links(ed25519, seed);
//             assert_eq!(ed_state_1, ed_state_2);

//             // Test BLS multisig MinPk
//             let pk_state_1 = slow_and_lossy_links(bls12381_multisig::<MinPk, _>, seed);
//             let pk_state_2 = slow_and_lossy_links(bls12381_multisig::<MinPk, _>, seed);
//             assert_eq!(pk_state_1, pk_state_2);

//             // Test BLS multisig MinSig
//             let sig_state_1 = slow_and_lossy_links(bls12381_multisig::<MinSig, _>, seed);
//             let sig_state_2 = slow_and_lossy_links(bls12381_multisig::<MinSig, _>, seed);
//             assert_eq!(sig_state_1, sig_state_2);

//             // Test BLS threshold MinPk
//             let thresh_pk_state_1 = slow_and_lossy_links(bls12381_threshold::<MinPk, _>, seed);
//             let thresh_pk_state_2 = slow_and_lossy_links(bls12381_threshold::<MinPk, _>, seed);
//             assert_eq!(thresh_pk_state_1, thresh_pk_state_2);

//             // Test BLS threshold MinSig
//             let thresh_sig_state_1 = slow_and_lossy_links(bls12381_threshold::<MinSig, _>, seed);
//             let thresh_sig_state_2 = slow_and_lossy_links(bls12381_threshold::<MinSig, _>, seed);
//             assert_eq!(thresh_sig_state_1, thresh_sig_state_2);

//             // Sanity check that different schemes produce different states
//             assert_ne!(ed_state_1, pk_state_1);
//             assert_ne!(pk_state_1, sig_state_1);
//             assert_ne!(sig_state_1, thresh_pk_state_1);
//             assert_ne!(thresh_pk_state_1, thresh_sig_state_1);
//         }
//     }

//     /// Test consensus with one validator offline.
//     fn one_offline<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 5u32;
//         let runner = deterministic::Runner::timed(Duration::from_secs(30));

//         runner.start(|mut context| async move {
//             let mut fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             // Truncate to only 4 validators (one offline)
//             fixture.participants.truncate(4);
//             fixture.schemes.truncate(4);

//             let (mut oracle, mut registrations) =
//                 initialize_simulation(context.with_label("simulation"), &fixture, RELIABLE_LINK)
//                     .await;
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             spawn_validator_engines(
//                 context.with_label("validator"),
//                 &fixture,
//                 &mut registrations,
//                 &mut reporters,
//                 &mut oracle,
//                 namespace,
//                 epoch,
//                 Duration::from_secs(5),
//                 vec![],
//                 "aggregation",
//             );
// <<<<<<< HEAD

//             await_reporters(context.with_label("reporter"), &reporters, 100).await;
// ||||||| fe23fd2b5
//             await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
// =======
//             await_reporters(
//                 context.with_label("reporter"),
//                 &reporters,
//                 100,
//                 Epoch::new(111),
//             )
//             .await;
// >>>>>>> main
//         });
//     }

//     #[test_traced("INFO")]
//     fn test_one_offline() {
//         one_offline(bls12381_threshold::<MinPk, _>);
//         one_offline(bls12381_threshold::<MinSig, _>);
//         one_offline(bls12381_multisig::<MinPk, _>);
//         one_offline(bls12381_multisig::<MinSig, _>);
//         one_offline(ed25519);
//     }

//     /// Test consensus recovery after a network partition.
//     fn network_partition<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 4u32;
//         let runner = deterministic::Runner::timed(Duration::from_secs(60));

//         runner.start(|mut context| async move {
//             let fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             let (mut oracle, mut registrations) =
//                 initialize_simulation(context.with_label("simulation"), &fixture, RELIABLE_LINK)
//                     .await;
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             spawn_validator_engines(
//                 context.with_label("validator"),
//                 &fixture,
//                 &mut registrations,
//                 &mut reporters,
//                 &mut oracle,
//                 namespace,
//                 epoch,
//                 Duration::from_secs(5),
//                 vec![],
//                 "aggregation",
//             );

//             // Partition network (remove all links)
//             for v1 in fixture.participants.iter() {
//                 for v2 in fixture.participants.iter() {
//                     if v2 == v1 {
//                         continue;
//                     }
//                     oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
//                 }
//             }
//             context.sleep(Duration::from_secs(20)).await;

//             // Restore network links
//             for v1 in fixture.participants.iter() {
//                 for v2 in fixture.participants.iter() {
//                     if v2 == v1 {
//                         continue;
//                     }
//                     oracle
//                         .add_link(v1.clone(), v2.clone(), RELIABLE_LINK)
//                         .await
//                         .unwrap();
//                 }
//             }

// <<<<<<< HEAD
//             await_reporters(context.with_label("reporter"), &reporters, 100).await;
// ||||||| fe23fd2b5
//             await_reporters(context.with_label("reporter"), &reporters, 100, 111).await;
// =======
//             await_reporters(
//                 context.with_label("reporter"),
//                 &reporters,
//                 100,
//                 Epoch::new(111),
//             )
//             .await;
// >>>>>>> main
//         });
//     }

//     #[test_traced("INFO")]
//     fn test_network_partition() {
//         network_partition(bls12381_threshold::<MinPk, _>);
//         network_partition(bls12381_threshold::<MinSig, _>);
//         network_partition(bls12381_multisig::<MinPk, _>);
//         network_partition(bls12381_multisig::<MinSig, _>);
//         network_partition(ed25519);
//     }

//     /// Test insufficient validator participation (below quorum).
//     fn insufficient_validators<S, F>(fixture: F)
//     where
//         S: AggregationScheme<Sha256Digest, PublicKey = PublicKey>,
//         F: FnOnce(&mut deterministic::Context, u32) -> Fixture<S>,
//     {
//         let num_validators = 5u32;
//         let runner = deterministic::Runner::timed(Duration::from_secs(15));

//         runner.start(|mut context| async move {
//             let fixture = fixture(&mut context, num_validators);
//             let namespace = b"my testing namespace";
//             let epoch = 111u64;

//             // Set up simulated network
//             let (network, mut oracle) = Network::new(
//                 context.with_label("network"),
//                 commonware_p2p::simulated::Config {
//                     max_size: 1024 * 1024,
//                     disconnect_on_block: true,
//                     tracked_peer_sets: None,
//                 },
//             );
//             network.start();

//             let mut registrations = register_participants(&mut oracle, &fixture.participants).await;
//             link_participants(&mut oracle, &fixture.participants, RELIABLE_LINK).await;

//             // Create reporters (one per online validator)
//             let mut reporters =
//                 BTreeMap::<PublicKey, mocks::ReporterMailbox<S, Sha256Digest>>::new();

//             // Start only 2 out of 5 validators (below quorum of 3)
// <<<<<<< HEAD
//             for (idx, participant) in fixture.participants.iter().take(2).enumerate() {
//                 let validator_context = context.with_label(&participant.to_string());
// ||||||| fe23fd2b5
//             let namespace = b"my testing namespace";
//             for (validator, _scheme, share) in validators.iter().take(2) {
//                 let context = context.with_label(&validator.to_string());
//                 let monitor = mocks::Monitor::new(111);
//                 let supervisor = {
//                     let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                     s.add_epoch(
//                         111,
//                         share.clone(),
//                         polynomial.clone(),
//                         pks.to_vec(),
//                     );
//                     s
//                 };
// =======
//             let namespace = b"my testing namespace";
//             for (validator, _scheme, share) in validators.iter().take(2) {
//                 let context = context.with_label(&validator.to_string());
//                 let monitor = mocks::Monitor::new(Epoch::new(111));
//                 let supervisor = {
//                     let mut s = mocks::Supervisor::<PublicKey, V>::new(identity);
//                     s.add_epoch(
//                         Epoch::new(111),
//                         share.clone(),
//                         polynomial.clone(),
//                         pks.to_vec(),
//                     );
//                     s
//                 };
// >>>>>>> main

//                 // Create SchemeProvider and register scheme for epoch
//                 let scheme_provider = mocks::SchemeProvider::new();
//                 assert!(scheme_provider.register(epoch, fixture.schemes[idx].clone()));

//                 // Create monitor
//                 let monitor = mocks::Monitor::new(epoch);

//                 // Create automaton with Correct strategy
//                 let automaton = mocks::Application::new(mocks::Strategy::Correct);

//                 // Create reporter with verifier scheme
//                 let (reporter, reporter_mailbox) =
//                     mocks::Reporter::new(context.clone(), namespace, fixture.verifier.clone());
//                 validator_context
//                     .with_label("reporter")
//                     .spawn(|_| reporter.run());
//                 reporters.insert(participant.clone(), reporter_mailbox.clone());

//                 // Create blocker
//                 let blocker = oracle.control(participant.clone());

//                 // Create and start engine
//                 let engine = Engine::new(
//                     validator_context.with_label("engine"),
//                     Config {
//                         monitor,
//                         scheme_provider,
//                         automaton,
//                         reporter: reporter_mailbox,
//                         blocker,
//                         namespace: namespace.to_vec(),
//                         priority_acks: false,
//                         rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(3)),
//                         epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
//                         window: std::num::NonZeroU64::new(10).unwrap(),
//                         activity_timeout: 100,
//                         journal_partition: format!("aggregation/{participant}"),
//                         journal_write_buffer: NZUsize!(4096),
//                         journal_replay_buffer: NZUsize!(4096),
//                         journal_heights_per_section: std::num::NonZeroU64::new(6).unwrap(),
//                         journal_compression: Some(3),
//                         journal_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
//                     },
//                 );

//                 let (sender, receiver) = registrations.remove(participant).unwrap();
//                 engine.start((sender, receiver));
//             }

//             // With insufficient validators, consensus should not be achievable
//             // Wait long enough for any potential consensus attempts to complete
//             context.sleep(Duration::from_secs(12)).await;

//             // Check that no validator achieved consensus
//             let mut any_consensus = false;
//             for (validator_pk, mut reporter_mailbox) in reporters {
//                 let (tip, _) = reporter_mailbox
//                     .get_tip()
//                     .await
//                     .unwrap_or((0, Epoch::zero()));
//                 if tip > 0 {
//                     any_consensus = true;
//                     tracing::warn!(
//                         ?validator_pk,
//                         tip,
//                         "Unexpected consensus with insufficient validators"
//                     );
//                 }
//             }

//             // With only 2 out of 5 validators (below quorum of 3), consensus should not succeed
//             assert!(
//                 !any_consensus,
//                 "Consensus should not be achieved with insufficient validator participation (below quorum)"
//             );
//         });
//     }

//     #[test_traced("INFO")]
//     fn test_insufficient_validators() {
//         insufficient_validators(bls12381_threshold::<MinPk, _>);
//         insufficient_validators(bls12381_threshold::<MinSig, _>);
//         insufficient_validators(bls12381_multisig::<MinPk, _>);
//         insufficient_validators(bls12381_multisig::<MinSig, _>);
//         insufficient_validators(ed25519);
//     }
// }
