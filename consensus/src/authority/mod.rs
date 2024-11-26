//! Authority
//!
//! PoA Consensus useful for running a DKG (round-robin leader selection, update participants with config).
//!
//! All decisions made to minimize container time and finalization latency without sacrificing
//! the ability to attribute uptime and faults.
//!
//! # Externalizable Uptime and Faults
//!
//! Instead of handling uptime and fault tracking internally, the application is notified of all
//! activity and can incorportate such information as needed (into the payload or otherwise).
//!
//! # Sync
//!
//! Wait for container notarization at tip (2f+1), fetch heights backwards (don't
//! need to backfill views).
//!
//! # Async Handling
//!
//! All application interaction occurs asynchronously, meaning that the engine can continue processing messages
//! while a payload is being built or verified (usually take hundreds of milliseconds).
//!
//! # Dedicated Processing for Consensus Messages
//!
//! All peer interaction related to consensus is strictly prioritized over any other messages (i.e. helping new
//! peers sync to the network).
//!
//! # Specification for View `v`
//!
//! _We don't assume that messages are eventually delivered and instead tolerate arbitrary drops._
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l` and advance `t_a`
//!     * If leader `l` has not been active (no votes) in last `r` views, set `t_l` to 0.
//! * If leader, propose container `c` for view `v`
//!   * If can't propose container because missing notarization/nullification for a previous view, fetch it
//!
//! Upon receiving first container `c` from `l`:
//! * Cancel `t_l`
//! * If we have `c_parent`, have verified `c_parent`, `c_parent` is notarized (either implicitly or explicitly), and we have null notarizations
//!   for all views between `c_parent` and `c`, then verify `c` and broadcast vote for `c`.
//!
//! Upon receiving `2f+1` votes for `c`:
//! * Cancel `t_a`
//! * Broadcast `c` and notarization for `c` (even if we have not verified `c`)
//! * Notarize `c` at height `h` (and recursively notarize its parents)
//! * If have not broadcast null vote for view `v`, broadcast finalize for `c`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` null votes for `v`:
//! * Broadcast null notarization for `v`
//! * Enter `v+1`
//! * If observe `>= f+1` votes for some proposal `c` in a view, fetch the non-null notarization for `c_parent` and any missing null notarizations
//!   between `c_parent` and `c`, if `c_parent` is less than last finalized, broadcast finalization instead
//!
//! Upon receiving `2f+1` finalizes for `c`:
//! * Broadcast finalization for `c` (even if we have not verified `c`)
//! * Finalize `c` at height `h` (and recursively finalize its parents)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast null vote for view `v`
//! * Every `t_r` after null vote that we are still in view `v`:
//!    * For nodes that have yet to vote null, rebroadcast null vote for view `v` and notarization from `v-1`
//!
//! _For efficiency, `c` is `hash(c)` and it is up to an external mechanism to ensure that the contents of `c` are available to all participants._
//!
//! ## Adapting Simplex to Real-World: Syncing, Restarts, and Dropped Messages
//!
//! * Distinct Leader timeout (in addition to notarization timeout)
//!     * Skip leader timeout/notarization timeout if we haven't seen a participant vote in some number of views
//! * Don't assume that all notarizations are sent with each proposal
//! * Backfill containers from notarizing peers rather than passing along with notarization message
//! * Dynamic sync for new nodes (join consensus at tip right away and backfill history + new containers on-the-fly)/no dedicated
//!   "sync" phase
//! * Send indices of public keys rather than public keys themselves
//! * Only multicast proposal `c` in `v` on transition to `v+1  to peers that haven't already voted for `c`
//! * Only multicast dependent notarizations (notarization for `c_parent` and null notarizations between `c_parent` and `c`) for `v` to peers that
//!   didn't vote for `c`
//!
//! # What is a good fit?
//!
//! * Desire fast block times (as fast as possible): No message relay through leader
//!     * Uptime/Fault tracking (over `n` previous heights instead of waiting for some timeout after notarization for
//!       more votes) -> means there is no wait at the end of a view to collect more votes/finalizes
//! * Proposals are small (include references to application data rather than application data itself): Each notarization may require each party to re-broadcast the proposal
//! * Small to medium number of validators (< 500): All messages are broadcast
//! * Strong robustness against Byzantine leaders? (still can trigger later than desired start to verification) but can't force a fetch
//!     * Saves at least 1 RTT (and more if first recipient doesn't have/is byzantine)
//!     * Minimal ability to impact performance in next view (still can timeout current view)
//!     * No requirement for consecutive honest leaders to commit
//!
//! # Tradeoff: Bandwidth Efficiency or Robustness
//!
//! * This is the difference between broadcasting a proposal to the next leader if they didn't vote for the block and waiting for them
//!   to fetch the block themselves.
//!
//! # Performance Degradation
//!
//! * Ever-growing unfinalized tip: processing views are cached in-memory
//!     * Particularly bad if composed of null notarizations
//!
//! Crazy Idea: What if there is no proposal and the vote/notarization contains all info (only ever include a hash of the proposal)? Would this undermine
//! an application's ability to build a useful product (as wouldn't know contents of block until an arbitrary point in the future, potentially after asked to produce
//! a new block/may also not know parent yet)?
//! * Could leave to the builder to decide whether to wait to produce a block until they've seen finalized parent or not. Would anyone ever want not? Could also
//!   leave constructing/disseminating the block to the builder. We agree on hashes, you can do whatever you want to get to that point?
//! * TL;DR: Agreement isn't Dissemination -> Tension: Agreement is most reliable with all-to-all broadcast but dissemnination is definitely not most efficient that way
//! * Verify returns as soon as get the proposal rather than immediately if don't have it. This will ensure that consensus messages that get to participant before payload
//!   won't just immediately be dropped?

mod actors;
mod byzantine;
mod config;
pub use config::Config;
mod encoder;
mod engine;
pub use engine::Engine;
mod mocks;
pub mod prover;
mod verifier;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

use commonware_cryptography::Digest;

pub type View = u64;

/// Context is a collection of information about the context in which a container is built.
#[derive(Clone)]
pub struct Context {
    pub view: View,
    pub parent: (View, Digest),
}

use crate::Activity;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Network closed")]
    NetworkClosed,
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Invalid container")]
    InvalidContainer,
    #[error("Invalid signature")]
    InvalidSignature,
}

/// Vote for leader is considered a proposal and a vote.
///
/// Note: it is ok to have both a vote for a proposal and the null
/// container in the same view.
///
/// Note: it is ok to notarize/finalize different proposals in the same view.
pub const NOTARIZE: Activity = 0;
pub const FINALIZE: Activity = 1;
pub const CONFLICTING_NOTARIZE: Activity = 2;
pub const CONFLICTING_FINALIZE: Activity = 3;
pub const NULLIFY_AND_FINALIZE: Activity = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use byzantine::{
        conflicter::{self, Conflicter},
        nuller::{self, Nuller},
    };
    use commonware_cryptography::{Ed25519, Scheme, Sha256};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network};
    use commonware_runtime::{
        deterministic::{self, Executor, Seed},
        Clock, Runner, Spawner,
    };
    use commonware_storage::journal::{self, Journal};
    use commonware_utils::{hex, quorum};
    use engine::Engine;
    use futures::{channel::mpsc, StreamExt};
    use governor::Quota;
    use prometheus_client::registry::Registry;
    use prover::Prover;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;

    #[test_traced]
    fn test_all_online() {
        // Create runtime
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let max_exceptions = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no forks
                let mut exceptions = 0;
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        // Ensure no skips (height == view)
                        if payloads.len() > 1 {
                            let hex_payloads =
                                payloads.iter().map(|p| hex(p.0)).collect::<Vec<String>>();
                            panic!("view: {}, payloads: {:?}", view, hex_payloads);
                        }

                        // Only check at views below timeout
                        if *view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(view).expect("view should be finalized");
                        let voters = payloads.get(digest).expect("digest should exist");
                        if voters.len() < threshold as usize {
                            // We can't verify that everyone participated at every height because some nodes may have started later.
                            panic!("view: {}, voters: {:?}", view, voters);
                        }
                        if voters.len() != n as usize {
                            exceptions += 1;
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (height, views) in finalizes.iter() {
                        // Ensure no skips (height == view)
                        if views.len() > 1 {
                            panic!("height: {}, views: {:?}", height, views);
                        }

                        // Only check at views below timeout
                        if *height > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(height).expect("height should be finalized");
                        let finalizers = views.get(digest).expect("digest should exist");
                        if finalizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every height because some nodes may have started later.
                            panic!("height: {}, finalizers: {:?}", height, finalizers);
                        }
                        if finalizers.len() != n as usize {
                            exceptions += 1;
                        }
                    }
                }

                // Ensure exceptions within allowed
                assert!(exceptions <= max_exceptions);
            }
        });
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        // Create runtime
        let n = 5;
        let seed = 42;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let rng = Arc::new(Mutex::new(StdRng::seed_from_u64(seed)));
        let storage = Arc::new(Mutex::new(HashMap::new()));
        let notarized = Arc::new(Mutex::new(HashMap::new()));
        let finalized = Arc::new(Mutex::new(HashMap::new()));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        while completed.lock().unwrap().len() != n as usize {
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let rng = rng.clone();
            let notarized = notarized.clone();
            let finalized = finalized.clone();
            let completed = completed.clone();
            let cfg = deterministic::Config {
                seed: Seed::Sampler(rng.clone()), // allows us to reuse same sampler (from original seed) across restarts
                timeout: Some(Duration::from_secs(30)),
                storage: Some(storage.clone()),
                ..Default::default()
            };
            let (executor, mut runtime, _) = Executor::init(cfg);
            executor.start(async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    runtime.clone(),
                    Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                    },
                );

                // Start network
                runtime.spawn("network", network.run());

                // Register participants
                let mut schemes = Vec::new();
                let mut validators = Vec::new();
                for i in 0..n {
                    let scheme = Ed25519::from_seed(i as u64);
                    let pk = scheme.public_key();
                    schemes.push(scheme);
                    validators.push(pk);
                }
                validators.sort();
                schemes.sort_by_key(|s| s.public_key());
                let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

                // Create engines
                let hasher = Sha256::default();
                let prover = Prover::new(namespace.clone());
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut supervisors = HashMap::new();
                let (done_sender, mut done_receiver) = mpsc::unbounded();
                let mut engine_handlers = Vec::new();
                for scheme in schemes.into_iter() {
                    // Register on network
                    let validator = scheme.public_key();
                    let partition = hex(&validator);
                    let (container_sender, container_receiver) = oracle
                        .register(validator.clone(), 0, 1024 * 1024)
                        .await
                        .unwrap();
                    let (vote_sender, vote_receiver) = oracle
                        .register(validator.clone(), 1, 1024 * 1024)
                        .await
                        .unwrap();

                    // Link to all other validators
                    for other in validators.iter() {
                        if other == &validator {
                            continue;
                        }
                        oracle
                            .add_link(
                                validator.clone(),
                                other.clone(),
                                Link {
                                    latency: 50.0,
                                    jitter: 50.0,
                                    success_rate: 1.0,
                                },
                            )
                            .await
                            .unwrap();
                    }

                    // Start engine
                    let supervisor_config = mocks::actor::SupervisorConfig {
                        prover: prover.clone(),
                        participants: view_validators.clone(),
                    };
                    let supervisor =
                        mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                    supervisors.insert(validator.clone(), supervisor.clone());
                    let application_cfg = mocks::actor::ApplicationConfig {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) =
                        mocks::actor::Application::new(runtime.clone(), application_cfg);
                    runtime.spawn("application", async move {
                        actor.run().await;
                    });
                    let cfg = journal::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        partition,
                    };
                    let journal = Journal::init(runtime.clone(), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        hasher: hasher.clone(),
                        application,
                        supervisor,
                        registry: Arc::new(Mutex::new(Registry::default())),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        max_fetch_count: 1,
                        max_fetch_size: 1024 * 512,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(runtime.clone(), journal, cfg);
                    engine_handlers.push(runtime.spawn("engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    }));
                }

                // Wait for all engines to finish
                runtime.spawn("confirmed", async move {
                    loop {
                        // Parse events
                        let (validator, event) = done_receiver.next().await.unwrap();
                        match event {
                            mocks::actor::Progress::Notarized(proof, digest) => {
                                // Check correctness of proof
                                let (view, _, payload, _) =
                                    prover.deserialize_notarization(proof, 5, true).unwrap();
                                if digest != payload {
                                    panic!(
                                        "notarization mismatch digest: {:?}, payload: {:?}",
                                        digest, payload
                                    );
                                }

                                // Store notarized
                                {
                                    let mut notarized = notarized.lock().unwrap();
                                    if let Some(previous) = notarized.insert(view, digest.clone())
                                    {
                                        if previous != digest {
                                            panic!(
                                                "notarization mismatch at {:?} previous: {:?}, current: {:?}",
                                                view, previous, digest
                                            );
                                        }
                                    }
                                    if (notarized.len() as u64) < required_containers {
                                        continue;
                                    }
                                }
                            }
                            mocks::actor::Progress::Finalized(proof, digest) => {
                                // Check correctness of proof
                                let (view, _, payload, _) =
                                    prover.deserialize_finalization(proof, 5, true).unwrap();
                                if digest != payload {
                                    panic!(
                                        "finalization mismatch digest: {:?}, payload: {:?}",
                                        digest, payload
                                    );
                                }

                                // Store finalized
                                {
                                    let mut finalized = finalized.lock().unwrap();
                                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                                        if previous != digest {
                                            panic!(
                                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                                view, previous, digest
                                            );
                                        }
                                    }
                                    if (finalized.len() as u64) < required_containers {
                                        continue;
                                    }
                                }
                                completed.lock().unwrap().insert(validator);
                            }
                        }

                        // Check supervisors for correct activity
                        for (_, supervisor) in supervisors.iter() {
                            // Ensure no faults
                            let faults = supervisor.faults.lock().unwrap();
                            assert!(faults.is_empty());
                        }
                    }
                });

                // Exit at random points for unclean shutdown of entire set
                let wait =
                    runtime.gen_range(Duration::from_millis(10)..Duration::from_millis(2000));
                runtime.sleep(wait).await;
                {
                    let mut shutdowns = shutdowns.lock().unwrap();
                    debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                    *shutdowns += 1;
                }
            });
        }
    }

    #[test_traced]
    fn test_backfill() {
        // Create runtime
        let n = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1, // force many fetches
                    max_fetch_size: 1024 * 1024,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    finalized.insert(view, digest);
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == (n - 1) as usize {
                    break;
                }
            }

            // Degrade network connections for online peers
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx == 0 {
                    continue;
                }

                // Degrade connection
                let validator = scheme.public_key();
                for (other_idx, other) in validators.iter().enumerate() {
                    if other_idx == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 3_000.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for null notarizations to accrue
            runtime.sleep(Duration::from_secs(120)).await;

            // Remove all connections from second peer
            let failed_validator = validators[1].clone();
            for (other_idx, other) in validators.iter().enumerate() {
                if other_idx == 0 {
                    continue;
                }
                if other == &failed_validator {
                    continue;
                }
                oracle
                    .remove_link(failed_validator.clone(), other.clone())
                    .await
                    .unwrap();
                oracle
                    .remove_link(other.clone(), failed_validator.clone())
                    .await
                    .unwrap();
            }

            // Start engine for first peer
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let partition = hex(&validator);
            let (container_sender, container_receiver) = oracle
                .register(validator.clone(), 0, 1024 * 1024)
                .await
                .unwrap();
            let (vote_sender, vote_receiver) = oracle
                .register(validator.clone(), 1, 1024 * 1024)
                .await
                .unwrap();

            // Restore network connections for online peers
            for (idx, scheme) in schemes.iter().enumerate() {
                // Skip newly offline peer
                if idx == 1 {
                    continue;
                }

                // Restore connection
                let validator = scheme.public_key();
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 1 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 2.5,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Start engine
            let supervisor_config = mocks::actor::SupervisorConfig {
                prover: prover.clone(),
                participants: view_validators.clone(),
            };
            let supervisor = mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
            supervisors.push(supervisor.clone());
            let application_cfg = mocks::actor::ApplicationConfig {
                hasher: hasher.clone(),
                relay: relay.clone(),
                participant: validator.clone(),
                tracker: done_sender.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) =
                mocks::actor::Application::new(runtime.clone(), application_cfg);
            runtime.spawn("application", async move {
                actor.run().await;
            });
            let cfg = journal::Config {
                registry: Arc::new(Mutex::new(Registry::default())),
                partition,
            };
            let journal = Journal::init(runtime.clone(), cfg)
                .await
                .expect("unable to create journal");
            let cfg = config::Config {
                crypto: scheme,
                hasher: hasher.clone(),
                application,
                supervisor,
                registry: Arc::new(Mutex::new(Registry::default())),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                max_fetch_count: 1,
                max_fetch_size: 1024 * 512,
                fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                replay_concurrency: 1,
            };
            let engine = Engine::new(runtime.clone(), journal, cfg);
            engine_handlers.push(runtime.spawn("engine", async move {
                engine
                    .run(
                        (container_sender, container_receiver),
                        (vote_sender, vote_receiver),
                    )
                    .await;
            }));

            // Wait for new engine to finalize required
            let mut finalized = HashMap::new();
            let mut validator_finalized = HashSet::new();
            loop {
                let (candidate, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if validator == candidate {
                        validator_finalized.insert(view);
                    }
                }
                if validator_finalized.len() == required_containers as usize {
                    break;
                }
            }
        });
    }

    #[test_traced]
    fn test_one_offline() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for (idx_other, other) in validators.iter().enumerate() {
                    if idx_other == 0 {
                        continue;
                    }
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == (n - 1) as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let offline = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure offline node is never active
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(offline) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(offline) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_slow_validator() {
        // Create runtime
        let n = 5;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::actor::ApplicationConfig {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (3_000.0, 0.0),
                        verify_latency: (3_000.0, 5.0),
                    }
                } else {
                    mocks::actor::ApplicationConfig {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let slow = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure slow node is never active
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(slow) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(slow) {
                                panic!("view: {}", view);
                            }
                        }
                    }
                }
            }
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(120));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 3_000.0,
                                jitter: 0.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(60)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Update links
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
    }

    #[test_traced]
    fn test_partition() {
        // Create runtime
        let n = 10;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(900));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 10, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if view > highest_finalized {
                        highest_finalized = view;
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Cut all links between validator halves
            for (me_idx, me) in validators.iter().enumerate() {
                for (other_idx, other) in validators.iter().enumerate() {
                    if other == me {
                        continue;
                    }
                    let me_idx = me_idx as u32;
                    let other_idx = other_idx as u32;
                    if me_idx < n / 2 && other_idx >= n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                    if me_idx >= n / 2 && other_idx < n / 2 {
                        debug!("cutting link between {:?} and {:?}", me_idx, other_idx);
                        oracle.remove_link(me.clone(), other.clone()).await.unwrap();
                    }
                }
            }

            // Wait for any in-progress notarizations/finalizations to finish
            runtime.sleep(Duration::from_secs(10)).await;

            // Empty done receiver
            loop {
                if done_receiver.try_next().is_err() {
                    break;
                }
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(600)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Restore links
            debug!("restoring links");
            for scheme in schemes.iter() {
                let validator = scheme.public_key();
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 10, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers + highest_finalized {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
    }

    fn test_slow_and_lossy_links(seed: u64) -> String {
        // Create runtime
        let n = 5;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let cfg = deterministic::Config {
            seed: Seed::Number(seed),
            timeout: Some(Duration::from_secs(3_000)),
            ..deterministic::Config::default()
        };
        let (executor, runtime, auditor) = Executor::init(cfg);
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 200.0,
                                jitter: 150.0,
                                success_rate: 0.5,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::actor::ApplicationConfig {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::actor::Application::new(runtime.clone(), application_cfg);
                runtime.spawn("application", async move {
                    actor.run().await;
                });
                let cfg = journal::Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    partition,
                };
                let journal = Journal::init(runtime.clone(), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    hasher: hasher.clone(),
                    application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (container_sender, container_receiver),
                            (vote_sender, vote_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == n as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
            }
        });
        auditor.state()
    }

    #[test_traced]
    fn test_determinism() {
        for seed in 0..5 {
            // Run test with seed
            let state_1 = test_slow_and_lossy_links(seed);

            // Run test again with same seed
            let state_2 = test_slow_and_lossy_links(seed);

            // Ensure states are equal
            assert_eq!(state_1, state_2);
        }
    }

    #[test_traced]
    fn test_conflicter() {
        // Create runtime
        let n = 4;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                if idx_scheme == 0 {
                    let cfg = conflicter::Config {
                        crypto: scheme,
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: Conflicter<_, _, Sha256, _> =
                        conflicter::Conflicter::new(runtime.clone(), cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::actor::ApplicationConfig {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) =
                        mocks::actor::Application::new(runtime.clone(), application_cfg);
                    runtime.spawn("application", async move {
                        actor.run().await;
                    });
                    let cfg = journal::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        partition,
                    };
                    let journal = Journal::init(runtime.clone(), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        hasher: hasher.clone(),
                        application,
                        supervisor,
                        registry: Arc::new(Mutex::new(Registry::default())),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        max_fetch_count: 1,
                        max_fetch_size: 1024 * 512,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(runtime.clone(), journal, cfg);
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == (n - 1) as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_conflicting_notarize = 0;
            let mut count_conflicting_finalize = 0;
            for supervisor in supervisors.iter() {
                // Ensure only faults for byz
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match *fault {
                                CONFLICTING_NOTARIZE => {
                                    count_conflicting_notarize += 1;
                                }
                                CONFLICTING_FINALIZE => {
                                    count_conflicting_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }
            }
            assert!(count_conflicting_notarize > 0);
            assert!(count_conflicting_finalize > 0);
        });
    }

    #[test_traced]
    fn test_nuller() {
        // Create runtime
        let n = 4;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = Bytes::from("consensus");
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..n {
                let scheme = Ed25519::from_seed(i as u64);
                let pk = scheme.public_key();
                schemes.push(scheme);
                validators.push(pk);
            }
            validators.sort();
            schemes.sort_by_key(|s| s.public_key());
            let view_validators = BTreeMap::from_iter(vec![(0, validators.clone())]);

            // Create engines
            let hasher = Sha256::default();
            let prover = Prover::new(namespace.clone());
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (container_sender, container_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (vote_sender, vote_receiver) = oracle
                    .register(validator.clone(), 1, 1024 * 1024)
                    .await
                    .unwrap();

                // Link to all other validators
                for other in validators.iter() {
                    if other == &validator {
                        continue;
                    }
                    oracle
                        .add_link(
                            validator.clone(),
                            other.clone(),
                            Link {
                                latency: 10.0,
                                jitter: 1.0,
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }

                // Start engine
                let supervisor_config = mocks::actor::SupervisorConfig {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::actor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                if idx_scheme == 0 {
                    let cfg = nuller::Config {
                        crypto: scheme,
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: Nuller<_, _, Sha256, _> = nuller::Nuller::new(runtime.clone(), cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::actor::ApplicationConfig {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) =
                        mocks::actor::Application::new(runtime.clone(), application_cfg);
                    runtime.spawn("application", async move {
                        actor.run().await;
                    });
                    let cfg = journal::Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        partition,
                    };
                    let journal = Journal::init(runtime.clone(), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        hasher: hasher.clone(),
                        application,
                        supervisor,
                        registry: Arc::new(Mutex::new(Registry::default())),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        max_fetch_count: 1,
                        max_fetch_size: 1024 * 512,
                        fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                        replay_concurrency: 1,
                    };
                    let engine = Engine::new(runtime.clone(), journal, cfg);
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    });
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::actor::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _) =
                        prover.deserialize_finalization(proof, 5, true).unwrap();
                    if digest != payload {
                        panic!(
                            "finalization mismatch digest: {:?}, payload: {:?}",
                            digest, payload
                        );
                    }
                    if let Some(previous) = finalized.insert(view, digest.clone()) {
                        if previous != digest {
                            panic!(
                                "finalization mismatch at {:?} previous: {:?}, current: {:?}",
                                view, previous, digest
                            );
                        }
                    }
                    if (finalized.len() as u64) < required_containers {
                        continue;
                    }
                    completed.insert(validator);
                }
                if completed.len() == (n - 1) as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_nullify_and_finalize = 0;
            let mut count_conflicting_notarize = 0;
            for supervisor in supervisors.iter() {
                // Ensure only faults for byz
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match *fault {
                                NULLIFY_AND_FINALIZE => {
                                    count_nullify_and_finalize += 1;
                                }
                                CONFLICTING_NOTARIZE => {
                                    count_conflicting_notarize += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }
            }
            assert!(count_nullify_and_finalize > 0);
            assert!(count_conflicting_notarize > 0);
        });
    }
}
