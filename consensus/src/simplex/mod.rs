//! Simple and fast BFT agreement inspired by Simplex Consensus.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `simplex` provides
//! simple and fast BFT agreement that seeks to minimize view latency (i.e. block time)
//! and to provide optimal finalization latency in a partially synchronous setting.
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Flexible Block Format
//!
//! # Design
//!
//! ## Architecture
//!
//! All logic is split into two components: the `Voter` and the `Resolver` (and the user of `simplex`
//! provides `Application`). The `Voter` is responsible for participating in the latest view and the
//! `Resolver` is responsible for fetching artifacts from previous views required to verify proposed
//! blocks in the latest view.
//!
//! To provide great performance, all interactions between `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` verifies a notarization.
//!
//! ```txt
//! +---------------+           +---------+            +++++++++++++++
//! |               |<----------+         +----------->+             +
//! |  Application  |           |  Voter  |            +    Peers    +
//! |               +---------->|         |<-----------+             +
//! +---------------+           +--+------+            +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
//!                            +-------+----+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Resolver  |          +    Peers    +
//!                            |            |<---------+             +
//!                            +------------+          +++++++++++++++
//! ```
//!
//! _Application is usually a single object that implements the `Automaton`, `Relay`, `Committer`,
//! and `Supervisor` traits._
//!
//! ## Joining Consensus
//!
//! As soon as `2f+1` votes or finalizes are observed for some view `v`, the `Voter` will enter `v+1`.
//! This means that a new participant joining consensus will immediately jump ahead to the latest view
//! and begin participating in consensus (assuming it can verify blocks).
//!
//! ## Persistence
//!
//! The `Voter` caches all data required to participate in consensus to avoid any disk reads on
//! on the critical path. To enable recovery, the `Voter` writes valid messages it receives from
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [`Journal`](https://docs.rs/commonware-storage/latest/commonware_storage/journal/index.html).
//! Before sending a message, the `Journal` sync is invoked to prevent inadvertent Byzantine behavior
//! on restart (especially in the case of unclean shutdown).
//!
//! ## Protocol Description
//!
//! ### Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t_l = 2Δ` and advance `t_a = 3Δ`
//!     * If leader `l` has not been active (no votes) in last `r` views, set `t_l` to 0.
//! * If leader `l`, broadcast `notarize(c,v)`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `notarize(c,v)` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is notarized at `v_parent` and we have null notarizations for all views
//!   between `v` and `v_parent`, verify `c` and broadcast `notarize(c,v)`
//!
//! Upon receiving `2f+1` `notarize(c,v)`:
//! * Cancel `t_a`
//! * Mark `c` as notarized
//! * Broadcast `notarization(c,v)` (even if we have not verified `c`)
//! * If have not broadcast `nullify(v)`, broadcast `finalize(c,v)`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `nullify(v)`:
//! * Broadcast `nullification(v)`
//!     * If observe `>= f+1` `notarize(c,v)` for some `c`, request `notarization(c_parent, v_parent)` and any missing
//!       `nullification(*)` between `v_parent` and `v`. If `c_parent` is than last finalized, broadcast last finalization
//!       instead.
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `finalize(c,v)`:
//! * Mark `c` as finalized (and recursively finalize its parents)
//! * Broadcast `finalization(c,v)` (even if we have not verified `c`)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast `nullify(v)`
//! * Every `t_r` after `nullify(v)` broadcast that we are still in view `v`:
//!    * Rebroadcast `nullify(v)` and either `notarization(v-1)` or `nullification(v-1)`
//!
//! ### Deviations from Simplex Consensus
//!
//! * Fetch missing notarizations/nullifications as needed rather than assuming each proposal contains
//!   a set of all notarizations/nullifications for all historical blocks.
//! * Introduce distinct messages for `notarize` and `nullify` rather than referring to both as a `vote` for
//!   either a "block" or a "dummy block", respectively.
//! * Introduce a "leader timeout" to trigger early view transitions for unresponsive leaders.
//! * Skip "leader timeout" and "notarization timeout" if a designated leader hasn't participated in
//!   some number of views (again to trigger early view transition for an unresponsive leader).
//! * Introduce message rebroadcast to continue making progress if messages from a given view are dropped (only way
//!   to ensure messages are reliably delivered is with a heavyweight reliable broadcast protocol).

use commonware_cryptography::Digest;

mod actors;
mod config;
pub use config::Config;
mod encoder;
mod engine;
pub use engine::Engine;
mod metrics;
mod prover;
pub use prover::Prover;
pub mod mocks;
mod verifier;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// View is a monotonically increasing counter that represents the current focus of consensus.
pub type View = u64;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Clone)]
pub struct Context {
    /// Current view of consensus.
    pub view: View,

    /// Parent the payload is built on.
    ///
    /// Payloads from views between the current view and the parent view can never be
    /// directly finalized (must exist some nullification).
    pub parent: (View, Digest),
}

use crate::Activity;
use thiserror::Error;

/// Errors that can occur during consensus.
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

/// Notarize a payload at a given view.
///
/// ## Clarifications
/// * Vote for leader is considered a proposal and a vote.
/// * It is ok to have both a vote for a proposal and the null
///   container in the same view.
/// * It is ok to notarize/finalize different proposals in the same view.
pub const NOTARIZE: Activity = 0;
/// Finalize a payload at a given view.
pub const FINALIZE: Activity = 1;
/// Notarize a payload that conflicts with a previous notarize.
pub const CONFLICTING_NOTARIZE: Activity = 2;
/// Finalize a payload that conflicts with a previous finalize.
pub const CONFLICTING_FINALIZE: Activity = 3;
/// Nullify and finalize in the same view.
pub const NULLIFY_AND_FINALIZE: Activity = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Ed25519, Scheme, Sha256};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network};
    use commonware_runtime::{
        deterministic::{self, Executor},
        Clock, Runner, Spawner,
    };
    use commonware_storage::journal::{self, Journal};
    use commonware_utils::{hex, quorum};
    use engine::Engine;
    use futures::{channel::mpsc, StreamExt};
    use governor::Quota;
    use prometheus_client::registry::Registry;
    use prover::Prover;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[test_traced]
    fn test_all_online() {
        // Create runtime
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let max_exceptions = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
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
            let prover = Prover::new();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) = oracle
                    .register(validator.clone(), 0, 1024 * 1024)
                    .await
                    .unwrap();
                let (backfiller_sender, backfiller_receiver) = oracle
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
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::supervisor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: hasher.clone(),
                    relay: relay.clone(),
                    participant: validator,
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) =
                    mocks::application::Application::new(runtime.clone(), application_cfg);
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
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
                    registry: Arc::new(Mutex::new(Registry::default())),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    max_fetch_count: 1,
                    max_fetch_size: 1024 * 512,
                    fetch_rate_per_peer: Quota::per_second(NonZeroU32::new(1).unwrap()),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                };
                let engine = Engine::new(runtime.clone(), journal, cfg);
                engine_handlers.push(runtime.spawn("engine", async move {
                    engine
                        .run(
                            (voter_sender, voter_receiver),
                            (backfiller_sender, backfiller_receiver),
                        )
                        .await;
                }));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
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
                        // Ensure only one payload proposed per view
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }

                        // Only check at views below timeout
                        if *view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(view).expect("view should be finalized");
                        let voters = payloads.get(digest).expect("digest should exist");
                        if voters.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
                        }
                        if voters.len() != n as usize {
                            exceptions += 1;
                        }
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        // Ensure only one payload proposed per view
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }

                        // Only check at views below timeout
                        if *view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        let digest = finalized.get(view).expect("view should be finalized");
                        let finalizers = payloads.get(digest).expect("digest should exist");
                        if finalizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
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
}
