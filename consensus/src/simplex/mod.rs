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
#[cfg(test)]
mod mocks;
mod prover;
pub use prover::Prover;
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
    use bytes::Bytes;
    use commonware_cryptography::{Ed25519, Scheme, Sha256};
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network, Oracle};
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
    use rand::Rng;
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;

    enum Action {
        NewLink(Link),
        Relink(Link),
        Unlink,
    }

    enum Scope {
        All,
        Where(fn(usize, usize) -> bool),
    }

    fn only(x: usize, i: usize, j: usize) -> bool {
        x == i || x == j
    }
    fn omit(x: usize, i: usize, j: usize) -> bool {
        x != i && x != j
    }

    // Helper function to link validators together.
    async fn link_validators(
        oracle: &mut Oracle,
        validators: &[Bytes],
        action: Action,
        scope: Scope,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                // Ignore self
                if v2 == v1 {
                    continue;
                }

                // Scope only to certain connections
                if let Scope::Where(f) = scope {
                    if !f(i1, i2) {
                        continue;
                    }
                }

                // Do any unlinking first
                match action {
                    Action::Relink(_) | Action::Unlink => {
                        oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                    }
                    _ => {}
                }

                // Do any linking after
                match action {
                    Action::NewLink(ref link) | Action::Relink(ref link) => {
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
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

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

    #[test_traced]
    fn test_unclean_shutdown() {
        // Create runtime
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let notarized = Arc::new(Mutex::new(HashMap::new()));
        let finalized = Arc::new(Mutex::new(HashMap::new()));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        let (mut executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        while completed.lock().unwrap().len() != n as usize {
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let notarized = notarized.clone();
            let finalized = finalized.clone();
            let completed = completed.clone();
            executor.start({
                let mut runtime = runtime.clone();
                async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    runtime.clone(),
                    Config {
                        registry: Arc::new(Mutex::new(Registry::default())),
                        max_size: 1024 * 1024,
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
                let prover = Prover::new(&namespace);
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut supervisors = HashMap::new();
                let (done_sender, mut done_receiver) = mpsc::unbounded();
                let mut engine_handlers = Vec::new();
                for scheme in schemes.into_iter() {
                    // Register on network
                    let validator = scheme.public_key();
                    let partition = hex(&validator);
                    let (container_sender, container_receiver) = oracle
                        .register(validator.clone(), 0)
                        .await
                        .unwrap();
                    let (vote_sender, vote_receiver) = oracle
                        .register(validator.clone(), 1)
                        .await
                        .unwrap();

                    // Start engine
                    let supervisor_config = mocks::supervisor::Config {
                        prover: prover.clone(),
                        participants: view_validators.clone(),
                    };
                    let supervisor =
                        mocks::supervisor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                    supervisors.insert(validator.clone(), supervisor.clone());
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
                                (container_sender, container_receiver),
                                (vote_sender, vote_receiver),
                            )
                            .await;
                    }));
                }

                // Link all validators
                let link = Link {
                    latency: 10.0,
                    jitter: 1.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

                // Wait for all engines to finish
                runtime.spawn("confirmed", async move {
                    loop {
                        // Parse events
                        let (validator, event) = done_receiver.next().await.unwrap();
                        match event {
                            mocks::application::Progress::Notarized(proof, digest) => {
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
                            mocks::application::Progress::Finalized(proof, digest) => {
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
            }});

            // Recover runtime
            (executor, runtime, _) = runtime.recover();
        }
    }

    #[test_traced]
    fn test_backfill() {
        // Create runtime
        let n = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
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
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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
                    crypto: scheme.clone(),
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
                    max_fetch_count: 1, // force many fetches
                    max_fetch_size: 1024 * 1024,
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

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(link),
                Scope::Where(|i, j| omit(0, i, j)),
            )
            .await;

            // Wait for all online engines to finish
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
            let link = Link {
                latency: 3_000.0,
                jitter: 0.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Relink(link.clone()),
                Scope::Where(|i, j| omit(0, i, j)),
            )
            .await;

            // Wait for null notarizations to accrue
            runtime.sleep(Duration::from_secs(120)).await;

            // Unlink second peer from all (except first)
            link_validators(
                &mut oracle,
                &validators,
                Action::Unlink,
                Scope::Where(|i, j| only(1, i, j) && omit(0, i, j)),
            )
            .await;

            // Start engine for first peer
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            let partition = hex(&validator);
            let (container_sender, container_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (vote_sender, vote_receiver) = oracle.register(validator.clone(), 1).await.unwrap();

            // Link first peer to all (except second)
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(link),
                Scope::Where(|i, j| only(0, i, j) && omit(1, i, j)),
            )
            .await;

            // Restore network connections for all online peers
            let link = Link {
                latency: 10.0,
                jitter: 2.5,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Relink(link),
                Scope::Where(|i, j| omit(1, i, j)),
            )
            .await;

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
                participant: validator.clone(),
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
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
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
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(link),
                Scope::Where(|i, j| omit(0, i, j)),
            )
            .await;

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
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

                // Start engine
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::supervisor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::application::Config {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (3_000.0, 0.0),
                        verify_latency: (3_000.0, 5.0),
                    }
                } else {
                    mocks::application::Config {
                        hasher: hasher.clone(),
                        relay: relay.clone(),
                        participant: validator,
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
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

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

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
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(120));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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
                    crypto: scheme.clone(),
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

            // Link all validators
            let link = Link {
                latency: 3_000.0,
                jitter: 0.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

            // Wait for a few virtual minutes (shouldn't finalize anything)
            select! {
                _timeout = runtime.sleep(Duration::from_secs(60)) => {},
                _done = done_receiver.next() => {
                    panic!("engine should not notarize or finalize anything");
                }
            }

            // Update links
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Relink(link), Scope::All).await;

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
        const N: usize = 10;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(900));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            runtime.spawn("network", network.run());

            // Register participants
            let mut schemes = Vec::new();
            let mut validators = Vec::new();
            for i in 0..N {
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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
                    crypto: scheme.clone(),
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

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(link.clone()),
                Scope::All,
            )
            .await;

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
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
                if completed.len() == N {
                    break;
                }
            }

            // Cut all links between validator halves
            fn are_separated(a: usize, b: usize) -> bool {
                let m = N / 2;
                (a < m && b >= m) || (a >= m && b < m)
            }
            link_validators(
                &mut oracle,
                &validators,
                Action::Unlink,
                Scope::Where(are_separated),
            )
            .await;

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
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(link),
                Scope::Where(are_separated),
            )
            .await;

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
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
                if completed.len() == N {
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

    fn slow_and_lossy_links(seed: u64) -> String {
        // Create runtime
        let n = 5;
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config {
            seed,
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
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for scheme in schemes.into_iter() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

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

            // Link all validators
            let degraded_link = Link {
                latency: 200.0,
                jitter: 150.0,
                success_rate: 0.5,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::NewLink(degraded_link),
                Scope::All,
            )
            .await;

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
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links(0);
    }

    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            // Run test with seed
            let state_1 = slow_and_lossy_links(seed);

            // Run test again with same seed
            let state_2 = slow_and_lossy_links(seed);

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
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

                // Start engine
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::supervisor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        crypto: scheme,
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::conflicter::Conflicter<_, _, Sha256, _> =
                        mocks::conflicter::Conflicter::new(runtime.clone(), cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (voter_sender, voter_receiver),
                                (backfiller_sender, backfiller_receiver),
                            )
                            .await;
                    });
                } else {
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
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (voter_sender, voter_receiver),
                                (backfiller_sender, backfiller_receiver),
                            )
                            .await;
                    });
                }
            }

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

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
        let namespace = b"consensus".to_vec();
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.clone(),
                Config {
                    registry: Arc::new(Mutex::new(Registry::default())),
                    max_size: 1024 * 1024,
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
            let prover = Prover::new(&namespace);
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Register on network
                let validator = scheme.public_key();
                let partition = hex(&validator);
                let (voter_sender, voter_receiver) =
                    oracle.register(validator.clone(), 0).await.unwrap();
                let (backfiller_sender, backfiller_receiver) =
                    oracle.register(validator.clone(), 1).await.unwrap();

                // Start engine
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants: view_validators.clone(),
                };
                let supervisor =
                    mocks::supervisor::Supervisor::<Ed25519, Sha256>::new(supervisor_config);
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        crypto: scheme,
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, Sha256, _> =
                        mocks::nuller::Nuller::new(cfg);
                    runtime.spawn("byzantine_engine", async move {
                        engine
                            .run(
                                (voter_sender, voter_receiver),
                                (backfiller_sender, backfiller_receiver),
                            )
                            .await;
                    });
                } else {
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
                    runtime.spawn("engine", async move {
                        engine
                            .run(
                                (voter_sender, voter_receiver),
                                (backfiller_sender, backfiller_receiver),
                            )
                            .await;
                    });
                }
            }

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::NewLink(link), Scope::All).await;

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
                if completed.len() == (n - 1) as usize {
                    break;
                }
            }

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_nullify_and_finalize = 0;
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
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }
            }
            assert!(count_nullify_and_finalize > 0);
        });
    }
}
