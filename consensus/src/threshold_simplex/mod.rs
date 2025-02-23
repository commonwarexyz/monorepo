//! [Simplex](crate::simplex)-like BFT agreement with an embedded VRF and succinct consensus certificates.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `threshold-simplex` provides
//! simple and fast BFT agreement with network-speed view (i.e. block time) latency and optimal finalization
//! latency in a partially synchronous setting. Unlike Simplex Consensus, however, `threshold-simplex` employs threshold
//! cryptography (specifically BLS12-381 threshold signatures with a `2f+1` of `3f+1` quorum) to generate both
//! a bias-resistant beacon (for leader election and post-facto execution randomness) and succinct consensus certificates
//! (any certificate can be verified with just the static public key of the consensus instance) for each view
//! with zero message overhead (natively integrated).
//!
//! _If you wish to deploy Simplex Consensus but can't employ threshold signatures, see
//! [Simplex](crate::simplex)._
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Flexible Block Format
//! * Embedded VRF for Leader Election and Post-Facto Execution Randomness
//! * Succinct Consensus Certificates for Notarization, Nullification, and Finality
//!
//! # Design
//!
//! ## Architecture
//!
//! All logic is split into two components: the `Voter` and the `Resolver` (and the user of `threshold-simplex`
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
//! and `ThresholdSupervisor` traits._
//!
//! ## Joining Consensus
//!
//! As soon as `2f+1` notarizes, nullifies, or finalizes are observed for some view `v`, the `Voter` will
//! enter `v+1`. This means that a new participant joining consensus will immediately jump ahead to the
//! latest view and begin participating in consensus (assuming it can verify blocks).
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
//!     * If leader `l` has not been active in last `r` views, set `t_l` to 0.
//! * If leader `l`, broadcast `(part(v), notarize(c,v))`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `(part(v), notarize(c,v))` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is notarized at `v_parent` and we have nullifications for all views
//!   between `v` and `v_parent`, verify `c` and broadcast `(part(v), notarize(c,v))`
//!
//! Upon receiving `2f+1` `(part(v), notarize(c,v))`:
//! * Cancel `t_a`
//! * Mark `c` as notarized
//! * Broadcast `(seed(v), notarization(c,v))` (even if we have not verified `c`)
//! * If have not broadcast `(part(v), nullify(v))`, broadcast `finalize(c,v)`
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `(part(v), nullify(v))`:
//! * Broadcast `(seed(v), nullification(v))`
//!     * If observe `>= f+1` `notarize(c,v)` for some `c`, request `notarization(c_parent, v_parent)` and any missing
//!       `nullification(*)` between `v_parent` and `v`. If `c_parent` is than last finalized, broadcast last finalization
//!       instead.
//! * Enter `v+1`
//!
//! Upon receiving `2f+1` `finalize(c,v)`:
//! * Mark `c` as finalized (and recursively finalize its parents)
//! * Broadcast `(seed(v), finalization(c,v))` (even if we have not verified `c`)
//!
//! Upon `t_l` or `t_a` firing:
//! * Broadcast `(part(v), nullify(v))`
//! * Every `t_r` after `(part(v), nullify(v))` broadcast that we are still in view `v`:
//!    * Rebroadcast `(part(v), nullify(v))` and either `(seed(v-1), notarization(v-1))` or `(seed(v-1), nullification(v-1))`
//!
//! #### Embedded VRF
//!
//! When broadcasting any `notarize(c,v)` or `nullify(v)` message, a participant must also include a `part(v)` message (a partial
//! signature over the view `v`). After `2f+1` `notarize(c,v)` or `nullify(v)` messages are collected from unique participants,
//! `seed(v)` can be recovered. Because `part(v)` is only over the view `v`, the seed derived for a given view `v` is the same regardless of
//! whether or not a block was notarized in said view `v`.
//!
//! Because the value of `seed(v)` cannot be known prior to message broadcast by any participant (including the leader) in view `v`
//! and cannot be manipulated by any participant (deterministic for any `2f+1` signers at a given view `v`), it can be used both as a beacon
//! for leader election (where `seed(v)` determines the leader for `v+1`) and a source of randomness in execution (where `seed(v)`
//! is used as a seed in `v`).
//!
//! #### Succinct Consensus Certificates
//!
//! All broadcast consensus messages (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`) contain partial signatures for a static
//! public key (derived from a group polynomial that can be recomputed during reconfiguration using [dkg](commonware_cryptography::bls12381::dkg)).
//! As soon as `2f+1` messages are collected, a threshold signature over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)`
//! can be recovered, respectively. Because the public key is static, any of these certificates can be verified by an external
//! process without following the consensus instance and/or tracking the current set of participants (as is typically required
//! to operate a lite client).
//!
//! These threshold signatures over `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)` (i.e. the consensus certificates)
//! can be used to secure interoperability between different consensus instances and user interactions with an infrastructure provider
//! (where any data served can be proven to derive from some finalized block of some consensus instance with a known static public key).
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

use commonware_cryptography::Array;

mod encoder;
mod prover;
pub use prover::Prover;
mod wire {
    include!(concat!(env!("OUT_DIR"), "/threshold_simplex.wire.rs"));
}

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actors;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
        mod verifier;
    }
}

#[cfg(test)]
pub mod mocks;

/// View is a monotonically increasing counter that represents the current focus of consensus.
pub type View = u64;

use crate::Activity;

/// Context is a collection of metadata from consensus about a given payload.
#[derive(Clone)]
pub struct Context<D: Array> {
    /// Current view of consensus.
    pub view: View,

    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
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
    use commonware_cryptography::{
        bls12381::{dkg::ops, primitives::poly},
        Ed25519, Scheme, Sha256,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{
        deterministic::{self, Executor},
        Clock, Metrics, Runner, Spawner,
    };
    use commonware_storage::journal::variable::{Config as JConfig, Journal};
    use commonware_utils::quorum;
    use engine::Engine;
    use futures::{channel::mpsc, StreamExt};
    use governor::Quota;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        num::NonZeroU32,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::debug;

    /// Registers all validators using the oracle.
    async fn register_validators<P: Array>(
        oracle: &mut Oracle<P>,
        validators: &[P],
    ) -> HashMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))> {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (voter_sender, voter_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (resolver_sender, resolver_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            registrations.insert(
                validator.clone(),
                (
                    (voter_sender, voter_receiver),
                    (resolver_sender, resolver_receiver),
                ),
            );
        }
        registrations
    }

    /// Enum to describe the action to take when linking validators.
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
    async fn link_validators<P: Array>(
        oracle: &mut Oracle<P>,
        validators: &[P],
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
        // Create runtime
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let max_exceptions = 4;
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = ops::generate_shares(&mut rng, None, n, threshold);
        let pk = poly::public(&public);

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let notarized = Arc::new(Mutex::new(HashMap::new()));
        let finalized = Arc::new(Mutex::new(HashMap::new()));
        let completed = Arc::new(Mutex::new(HashSet::new()));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let (mut executor, mut runtime, _) = Executor::timed(Duration::from_secs(300));
        while completed.lock().unwrap().len() != n as usize {
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let notarized = notarized.clone();
            let finalized = finalized.clone();
            let completed = completed.clone();
            let supervised = supervised.clone();
            executor.start({
                let mut runtime = runtime.clone();
                let public = public.clone();
                let shares = shares.clone();
                async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    runtime.with_label("network"),
                    Config {
                        max_size: 1024 * 1024,
                    },
                );

                // Start network
                network.start();

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
                let mut registrations = register_validators(&mut oracle, &validators).await;

                // Link all validators
                let link = Link {
                    latency: 50.0,
                    jitter: 50.0,
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &validators, Action::Link(link), None).await;

                // Create engines
                let prover = Prover::new(pk, &namespace);
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut supervisors = HashMap::new();
                let (done_sender, mut done_receiver) = mpsc::unbounded();
                let mut engine_handlers = Vec::new();
                for (idx, scheme) in schemes.into_iter().enumerate() {
                    // Create scheme runtime
                    let runtime = runtime
                        .clone()
                        .with_label(&format!("validator-{}", scheme.public_key()));

                    // Configure engine
                    let validator = scheme.public_key();
                    let mut participants = BTreeMap::new();
                    participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                    let supervisor_config = mocks::supervisor::Config {
                        prover: prover.clone(),
                        participants,
                    };
                    let supervisor =
                        mocks::supervisor::Supervisor::new(supervisor_config);
                    supervisors.insert(validator.clone(), supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) =
                        mocks::application::Application::new(runtime.with_label("application"), application_cfg);
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(runtime.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        committer: application,
                        supervisor,
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
                    let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                    // Start engine
                    let (voter, resolver) = registrations
                        .remove(&validator)
                        .expect("validator should be registered");
                    engine_handlers.push(engine.start(voter, resolver));
                }

                // Wait for all engines to finish
                runtime.with_label("confirmed").spawn(move |_| async move {
                    loop {
                        // Parse events
                        let (validator, event) = done_receiver.next().await.unwrap();
                        match event {
                            mocks::application::Progress::Notarized(proof, digest) => {
                                // Check correctness of proof
                                let (view, _, payload, _, _) =
                                    prover.deserialize_notarization(proof).unwrap();
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
                                let (view, _, payload, _, _) =
                                    prover.deserialize_finalization(proof).unwrap();
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
                    }
                });

                // Exit at random points for unclean shutdown of entire set
                let wait =
                    runtime.gen_range(Duration::from_millis(10)..Duration::from_millis(2_000));
                runtime.sleep(wait).await;
                {
                    let mut shutdowns = shutdowns.lock().unwrap();
                    debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                    *shutdowns += 1;
                }

                // Collect supervisors
                supervised.lock().unwrap().push(supervisors);
            }});

            // Recover runtime
            (executor, runtime, _) = runtime.recover();
        }

        // Check supervisors for faults activity
        let supervised = supervised.lock().unwrap();
        for supervisors in supervised.iter() {
            for (_, supervisor) in supervisors.iter() {
                let faults = supervisor.faults.lock().unwrap();
                assert!(faults.is_empty());
            }
        }
    }

    #[test_traced]
    fn test_backfill() {
        // Create runtime
        let n = 4;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(360));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all online engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
                Action::Update(link.clone()),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Wait for nullifications to accrue
            runtime.sleep(Duration::from_secs(120)).await;

            // Unlink second peer from all (except first)
            link_validators(
                &mut oracle,
                &validators,
                Action::Unlink,
                Some(|_, i, j| [i, j].contains(&1usize) && ![i, j].contains(&0usize)),
            )
            .await;

            // Configure engine for first peer
            let scheme = schemes[0].clone();
            let validator = scheme.public_key();
            {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", validator));

                // Link first peer to all (except second)
                link_validators(
                    &mut oracle,
                    &validators,
                    Action::Link(link),
                    Some(|_, i, j| [i, j].contains(&0usize) && ![i, j].contains(&1usize)),
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
                    Action::Update(link),
                    Some(|_, i, j| ![i, j].contains(&1usize)),
                )
                .await;

                // Configure engine
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[0]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for new engine to finalize required
            let mut finalized = HashMap::new();
            let mut validator_finalized = HashSet::new();
            loop {
                let (candidate, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        tracker: done_sender.clone(),
                        propose_latency: (3_000.0, 0.0),
                        verify_latency: (3_000.0, 5.0),
                    }
                } else {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 100;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(120));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 3_000.0,
                jitter: 0.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

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
            link_validators(&mut oracle, &validators, Action::Update(link), None).await;

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(900));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link.clone()), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            let mut highest_finalized = 0;
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
            fn separated(n: usize, a: usize, b: usize) -> bool {
                let m = n / 2;
                (a < m && b >= m) || (a >= m && b < m)
            }
            link_validators(&mut oracle, &validators, Action::Unlink, Some(separated)).await;

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
                Action::Link(link),
                Some(separated),
            )
            .await;

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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

    fn slow_and_lossy_links(seed: u64) -> String {
        // Create runtime
        let n = 5;
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config {
            seed,
            timeout: Some(Duration::from_secs(3_000)),
            ..deterministic::Config::default()
        };
        let (executor, mut runtime, auditor) = Executor::init(cfg);
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let degraded_link = Link {
                latency: 200.0,
                jitter: 150.0,
                success_rate: 0.5,
            };
            link_validators(&mut oracle, &validators, Action::Link(degraded_link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    tracker: done_sender.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    runtime.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let cfg = JConfig {
                    partition: validator.to_string(),
                };
                let journal = Journal::init(runtime.with_label("journal"), cfg)
                    .await
                    .expect("unable to create journal");
                let cfg = config::Config {
                    crypto: scheme,
                    automaton: application.clone(),
                    relay: application.clone(),
                    committer: application,
                    supervisor,
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
                let engine = Engine::new(runtime.with_label("engine"), journal, cfg);

                // Start engine
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(voter, resolver));
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::conflicter::Conflicter<_, Sha256, _> =
                        mocks::conflicter::Conflicter::new(
                            runtime.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(voter);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        runtime.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(runtime.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        committer: application,
                        supervisor,
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
                    let engine = Engine::new(runtime.with_label("engine"), journal, cfg);
                    engine.start(voter, resolver);
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
        let threshold = quorum(n).expect("unable to calculate threshold");
        let required_containers = 50;
        let activity_timeout = 10;
        let namespace = b"consensus".to_vec();
        let (executor, mut runtime, _) = Executor::timed(Duration::from_secs(30));
        executor.start(async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                runtime.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                },
            );

            // Start network
            network.start();

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
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (public, shares) = ops::generate_shares(&mut runtime, None, n, threshold);
            let pk = poly::public(&public);
            let prover = Prover::new(pk, &namespace);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let (done_sender, mut done_receiver) = mpsc::unbounded();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme runtime
                let runtime = runtime
                    .clone()
                    .with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(0, (public.clone(), validators.clone(), shares[idx_scheme]));
                let supervisor_config = mocks::supervisor::Config {
                    prover: prover.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (voter, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, Sha256, _> =
                        mocks::nuller::Nuller::new(runtime.with_label("byzantine_engine"), cfg);
                    engine.start(voter);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        tracker: done_sender.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        runtime.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let cfg = JConfig {
                        partition: validator.to_string(),
                    };
                    let journal = Journal::init(runtime.with_label("journal"), cfg)
                        .await
                        .expect("unable to create journal");
                    let cfg = config::Config {
                        crypto: scheme,
                        automaton: application.clone(),
                        relay: application.clone(),
                        committer: application,
                        supervisor,
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
                    let engine = Engine::new(runtime.with_label("engine"), journal, cfg);
                    engine.start(voter, resolver);
                }
            }

            // Wait for all engines to finish
            let mut completed = HashSet::new();
            let mut finalized = HashMap::new();
            loop {
                let (validator, event) = done_receiver.next().await.unwrap();
                if let mocks::application::Progress::Finalized(proof, digest) = event {
                    let (view, _, payload, _, _) = prover.deserialize_finalization(proof).unwrap();
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
