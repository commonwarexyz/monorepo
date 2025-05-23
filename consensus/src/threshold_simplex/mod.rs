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
//! * Lazy Message Verification
//! * Flexible Block Format
//! * Embedded VRF for Leader Election and Post-Facto Execution Randomness
//! * Succinct Consensus Certificates for Notarization, Nullification, and Finality
//!
//! # Design
//!
//! ## Architecture
//!
//! All logic is split into four components: the `Batcher`, the `Voter`, the `Resolver`, and the `Application` (provided by the user).
//! The `Batcher` is responsible for collecting messages from peers and lazily verifying them when a quorum is met. The `Voter`
//! is responsible for directing participation in the current view. Lastly, the `Resolver` is responsible for
//! fetching artifacts from previous views required to verify proposed blocks in the latest view.
//!
//! To drive great performance, all interactions between `Batcher`, `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` verifies a notarization.
//!
//! ```txt
//!                            +------------+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Batcher   |          +    Peers    +
//!                            |            |<---------+             +
//!                            +-------+----+          +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                |   |
//!                                |   |
//!                                v   |
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
//! ## Batched Verification
//!
//! Unlike other consensus constructions that verify all incoming messages received from peers,
//! `threshold-simplex` lazily verifies messages (only when a quorum is met). If an invalid signature
//! is detected, the `Batcher` will perform repeated bisections over collected messages to find the
//! offending message (and block the peer(s) that sent it via [commonware_p2p::Blocker]).
//!
//! _If using a p2p implementation that is not authenticated, it is not safe to employ this optimization
//! as any attacking peer could simply reconnect from a different address. We recommend [commonware_p2p::authenticated]._
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

use types::View;

pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actors;
        mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
    }
}

#[cfg(test)]
pub mod mocks;

/// The minimum view we are tracking both in-memory and on-disk.
pub(crate) fn min_active(activity_timeout: View, last_finalized: View) -> View {
    last_finalized.saturating_sub(activity_timeout)
}

/// Whether or not a view is interesting to us. This is a function
/// of both `min_active` and whether or not the view is too far
/// in the future (based on the view we are currently in).
pub(crate) fn interesting(
    activity_timeout: View,
    last_finalized: View,
    current: View,
    pending: View,
    allow_future: bool,
) -> bool {
    if pending < min_active(activity_timeout, last_finalized) {
        return false;
    }
    if !allow_future && pending > current + 1 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Monitor;
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::variant::{MinPk, MinSig, Variant},
        },
        Ed25519, Sha256, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use commonware_utils::{quorum, Array, NZU32};
    use engine::Engine;
    use futures::{future::join_all, StreamExt};
    use governor::Quota;
    use rand::{rngs::StdRng, Rng as _, SeedableRng as _};
    use std::{
        collections::{BTreeMap, HashMap},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::{debug, warn};
    use types::Activity;

    /// Registers all validators using the oracle.
    async fn register_validators<P: Array>(
        oracle: &mut Oracle<P>,
        validators: &[P],
    ) -> HashMap<
        P,
        (
            (Sender<P>, Receiver<P>),
            (Sender<P>, Receiver<P>),
            (Sender<P>, Receiver<P>),
        ),
    > {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let (pending_sender, pending_receiver) =
                oracle.register(validator.clone(), 0).await.unwrap();
            let (recovered_sender, recovered_receiver) =
                oracle.register(validator.clone(), 1).await.unwrap();
            let (resolver_sender, resolver_receiver) =
                oracle.register(validator.clone(), 2).await.unwrap();
            registrations.insert(
                validator.clone(),
                (
                    (pending_sender, pending_receiver),
                    (recovered_sender, recovered_receiver),
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

    fn all_online<V: Variant>() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (polynomial.clone(), validators.clone(), shares[idx].clone()),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let latest_complete = required_containers - activity_timeout;
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure seeds for all views
                {
                    let seeds = supervisor.seeds.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure seed for every view
                        if !seeds.contains_key(&view) {
                            panic!("view: {}", view);
                        }
                    }
                }

                // Ensure no forks
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = supervisor.notarizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        if notarizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
                        }
                    }
                }
                {
                    let notarizations = supervisor.notarizations.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure notarization matches digest from notarizes
                        let Some(notarization) = notarizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = notarized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&notarization.proposal.payload, digest);
                    }
                }
                {
                    let finalizes = supervisor.finalizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {}", view);
                        }
                        let (digest, finalizers) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        if finalizers.len() < threshold as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {}", view);
                        }

                        // Ensure no nullifies for any finalizers
                        let nullifies = supervisor.nullifies.lock().unwrap();
                        let Some(nullifies) = nullifies.get(&view) else {
                            continue;
                        };
                        for (_, finalizers) in payloads.iter() {
                            for finalizer in finalizers.iter() {
                                if nullifies.contains(finalizer) {
                                    panic!("should not nullify and finalize at same view");
                                }
                            }
                        }
                    }
                }
                {
                    let finalizations = supervisor.finalizations.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure finalization matches digest from finalizes
                        let Some(finalization) = finalizations.get(&view) else {
                            continue;
                        };
                        let Some(digest) = finalized.get(&view) else {
                            continue;
                        };
                        assert_eq!(&finalization.proposal.payload, digest);
                    }
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_all_online() {
        all_online::<MinPk>();
        all_online::<MinSig>();
    }

    fn unclean_shutdown<V: Variant>() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();

        // Derive threshold
        let mut rng = StdRng::seed_from_u64(0);
        let (polynomial, shares) = ops::generate_shares::<_, V>(&mut rng, None, n, threshold);

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let mut prev_ctx = None;

        loop {
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let supervised = supervised.clone();
            let polynomial = polynomial.clone();
            let shares = shares.clone();

            let f = |mut context: deterministic::Context| async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
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
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut supervisors = HashMap::new();
                let mut engine_handlers = Vec::new();
                for (idx, scheme) in schemes.into_iter().enumerate() {
                    // Create scheme context
                    let context = context
                        .clone()
                        .with_label(&format!("validator-{}", scheme.public_key()));

                    // Configure engine
                    let validator = scheme.public_key();
                    let mut participants = BTreeMap::new();
                    participants.insert(
                        0,
                        (polynomial.clone(), validators.clone(), shares[idx].clone()),
                    );
                    let supervisor_config = mocks::supervisor::Config::<_, V> {
                        namespace: namespace.clone(),
                        participants,
                    };
                    let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                    supervisors.insert(validator.clone(), supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);

                    // Start engine
                    let (pending, recovered, resolver) = registrations
                        .remove(&validator)
                        .expect("validator should be registered");
                    engine_handlers.push(engine.start(pending, recovered, resolver));
                }

                // Store all finalizer handles
                let mut finalizers = Vec::new();
                for (_, supervisor) in supervisors.iter_mut() {
                    let (mut latest, mut monitor) = supervisor.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < required_containers {
                            latest = monitor.next().await.expect("event missing");
                        }
                    }));
                }

                // Exit at random points for unclean shutdown of entire set
                let wait =
                    context.gen_range(Duration::from_millis(10)..Duration::from_millis(2_000));
                let result = select! {
                    _ = context.sleep(wait) => {
                        // Collect supervisors to check faults
                        {
                            let mut shutdowns = shutdowns.lock().unwrap();
                            debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                            *shutdowns += 1;
                        }
                        supervised.lock().unwrap().push(supervisors);
                        (false,context)
                    },
                    _ = join_all(finalizers) => {
                        // Check supervisors for faults activity
                        let supervised = supervised.lock().unwrap();
                        for supervisors in supervised.iter() {
                            for (_, supervisor) in supervisors.iter() {
                                let faults = supervisor.faults.lock().unwrap();
                                assert!(faults.is_empty());
                            }
                        }
                        (true,context)
                    }
                };

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());

                result
            };

            let (complete, context) = if let Some(prev_ctx) = prev_ctx {
                deterministic::Runner::from(prev_ctx)
            } else {
                deterministic::Runner::timed(Duration::from_secs(30))
            }
            .start(f);

            // Check if we should exit
            if complete {
                break;
            }

            prev_ctx = Some(context.recover());
        }
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown::<MinPk>();
        unclean_shutdown::<MinSig>();
    }

    fn backfill<V: Variant>() {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(720));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1, // force many fetches
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

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
            context.sleep(Duration::from_secs(120)).await;

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
            let context = context.with_label(&format!("validator-{}", validator));

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
            participants.insert(
                0,
                (polynomial.clone(), validators.clone(), shares[0].clone()),
            );
            let supervisor_config = mocks::supervisor::Config::<_, V> {
                namespace: namespace.clone(),
                participants,
            };
            let mut supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
            supervisors.push(supervisor.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validator.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let blocker = oracle.control(scheme.public_key());
            let cfg = config::Config {
                crypto: scheme,
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: supervisor.clone(),
                supervisor: supervisor.clone(),
                partition: validator.to_string(),
                compression: Some(3),
                mailbox_size: 1024,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                max_fetch_count: 1,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 1,
                replay_concurrency: 1,
                replay_buffer: 1024 * 1024,
                write_buffer: 1024 * 1024,
            };
            let engine = Engine::new(context.with_label("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            engine_handlers.push(engine.start(pending, recovered, resolver));

            // Wait for new engine to finalize required
            let (mut latest, mut monitor) = supervisor.subscribe().await;
            while latest < required_containers {
                latest = monitor.next().await.expect("event missing");
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_backfill() {
        backfill::<MinPk>();
        backfill::<MinSig>();
    }

    fn one_offline<V: Variant>() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let max_exceptions = 10;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let exceptions = 0;
            let offline = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure offline node is never active
                let mut exceptions = 0;
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
                    let nullifies = supervisor.nullifies.lock().unwrap();
                    for (view, participants) in nullifies.iter() {
                        if participants.contains(offline) {
                            panic!("view: {}", view);
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

                // Identify offline views
                let mut offline_views = Vec::new();
                {
                    let leaders = supervisor.leaders.lock().unwrap();
                    for (view, leader) in leaders.iter() {
                        if leader == offline {
                            offline_views.push(*view);
                        }
                    }
                }
                assert!(!offline_views.is_empty());

                // Ensure nullifies/nullification collected for offline node
                {
                    let nullifies = supervisor.nullifies.lock().unwrap();
                    for view in offline_views.iter() {
                        let nullifies = nullifies.get(view).map_or(0, |n| n.len());
                        if nullifies < threshold as usize {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }
                {
                    let nullifications = supervisor.nullifications.lock().unwrap();
                    for view in offline_views.iter() {
                        if !nullifications.contains_key(view) {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }

                // Ensure exceptions within allowed
                assert!(exceptions <= max_exceptions);
            }
            assert!(exceptions <= max_exceptions);

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());

            // Ensure we are skipping views
            let encoded = context.encode();
            let lines = encoded.lines();
            let mut skipped_views = 0;
            let mut nodes_skipping = 0;
            for line in lines {
                if line.contains("_engine_voter_skipped_views_total") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(number_str) = parts.last() {
                        if let Ok(number) = number_str.parse::<u64>() {
                            if number > 0 {
                                nodes_skipping += 1;
                            }
                            if number > skipped_views {
                                skipped_views = number;
                            }
                        }
                    }
                }
            }
            assert!(
                skipped_views > 0,
                "expected skipped views to be greater than 0"
            );
            assert_eq!(
                nodes_skipping,
                n - 1,
                "expected all online nodes to be skipping views"
            );
        });
    }

    #[test_traced]
    fn test_one_offline() {
        one_offline::<MinPk>();
        one_offline::<MinSig>();
    }

    fn slow_validator<V: Variant>() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = if idx_scheme == 0 {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10_000.0, 0.0),
                        verify_latency: (10_000.0, 5.0),
                    }
                } else {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let slow = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure slow node never emits a notarize or finalize (will never finish verification in a timely manner)
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

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_slow_validator() {
        slow_validator::<MinPk>();
        slow_validator::<MinSig>();
    }

    fn all_recovery<V: Variant>() {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 2;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(180));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (polynomial.clone(), validators.clone(), shares[idx].clone()),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (_, mut monitor) = supervisor.subscribe().await;
                finalizers.push(
                    context
                        .with_label("finalizer")
                        .spawn(move |context| async move {
                            select! {
                                _timeout = context.sleep(Duration::from_secs(60)) => {},
                                _done = monitor.next() => {
                                    panic!("engine should not notarize or finalize anything");
                                }
                            }
                        }),
                );
            }
            join_all(finalizers).await;

            // Unlink all validators to get latest view
            link_validators(&mut oracle, &validators, Action::Unlink, None).await;

            // Wait for a virtual minute (nothing should happen)
            context.sleep(Duration::from_secs(60)).await;

            // Get latest view
            let mut latest = 0;
            for supervisor in supervisors.iter() {
                let nullifies = supervisor.nullifies.lock().unwrap();
                let max = nullifies.keys().max().unwrap();
                if *max > latest {
                    latest = *max;
                }
            }

            // Update links
            let link = Link {
                latency: 10.0,
                jitter: 1.0,
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure quick recovery.
                //
                // If the skip timeout isn't implemented correctly, we may go many views before participants
                // start to consider a validator's proposal.
                {
                    // Ensure nearly all views around latest finalize
                    let mut found = 0;
                    let finalizations = supervisor.finalizations.lock().unwrap();
                    for i in latest..latest + activity_timeout {
                        if finalizations.contains_key(&i) {
                            found += 1;
                        }
                    }
                    assert!(found >= activity_timeout - 2, "found: {}", found);
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        all_recovery::<MinPk>();
        all_recovery::<MinSig>();
    }

    fn partition<V: Variant>() {
        // Create context
        let n = 10;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (polynomial.clone(), validators.clone(), shares[idx].clone()),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Cut all links between validator halves
            fn separated(n: usize, a: usize, b: usize) -> bool {
                let m = n / 2;
                (a < m && b >= m) || (a >= m && b < m)
            }
            link_validators(&mut oracle, &validators, Action::Unlink, Some(separated)).await;

            // Wait for any in-progress notarizations/finalizations to finish
            context.sleep(Duration::from_secs(10)).await;

            // Wait for a few virtual minutes (shouldn't finalize anything)
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (_, mut monitor) = supervisor.subscribe().await;
                finalizers.push(
                    context
                        .with_label("finalizer")
                        .spawn(move |context| async move {
                            select! {
                                _timeout = context.sleep(Duration::from_secs(60)) => {},
                                _done = monitor.next() => {
                                    panic!("engine should not notarize or finalize anything");
                                }
                            }
                        }),
                );
            }
            join_all(finalizers).await;

            // Restore links
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(separated),
            )
            .await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                let required = latest + required_containers;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    #[ignore]
    fn test_partition() {
        partition::<MinPk>();
        partition::<MinSig>();
    }

    fn slow_and_lossy_links<V: Variant>(seed: u64) -> String {
        // Create context
        let n = 5;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(5_000)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (polynomial.clone(), validators.clone(), shares[idx].clone()),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());

            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_slow_and_lossy_links() {
        slow_and_lossy_links::<MinPk>(0);
        slow_and_lossy_links::<MinSig>(0);
    }

    #[test_traced]
    #[ignore]
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

            // Sanity check that different types can't be identical
            assert_ne!(pk_state_1, sig_state_1);
        }
    }

    fn conflicter<V: Variant>(seed: u64) {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };

                    let engine: mocks::conflicter::Conflicter<_, V, Sha256, _> =
                        mocks::conflicter::Conflicter::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let byz = &validators[0];
            let mut count_conflicting = 0;
            for supervisor in supervisors.iter() {
                // Ensure only faults for byz
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::ConflictingNotarize(_) => {
                                    count_conflicting += 1;
                                }
                                Activity::ConflictingFinalize(_) => {
                                    count_conflicting += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }
            assert!(count_conflicting > 0);

            // Ensure conflicter is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    #[test_traced]
    #[ignore]
    fn test_conflicter() {
        for seed in 0..5 {
            conflicter::<MinPk>(seed);
            conflicter::<MinSig>(seed);
        }
    }

    fn invalid<V: Variant>(seed: u64) {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::invalid::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };

                    let engine: mocks::invalid::Invalid<_, V, Sha256, _> =
                        mocks::invalid::Invalid::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let mut invalid_count = 0;
            let byz = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Count invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    if *invalid > 0 {
                        invalid_count += 1;
                    }
                }
            }
            assert_eq!(invalid_count, n - 1);

            // Ensure invalid is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    #[test_traced]
    #[ignore]
    fn test_invalid() {
        for seed in 0..5 {
            invalid::<MinPk>(seed);
            invalid::<MinSig>(seed);
        }
    }

    fn impersonator<V: Variant>(seed: u64) {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::impersonator::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };

                    let engine: mocks::impersonator::Impersonator<_, V, Sha256, _> =
                        mocks::impersonator::Impersonator::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            let byz = &validators[0];
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure invalid is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    #[test_traced]
    #[ignore]
    fn test_impersonator() {
        for seed in 0..5 {
            impersonator::<MinPk>(seed);
            impersonator::<MinSig>(seed);
        }
    }

    fn nuller<V: Variant>(seed: u64) {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 50;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        supervisor,
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, V, Sha256, _> =
                        mocks::nuller::Nuller::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

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
                            match fault {
                                Activity::NullifyFinalize(_) => {
                                    count_nullify_and_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {:?}", fault),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }
            assert!(count_nullify_and_finalize > 0);

            // Ensure nullifier is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    #[test_traced]
    #[ignore]
    fn test_nuller() {
        for seed in 0..5 {
            nuller::<MinPk>(seed);
            nuller::<MinSig>(seed);
        }
    }

    fn outdated<V: Variant>(seed: u64) {
        // Create context
        let n = 4;
        let threshold = quorum(n);
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (
                        polynomial.clone(),
                        validators.clone(),
                        shares[idx_scheme].clone(),
                    ),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::outdated::Config {
                        supervisor,
                        namespace: namespace.clone(),
                        view_delta: activity_timeout * 4,
                    };
                    let engine: mocks::outdated::Outdated<_, V, Sha256, _> =
                        mocks::outdated::Outdated::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    supervisors.push(supervisor.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        participant: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(scheme.public_key());
                    let cfg = config::Config {
                        crypto: scheme,
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: supervisor.clone(),
                        supervisor,
                        partition: validator.to_string(),
                        compression: Some(3),
                        mailbox_size: 1024,
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        max_fetch_count: 1,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 1,
                        replay_concurrency: 1,
                        replay_buffer: 1024 * 1024,
                        write_buffer: 1024 * 1024,
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    #[ignore]
    fn test_outdated() {
        for seed in 0..5 {
            outdated::<MinPk>(seed);
            outdated::<MinSig>(seed);
        }
    }

    fn run_1k<V: Variant>() {
        // Create context
        let n = 10;
        let threshold = quorum(n);
        let required_containers = 1_000;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new();
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
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
                latency: 80.0,
                jitter: 10.0,
                success_rate: 0.98,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Derive threshold
            let (polynomial, shares) =
                ops::generate_shares::<_, V>(&mut context, None, n, threshold);

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut supervisors = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let mut participants = BTreeMap::new();
                participants.insert(
                    0,
                    (polynomial.clone(), validators.clone(), shares[idx].clone()),
                );
                let supervisor_config = mocks::supervisor::Config::<_, V> {
                    namespace: namespace.clone(),
                    participants,
                };
                let supervisor = mocks::supervisor::Supervisor::new(supervisor_config);
                supervisors.push(supervisor.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    participant: validator.clone(),
                    propose_latency: (100.0, 50.0),
                    verify_latency: (50.0, 40.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(scheme.public_key());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: supervisor.clone(),
                    supervisor,
                    partition: validator.to_string(),
                    compression: Some(3),
                    mailbox_size: 1024,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 1,
                    replay_concurrency: 1,
                    replay_buffer: 1024 * 1024,
                    write_buffer: 1024 * 1024,
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for supervisor in supervisors.iter_mut() {
                let (mut latest, mut monitor) = supervisor.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check supervisors for correct activity
            for supervisor in supervisors.iter() {
                // Ensure no faults
                {
                    let faults = supervisor.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = supervisor.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        })
    }

    #[test_traced]
    #[ignore]
    fn test_1k() {
        run_1k::<MinPk>();
        run_1k::<MinSig>();
    }
}
