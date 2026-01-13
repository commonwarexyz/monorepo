//! Fast finality with even faster blocks inspired by Minimmit Consensus.
//!
//! Inspired by [Minimmit Consensus](https://arxiv.org/abs/2508.10862), `minimmit` provides responsive,
//! leader-based BFT agreement that prioritizes block time minimization while delivering finality
//! after a single round of voting.
//!
//! # Features
//!
//! * Fast Block Times (~50-130ms depending on configuration)
//! * Single-Round Finality (~100-250ms)
//! * Externalized Uptime and Fault Proofs
//! * Nullify-by-Contradiction (can nullify after notarizing if conflicting votes observed)
//! * Application-Defined Block Format
//! * Pluggable Hashing and Cryptography
//! * Embedded VRF (via [scheme::bls12381_threshold])
//!
//! # Design
//!
//! ## Protocol Description
//!
//! Minimmit tolerates Byzantine adversaries controlling fewer than 20% of replicas (n >= 5f + 1).
//! It advances to the next view when a 40% quorum (M = 2f + 1) is reached and finalizes blocks
//! when an 80% quorum (L = n - f) is reached after only a single round of voting.
//!
//! ### Quorums
//!
//! * M = 2f + 1: Certificate threshold (view advancement)
//! * L = n - f: Finalization threshold
//!
//! There exists at least 1 honest replica in any M-set and L-set intersection.
//!
//! ### Specification for View `v`
//!
//! Upon entering view `v`:
//! * Determine leader `l` for view `v`
//! * Set timer for leader proposal `t = 2*Delta`
//! * If leader `l`, select valid parent and broadcast `propose(c, v, (c', v'))`
//!
//! Upon receiving first valid `propose(c, v, (c', v'))` from leader:
//! * If already notarized or nullified, return
//! * If valid_parent check passes and verify(c, c') passes, set notarized = c
//! * Broadcast `notarize(c, v)`
//!
//! Upon observing M `notarize(c, v)` messages:
//! * Assemble `notarization(c, v)` certificate
//! * Broadcast `notarization(c, v)`
//! * Enter view `v + 1`
//!
//! Upon observing L `notarize(c, v)` messages:
//! * Finalize `c` and all of its ancestors
//! * Prune old data
//!
//! Upon timer expiry (and not notarized/nullified):
//! * Set nullified = true
//! * Broadcast `nullify(v)`
//!
//! Upon observing M `nullify(v)` messages:
//! * Assemble `nullification(v)` certificate
//! * Broadcast `nullification(v)`
//! * Enter view `v + 1`
//!
//! ### Nullify by Contradiction
//!
//! If you have broadcast `notarize(c, v)` but observe M distinct replicas sending either
//! `nullify(v)` or `notarize(c', v)` where `c' != c`, you know finalization is impossible
//! and must broadcast `nullify(v)` to ensure some proof(v) will exist.
//!
//! ### Deviations from Simplex Consensus
//!
//! * Higher fault tolerance requirement: n >= 5f + 1 (vs n >= 3f + 1)
//! * No separate finalize phase: finalization occurs at L notarizes
//! * Nullify-by-contradiction: can nullify after notarizing if M conflicting votes observed
//! * Different quorum thresholds: M = 2f + 1 for certificates, L = n - f for finalization
//!
//! ## Architecture
//!
//! All logic is split into three components: the `Voter`, the `Resolver`, and the `Application`.
//! The `Voter` handles both vote collection/verification and consensus state (combining the
//! simplex `Batcher` and `Voter` roles). The `Resolver` fetches missing certificates from peers.
//! The `Application` proposes new blocks and indicates whether some block is valid.
//!
//! ```txt
//!                            +------------+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |   Voter    |          +    Peers    +
//!                            |            |<---------+             +
//!                            +-------+----+          +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                v   |
//!                            +-------+----+          +++++++++++++++
//!                            |            +--------->+             +
//!                            |  Resolver  |          +    Peers    +
//!                            |            |<---------+             +
//!                            +-------+----+          +++++++++++++++
//!                                |   ^
//!                                |   |
//!                                v   |
//!                            +-----------+
//!                            |           |
//!                            |Application|
//!                            |           |
//!                            +-----------+
//! ```
//!
//! # Signing Schemes
//!
//! `minimmit` supports the same signing schemes as `simplex`:
//!
//! * [`scheme::ed25519`]: Attributable, no trusted setup
//! * [`scheme::bls12381_multisig`]: Attributable, compact certificates
//! * [`scheme::bls12381_threshold`]: Non-attributable, constant-size certificates, requires DKG
//!
//! # Status
//!
//! `minimmit` is **ALPHA** software and is not yet recommended for production use.

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod config;
        pub mod elector;
        mod engine;
        mod metrics;
        mod actors;

        pub use config::Config;
        pub use engine::Engine;
        pub use elector::{Elector, RoundRobinElector};
    }
}

#[cfg(any(test, feature = "fuzz"))]
pub mod mocks;

/// Calculate f (maximum Byzantine replicas) from n where n >= 5f + 1.
///
/// Returns the maximum number of Byzantine replicas that can be tolerated.
#[inline]
pub const fn calculate_f(n: usize) -> usize {
    (n.saturating_sub(1)) / 5
}

/// Calculate M quorum threshold (2f + 1) for creating certificates.
///
/// This is the number of votes needed to create a notarization or nullification certificate
/// and advance to the next view.
#[inline]
pub const fn m_quorum(n: usize) -> usize {
    let f = calculate_f(n);
    2 * f + 1
}

/// Calculate L quorum threshold (n - f) for finalization.
///
/// This is the number of notarize votes needed to finalize a block.
#[inline]
pub const fn l_quorum(n: usize) -> usize {
    let f = calculate_f(n);
    n.saturating_sub(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_calculations() {
        // n = 5: f = 0, M = 1, L = 5 (degenerate case)
        assert_eq!(calculate_f(5), 0);
        assert_eq!(m_quorum(5), 1);
        assert_eq!(l_quorum(5), 5);

        // n = 6: f = 1, M = 3, L = 5
        assert_eq!(calculate_f(6), 1);
        assert_eq!(m_quorum(6), 3);
        assert_eq!(l_quorum(6), 5);

        // n = 11: f = 2, M = 5, L = 9
        assert_eq!(calculate_f(11), 2);
        assert_eq!(m_quorum(11), 5);
        assert_eq!(l_quorum(11), 9);

        // n = 16: f = 3, M = 7, L = 13
        assert_eq!(calculate_f(16), 3);
        assert_eq!(m_quorum(16), 7);
        assert_eq!(l_quorum(16), 13);

        // n = 21: f = 4, M = 9, L = 17
        assert_eq!(calculate_f(21), 4);
        assert_eq!(m_quorum(21), 9);
        assert_eq!(l_quorum(21), 17);
    }

    #[test]
    fn test_fault_tolerance_bound() {
        // Verify n >= 5f + 1 for various f values
        for f in 0..10 {
            let n = 5 * f + 1;
            assert_eq!(calculate_f(n), f);
            // M + L > n ensures intersection has at least one honest
            let m = m_quorum(n);
            let l = l_quorum(n);
            assert!(m + l > n, "M + L must exceed n for safety");
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod integration_tests {
    use super::{
        config,
        elector::{Config as ElectorConfig, RoundRobin},
        engine::Engine,
        l_quorum, m_quorum, mocks, scheme,
    };
    use crate::minimmit::types::Activity;
    use crate::{
        minimmit::scheme::Scheme,
        types::{Epoch, View, ViewDelta},
        Monitor,
    };
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest, Sha256,
    };
    use commonware_macros::test_traced;
    use commonware_p2p::simulated::{Config, Link, Network, Oracle, Receiver, Sender};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::PoolRef, deterministic, Metrics, Quota, Runner as _, Spawner,
    };
    use commonware_utils::NZUsize;
    use futures::{future::join_all, StreamExt};
    use std::{
        collections::HashMap,
        num::{NonZeroU16, NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    use tracing::warn;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroU16 = unsafe { NonZeroU16::new_unchecked(10) };
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// Register a validator with the oracle for three network channels.
    async fn register_validator(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validator: PublicKey,
    ) -> (
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
    ) {
        let mut control = oracle.control(validator.clone());
        let (vote_sender, vote_receiver) = control.register(0, TEST_QUOTA).await.unwrap();
        let (certificate_sender, certificate_receiver) =
            control.register(1, TEST_QUOTA).await.unwrap();
        let (resolver_sender, resolver_receiver) = control.register(2, TEST_QUOTA).await.unwrap();
        (
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        )
    }

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
    ) -> HashMap<
        PublicKey,
        (
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        ),
    > {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let registration = register_validator(oracle, validator.clone()).await;
            registrations.insert(validator.clone(), registration);
        }
        registrations
    }

    /// Action to perform when linking validators.
    enum Action {
        Link(Link),
        #[allow(dead_code)]
        Update(Link),
        #[allow(dead_code)]
        Unlink,
    }

    /// Links (or unlinks) validators using the oracle.
    async fn link_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
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

    fn all_online<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // Create context
        // n = 6 gives f = 1, M = 3, L = 5
        let n: u32 = 6;
        let l_quorum = l_quorum(n as usize) as usize;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context: deterministic::Context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator_{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    strategy: Sequential,
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    namespace: namespace.clone(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(10),
                    activity_timeout,
                    skip_timeout,
                    fetch_timeout: Duration::from_secs(1),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_CACHE_SIZE, PAGE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        let view: View = monitor.next().await.expect("event missing");
                        latest = view;
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let latest_complete = required_containers.saturating_sub(activity_timeout);
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().expect("faults lock poisoned");
                    assert!(faults.is_empty(), "expected no faults");
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().expect("invalid lock poisoned");
                    assert_eq!(*invalid, 0, "expected no invalid signatures");
                }

                // Ensure notarizations for all views
                let mut notarized: HashMap<View, Sha256Digest> = HashMap::new();
                {
                    let notarizes = reporter.notarizes.lock().expect("notarizes lock poisoned");
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        assert!(
                            payloads.len() <= 1,
                            "view {view}: multiple payloads notarized"
                        );
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        assert!(
                            notarizers.len() >= l_quorum,
                            "view {view}: not enough notarizers ({} < {l_quorum})",
                            notarizers.len()
                        );
                    }
                }
                {
                    let notarizations = reporter
                        .notarizations
                        .lock()
                        .expect("notarizations lock poisoned");
                    for view in View::range(View::new(1), latest_complete) {
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
            }

            // Ensure no blocked connections
            let blocked: Vec<(PublicKey, PublicKey)> = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "expected no blocked connections");
        });
    }

    #[test_traced]
    fn test_all_online_ed25519() {
        all_online::<_, _, RoundRobin>(|ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
    }

    #[test_traced]
    fn test_all_online_bls12381_multisig() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        all_online::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinPk, _>(ctx, b"minimmit_consensus", n));
        all_online::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinSig, _>(ctx, b"minimmit_consensus", n));
    }

    // Note: These tests are expected to fail/timeout until the minimmit engine
    // supports nullification properly. Currently the engine cannot form
    // nullification certificates when a validator is offline.

    fn one_offline<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // Create context
        // n = 6 gives f = 1, M = 3, L = 5
        let n: u32 = 6;
        let m_quorum_val = m_quorum(n as usize);
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let max_exceptions = 10;
        let namespace = b"minimmit_consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context: deterministic::Context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators except first (first is offline)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create engines (skip first validator - it's offline)
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Skip first peer (offline)
                if idx == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator_{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    strategy: Sequential,
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    namespace: namespace.clone(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(10),
                    activity_timeout,
                    skip_timeout,
                    fetch_timeout: Duration::from_secs(1),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_CACHE_SIZE, PAGE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let offline = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().expect("faults lock poisoned");
                    assert!(faults.is_empty(), "expected no faults");
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().expect("invalid lock poisoned");
                    assert_eq!(*invalid, 0, "expected no invalid signatures");
                }

                // Ensure offline node is never active in notarizes
                let mut exceptions = 0;
                {
                    let notarizes = reporter.notarizes.lock().expect("notarizes lock poisoned");
                    for (view, payloads) in notarizes.iter() {
                        for (_, notarizers) in payloads.iter() {
                            if notarizers.contains(offline) {
                                panic!("offline node participated in notarize for view: {view}");
                            }
                        }
                    }
                }

                // Ensure offline node is never active in nullifies
                {
                    let nullifies = reporter.nullifies.lock().expect("nullifies lock poisoned");
                    for (view, participants) in nullifies.iter() {
                        if participants.contains(offline) {
                            panic!("offline node participated in nullify for view: {view}");
                        }
                    }
                }

                // Identify offline views (where offline node would be leader)
                let mut offline_views = Vec::new();
                {
                    let leaders = reporter.leaders.lock().expect("leaders lock poisoned");
                    for (view, leader) in leaders.iter() {
                        if leader == offline {
                            offline_views.push(*view);
                        }
                    }
                }
                assert!(!offline_views.is_empty(), "expected some offline views");

                // Ensure nullifies/nullification collected for offline node views
                {
                    let nullifies = reporter.nullifies.lock().expect("nullifies lock poisoned");
                    for view in offline_views.iter() {
                        let nullifies = nullifies.get(view).map_or(0, |n| n.len());
                        if nullifies < m_quorum_val {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }
                {
                    let nullifications = reporter
                        .nullifications
                        .lock()
                        .expect("nullifications lock poisoned");
                    for view in offline_views.iter() {
                        if !nullifications.contains_key(view) {
                            warn!("missing expected view nullification: {}", view);
                            exceptions += 1;
                        }
                    }
                }

                // Ensure exceptions within allowed
                assert!(
                    exceptions <= max_exceptions,
                    "too many exceptions: {exceptions}"
                );
            }

            // Ensure no blocked connections
            let blocked: Vec<(PublicKey, PublicKey)> = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "expected no blocked connections");

            // Ensure we are skipping views
            let encoded = context.encode();
            let lines = encoded.lines();
            let mut skipped_views = 0;
            let mut nodes_skipping = 0;
            for line in lines {
                if line.contains("_skipped_views_total") {
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
                (n - 1) as u64,
                "expected all online nodes to be skipping views"
            );
        });
    }

    #[test_traced]
    fn test_one_offline_ed25519() {
        one_offline::<_, _, RoundRobin>(|ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
    }

    #[test_traced]
    fn test_one_offline_bls12381_multisig() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        one_offline::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinPk, _>(ctx, b"minimmit_consensus", n));
        one_offline::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinSig, _>(ctx, b"minimmit_consensus", n));
    }

    fn slow_validator<S, F, L>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // Create context
        // n = 6 gives f = 1, M = 3, L = 5
        let n: u32 = 6;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context: deterministic::Context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator_{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    strategy: Sequential,
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());

                // First validator has high latency (slow)
                let application_cfg = if idx == 0 {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10_000.0, 0.0),
                        verify_latency: (10_000.0, 5.0),
                    }
                } else {
                    mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    }
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    namespace: namespace.clone(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(10),
                    activity_timeout,
                    skip_timeout,
                    fetch_timeout: Duration::from_secs(1),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_CACHE_SIZE, PAGE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let slow = &participants[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().expect("faults lock poisoned");
                    assert!(faults.is_empty(), "expected no faults");
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().expect("invalid lock poisoned");
                    assert_eq!(*invalid, 0, "expected no invalid signatures");
                }

                // Ensure slow node still emits notarizes (when receiving certificates)
                let mut observed = false;
                {
                    let notarizes = reporter.notarizes.lock().expect("notarizes lock poisoned");
                    for (_, payloads) in notarizes.iter() {
                        for (_, notarizers) in payloads.iter() {
                            if notarizers.contains(slow) {
                                observed = true;
                                break;
                            }
                        }
                    }
                }
                assert!(observed, "slow node should still participate in notarizes");
            }

            // Ensure no blocked connections
            let blocked: Vec<(PublicKey, PublicKey)> = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "expected no blocked connections");
        });
    }

    #[test_traced]
    fn test_slow_validator_ed25519() {
        slow_validator::<_, _, RoundRobin>(|ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
    }

    #[test_traced]
    fn test_slow_validator_bls12381_multisig() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        slow_validator::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinPk, _>(ctx, b"minimmit_consensus", n));
        slow_validator::<_, _, RoundRobin>(|ctx, n| scheme::bls12381_multisig::fixture::<MinSig, _>(ctx, b"minimmit_consensus", n));
    }

    fn slow_and_lossy_links<S, F, L>(seed: u64, mut fixture: F) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // Create context
        // n = 6 gives f = 1, M = 3, L = 5
        let n: u32 = 6;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(5_000)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context: deterministic::Context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators with degraded links
            let degraded_link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.5,
            };
            link_validators(
                &mut oracle,
                &participants,
                Action::Link(degraded_link),
                None,
            )
            .await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator_{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    strategy: Sequential,
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    namespace: namespace.clone(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(10),
                    activity_timeout,
                    skip_timeout,
                    fetch_timeout: Duration::from_secs(1),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_CACHE_SIZE, PAGE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().expect("faults lock poisoned");
                    assert!(faults.is_empty(), "expected no faults");
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().expect("invalid lock poisoned");
                    assert_eq!(*invalid, 0, "expected no invalid signatures");
                }
            }

            // Ensure no blocked connections
            let blocked: Vec<(PublicKey, PublicKey)> = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty(), "expected no blocked connections");

            context.auditor().state()
        })
    }

    #[test_traced]
    fn test_slow_and_lossy_links_ed25519() {
        slow_and_lossy_links::<_, _, RoundRobin>(0, |ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
    }

    #[test_traced]
    fn test_slow_and_lossy_links_bls12381_multisig() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        slow_and_lossy_links::<_, _, RoundRobin>(0, |ctx, n| scheme::bls12381_multisig::fixture::<MinPk, _>(ctx, b"minimmit_consensus", n));
        slow_and_lossy_links::<_, _, RoundRobin>(
            0,
            |ctx, n| scheme::bls12381_multisig::fixture::<MinSig, _>(ctx, b"minimmit_consensus", n),
        );
    }

    fn conflicter<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
        L: ElectorConfig<S>,
    {
        // Create context
        // n = 6 gives f = 1, M = 3, L = 5
        // With one Byzantine node, we still have 5 honest (satisfying n >= 5f + 1 for f = 1)
        let n: u32 = 6;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context: deterministic::Context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines (first one is Byzantine conflicter)
            let elector = L::default();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator_{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    strategy: Sequential,
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");

                if idx == 0 {
                    // Byzantine conflicter
                    let cfg = mocks::conflicter::Config {
                        namespace: namespace.clone(),
                        scheme: schemes[idx].clone(),
                    };
                    let engine: mocks::conflicter::Conflicter<_, _, Sha256> =
                        mocks::conflicter::Conflicter::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(vote);
                } else {
                    reporters.push(reporter.clone());
                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        namespace: namespace.clone(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        leader_timeout: Duration::from_secs(1),
                        nullify_retry: Duration::from_secs(10),
                        activity_timeout,
                        skip_timeout,
                        fetch_timeout: Duration::from_secs(1),
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_CACHE_SIZE, PAGE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(vote, certificate, resolver);
                }
            }

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            let byz = &participants[0];
            let mut count_conflicting = 0;
            for reporter in reporters.iter() {
                // Ensure only faults for Byzantine node
                {
                    let faults = reporter.faults.lock().expect("faults lock poisoned");
                    assert_eq!(faults.len(), 1, "expected exactly one faulter");
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::ConflictingNotarize(_) => {
                                    count_conflicting += 1;
                                }
                                _ => panic!("unexpected fault: {fault:?}"),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().expect("invalid lock poisoned");
                    assert_eq!(*invalid, 0, "expected no invalid signatures");
                }
            }
            assert!(count_conflicting > 0, "expected some conflicting faults");

            // Ensure conflicter is blocked
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty(), "expected Byzantine node to be blocked");
            for (a, b) in blocked {
                assert_ne!(&a, byz, "Byzantine node should be the one blocked");
                assert_eq!(&b, byz, "Byzantine node should be the one blocked");
            }
        });
    }

    #[test_traced]
    fn test_conflicter_ed25519() {
        for seed in 0..5 {
            conflicter::<_, _, RoundRobin>(seed, |ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
        }
    }

    #[test_traced]
    fn test_conflicter_bls12381_multisig() {
        use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};
        for seed in 0..5 {
            conflicter::<_, _, RoundRobin>(seed, |ctx, n| scheme::bls12381_multisig::fixture::<MinPk, _>(ctx, b"minimmit_consensus", n));
            conflicter::<_, _, RoundRobin>(seed, |ctx, n| scheme::bls12381_multisig::fixture::<MinSig, _>(ctx, b"minimmit_consensus", n));
        }
    }

    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            let ms_pk_state_1 = slow_and_lossy_links::<_, _, RoundRobin>(
                seed,
                |ctx, n| scheme::bls12381_multisig::fixture::<
                    commonware_cryptography::bls12381::primitives::variant::MinPk,
                    _,
                >(ctx, b"minimmit_consensus", n),
            );
            let ms_pk_state_2 = slow_and_lossy_links::<_, _, RoundRobin>(
                seed,
                |ctx, n| scheme::bls12381_multisig::fixture::<
                    commonware_cryptography::bls12381::primitives::variant::MinPk,
                    _,
                >(ctx, b"minimmit_consensus", n),
            );
            assert_eq!(
                ms_pk_state_1, ms_pk_state_2,
                "determinism failed for seed {seed}"
            );

            let ms_sig_state_1 = slow_and_lossy_links::<_, _, RoundRobin>(
                seed,
                |ctx, n| scheme::bls12381_multisig::fixture::<
                    commonware_cryptography::bls12381::primitives::variant::MinSig,
                    _,
                >(ctx, b"minimmit_consensus", n),
            );
            let ms_sig_state_2 = slow_and_lossy_links::<_, _, RoundRobin>(
                seed,
                |ctx, n| scheme::bls12381_multisig::fixture::<
                    commonware_cryptography::bls12381::primitives::variant::MinSig,
                    _,
                >(ctx, b"minimmit_consensus", n),
            );
            assert_eq!(
                ms_sig_state_1, ms_sig_state_2,
                "determinism failed for seed {seed}"
            );

            let ed_state_1 =
                slow_and_lossy_links::<_, _, RoundRobin>(seed, |ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
            let ed_state_2 =
                slow_and_lossy_links::<_, _, RoundRobin>(seed, |ctx, n| scheme::ed25519::fixture(ctx, b"minimmit_consensus", n));
            assert_eq!(ed_state_1, ed_state_2, "determinism failed for seed {seed}");

            let states = [
                ("multisig-minpk", ms_pk_state_1),
                ("multisig-minsig", ms_sig_state_1),
                ("ed25519", ed_state_1),
            ];

            // Sanity check that different types can't be identical
            for pair in states.windows(2) {
                assert_ne!(
                    pair[0].1, pair[1].1,
                    "state {} equals state {}",
                    pair[0].0, pair[1].0
                );
            }
        }
    }
}
