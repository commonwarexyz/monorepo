//! Simplex-like BFT agreement with pluggable signature schemes and scheme-dependent certificate formats.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `threshold-simplex` provides simple and
//! fast BFT agreement with network-speed view (i.e. block time) latency and optimal finalization latency in a
//! partially synchronous setting. Cryptography is abstracted behind the [`Scheme`] trait, letting deployments
//! plug in different vote/certificate schemes. The following signing schemes are currently implemented:
//!
//! * **BLS12-381 threshold signatures** – `2f+1` shares from a `3f+1` quorum to generate both a bias-resistant
//!   beacon (for leader election and post-facto execution randomness) and succinct consensus certificates (any
//!   certificate can be verified with just the static public key of the consensus instance) for each view with
//!   zero message overhead (natively integrated).
//! * **Ed25519 quorum signatures** – traditional individual signatures collected into a vector, retaining the
//!   same interface but without succinct certificate aggregation or randomness seed.
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Lazy Message Verification
//! * Flexible Block Format
//! * Scheme-dependent consensus certificates for notarization, nullification, and finality
//! * Embedded VRF for leader election and post-facto randomness (exposed by the BLS threshold scheme)
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
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [commonware_storage::journal::variable::Journal].
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
//! * If leader `l`, broadcast `notarize(c,v)`
//!   * If can't propose container in view `v` because missing notarization/nullification for a
//!     previous view `v_m`, request `v_m`
//!
//! Upon receiving first `notarize(c,v)` from `l`:
//! * Cancel `t_l`
//! * If the container's parent `c_parent` is notarized at `v_parent` and we have nullifications for all views
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
//! #### Embedded VRF (BLS Threshold Scheme)
//!
//! When the BLS threshold signing scheme is in use, every `notarize(c,v)` or `nullify(v)` message includes a `part(v)` message (a partial
//! signature over the view `v`). After `2f+1` `notarize(c,v)` or `nullify(v)` messages are collected from unique participants,
//! `seed(v)` can be recovered. Because `part(v)` is only over the view `v`, the seed derived for a given view `v` is the same regardless of
//! whether or not a block was notarized in said view `v`.
//!
//! Because the value of `seed(v)` cannot be known prior to message broadcast by any participant (including the leader) in view `v`
//! and cannot be manipulated by any participant (deterministic for any `2f+1` signers at a given view `v`), it can be used both as a beacon
//! for leader election (where `seed(v)` determines the leader for `v+1`) and a source of randomness in execution (where `seed(v)`
//! is used as a seed in `v`).
//!
//! #### Consensus Certificates
//!
//! Every view produces `notarization(c,v)`, `nullification(v)`, and `finalization(c,v)` evidence (i.e. consensus certificates) whose
//! concrete representation is dictated by the active signing scheme. These certificates are produced as soon as `2f+1` vote messages
//! (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`) are collected and they can be used to secure interoperability between different
//! consensus instances and user interactions with an infrastructure provider.
//!
//! * With **BLS12-381 threshold signatures**, each broadcast vote carries a partial signature for a static group public key (derived
//!   from a group polynomial that can be recomputed during reconfiguration using [dkg](commonware_cryptography::bls12381::dkg)). Once a
//!   quorum (`2f+1`) is collected, these partials aggregate into a succinct certificate that can be verified using only the committee
//!   public key. Because the public key is static, any of these certificates can be verified by an external process without following
//!   the consensus instance and/or tracking the current set of participants (as is typically required to operate a lite client).
//! * With **Ed25519 quorum signatures**, certificates consist of the individual signatures from the quorum. While larger, they preserve
//!   the same interface and can be validated against the ordered participant set exported by the scheme.
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

pub mod signing_scheme;
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

use crate::types::{Round, View};
use commonware_codec::Encode;
use signing_scheme::Scheme;

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

/// Selects the leader for a given round using scheme-provided randomness seed when available.
///
/// If the active [`Scheme`] exposes a seed (e.g. BLS threshold certificates), the seed is
/// encoded and reduced modulo the number of participants. Otherwise we fall back to
/// simple round-robin using the view number.
pub fn select_leader<S, P>(participants: &[P], round: Round, seed: Option<S::Seed>) -> u32
where
    S: Scheme,
{
    let idx = if let Some(seed) = seed {
        commonware_utils::modulo(seed.encode().as_ref(), participants.len() as u64) as usize
    } else {
        (round.epoch() + round.view()) as usize % participants.len()
    };

    idx as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        threshold_simplex::{
            mocks::fixtures::{bls_threshold_fixture, ed25519_fixture},
            signing_scheme::seed_namespace,
        },
        types::Round,
        Monitor,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{
        bls12381::{
            primitives::variant::{MinPk, MinSig, Variant},
            tle::{decrypt, encrypt, Block},
        },
        ed25519::PrivateKey,
        PrivateKeyExt as _, PublicKey, Sha256, Signer as _,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::simulated::{Config, Link, Network, Oracle, Receiver, Sender};
    use commonware_runtime::{buffer::PoolRef, deterministic, Clock, Metrics, Runner, Spawner};
    use commonware_utils::{quorum, NZUsize, NZU32};
    use engine::Engine;
    use futures::{future::join_all, StreamExt};
    use governor::Quota;
    use rand::{rngs::StdRng, Rng as _, SeedableRng as _};
    use std::{
        collections::HashMap,
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::{debug, warn};
    use types::Activity;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    type Fixture<S> = (
        Vec<PrivateKey>,
        Vec<<PrivateKey as commonware_cryptography::Signer>::PublicKey>,
        Vec<S>,
    );

    /// Registers all validators using the oracle.
    async fn register_validators<P: PublicKey>(
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
    async fn link_validators<P: PublicKey>(
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

    fn all_online<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n);
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
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            let latest_complete = required_containers - activity_timeout;
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure seeds for all views
                {
                    let seeds = reporter.seeds.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure seed for every view
                        if !seeds.contains_key(&view) {
                            panic!("view: {view}");
                        }
                    }
                }

                // Ensure no forks
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = reporter.notarizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        if notarizers.len() < quorum as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {view}");
                        }
                    }
                }
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
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
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for view in 1..latest_complete {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, finalizers) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
                        }

                        // Ensure everyone participating
                        if finalizers.len() < quorum as usize {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {view}");
                        }

                        // Ensure no nullifies for any finalizers
                        let nullifies = reporter.nullifies.lock().unwrap();
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
                    let finalizations = reporter.finalizations.lock().unwrap();
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
        all_online(bls_threshold_fixture::<MinPk, _>);
        all_online(bls_threshold_fixture::<MinSig, _>);
        all_online(ed25519_fixture);
    }

    fn observer<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n_active = 5;
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
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register participants (active)
            let (mut schemes, validators, signing_schemes) = fixture(&mut context, n_active);

            let observer_signing_scheme = signing_schemes[0].clone().into_verifier();

            // Add observer (no share)
            let scheme_observer = PrivateKey::from_seed(n_active as u64);
            let pk_observer = scheme_observer.public_key();
            schemes.push(scheme_observer);

            // Register all (including observer) with the network
            let mut all_validators = validators.clone();
            all_validators.push(pk_observer.clone());
            all_validators.sort();
            let mut registrations = register_validators(&mut oracle, &all_validators).await;

            // Link all peers (including observer)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &all_validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();

            for (idx, scheme) in schemes.into_iter().enumerate() {
                let is_observer = scheme.public_key() == pk_observer;

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let signing = if is_observer {
                    observer_signing_scheme.clone()
                } else {
                    signing_schemes[idx].clone()
                };
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing.clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    crypto: scheme,
                    blocker,
                    participants: validators.clone(),
                    signing: signing.clone(),
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }

            // Wait for all  engines to finish
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

            // Sanity check
            for reporter in reporters.iter() {
                // Ensure no faults or invalid signatures
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());
            }
        });
    }

    #[test_traced]
    fn test_observer() {
        observer(bls_threshold_fixture::<MinPk, _>);
        observer(bls_threshold_fixture::<MinSig, _>);
        observer(ed25519_fixture);
    }

    fn unclean_shutdown<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut StdRng, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let required_containers = 100;
        let activity_timeout = 10;
        let skip_timeout = 5;
        let namespace = b"consensus".to_vec();

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let mut prev_checkpoint = None;

        // Create validator keys
        let mut rng = StdRng::seed_from_u64(0);
        let (schemes, validators, signing_schemes) = fixture(&mut rng, n);

        loop {
            let rng = rng.clone();
            let schemes = schemes.clone();
            let validators = validators.clone();
            let signing_schemes = signing_schemes.clone();
            let namespace = namespace.clone();
            let shutdowns = shutdowns.clone();
            let supervised = supervised.clone();

            let f = |mut context: deterministic::Context| async move {
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    Config {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                    },
                );

                // Start network
                network.start();

                // Register participants
                let mut registrations = register_validators(&mut oracle, &validators).await;

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &validators, Action::Link(link), None).await;

                // Create engines
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut reporters = HashMap::new();
                let mut engine_handlers = Vec::new();
                for (idx, scheme) in schemes.into_iter().enumerate() {
                    // Create scheme context
                    let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                    // Configure engine
                    let validator = scheme.public_key();
                    let reporter_config = mocks::reporter::Config {
                        namespace: namespace.clone(),
                        participants: validators.clone(),
                        signing: signing_schemes[idx].clone(),
                    };
                    let reporter = mocks::reporter::Reporter::new(rng.clone(), reporter_config);
                    reporters.insert(validator.clone(), reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
                for (_, reporter) in reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
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
                        // Collect reporters to check faults
                        {
                            let mut shutdowns = shutdowns.lock().unwrap();
                            debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                            *shutdowns += 1;
                        }
                        supervised.lock().unwrap().push(reporters);
                        false
                    },
                    _ = join_all(finalizers) => {
                        // Check reporters for faults activity
                        let supervised = supervised.lock().unwrap();
                        for reporters in supervised.iter() {
                            for (_, reporter) in reporters.iter() {
                                let faults = reporter.faults.lock().unwrap();
                                assert!(faults.is_empty());
                            }
                        }
                        true
                    }
                };

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());

                result
            };

            let (complete, checkpoint) = if let Some(prev_checkpoint) = prev_checkpoint {
                deterministic::Runner::from(prev_checkpoint)
            } else {
                deterministic::Runner::timed(Duration::from_secs(60))
            }
            .start_and_recover(f);

            // Check if we should exit
            if complete {
                break;
            }

            prev_checkpoint = Some(checkpoint);
        }
    }

    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown(bls_threshold_fixture::<MinPk, _>);
        unclean_shutdown(bls_threshold_fixture::<MinSig, _>);
        unclean_shutdown(ed25519_fixture);
    }

    fn backfill<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
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
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Degrade network connections for online peers
            let link = Link {
                latency: Duration::from_secs(3),
                jitter: Duration::from_millis(0),
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
            let context = context.with_label(&format!("validator-{validator}"));

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
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(3),
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
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: validators.clone(),
                signing: signing_schemes[0].clone(),
            };
            let mut reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            reporters.push(reporter.clone());
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
                participants: validators.clone(),
                signing: signing_schemes[0].clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: 333,
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
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&validator)
                .expect("validator should be registered");
            engine_handlers.push(engine.start(pending, recovered, resolver));

            // Wait for new engine to finalize required
            let (mut latest, mut monitor) = reporter.subscribe().await;
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
        backfill(bls_threshold_fixture::<MinPk, _>);
        backfill(bls_threshold_fixture::<MinSig, _>);
        backfill(ed25519_fixture);
    }

    fn one_offline<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n);
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
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators except first
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(
                &mut oracle,
                &validators,
                Action::Link(link),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
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
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            let exceptions = 0;
            let offline = &validators[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure offline node is never active
                let mut exceptions = 0;
                {
                    let notarizes = reporter.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(offline) {
                                panic!("view: {view}");
                            }
                        }
                    }
                }
                {
                    let nullifies = reporter.nullifies.lock().unwrap();
                    for (view, participants) in nullifies.iter() {
                        if participants.contains(offline) {
                            panic!("view: {view}");
                        }
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(offline) {
                                panic!("view: {view}");
                            }
                        }
                    }
                }

                // Identify offline views
                let mut offline_views = Vec::new();
                {
                    let leaders = reporter.leaders.lock().unwrap();
                    for (view, leader) in leaders.iter() {
                        if leader == offline {
                            offline_views.push(*view);
                        }
                    }
                }
                assert!(!offline_views.is_empty());

                // Ensure nullifies/nullification collected for offline node
                {
                    let nullifies = reporter.nullifies.lock().unwrap();
                    for view in offline_views.iter() {
                        let nullifies = nullifies.get(view).map_or(0, |n| n.len());
                        if nullifies < quorum as usize {
                            warn!("missing expected view nullifies: {}", view);
                            exceptions += 1;
                        }
                    }
                }
                {
                    let nullifications = reporter.nullifications.lock().unwrap();
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
        one_offline(bls_threshold_fixture::<MinPk, _>);
        one_offline(bls_threshold_fixture::<MinSig, _>);
        one_offline(ed25519_fixture);
    }

    fn slow_validator<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
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
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            let slow = &validators[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure slow node never emits a notarize or finalize (will never finish verification in a timely manner)
                {
                    let notarizes = reporter.notarizes.lock().unwrap();
                    for (view, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(slow) {
                                panic!("view: {view}");
                            }
                        }
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for (view, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(slow) {
                                panic!("view: {view}");
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
        slow_validator(bls_threshold_fixture::<MinPk, _>);
        slow_validator(bls_threshold_fixture::<MinSig, _>);
        slow_validator(ed25519_fixture);
    }

    fn all_recovery<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_secs(3),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            for reporter in reporters.iter_mut() {
                let (_, mut monitor) = reporter.subscribe().await;
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
            for reporter in reporters.iter() {
                let nullifies = reporter.nullifies.lock().unwrap();
                let max = nullifies.keys().max().unwrap();
                if *max > latest {
                    latest = *max;
                }
            }

            // Update links
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

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
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }

                // Ensure quick recovery.
                //
                // If the skip timeout isn't implemented correctly, we may go many views before participants
                // start to consider a validator's proposal.
                {
                    // Ensure nearly all views around latest finalize
                    let mut found = 0;
                    let finalizations = reporter.finalizations.lock().unwrap();
                    for i in latest..latest + activity_timeout {
                        if finalizations.contains_key(&i) {
                            found += 1;
                        }
                    }
                    assert!(found >= activity_timeout - 2, "found: {found}");
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        all_recovery(bls_threshold_fixture::<MinPk, _>);
        all_recovery(bls_threshold_fixture::<MinSig, _>);
        all_recovery(ed25519_fixture);
    }

    fn partition<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 10;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link.clone()), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
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
            for reporter in reporters.iter_mut() {
                let (_, mut monitor) = reporter.subscribe().await;
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
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                let required = latest + required_containers;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check reporters for correct activity
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
        partition(bls_threshold_fixture::<MinPk, _>);
        partition(bls_threshold_fixture::<MinSig, _>);
        partition(ed25519_fixture);
    }

    fn slow_and_lossy_links<S, F>(seed: u64, mut fixture: F) -> String
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let degraded_link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.5,
            };
            link_validators(&mut oracle, &validators, Action::Link(degraded_link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
        slow_and_lossy_links(0, bls_threshold_fixture::<MinPk, _>);
        slow_and_lossy_links(0, bls_threshold_fixture::<MinSig, _>);
        slow_and_lossy_links(0, ed25519_fixture);
    }

    #[test_traced]
    #[ignore]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            let pk_state_1 = slow_and_lossy_links(seed, bls_threshold_fixture::<MinPk, _>);
            let pk_state_2 = slow_and_lossy_links(seed, bls_threshold_fixture::<MinPk, _>);
            assert_eq!(pk_state_1, pk_state_2);

            let sig_state_1 = slow_and_lossy_links(seed, bls_threshold_fixture::<MinSig, _>);
            let sig_state_2 = slow_and_lossy_links(seed, bls_threshold_fixture::<MinSig, _>);
            assert_eq!(sig_state_1, sig_state_2);

            let ed_state_1 = slow_and_lossy_links(seed, ed25519_fixture);
            let ed_state_2 = slow_and_lossy_links(seed, ed25519_fixture);
            assert_eq!(ed_state_1, ed_state_2);

            // Sanity check that different types can't be identical
            assert_ne!(pk_state_1, sig_state_1);
            assert_ne!(pk_state_1, ed_state_1);
            assert_ne!(sig_state_1, ed_state_1);
        }
    }

    fn conflicter<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        namespace: namespace.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                    };

                    let engine: mocks::conflicter::Conflicter<_, _, Sha256> =
                        mocks::conflicter::Conflicter::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            let byz = &validators[0];
            let mut count_conflicting = 0;
            for reporter in reporters.iter() {
                // Ensure only faults for byz
                {
                    let faults = reporter.faults.lock().unwrap();
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
                                _ => panic!("unexpected fault: {fault:?}"),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
            conflicter(seed, bls_threshold_fixture::<MinPk, _>);
            conflicter(seed, bls_threshold_fixture::<MinSig, _>);
            conflicter(seed, ed25519_fixture);
        }
    }

    fn invalid<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::invalid::Config {
                        signing: signing_schemes[idx_scheme].clone(),
                        namespace: namespace.clone(),
                    };

                    let engine: mocks::invalid::Invalid<_, _, Sha256> =
                        mocks::invalid::Invalid::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            let mut invalid_count = 0;
            let byz = &validators[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Count invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
            invalid(seed, bls_threshold_fixture::<MinPk, _>);
            invalid(seed, bls_threshold_fixture::<MinSig, _>);
            invalid(seed, ed25519_fixture);
        }
    }

    fn impersonator<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::impersonator::Config {
                        signing: signing_schemes[idx_scheme].clone(),
                        namespace: namespace.clone(),
                    };

                    let engine: mocks::impersonator::Impersonator<_, _, Sha256> =
                        mocks::impersonator::Impersonator::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            let byz = &validators[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
            impersonator(seed, bls_threshold_fixture::<MinPk, _>);
            impersonator(seed, bls_threshold_fixture::<MinSig, _>);
            impersonator(seed, ed25519_fixture);
        }
    }

    fn reconfigurer<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::reconfigurer::Config {
                        signing: signing_schemes[idx_scheme].clone(),
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::reconfigurer::Reconfigurer<_, _, Sha256> =
                        mocks::reconfigurer::Reconfigurer::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            let byz = &validators[0];
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }

            // Ensure reconfigurer is blocked (epoch mismatch)
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
    fn test_reconfigurer() {
        for seed in 0..5 {
            reconfigurer(seed, bls_threshold_fixture::<MinPk, _>);
            reconfigurer(seed, bls_threshold_fixture::<MinSig, _>);
            reconfigurer(seed, ed25519_fixture);
        }
    }

    fn nuller<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        namespace: namespace.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, _, Sha256> =
                        mocks::nuller::Nuller::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            let byz = &validators[0];
            let mut count_nullify_and_finalize = 0;
            for reporter in reporters.iter() {
                // Ensure only faults for byz
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert_eq!(faults.len(), 1);
                    let faulter = faults.get(byz).expect("byzantine party is not faulter");
                    for (_, faults) in faulter.iter() {
                        for fault in faults.iter() {
                            match fault {
                                Activity::NullifyFinalize(_) => {
                                    count_nullify_and_finalize += 1;
                                }
                                _ => panic!("unexpected fault: {fault:?}"),
                            }
                        }
                    }
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
            nuller(seed, bls_threshold_fixture::<MinPk, _>);
            nuller(seed, bls_threshold_fixture::<MinSig, _>);
            nuller(seed, ed25519_fixture);
        }
    }

    fn outdated<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Start engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::outdated::Config {
                        signing: signing_schemes[idx_scheme].clone(),
                        namespace: namespace.clone(),
                        view_delta: activity_timeout * 4,
                    };
                    let engine: mocks::outdated::Outdated<_, _, Sha256> =
                        mocks::outdated::Outdated::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
                } else {
                    reporters.push(reporter.clone());
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
                        participants: validators.clone(),
                        signing: signing_schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: 333,
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
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine.start(pending, recovered, resolver);
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
            for reporter in reporters.iter() {
                // Ensure no faults
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
            outdated(seed, bls_threshold_fixture::<MinPk, _>);
            outdated(seed, bls_threshold_fixture::<MinSig, _>);
            outdated(seed, ed25519_fixture);
        }
    }

    fn run_1k<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 10;
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
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
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
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
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
        run_1k(bls_threshold_fixture::<MinPk, _>);
        run_1k(bls_threshold_fixture::<MinSig, _>);
        run_1k(ed25519_fixture);
    }

    fn children_shutdown_on_engine_abort<S, F>(mut fixture: F)
    where
        S: Scheme,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 1;
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                },
            );

            // Start network
            network.start();

            // Register a single participant
            let (schemes, validators, signing_schemes) = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link the single validator to itself (no-ops for completeness)
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engine
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: validators.clone(),
                signing: signing_schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                participant: validators[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let blocker = oracle.control(validators[0].clone());
            let cfg = config::Config {
                crypto: schemes[0].clone(),
                participants: validators.clone(),
                signing: signing_schemes[0].clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validators[0].to_string(),
                mailbox_size: 64,
                epoch: 333,
                namespace: namespace.clone(),
                leader_timeout: Duration::from_millis(50),
                notarization_timeout: Duration::from_millis(100),
                nullify_retry: Duration::from_millis(250),
                fetch_timeout: Duration::from_millis(50),
                activity_timeout: 4,
                skip_timeout: 2,
                max_fetch_count: 1,
                fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 16),
                write_buffer: NZUsize!(1024 * 16),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&validators[0])
                .expect("validator should be registered");
            let handle = engine.start(pending, recovered, resolver);

            // Allow tasks to start
            context.sleep(Duration::from_millis(1000)).await;

            // Verify that engine and child actors are running
            let metrics_before = context.encode();
            let is_running = |name: &str| -> bool {
                metrics_before.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{}\"", name))
                        && line.contains("kind=\"Task\"")
                        && line.trim_end().ends_with(" 1")
                })
            };
            assert!(is_running("engine"));
            assert!(is_running("engine_batcher"));
            assert!(is_running("engine_voter"));
            assert!(is_running("engine_resolver"));

            // Make sure the engine is still running
            context.sleep(Duration::from_millis(1000)).await;
            assert!(is_running("engine"));

            // Abort engine and ensure children stop
            handle.abort();
            let _ = handle.await; // ensure parent tear-down runs

            // Give the runtime a tick to process aborts
            context.sleep(Duration::from_millis(1000)).await;

            let metrics_after = context.encode();
            let is_stopped = |name: &str| -> bool {
                // Either the gauge is 0, or the entry is absent (both imply not running)
                metrics_after.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{}\"", name))
                        && line.contains("kind=\"Task\"")
                        && line.trim_end().ends_with(" 0")
                })
            };
            assert!(is_stopped("engine"));
            assert!(is_stopped("engine_batcher"));
            assert!(is_stopped("engine_voter"));
            assert!(is_stopped("engine_resolver"));
        });
    }

    #[test_traced]
    fn test_children_shutdown_on_engine_abort() {
        children_shutdown_on_engine_abort(bls_threshold_fixture::<MinPk, _>);
        children_shutdown_on_engine_abort(bls_threshold_fixture::<MinSig, _>);
        children_shutdown_on_engine_abort(ed25519_fixture);
    }

    fn tle<V: Variant>() {
        // Create context
        let n = 4;
        let namespace = b"consensus".to_vec();
        let activity_timeout = 100;
        let skip_timeout = 50;
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                },
            );

            // Start network
            network.start();

            // Register participants
            let (schemes, validators, signing_schemes) =
                bls_threshold_fixture::<V, _>(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &validators).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &validators, Action::Link(link), None).await;

            // Create engines and reporters
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            let monitor_reporter = Arc::new(Mutex::new(None));
            for (idx, scheme) in schemes.into_iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", scheme.public_key()));

                // Configure engine
                let validator = scheme.public_key();

                // Store first reporter for monitoring
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                if idx == 0 {
                    *monitor_reporter.lock().unwrap() = Some(reporter.clone());
                }

                // Configure application
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
                    participants: validators.clone(),
                    signing: signing_schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: 333,
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_millis(100),
                    notarization_timeout: Duration::from_millis(200),
                    nullify_retry: Duration::from_millis(500),
                    fetch_timeout: Duration::from_millis(100),
                    activity_timeout,
                    skip_timeout,
                    max_fetch_count: 1,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
                    fetch_concurrent: 1,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(&validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Prepare TLE test data
            let target = Round::new(333, 10); // Encrypt for view 10
            let message_content = b"Secret message for future view10"; // 32 bytes
            let message = Block::new(*message_content);

            // Encrypt message for future view using threshold public key
            let seed_namespace = seed_namespace(&namespace);
            let ciphertext = encrypt::<_, V>(
                &mut context,
                *signing_schemes[0].identity(),
                (Some(&seed_namespace), &target.encode()),
                &message,
            );

            // Wait for consensus to reach the target view and then decrypt
            let reporter = monitor_reporter.lock().unwrap().clone().unwrap();
            loop {
                // Wait for notarization
                context.sleep(Duration::from_millis(100)).await;
                let notarizations = reporter.notarizations.lock().unwrap();
                let Some(notarization) = notarizations.get(&target.view()) else {
                    continue;
                };

                // Decrypt the message using the seed signature
                let seed_signature = notarization.certificate.seed_signature;
                let decrypted = decrypt::<V>(&seed_signature, &ciphertext)
                    .expect("Decryption should succeed with valid seed signature");
                assert_eq!(
                    message.as_ref(),
                    decrypted.as_ref(),
                    "Decrypted message should match original message"
                );
                break;
            }
        });
    }

    #[test_traced]
    fn test_tle() {
        tle::<MinPk>();
        tle::<MinSig>();
    }
}
