//! Simple and fast BFT agreement inspired by Simplex Consensus.
//!
//! Inspired by [Simplex Consensus](https://eprint.iacr.org/2023/463), `simplex` provides simple and fast BFT
//! agreement with network-speed view (i.e. block time) latency and optimal finalization latency in a
//! partially synchronous setting.
//!
//! # Features
//!
//! * Wicked Fast Block Times (2 Network Hops)
//! * Optimal Finalization Latency (3 Network Hops)
//! * Externalized Uptime and Fault Proofs
//! * Decoupled Block Broadcast and Sync
//! * Lazy Message Verification
//! * Application-Defined Block Format
//! * Pluggable Hashing and Cryptography
//! * Embedded VRF (via [scheme::bls12381_threshold])
//!
//! # Design
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
//! _When `2f+1` votes of a given type (`notarize(c,v)`, `nullify(v)`, or `finalize(c,v)`) have been have been collected
//! from unique participants, a certificate (`notarization(c,v)`, `nullification(v)`, or `finalization(c,v)`) can be assembled.
//! These certificates serve as a standalone proof of consensus progress that downstream systems can ingest without executing
//! the protocol._
//!
//! ### Joining Consensus
//!
//! As soon as `2f+1` notarizes, nullifies, or finalizes are observed for some view `v`, the `Voter` will
//! enter `v+1`. This means that a new participant joining consensus will immediately jump ahead to the
//! latest view and begin participating in consensus (assuming it can verify blocks).
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
//!
//! ## Architecture
//!
//! All logic is split into four components: the `Batcher`, the `Voter`, the `Resolver`, and the `Application` (provided by the user).
//! The `Batcher` is responsible for collecting messages from peers and lazily verifying them when a quorum is met. The `Voter`
//! is responsible for directing participation in the current view. The `Resolver` is responsible for
//! fetching artifacts from previous views required to verify proposed blocks in the latest view. Lastly, the `Application`
//! is responsible for proposing new blocks and indicating whether some block is valid.
//!
//! To drive great performance, all interactions between `Batcher`, `Voter`, `Resolver`, and `Application` are
//! non-blocking. This means that, for example, the `Voter` can continue processing messages while the
//! `Application` verifies a proposed block or the `Resolver` fetches a notarization.
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
//! ### Batched Verification
//!
//! Unlike other consensus constructions that verify all incoming messages received from peers, `simplex`
//! lazily verifies messages (only when a quorum is met). If an invalid signature is detected, the `Batcher`
//! will perform repeated bisections over collected messages to find the offending message (and block the
//! peer(s) that sent it via [commonware_p2p::Blocker]).
//!
//! _If using a p2p implementation that is not authenticated, it is not safe to employ this optimization
//! as any attacking peer could simply reconnect from a different address. We recommend [commonware_p2p::authenticated]._
//!
//! ### Fetching Missing Certificates
//!
//! Instead of trying to fetch all possible certificates above the last finalized view, we only attempt to fetch
//! nullifications for all views from the last notarized/finalized view to the current view. This technique, however,
//! is not sufficient to guarantee progress.
//!
//! Consider the case where `f` honest participants have seen a notarization for a given view `v` (and nullifications only
//! from `v` to the current view `c`) but the remaining `f+1` honest participants have not (they have exclusively seen
//! nullifications from some view `o < v` to `c`). Neither partition of participants will vote for the other's proposals.
//!
//! To ensure progress is eventually made, leaders with nullified proposals broadcast the best notarization/finalization
//! certificate they are aware of to ensure all honest participants eventually consider the same proposal ancestry valid.
//!
//! _While a more aggressive recovery mechanism could be employed, like requiring all participants to broadcast their highest
//! notarization/finalization certificate after nullification, it would impose significant overhead under normal network
//! conditions (whereas the approach described incurs no overhead under normal network conditions). Recall, honest participants
//! already broadcast observed certificates to all other participants in each view (and misaligned participants should only ever
//! be observed following severe network degradation)._
//!
//! ## Pluggable Hashing and Cryptography
//!
//! Hashing is abstracted via the [commonware_cryptography::Hasher] trait and cryptography is abstracted via
//! the [commonware_cryptography::certificate::Scheme] trait, allowing deployments to employ approaches that best match their
//! requirements (or to provide their own without modifying any consensus logic). The following schemes
//! are supported out-of-the-box:
//!
//! ### [scheme::ed25519]
//!
//! [commonware_cryptography::ed25519] signatures are ["High-speed high-security signatures"](https://eprint.iacr.org/2011/368)
//! with 32 byte public keys and 64 byte signatures. While they are well-supported by commercial HSMs and offer efficient batch
//! verification, the signatures are not aggregatable (and certificates grow linearly with the quorum size).
//!
//! ### [scheme::bls12381_multisig]
//!
//! [commonware_cryptography::bls12381] is a ["digital signature scheme with aggregation properties"](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.txt).
//! Unlike [commonware_cryptography::ed25519], signatures from multiple participants (say the signers in a certificate) can be aggregated
//! into a single signature (reducing bandwidth usage per broadcast). That being said, [commonware_cryptography::bls12381] is much slower
//! to verify than [commonware_cryptography::ed25519] and isn't supported by most HSMs (a standardization effort expired in 2022).
//!
//! ### [scheme::bls12381_threshold]
//!
//! Last but not least, [scheme::bls12381_threshold]  employs threshold cryptography (specifically BLS12-381 threshold signatures
//! with a `2f+1` of `3f+1` quorum) to generate both a bias-resistant beacon (for leader election and post-facto execution randomness)
//! and succinct consensus certificates (any certificate can be verified with just the static public key of the consensus instance) for each view
//! with zero message overhead (natively integrated). While powerful, this scheme requires both instantiating the shared secret
//! via [commonware_cryptography::bls12381::dkg] and performing a resharing procedure whenever participants are added or removed.
//!
//! #### Embedded VRF
//!
//! Every `notarize(c,v)` or `nullify(v)` message includes an `attestation(v)` (a partial signature over the view `v`). After `2f+1`
//! `notarize(c,v)` or `nullify(v)` messages are collected from unique participants, `seed(v)` can be recovered. Because `attestation(v)` is
//! only over the view `v`, the seed derived for a given view `v` is the same regardless of whether or not a block was notarized in said
//! view `v`.
//!
//! Because the value of `seed(v)` cannot be known prior to message broadcast by any participant (including the leader) in view `v`
//! and cannot be manipulated by any participant (deterministic for any `2f+1` signers at a given view `v`), it can be used both as a beacon
//! for leader election (where `seed(v)` determines the leader for `v+1`) and a source of randomness in execution (where `seed(v)`
//! is used as a seed in `v`).
//!
//! #### Succinct Certificates
//!
//! All broadcast consensus messages (`notarize(c,v)`, `nullify(v)`, `finalize(c,v)`) contain attestations (partial signatures) for a static
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
//! ## Persistence
//!
//! The `Voter` caches all data required to participate in consensus to avoid any disk reads on
//! on the critical path. To enable recovery, the `Voter` writes valid messages it receives from
//! consensus and messages it generates to a write-ahead log (WAL) implemented by [commonware_storage::journal::segmented::variable::Journal].
//! Before sending a message, the `Journal` sync is invoked to prevent inadvertent Byzantine behavior
//! on restart (especially in the case of unclean shutdown).

pub mod scheme;
pub mod types;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        mod actors;
        pub mod config;
        pub use config::Config;
        mod engine;
        pub use engine::Engine;
        mod metrics;
    }
}

#[cfg(any(test, feature = "fuzz"))]
pub mod mocks;

use crate::types::{Round, View, ViewDelta};
use commonware_codec::Encode;
use scheme::SeededScheme;

/// The minimum view we are tracking both in-memory and on-disk.
pub(crate) const fn min_active(activity_timeout: ViewDelta, last_finalized: View) -> View {
    last_finalized.saturating_sub(activity_timeout)
}

/// Whether or not a view is interesting to us. This is a function
/// of both `min_active` and whether or not the view is too far
/// in the future (based on the view we are currently in).
pub(crate) fn interesting(
    activity_timeout: ViewDelta,
    last_finalized: View,
    current: View,
    pending: View,
    allow_future: bool,
) -> bool {
    if pending < min_active(activity_timeout, last_finalized) {
        return false;
    }
    if !allow_future && pending > current.next() {
        return false;
    }
    true
}

/// Selects the leader for a given round using scheme-provided randomness seed when available.
///
/// If the active [`SeededScheme`] exposes a seed (e.g. BLS threshold certificates), the seed is
/// encoded and reduced modulo the number of participants. Otherwise we fall back to
/// simple round-robin using the view number.
///
/// # Panics
///
/// Panics if `participants` is empty.
pub fn select_leader<S>(
    participants: &[S::PublicKey],
    round: Round,
    seed: Option<S::Seed>,
) -> (S::PublicKey, u32)
where
    S: SeededScheme,
    S::PublicKey: Clone,
{
    assert!(
        !participants.is_empty(),
        "no participants to select leader from"
    );
    let idx = seed.map_or_else(
        || (round.epoch().get().wrapping_add(round.view().get()) as usize) % participants.len(),
        |seed| commonware_utils::modulo(seed.encode().as_ref(), participants.len() as u64) as usize,
    );
    let leader = participants[idx].clone();

    (leader, idx as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::twins::Strategy,
            scheme::{
                bls12381_multisig, bls12381_threshold, bls12381_threshold::Seedable, ed25519,
                Scheme,
            },
            types::{
                Certificate, Finalization as TFinalization, Finalize as TFinalize,
                Notarization as TNotarization, Notarize as TNotarize,
                Nullification as TNullification, Nullify as TNullify, Proposal, Vote,
            },
        },
        types::{Epoch, Round},
        Monitor, Viewable,
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig, Variant},
        certificate::mocks::Fixture,
        ed25519::{PrivateKey, PublicKey},
        sha256::{Digest as Sha256Digest, Digest as D},
        Hasher as _, Sha256, Signer as _,
    };
    use commonware_macros::{select, test_group, test_traced};
    use commonware_p2p::{
        simulated::{Config, Link, Network, Oracle, Receiver, Sender, SplitOrigin, SplitTarget},
        Recipients, Sender as _,
    };
    use commonware_runtime::{
        buffer::PoolRef, deterministic, Clock, Metrics, Quota, Runner, Spawner,
    };
    use commonware_utils::{max_faults, quorum, NZUsize, NZU32};
    use engine::Engine;
    use futures::{future::join_all, StreamExt};
    use rand::{rngs::StdRng, Rng as _, SeedableRng as _};
    use std::{
        collections::{BTreeMap, HashMap},
        num::{NonZeroU32, NonZeroUsize},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tracing::{debug, info, warn};
    use types::Activity;

    const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// Register a validator with the oracle.
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

    fn all_online<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n) as usize;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
            let latest_complete = required_containers.saturating_sub(activity_timeout);
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
                    for view in View::range(View::new(1), latest_complete) {
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
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, notarizers) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);

                        if notarizers.len() < quorum {
                            // We can't verify that everyone participated at every view because some nodes may
                            // have started later.
                            panic!("view: {view}");
                        }
                    }
                }
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
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
                {
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for view in View::range(View::new(1), latest_complete) {
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
                        if finalizers.len() < quorum {
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
                    for view in View::range(View::new(1), latest_complete) {
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
        all_online(bls12381_threshold::fixture::<MinPk, _>);
        all_online(bls12381_threshold::fixture::<MinSig, _>);
        all_online(bls12381_multisig::fixture::<MinPk, _>);
        all_online(bls12381_multisig::fixture::<MinSig, _>);
        all_online(ed25519::fixture);
    }

    fn observer<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n_active = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
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

            // Register participants (active)
            let Fixture {
                participants,
                schemes,
                verifier,
                ..
            } = fixture(&mut context, n_active);

            // Add observer (no share)
            let private_key_observer = PrivateKey::from_seed(n_active as u64);
            let public_key_observer = private_key_observer.public_key();

            // Register all (including observer) with the network
            let mut all_validators = participants.clone();
            all_validators.push(public_key_observer.clone());
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

            for (idx, validator) in participants.iter().enumerate() {
                let is_observer = *validator == public_key_observer;

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let signing = if is_observer {
                    verifier.clone()
                } else {
                    schemes[idx].clone()
                };
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: signing.clone(),
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
                    scheme: signing.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
        observer(bls12381_threshold::fixture::<MinPk, _>);
        observer(bls12381_threshold::fixture::<MinSig, _>);
        observer(bls12381_multisig::fixture::<MinPk, _>);
        observer(bls12381_multisig::fixture::<MinSig, _>);
        observer(ed25519::fixture);
    }

    fn unclean_shutdown<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();

        // Random restarts every x seconds
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let supervised = Arc::new(Mutex::new(Vec::new()));
        let mut prev_checkpoint = None;

        // Create validator keys
        let mut rng = StdRng::seed_from_u64(0);
        let Fixture {
            participants,
            schemes,
            ..
        } = fixture(&mut rng, n);

        loop {
            let rng = rng.clone();
            let participants = participants.clone();
            let schemes = schemes.clone();
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
                        tracked_peer_sets: None,
                    },
                );

                // Start network
                network.start();

                // Register participants
                let mut registrations = register_validators(&mut oracle, &participants).await;

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &participants, Action::Link(link), None).await;

                // Create engines
                let relay = Arc::new(mocks::relay::Relay::new());
                let mut reporters = HashMap::new();
                let mut engine_handlers = Vec::new();
                for (idx, validator) in participants.iter().enumerate() {
                    // Create scheme context
                    let context = context.with_label(&format!("validator-{}", *validator));

                    // Configure engine
                    let reporter_config = mocks::reporter::Config {
                        namespace: namespace.clone(),
                        participants: participants.clone().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                    };
                    let reporter = mocks::reporter::Reporter::new(rng.clone(), reporter_config);
                    reporters.insert(validator.clone(), reporter.clone());
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
                        scheme: schemes[idx].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);

                    // Start engine
                    let (pending, recovered, resolver) = registrations
                        .remove(validator)
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
                    context.gen_range(Duration::from_millis(100)..Duration::from_millis(2_000));
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

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || deterministic::Runner::timed(Duration::from_secs(180)),
                    deterministic::Runner::from,
                )
                .start_and_recover(f);

            // Check if we should exit
            if complete {
                break;
            }

            prev_checkpoint = Some(checkpoint);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_unclean_shutdown() {
        unclean_shutdown(bls12381_threshold::fixture::<MinPk, _>);
        unclean_shutdown(bls12381_threshold::fixture::<MinSig, _>);
        unclean_shutdown(bls12381_multisig::fixture::<MinPk, _>);
        unclean_shutdown(bls12381_multisig::fixture::<MinSig, _>);
        unclean_shutdown(ed25519::fixture);
    }

    fn backfill<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(720));
        executor.start(|mut context| async move {
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

            // Link all validators except first
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

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
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
                    scheme: schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(4)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
                &participants,
                Action::Update(link.clone()),
                Some(|_, i, j| ![i, j].contains(&0usize)),
            )
            .await;

            // Wait for nullifications to accrue
            context.sleep(Duration::from_secs(120)).await;

            // Unlink second peer from all (except first)
            link_validators(
                &mut oracle,
                &participants,
                Action::Unlink,
                Some(|_, i, j| [i, j].contains(&1usize) && ![i, j].contains(&0usize)),
            )
            .await;

            // Configure engine for first peer
            let me = participants[0].clone();
            let context = context.with_label(&format!("validator-{me}"));

            // Link first peer to all (except second)
            link_validators(
                &mut oracle,
                &participants,
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
                &participants,
                Action::Update(link),
                Some(|_, i, j| ![i, j].contains(&1usize)),
            )
            .await;

            // Configure engine
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
            };
            let mut reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            reporters.push(reporter.clone());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: me.clone(),
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let blocker = oracle.control(me.clone());
            let cfg = config::Config {
                scheme: schemes[0].clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: me.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 4,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&me)
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
        backfill(bls12381_threshold::fixture::<MinPk, _>);
        backfill(bls12381_threshold::fixture::<MinSig, _>);
        backfill(bls12381_multisig::fixture::<MinPk, _>);
        backfill(bls12381_multisig::fixture::<MinSig, _>);
        backfill(ed25519::fixture);
    }

    fn one_offline<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let quorum = quorum(n) as usize;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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

            // Link all validators except first
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

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Skip first peer
                if idx_scheme == 0 {
                    continue;
                }

                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
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
                    scheme: schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
            let offline = &participants[0];
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
                        if nullifies < quorum {
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
                n - 1,
                "expected all online nodes to be skipping views"
            );
        });
    }

    #[test_traced]
    fn test_one_offline() {
        one_offline(bls12381_threshold::fixture::<MinPk, _>);
        one_offline(bls12381_threshold::fixture::<MinSig, _>);
        one_offline(bls12381_multisig::fixture::<MinPk, _>);
        one_offline(bls12381_multisig::fixture::<MinSig, _>);
        one_offline(ed25519::fixture);
    }

    fn slow_validator<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = if idx_scheme == 0 {
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
                    scheme: schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
            let slow = &participants[0];
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

                // Ensure slow node still emits notarizes and finalizes (when receiving certificates)
                let mut observed = false;
                {
                    let notarizes = reporter.notarizes.lock().unwrap();
                    for (_, payloads) in notarizes.iter() {
                        for (_, participants) in payloads.iter() {
                            if participants.contains(slow) {
                                observed = true;
                                break;
                            }
                        }
                    }
                }
                {
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for (_, payloads) in finalizes.iter() {
                        for (_, finalizers) in payloads.iter() {
                            if finalizers.contains(slow) {
                                observed = true;
                                break;
                            }
                        }
                    }
                }
                assert!(observed);
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_slow_validator() {
        slow_validator(bls12381_threshold::fixture::<MinPk, _>);
        slow_validator(bls12381_threshold::fixture::<MinSig, _>);
        slow_validator(bls12381_multisig::fixture::<MinPk, _>);
        slow_validator(bls12381_multisig::fixture::<MinSig, _>);
        slow_validator(ed25519::fixture);
    }

    fn all_recovery<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(2);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(180));
        executor.start(|mut context| async move {
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
                latency: Duration::from_secs(3),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
            link_validators(&mut oracle, &participants, Action::Unlink, None).await;

            // Wait for a virtual minute (nothing should happen)
            context.sleep(Duration::from_secs(60)).await;

            // Get latest view
            let mut latest = View::zero();
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
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

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
                    for view in View::range(latest, latest.saturating_add(activity_timeout)) {
                        if finalizations.contains_key(&view) {
                            found += 1;
                        }
                    }
                    assert!(
                        found >= activity_timeout.get().saturating_sub(2),
                        "found: {found}"
                    );
                }
            }

            // Ensure no blocked connections
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_all_recovery() {
        all_recovery(bls12381_threshold::fixture::<MinPk, _>);
        all_recovery(bls12381_threshold::fixture::<MinSig, _>);
        all_recovery(bls12381_multisig::fixture::<MinPk, _>);
        all_recovery(bls12381_multisig::fixture::<MinSig, _>);
        all_recovery(ed25519::fixture);
    }

    fn partition<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 10;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(|mut context| async move {
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
            link_validators(&mut oracle, &participants, Action::Link(link.clone()), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
            link_validators(&mut oracle, &participants, Action::Unlink, Some(separated)).await;

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
                &participants,
                Action::Link(link),
                Some(separated),
            )
            .await;

            // Wait for all engines to finish
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                let required = latest.saturating_add(ViewDelta::new(required_containers.get()));
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

    #[test_group("slow")]
    #[test_traced]
    fn test_partition() {
        partition(bls12381_threshold::fixture::<MinPk, _>);
        partition(bls12381_threshold::fixture::<MinSig, _>);
        partition(bls12381_multisig::fixture::<MinPk, _>);
        partition(bls12381_multisig::fixture::<MinSig, _>);
        partition(ed25519::fixture);
    }

    fn slow_and_lossy_links<S, F>(seed: u64, mut fixture: F) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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
        slow_and_lossy_links(0, bls12381_threshold::fixture::<MinPk, _>);
        slow_and_lossy_links(0, bls12381_threshold::fixture::<MinSig, _>);
        slow_and_lossy_links(0, bls12381_multisig::fixture::<MinPk, _>);
        slow_and_lossy_links(0, bls12381_multisig::fixture::<MinSig, _>);
        slow_and_lossy_links(0, ed25519::fixture);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_determinism() {
        // We use slow and lossy links as the deterministic test
        // because it is the most complex test.
        for seed in 1..6 {
            let ts_pk_state_1 = slow_and_lossy_links(seed, bls12381_threshold::fixture::<MinPk, _>);
            let ts_pk_state_2 = slow_and_lossy_links(seed, bls12381_threshold::fixture::<MinPk, _>);
            assert_eq!(ts_pk_state_1, ts_pk_state_2);

            let ts_sig_state_1 =
                slow_and_lossy_links(seed, bls12381_threshold::fixture::<MinSig, _>);
            let ts_sig_state_2 =
                slow_and_lossy_links(seed, bls12381_threshold::fixture::<MinSig, _>);
            assert_eq!(ts_sig_state_1, ts_sig_state_2);

            let ms_pk_state_1 = slow_and_lossy_links(seed, bls12381_multisig::fixture::<MinPk, _>);
            let ms_pk_state_2 = slow_and_lossy_links(seed, bls12381_multisig::fixture::<MinPk, _>);
            assert_eq!(ms_pk_state_1, ms_pk_state_2);

            let ms_sig_state_1 =
                slow_and_lossy_links(seed, bls12381_multisig::fixture::<MinSig, _>);
            let ms_sig_state_2 =
                slow_and_lossy_links(seed, bls12381_multisig::fixture::<MinSig, _>);
            assert_eq!(ms_sig_state_1, ms_sig_state_2);

            let ed_state_1 = slow_and_lossy_links(seed, ed25519::fixture);
            let ed_state_2 = slow_and_lossy_links(seed, ed25519::fixture);
            assert_eq!(ed_state_1, ed_state_2);

            let states = [
                ("threshold-minpk", ts_pk_state_1),
                ("threshold-minsig", ts_sig_state_1),
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

    fn conflicter<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::conflicter::Config {
                        namespace: namespace.clone(),
                        scheme: schemes[idx_scheme].clone(),
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
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
            let byz = &participants[0];
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

    #[test_group("slow")]
    #[test_traced]
    fn test_conflicter() {
        for seed in 0..5 {
            conflicter(seed, bls12381_threshold::fixture::<MinPk, _>);
            conflicter(seed, bls12381_threshold::fixture::<MinSig, _>);
            conflicter(seed, bls12381_multisig::fixture::<MinPk, _>);
            conflicter(seed, bls12381_multisig::fixture::<MinSig, _>);
            conflicter(seed, ed25519::fixture);
        }
    }

    fn invalid<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Byzantine node (idx 0) uses empty namespace to produce invalid signatures
                let engine_namespace = if idx_scheme == 0 {
                    vec![]
                } else {
                    namespace.clone()
                };

                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(), // Reporter always uses correct namespace
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
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
                    scheme: schemes[idx_scheme].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.clone().to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: engine_namespace,
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
            }

            // Wait for honest engines to finish (skip byzantine node at index 0)
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Check honest reporters (reporters[1..]) for correct activity
            let mut invalid_count = 0;
            for reporter in reporters.iter().skip(1) {
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

            // All honest nodes should see invalid signatures from the byzantine node
            assert_eq!(invalid_count, n - 1);

            // Ensure byzantine node is blocked by honest nodes
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                if a != participants[0] {
                    assert_eq!(b, participants[0]);
                }
            }
        });
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_invalid() {
        for seed in 0..5 {
            invalid(seed, bls12381_threshold::fixture::<MinPk, _>);
            invalid(seed, bls12381_threshold::fixture::<MinSig, _>);
            invalid(seed, bls12381_multisig::fixture::<MinPk, _>);
            invalid(seed, bls12381_multisig::fixture::<MinSig, _>);
            invalid(seed, ed25519::fixture);
        }
    }

    fn impersonator<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::impersonator::Config {
                        scheme: schemes[idx_scheme].clone(),
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.clone().to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
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
            let byz = &participants[0];
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

    #[test_group("slow")]
    #[test_traced]
    fn test_impersonator() {
        for seed in 0..5 {
            impersonator(seed, bls12381_threshold::fixture::<MinPk, _>);
            impersonator(seed, bls12381_threshold::fixture::<MinSig, _>);
            impersonator(seed, bls12381_multisig::fixture::<MinPk, _>);
            impersonator(seed, bls12381_multisig::fixture::<MinSig, _>);
            impersonator(seed, ed25519::fixture);
        }
    }

    fn equivocator<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 7;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let mut engines = Vec::new();
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::equivocator::Config {
                        namespace: namespace.clone(),
                        scheme: schemes[idx_scheme].clone(),
                        epoch: Epoch::new(333),
                        relay: relay.clone(),
                        hasher: Sha256::default(),
                    };

                    let engine: mocks::equivocator::Equivocator<_, _, Sha256> =
                        mocks::equivocator::Equivocator::new(
                            context.with_label("byzantine_engine"),
                            cfg,
                        );
                    engines.push(engine.start(pending, recovered));
                } else {
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engines.push(engine.start(pending, recovered, resolver));
                }
            }

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Abort a validator
            let idx = context.gen_range(1..engines.len()); // skip byzantine validator
            let validator = &participants[idx];
            let handle = engines.remove(idx);
            handle.abort();
            let _ = handle.await;
            reporters.remove(idx);
            info!(idx, ?validator, "aborted validator");

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < View::new(required_containers.get() * 2) {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Recreate engine
            info!(idx, ?validator, "restarting validator");
            let context = context.with_label(&format!("validator-{}-restarted", *validator));

            // Start engine
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[idx].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let (pending, recovered, resolver) =
                register_validator(&mut oracle, validator.clone()).await;
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
                scheme: schemes[idx].clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: validator.to_string(),
                mailbox_size: 1024,
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                activity_timeout,
                skip_timeout,
                fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                fetch_concurrent: 4,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);
            engine.start(pending, recovered, resolver);

            // Wait for all engines to hit required containers
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(1) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < View::new(required_containers.get() * 3) {
                        latest = monitor.next().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Ensure equivocator is blocked (we aren't guaranteed a fault will be produced
            // because it may not be possible to extract a conflicting vote from the certificate
            // we receive)
            let byz = &participants[0];
            let blocked = oracle.blocked().await.unwrap();
            assert!(!blocked.is_empty());
            for (a, b) in blocked {
                assert_ne!(&a, byz);
                assert_eq!(&b, byz);
            }
        });
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_equivocator_bls12381_threshold_min_pk() {
        for seed in 0..5 {
            equivocator(seed, bls12381_threshold::fixture::<MinPk, _>);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_equivocator_bls12381_threshold_min_sig() {
        for seed in 0..5 {
            equivocator(seed, bls12381_threshold::fixture::<MinSig, _>);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_equivocator_bls12381_multisig_min_pk() {
        for seed in 0..5 {
            equivocator(seed, bls12381_multisig::fixture::<MinPk, _>);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_equivocator_bls12381_multisig_min_sig() {
        for seed in 0..5 {
            equivocator(seed, bls12381_multisig::fixture::<MinSig, _>);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_equivocator_ed25519() {
        for seed in 0..5 {
            equivocator(seed, ed25519::fixture);
        }
    }

    fn reconfigurer<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::reconfigurer::Config {
                        scheme: schemes[idx_scheme].clone(),
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
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
            let byz = &participants[0];
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

    #[test_group("slow")]
    #[test_traced]
    fn test_reconfigurer() {
        for seed in 0..5 {
            reconfigurer(seed, bls12381_threshold::fixture::<MinPk, _>);
            reconfigurer(seed, bls12381_threshold::fixture::<MinSig, _>);
            reconfigurer(seed, bls12381_multisig::fixture::<MinPk, _>);
            reconfigurer(seed, bls12381_multisig::fixture::<MinSig, _>);
            reconfigurer(seed, ed25519::fixture);
        }
    }

    fn nuller<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::nuller::Config {
                        namespace: namespace.clone(),
                        scheme: schemes[idx_scheme].clone(),
                    };
                    let engine: mocks::nuller::Nuller<_, _, Sha256> =
                        mocks::nuller::Nuller::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.clone().to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
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
            let byz = &participants[0];
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

    #[test_group("slow")]
    #[test_traced]
    fn test_nuller() {
        for seed in 0..5 {
            nuller(seed, bls12381_threshold::fixture::<MinPk, _>);
            nuller(seed, bls12381_threshold::fixture::<MinSig, _>);
            nuller(seed, bls12381_multisig::fixture::<MinPk, _>);
            nuller(seed, bls12381_multisig::fixture::<MinSig, _>);
            nuller(seed, ed25519::fixture);
        }
    }

    fn outdated<S, F>(seed: u64, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 4;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx_scheme, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Start engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx_scheme].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                if idx_scheme == 0 {
                    let cfg = mocks::outdated::Config {
                        scheme: schemes[idx_scheme].clone(),
                        namespace: namespace.clone(),
                        view_delta: ViewDelta::new(activity_timeout.get().saturating_mul(4)),
                    };
                    let engine: mocks::outdated::Outdated<_, _, Sha256> =
                        mocks::outdated::Outdated::new(context.with_label("byzantine_engine"), cfg);
                    engine.start(pending);
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
                        scheme: schemes[idx_scheme].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.clone().to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
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

    #[test_group("slow")]
    #[test_traced]
    fn test_outdated() {
        for seed in 0..5 {
            outdated(seed, bls12381_threshold::fixture::<MinPk, _>);
            outdated(seed, bls12381_threshold::fixture::<MinSig, _>);
            outdated(seed, bls12381_multisig::fixture::<MinPk, _>);
            outdated(seed, bls12381_multisig::fixture::<MinSig, _>);
            outdated(seed, ed25519::fixture);
        }
    }

    fn run_1k<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 10;
        let required_containers = View::new(1_000);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
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
                latency: Duration::from_millis(80),
                jitter: Duration::from_millis(10),
                success_rate: 0.98,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());
                let application_cfg = mocks::application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (100.0, 50.0),
                    verify_latency: (50.0, 40.0),
                };
                let (actor, application) = mocks::application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
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

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_bls12381_threshold_min_pk() {
        run_1k(bls12381_threshold::fixture::<MinPk, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_bls12381_threshold_min_sig() {
        run_1k(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_bls12381_multisig_min_pk() {
        run_1k(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_bls12381_multisig_min_sig() {
        run_1k(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_1k_ed25519() {
        run_1k(ed25519::fixture);
    }

    fn engine_shutdown<S, F>(mut fixture: F, graceful: bool)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
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
                    tracked_peer_sets: None,
                },
            );

            // Start network
            network.start();

            // Register a single participant
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link the single validator to itself (no-ops for completeness)
            let link = Link {
                latency: Duration::from_millis(1),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engine
            let reporter_config = mocks::reporter::Config {
                namespace: namespace.clone(),
                participants: participants.clone().try_into().unwrap(),
                scheme: schemes[0].clone(),
            };
            let reporter =
                mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
            let relay = Arc::new(mocks::relay::Relay::new());
            let application_cfg = mocks::application::Config {
                hasher: Sha256::default(),
                relay: relay.clone(),
                me: participants[0].clone(),
                propose_latency: (1.0, 0.0),
                verify_latency: (1.0, 0.0),
            };
            let (actor, application) = mocks::application::Application::new(
                context.with_label("application"),
                application_cfg,
            );
            actor.start();
            let blocker = oracle.control(participants[0].clone());
            let cfg = config::Config {
                scheme: schemes[0].clone(),
                blocker,
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter.clone(),
                partition: participants[0].clone().to_string(),
                mailbox_size: 64,
                epoch: Epoch::new(333),
                namespace: namespace.clone(),
                leader_timeout: Duration::from_millis(50),
                notarization_timeout: Duration::from_millis(100),
                nullify_retry: Duration::from_millis(250),
                fetch_timeout: Duration::from_millis(50),
                activity_timeout: ViewDelta::new(4),
                skip_timeout: ViewDelta::new(2),
                fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
                fetch_concurrent: 4,
                replay_buffer: NZUsize!(1024 * 16),
                write_buffer: NZUsize!(1024 * 16),
                buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let engine = Engine::new(context.with_label("engine"), cfg);

            // Start engine
            let (pending, recovered, resolver) = registrations
                .remove(&participants[0])
                .expect("validator should be registered");
            let handle = engine.start(pending, recovered, resolver);

            // Allow tasks to start
            context.sleep(Duration::from_millis(1000)).await;

            // Verify that engine and child actors are running
            let metrics_before = context.encode();
            let is_running = |name: &str| -> bool {
                metrics_before.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{name}\""))
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

            // Shutdown engine and ensure children stop
            let metrics_after = if graceful {
                let metrics_context = context.clone();
                let result = context.stop(0, Some(Duration::from_secs(5))).await;
                assert!(
                    result.is_ok(),
                    "graceful shutdown should complete: {result:?}"
                );
                metrics_context.encode()
            } else {
                handle.abort();
                let _ = handle.await; // ensure parent tear-down runs

                // Give the runtime a tick to process aborts
                context.sleep(Duration::from_millis(1000)).await;
                context.encode()
            };
            let is_stopped = |name: &str| -> bool {
                // Either the gauge is 0, or the entry is absent (both imply not running)
                metrics_after.lines().any(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains(&format!("name=\"{name}\""))
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
        engine_shutdown(bls12381_threshold::fixture::<MinPk, _>, false);
        engine_shutdown(bls12381_threshold::fixture::<MinSig, _>, false);
        engine_shutdown(bls12381_multisig::fixture::<MinPk, _>, false);
        engine_shutdown(bls12381_multisig::fixture::<MinSig, _>, false);
        engine_shutdown(ed25519::fixture, false);
    }

    #[test_traced]
    fn test_graceful_shutdown() {
        engine_shutdown(bls12381_threshold::fixture::<MinPk, _>, true);
        engine_shutdown(bls12381_threshold::fixture::<MinSig, _>, true);
        engine_shutdown(bls12381_multisig::fixture::<MinPk, _>, true);
        engine_shutdown(bls12381_multisig::fixture::<MinSig, _>, true);
        engine_shutdown(ed25519::fixture, true);
    }

    fn attributable_reporter_filtering<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let n = 3;
        let required_containers = View::new(10);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );
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

            // Create engines with `AttributableReporter` wrapper
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let context = context.with_label(&format!("validator-{}", *validator));

                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                };
                let mock_reporter = mocks::reporter::Reporter::new(
                    context.with_label("mock_reporter"),
                    reporter_config,
                );

                // Wrap with `AttributableReporter`
                let attributable_reporter = scheme::reporter::AttributableReporter::new(
                    context.with_label("rng"),
                    schemes[idx].clone(),
                    namespace.clone(),
                    mock_reporter.clone(),
                    true, // Enable verification
                );
                reporters.push(mock_reporter.clone());

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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: attributable_reporter,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(pending, recovered, resolver);
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

            // Verify filtering behavior based on scheme attributability
            for reporter in reporters.iter() {
                // Ensure no faults (normal operation)
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty(), "No faults should be reported");
                }

                // Ensure no invalid signatures
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0, "No invalid signatures");
                }

                // Check that we have certificates reported
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
                    let finalizations = reporter.finalizations.lock().unwrap();
                    assert!(
                        !notarizations.is_empty() || !finalizations.is_empty(),
                        "Certificates should be reported"
                    );
                }

                // Check notarizes
                let notarizes = reporter.notarizes.lock().unwrap();
                let last_view = notarizes.keys().max().cloned().unwrap_or_default();
                for (view, payloads) in notarizes.iter() {
                    if *view == last_view {
                        continue; // Skip last view
                    }

                    let signers: usize = payloads.values().map(|signers| signers.len()).sum();

                    // For attributable schemes, we should see peer activities
                    if schemes[0].is_attributable() {
                        assert!(signers > 1, "view {view}: {signers}");
                    } else {
                        // For non-attributable, we shouldn't see any peer activities
                        assert_eq!(signers, 0);
                    }
                }

                // Check finalizes
                let finalizes = reporter.finalizes.lock().unwrap();
                for (_, payloads) in finalizes.iter() {
                    let signers: usize = payloads.values().map(|signers| signers.len()).sum();

                    // For attributable schemes, we should see peer activities
                    if schemes[0].is_attributable() {
                        assert!(signers > 1);
                    } else {
                        // For non-attributable, we shouldn't see any peer activities
                        assert_eq!(signers, 0);
                    }
                }
            }

            // Ensure no blocked connections (normal operation)
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_attributable_reporter_filtering() {
        attributable_reporter_filtering(bls12381_threshold::fixture::<MinPk, _>);
        attributable_reporter_filtering(bls12381_threshold::fixture::<MinSig, _>);
        attributable_reporter_filtering(bls12381_multisig::fixture::<MinPk, _>);
        attributable_reporter_filtering(bls12381_multisig::fixture::<MinSig, _>);
        attributable_reporter_filtering(ed25519::fixture);
    }

    fn split_views_no_lockup<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Scenario:
        // - View F: Finalization of B_1 seen by all participants.
        // - View F+1:
        //   - Nullification seen by honest (4..=6,7) and all 3 byzantines
        //   - Notarization of B_2A seen by honest (1..=3)
        // - View F+2:
        //   - Nullification seen by honest (1..=3,7) and all 3 byzantines
        //   - Notarization of B_2B seen by honest (4..=6)
        // - View F+3: Nullification. Seen by all participants.
        // - Then ensure progress resumes beyond F+3 after reconnecting

        // Define participant types
        enum ParticipantType {
            Group1,    // receives notarization for f+1, nullification for f+2
            Group2,    // receives nullification for f+1, notarization for f+2
            Ignorant,  // receives nullification for f+1 and f+2
            Byzantine, // nullify-only
        }
        let get_type = |idx: usize| -> ParticipantType {
            match idx {
                0..3 => ParticipantType::Group1,
                3..6 => ParticipantType::Group2,
                6 => ParticipantType::Ignorant,
                7..10 => ParticipantType::Byzantine,
                _ => unreachable!(),
            }
        };

        // Create context
        let n = 10;
        let quorum = quorum(n) as usize;
        assert_eq!(quorum, 7);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // ========== Create engines ==========

            // Do not link validators yet; we will inject certificates first, then link everyone.

            // Create engines: 7 honest engines, 3 byzantine
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut honest_reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                let participant_type = get_type(idx);
                if matches!(participant_type, ParticipantType::Byzantine) {
                    // Byzantine engines
                    let cfg = mocks::nullify_only::Config {
                        scheme: schemes[idx].clone(),
                        namespace: namespace.clone(),
                    };
                    let engine: mocks::nullify_only::NullifyOnly<_, _, Sha256> =
                        mocks::nullify_only::NullifyOnly::new(
                            context.with_label(&format!("byzantine-{}", *validator)),
                            cfg,
                        );
                    engine.start(pending);
                    // Recovered/resolver channels are unused for byzantine actors.
                    drop(recovered);
                    drop(resolver);
                } else {
                    // Honest engines
                    let reporter_config = mocks::reporter::Config {
                        namespace: namespace.clone(),
                        participants: participants.clone().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                    };
                    let reporter = mocks::reporter::Reporter::new(
                        context.with_label(&format!("reporter-{}", *validator)),
                        reporter_config,
                    );
                    honest_reporters.push(reporter.clone());

                    let application_cfg = mocks::application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                    };
                    let (actor, application) = mocks::application::Application::new(
                        context.with_label(&format!("application-{}", *validator)),
                        application_cfg,
                    );
                    actor.start();
                    let blocker = oracle.control(validator.clone());
                    let cfg = config::Config {
                        scheme: schemes[idx].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(10),
                        notarization_timeout: Duration::from_secs(10),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine =
                        Engine::new(context.with_label(&format!("engine-{}", *validator)), cfg);
                    engine.start(pending, recovered, resolver);
                }
            }

            // ========== Build the certificates manually ==========

            // Helper: assemble finalization from explicit signer indices
            let build_finalization = |proposal: &Proposal<D>| -> TFinalization<_, D> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TFinalize::sign(&schemes[i], &namespace, proposal.clone()).unwrap())
                    .collect();
                TFinalization::from_finalizes(&schemes[0], &votes).expect("finalization quorum")
            };
            // Helper: assemble notarization from explicit signer indices
            let build_notarization = |proposal: &Proposal<D>| -> TNotarization<_, D> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TNotarize::sign(&schemes[i], &namespace, proposal.clone()).unwrap())
                    .collect();
                TNotarization::from_notarizes(&schemes[0], &votes).expect("notarization quorum")
            };
            let build_nullification = |round: Round| -> TNullification<_> {
                let votes: Vec<_> = (0..=quorum)
                    .map(|i| TNullify::sign::<D>(&schemes[i], &namespace, round).unwrap())
                    .collect();
                TNullification::from_nullifies(&schemes[0], &votes).expect("nullification quorum")
            };
            // Choose F=1 and construct B_1, B_2A, B_2B
            let f_view = 1;
            let round_f = Round::new(Epoch::new(333), View::new(f_view));
            let payload_b0 = Sha256::hash(b"B_F");
            let proposal_b0 = Proposal::new(round_f, View::new(f_view - 1), payload_b0);
            let payload_b1a = Sha256::hash(b"B_G1");
            let proposal_b1a = Proposal::new(
                Round::new(Epoch::new(333), View::new(f_view + 1)),
                View::new(f_view),
                payload_b1a,
            );
            let payload_b1b = Sha256::hash(b"B_G2");
            let proposal_b1b = Proposal::new(
                Round::new(Epoch::new(333), View::new(f_view + 2)),
                View::new(f_view),
                payload_b1b,
            );

            // Build notarization and finalization for the first block
            let b0_notarization = build_notarization(&proposal_b0);
            let b0_finalization = build_finalization(&proposal_b0);
            // Build notarizations for F+1 and F+2
            let b1a_notarization = build_notarization(&proposal_b1a);
            let b1b_notarization = build_notarization(&proposal_b1b);
            // Build nullifications for F+1 and F+2
            let null_a = build_nullification(Round::new(Epoch::new(333), View::new(f_view + 1)));
            let null_b = build_nullification(Round::new(Epoch::new(333), View::new(f_view + 2)));

            // Create an 11th non-participant injector and obtain senders
            let injector_pk = PrivateKey::from_seed(1_000_000).public_key();
            let (mut injector_sender, _inj_certificate_receiver) = oracle
                .control(injector_pk.clone())
                .register(1, TEST_QUOTA)
                .await
                .unwrap();

            // Create minimal one-way links from injector to all participants (not full mesh)
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(0),
                success_rate: 1.0,
            };
            for p in participants.iter() {
                oracle
                    .add_link(injector_pk.clone(), p.clone(), link.clone())
                    .await
                    .unwrap();
            }

            // ========== Broadcast certificates over recovered network. ==========

            // Broadcasts are in reverse order of views to make the tests easier by preventing the
            // proposer from making a proposal in F+1 or F+2, as it may panic when it proposes
            // something but generates a certificate for a different proposal.

            // View F+2:
            let notarization_msg = Certificate::<_, D>::Notarization(b1b_notarization);
            let nullification_msg = Certificate::<_, D>::Nullification(null_b.clone());
            for (i, participant) in participants.iter().enumerate() {
                let recipient = Recipients::One(participant.clone());
                let msg = match get_type(i) {
                    ParticipantType::Group2 => notarization_msg.encode().into(),
                    _ => nullification_msg.encode().into(),
                };
                injector_sender.send(recipient, msg, true).await.unwrap();
            }
            // View F+1:
            let notarization_msg = Certificate::<_, D>::Notarization(b1a_notarization);
            let nullification_msg = Certificate::<_, D>::Nullification(null_a.clone());
            for (i, participant) in participants.iter().enumerate() {
                let recipient = Recipients::One(participant.clone());
                let msg = match get_type(i) {
                    ParticipantType::Group1 => notarization_msg.encode().into(),
                    _ => nullification_msg.encode().into(),
                };
                injector_sender.send(recipient, msg, true).await.unwrap();
            }
            // View F:
            let msg = Certificate::<_, D>::Notarization(b0_notarization)
                .encode()
                .into();
            injector_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();
            let msg = Certificate::<_, D>::Finalization(b0_finalization)
                .encode()
                .into();
            injector_sender
                .send(Recipients::All, msg, true)
                .await
                .unwrap();

            // Wait for a while to let the certificates propagate, but not so long that we
            // nullify view F+2.
            debug!("waiting for certificates to propagate");
            context.sleep(Duration::from_secs(5)).await;
            debug!("certificates propagated");

            // ========== Assert the exact certificates are seen in each view ==========

            // Assert the exact certificates in view F
            // All participants should have finalized B_0
            let view = View::new(f_view);
            for reporter in honest_reporters.iter() {
                let finalizations = reporter.finalizations.lock().unwrap();
                assert!(finalizations.contains_key(&view));
            }

            // Assert the exact certificates in view F+1
            // Group 1 should have notarized B_1A only
            // All other participants should have nullified F+1
            let view = View::new(f_view + 1);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let finalizations = reporter.finalizations.lock().unwrap();
                assert!(!finalizations.contains_key(&view));
                let nullifications = reporter.nullifications.lock().unwrap();
                let notarizations = reporter.notarizations.lock().unwrap();
                match get_type(i) {
                    ParticipantType::Group1 => {
                        assert!(notarizations.contains_key(&view));
                        assert!(!nullifications.contains_key(&view));
                    }
                    _ => {
                        assert!(nullifications.contains_key(&view));
                        assert!(!notarizations.contains_key(&view));
                    }
                }
            }

            // Assert the exact certificates in view F+2
            // Group 2 should have notarized B_1B only
            // All other participants should have nullified F+2
            let view = View::new(f_view + 2);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let finalizations = reporter.finalizations.lock().unwrap();
                assert!(!finalizations.contains_key(&view));
                let nullifications = reporter.nullifications.lock().unwrap();
                let notarizations = reporter.notarizations.lock().unwrap();
                match get_type(i) {
                    ParticipantType::Group2 => {
                        assert!(notarizations.contains_key(&view));
                        assert!(!nullifications.contains_key(&view));
                    }
                    _ => {
                        assert!(nullifications.contains_key(&view));
                        assert!(!notarizations.contains_key(&view));
                    }
                }
            }

            // Assert no members have yet nullified view F+3
            let next_view = View::new(f_view + 3);
            for (i, reporter) in honest_reporters.iter().enumerate() {
                let nullifies = reporter.nullifies.lock().unwrap();
                assert!(!nullifies.contains_key(&next_view), "reporter {i}");
            }

            // ========== Reconnect all participants ==========

            // Reconnect all participants fully using the helper
            link_validators(&mut oracle, &participants, Action::Link(link.clone()), None).await;

            // Wait until all honest reporters finalize strictly past F+2 (e.g., at least F+3)
            {
                let target = View::new(f_view + 3);
                let mut finalizers = Vec::new();
                for reporter in honest_reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.with_label("resume-finalizer").spawn(
                        move |_| async move {
                            while latest < target {
                                latest = monitor.next().await.expect("event missing");
                            }
                        },
                    ));
                }
                join_all(finalizers).await;
            }

            // Sanity checks: no faults/invalid signatures, and no peers blocked
            for reporter in honest_reporters.iter() {
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty());
                }
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0);
                }
            }
            let blocked = oracle.blocked().await.unwrap();
            assert!(blocked.is_empty());
        });
    }

    #[test_traced]
    fn test_split_views_no_lockup() {
        split_views_no_lockup(bls12381_threshold::fixture::<MinPk, _>);
        split_views_no_lockup(bls12381_threshold::fixture::<MinSig, _>);
        split_views_no_lockup(bls12381_multisig::fixture::<MinPk, _>);
        split_views_no_lockup(bls12381_multisig::fixture::<MinSig, _>);
        split_views_no_lockup(ed25519::fixture);
    }

    fn tle<V: Variant>() {
        // Create context
        let n = 4;
        let namespace = b"consensus".to_vec();
        let activity_timeout = ViewDelta::new(100);
        let skip_timeout = ViewDelta::new(50);
        let executor = deterministic::Runner::timed(Duration::from_secs(30));
        executor.start(|mut context| async move {
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
            } = bls12381_threshold::fixture::<V, _>(&mut context, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // Create engines and reporters
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            let monitor_reporter = Arc::new(Mutex::new(None));
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Store first reporter for monitoring
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_millis(100),
                    notarization_timeout: Duration::from_millis(200),
                    nullify_retry: Duration::from_millis(500),
                    fetch_timeout: Duration::from_millis(100),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(10)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Prepare TLE test data
            let target = Round::new(Epoch::new(333), View::new(10)); // Encrypt for round (epoch 333, view 10)
            let message = b"Secret message for future view10"; // 32 bytes

            // Encrypt message
            let ciphertext = schemes[0].encrypt(&mut context, &namespace, target, *message);

            // Wait for consensus to reach the target view and then decrypt
            let reporter = monitor_reporter.lock().unwrap().clone().unwrap();
            loop {
                // Wait for notarization
                context.sleep(Duration::from_millis(100)).await;
                let notarizations = reporter.notarizations.lock().unwrap();
                let Some(notarization) = notarizations.get(&target.view()) else {
                    continue;
                };

                // Decrypt the message using the seed
                let seed = notarization.seed();
                let decrypted = seed
                    .decrypt(&ciphertext)
                    .expect("Decryption should succeed with valid seed signature");
                assert_eq!(
                    message,
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

    fn hailstorm<S, F>(seed: u64, shutdowns: usize, interval: ViewDelta, mut fixture: F) -> String
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        // Create context
        let n = 5;
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new().with_seed(seed);
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
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
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = BTreeMap::new();
            let mut engine_handlers = BTreeMap::new();
            for (idx, validator) in participants.iter().enumerate() {
                // Create scheme context
                let context = context.with_label(&format!("validator-{}", *validator));

                // Configure engine
                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                };
                let reporter =
                    mocks::reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.insert(idx, reporter.clone());
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                // Start engine
                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.insert(idx, engine.start(pending, recovered, resolver));
            }

            // Run shutdowns
            let mut target = View::zero();
            for i in 0..shutdowns {
                // Update target
                target = target.saturating_add(interval);

                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for (_, reporter) in reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.next().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                target = target.saturating_add(interval);

                // Select a random engine to shutdown
                let idx = context.gen_range(0..engine_handlers.len());
                let validator = &participants[idx];
                let handle = engine_handlers.remove(&idx).unwrap();
                handle.abort();
                let _ = handle.await;
                let selected_reporter = reporters.remove(&idx).unwrap();
                info!(idx, ?validator, "shutdown validator");

                // Wait for all engines to finish
                let mut finalizers = Vec::new();
                for (_, reporter) in reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.next().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                target = target.saturating_add(interval);

                // Recreate engine
                info!(idx, ?validator, "restarting validator");
                let context =
                    context.with_label(&format!("validator-{}-restarted-{}", *validator, i));

                // Start engine
                let (pending, recovered, resolver) =
                    register_validator(&mut oracle, validator.clone()).await;
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
                reporters.insert(idx, selected_reporter.clone());
                let blocker = oracle.control(validator.clone());
                let cfg = config::Config {
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: selected_reporter,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);
                engine_handlers.insert(idx, engine.start(pending, recovered, resolver));

                // Wait for all engines to hit required containers
                let mut finalizers = Vec::new();
                for (_, reporter) in reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < target {
                            latest = monitor.next().await.expect("event missing");
                        }
                    }));
                }
                join_all(finalizers).await;
                info!(idx, ?validator, "validator recovered");
            }

            // Check reporters for correct activity
            let latest_complete = target.saturating_sub(activity_timeout);
            for (_, reporter) in reporters.iter() {
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

                // Ensure no forks
                let mut notarized = HashMap::new();
                let mut finalized = HashMap::new();
                {
                    let notarizes = reporter.notarizes.lock().unwrap();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = notarizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, _) = payloads.iter().next().unwrap();
                        notarized.insert(view, *digest);
                    }
                }
                {
                    let notarizations = reporter.notarizations.lock().unwrap();
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
                {
                    let finalizes = reporter.finalizes.lock().unwrap();
                    for view in View::range(View::new(1), latest_complete) {
                        // Ensure only one payload proposed per view
                        let Some(payloads) = finalizes.get(&view) else {
                            continue;
                        };
                        if payloads.len() > 1 {
                            panic!("view: {view}");
                        }
                        let (digest, _) = payloads.iter().next().unwrap();
                        finalized.insert(view, *digest);

                        // Only check at views below timeout
                        if view > latest_complete {
                            continue;
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
                    for view in View::range(View::new(1), latest_complete) {
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

            // Return state for audit
            context.auditor().state()
        })
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_hailstorm_bls12381_threshold_min_pk() {
        assert_eq!(
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_threshold::fixture::<MinPk, _>
            ),
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_threshold::fixture::<MinPk, _>
            ),
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_hailstorm_bls12381_threshold_min_sig() {
        assert_eq!(
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_threshold::fixture::<MinSig, _>
            ),
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_threshold::fixture::<MinSig, _>
            ),
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_hailstorm_bls12381_multisig_min_pk() {
        assert_eq!(
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_multisig::fixture::<MinPk, _>
            ),
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_multisig::fixture::<MinPk, _>
            ),
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_hailstorm_bls12381_multisig_min_sig() {
        assert_eq!(
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_multisig::fixture::<MinSig, _>
            ),
            hailstorm(
                0,
                10,
                ViewDelta::new(15),
                bls12381_multisig::fixture::<MinSig, _>
            ),
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_hailstorm_ed25519() {
        assert_eq!(
            hailstorm(0, 10, ViewDelta::new(15), ed25519::fixture),
            hailstorm(0, 10, ViewDelta::new(15), ed25519::fixture)
        );
    }

    /// Implementation of [Twins: BFT Systems Made Robust](https://arxiv.org/abs/2004.10617).
    fn twins<S, F>(seed: u64, n: u32, strategy: Strategy, link: Link, mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        let faults = max_faults(n);
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"consensus".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(600)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                Config {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, n);
            let participants: Arc<[_]> = participants.into();
            let mut registrations = register_validators(&mut oracle, &participants).await;
            link_validators(&mut oracle, &participants, Action::Link(link), None).await;

            // We don't apply partitioning to the relay explicitly, however, a participant will only query the relay by digest
            // after receiving a vote (implicitly respecting the partitioning)
            let relay = Arc::new(mocks::relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();

            // Create twin engines (f Byzantine twins)
            for (idx, validator) in participants.iter().enumerate().take(faults as usize) {
                let (
                    (vote_sender, vote_receiver),
                    (certificate_sender, certificate_receiver),
                    (resolver_sender, resolver_receiver),
                ) = registrations
                    .remove(validator)
                    .expect("validator should be registered");

                // Create forwarder closures for votes
                let make_vote_forwarder = || {
                    let participants = participants.clone();
                    move |origin: SplitOrigin, _: &Recipients<_>, message: &Bytes| {
                        let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                        let (primary, secondary) =
                            strategy.partitions(msg.view(), participants.as_ref());
                        match origin {
                            SplitOrigin::Primary => Some(Recipients::Some(primary)),
                            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                        }
                    }
                };
                // Create forwarder closures for certificates
                let make_certificate_forwarder = || {
                    let codec = schemes[idx].certificate_codec_config();
                    let participants = participants.clone();
                    move |origin: SplitOrigin, _: &Recipients<_>, message: &Bytes| {
                        let msg: Certificate<S, D> =
                            Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                        let (primary, secondary) =
                            strategy.partitions(msg.view(), participants.as_ref());
                        match origin {
                            SplitOrigin::Primary => Some(Recipients::Some(primary)),
                            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                        }
                    }
                };
                let make_drop_forwarder =
                    || move |_: SplitOrigin, _: &Recipients<_>, _: &Bytes| None;

                // Create router closures for votes
                let make_vote_router = || {
                    let participants = participants.clone();
                    move |(sender, message): &(_, Bytes)| {
                        let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                        strategy.route(msg.view(), sender, participants.as_ref())
                    }
                };
                // Create router closures for certificates
                let make_certificate_router = || {
                    let codec = schemes[idx].certificate_codec_config();
                    let participants = participants.clone();
                    move |(sender, message): &(_, Bytes)| {
                        let msg: Certificate<S, D> =
                            Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                        strategy.route(msg.view(), sender, participants.as_ref())
                    }
                };
                let make_drop_router = || move |(_, _): &(_, _)| SplitTarget::None;

                // Apply view-based forwarder and router to pending and recovered channel
                let (vote_sender_primary, vote_sender_secondary) =
                    vote_sender.split_with(make_vote_forwarder());
                let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                    context.with_label(&format!("pending-split-{idx}")),
                    make_vote_router(),
                );
                let (certificate_sender_primary, certificate_sender_secondary) =
                    certificate_sender.split_with(make_certificate_forwarder());
                let (certificate_receiver_primary, certificate_receiver_secondary) =
                    certificate_receiver.split_with(
                        context.with_label(&format!("recovered-split-{idx}")),
                        make_certificate_router(),
                    );

                // Prevent any resolver messages from being sent or received by twins (these messages aren't cleanly mapped to a view and allowing them to bypass partitions seems wrong)
                let (resolver_sender_primary, resolver_sender_secondary) =
                    resolver_sender.split_with(make_drop_forwarder());
                let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                    .split_with(
                        context.with_label(&format!("resolver-split-{idx}")),
                        make_drop_router(),
                    );

                for (twin_label, pending, recovered, resolver) in [
                    (
                        "primary",
                        (vote_sender_primary, vote_receiver_primary),
                        (certificate_sender_primary, certificate_receiver_primary),
                        (resolver_sender_primary, resolver_receiver_primary),
                    ),
                    (
                        "secondary",
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    ),
                ] {
                    let label = format!("twin-{idx}-{twin_label}");
                    let context = context.with_label(&label);

                    let reporter_config = mocks::reporter::Config {
                        namespace: namespace.clone(),
                        participants: participants.as_ref().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                    };
                    let reporter = mocks::reporter::Reporter::new(
                        context.with_label("reporter"),
                        reporter_config,
                    );
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
                        scheme: schemes[idx].clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        partition: label,
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        namespace: namespace.clone(),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_rate_per_peer: Quota::per_hour(NZU32!(1)), // resolver networking is disabled, so let's prevent unnecessary task polling
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine_handlers.push(engine.start(pending, recovered, resolver));
                }
            }

            // Create honest engines
            for (idx, validator) in participants.iter().enumerate().skip(faults as usize) {
                let label = format!("honest-{idx}");
                let context = context.with_label(&label);

                let reporter_config = mocks::reporter::Config {
                    namespace: namespace.clone(),
                    participants: participants.as_ref().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
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
                    scheme: schemes[idx].clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    partition: label,
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    namespace: namespace.clone(),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_rate_per_peer: Quota::per_second(NZU32!(1)),
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                let (pending, recovered, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(pending, recovered, resolver));
            }

            // Wait for progress (liveness check)
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

            // Verify safety: no conflicting finalizations across honest reporters
            let honest_start = faults as usize * 2; // Each twin produces 2 reporters
            let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
            for reporter in reporters.iter().skip(honest_start) {
                let finalizations = reporter.finalizations.lock().unwrap();
                for (view, finalization) in finalizations.iter() {
                    let digest = finalization.proposal.payload;
                    if let Some(existing) = finalized_at_view.get(view) {
                        assert_eq!(
                            existing, &digest,
                            "safety violation: conflicting finalizations at view {view}"
                        );
                    } else {
                        finalized_at_view.insert(*view, digest);
                    }
                }
            }

            // Verify no invalid signatures were observed
            for reporter in reporters.iter().skip(honest_start) {
                let invalid = reporter.invalid.lock().unwrap();
                assert_eq!(*invalid, 0, "invalid signatures detected");
            }

            // Ensure faults are attributable to twins
            let twin_identities: Vec<_> = participants.iter().take(faults as usize).collect();
            for reporter in reporters.iter().skip(honest_start) {
                let faults = reporter.faults.lock().unwrap();
                for (faulter, _) in faults.iter() {
                    assert!(
                        twin_identities.contains(&faulter),
                        "fault from non-twin participant"
                    );
                }
            }

            // Ensure blocked connections are attributable to twins
            let blocked = oracle.blocked().await.unwrap();
            for (_, faulter) in blocked.iter() {
                assert!(
                    twin_identities.contains(&faulter),
                    "blocked connection from non-twin participant"
                );
            }
        });
    }

    fn test_twins<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256Digest, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, u32) -> Fixture<S>,
    {
        for strategy in [
            Strategy::View,
            Strategy::Fixed(3),
            Strategy::Isolate(4),
            Strategy::Broadcast,
            Strategy::Shuffle,
        ] {
            for link in [
                Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: 1.0,
                },
                Link {
                    latency: Duration::from_millis(200),
                    jitter: Duration::from_millis(150),
                    success_rate: 0.75,
                },
            ] {
                twins(0, 5, strategy, link, |context, n| fixture(context, n));
            }
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_multisig_min_pk() {
        test_twins(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_multisig_min_sig() {
        test_twins(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_threshold_min_pk() {
        test_twins(bls12381_threshold::fixture::<MinPk, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_threshold_min_sig() {
        test_twins(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_ed25519() {
        test_twins(ed25519::fixture);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_large_view() {
        twins(
            0,
            10,
            Strategy::View,
            Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.75,
            },
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_large_shuffle() {
        twins(
            0,
            10,
            Strategy::Shuffle,
            Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.75,
            },
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }
}
