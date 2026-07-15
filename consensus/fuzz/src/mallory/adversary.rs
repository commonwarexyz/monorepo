//! Episode-level Byzantine adversary profiles for Mallory.
//!
//! Where [`fault`](super::fault) perturbs only the network, an adversary *role*
//! replaces the single faultable identity ([`crate::BYZANTINE_IDX`]) with an
//! explicit Byzantine actor for the WHOLE episode. The role is an environment
//! property sampled once at setup, not a per-step policy fault, so it never
//! enters the fault catalog and adds no catalog id. `BYZANTINE_IDX` then runs as a raw,
//! unmanaged byzantine node: it gets its registered channels directly, with no
//! packet pump, no [`SniffingReceiver`](crate::SniffingReceiver), no reporter, and
//! no [`ManagedValidator`](crate::ManagedValidator). The other three nodes stay
//! honest and form the N4F0C4 quorum of three.
//!
//! Six profiles, each an existing mock:
//!
//! - [`AdversaryRole::Disrupter`]: a full byzantine engine ([`crate::disrupter`])
//!   that emits on ALL THREE consensus channels (vote, certificate, resolver).
//! - [`AdversaryRole::Conflicter`]: emits a conflicting notarize/finalize pair on
//!   the VOTE channel only (`conflicter`).
//! - [`AdversaryRole::Nuller`]: emits a nullify+finalize pair for the same view on
//!   the VOTE channel only (`nuller`).
//! - [`AdversaryRole::Equivocator`]: sends different proposals to different nodes,
//!   listening to recovered certificates (CERTIFICATE channel) and equivocating on
//!   the VOTE channel (`equivocator`).
//! - [`AdversaryRole::Impersonator`]: re-signs and forwards votes under a swapped
//!   signer index on the VOTE channel only (`impersonator`).
//! - [`AdversaryRole::Outdated`]: re-notarizes/finalizes a stale (earlier-view)
//!   proposal on the VOTE channel only (`outdated`).
//!
//! # Single-owner rule
//!
//! Each channel mailbox is single-consumer, so exactly one owner is spawned at
//! `BYZANTINE_IDX`. The Disrupter consumes all three channels; the Equivocator consumes the
//! vote and certificate channels (dropping resolver); the Conflicter, Nuller,
//! Impersonator, and Outdated consume only the vote channel and explicitly drop the
//! certificate and resolver channels (freeing those receivers rather than leaving a
//! second owner).

use crate::{
    disrupter::Disrupter, simplex::Simplex, strategy::AnyScope, NetworkChannels, PublicKeyOf,
};
use commonware_consensus::{
    simplex::mocks::{conflicter, equivocator, impersonator, nuller, outdated, relay},
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
use commonware_runtime::{deterministic, Handle, Supervisor as _};
use commonware_utils::sync::Mutex;
use rand::{Rng, RngExt as _};
use std::sync::{Arc, OnceLock};

/// The Byzantine profile `BYZANTINE_IDX` plays for a whole Mallory episode.
///
/// Sampled once at setup from the runtime `FuzzRng` and held for the episode, so a
/// replay reproduces it. Folded into the Q-state (via [`tag`](Self::tag)) so a
/// campaign never merges incompatible environments (Honest and each Byzantine role
/// are distinct Q-rows and novelty registries).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AdversaryRole {
    /// `BYZANTINE_IDX` is an honest [`ManagedValidator`](crate::ManagedValidator) like the
    /// other three (the pre-adversary environment).
    Honest,
    /// `BYZANTINE_IDX` is a [`Disrupter`] emitting on all three
    /// consensus channels.
    Disrupter,
    /// `BYZANTINE_IDX` is a conflicter emitting conflicting notarize/finalize pairs on the
    /// vote channel.
    Conflicter,
    /// `BYZANTINE_IDX` is a nuller emitting nullify+finalize for the same view on the vote
    /// channel.
    Nuller,
    /// `BYZANTINE_IDX` is an equivocator sending different proposals to different nodes,
    /// consuming the vote and certificate channels.
    Equivocator,
    /// `BYZANTINE_IDX` is an impersonator re-signing votes under a swapped signer index on
    /// the vote channel.
    Impersonator,
    /// `BYZANTINE_IDX` is an outdated adversary re-notarizing/finalizing a stale proposal on
    /// the vote channel.
    Outdated,
}

impl AdversaryRole {
    /// The number of distinct roles: the [`RoleBandit`] arm count and the width of
    /// every per-role array. Matches the stable [`index`](Self::index) /
    /// [`from_index`](Self::from_index) / [`sample`](Self::sample) order.
    pub(crate) const COUNT: usize = 7;

    /// Uniformly sample a role from the runtime RNG. Drawn once at setup, before the
    /// per-node loop, so the whole episode runs under one fixed environment.
    pub(crate) fn sample(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..7u8) {
            0 => AdversaryRole::Honest,
            1 => AdversaryRole::Disrupter,
            2 => AdversaryRole::Conflicter,
            3 => AdversaryRole::Nuller,
            4 => AdversaryRole::Equivocator,
            5 => AdversaryRole::Impersonator,
            _ => AdversaryRole::Outdated,
        }
    }

    /// Uniformly sample a BYZANTINE role from the runtime RNG, never
    /// [`Honest`](Self::Honest). The target of a per-step
    /// [`SwapByzantineRole`](super::fault::Fault::SwapByzantineRole) role switch: the multiplexer
    /// only ever hosts one of the six Byzantine profiles, so an
    /// Honest<->Byzantine transition (which would need an oracle flip) is out of
    /// scope. Drawn from the runtime RNG so a replay reproduces the target.
    pub(crate) fn sample_byzantine(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..6u8) {
            0 => AdversaryRole::Disrupter,
            1 => AdversaryRole::Conflicter,
            2 => AdversaryRole::Nuller,
            3 => AdversaryRole::Equivocator,
            4 => AdversaryRole::Impersonator,
            _ => AdversaryRole::Outdated,
        }
    }

    /// The role's 0-based index in the stable catalog order (the inverse of
    /// [`from_index`](Self::from_index)), matching [`sample`](Self::sample): Honest is
    /// `0`, then each Byzantine role. Used as the [`RoleBandit`] arm index.
    pub(crate) fn index(self) -> usize {
        match self {
            AdversaryRole::Honest => 0,
            AdversaryRole::Disrupter => 1,
            AdversaryRole::Conflicter => 2,
            AdversaryRole::Nuller => 3,
            AdversaryRole::Equivocator => 4,
            AdversaryRole::Impersonator => 5,
            AdversaryRole::Outdated => 6,
        }
    }

    /// The role at 0-based catalog index `i` (the inverse of [`index`](Self::index)).
    /// Panics for `i >= COUNT`, which is a caller bug.
    pub(crate) fn from_index(i: usize) -> Self {
        match i {
            0 => AdversaryRole::Honest,
            1 => AdversaryRole::Disrupter,
            2 => AdversaryRole::Conflicter,
            3 => AdversaryRole::Nuller,
            4 => AdversaryRole::Equivocator,
            5 => AdversaryRole::Impersonator,
            6 => AdversaryRole::Outdated,
            _ => panic!("role index out of range: {i}"),
        }
    }

    /// A distinct per-role mixing constant folded into the Q-state / novelty
    /// fingerprints. Honest is `0` (an identity mix, so the warm campaign Q-table's
    /// honest rows are unchanged); each Byzantine role is a well-separated nonzero
    /// constant, so `fingerprint ^ tag` keys a distinct row per environment.
    pub(crate) fn tag(self) -> u64 {
        match self {
            AdversaryRole::Honest => 0,
            AdversaryRole::Disrupter => 0x9e37_79b9_7f4a_7c15,
            AdversaryRole::Conflicter => 0xc2b2_ae3d_27d4_eb4f,
            AdversaryRole::Nuller => 0x1656_67b1_9e37_79f9,
            AdversaryRole::Equivocator => 0x2545_f491_4f6c_dd1d,
            AdversaryRole::Impersonator => 0xff51_afd7_ed55_8ccd,
            AdversaryRole::Outdated => 0xc4ce_b9fe_1a85_ec53,
        }
    }

    /// Whether this role replaces `BYZANTINE_IDX` with a Byzantine actor (everything except
    /// [`Honest`](Self::Honest)).
    pub(crate) fn is_byzantine(self) -> bool {
        !matches!(self, AdversaryRole::Honest)
    }

    /// Short label for the decision log.
    pub(crate) fn label(self) -> &'static str {
        match self {
            AdversaryRole::Honest => "honest",
            AdversaryRole::Disrupter => "disrupter",
            AdversaryRole::Conflicter => "conflicter",
            AdversaryRole::Nuller => "nuller",
            AdversaryRole::Equivocator => "equivocator",
            AdversaryRole::Impersonator => "impersonator",
            AdversaryRole::Outdated => "outdated",
        }
    }
}

/// Running-average learning rate for the [`RoleBandit`]. A constant (non-stationary)
/// rate, so recent episode productivity outweighs stale credit as campaign novelty
/// saturates and a once-productive role dries up.
const ROLE_BANDIT_ALPHA: f64 = 0.1;
/// Softmax temperature for role selection. `1.0` (plain `exp(q)`) so the bandit
/// actually concentrates on the productive roles rather than staying near-uniform.
const ROLE_BANDIT_TEMPERATURE: f64 = 1.0;

/// Campaign-persistent multi-armed bandit over the [`AdversaryRole::COUNT`] roles:
/// one Q-value per role tracking its recent episode productivity. Selection is a
/// softmax over those values, so the campaign concentrates episodes on the Byzantine
/// profiles that keep producing novelty (Mallory-faithful adaptive fault selection).
///
/// Persisted for the whole libFuzzer campaign like the per-step
/// [`Campaign`](super::policy::Campaign), but SEPARATE from it: this picks the
/// episode's fixed environment (the role), not a per-step fault. Only the learned
/// chooser selects through it and updates it; the random and fixed choosers keep the
/// campaign-independent uniform [`AdversaryRole::sample`], so the A/B baseline stays
/// campaign-independent.
pub(crate) struct RoleBandit {
    /// Per-role Q-value in [`AdversaryRole::index`] order; all zero by default, which
    /// makes the initial softmax uniform over the roles.
    q: [f64; AdversaryRole::COUNT],
}

impl Default for RoleBandit {
    fn default() -> Self {
        Self {
            q: [0.0; AdversaryRole::COUNT],
        }
    }
}

impl RoleBandit {
    /// Softmax distribution over the per-role Q-values at [`ROLE_BANDIT_TEMPERATURE`].
    /// Shifts by the max for numerical stability, so an all-zero row is uniform over
    /// the roles.
    fn softmax(&self) -> [f64; AdversaryRole::COUNT] {
        let max = self.q.iter().copied().fold(f64::MIN, f64::max);
        let mut probs = [0.0f64; AdversaryRole::COUNT];
        let mut sum = 0.0;
        for (p, &q) in probs.iter_mut().zip(self.q.iter()) {
            let e = ((q - max) / ROLE_BANDIT_TEMPERATURE).exp();
            *p = e;
            sum += e;
        }
        for p in &mut probs {
            *p /= sum;
        }
        probs
    }

    /// Select a role by softmax over the per-role Q-values, drawing from the
    /// caller-supplied RNG (the deterministic runtime context) and sampling by
    /// inverse-CDF, mirroring [`QPolicy::select`](super::policy::QPolicy::select). An
    /// all-zero row is uniform over the roles.
    pub(crate) fn select(&self, rng: &mut impl Rng) -> AdversaryRole {
        let probs = self.softmax();
        // Uniform draw in [0, 1) from 53 random bits, then inverse-CDF over `probs`.
        let draw = ((rng.random::<u64>() >> 11) as f64) / ((1u64 << 53) as f64);
        let mut cumulative = 0.0;
        for (i, &p) in probs.iter().enumerate() {
            cumulative += p;
            if draw < cumulative {
                return AdversaryRole::from_index(i);
            }
        }
        // Floating-point guard: the last role.
        AdversaryRole::from_index(AdversaryRole::COUNT - 1)
    }

    /// Non-stationary running-average update of the chosen role's Q-value toward the
    /// episode's productivity `reward`, the PER-STEP-averaged novelty in `[-2, 0]`
    /// (`0` = every step reached a novel state and happens-before fingerprint, `-2` =
    /// none): `q[role] <- (1 - ALPHA) q[role] + ALPHA reward`. Constant-alpha (not
    /// `1/n`) so the bandit tracks recent productivity as campaign novelty saturates.
    /// The signal is a per-step average, not a sum, so a short (early crash-stop)
    /// episode is compared to a full-length one by novelty density, not length.
    pub(crate) fn learn(&mut self, role: AdversaryRole, reward: f64) {
        let q = &mut self.q[role.index()];
        *q = (1.0 - ROLE_BANDIT_ALPHA) * *q + ROLE_BANDIT_ALPHA * reward;
    }

    /// Whether any arm's Q-value has moved away from zero. Test-only (the smoke test
    /// asserts a few learned episodes taught the bandit something).
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.q.iter().all(|&q| q == 0.0)
    }
}

static ROLE_BANDIT: OnceLock<Mutex<RoleBandit>> = OnceLock::new();

/// Process-global role bandit, initialised empty on first use and persisted across
/// every libFuzzer input for the rest of the campaign (like
/// [`campaign`](super::policy::campaign)). Only the learned chooser selects through
/// it and updates it at episode end; the random and fixed choosers keep the uniform
/// [`AdversaryRole::sample`], so the A/B baseline stays campaign-independent.
pub(crate) fn role_bandit() -> &'static Mutex<RoleBandit> {
    ROLE_BANDIT.get_or_init(|| Mutex::new(RoleBandit::default()))
}

/// Reset the process-global role bandit to an empty one. Test-only, so ignored
/// integration tests do not leak learned Q-values into one another.
#[cfg(test)]
pub(crate) fn reset_role_bandit() {
    *role_bandit().lock() = RoleBandit::default();
}

/// Spawn the Byzantine actor for `role` at `BYZANTINE_IDX` with its RAW registered channels
/// (no pump, no sniffer, no reporter, no [`ManagedValidator`](crate::ManagedValidator))
/// and return its task [`Handle`].
///
/// The returned handle is the single owner of the spawned actor's task: aborting and
/// awaiting it (as [`RoleMultiplexer::set_role`](super::multiplexer::RoleMultiplexer::set_role)
/// does on a role switch) drives it to termination, cascading to every sub-task, so no
/// second incarnation ever coexists. The actor runs as an unmanaged byzantine node and
/// its equivocation is excluded from the safety oracle via the honest reporters (see
/// [`crate::mallory::runner`]).
///
/// Single-owner: the Disrupter takes all three channels; the Equivocator takes the
/// vote and certificate channels (dropping resolver); the Conflicter, Nuller,
/// Impersonator, and Outdated take only the vote channel and explicitly drop the
/// certificate and resolver channels.
///
/// `relay` and `elector` are used only by the [`AdversaryRole::Equivocator`], which
/// broadcasts its conflicting payloads via the shared relay and shares the honest
/// nodes' leader schedule (`elector`, the same [`Simplex::Elector`] config the
/// honest validators build); the other roles ignore them.
///
/// Must be called only for a Byzantine role; [`AdversaryRole::Honest`] builds a
/// managed validator instead.
pub(crate) fn spawn_adversary<P: Simplex>(
    role: AdversaryRole,
    context: deterministic::Context,
    scheme: P::Scheme,
    required_containers: u64,
    relay: Arc<relay::Relay<Sha256Digest, PublicKeyOf<P>>>,
    elector: P::Elector,
    channels: NetworkChannels<PublicKeyOf<P>>,
) -> Handle<()> {
    let (vote_network, certificate_network, resolver_network) = channels;
    match role {
        AdversaryRole::Honest => {
            unreachable!("spawn_adversary is only called for a byzantine role")
        }
        AdversaryRole::Disrupter => {
            // Full byzantine engine: consumes ALL THREE channels, stamped with the
            // harness-wide `EPOCH` (in-epoch adversary, not wrong-epoch noise). The
            // disrupter draws from the shared runtime RNG while running; this is
            // still deterministic under the single-threaded scheduler but couples
            // the stream to the disrupter's timing (acceptable: the role is fixed
            // for the observation window). Built inline (rather than via
            // `start_disrupter`) so the actor's `Handle` flows back to the caller;
            // the AnyScope path is the only strategy the adversary profiles use.
            let disrupter = Disrupter::new_with_epoch(
                context.child("adversary_disrupter"),
                scheme,
                AnyScope,
                required_containers,
                Epoch::new(crate::EPOCH),
            );
            disrupter.start(vote_network, certificate_network, resolver_network)
        }
        AdversaryRole::Conflicter => {
            // Vote-only: drop the certificate and resolver channels so no second
            // owner holds their single-consumer mailboxes.
            drop(certificate_network);
            drop(resolver_network);
            let actor = conflicter::Conflicter::<_, P::Scheme, Sha256>::new(
                context.child("adversary_conflicter"),
                conflicter::Config { scheme },
            );
            actor.start(vote_network)
        }
        AdversaryRole::Nuller => {
            drop(certificate_network);
            drop(resolver_network);
            let actor = nuller::Nuller::<_, P::Scheme, Sha256>::new(
                context.child("adversary_nuller"),
                nuller::Config { scheme },
            );
            actor.start(vote_network)
        }
        AdversaryRole::Equivocator => {
            // Consumes vote + certificate: listens to recovered certificates and
            // equivocates on the vote channel. Drop only the resolver channel.
            // Stamped with the harness-wide `EPOCH` and given the honest nodes'
            // leader schedule (`elector`) so it equivocates as the elected leader.
            drop(resolver_network);
            let actor = equivocator::Equivocator::new(
                context.child("adversary_equivocator"),
                equivocator::Config {
                    scheme,
                    epoch: Epoch::new(crate::EPOCH),
                    relay,
                    hasher: Sha256::default(),
                    elector,
                },
            );
            actor.start(vote_network, certificate_network)
        }
        AdversaryRole::Impersonator => {
            // Vote-only (like Conflicter/Nuller): drop the certificate and resolver
            // channels so no second owner holds their single-consumer mailboxes.
            drop(certificate_network);
            drop(resolver_network);
            let actor = impersonator::Impersonator::<_, P::Scheme, Sha256>::new(
                context.child("adversary_impersonator"),
                impersonator::Config { scheme },
            );
            actor.start(vote_network)
        }
        AdversaryRole::Outdated => {
            drop(certificate_network);
            drop(resolver_network);
            let actor = outdated::Outdated::<_, P::Scheme, Sha256>::new(
                context.child("adversary_outdated"),
                outdated::Config {
                    scheme,
                    // Small delta so the stale resend fires within a short episode:
                    // re-notarize/finalize the proposal from one view back.
                    view_delta: ViewDelta::new(1),
                },
            );
            actor.start(vote_network)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::FuzzRng;

    /// Every role, in a stable order, for exhaustive test coverage.
    const ALL_ROLES: [AdversaryRole; 7] = [
        AdversaryRole::Honest,
        AdversaryRole::Disrupter,
        AdversaryRole::Conflicter,
        AdversaryRole::Nuller,
        AdversaryRole::Equivocator,
        AdversaryRole::Impersonator,
        AdversaryRole::Outdated,
    ];

    #[test]
    fn sample_is_deterministic_and_covers_every_role() {
        // Same seed reproduces the same role sequence (replay determinism) and the
        // uniform draw reaches all seven roles over a modest number of samples.
        let seed = vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15];
        let mut a = FuzzRng::new(seed.clone());
        let mut b = FuzzRng::new(seed);
        let mut seen = [false; 7];
        for _ in 0..256 {
            let role = AdversaryRole::sample(&mut a);
            assert_eq!(
                role,
                AdversaryRole::sample(&mut b),
                "sample must be deterministic"
            );
            let idx = ALL_ROLES.iter().position(|&r| r == role).unwrap();
            seen[idx] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "every role must be sampled: {seen:?}"
        );
    }

    #[test]
    fn sample_byzantine_is_deterministic_and_never_honest() {
        // The SwapByzantineRole target sampler covers all six Byzantine roles, never Honest,
        // and a fixed seed reproduces the sequence (replay determinism).
        let seed = vec![0x24, 0x8b, 0xf1, 0x0e, 0x77, 0x35, 0xac, 0x51];
        let mut a = FuzzRng::new(seed.clone());
        let mut b = FuzzRng::new(seed);
        let mut seen = [false; 6];
        for _ in 0..256 {
            let role = AdversaryRole::sample_byzantine(&mut a);
            assert_eq!(
                role,
                AdversaryRole::sample_byzantine(&mut b),
                "sample_byzantine must be deterministic"
            );
            assert!(
                role.is_byzantine(),
                "sample_byzantine must never yield Honest"
            );
            // index 1..=6 are the byzantine roles; map to a 0..6 slot.
            seen[role.index() - 1] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "every byzantine role must be sampled: {seen:?}"
        );
    }

    #[test]
    fn is_byzantine_only_false_for_honest() {
        assert!(!AdversaryRole::Honest.is_byzantine());
        for role in ALL_ROLES
            .into_iter()
            .filter(|r| *r != AdversaryRole::Honest)
        {
            assert!(role.is_byzantine(), "{role:?} must be byzantine");
        }
    }

    #[test]
    fn labels_are_distinct_and_stable() {
        assert_eq!(AdversaryRole::Honest.label(), "honest");
        assert_eq!(AdversaryRole::Disrupter.label(), "disrupter");
        assert_eq!(AdversaryRole::Conflicter.label(), "conflicter");
        assert_eq!(AdversaryRole::Nuller.label(), "nuller");
        assert_eq!(AdversaryRole::Equivocator.label(), "equivocator");
        assert_eq!(AdversaryRole::Impersonator.label(), "impersonator");
        assert_eq!(AdversaryRole::Outdated.label(), "outdated");
        // Distinct across all roles (a shared label would confuse the decision log).
        let mut labels: Vec<&str> = ALL_ROLES.iter().map(|r| r.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), ALL_ROLES.len(), "labels must be distinct");
    }

    #[test]
    fn role_tag_separates_q_state() {
        // Honest is the identity mix, so warm honest Q-rows are unchanged; every
        // byzantine role keys a distinct row from Honest and from each other for the
        // same fingerprint, so a campaign never merges incompatible environments.
        // (Distinctness from the runner's AMNESIA_TAG is asserted in the runner's
        // `env_tag_separates_post_amnesia_from_every_other_environment` test, where
        // that constant is in scope.)
        let fp = 0x0123_4567_89ab_cdefu64;
        assert_eq!(
            AdversaryRole::Honest.tag(),
            0,
            "honest tag must be the identity"
        );
        assert_eq!(fp ^ AdversaryRole::Honest.tag(), fp);
        for (i, a) in ALL_ROLES.iter().enumerate() {
            for b in &ALL_ROLES[i + 1..] {
                assert_ne!(
                    fp ^ a.tag(),
                    fp ^ b.tag(),
                    "{a:?} and {b:?} must key distinct Q-rows for the same fingerprint"
                );
            }
        }
    }

    #[test]
    fn index_round_trips_and_matches_sample_order() {
        // COUNT spans every role, index/from_index are inverse, and the index order
        // matches the uniform `sample` catalog order (Honest is 0).
        assert_eq!(AdversaryRole::COUNT, ALL_ROLES.len());
        assert_eq!(AdversaryRole::Honest.index(), 0);
        for (i, &role) in ALL_ROLES.iter().enumerate() {
            assert_eq!(role.index(), i, "{role:?} index must match catalog order");
            assert_eq!(
                AdversaryRole::from_index(i),
                role,
                "from_index inverts index"
            );
        }
    }

    #[test]
    fn role_bandit_softmax_is_valid_and_uniform_at_zero_q() {
        // A fresh (all-zero) bandit is a uniform distribution over the roles.
        let dist = RoleBandit::default().softmax();
        let sum: f64 = dist.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "distribution must sum to 1");
        for p in dist {
            assert!(
                (p - 1.0 / AdversaryRole::COUNT as f64).abs() < 1e-9,
                "a zero-q bandit must be uniform"
            );
        }
    }

    #[test]
    fn role_bandit_ranks_by_novelty_density_not_episode_length() {
        // Production rewards are the per-step AVERAGE novelty in [-2, 0]. The bug this
        // guards: a short unproductive episode (a 1-step crash-stop, avg -2) must NOT
        // outrank a long productive one (12 steps, 20/24 novel -> avg -4/12 = -0.33).
        // The pre-fix raw sum was -2 vs -4 and wrongly favored the crash.
        let mut bandit = RoleBandit::default();
        bandit.learn(AdversaryRole::Honest, -2.0); // short, discovered nothing
        bandit.learn(AdversaryRole::Disrupter, -4.0 / 12.0); // long, productive
        let dist = bandit.softmax();
        assert!(
            dist[AdversaryRole::Disrupter.index()] > dist[AdversaryRole::Honest.index()],
            "the higher novelty-per-step role must win: {} vs {}",
            dist[AdversaryRole::Disrupter.index()],
            dist[AdversaryRole::Honest.index()],
        );
    }

    #[test]
    fn role_bandit_keeps_untried_roles_optimistic() {
        // Nonpositive rewards keep an untried role (q = 0) above any explored role, so
        // the bandit explores all roles before concentrating; among explored roles the
        // less-negative (more productive) one wins.
        let mut bandit = RoleBandit::default();
        bandit.learn(AdversaryRole::Disrupter, -0.3); // explored, productive
        bandit.learn(AdversaryRole::Nuller, -1.5); // explored, less productive
        let dist = bandit.softmax();
        assert!(
            dist[AdversaryRole::Honest.index()] > dist[AdversaryRole::Disrupter.index()],
            "an untried role stays optimistic (above any explored role)"
        );
        assert!(
            dist[AdversaryRole::Disrupter.index()] > dist[AdversaryRole::Nuller.index()],
            "among explored roles the more productive one wins"
        );
    }

    #[test]
    fn role_bandit_select_is_in_range_and_deterministic() {
        // Every draw is a valid role, and a fixed FuzzRng seed reproduces the sequence.
        let mut bandit = RoleBandit::default();
        bandit.learn(AdversaryRole::Equivocator, -0.5);
        let draw = || {
            let mut rng = FuzzRng::new(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            (0..16).map(|_| bandit.select(&mut rng)).collect::<Vec<_>>()
        };
        let first = draw();
        assert!(
            first.iter().all(|r| ALL_ROLES.contains(r)),
            "select must return a valid role"
        );
        assert_eq!(first, draw(), "same RNG seed must yield the same roles");
    }
}
