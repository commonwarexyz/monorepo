//! Episode-level Byzantine adversary profiles for `Mode::Mallory`.
//!
//! Where [`action`](super::action) perturbs only the network, an adversary *role*
//! replaces the single faultable identity ([`crate::BYZANTINE_IDX`]) with an
//! explicit Byzantine actor for the WHOLE episode. The role is an environment
//! property sampled once at setup, not a per-step policy action, so it never
//! enters the action catalog and adds no catalog id. Node 0 then runs as a raw,
//! unmanaged byzantine node: it gets its registered channels directly, with no
//! packet pump, no [`SniffingReceiver`](crate::SniffingReceiver), no reporter, and
//! no [`ManagedValidator`](crate::ManagedValidator). The other three nodes stay
//! honest and form the N4F0C4 quorum of three.
//!
//! Three profiles, each an existing mock:
//!
//! - [`AdversaryRole::Disrupter`]: a full byzantine engine ([`crate::disrupter`])
//!   that emits on ALL THREE consensus channels (vote, certificate, resolver).
//! - [`AdversaryRole::Conflicter`]: emits a conflicting notarize/finalize pair on
//!   the VOTE channel only (`conflicter`).
//! - [`AdversaryRole::Nuller`]: emits a nullify+finalize pair for the same view on
//!   the VOTE channel only (`nuller`).
//!
//! # Single-owner rule
//!
//! Each channel mailbox is single-consumer, so exactly one owner is spawned at
//! node 0. The Disrupter consumes all three channels; the Conflicter and Nuller
//! consume only the vote channel and explicitly drop the certificate and resolver
//! channels (freeing those receivers rather than leaving a second owner).

use crate::{simplex::Simplex, strategy::StrategyChoice, NetworkChannels, PublicKeyOf};
use commonware_consensus::simplex::mocks::{conflicter, nuller};
use commonware_cryptography::Sha256;
use commonware_runtime::{deterministic, Supervisor as _};
use rand::{Rng, RngExt as _};

/// The Byzantine profile node 0 plays for a whole Mallory episode.
///
/// Sampled once at setup from the runtime `FuzzRng` and held for the episode, so a
/// replay reproduces it. Folded into the Q-state (via [`tag`](Self::tag)) so a
/// campaign never merges incompatible environments (Honest and each Byzantine role
/// are distinct Q-rows and novelty registries).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AdversaryRole {
    /// Node 0 is an honest [`ManagedValidator`](crate::ManagedValidator) like the
    /// other three (the pre-adversary environment).
    Honest,
    /// Node 0 is a [`Disrupter`](crate::disrupter::Disrupter) emitting on all three
    /// consensus channels.
    Disrupter,
    /// Node 0 is a conflicter emitting conflicting notarize/finalize pairs on the
    /// vote channel.
    Conflicter,
    /// Node 0 is a nuller emitting nullify+finalize for the same view on the vote
    /// channel.
    Nuller,
}

impl AdversaryRole {
    /// Uniformly sample a role from the runtime RNG. Drawn once at setup, before the
    /// per-node loop, so the whole episode runs under one fixed environment.
    pub(crate) fn sample(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..4u8) {
            0 => AdversaryRole::Honest,
            1 => AdversaryRole::Disrupter,
            2 => AdversaryRole::Conflicter,
            _ => AdversaryRole::Nuller,
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
        }
    }

    /// Whether this role replaces node 0 with a Byzantine actor (everything except
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
        }
    }
}

/// Spawn the Byzantine actor for `role` at node 0 with its RAW registered channels
/// (no pump, no sniffer, no reporter, no [`ManagedValidator`](crate::ManagedValidator)).
///
/// Single-owner: the Disrupter takes all three channels; the Conflicter and Nuller
/// take only the vote channel and explicitly drop the certificate and resolver
/// channels. Nothing observable is returned -- the actor runs as an unmanaged
/// byzantine node and its equivocation is excluded from the safety oracle via the
/// honest reporters (see [`crate::mallory::runner`]).
///
/// Must be called only for a Byzantine role; [`AdversaryRole::Honest`] builds a
/// managed validator instead.
pub(crate) fn spawn_adversary<P: Simplex>(
    role: AdversaryRole,
    context: deterministic::Context,
    scheme: P::Scheme,
    required_containers: u64,
    channels: NetworkChannels<PublicKeyOf<P>>,
) {
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
            // for the episode).
            crate::start_disrupter::<P>(
                context.child("adversary_disrupter"),
                scheme,
                &StrategyChoice::AnyScope,
                required_containers,
                vote_network,
                certificate_network,
                resolver_network,
            );
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
            actor.start(vote_network);
        }
        AdversaryRole::Nuller => {
            drop(certificate_network);
            drop(resolver_network);
            let actor = nuller::Nuller::<_, P::Scheme, Sha256>::new(
                context.child("adversary_nuller"),
                nuller::Config { scheme },
            );
            actor.start(vote_network);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::FuzzRng;

    #[test]
    fn sample_is_deterministic_and_covers_every_role() {
        // Same seed reproduces the same role sequence (replay determinism) and the
        // uniform draw reaches all four roles over a modest number of samples.
        let seed = vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15];
        let mut a = FuzzRng::new(seed.clone());
        let mut b = FuzzRng::new(seed);
        let mut seen = [false; 4];
        for _ in 0..256 {
            let role = AdversaryRole::sample(&mut a);
            assert_eq!(role, AdversaryRole::sample(&mut b), "sample must be deterministic");
            let idx = match role {
                AdversaryRole::Honest => 0,
                AdversaryRole::Disrupter => 1,
                AdversaryRole::Conflicter => 2,
                AdversaryRole::Nuller => 3,
            };
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s), "every role must be sampled: {seen:?}");
    }

    #[test]
    fn is_byzantine_only_false_for_honest() {
        assert!(!AdversaryRole::Honest.is_byzantine());
        for role in [
            AdversaryRole::Disrupter,
            AdversaryRole::Conflicter,
            AdversaryRole::Nuller,
        ] {
            assert!(role.is_byzantine(), "{role:?} must be byzantine");
        }
    }

    #[test]
    fn labels_are_distinct_and_stable() {
        assert_eq!(AdversaryRole::Honest.label(), "honest");
        assert_eq!(AdversaryRole::Disrupter.label(), "disrupter");
        assert_eq!(AdversaryRole::Conflicter.label(), "conflicter");
        assert_eq!(AdversaryRole::Nuller.label(), "nuller");
    }

    #[test]
    fn role_tag_separates_q_state() {
        // Honest is the identity mix, so warm honest Q-rows are unchanged; every
        // byzantine role keys a distinct row from Honest and from each other for the
        // same fingerprint, so a campaign never merges incompatible environments.
        let fp = 0x0123_4567_89ab_cdefu64;
        assert_eq!(AdversaryRole::Honest.tag(), 0, "honest tag must be the identity");
        assert_eq!(fp ^ AdversaryRole::Honest.tag(), fp);
        let roles = [
            AdversaryRole::Honest,
            AdversaryRole::Disrupter,
            AdversaryRole::Conflicter,
            AdversaryRole::Nuller,
        ];
        for (i, a) in roles.iter().enumerate() {
            for b in &roles[i + 1..] {
                assert_ne!(
                    fp ^ a.tag(),
                    fp ^ b.tag(),
                    "{a:?} and {b:?} must key distinct Q-rows for the same fingerprint"
                );
            }
        }
    }
}
