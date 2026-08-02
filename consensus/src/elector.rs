//! Protocol-neutral leader election.
//!
//! A consensus protocol picks one leader per round from an ordered participant set. This module
//! owns that abstraction so every protocol in this crate shares one contract, one term model, and
//! one set of reusable electors.
//!
//! # Determinism
//!
//! [`Elector::elect`] must be a pure function of the elector's construction parameters and its
//! arguments: every honest participant must select the same leader for the same round and the same
//! evidence. A non-deterministic elector is a safety bug, not a liveness one.
//!
//! # Evidence
//!
//! Randomized election needs a per-round value that no participant can predict or grind. The
//! `Evidence` type parameter names whatever a protocol can supply for that, such as a unique
//! threshold certificate. A protocol that produces no such value uses `()` and can then only
//! configure deterministic schedules like [`RoundRobin`].

use crate::types::{Participant, Round, TermLength, ViewDelta};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, PublicKey, Sha256};
use commonware_utils::ordered::Set;
use std::{marker::PhantomData, time::Duration};

/// Leadership term structure reported by an [`Elector`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terms {
    /// Number of consecutive views per term (one if and only if rotating).
    length: TermLength,
    /// Term-abandonment timeout (set if and only if `length` exceeds one).
    stall_timeout: Option<Duration>,
    /// Optimistic intra-term lookahead (zero unless `length` exceeds one).
    optimistic_views: ViewDelta,
}

impl Terms {
    /// Every view is its own term: a new leader is elected each view, and
    /// leader rotation itself bounds how long finality can stall.
    pub const fn rotating() -> Self {
        Self {
            length: TermLength::ONE,
            stall_timeout: None,
            optimistic_views: ViewDelta::zero(),
        }
    }

    /// Views are grouped into terms of `length` consecutive views served by
    /// one leader.
    ///
    /// The length is consensus-critical: every participant must configure
    /// the same value (see [`TermLength`]).
    ///
    /// `stall_timeout` is local policy: the maximum time an entered view may
    /// remain unfinalized before this participant abandons the term. On
    /// expiry it treats its current view as timed out and votes nullify,
    /// which (with a quorum) forms a nullification covering the rest of the
    /// term and evicts the leader.
    ///
    /// A Byzantine stable leader can keep every per-view timer satisfied
    /// while preventing finality: each view notarizes and certifies, but
    /// no finalization certificate forms. With single-view terms, leader
    /// rotation bounds such a stall to one view. With longer terms, this
    /// timeout bounds it instead.
    ///
    /// # Panics
    ///
    /// Panics if `length` is 1 or if `stall_timeout` is zero. Single-view
    /// terms are [`Terms::rotating`] (the default), where per-view timeouts
    /// already bound a stall.
    pub const fn stable(
        length: TermLength,
        stall_timeout: Duration,
        optimistic_views: ViewDelta,
    ) -> Self {
        assert!(
            length.get() > 1,
            "stable leaders require a term length greater than 1"
        );
        assert!(
            !stall_timeout.is_zero(),
            "stable leaders require a stall timeout greater than zero"
        );
        Self {
            length,
            stall_timeout: Some(stall_timeout),
            optimistic_views,
        }
    }

    /// Returns the number of consecutive views per term.
    ///
    /// Returns [`TermLength::ONE`] if and only if this is [`Terms::rotating`].
    /// A length of one is the definition of rotation, not an approximation of
    /// it: all term arithmetic ([`crate::types::View::covers`],
    /// [`crate::types::View::admits`], [`crate::types::View::term_index`],
    /// [`crate::types::View::next_term_start`]) reduces exactly to per-view
    /// behavior at length one. The only regime fact the length does not carry
    /// is the stall deadline, which callers read from
    /// [`Terms::stall_timeout`].
    pub const fn length(&self) -> TermLength {
        self.length
    }

    /// Returns the term-abandonment timeout, if stable leaders are configured.
    ///
    /// Returns `Some` if and only if [`Self::length`] is greater than one.
    pub const fn stall_timeout(&self) -> Option<Duration> {
        self.stall_timeout
    }

    /// Returns the optimistic intra-term lookahead.
    ///
    /// Always zero when [`Self::length`] is one.
    pub const fn optimistic_views(&self) -> ViewDelta {
        self.optimistic_views
    }
}

impl Default for Terms {
    fn default() -> Self {
        Self::rotating()
    }
}

/// Configuration that builds an [`Elector`] once the participant set is known.
///
/// Users create and configure this type, then pass it to a consensus configuration; consensus
/// calls [`build`](Config::build) internally with the correct participants.
pub trait Config<P: PublicKey, Evidence>: Clone + Default + Send + 'static {
    /// The initialized elector type.
    type Elector: Elector<Evidence>;

    /// Builds the elector with the given participants.
    ///
    /// # Panics
    ///
    /// Implementations should panic if `participants` is empty.
    fn build(self, participants: &Set<P>) -> Self::Elector;
}

/// An initialized elector that selects leaders for consensus rounds.
///
/// See the module documentation for the determinism requirement and the meaning of `Evidence`.
pub trait Elector<Evidence>: Clone + Send + 'static {
    /// Returns the leadership term structure this elector was built with.
    ///
    /// Callers that need term arithmetic should use this value so leader election and protocol
    /// term handling stay aligned.
    fn terms(&self) -> Terms;

    /// Selects the leader for `round`.
    ///
    /// Implementations must return the same leader for every view within a stable-leader term (as
    /// defined by [`Self::terms`]).
    ///
    /// `evidence` is `None` when the protocol has no value to supply for this round, which
    /// includes every round of a protocol whose evidence type is `()`.
    fn elect(&self, round: Round, evidence: Option<&Evidence>) -> Participant;
}

/// Configuration for round-robin leader election.
///
/// Rotates through participants based on `(epoch + term) % num_participants`, where `term` is the
/// stable-leader term containing the view.
/// The rotation order can be shuffled at construction using a seed.
///
/// Works with any signing scheme.
#[derive(Debug, Default)]
pub struct RoundRobin<H: Hasher = Sha256> {
    seed: Option<Vec<u8>>,
    terms: Terms,
    _phantom: PhantomData<H>,
}

impl<H: Hasher> Clone for RoundRobin<H> {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed.clone(),
            terms: self.terms,
            _phantom: PhantomData,
        }
    }
}

impl<H: Hasher> RoundRobin<H> {
    /// Creates a round-robin config that will shuffle the rotation order based on seed.
    ///
    /// The seed is used during [`Config::build`] to deterministically
    /// shuffle the permutation.
    pub fn shuffled(seed: &[u8]) -> Self {
        Self {
            seed: Some(seed.to_vec()),
            terms: Terms::rotating(),
            _phantom: PhantomData,
        }
    }

    /// Enables stable leaders: `term_length` consecutive views share a leader,
    /// a term abandoned after `stall_timeout` evicts them, and participants
    /// may run up to `optimistic_views` ahead within a term.
    ///
    /// The term length is consensus-critical: every participant must configure
    /// the same value (see [`TermLength`]). The timeout is local policy.
    ///
    /// # Panics
    ///
    /// Panics if `term_length` is 1 or `stall_timeout` is zero (see
    /// [`Terms::stable`]).
    pub const fn with_term(
        mut self,
        term_length: TermLength,
        stall_timeout: Duration,
        optimistic_views: ViewDelta,
    ) -> Self {
        self.terms = Terms::stable(term_length, stall_timeout, optimistic_views);
        self
    }
}

impl<H: Hasher> RoundRobin<H> {
    /// Builds the rotation over `participants` participants.
    ///
    /// [`Config::build`] delegates here. Call this directly to avoid naming an evidence type at
    /// the call site: this config satisfies [`Config`] for every one.
    ///
    /// # Panics
    ///
    /// Panics if `participants` is zero.
    pub fn rotation(self, participants: usize) -> RoundRobinElector {
        assert!(participants > 0, "no participants");

        let mut permutation: Vec<Participant> =
            (0..participants).map(Participant::from_usize).collect();
        if let Some(seed) = &self.seed {
            permutation.sort_by_key(|&index| H::hash(&[seed, &index.get().encode()]));
        }

        RoundRobinElector {
            permutation,
            terms: self.terms,
        }
    }
}

impl<P: PublicKey, Evidence, H: Hasher> Config<P, Evidence> for RoundRobin<H> {
    type Elector = RoundRobinElector;

    fn build(self, participants: &Set<P>) -> RoundRobinElector {
        self.rotation(participants.len())
    }
}

/// Initialized round-robin leader elector.
///
/// Created via [`Config::build`] on [`RoundRobin`]. It ignores evidence, so it satisfies
/// [`Elector`] for every evidence type.
#[derive(Clone, Debug)]
pub struct RoundRobinElector {
    permutation: Vec<Participant>,
    terms: Terms,
}

impl RoundRobinElector {
    /// Returns the rotation order this elector cycles through.
    pub fn permutation(&self) -> &[Participant] {
        &self.permutation
    }

    /// Returns the leader for `round`.
    ///
    /// This elector ignores evidence, so it implements [`Elector`] for every evidence type; call
    /// this inherent method to avoid annotating one at the call site.
    pub fn leader(&self, round: Round) -> Participant {
        // In order to get a stable leader, use the 1-based index of the term
        let term_idx = round.view().term_index(self.terms.length());

        // Incorporate the epoch number
        let n = self.permutation.len();
        let idx = round.epoch().get().wrapping_add(term_idx)
            % u64::try_from(n).expect("permutation length fits in u64");
        let idx = usize::try_from(idx).expect("leader index fits in usize");
        self.permutation[idx]
    }
}

impl<Evidence> Elector<Evidence> for RoundRobinElector {
    fn terms(&self) -> Terms {
        self.terms
    }

    fn elect(&self, round: Round, _evidence: Option<&Evidence>) -> Participant {
        self.leader(round)
    }
}
