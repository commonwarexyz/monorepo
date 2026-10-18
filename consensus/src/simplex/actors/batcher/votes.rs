//! Per-view vote tracking for the batcher.

use crate::{
    simplex::types::{Attributable, AttributableMap, Finalize, Notarize, Nullify, Proposal, Vote},
    types::Participant,
};
use commonware_cryptography::{Digest, certificate::Scheme};

/// Full vote storage for a phase, or a marker that full votes are not retained
/// (its certificate was recorded or the view was skipped).
enum Phase<T: Attributable> {
    Full(AttributableMap<T>),
    Compacted,
}

impl<T: Attributable> Phase<T> {
    const fn new(participants: usize) -> Self {
        Self::Full(AttributableMap::new(participants))
    }

    fn get(&self, signer: Participant) -> Option<&T> {
        match self {
            Self::Full(votes) => votes.get(signer),
            Self::Compacted => None,
        }
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        match self {
            Self::Full(votes) => Some(votes),
            Self::Compacted => None,
        }
        .into_iter()
        .flat_map(AttributableMap::iter)
    }

    fn compact(&mut self) -> Option<AttributableMap<T>> {
        match std::mem::replace(self, Self::Compacted) {
            Self::Full(votes) => Some(votes),
            Self::Compacted => None,
        }
    }
}

/// Bit positions of one phase's compact signer facts within [VoteTracker::compacted].
#[derive(Clone, Copy)]
struct PhaseBits {
    /// The signer voted in the phase.
    seen: u8,
    /// The signer's vote carried the authoritative proposal.
    has_proposal: u8,
    /// The signer's vote was compared with the authoritative proposal. Until
    /// then a clear `has_proposal` means unknown rather than a mismatch, so no
    /// conflict is inferred from it.
    relation: u8,
}

/// Tracks notarize/nullify/finalize votes for a view.
///
/// Each vote type is stored in its own lazily allocated phase so a validator can
/// contribute at most one vote per phase. Compact signer facts replace full votes
/// once a phase certifies, or from the start for a skipped view, while preserving
/// forwarding, duplicate suppression, and compact conflict detection.
pub(super) struct VoteTracker<S: Scheme, D: Digest> {
    participants: usize,
    retain_votes_after_certification: bool,
    /// Per-signer facts for compacted phases (see [PhaseBits]): whether the signer
    /// voted suppresses duplicates and cross-phase conflicts; whether its vote was
    /// compared with the authoritative proposal, and matched it, infers same-phase
    /// conflicts and avoids forwarding a block to validators that already have it.
    compacted: Vec<u8>,
    notarizes: Phase<Notarize<S, D>>,
    nullifies: Phase<Nullify<S>>,
    /// Finalize votes include the proposal digest so the entire certificate can be
    /// reconstructed once the quorum threshold is hit.
    finalizes: Phase<Finalize<S, D>>,
}

/// Outcome of recording a vote in its phase-specific lifecycle state.
pub(super) enum Outcome {
    /// Newly recorded, with the full vote retained when `retained` is true.
    Added { retained: bool },
    /// Not newly recorded, with full votes still retained when `retained` is true.
    Duplicate { retained: bool },
    /// The compact proposal relation proves a same-phase conflict.
    Conflicting,
}

/// A recorded vote retained in full or represented by compact signer state.
pub(super) enum ObservedVote<'a, T> {
    Retained(&'a T),
    Compacted,
}

impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    const NOTARIZE: PhaseBits = PhaseBits {
        seen: 1 << 0,
        has_proposal: 1 << 1,
        relation: 1 << 2,
    };
    const NULLIFY: PhaseBits = PhaseBits {
        seen: 1 << 3,
        has_proposal: 0,
        relation: 0,
    };
    const FINALIZE: PhaseBits = PhaseBits {
        seen: 1 << 4,
        has_proposal: 1 << 5,
        relation: 1 << 6,
    };

    /// Creates a tracker sized for `participants` validators.
    ///
    /// When `retain_votes_after_certification` is false, full votes are released
    /// once their phase certifies. Otherwise they remain until the tracker is
    /// dropped.
    pub(super) const fn new(participants: usize, retain_votes_after_certification: bool) -> Self {
        Self {
            participants,
            retain_votes_after_certification,
            compacted: Vec::new(),
            notarizes: Phase::new(participants),
            nullifies: Phase::new(participants),
            finalizes: Phase::new(participants),
        }
    }

    /// Creates a tracker for a view this node skipped, which keeps only compact
    /// signer facts from the start.
    ///
    /// Votes are deduplicated and reported but never retained for assembly, so a
    /// round costs one byte per signer rather than a vote map per phase.
    pub(super) const fn skipped(participants: usize) -> Self {
        Self {
            participants,
            retain_votes_after_certification: false,
            compacted: Vec::new(),
            notarizes: Phase::Compacted,
            nullifies: Phase::Compacted,
            finalizes: Phase::Compacted,
        }
    }

    /// Records monotonic signer facts in a compacted phase.
    ///
    /// `matches` tells whether the vote carries the authoritative proposal, or is
    /// `None` when no proposal is known yet. A conflict is inferred only against
    /// a relation that was itself established by a comparison; a later matching
    /// vote can record that the signer has the authoritative proposal even when
    /// the signer was already observed.
    fn remember(
        participants: usize,
        compacted: &mut Vec<u8>,
        signer: Participant,
        bits: PhaseBits,
        matches: Option<bool>,
    ) -> Outcome {
        let index = usize::from(signer);
        if index >= participants {
            return Outcome::Duplicate { retained: false };
        }

        // Certificate-first rounds remain allocation-free until a vote arrives.
        if compacted.is_empty() {
            compacted.resize(participants, 0);
        }

        let flags = &mut compacted[index];
        let previously_seen = *flags & bits.seen != 0;
        let proposal_conflict = matches.is_some_and(|matches| {
            previously_seen
                && *flags & bits.relation != 0
                && (*flags & bits.has_proposal != 0) != matches
        });
        *flags |= bits.seen;
        if let Some(matches) = matches {
            *flags |= bits.relation;
            if matches {
                *flags |= bits.has_proposal;
            }
        }
        if !previously_seen {
            Outcome::Added { retained: false }
        } else if proposal_conflict {
            Outcome::Conflicting
        } else {
            Outcome::Duplicate { retained: false }
        }
    }

    /// Records one phase according to its full-to-compact storage lifecycle.
    ///
    /// A full phase owns duplicate detection and full-vote storage. A compacted
    /// phase retains only signer facts.
    fn record_phase<T: Attributable + Clone>(
        participants: usize,
        compacted: &mut Vec<u8>,
        phase: &mut Phase<T>,
        vote: &T,
        bits: PhaseBits,
        matches: Option<bool>,
    ) -> Outcome {
        match phase {
            Phase::Full(votes) => {
                if votes.insert(vote.clone()) {
                    Outcome::Added { retained: true }
                } else {
                    Outcome::Duplicate { retained: true }
                }
            }
            Phase::Compacted => {
                Self::remember(participants, compacted, vote.signer(), bits, matches)
            }
        }
    }

    fn remembered(&self, signer: Participant, flag: u8) -> bool {
        self.compacted
            .get(usize::from(signer))
            .is_some_and(|flags| flags & flag != 0)
    }

    /// Records a vote in full or as compact state.
    ///
    /// `proposal` identifies the authoritative proposal used for compact match state.
    pub(super) fn record(&mut self, vote: &Vote<S, D>, proposal: Option<&Proposal<D>>) -> Outcome {
        match vote {
            Vote::Notarize(notarize) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.notarizes,
                notarize,
                Self::NOTARIZE,
                proposal.map(|proposal| proposal == &notarize.proposal),
            ),
            Vote::Nullify(nullify) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.nullifies,
                nullify,
                Self::NULLIFY,
                None,
            ),
            Vote::Finalize(finalize) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.finalizes,
                finalize,
                Self::FINALIZE,
                proposal.map(|proposal| proposal == &finalize.proposal),
            ),
        }
    }

    /// Moves a phase from full vote storage to compact signer state.
    ///
    /// Taking the map makes the transition idempotent. Empty phases remain
    /// allocation-free, while existing signer and proposal-match facts survive.
    fn release<T: Attributable>(
        participants: usize,
        compacted: &mut Vec<u8>,
        phase: &mut Phase<T>,
        bits: PhaseBits,
        carries_proposal: impl Fn(&T) -> bool,
    ) {
        let Some(votes) = phase.compact() else {
            return;
        };

        // A certificate may arrive before any individual votes, in which case there
        // are no signer facts worth allocating a table for.
        if !votes.is_empty() && compacted.is_empty() {
            compacted.resize(participants, 0);
        }

        // Proposal-match bits are relative to the certificate-backed proposal.
        for vote in votes.iter() {
            let flags = &mut compacted[usize::from(vote.signer())];
            *flags |= bits.seen | bits.relation;
            if carries_proposal(vote) {
                *flags |= bits.has_proposal;
            }
        }
    }

    /// Returns the retained or compact state for a previously observed nullify vote.
    pub(super) fn saw_nullify(&self, signer: Participant) -> Option<ObservedVote<'_, Nullify<S>>> {
        self.nullify(signer)
            .map(ObservedVote::Retained)
            .or_else(|| {
                self.remembered(signer, Self::NULLIFY.seen)
                    .then_some(ObservedVote::Compacted)
            })
    }

    /// Returns the retained or compact state for a previously observed finalize vote.
    pub(super) fn saw_finalize(
        &self,
        signer: Participant,
    ) -> Option<ObservedVote<'_, Finalize<S, D>>> {
        self.finalize(signer)
            .map(ObservedVote::Retained)
            .or_else(|| {
                self.remembered(signer, Self::FINALIZE.seen)
                    .then_some(ObservedVote::Compacted)
            })
    }

    /// Returns whether `signer` is known to have the authoritative proposal
    /// from notarizing it.
    pub(super) fn has_notarize_for(&self, signer: Participant, proposal: &Proposal<D>) -> bool {
        self.remembered(signer, Self::NOTARIZE.has_proposal)
            || self
                .notarize(signer)
                .is_some_and(|vote| &vote.proposal == proposal)
    }

    /// Returns whether `signer` is known to have the authoritative proposal
    /// from finalizing it.
    pub(super) fn has_finalize_for(&self, signer: Participant, proposal: &Proposal<D>) -> bool {
        self.remembered(signer, Self::FINALIZE.has_proposal)
            || self
                .finalize(signer)
                .is_some_and(|vote| &vote.proposal == proposal)
    }

    /// Releases notarize votes unless full evidence is configured for retention.
    pub(super) fn release_notarizes(&mut self, proposal: &Proposal<D>) {
        if self.retain_votes_after_certification {
            return;
        }
        Self::release(
            self.participants,
            &mut self.compacted,
            &mut self.notarizes,
            Self::NOTARIZE,
            |vote: &Notarize<S, D>| &vote.proposal == proposal,
        );
    }

    /// Releases nullify votes unless full evidence is configured for retention.
    pub(super) fn release_nullifies(&mut self) {
        if self.retain_votes_after_certification {
            return;
        }
        Self::release(
            self.participants,
            &mut self.compacted,
            &mut self.nullifies,
            Self::NULLIFY,
            |_| false,
        );
    }

    /// Releases finalize votes unless full evidence is configured for retention.
    pub(super) fn release_finalizes(&mut self, proposal: &Proposal<D>) {
        if self.retain_votes_after_certification {
            return;
        }
        Self::release(
            self.participants,
            &mut self.compacted,
            &mut self.finalizes,
            Self::FINALIZE,
            |vote: &Finalize<S, D>| &vote.proposal == proposal,
        );
    }

    /// Returns the notarize vote for `signer`, if present.
    pub(super) fn notarize(&self, signer: Participant) -> Option<&Notarize<S, D>> {
        self.notarizes.get(signer)
    }

    /// Returns the nullify vote for `signer`, if present.
    pub(super) fn nullify(&self, signer: Participant) -> Option<&Nullify<S>> {
        self.nullifies.get(signer)
    }

    /// Returns the finalize vote for `signer`, if present.
    pub(super) fn finalize(&self, signer: Participant) -> Option<&Finalize<S, D>> {
        self.finalizes.get(signer)
    }

    /// Iterates over finalize votes in signer order.
    pub(super) fn iter_finalizes(&self) -> impl Iterator<Item = &Finalize<S, D>> {
        self.finalizes.iter()
    }

    /// Returns `true` if a nullify vote has been recorded for `signer`.
    pub(super) fn has_nullify(&self, signer: Participant) -> bool {
        self.nullify(signer).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::scheme::ed25519,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256;
    use commonware_utils::test_rng;

    const NAMESPACE: &[u8] = b"test";

    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32])
    }

    #[test]
    fn test_vote_tracker_record_and_release() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 2);
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round, View::zero(), sample_digest(1));
        let scheme = &fixture.schemes[0];
        let signer = Participant::new(0);
        let votes = [
            Vote::Notarize(Notarize::sign(scheme, proposal.clone()).unwrap()),
            Vote::Nullify(Nullify::sign::<Sha256>(scheme, round).unwrap()),
            Vote::Finalize(Finalize::sign(scheme, proposal.clone()).unwrap()),
        ];
        let mut tracker = VoteTracker::new(2, false);

        for vote in &votes {
            assert!(matches!(
                tracker.record(vote, Some(&proposal)),
                Outcome::Added { retained: true }
            ));
        }
        assert!(tracker.notarize(signer).is_some());
        assert!(tracker.has_nullify(signer));
        assert!(tracker.finalize(signer).is_some());

        tracker.release_notarizes(&proposal);
        tracker.release_nullifies();
        tracker.release_finalizes(&proposal);
        assert!(tracker.notarize(signer).is_none());
        assert!(!tracker.has_nullify(signer));
        assert!(tracker.finalize(signer).is_none());
        assert!(tracker.iter_finalizes().next().is_none());
        assert!(tracker.has_notarize_for(signer, &proposal));
        assert!(tracker.has_finalize_for(signer, &proposal));
        for vote in &votes {
            assert!(matches!(
                tracker.record(vote, Some(&proposal)),
                Outcome::Duplicate { retained: false }
            ));
        }

        // Releasing a compacted phase is idempotent.
        tracker.release_notarizes(&proposal);
        assert!(tracker.has_notarize_for(signer, &proposal));
    }

    #[test]
    fn test_vote_tracker_retention_policy() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 2);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(1)),
            View::zero(),
            sample_digest(1),
        );
        let notarize = Notarize::sign(&fixture.schemes[0], proposal.clone()).unwrap();
        let signer = notarize.signer();
        let vote = Vote::Notarize(notarize);

        let mut releasing = VoteTracker::new(2, false);
        assert!(matches!(
            releasing.record(&vote, Some(&proposal)),
            Outcome::Added { retained: true }
        ));
        let Phase::Full(votes) = &releasing.notarizes else {
            panic!("notarize phase compacted before certification");
        };
        assert!(votes.capacity() >= 2);
        releasing.release_notarizes(&proposal);
        assert!(matches!(&releasing.notarizes, Phase::Compacted));
        assert!(matches!(
            releasing.record(&vote, Some(&proposal)),
            Outcome::Duplicate { retained: false }
        ));

        // A certificate can arrive before any individual votes. Subsequent votes
        // must use compact storage instead of recreating the released full map.
        let finalize =
            Vote::Finalize(Finalize::sign(&fixture.schemes[0], proposal.clone()).unwrap());
        let mut certificate_first = VoteTracker::new(2, false);
        certificate_first.release_notarizes(&proposal);
        certificate_first.release_finalizes(&proposal);
        for vote in [&vote, &finalize] {
            assert!(matches!(
                certificate_first.record(vote, Some(&proposal)),
                Outcome::Added { retained: false }
            ));
        }
        assert!(matches!(&certificate_first.notarizes, Phase::Compacted));
        assert!(matches!(&certificate_first.finalizes, Phase::Compacted));

        // Compact records still mark signers that have the proposal.
        assert!(certificate_first.has_notarize_for(signer, &proposal));
        assert!(certificate_first.has_finalize_for(signer, &proposal));
        for vote in [&vote, &finalize] {
            assert!(matches!(
                certificate_first.record(vote, Some(&proposal)),
                Outcome::Duplicate { retained: false }
            ));
        }

        let mut retaining = VoteTracker::new(2, true);
        assert!(matches!(
            retaining.record(&vote, Some(&proposal)),
            Outcome::Added { retained: true }
        ));
        let Phase::Full(votes) = &retaining.notarizes else {
            panic!("retained notarize phase compacted");
        };
        let retained_capacity = votes.capacity();
        retaining.release_notarizes(&proposal);
        let Phase::Full(votes) = &retaining.notarizes else {
            panic!("retained notarize phase compacted");
        };
        assert_eq!(votes.capacity(), retained_capacity);
        assert!(retaining.notarize(signer).is_some());
    }
}
