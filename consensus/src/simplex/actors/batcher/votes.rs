//! Per-view vote tracking for the batcher.

use crate::{
    simplex::types::{Attributable, AttributableMap, Finalize, Notarize, Nullify, Proposal, Vote},
    types::Participant,
};
use commonware_cryptography::{Digest, certificate::Scheme};

/// Full vote storage for a phase, or a marker that its certificate was recorded.
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

#[cfg(test)]
impl<T: Attributable> Phase<T> {
    fn insert(&mut self, vote: T) -> bool {
        match self {
            Self::Full(votes) => votes.insert(vote),
            Self::Compacted => false,
        }
    }

    const fn len(&self) -> usize {
        match self {
            Self::Full(votes) => votes.len(),
            Self::Compacted => 0,
        }
    }

    fn reset(&mut self, participants: usize) {
        *self = Self::new(participants);
    }
}

/// Tracks notarize/nullify/finalize votes for a view.
///
/// Each vote type is stored in its own lazily allocated phase so a validator can
/// contribute at most one vote per phase. After certification, compact signer facts
/// can replace full votes while preserving forwarding, duplicate suppression, and
/// compact conflict detection.
pub(super) struct VoteTracker<S: Scheme, D: Digest> {
    participants: usize,
    retain_votes_after_certification: bool,
    /// Compact state records whether a signer voted and whether the vote carried the
    /// authoritative proposal. The first fact suppresses duplicates and cross-phase
    /// conflicts. The second avoids forwarding a block to validators that already have it.
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
    const NOTARIZE_SEEN: u8 = 1 << 0;
    const NOTARIZE_HAS_PROPOSAL: u8 = 1 << 1;
    const NULLIFY_SEEN: u8 = 1 << 2;
    const FINALIZE_SEEN: u8 = 1 << 3;
    const FINALIZE_HAS_PROPOSAL: u8 = 1 << 4;

    /// Creates a tracker sized for `participants` validators.
    ///
    /// When `retain_votes_after_certification` is false, full votes are released
    /// once their phase certifies. Otherwise they remain until explicitly cleared
    /// or the tracker is dropped.
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

    /// Records monotonic signer facts after a phase releases its full vote map.
    ///
    /// A later matching vote can record that the signer has the authoritative
    /// proposal even when the signer was already observed.
    fn remember(
        participants: usize,
        compacted: &mut Vec<u8>,
        signer: Participant,
        seen: u8,
        proposal_relation: Option<(u8, bool)>,
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
        let previously_seen = *flags & seen != 0;
        let proposal_conflict = proposal_relation.is_some_and(|(has_proposal, matches)| {
            previously_seen && (*flags & has_proposal != 0) != matches
        });
        *flags |= seen;
        if let Some((has_proposal, true)) = proposal_relation {
            *flags |= has_proposal;
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
    /// phase retains only signer facts until explicitly cleared.
    fn record_phase<T: Attributable + Clone>(
        participants: usize,
        compacted: &mut Vec<u8>,
        phase: &mut Phase<T>,
        vote: &T,
        seen: u8,
        proposal_relation: Option<(u8, bool)>,
    ) -> Outcome {
        match phase {
            Phase::Full(votes) => {
                if votes.insert(vote.clone()) {
                    Outcome::Added { retained: true }
                } else {
                    Outcome::Duplicate { retained: true }
                }
            }
            Phase::Compacted => Self::remember(
                participants,
                compacted,
                vote.signer(),
                seen,
                proposal_relation,
            ),
        }
    }

    fn remembered(&self, signer: Participant, flag: u8) -> bool {
        self.compacted
            .get(usize::from(signer))
            .is_some_and(|flags| flags & flag != 0)
    }

    /// Records a vote in full or as compact post-certificate state.
    ///
    /// `proposal` identifies the authoritative proposal used for compact match state.
    pub(super) fn record(&mut self, vote: &Vote<S, D>, proposal: Option<&Proposal<D>>) -> Outcome {
        match vote {
            Vote::Notarize(notarize) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.notarizes,
                notarize,
                Self::NOTARIZE_SEEN,
                proposal
                    .map(|proposal| (Self::NOTARIZE_HAS_PROPOSAL, proposal == &notarize.proposal)),
            ),
            Vote::Nullify(nullify) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.nullifies,
                nullify,
                Self::NULLIFY_SEEN,
                None,
            ),
            Vote::Finalize(finalize) => Self::record_phase(
                self.participants,
                &mut self.compacted,
                &mut self.finalizes,
                finalize,
                Self::FINALIZE_SEEN,
                proposal
                    .map(|proposal| (Self::FINALIZE_HAS_PROPOSAL, proposal == &finalize.proposal)),
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
        seen: u8,
        has_proposal: u8,
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
            *flags |= seen;
            if carries_proposal(vote) {
                *flags |= has_proposal;
            }
        }
    }

    /// Returns the retained or compact state for a previously observed nullify vote.
    pub(super) fn saw_nullify(&self, signer: Participant) -> Option<ObservedVote<'_, Nullify<S>>> {
        self.nullify(signer)
            .map(ObservedVote::Retained)
            .or_else(|| {
                self.remembered(signer, Self::NULLIFY_SEEN)
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
                self.remembered(signer, Self::FINALIZE_SEEN)
                    .then_some(ObservedVote::Compacted)
            })
    }

    /// Returns whether `signer` is known to have the authoritative proposal
    /// from notarizing it.
    pub(super) fn has_notarize_for(&self, signer: Participant, proposal: &Proposal<D>) -> bool {
        self.remembered(signer, Self::NOTARIZE_HAS_PROPOSAL)
            || self
                .notarize(signer)
                .is_some_and(|vote| &vote.proposal == proposal)
    }

    /// Returns whether `signer` is known to have the authoritative proposal
    /// from finalizing it.
    pub(super) fn has_finalize_for(&self, signer: Participant, proposal: &Proposal<D>) -> bool {
        self.remembered(signer, Self::FINALIZE_HAS_PROPOSAL)
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
            Self::NOTARIZE_SEEN,
            Self::NOTARIZE_HAS_PROPOSAL,
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
            Self::NULLIFY_SEEN,
            0,
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
            Self::FINALIZE_SEEN,
            Self::FINALIZE_HAS_PROPOSAL,
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
impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    fn clear_compacted(&mut self, cleared: u8) {
        for flags in &mut self.compacted {
            *flags &= !cleared;
        }
        if self.compacted.iter().all(|&flags| flags == 0) {
            self.compacted = Vec::new();
        }
    }

    /// Inserts a notarize vote if the signer has not already voted.
    pub(super) fn insert_notarize(&mut self, vote: Notarize<S, D>) -> bool {
        self.notarizes.insert(vote)
    }

    /// Inserts a nullify vote if the signer has not already voted.
    pub(super) fn insert_nullify(&mut self, vote: Nullify<S>) -> bool {
        self.nullifies.insert(vote)
    }

    /// Inserts a finalize vote if the signer has not already voted.
    pub(super) fn insert_finalize(&mut self, vote: Finalize<S, D>) -> bool {
        self.finalizes.insert(vote)
    }

    /// Iterates over notarize votes in signer order.
    pub(super) fn iter_notarizes(&self) -> impl Iterator<Item = &Notarize<S, D>> {
        self.notarizes.iter()
    }

    /// Iterates over nullify votes in signer order.
    pub(super) fn iter_nullifies(&self) -> impl Iterator<Item = &Nullify<S>> {
        self.nullifies.iter()
    }

    /// Returns how many notarize votes have been recorded.
    pub(super) fn len_notarizes(&self) -> u32 {
        let len = self.notarizes.len();
        u32::try_from(len).expect("too many notarize votes")
    }

    /// Returns how many nullify votes have been recorded.
    pub(super) fn len_nullifies(&self) -> u32 {
        let len = self.nullifies.len();
        u32::try_from(len).expect("too many nullify votes")
    }

    /// Returns how many finalize votes have been recorded.
    pub(super) fn len_finalizes(&self) -> u32 {
        let len = self.finalizes.len();
        u32::try_from(len).expect("too many finalize votes")
    }

    /// Returns `true` if the given signer has a notarize vote recorded.
    pub(super) fn has_notarize(&self, signer: Participant) -> bool {
        self.notarize(signer).is_some()
    }

    /// Returns `true` if a finalize vote has been recorded for `signer`.
    pub(super) fn has_finalize(&self, signer: Participant) -> bool {
        self.finalize(signer).is_some()
    }

    /// Clears all notarize votes and releases their storage.
    pub(super) fn clear_notarizes(&mut self) {
        self.notarizes.reset(self.participants);
        self.clear_compacted(Self::NOTARIZE_SEEN | Self::NOTARIZE_HAS_PROPOSAL);
    }

    /// Clears all finalize votes and releases their storage.
    pub(super) fn clear_finalizes(&mut self) {
        self.finalizes.reset(self.participants);
        self.clear_compacted(Self::FINALIZE_SEEN | Self::FINALIZE_HAS_PROPOSAL);
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

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    #[test]
    fn test_vote_tracker_clears_compacted_state() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 2);
        let round = Round::new(Epoch::new(0), View::new(1));
        let mut tracker = VoteTracker::<ed25519::Scheme, Sha256>::new(2, false);
        let signer = Participant::new(1);
        let scheme = &fixture.schemes[usize::from(signer)];
        let proposal = Proposal::new(round, View::zero(), sample_digest(1));
        let notarize = Vote::Notarize(Notarize::sign(scheme, proposal.clone()).unwrap());
        let finalize = Vote::Finalize(Finalize::sign(scheme, proposal.clone()).unwrap());

        tracker.release_notarizes(&proposal);
        tracker.release_finalizes(&proposal);
        assert!(matches!(
            tracker.record(&notarize, Some(&proposal)),
            Outcome::Added { retained: false }
        ));
        assert!(matches!(
            tracker.record(&finalize, Some(&proposal)),
            Outcome::Added { retained: false }
        ));
        assert!(tracker.has_notarize_for(signer, &proposal));
        assert!(tracker.has_finalize_for(signer, &proposal));

        tracker.clear_notarizes();
        assert!(!tracker.has_notarize_for(signer, &proposal));
        assert!(matches!(
            tracker.record(&notarize, Some(&proposal)),
            Outcome::Added { retained: true }
        ));

        tracker.clear_finalizes();
        assert!(!tracker.has_finalize_for(signer, &proposal));
        assert_eq!(tracker.compacted.capacity(), 0);
        assert!(matches!(
            tracker.record(&finalize, Some(&proposal)),
            Outcome::Added { retained: true }
        ));
    }

    #[test]
    fn test_vote_tracker_insert_and_accessors() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 2);
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round, View::zero(), sample_digest(1));
        let scheme = &fixture.schemes[0];
        let signer = Participant::new(0);
        let notarize = Notarize::sign(scheme, proposal.clone()).unwrap();
        let nullify = Nullify::sign::<Sha256>(scheme, round).unwrap();
        let finalize = Finalize::sign(scheme, proposal.clone()).unwrap();
        let mut tracker = VoteTracker::new(2, false);

        assert!(tracker.insert_notarize(notarize.clone()));
        assert!(tracker.insert_nullify(nullify.clone()));
        assert!(tracker.insert_finalize(finalize.clone()));
        assert_eq!(tracker.len_notarizes(), 1);
        assert_eq!(tracker.len_nullifies(), 1);
        assert_eq!(tracker.len_finalizes(), 1);
        assert!(tracker.has_notarize(signer));
        assert!(tracker.has_nullify(signer));
        assert!(tracker.has_finalize(signer));

        tracker.release_notarizes(&proposal);
        tracker.release_nullifies();
        tracker.release_finalizes(&proposal);
        assert_eq!(tracker.len_notarizes(), 0);
        assert_eq!(tracker.len_nullifies(), 0);
        assert_eq!(tracker.len_finalizes(), 0);
        assert!(!tracker.has_notarize(signer));
        assert!(!tracker.has_nullify(signer));
        assert!(!tracker.has_finalize(signer));
        assert!(tracker.iter_notarizes().next().is_none());
        assert!(tracker.iter_nullifies().next().is_none());
        assert!(tracker.iter_finalizes().next().is_none());
        assert!(!tracker.insert_notarize(notarize));
        assert!(!tracker.insert_nullify(nullify));
        assert!(!tracker.insert_finalize(finalize));

        // Releasing a compacted phase is idempotent.
        tracker.release_notarizes(&proposal);
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
        let mut certificate_first = VoteTracker::new(2, false);
        certificate_first.release_notarizes(&proposal);
        assert!(matches!(
            certificate_first.record(&vote, Some(&proposal)),
            Outcome::Added { retained: false }
        ));
        assert!(matches!(&certificate_first.notarizes, Phase::Compacted));
        assert!(matches!(
            certificate_first.record(&vote, Some(&proposal)),
            Outcome::Duplicate { retained: false }
        ));

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
