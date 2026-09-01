//! The local choices this node has made in one view.
//!
//! Staging, journal replay and snapshot validation share one rule set through
//! [`ViewSlotSnapshot`]: in particular, a local vote is accepted only before any local nullify for
//! its view. Staging and replay apply choices in the order they were made, while snapshot
//! validation cannot recover that order and applies them in the canonical order of
//! `ViewSnapshot::from_durable`, so it also accepts a signed nullify followed by a vote.

use crate::multimmit::{
    machine::durability::SignRequest,
    types::{Artifact, ArtifactId, LeaderBlock, VoteBody},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// Whether this node has left one view, and the proof that exited it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewTransition<D: Digest> {
    #[default]
    Active,
    Exited(ArtifactId<D>),
}

/// This node's voting choice in one view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewStance<D: Digest> {
    #[default]
    Unchosen,
    Voted(VoteBody<D>),
    NoVoted,
}

/// Whether this node authorized a nullification share in one view.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum ViewNullification {
    #[default]
    Unsigned,
    Signed,
}

/// A local choice that contradicts an earlier one in the same view.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SlotError {
    #[error("a local leader proposal conflicts with an earlier durable choice")]
    Proposal,
    #[error("a local vote conflicts with an earlier durable choice")]
    Vote,
    #[error("a local vote or novote conflicts with a durable stance, nullify or exit")]
    Stance,
}

/// One local input to a view slot.
#[derive(Clone, Debug)]
enum SlotInput<V: Variant, D: Digest> {
    Propose(LeaderBlock<V, D>),
    Vote(VoteBody<D>),
    NoVote,
    Nullify,
    Exit(ArtifactId<D>),
}

/// The local choices for one retained view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewSlotSnapshot<V: Variant, D: Digest> {
    pub(crate) transition: ViewTransition<D>,
    pub(crate) stance: ViewStance<D>,
    pub(crate) nullification: ViewNullification,
    pub(crate) proposal: Option<LeaderBlock<V, D>>,
}

impl<V: Variant, D: Digest> Default for ViewSlotSnapshot<V, D> {
    fn default() -> Self {
        Self {
            transition: ViewTransition::Active,
            stance: ViewStance::Unchosen,
            nullification: ViewNullification::Unsigned,
            proposal: None,
        }
    }
}

impl<V: Variant, D: Digest> ViewSlotSnapshot<V, D> {
    /// Applies one input and returns whether the slot changed.
    ///
    /// Repeating an earlier choice changes nothing. Proposing, voting and abstaining require an
    /// active view; a nullify after the view exited changes nothing; the first exit proof is kept.
    fn apply(&mut self, input: SlotInput<V, D>) -> Result<bool, SlotError> {
        let active = matches!(self.transition, ViewTransition::Active);
        match input {
            SlotInput::Propose(block) => match &self.proposal {
                Some(existing) if *existing == block => Ok(false),
                Some(_) => Err(SlotError::Proposal),
                None if active => {
                    self.proposal = Some(block);
                    Ok(true)
                }
                None => Err(SlotError::Proposal),
            },
            SlotInput::Vote(body) => match &self.stance {
                ViewStance::Voted(existing) if *existing == body => Ok(false),
                ViewStance::Voted(_) => Err(SlotError::Vote),
                ViewStance::Unchosen
                    if active && self.nullification == ViewNullification::Unsigned =>
                {
                    self.stance = ViewStance::Voted(body);
                    Ok(true)
                }
                ViewStance::Unchosen | ViewStance::NoVoted => Err(SlotError::Stance),
            },
            SlotInput::NoVote => match self.stance {
                ViewStance::NoVoted => Ok(false),
                ViewStance::Unchosen if active => {
                    self.stance = ViewStance::NoVoted;
                    Ok(true)
                }
                ViewStance::Unchosen | ViewStance::Voted(_) => Err(SlotError::Stance),
            },
            SlotInput::Nullify => {
                let changed = active && self.nullification == ViewNullification::Unsigned;
                if changed {
                    self.nullification = ViewNullification::Signed;
                }
                Ok(changed)
            }
            SlotInput::Exit(proof) => {
                if active {
                    self.transition = ViewTransition::Exited(proof);
                }
                Ok(active)
            }
        }
    }

    /// Applies the view choice a local signing request makes, if any.
    pub(crate) fn observe_request(
        &mut self,
        request: &SignRequest<V, D>,
    ) -> Result<bool, SlotError> {
        match request {
            SignRequest::LeaderBlock(request) => {
                self.apply(SlotInput::Propose(request.block().clone()))
            }
            SignRequest::Vote(body) => self.apply(SlotInput::Vote(body.clone())),
            SignRequest::NoVote { .. } => self.apply(SlotInput::NoVote),
            SignRequest::Nullify { .. } => self.apply(SlotInput::Nullify),
            SignRequest::TransactionBlock(_) | SignRequest::DaVote(_) => Ok(false),
        }
    }

    /// Applies the view choice a locally signed artifact records, if any.
    pub(crate) fn observe_artifact(
        &mut self,
        artifact: &Artifact<V, D>,
    ) -> Result<bool, SlotError> {
        match artifact {
            Artifact::LeaderBlock(block) => self.apply(SlotInput::Propose(block.block().clone())),
            Artifact::Vote(vote) => self.apply(SlotInput::Vote(vote.body().clone())),
            Artifact::NoVote(_) => self.apply(SlotInput::NoVote),
            Artifact::Nullify(_) => self.apply(SlotInput::Nullify),
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::Nullification(_)
            | Artifact::Vqc(_)
            | Artifact::Lqc(_) => Ok(false),
        }
    }

    /// Records the proof that exited the view, keeping the first one.
    pub(crate) fn observe_exit(&mut self, proof: ArtifactId<D>) -> bool {
        matches!(self.apply(SlotInput::Exit(proof)), Ok(true))
    }

    /// Returns the vote this node cast, if any.
    pub(crate) const fn vote(&self) -> Option<&VoteBody<D>> {
        match &self.stance {
            ViewStance::Voted(body) => Some(body),
            ViewStance::Unchosen | ViewStance::NoVoted => None,
        }
    }

    /// Returns whether this node may still vote, abstain or time out in the view.
    pub(crate) const fn can_vote(&self) -> bool {
        matches!(self.transition, ViewTransition::Active)
            && matches!(self.stance, ViewStance::Unchosen)
            && matches!(self.nullification, ViewNullification::Unsigned)
    }

    /// Returns whether this node voted in the view.
    pub(crate) const fn has_voted(&self) -> bool {
        matches!(self.stance, ViewStance::Voted(_))
    }

    /// Returns whether this node authorized a nullification share in the view.
    pub(crate) const fn nullified(&self) -> bool {
        matches!(self.nullification, ViewNullification::Signed)
    }

    /// Returns whether the slot is one a completed signing step can leave: a timeout signs its
    /// novote and nullify together, so neither appears alone.
    pub(crate) const fn stable(&self) -> bool {
        !matches!(
            (&self.stance, self.nullification),
            (ViewStance::Unchosen, ViewNullification::Signed)
                | (ViewStance::NoVoted, ViewNullification::Unsigned)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::machine::{
        testing::fixtures::Harness,
        tests::fixtures::{leader, view_vote},
    };
    use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinPk};

    #[test]
    fn slot_transition_table_is_exhaustive() {
        let (machine, _) = Harness::observer().participants(6).start();
        let block = leader(&machine, 1);
        let other_block = leader(&machine, 2);
        let body = view_vote(&machine, &block, 0).body().clone();
        let other_body = view_vote(&machine, &other_block, 0).body().clone();
        let proof = ArtifactId::new(Sha256::hash(&[b"exit"]));
        let other_proof = ArtifactId::new(Sha256::hash(&[b"other exit"]));
        let inputs = [
            SlotInput::Propose(block.clone()),
            SlotInput::Propose(other_block),
            SlotInput::Vote(body.clone()),
            SlotInput::Vote(other_body),
            SlotInput::NoVote,
            SlotInput::Nullify,
            SlotInput::Exit(proof),
            SlotInput::Exit(other_proof),
        ];

        let mut cases = 0;
        for transition in [ViewTransition::Active, ViewTransition::Exited(proof)] {
            for stance in [
                ViewStance::Unchosen,
                ViewStance::Voted(body.clone()),
                ViewStance::NoVoted,
            ] {
                for nullification in [ViewNullification::Unsigned, ViewNullification::Signed] {
                    for proposal in [None, Some(block.clone())] {
                        for input in &inputs {
                            let before = ViewSlotSnapshot {
                                transition,
                                stance: stance.clone(),
                                nullification,
                                proposal: proposal.clone(),
                            };
                            let active = transition == ViewTransition::Active;
                            let mut actual = before.clone();
                            let result = actual.apply(input.clone());
                            let mut expected = before.clone();
                            match (input, result) {
                                (SlotInput::Propose(block), Ok(true)) => {
                                    assert!(active && proposal.is_none());
                                    expected.proposal = Some(block.clone());
                                }
                                (SlotInput::Propose(block), Ok(false)) => {
                                    assert_eq!(proposal.as_ref(), Some(block));
                                }
                                (SlotInput::Propose(block), Err(SlotError::Proposal)) => {
                                    assert!(
                                        proposal.as_ref().map_or(!active, |held| held != block)
                                    );
                                }
                                (SlotInput::Vote(body), Ok(true)) => {
                                    assert!(active && nullification == ViewNullification::Unsigned);
                                    assert_eq!(stance, ViewStance::Unchosen);
                                    expected.stance = ViewStance::Voted(body.clone());
                                }
                                (SlotInput::Vote(body), Ok(false)) => {
                                    assert_eq!(stance, ViewStance::Voted(body.clone()));
                                }
                                (SlotInput::Vote(body), Err(SlotError::Vote)) => {
                                    assert!(
                                        matches!(&stance, ViewStance::Voted(held) if held != body)
                                    );
                                }
                                (SlotInput::Vote(_), Err(SlotError::Stance)) => {
                                    // No vote after an abstention, an exit or a local nullify.
                                    assert!(
                                        stance == ViewStance::NoVoted
                                            || (stance == ViewStance::Unchosen
                                                && (!active
                                                    || nullification == ViewNullification::Signed))
                                    );
                                }
                                (SlotInput::NoVote, Ok(true)) => {
                                    assert!(active && stance == ViewStance::Unchosen);
                                    expected.stance = ViewStance::NoVoted;
                                }
                                (SlotInput::NoVote, Ok(false)) => {
                                    assert_eq!(stance, ViewStance::NoVoted);
                                }
                                (SlotInput::NoVote, Err(SlotError::Stance)) => {
                                    assert!(
                                        matches!(stance, ViewStance::Voted(_))
                                            || (stance == ViewStance::Unchosen && !active)
                                    );
                                }
                                (SlotInput::Nullify, Ok(true)) => {
                                    assert!(active && nullification == ViewNullification::Unsigned);
                                    expected.nullification = ViewNullification::Signed;
                                }
                                (SlotInput::Nullify, Ok(false)) => {
                                    assert!(!active || nullification == ViewNullification::Signed);
                                }
                                (SlotInput::Exit(proof), Ok(true)) => {
                                    assert!(active);
                                    expected.transition = ViewTransition::Exited(*proof);
                                }
                                (SlotInput::Exit(_), Ok(false)) => assert!(!active),
                                (input, result) => {
                                    panic!("unexpected slot transition: {input:?} -> {result:?}")
                                }
                            }
                            assert_eq!(actual, expected);
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 192);
    }

    #[test]
    fn a_vote_may_precede_a_nullify_but_not_follow_it() {
        let (machine, _) = Harness::observer().participants(6).start();
        let body = view_vote(&machine, &leader(&machine, 1), 0).body().clone();

        let mut voted_first = ViewSlotSnapshot::<MinPk, _>::default();
        assert!(voted_first.can_vote());
        assert_eq!(voted_first.apply(SlotInput::Vote(body.clone())), Ok(true));
        assert!(!voted_first.can_vote());
        assert_eq!(voted_first.apply(SlotInput::Nullify), Ok(true));
        assert!(voted_first.has_voted() && voted_first.nullified() && voted_first.stable());

        let mut nullified_first = ViewSlotSnapshot::<MinPk, _>::default();
        assert_eq!(nullified_first.apply(SlotInput::Nullify), Ok(true));
        assert_eq!(
            nullified_first.apply(SlotInput::Vote(body)),
            Err(SlotError::Stance)
        );
        assert!(!nullified_first.stable());
    }
}
