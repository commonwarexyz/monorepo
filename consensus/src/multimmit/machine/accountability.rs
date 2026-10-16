//! Accountability: objective equivocation evidence and the quarantine of the validators it proves
//! faulty.
//!
//! Within one signer and view tag, a correct validator's vote statements form a chain under the
//! partial order `A <= B`: every tip of `A` is an ancestor of, or equal to, `B`'s tip on its chain,
//! `A`'s declared chains are a subset of `B`'s, `A` names no leader block or `B`'s, and a final `A`
//! is `B`. Two authenticated statements of one signer that no correct validator signs prove it
//! faulty, without any timing assumption ([`Equivocation`]):
//!
//! 1. two final votes of one tag with different contents;
//! 2. votes of one tag for two different leader blocks;
//! 3. two non-final votes of one tag neither of which is below the other as far as tip heights
//!    show: one chain higher in each, one height with two digests, declared sets neither of which
//!    holds the other, or higher tips paired with fewer declared chains;
//! 4. a final vote and a vote of the same tag that is not below it;
//! 5. two producer-signed headers at one height of a chain, or two leader blocks of one view.
//!
//! A vote lower than an earlier one on every chain is indistinguishable from reordering and proves
//! nothing; neither do omission, late arrival, unresolvable tips, or an invalid leader block.
//!
//! Statements count only once authenticated: a vote update whose signature verified, the final
//! votes a V-QC's aggregate vouches for, the votes an L-QC's aggregate vouches for, a
//! producer-signed header, and a signed leader block. Blame goes to the statement's signer, never
//! to the peer or assembler that relayed it, and each signer is quarantined once
//! ([`Capability::Quarantine`]).
//!
//! Per signer and tag within the window the pool reads, the greatest vote seen is kept and every
//! later vote is compared with it, so the evidence held is bounded by `n` times the window. A vote
//! that conflicts only with a lower vote no longer kept goes unnoticed: detection is best effort,
//! and never blames a correct validator.

use crate::{
    Viewable as _,
    multimmit::{
        config::Role,
        machine::{capability::Capability, reducer::machine::Machine},
        types::VoteContent,
    },
    types::{Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::cmp::Ordering;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
};

/// A pattern of two signed statements that no correct validator signs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Equivocation {
    /// Two final votes of one tag with different contents.
    Finals,
    /// Votes of one tag for two different leader blocks.
    Leaders,
    /// Two non-final votes of one tag, neither below the other.
    Incomparable,
    /// A final vote and a vote of the same tag that is not below it.
    AfterFinal,
}

/// Returns the equivocation two authenticated votes of one signer and tag prove, if any.
pub(crate) fn equivocation<D: Digest>(
    a: &VoteContent<D>,
    b: &VoteContent<D>,
) -> Option<Equivocation> {
    if a == b {
        return None;
    }
    if let (Some(first), Some(second)) = (a.leader(), b.leader())
        && first != second
    {
        return Some(Equivocation::Leaders);
    }
    match (a.is_final(), b.is_final()) {
        (true, true) => Some(Equivocation::Finals),
        (true, false) => (!below(b, a)).then_some(Equivocation::AfterFinal),
        (false, true) => (!below(a, b)).then_some(Equivocation::AfterFinal),
        (false, false) => (!below(a, b) && !below(b, a)).then_some(Equivocation::Incomparable),
    }
}

/// Returns whether `a <= b` holds as far as tip heights show: no tip of `a` is higher than `b`'s
/// or at its height with another digest, `a`'s declared chains are `b`'s or fewer, and `a` names no
/// leader block or `b`'s.
fn below<D: Digest>(a: &VoteContent<D>, b: &VoteContent<D>) -> bool {
    tip_order(a, b).is_some_and(Ordering::is_le)
        && a.declared().is_subset(b.declared())
        && a.leader().is_none_or(|leader| b.leader() == Some(leader))
}

/// Compares `a`'s tips with `b`'s by height on every chain, or returns `None` when one chain is
/// higher in each or one height carries two digests.
fn tip_order<D: Digest>(a: &VoteContent<D>, b: &VoteContent<D>) -> Option<Ordering> {
    let mut order = Ordering::Equal;
    for (first, second) in a.tips().iter().zip(b.tips()) {
        let chain = first.height().cmp(&second.height());
        if chain.is_eq() && first != second {
            return None;
        }
        order = match (order, chain) {
            (Ordering::Equal, chain) => chain,
            (order, Ordering::Equal) => order,
            (order, chain) if order == chain => order,
            _ => return None,
        };
    }
    Some(order)
}

/// The equivocation evidence held and the validators it proved faulty.
pub(crate) struct Accountability<D: Digest> {
    /// Per tag and signer, the greatest authenticated vote seen.
    votes: BTreeMap<(View, Participant), Arc<VoteContent<D>>>,
    /// Every validator proven to equivocate.
    quarantined: BTreeSet<Participant>,
    /// The validators proven since the last quarantine was issued.
    proven: Vec<Participant>,
}

impl<D: Digest> Accountability<D> {
    pub(crate) const fn new() -> Self {
        Self {
            votes: BTreeMap::new(),
            quarantined: BTreeSet::new(),
            proven: Vec::new(),
        }
    }

    /// Records that `signer` equivocated.
    fn prove(&mut self, signer: Participant) {
        if self.quarantined.insert(signer) {
            self.proven.push(signer);
        }
    }

    /// Returns whether `content`, an unauthenticated vote of `signer`, would prove it faulty
    /// against the greatest vote of its tag seen.
    pub(crate) fn conflicts(&self, signer: Participant, content: &VoteContent<D>) -> bool {
        !self.quarantined.contains(&signer)
            && self
                .votes
                .get(&(content.view(), signer))
                .is_some_and(|kept| equivocation(kept, content).is_some())
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Compares an authenticated vote of `signer` with the greatest vote of its tag seen, keeps the
    /// greater, and quarantines `signer` when the two equivocate. This node's own votes and tags
    /// outside the window the pool reads are skipped; tags below the window are forgotten.
    pub(in crate::multimmit::machine) fn account_vote(
        &mut self,
        signer: Participant,
        content: &Arc<VoteContent<H::Digest>>,
    ) {
        let (low, high) = self.vote_tags();
        let view = content.view();
        if self.profile.role() == Role::Validator(signer) || view < low || view > high {
            return;
        }
        let accountability = &mut self.components.accountability;
        if accountability.quarantined.contains(&signer) {
            return;
        }
        if accountability
            .votes
            .first_key_value()
            .is_some_and(|((oldest, _), _)| *oldest < low)
        {
            accountability.votes = accountability.votes.split_off(&(low, Participant::new(0)));
        }
        match accountability.votes.entry((view, signer)) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::clone(content));
            }
            Entry::Occupied(mut entry) => {
                let kept = entry.get();
                if equivocation(kept, content).is_some() {
                    accountability.prove(signer);
                } else if !kept.is_final() && below(kept, content) {
                    entry.insert(Arc::clone(content));
                }
            }
        }
    }

    /// Quarantines `signer`, proven faulty by two signed headers or leader blocks.
    pub(in crate::multimmit::machine) fn account_equivocation(&mut self, signer: Participant) {
        self.components.accountability.prove(signer);
    }

    /// Returns whether `signer` was proven faulty.
    pub(in crate::multimmit::machine) fn quarantined(&self, signer: Participant) -> bool {
        self.components.accountability.quarantined.contains(&signer)
    }

    /// Returns the quarantine of the validators proven faulty since the last one, if any.
    pub(in crate::multimmit::machine) fn take_quarantine(
        &mut self,
    ) -> Option<Capability<V, H::Digest>> {
        let proven = core::mem::take(&mut self.components.accountability.proven);
        (!proven.is_empty()).then(|| Capability::Quarantine(proven))
    }
}
