//! A disrupter strategy scoped to the live views above the scenario floor.
//!
//! The stock strategies schedule faulty views in `1..=required_containers`, which
//! for a run that starts above a prefix floor targets already-finalized prefix
//! views. `LiveScope` wraps an inner strategy and keeps its semantic proposal
//! mutations (mutate the proposal and let the disrupter re-sign it, so the
//! message is validly signed but adversarial) while confining the adversary to
//! the live window above the attack view: it overrides the faulty-view schedule
//! to `[first_view, last_view]`, clamps every emitted proposal/nullify round to
//! that lower bound, and disables raw byte corruption so emissions are semantic
//! only. The window excludes the attack view itself, which the block-dissemination
//! fault owns, so there is a single vote producer per view. Fault density tracks
//! the inner strategy's own schedule length.

use crate::{strategy::Strategy, utils::SetPartition};
use commonware_consensus::{Viewable, simplex::types::Proposal, types::View};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::{Rng, RngExt as _};

pub(crate) struct LiveScope<S: Strategy> {
    inner: S,
    /// First live view the disrupter may fault (inclusive).
    first_view: u64,
    /// Last live view the disrupter may fault (inclusive).
    last_view: u64,
}

impl<S: Strategy> LiveScope<S> {
    pub(crate) fn new(inner: S, first_view: u64, last_view: u64) -> Self {
        Self {
            inner,
            first_view,
            last_view: last_view.max(first_view),
        }
    }

    /// Raise a mutated proposal's round to the live window if the inner strategy
    /// shifted it at or below the attack view, so every emission stays a single
    /// vote producer strictly above the attack view (and off the finalized
    /// prefix). Parent view is left untouched: an old parent is a valid
    /// adversarial header, and only the round drives the leader slot.
    fn lift_round(&self, proposal: Proposal<Sha256Digest>) -> Proposal<Sha256Digest> {
        if proposal.view().get() < self.first_view {
            self.inner.proposal_with_view(&proposal, self.first_view)
        } else {
            proposal
        }
    }
}

impl<S: Strategy> Strategy for LiveScope<S> {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.random_proposal(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn proposal_with_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.proposal_with_view(proposal, view)
    }

    fn proposal_with_parent_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.proposal_with_parent_view(proposal, view)
    }

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        // `mutate_proposal` is the authoritative round source for every signed
        // proposal the disrupter emits, so clamping here bounds all of them.
        let mutated = self.inner.mutate_proposal(
            rng,
            proposal,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        self.lift_round(mutated)
    }

    fn mutate_nullify_view(
        &self,
        rng: &mut impl Rng,
        last_vote: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        self.inner
            .mutate_nullify_view(
                rng,
                last_vote,
                last_finalized_view,
                last_notarized_view,
                last_nullified_view,
            )
            .max(self.first_view)
    }

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        self.inner.random_view_for_proposal(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_parent_view(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        self.inner.random_parent_view(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        self.inner.random_payload(rng)
    }

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        self.inner.mutate_certificate_bytes(rng, cert)
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        self.inner.mutate_resolver_bytes(rng, msg)
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        self.inner.repeated_proposal_index(rng, proposals_len)
    }

    fn preserves_proposal_payload(&self) -> bool {
        self.inner.preserves_proposal_payload()
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, SetPartition)> {
        self.inner.network_faults(required_containers, rng)
    }

    fn messaging_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Vec<(View, u8)> {
        self.inner.messaging_faults(required_containers, rng)
    }

    fn emit_byte_corruption(&self) -> bool {
        false
    }

    fn disrupter_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Option<Vec<View>> {
        let mut views: Vec<u64> = (self.first_view..=self.last_view).collect();
        if views.is_empty() {
            return Some(Vec::new());
        }
        // Density tracks the inner strategy's own schedule length (driven by the
        // fuzzed fault_rounds); `None` (AnyScope) faults every live view.
        let density = match self.inner.disrupter_faults(required_containers, rng) {
            Some(schedule) => schedule.len(),
            None => views.len(),
        };
        let count = density.min(views.len());
        let mut chosen = Vec::with_capacity(count);
        for i in 0..count {
            let idx = i + (rng.random::<u64>() as usize % (views.len() - i));
            views.swap(i, idx);
            chosen.push(View::new(views[i]));
        }
        Some(chosen)
    }
}
