//! ByzzFuzz content mutator: wraps `SmallScope` and biases vote/nullify
//! mutations toward observed-value replay (seen payloads, proposals,
//! finalized/notarized views) before falling back to local edits.
//! Certificate and resolver byte mutators delegate straight to the inner
//! `SmallScope` because ByzzFuzz process faults on those channels are
//! omit-only and never call them.

use crate::{
    byzzfuzz::observed::ObservedState,
    strategy::{SmallScope, Strategy},
    EPOCH,
};
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::Rng;
use std::sync::Arc;

pub struct ByzzFuzzMutator {
    pool: Arc<ObservedState>,
    inner: SmallScope,
}

impl ByzzFuzzMutator {
    pub fn new(pool: Arc<ObservedState>) -> Self {
        Self {
            pool,
            // SmallScope's fault_rounds/_bound aren't read on the mutate_*
            // path; only sampled by network/messaging_faults which we don't call.
            inner: SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
        }
    }
}

fn proposal_with_payload(
    p: &Proposal<Sha256Digest>,
    payload: Sha256Digest,
) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(p.view().get())),
        p.parent,
        payload,
    )
}

fn proposal_with_parent(p: &Proposal<Sha256Digest>, parent: u64) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(p.view().get())),
        View::new(parent),
        p.payload,
    )
}

impl Strategy for ByzzFuzzMutator {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> Proposal<Sha256Digest> {
        self.inner.random_proposal(rng, a, b, c, d)
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
        a: u64,
        b: u64,
        c: u64,
        d: u64,
    ) -> Proposal<Sha256Digest> {
        // Bias 60% toward observed-value mutations; 40% local edits.
        // Identity mutations (== original proposal) are degenerate -- the
        // injector would re-sign and resend the same vote content. Reject
        // them and fall back to SmallScope.
        if rng.gen_bool(0.6) {
            let candidate = match rng.gen_range(0..4) {
                0 => self
                    .pool
                    .random_payload(rng)
                    .map(|payload| proposal_with_payload(proposal, payload)),
                1 => self.pool.random_proposal(rng).map(|other| {
                    Proposal::new(
                        Round::new(Epoch::new(EPOCH), proposal.view()),
                        other.parent,
                        other.payload,
                    )
                }),
                2 => self
                    .pool
                    .random_proposal(rng)
                    .map(|other| proposal_with_parent(proposal, other.parent.get())),
                _ => self.pool.random_proposal_at(rng, proposal.view().get()),
            };
            if let Some(c) = candidate {
                if c != *proposal {
                    return c;
                }
            }
        }
        // SmallScope fallback can also return the original (e.g. parent=0
        // with saturating_sub(1), or a payload tweak that happens to be a
        // no-op). Force a distinct proposal by bumping the view by one --
        // symmetric to the nullify guard: try +1, then -1 for u64::MAX.
        let mutated = self.inner.mutate_proposal(rng, proposal, a, b, c, d);
        if mutated != *proposal {
            return mutated;
        }
        let view = proposal.view().get();
        let bumped = self
            .inner
            .proposal_with_view(proposal, view.saturating_add(1));
        if bumped != *proposal {
            return bumped;
        }
        self.inner
            .proposal_with_view(proposal, view.saturating_sub(1))
    }

    fn mutate_nullify_view(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        // Bias toward nullifying an observed notarized/finalized view --
        // a more interesting fault than a small local view edit.
        if rng.gen_bool(0.5) {
            if let Some(v) = self.pool.random_notarized_or_finalized_view(rng) {
                return v;
            }
        }
        self.inner.mutate_nullify_view(rng, a, b, c, d)
    }

    fn random_view_for_proposal(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        self.inner.random_view_for_proposal(rng, a, b, c, d)
    }

    fn random_parent_view(&self, rng: &mut impl Rng, a: u64, b: u64, c: u64, d: u64) -> u64 {
        self.inner.random_parent_view(rng, a, b, c, d)
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        // Reuse an observed payload when available; otherwise random.
        self.pool
            .random_payload(rng)
            .unwrap_or_else(|| self.inner.random_payload(rng))
    }

    // Cert and resolver byte mutators are intentionally NOT overridden.
    // ByzzFuzz process faults on those channels are omit-only (see
    // `ByzzFuzzInjector::handle`); the trait methods below delegate to
    // the inner SmallScope so the trait remains usable from other modes
    // unchanged, but the injector never calls them in Byzzfuzz mode.
    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        self.inner.mutate_certificate_bytes(rng, cert)
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        self.inner.mutate_resolver_bytes(rng, msg)
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        self.inner.repeated_proposal_index(rng, proposals_len)
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, crate::utils::SetPartition)> {
        self.inner.network_faults(required_containers, rng)
    }

    fn messaging_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Vec<(View, u8)> {
        self.inner.messaging_faults(required_containers, rng)
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        self.inner.fault_bounds()
    }
}
