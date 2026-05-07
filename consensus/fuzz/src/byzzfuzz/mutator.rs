//! ByzzFuzz self-contained small-scope mutator. Vote mutations are self-contained: proposal
//! votes are biased toward observed-value replay before falling back to local
//! +/-1 or +/-2 view/parent edits or payload edits. Nullify votes target
//! observed notarized/finalized views before falling back to local +/-1 or
//! +/-2 edits. Certificate and resolver process faults are omit-only, so
//! their byte mutators must not run.

use crate::{byzzfuzz::observed::ObservedState, strategy::Strategy, EPOCH};
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::Rng;
use std::sync::Arc;

/// ByzzFuzz-local mutator used only by the ByzzFuzz injector. Scheduling
/// methods from [`Strategy`] are unreachable because ByzzFuzz samples network
/// and process faults in its own module.
pub struct ByzzFuzzMutator {
    pool: Arc<ObservedState>,
}

impl ByzzFuzzMutator {
    pub fn new(pool: Arc<ObservedState>) -> Self {
        Self { pool }
    }
}

fn random_payload(rng: &mut impl Rng) -> Sha256Digest {
    let mut arr = [0u8; 32];
    rng.fill_bytes(&mut arr);
    Sha256Digest::from(arr)
}

fn random_payload_except(rng: &mut impl Rng, original: Sha256Digest) -> Sha256Digest {
    let payload = random_payload(rng);
    if payload == original {
        tweak_payload(rng, payload)
    } else {
        payload
    }
}

fn nearby_value(rng: &mut impl Rng, value: u64) -> u64 {
    let candidates = [
        value.checked_sub(2),
        value.checked_sub(1),
        value.checked_add(1),
        value.checked_add(2),
    ];
    let mut available = [0u64; 4];
    let mut len = 0;
    for candidate in candidates.into_iter().flatten() {
        available[len] = candidate;
        len += 1;
    }
    available[rng.gen_range(0..len)]
}

fn context_value(
    rng: &mut impl Rng,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    match rng.gen_range(0..4) {
        0 => last_vote_view,
        1 => last_finalized_view,
        2 => last_notarized_view,
        _ => last_nullified_view,
    }
}

fn nearby_context_value(
    rng: &mut impl Rng,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    let value = context_value(
        rng,
        last_vote_view,
        last_finalized_view,
        last_notarized_view,
        last_nullified_view,
    );
    nearby_value(rng, value)
}

fn nearby_context_value_except(
    rng: &mut impl Rng,
    current: u64,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    for _ in 0..4 {
        let candidate = nearby_context_value(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        if candidate != current {
            return candidate;
        }
    }
    nearby_value(rng, current)
}

fn nearby_parent_for_context(
    rng: &mut impl Rng,
    proposal_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    // Genesis-style fallback for callers that ask for view 0 or 1: choose
    // the only non-greater parent view available.
    if proposal_view <= 1 {
        return 0;
    }

    let max_parent = proposal_view - 1;
    let base = match rng.gen_range(0..4) {
        0 => max_parent,
        1 => last_finalized_view.min(max_parent),
        2 => last_notarized_view.min(max_parent),
        _ => last_nullified_view.min(max_parent),
    };
    nearby_value(rng, base).min(max_parent)
}

fn tweak_payload(rng: &mut impl Rng, payload: Sha256Digest) -> Sha256Digest {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(payload.as_ref());
    let idx = rng.gen_range(0..bytes.len());
    let bit = rng.gen_range(0..8);
    bytes[idx] ^= 1 << bit;
    Sha256Digest::from(bytes)
}

fn proposal_with_view(p: &Proposal<Sha256Digest>, view: u64) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(view)),
        p.parent,
        p.payload,
    )
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
        let view = self.random_view_for_proposal(rng, a, b, c, d);
        let parent = self.random_parent_view(rng, view, b, c, d);
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent),
            self.random_payload(rng),
        )
    }

    fn proposal_with_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        proposal_with_view(proposal, view)
    }

    fn proposal_with_parent_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        proposal_with_parent(proposal, view)
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
        // Bias 60% toward observed-value mutations; 40% local edits.
        // Identity mutations (== original proposal) are degenerate -- the
        // injector would re-sign and resend the same vote content. Reject
        // them and fall back to local edits.
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
        match rng.gen_range(0..5) {
            0 => proposal_with_view(
                proposal,
                nearby_context_value(
                    rng,
                    last_vote_view,
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                ),
            ),
            // Byzantine proposal mutation may intentionally produce a parent
            // that is not below the proposal view.
            1 => proposal_with_parent(
                proposal,
                nearby_context_value_except(
                    rng,
                    proposal.parent.get(),
                    proposal.parent.get(),
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                ),
            ),
            2 => proposal_with_payload(proposal, tweak_payload(rng, proposal.payload)),
            3 => Proposal::new(
                Round::new(
                    Epoch::new(EPOCH),
                    View::new(nearby_context_value(
                        rng,
                        last_vote_view,
                        last_finalized_view,
                        last_notarized_view,
                        last_nullified_view,
                    )),
                ),
                View::new(nearby_context_value(
                    rng,
                    proposal.parent.get(),
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                )),
                proposal.payload,
            ),
            _ => proposal_with_payload(proposal, random_payload_except(rng, proposal.payload)),
        }
    }

    fn mutate_nullify_view(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        // Bias toward nullifying an observed notarized/finalized view --
        // a more interesting fault than a small local view edit.
        if rng.gen_bool(0.5) {
            if let Some(v) = self.pool.random_notarized_or_finalized_view(rng) {
                if v != last_vote_view {
                    return v;
                }
            }
        }
        nearby_context_value_except(
            rng,
            last_vote_view,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        base_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        nearby_context_value(
            rng,
            base_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_parent_view(
        &self,
        rng: &mut impl Rng,
        proposal_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        nearby_parent_for_context(
            rng,
            proposal_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        // Reuse an observed payload when available; otherwise random.
        self.pool
            .random_payload(rng)
            .unwrap_or_else(|| random_payload(rng))
    }

    fn mutate_certificate_bytes(&self, _rng: &mut impl Rng, _cert: &[u8]) -> Vec<u8> {
        unreachable!("ByzzFuzz certificate process faults are omit-only")
    }

    fn mutate_resolver_bytes(&self, _rng: &mut impl Rng, _msg: &[u8]) -> Vec<u8> {
        unreachable!("ByzzFuzz resolver process faults are omit-only")
    }

    fn repeated_proposal_index(&self, _rng: &mut impl Rng, _proposals_len: usize) -> Option<usize> {
        unreachable!("ByzzFuzz does not use repeated-proposal mutation")
    }

    fn network_faults(
        &self,
        _required_containers: u64,
        _rng: &mut impl Rng,
    ) -> Vec<(View, crate::utils::SetPartition)> {
        unreachable!("ByzzFuzz samples network faults in byzzfuzz::sampling")
    }

    fn messaging_faults(&self, _required_containers: u64, _rng: &mut impl Rng) -> Vec<(View, u8)> {
        unreachable!("ByzzFuzz samples process faults in byzzfuzz::sampling")
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        unreachable!("ByzzFuzz samples fault bounds in byzzfuzz::runner")
    }
}
