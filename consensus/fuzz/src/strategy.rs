use crate::EPOCH;
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::Rng;

pub trait Strategy: Send + Sync {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest>;

    fn proposal_with_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest>;

    fn proposal_with_parent_view(
        &self,
        proposal: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest>;

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest>;

    fn mutate_nullify_view(
        &self,
        rng: &mut impl Rng,
        last_vote: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64;

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64;

    fn random_parent_view(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64;

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest;

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8>;

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8>;

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize>;

    fn fault_bounds(&self) -> Option<(u64, u64)>;
}

#[derive(Clone, Copy, Debug)]
pub enum StrategyChoice {
    SmallScope {
        fault_rounds: u64,
        fault_rounds_bound: u64,
    },
    AnyScope,
    FutureScope {
        fault_rounds: u64,
        fault_rounds_bound: u64,
    },
}

pub struct SmallScope {
    pub fault_rounds: u64,
    pub fault_rounds_bound: u64,
}

impl Strategy for SmallScope {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = self.random_view_for_proposal(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let parent = self.random_parent_view(
            rng,
            view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let payload = self.random_payload(rng);
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent),
            payload,
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
        proposal_with_parent_view(proposal, view)
    }

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        _last_vote_view: u64,
        _last_finalized_view: u64,
        _last_notarized_view: u64,
        _last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = proposal.view().get();
        let parent = proposal.parent.get();
        match rng.gen::<u8>() % 5 {
            0 => proposal_with_view(proposal, view.saturating_add(1)),
            1 => proposal_with_view(proposal, view.saturating_sub(1)),
            2 => proposal_with_parent(proposal, parent.saturating_add(1)),
            3 => proposal_with_parent(proposal, parent.saturating_sub(1)),
            _ => proposal_with_payload(proposal, tweak_payload(rng, proposal.payload)),
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
        match rng.gen::<u8>() % 12 {
            0 => last_vote_view,
            1 => last_vote_view.saturating_add(1),
            2 => last_vote_view.saturating_sub(1),
            3 => last_notarized_view,
            4 => last_notarized_view.saturating_add(1),
            5 => last_notarized_view.saturating_sub(1),
            6 => last_finalized_view,
            7 => last_finalized_view.saturating_add(1),
            8 => last_finalized_view.saturating_sub(1),
            9 => last_nullified_view,
            10 => last_nullified_view.saturating_add(1),
            _ => last_nullified_view.saturating_sub(1),
        }
    }

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        match rng.gen::<u8>() % 8 {
            0 => {
                let hi = last_notarized_view
                    .min(last_vote_view)
                    .max(last_finalized_view);
                sample_inclusive(rng, last_finalized_view, hi)
            }
            1 => last_vote_view,
            2 => last_vote_view.saturating_add(1),
            3 => last_vote_view.saturating_sub(1),
            4 => last_notarized_view.saturating_add(1),
            5 => last_notarized_view.saturating_sub(1),
            6 => last_nullified_view.saturating_add(1),
            _ => last_nullified_view.saturating_sub(1),
        }
    }

    fn random_parent_view(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        match rng.gen::<u8>() % 6 {
            0 => last_vote_view.saturating_sub(1),
            1 => last_finalized_view,
            2 => last_notarized_view.saturating_sub(1),
            3 => last_notarized_view,
            4 => last_nullified_view.saturating_sub(1),
            _ => last_finalized_view.saturating_sub(1),
        }
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        random_payload(rng)
    }

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        tweak_bytes(rng, cert)
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        tweak_bytes(rng, msg)
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        if proposals_len == 0 {
            return None;
        }
        if proposals_len <= 1 {
            return Some(0);
        }
        if rng.gen_bool(0.5) {
            return None;
        }
        Some(proposals_len - 2)
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        Some((self.fault_rounds, self.fault_rounds_bound))
    }
}

pub struct AnyScope;

impl Strategy for AnyScope {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = self.random_view_for_proposal(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let parent = self.random_parent_view(
            rng,
            view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let payload = self.random_payload(rng);
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent),
            payload,
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
        proposal_with_parent_view(proposal, view)
    }

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        _last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = proposal.view().get();
        match rng.gen::<u8>() % 4 {
            0 => proposal_with_payload(proposal, random_payload(rng)),
            1 => proposal_with_view(
                proposal,
                random_view(
                    rng,
                    view,
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                ),
            ),
            2 => proposal_with_parent(
                proposal,
                random_parent_view(
                    rng,
                    view,
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                ),
            ),
            _ => {
                let view = random_view(
                    rng,
                    view,
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                );
                let parent = random_parent_view(
                    rng,
                    view,
                    last_finalized_view,
                    last_notarized_view,
                    last_nullified_view,
                );
                let payload = random_payload(rng);
                Proposal::new(
                    Round::new(Epoch::new(EPOCH), View::new(view)),
                    View::new(parent),
                    payload,
                )
            }
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
        random_view(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        last_view_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> u64 {
        random_view(
            rng,
            last_view_view,
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
        random_parent_view(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        )
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        random_payload(rng)
    }

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        if cert.is_empty() {
            return vec![0];
        }
        let len = cert.len();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        if msg.is_empty() {
            return vec![0];
        }
        let len = msg.len();
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        if proposals_len == 0 {
            return None;
        }
        if rng.gen_bool(0.5) {
            return None;
        }
        let idx = rng.gen_range(0..proposals_len);
        Some(idx)
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        None
    }
}

pub struct FutureScope {
    pub fault_rounds: u64,
    pub fault_rounds_bound: u64,
}

impl Strategy for FutureScope {
    fn random_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        last_finalized_view: u64,
        last_notarized_view: u64,
        last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = self.random_view_for_proposal(
            rng,
            last_vote_view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let parent = self.random_parent_view(
            rng,
            view,
            last_finalized_view,
            last_notarized_view,
            last_nullified_view,
        );
        let payload = self.random_payload(rng);
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent),
            payload,
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
        proposal_with_parent_view(proposal, view)
    }

    fn mutate_proposal(
        &self,
        rng: &mut impl Rng,
        proposal: &Proposal<Sha256Digest>,
        _last_vote_view: u64,
        _last_finalized_view: u64,
        _last_notarized_view: u64,
        _last_nullified_view: u64,
    ) -> Proposal<Sha256Digest> {
        let view = proposal.view().get();
        let parent = proposal.parent.get();
        let bump = if rng.gen_bool(0.5) { 1 } else { 2 };
        match rng.gen::<u8>() % 3 {
            0 => proposal_with_view(proposal, view.saturating_add(bump)),
            1 => proposal_with_parent(proposal, parent.saturating_add(bump)),
            _ => {
                let view = view.saturating_add(bump);
                let parent = parent.saturating_add(bump);
                Proposal::new(
                    Round::new(Epoch::new(EPOCH), View::new(view)),
                    View::new(parent),
                    proposal.payload,
                )
            }
        }
    }

    fn mutate_nullify_view(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        _last_finalized_view: u64,
        _last_notarized_view: u64,
        _last_nullified_view: u64,
    ) -> u64 {
        let bump = if rng.gen_bool(0.5) { 1 } else { 2 };
        last_vote_view.saturating_add(bump)
    }

    fn random_view_for_proposal(
        &self,
        rng: &mut impl Rng,
        last_vote_view: u64,
        _last_finalized_view: u64,
        _last_notarized_view: u64,
        _last_nullified_view: u64,
    ) -> u64 {
        let bump = if rng.gen_bool(0.5) { 1 } else { 2 };
        last_vote_view.saturating_add(bump)
    }

    fn random_parent_view(
        &self,
        rng: &mut impl Rng,
        base_view: u64,
        _last_finalized_view: u64,
        _last_notarized_view: u64,
        _last_nullified_view: u64,
    ) -> u64 {
        let bump = if rng.gen_bool(0.5) { 1 } else { 2 };
        base_view.saturating_add(bump)
    }

    fn random_payload(&self, rng: &mut impl Rng) -> Sha256Digest {
        random_payload(rng)
    }

    fn mutate_certificate_bytes(&self, rng: &mut impl Rng, cert: &[u8]) -> Vec<u8> {
        tweak_bytes(rng, cert)
    }

    fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
        tweak_bytes(rng, msg)
    }

    fn repeated_proposal_index(&self, rng: &mut impl Rng, proposals_len: usize) -> Option<usize> {
        if proposals_len == 0 {
            return None;
        }
        if proposals_len <= 1 {
            return Some(0);
        }
        if rng.gen_bool(0.5) {
            return None;
        }
        Some(proposals_len - 2)
    }

    fn fault_bounds(&self) -> Option<(u64, u64)> {
        Some((self.fault_rounds, self.fault_rounds_bound))
    }
}

fn proposal_with_view(proposal: &Proposal<Sha256Digest>, view: u64) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(view)),
        proposal.parent,
        proposal.payload,
    )
}

fn proposal_with_parent_view(
    proposal: &Proposal<Sha256Digest>,
    parent: u64,
) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(proposal.view().get())),
        View::new(parent),
        proposal.payload,
    )
}

fn proposal_with_parent(proposal: &Proposal<Sha256Digest>, parent: u64) -> Proposal<Sha256Digest> {
    proposal_with_parent_view(proposal, parent)
}

fn proposal_with_payload(
    proposal: &Proposal<Sha256Digest>,
    payload: Sha256Digest,
) -> Proposal<Sha256Digest> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(proposal.view().get())),
        proposal.parent,
        payload,
    )
}

fn tweak_payload(rng: &mut impl Rng, payload: Sha256Digest) -> Sha256Digest {
    let mut bytes = payload.0;
    let idx = rng.gen_range(0..bytes.len());
    let bit = rng.gen::<u8>() % 8;
    bytes[idx] ^= 1 << bit;
    Sha256Digest(bytes)
}

fn tweak_bytes(rng: &mut impl Rng, bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0];
    }
    let mut out = bytes.to_vec();
    let idx = rng.gen_range(0..out.len());
    let bit = rng.gen::<u8>() % 8;
    out[idx] ^= 1 << bit;
    out
}

fn random_payload(rng: &mut impl Rng) -> Sha256Digest {
    let mut arr = [0u8; 32];
    rng.fill_bytes(&mut arr);
    Sha256Digest::from(arr)
}

fn random_view(
    rng: &mut impl Rng,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    match rng.gen::<u8>() % 7 {
        0 => {
            if last_finalized_view == 0 {
                last_finalized_view
            } else {
                sample_inclusive(rng, 0, last_finalized_view - 1)
            }
        }
        1 => {
            if last_vote_view <= last_finalized_view {
                last_finalized_view
            } else {
                sample_inclusive(rng, last_finalized_view, last_vote_view)
            }
        }
        2 => {
            let hi = last_notarized_view
                .min(last_vote_view)
                .max(last_finalized_view);
            sample_inclusive(rng, last_finalized_view, hi)
        }
        3 => {
            let k = 1 + (rng.gen::<u8>() as u64 % 4);
            add_or_sample_at_or_above(rng, last_vote_view, k)
        }
        4 => {
            let k = 5 + (rng.gen::<u8>() as u64 % 6);
            add_or_sample_at_or_above(rng, last_vote_view, k)
        }
        5 => {
            let view = last_vote_view.max(last_nullified_view);
            let k = 1 + (rng.gen::<u8>() as u64 % 10);
            add_or_sample_at_or_above(rng, view, k)
        }
        _ => rng.gen::<u64>(),
    }
}

fn random_parent_view(
    rng: &mut impl Rng,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,
) -> u64 {
    random_view(
        rng,
        last_vote_view.saturating_sub(1),
        last_finalized_view,
        last_notarized_view,
        last_nullified_view,
    )
}

fn add_or_sample_at_or_above(rng: &mut impl Rng, view: u64, delta: u64) -> u64 {
    view.checked_add(delta)
        .unwrap_or_else(|| sample_inclusive(rng, view, u64::MAX))
}

fn sample_inclusive(rng: &mut impl Rng, lo: u64, hi: u64) -> u64 {
    if hi < lo {
        return lo;
    }
    if lo == 0 && hi == u64::MAX {
        return rng.gen::<u64>();
    }
    let width = (hi - lo) + 1;
    lo + (rng.gen::<u64>() % width)
}
