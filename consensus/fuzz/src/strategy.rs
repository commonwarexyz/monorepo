use crate::{FuzzInput, EPOCH};
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;

pub trait Strategy: Send + Sync {
    fn random_proposal(
        &self,
        input: &FuzzInput,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
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
        input: &FuzzInput,
        proposal: &Proposal<Sha256Digest>,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> Proposal<Sha256Digest>;

    fn mutate_nullify_view(
        &self,
        input: &FuzzInput,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64;

    fn random_view_for_proposal(
        &self,
        input: &FuzzInput,
        current_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64;

    fn random_parent_view(
        &self,
        input: &FuzzInput,
        base_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64;

    fn random_payload(&self, input: &FuzzInput) -> Sha256Digest;
}

#[derive(Clone, Copy, Debug)]
pub enum StrategyChoice {
    SmallScope,
    AnyScope,
}

pub struct SmallScope;

impl Strategy for SmallScope {
    fn random_proposal(
        &self,
        input: &FuzzInput,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> Proposal<Sha256Digest> {
        let view = self.random_view_for_proposal(
            input,
            last_vote,
            last_finalized,
            last_notarized,
            last_nullified,
        );
        let parent =
            self.random_parent_view(input, view, last_finalized, last_notarized, last_nullified);
        let payload = self.random_payload(input);
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
        input: &FuzzInput,
        proposal: &Proposal<Sha256Digest>,
        _last_vote: u64,
        _last_finalized: u64,
        _last_notarized: u64,
        _last_nullified: u64,
    ) -> Proposal<Sha256Digest> {
        let view = proposal.view().get();
        let parent = proposal.parent.get();
        match input.random_byte() % 4 {
            0 => proposal_with_view(proposal, view.saturating_add(1)),
            1 => proposal_with_view(proposal, view.saturating_sub(1)),
            2 => proposal_with_parent(proposal, parent.saturating_add(1)),
            _ => proposal_with_parent(proposal, parent.saturating_sub(1)),
        }
    }

    fn mutate_nullify_view(
        &self,
        input: &FuzzInput,
        last_vote: u64,
        _last_finalized: u64,
        last_notarized: u64,
        _last_nullified: u64,
    ) -> u64 {
        match input.random_byte() % 4 {
            0 => last_vote.saturating_add(1),
            1 => last_vote.saturating_sub(1),
            2 => last_notarized.saturating_add(1),
            _ => last_notarized.saturating_sub(1),
        }
    }

    fn random_view_for_proposal(
        &self,
        input: &FuzzInput,
        current_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64 {
        match input.random_byte() % 7 {
            0 => {
                let hi = last_notarized.min(current_view).max(last_finalized);
                sample_inclusive(input, last_finalized, hi)
            }
            1 => current_view,
            2 => current_view.saturating_add(1),
            3 => last_notarized.saturating_add(1),
            4 => last_notarized.saturating_add(2),
            5 => last_nullified.saturating_add(1),
            _ => input.random_u64(),
        }
    }

    fn random_parent_view(
        &self,
        input: &FuzzInput,
        base_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64 {
        random_parent_view(
            input,
            base_view,
            last_finalized,
            last_notarized,
            last_nullified,
        )
    }

    fn random_payload(&self, input: &FuzzInput) -> Sha256Digest {
        random_payload(input)
    }
}

pub struct AnyScope;

impl Strategy for AnyScope {
    fn random_proposal(
        &self,
        input: &FuzzInput,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> Proposal<Sha256Digest> {
        let view = self.random_view_for_proposal(
            input,
            last_vote,
            last_finalized,
            last_notarized,
            last_nullified,
        );
        let parent =
            self.random_parent_view(input, view, last_finalized, last_notarized, last_nullified);
        let payload = self.random_payload(input);
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
        input: &FuzzInput,
        proposal: &Proposal<Sha256Digest>,
        _last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> Proposal<Sha256Digest> {
        let base_view = proposal.view().get();
        match input.random_byte() % 4 {
            0 => proposal_with_payload(proposal, random_payload(input)),
            1 => proposal_with_view(
                proposal,
                random_view(
                    input,
                    base_view,
                    last_finalized,
                    last_notarized,
                    last_nullified,
                ),
            ),
            2 => proposal_with_parent(
                proposal,
                random_parent_view(
                    input,
                    base_view,
                    last_finalized,
                    last_notarized,
                    last_nullified,
                ),
            ),
            _ => {
                let view = random_view(
                    input,
                    base_view,
                    last_finalized,
                    last_notarized,
                    last_nullified,
                );
                let parent = random_parent_view(
                    input,
                    base_view,
                    last_finalized,
                    last_notarized,
                    last_nullified,
                );
                let payload = random_payload(input);
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
        input: &FuzzInput,
        last_vote: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64 {
        random_view(
            input,
            last_vote,
            last_finalized,
            last_notarized,
            last_nullified,
        )
    }

    fn random_view_for_proposal(
        &self,
        input: &FuzzInput,
        current_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64 {
        random_view(
            input,
            current_view,
            last_finalized,
            last_notarized,
            last_nullified,
        )
    }

    fn random_parent_view(
        &self,
        input: &FuzzInput,
        base_view: u64,
        last_finalized: u64,
        last_notarized: u64,
        last_nullified: u64,
    ) -> u64 {
        random_parent_view(
            input,
            base_view,
            last_finalized,
            last_notarized,
            last_nullified,
        )
    }

    fn random_payload(&self, input: &FuzzInput) -> Sha256Digest {
        random_payload(input)
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

fn random_payload(input: &FuzzInput) -> Sha256Digest {
    let bytes = input.random(32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32.min(bytes.len())]);
    Sha256Digest::from(arr)
}

fn random_view(
    input: &FuzzInput,
    current_view: u64,
    last_finalized: u64,
    last_notarized: u64,
    last_nullified: u64,
) -> u64 {
    match input.random_byte() % 7 {
        0 => {
            if last_finalized == 0 {
                last_finalized
            } else {
                sample_inclusive(input, 0, last_finalized - 1)
            }
        }
        1 => {
            if current_view <= last_finalized {
                last_finalized
            } else {
                sample_inclusive(input, last_finalized, current_view)
            }
        }
        2 => {
            let hi = last_notarized.min(current_view).max(last_finalized);
            sample_inclusive(input, last_finalized, hi)
        }
        3 => {
            let k = 1 + (input.random_byte() as u64 % 4);
            add_or_sample_at_or_above(input, current_view, k)
        }
        4 => {
            let k = 5 + (input.random_byte() as u64 % 6);
            add_or_sample_at_or_above(input, current_view, k)
        }
        5 => {
            let base = current_view.max(last_nullified);
            let k = 1 + (input.random_byte() as u64 % 10);
            add_or_sample_at_or_above(input, base, k)
        }
        _ => input.random_u64(),
    }
}

fn random_parent_view(
    input: &FuzzInput,
    base_view: u64,
    last_finalized: u64,
    last_notarized: u64,
    last_nullified: u64,
) -> u64 {
    random_view(
        input,
        base_view.saturating_sub(1),
        last_finalized,
        last_notarized,
        last_nullified,
    )
}

fn add_or_sample_at_or_above(input: &FuzzInput, view: u64, delta: u64) -> u64 {
    view.checked_add(delta)
        .unwrap_or_else(|| sample_inclusive(input, view, u64::MAX))
}

fn sample_inclusive(input: &FuzzInput, lo: u64, hi: u64) -> u64 {
    if hi < lo {
        return lo;
    }
    if lo == 0 && hi == u64::MAX {
        return input.random_u64();
    }
    let width = (hi - lo) + 1;
    lo + (input.random_u64() % width)
}
