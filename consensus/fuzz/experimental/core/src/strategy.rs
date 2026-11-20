use crate::{EPOCH, FAULT_INJECTION_RATIO, utils::SetPartition};
use commonware_consensus::{
    Viewable,
    simplex::types::Proposal,
    types::{Epoch, Round, View},
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand::{Rng, RngExt as _};

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

    /// Whether proposal mutations are specifically probing header changes and
    /// must preserve the payload digest exactly.
    fn preserves_proposal_payload(&self) -> bool {
        false
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, SetPartition)>;

    /// Views where a `Disrupter` is allowed to inject or mutate messages.
    ///
    /// `None` means every observed view is faulty. `Some(views)` uses the same
    /// distinct-view schedule shape as `network_faults`.
    fn disrupter_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Option<Vec<View>>;

    /// Whether a `Disrupter` may emit raw byte-corrupted copies of observed
    /// votes, certificates, and resolver messages (which fail decode/signature
    /// checks). Semantic-only strategies return `false` to restrict emissions to
    /// validly re-signed messages.
    fn emit_byte_corruption(&self) -> bool {
        true
    }
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
    HeaderScope {
        fault_rounds: u64,
        fault_rounds_bound: u64,
        mutation: HeaderMutation,
    },
    SplitHeader {
        fault_rounds: u64,
        fault_rounds_bound: u64,
    },
}

fn sample_faults(
    count: u64,
    min_view: u64,
    max_view: u64,
    rng: &mut impl Rng,
) -> Vec<(View, SetPartition)> {
    sample_fault_views(count, min_view, max_view, rng)
        .into_iter()
        .map(|view| (view, sample_network_fault(rng)))
        .collect()
}

fn sample_fault_views(count: u64, min_view: u64, max_view: u64, rng: &mut impl Rng) -> Vec<View> {
    if count == 0 {
        return Vec::new();
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut views = (min_view..=max_view).collect::<Vec<_>>();
    let count = (count as usize).min(views.len());
    for i in 0..count {
        let idx = rng.random_range(i..views.len());
        views.swap(i, idx);
        let view = views[i];
        entries.push(View::new(view));
    }
    entries
}

/// Uniform sampler over the 14 non-trivial set partitions of `{0, 1, 2, 3}`.
/// Index 0 (the trivial single-block partition) is excluded because it equals
/// fully-connected and would be a no-op fault.
fn sample_network_fault(rng: &mut impl Rng) -> SetPartition {
    let idx = rng.random_range(1..15);
    SetPartition::n4(idx)
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
        match rng.random::<u8>() % 5 {
            0 => proposal_with_view(proposal, view.saturating_add(1)),
            1 => proposal_with_view(proposal, view.saturating_sub(1)),
            2 => proposal_with_parent_view(proposal, parent.saturating_add(1)),
            3 => proposal_with_parent_view(proposal, parent.saturating_sub(1)),
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
        match rng.random::<u8>() % 12 {
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
        match rng.random::<u8>() % 8 {
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
        match rng.random::<u8>() % 6 {
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
        if rng.random_bool(0.5) {
            return None;
        }
        Some(proposals_len - 2)
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, SetPartition)> {
        let bound = self.fault_rounds_bound.min(required_containers).max(1);
        // `.max(1)` enforces "adaptive is never silently empty" at the method
        // boundary, even if a caller constructs SmallScope with `fault_rounds = 0`.
        let d = self.fault_rounds.max(1).min(bound);
        sample_faults(d, 1, bound, rng)
    }

    fn disrupter_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Option<Vec<View>> {
        let bound = self.fault_rounds_bound.min(required_containers).max(1);
        let d = self.fault_rounds.max(1).min(bound);
        Some(sample_fault_views(d, 1, bound, rng))
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
        match rng.random::<u8>() % 4 {
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
            2 => proposal_with_parent_view(
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
        if rng.random_bool(0.5) {
            return None;
        }
        let idx = rng.random_range(0..proposals_len);
        Some(idx)
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, SetPartition)> {
        // Scale d with run length so density mirrors SmallScope's max
        // (`fault_rounds_bound / FAULT_INJECTION_RATIO`). Always ≥ 1 entry so
        // `Partition::Adaptive` is never silently empty.
        let max_d = (required_containers / FAULT_INJECTION_RATIO).max(1);
        let d = rng.random_range(1..=max_d);
        sample_faults(d, 1, required_containers, rng)
    }

    fn disrupter_faults(
        &self,
        _required_containers: u64,
        _rng: &mut impl Rng,
    ) -> Option<Vec<View>> {
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
        let bump = if rng.random_bool(0.5) { 1 } else { 2 };
        match rng.random::<u8>() % 3 {
            0 => proposal_with_view(proposal, view.saturating_add(bump)),
            1 => proposal_with_parent_view(proposal, parent.saturating_add(bump)),
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
        let bump = if rng.random_bool(0.5) { 1 } else { 2 };
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
        let bump = if rng.random_bool(0.5) { 1 } else { 2 };
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
        let bump = if rng.random_bool(0.5) { 1 } else { 2 };
        base_view.saturating_sub(bump)
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
        if rng.random_bool(0.5) {
            return None;
        }
        Some(proposals_len - 2)
    }

    fn network_faults(
        &self,
        required_containers: u64,
        rng: &mut impl Rng,
    ) -> Vec<(View, SetPartition)> {
        // Clamp `start` to at most `required_containers` so a future window of at least one
        // view always exists. Without the clamp, `bound == required_containers` would yield
        // an empty schedule and silently degenerate `Partition::Adaptive` into a no-op.
        let start = self
            .fault_rounds_bound
            .saturating_add(1)
            .min(required_containers)
            .max(1);
        let window = required_containers - start + 1;
        // `.max(1)` enforces "adaptive is never silently empty" at the method
        // boundary, even if a caller constructs FutureScope with `fault_rounds = 0`.
        let d = self.fault_rounds.max(1).min(window);
        sample_faults(d, start, required_containers, rng)
    }

    fn disrupter_faults(&self, required_containers: u64, rng: &mut impl Rng) -> Option<Vec<View>> {
        let start = self
            .fault_rounds_bound
            .saturating_add(1)
            .min(required_containers)
            .max(1);
        let window = required_containers - start + 1;
        let d = self.fault_rounds.max(1).min(window);
        Some(sample_fault_views(d, start, required_containers, rng))
    }
}

/// Payload-preserving proposal-header mutations.
#[derive(Clone, Copy, Debug)]
pub enum HeaderMutation {
    /// Re-point the proposal at the view immediately before its declared parent.
    PreviousParent,
    /// Re-point the proposal at the highest view the mutator has observed finalized.
    LastFinalizedParent,
    /// Re-point the proposal immediately before the highest view observed notarized.
    BeforeLastNotarizedParent,
}

/// Mutates proposal ancestry while preserving its round and payload.
///
/// A leader-valid proposal whose `(round, payload)` matches an honest proposal
/// but whose parent differs tests whether verification and certification state
/// is scoped to the full header. Unsolicited proposals stay at obsolete view 0
/// so they cannot occupy the victim's proposal slot before a reactive mutation
/// of an observed proposal arrives.
pub struct HeaderScope {
    pub fault_rounds: u64,
    pub fault_rounds_bound: u64,
    pub mutation: HeaderMutation,
}

impl HeaderScope {
    fn inner(&self) -> SmallScope {
        SmallScope {
            fault_rounds: self.fault_rounds,
            fault_rounds_bound: self.fault_rounds_bound,
        }
    }

    const fn header_mutation(&self) -> HeaderMutation {
        self.mutation
    }
}

/// Backward-compatible focused header strategy that always selects the
/// immediately previous parent.
pub struct SplitHeader {
    pub fault_rounds: u64,
    pub fault_rounds_bound: u64,
}

impl SplitHeader {
    fn inner(&self) -> SmallScope {
        SmallScope {
            fault_rounds: self.fault_rounds,
            fault_rounds_bound: self.fault_rounds_bound,
        }
    }

    const fn header_mutation(&self) -> HeaderMutation {
        HeaderMutation::PreviousParent
    }
}

fn mutate_header(
    mutation: HeaderMutation,
    proposal: &Proposal<Sha256Digest>,
    last_finalized_view: u64,
    last_notarized_view: u64,
) -> Proposal<Sha256Digest> {
    let parent = match mutation {
        HeaderMutation::PreviousParent => proposal.parent.get().saturating_sub(1),
        HeaderMutation::LastFinalizedParent => last_finalized_view,
        HeaderMutation::BeforeLastNotarizedParent => last_notarized_view.saturating_sub(1),
    };
    proposal_with_parent_view(proposal, parent)
}

macro_rules! impl_header_scope {
    ($strategy:ty) => {
        impl Strategy for $strategy {
            fn random_proposal(
                &self,
                rng: &mut impl Rng,
                last_vote_view: u64,
                last_finalized_view: u64,
                last_notarized_view: u64,
                last_nullified_view: u64,
            ) -> Proposal<Sha256Digest> {
                self.inner().random_proposal(
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
                _rng: &mut impl Rng,
                proposal: &Proposal<Sha256Digest>,
                _last_vote_view: u64,
                last_finalized_view: u64,
                last_notarized_view: u64,
                _last_nullified_view: u64,
            ) -> Proposal<Sha256Digest> {
                mutate_header(
                    self.header_mutation(),
                    proposal,
                    last_finalized_view,
                    last_notarized_view,
                )
            }

            fn mutate_nullify_view(
                &self,
                _rng: &mut impl Rng,
                last_vote_view: u64,
                _last_finalized_view: u64,
                last_notarized_view: u64,
                _last_nullified_view: u64,
            ) -> u64 {
                if last_notarized_view > 0 {
                    last_notarized_view
                } else {
                    last_vote_view
                }
            }

            // Proposal with view = 0 is guaranteed rejected; acts as a no-op
            fn random_view_for_proposal(
                &self,
                _rng: &mut impl Rng,
                _last_vote_view: u64,
                _last_finalized_view: u64,
                _last_notarized_view: u64,
                _last_nullified_view: u64,
            ) -> u64 {
                0
            }

            fn random_parent_view(
                &self,
                rng: &mut impl Rng,
                last_vote_view: u64,
                last_finalized_view: u64,
                last_notarized_view: u64,
                last_nullified_view: u64,
            ) -> u64 {
                self.inner().random_parent_view(
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
                tweak_bytes(rng, cert)
            }

            fn mutate_resolver_bytes(&self, rng: &mut impl Rng, msg: &[u8]) -> Vec<u8> {
                tweak_bytes(rng, msg)
            }

            fn repeated_proposal_index(
                &self,
                rng: &mut impl Rng,
                proposals_len: usize,
            ) -> Option<usize> {
                self.inner().repeated_proposal_index(rng, proposals_len)
            }

            fn preserves_proposal_payload(&self) -> bool {
                true
            }

            fn network_faults(
                &self,
                required_containers: u64,
                rng: &mut impl Rng,
            ) -> Vec<(View, SetPartition)> {
                self.inner().network_faults(required_containers, rng)
            }

            fn disrupter_faults(
                &self,
                _required_containers: u64,
                _rng: &mut impl Rng,
            ) -> Option<Vec<View>> {
                None
            }
        }
    };
}

impl_header_scope!(HeaderScope);
impl_header_scope!(SplitHeader);

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
    let idx = rng.random_range(0..bytes.len());
    let bit = rng.random::<u8>() % 8;
    bytes[idx] ^= 1 << bit;
    Sha256Digest(bytes)
}

fn tweak_bytes(rng: &mut impl Rng, bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![0];
    }
    let mut out = bytes.to_vec();
    let idx = rng.random_range(0..out.len());
    let bit = rng.random::<u8>() % 8;
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
    match rng.random::<u8>() % 7 {
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
            let k = 1 + (rng.random::<u8>() as u64 % 4);
            add_or_sample_at_or_above(rng, last_vote_view, k)
        }
        4 => {
            let k = 5 + (rng.random::<u8>() as u64 % 6);
            add_or_sample_at_or_above(rng, last_vote_view, k)
        }
        5 => {
            let view = last_vote_view.max(last_nullified_view);
            let k = 1 + (rng.random::<u8>() as u64 % 10);
            add_or_sample_at_or_above(rng, view, k)
        }
        _ => rng.random::<u64>(),
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
        return rng.random::<u64>();
    }
    let width = (hi - lo) + 1;
    lo + (rng.random::<u64>() % width)
}
