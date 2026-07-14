//! The ByzzFuzz backend's fixed action catalog: the fault types the Q-policy
//! chooses among, and their stable [`ActionId`] order.
//!
//! The Mallory Q-core is action-agnostic (it sees only numeric ids); this
//! catalog is the ByzzFuzz binding of ids to concrete faults. The order is the
//! contract between `run_qlearn`'s `select` and its `enact` step, so it must not
//! change: `NoFault = 0`, `Process(Omit) = 1`, `Process(MutateVote) = 2`,
//! `Partition = 3`, `Crash = 4`.

use crate::{byzzfuzz::fault::ProcessAction, mallory::policy::ActionId};

/// Number of ByzzFuzz actions (this backend's Q-table column count). All five
/// are always legal, so the runner selects and learns with an all-true mask.
pub(crate) const N_ACTIONS: usize = 5;

/// The fault type the policy chooses per step. The learner picks only the fault
/// TYPE; the concrete target (receiver subset, message scope, partition index,
/// crash duration) is filled in by the caller from the same runtime RNG, so
/// byte-level fuzz guidance still reaches those choices (Mallory-faithful).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FaultAction {
    /// Append nothing for the upcoming view.
    NoFault,
    /// A single-view Byzantine process fault against a sampled receiver subset.
    /// Reuses [`ProcessAction`] (omit vs mutate-and-re-sign) rather than
    /// restating those variants.
    Process(ProcessAction),
    /// Drop traffic across a sampled network partition
    /// ([`super::fault::NetworkFault`]) for the upcoming view.
    Partition,
    /// Byzantine suppresses its own outbound (multi-view [`ProcessAction::Omit`])
    /// across a small range of views. NOT a true crash-stop: the engine stays
    /// alive and receiving, and because process faults match a message's carried
    /// view, old-view rebroadcasts within the range still escape.
    Crash,
}

impl FaultAction {
    /// Actions in [`ActionId`] order: index `i` has id `i`.
    const ALL: [FaultAction; N_ACTIONS] = [
        Self::NoFault,
        Self::Process(ProcessAction::Omit),
        Self::Process(ProcessAction::MutateVote),
        Self::Partition,
        Self::Crash,
    ];

    /// The fault an [`ActionId`] the policy returned maps to.
    pub(crate) fn from_id(id: ActionId) -> Self {
        Self::ALL[id]
    }
}
