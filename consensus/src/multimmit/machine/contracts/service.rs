//! Deterministic service weights and costs.

/// One externally supplied scheduler lane.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Lane {
    PersistenceCompletion,
    LocalCompletion,
    Timer,
    ResolverResult,
    PeerObservation,
}

/// Positive weighted-round-robin credit for a lane.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LaneWeight {
    pub lane: Lane,
    pub credits: u16,
}

/// Latency-sensitive internal completions receive more service without starving ingress.
pub(crate) const LANE_WEIGHTS: [LaneWeight; 5] = [
    LaneWeight {
        lane: Lane::PersistenceCompletion,
        credits: 8,
    },
    LaneWeight {
        lane: Lane::LocalCompletion,
        credits: 8,
    },
    LaneWeight {
        lane: Lane::Timer,
        credits: 4,
    },
    LaneWeight {
        lane: Lane::ResolverResult,
        credits: 4,
    },
    LaneWeight {
        lane: Lane::PeerObservation,
        credits: 2,
    },
];

/// Maximum transition cost charged before the voter yields to the runtime.
pub(crate) const CORE_BUDGET: u32 = 256;

/// Accounting for one weighted-round-robin cycle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceCycle {
    lane_credits: [u16; 5],
    core_credits: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServiceError {
    LaneExhausted,
    CoreBudgetExhausted,
    CostOverflow,
}

impl ServiceCycle {
    pub fn new() -> Self {
        let mut lane_credits = [0; 5];
        for weight in LANE_WEIGHTS {
            lane_credits[weight.lane.index()] = weight.credits;
        }
        Self {
            lane_credits,
            core_credits: CORE_BUDGET,
        }
    }

    pub fn charge(&mut self, lane: Lane, cost: TransitionCost) -> Result<(), ServiceError> {
        let lane_credit = &mut self.lane_credits[lane.index()];
        if *lane_credit == 0 {
            return Err(ServiceError::LaneExhausted);
        }
        let cost = cost.credits().ok_or(ServiceError::CostOverflow)?;
        let Some(remaining) = self.core_credits.checked_sub(cost) else {
            return Err(ServiceError::CoreBudgetExhausted);
        };
        *lane_credit -= 1;
        self.core_credits = remaining;
        Ok(())
    }

    pub const fn remaining_core(&self) -> u32 {
        self.core_credits
    }

    pub const fn remaining_lane(&self, lane: Lane) -> u16 {
        self.lane_credits[lane.index()]
    }
}

impl Default for ServiceCycle {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor for component and per-chain fairness.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairCursor {
    next: usize,
}

impl FairCursor {
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    pub fn select(&mut self, ready: &[bool]) -> Option<usize> {
        if ready.is_empty() {
            return None;
        }
        for offset in 0..ready.len() {
            let index = self.next.checked_add(offset)? % ready.len();
            if ready[index] {
                self.next = (index + 1) % ready.len();
                return Some(index);
            }
        }
        None
    }
}

impl Default for FairCursor {
    fn default() -> Self {
        Self::new()
    }
}

impl Lane {
    const fn index(self) -> usize {
        match self {
            Self::PersistenceCompletion => 0,
            Self::LocalCompletion => 1,
            Self::Timer => 2,
            Self::ResolverResult => 3,
            Self::PeerObservation => 4,
        }
    }
}

/// A machine transition class charged against one core quantum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransitionCost {
    Constant,
    ArtifactItems(usize),
    CommitteePass(usize),
}

impl TransitionCost {
    pub fn credits(self) -> Option<u32> {
        let units = match self {
            Self::Constant => 1,
            Self::ArtifactItems(items) | Self::CommitteePass(items) => items.max(1),
        };
        u32::try_from(units).ok()
    }
}
