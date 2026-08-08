//! Fixed-domain protocol state machine checked independently from the physical codec fixture.

const MAX_PARTICIPANTS: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum Operation {
    Append,
    Rewind,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum LocalState {
    Old,
    PrepareBody,
    Prepared,
    AbortBody,
    Aborted,
    TornFinal,
    Materialized,
    Tombstone,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum Goal {
    Unknown,
    Old,
    New,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum Phase {
    Idle,
    Preparing,
    Recovering,
    Finalizing,
    Finalized,
    Observed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
enum Observation {
    None,
    Old,
    New,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
struct State {
    count: u8,
    operations: [Operation; MAX_PARTICIPANTS],
    local: [LocalState; MAX_PARTICIPANTS],
    payload_valid: [bool; MAX_PARTICIPANTS],
    body_exact: [bool; MAX_PARTICIPANTS],
    body_durable: [bool; MAX_PARTICIPANTS],
    body_credit: [bool; MAX_PARTICIPANTS],
    witness_exact: [bool; MAX_PARTICIPANTS],
    // Historical prepared-guard evidence persists after A/M/T replaces the current root.
    guard_issued: [bool; MAX_PARTICIPANTS],
    // This history bit records a successful live-path sync; recovery never consults it.
    guard_sync_succeeded: [bool; MAX_PARTICIPANTS],
    // GuardDone is a volatile join credit and is always cleared before recovery.
    guard_done_credit: [bool; MAX_PARTICIPANTS],
    // A non-B byte in a validated B-to-M/T transition proves that finalization was issued only
    // after the exact prepared ring established the decision.
    final_write_survivor: [bool; MAX_PARTICIPANTS],
    // An exact final image selected from an unsynchronized write becomes independently durable only
    // when the modeled crash realizes that selection.
    final_pending_exact: [bool; MAX_PARTICIPANTS],
    abort_body_exact: [bool; MAX_PARTICIPANTS],
    abort_credit: [bool; MAX_PARTICIPANTS],
    // A selected abort guard cannot release the old vector until a crash realizes it or its sync
    // completes.
    abort_guard_pending_exact: [bool; MAX_PARTICIPANTS],
    independently_final: [bool; MAX_PARTICIPANTS],
    truncated: [bool; MAX_PARTICIPANTS],
    // A selected unsynchronized truncate becomes durable only when a crash realizes it.
    truncate_pending: [bool; MAX_PARTICIPANTS],
    // Mutation admission ends this single-group lifecycle abstraction. The later mutation itself
    // belongs to the next serialized lifecycle.
    mutation_admitted: [bool; MAX_PARTICIPANTS],
    names: u8,
    unlink_issued: u8,
    decision: bool,
    acknowledged: bool,
    goal: Goal,
    phase: Phase,
    observations: [Observation; MAX_PARTICIPANTS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(not(kani), allow(dead_code))]
enum ActionKind {
    StagePayload,
    TearPrepareBody,
    SyncPrepareBody,
    TearPrepareGuard,
    SyncPrepareGuard,
    Crash,
    DecideLive,
    Acknowledge,
    BeginRecovery,
    TearAbortBody,
    SyncAbortBody,
    TearAbortGuard,
    SyncAbortGuard,
    TearFinal,
    SyncFinal,
    TearTruncate,
    SyncTruncate,
    MarkFinalized,
    IssueUnlink,
    CrashUnlink,
    SyncUnlink,
    AdmitMutation,
    Observe,
    Stutter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
struct Action {
    kind: ActionKind,
    participant: u8,
    landed: bool,
    // Root-repair bits denote a surviving target-only byte; unlink bits are the surviving names.
    survivor_mask: u8,
}

impl State {
    fn initial(count: u8, operations: [Operation; MAX_PARTICIPANTS]) -> Self {
        let members = member_mask(count);
        Self {
            count,
            operations,
            local: [LocalState::Old; MAX_PARTICIPANTS],
            payload_valid: core::array::from_fn(|participant| {
                participant < count as usize && operations[participant] != Operation::Append
            }),
            body_exact: [false; MAX_PARTICIPANTS],
            body_durable: [false; MAX_PARTICIPANTS],
            body_credit: [false; MAX_PARTICIPANTS],
            witness_exact: [false; MAX_PARTICIPANTS],
            guard_issued: [false; MAX_PARTICIPANTS],
            guard_sync_succeeded: [false; MAX_PARTICIPANTS],
            guard_done_credit: [false; MAX_PARTICIPANTS],
            final_write_survivor: [false; MAX_PARTICIPANTS],
            final_pending_exact: [false; MAX_PARTICIPANTS],
            abort_body_exact: [false; MAX_PARTICIPANTS],
            abort_credit: [false; MAX_PARTICIPANTS],
            abort_guard_pending_exact: [false; MAX_PARTICIPANTS],
            independently_final: [false; MAX_PARTICIPANTS],
            truncated: [false; MAX_PARTICIPANTS],
            truncate_pending: [false; MAX_PARTICIPANTS],
            mutation_admitted: [false; MAX_PARTICIPANTS],
            names: members,
            unlink_issued: 0,
            decision: false,
            acknowledged: false,
            goal: Goal::Unknown,
            phase: Phase::Idle,
            observations: [Observation::None; MAX_PARTICIPANTS],
        }
    }

    fn member(&self, participant: usize) -> bool {
        participant < self.count as usize
    }

    fn members(&self) -> u8 {
        member_mask(self.count)
    }

    fn removals(&self) -> u8 {
        let mut result = 0u8;
        for participant in 0..MAX_PARTICIPANTS {
            if self.member(participant) && self.operations[participant] == Operation::Remove {
                result |= bit(participant);
            }
        }
        result
    }

    fn all_prepared(&self) -> bool {
        (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || (self.local[participant] == LocalState::Prepared
                    && self.body_exact[participant]
                    && self.body_durable[participant]
                    && self.witness_exact[participant]
                    && self.payload_valid[participant])
        })
    }

    fn all_phase_one_durable(&self) -> bool {
        (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || (self.body_exact[participant]
                    && self.body_durable[participant]
                    && self.witness_exact[participant]
                    && self.payload_valid[participant])
        })
    }

    fn all_guard_sync_succeeded(&self) -> bool {
        (0..MAX_PARTICIPANTS)
            .all(|participant| !self.member(participant) || self.guard_sync_succeeded[participant])
    }

    fn all_guard_done(&self) -> bool {
        (0..MAX_PARTICIPANTS)
            .all(|participant| !self.member(participant) || self.guard_done_credit[participant])
    }

    fn any_guard_issued(&self) -> bool {
        self.guard_issued.iter().any(|issued| *issued)
    }

    fn retained_semantic_provenance_supports_new(&self) -> bool {
        // These fields summarize a prior codec classification. This layer checks their transition
        // discipline; it does not reconstruct them from arbitrary bytes.
        (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || (self.body_exact[participant]
                    && self.body_durable[participant]
                    && self.witness_exact[participant]
                    && self.payload_valid[participant]
                    && match self.local[participant] {
                        LocalState::Prepared => self.guard_issued[participant],
                        LocalState::TornFinal => self.final_write_survivor[participant],
                        LocalState::Materialized | LocalState::Tombstone => {
                            self.independently_final[participant]
                                || self.final_pending_exact[participant]
                        }
                        LocalState::Missing => self.independently_final[participant],
                        _ => false,
                    })
        })
    }

    fn all_old_ready(&self) -> bool {
        (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || self.local[participant] == LocalState::Old
                || (self.local[participant] == LocalState::Aborted
                    && !self.abort_guard_pending_exact[participant])
        })
    }

    fn has_durable_abort_authority(&self) -> bool {
        (0..MAX_PARTICIPANTS).any(|participant| {
            self.member(participant)
                && self.local[participant] == LocalState::Aborted
                && !self.abort_guard_pending_exact[participant]
        })
    }

    fn old_vector_selected(&self) -> bool {
        !self.decision
            && self.goal == Goal::Old
            && (self.all_old_ready() || self.has_durable_abort_authority())
    }

    fn participant_mutable(&self, participant: usize) -> bool {
        self.member(participant)
            && self.old_vector_selected()
            && (self.local[participant] == LocalState::Old
                || (self.local[participant] == LocalState::Aborted
                    && !self.abort_guard_pending_exact[participant]))
    }

    fn all_independently_final(&self) -> bool {
        (0..MAX_PARTICIPANTS)
            .all(|participant| !self.member(participant) || self.independently_final[participant])
    }

    fn all_required_truncations_complete(&self) -> bool {
        (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || self.operations[participant] != Operation::Rewind
                || self.truncated[participant]
        })
    }

    fn expected_new(&self, participant: usize) -> Observation {
        if self.operations[participant] == Operation::Remove {
            Observation::Absent
        } else {
            Observation::New
        }
    }

    fn live_prepare(&self) -> bool {
        !self.decision
            && self.goal == Goal::Unknown
            && matches!(self.phase, Phase::Idle | Phase::Preparing)
    }

    fn decode(&self, participant: usize) -> Observation {
        if !self.member(participant) {
            return Observation::None;
        }
        if self.names & bit(participant) == 0 {
            return if self.operations[participant] == Operation::Remove
                && self.independently_final[participant]
            {
                Observation::Absent
            } else {
                Observation::None
            };
        }
        if self.old_vector_selected() {
            return Observation::Old;
        }
        match self.local[participant] {
            LocalState::Old | LocalState::Aborted => Observation::Old,
            LocalState::Materialized if self.independently_final[participant] => Observation::New,
            LocalState::Tombstone if self.independently_final[participant] => Observation::Absent,
            _ => Observation::None,
        }
    }

    fn observed_atomic(&self) -> bool {
        if self.phase != Phase::Observed {
            return true;
        }
        let old = (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant) || self.observations[participant] == Observation::Old
        });
        let new = (0..MAX_PARTICIPANTS).all(|participant| {
            !self.member(participant)
                || self.observations[participant] == self.expected_new(participant)
        });
        old || new
    }

    fn well_formed(&self) -> bool {
        if !(1..=MAX_PARTICIPANTS as u8).contains(&self.count)
            || self.names & !self.members() != 0
            || self.unlink_issued & !self.removals() != 0
        {
            return false;
        }
        for participant in 0..MAX_PARTICIPANTS {
            if !self.member(participant) {
                if self.names & bit(participant) != 0 || self.unlink_issued & bit(participant) != 0
                {
                    return false;
                }
                continue;
            }
            if (self.truncated[participant] || self.truncate_pending[participant])
                && self.operations[participant] != Operation::Rewind
            {
                return false;
            }
            if self.truncated[participant] && self.truncate_pending[participant] {
                return false;
            }
            if self.truncate_pending[participant]
                && (!self.decision || !matches!(self.phase, Phase::Recovering | Phase::Finalizing))
            {
                return false;
            }
            if self.local[participant] == LocalState::Missing && self.names & bit(participant) != 0
            {
                return false;
            }
            if self.final_write_survivor[participant]
                != (self.local[participant] == LocalState::TornFinal)
            {
                return false;
            }
            if self.final_pending_exact[participant]
                && (!matches!(
                    self.local[participant],
                    LocalState::Materialized | LocalState::Tombstone
                ) || self.independently_final[participant]
                    || ((self.operations[participant] == Operation::Remove)
                        != (self.local[participant] == LocalState::Tombstone))
                    || self.phase != Phase::Finalizing)
            {
                return false;
            }
            if self.abort_guard_pending_exact[participant]
                && (self.local[participant] != LocalState::Aborted
                    || self.phase != Phase::Recovering
                    || self.goal != Goal::Old)
            {
                return false;
            }
        }
        true
    }

    fn invariant(&self) -> bool {
        if !self.well_formed() || !self.observed_atomic() {
            return false;
        }
        if self.acknowledged && (!self.decision || !self.all_guard_sync_succeeded()) {
            return false;
        }
        if self.unlink_issued != 0
            && !(self.phase == Phase::Finalized && self.decision && self.all_independently_final())
        {
            return false;
        }
        if (self.phase == Phase::Preparing && (self.decision || self.goal != Goal::Unknown))
            || (self.phase == Phase::Finalizing && !self.decision)
            || (self.goal == Goal::Old && self.decision)
            || (self.goal == Goal::New && !self.decision)
            || (self.phase != Phase::Observed
                && self
                    .observations
                    .iter()
                    .any(|observation| *observation != Observation::None))
        {
            return false;
        }
        if matches!(self.phase, Phase::Finalized | Phase::Observed)
            && !((self.decision
                && self.goal == Goal::New
                && self.all_independently_final()
                && self.all_required_truncations_complete())
                || self.old_vector_selected())
        {
            return false;
        }
        if self.decision && !self.retained_semantic_provenance_supports_new() {
            return false;
        }
        if self.names != self.members()
            && (!self.all_independently_final()
                || self.members() & !self.names & !self.removals() != 0)
        {
            return false;
        }
        for participant in 0..MAX_PARTICIPANTS {
            if self.mutation_admitted[participant] && !self.participant_mutable(participant) {
                return false;
            }
            if !self.member(participant) {
                continue;
            }
            let local = self.local[participant];
            if self.decision
                && !matches!(
                    local,
                    LocalState::Prepared
                        | LocalState::TornFinal
                        | LocalState::Materialized
                        | LocalState::Tombstone
                        | LocalState::Missing
                )
            {
                return false;
            }
            if self.body_credit[participant]
                && (!self.body_exact[participant]
                    || !self.body_durable[participant]
                    || !self.witness_exact[participant]
                    || !self.payload_valid[participant]
                    || local != LocalState::PrepareBody
                    || self.phase != Phase::Preparing
                    || self.guard_issued[participant]
                    || self.guard_sync_succeeded[participant]
                    || self.guard_done_credit[participant])
            {
                return false;
            }
            if self.guard_issued[participant] && !self.all_phase_one_durable() {
                return false;
            }
            if self.guard_sync_succeeded[participant] && !self.guard_issued[participant] {
                return false;
            }
            if self.guard_done_credit[participant]
                && (!self.guard_sync_succeeded[participant]
                    || local != LocalState::Prepared
                    || self.phase != Phase::Preparing
                    || self.decision
                    || self.goal != Goal::Unknown)
            {
                return false;
            }
            if self.phase == Phase::Preparing
                && self.guard_sync_succeeded[participant]
                && !self.guard_done_credit[participant]
            {
                return false;
            }
            if matches!(
                local,
                LocalState::Prepared
                    | LocalState::TornFinal
                    | LocalState::Materialized
                    | LocalState::Tombstone
            ) && !self.guard_issued[participant]
            {
                return false;
            }
            if self.abort_credit[participant]
                && (!self.abort_body_exact[participant]
                    || self.decision
                    || local != LocalState::AbortBody)
            {
                return false;
            }
            if local == LocalState::Aborted
                && (!self.abort_body_exact[participant] || self.decision)
            {
                return false;
            }
            if matches!(
                local,
                LocalState::TornFinal | LocalState::Materialized | LocalState::Tombstone
            ) && !self.decision
            {
                return false;
            }
            if self.independently_final[participant]
                != (matches!(
                    local,
                    LocalState::Materialized | LocalState::Tombstone | LocalState::Missing
                ) && !self.final_pending_exact[participant])
            {
                return false;
            }
            if self.independently_final[participant]
                && ((self.operations[participant] == Operation::Remove)
                    != matches!(local, LocalState::Tombstone | LocalState::Missing))
            {
                return false;
            }
            if self.truncated[participant] && !self.decision {
                return false;
            }
        }
        if self.all_guard_sync_succeeded() && !self.decision && self.phase != Phase::Preparing {
            return false;
        }
        if self.phase == Phase::Observed {
            for participant in 0..MAX_PARTICIPANTS {
                if !self.member(participant) {
                    continue;
                }
                if self.observations[participant] != self.decode(participant)
                    || self.observations[participant] == Observation::None
                {
                    return false;
                }
            }
            if self.acknowledged
                && !(0..MAX_PARTICIPANTS).all(|participant| {
                    !self.member(participant)
                        || self.observations[participant] == self.expected_new(participant)
                })
            {
                return false;
            }
        }
        true
    }

    fn step(mut self, action: Action) -> Self {
        if self.mutation_admitted.iter().any(|admitted| *admitted) {
            return self;
        }
        let participant = action.participant as usize;
        match action.kind {
            ActionKind::StagePayload
                if self.member(participant)
                    && self.live_prepare()
                    && !self.any_guard_issued()
                    && self.local[participant] == LocalState::Old
                    && !self.guard_issued[participant] =>
            {
                if self.operations[participant] == Operation::Append {
                    self.payload_valid[participant] = action.landed;
                } else {
                    self.payload_valid[participant] = true;
                }
                self.phase = Phase::Preparing;
            }
            ActionKind::TearPrepareBody
                if self.member(participant)
                    && self.live_prepare()
                    && !self.any_guard_issued()
                    && !self.guard_issued[participant]
                    && matches!(
                        self.local[participant],
                        LocalState::Old | LocalState::PrepareBody
                    ) =>
            {
                self.local[participant] = LocalState::PrepareBody;
                self.body_exact[participant] = action.landed;
                self.body_durable[participant] = false;
                self.body_credit[participant] = false;
                self.witness_exact[participant] = action.landed;
                self.phase = Phase::Preparing;
            }
            ActionKind::SyncPrepareBody
                if self.member(participant)
                    && self.live_prepare()
                    && !self.any_guard_issued()
                    && !self.guard_issued[participant]
                    && self.payload_valid[participant]
                    && matches!(
                        self.local[participant],
                        LocalState::Old | LocalState::PrepareBody
                    ) =>
            {
                self.local[participant] = LocalState::PrepareBody;
                self.body_exact[participant] = true;
                self.body_durable[participant] = true;
                self.body_credit[participant] = true;
                self.witness_exact[participant] = true;
                self.phase = Phase::Preparing;
            }
            ActionKind::TearPrepareGuard
                if self.member(participant)
                    && self.live_prepare()
                    && self.body_credit[participant]
                    && self.all_phase_one_durable() =>
            {
                self.guard_issued[participant] = action.landed;
                if action.landed {
                    self.local[participant] = LocalState::Prepared;
                }
                self.body_credit[participant] = false;
                self.phase = Phase::Preparing;
            }
            ActionKind::SyncPrepareGuard
                if self.member(participant)
                    && self.live_prepare()
                    && self.body_credit[participant]
                    && self.all_phase_one_durable() =>
            {
                self.guard_issued[participant] = true;
                self.guard_sync_succeeded[participant] = true;
                self.guard_done_credit[participant] = true;
                self.local[participant] = LocalState::Prepared;
                self.body_credit[participant] = false;
                self.phase = Phase::Preparing;
            }
            ActionKind::Crash => {
                self.body_credit = [false; MAX_PARTICIPANTS];
                self.guard_done_credit = [false; MAX_PARTICIPANTS];
                self.abort_credit = [false; MAX_PARTICIPANTS];
                self.unlink_issued = 0;
                for participant in 0..MAX_PARTICIPANTS {
                    if self.final_pending_exact[participant] {
                        self.final_pending_exact[participant] = false;
                        self.independently_final[participant] = true;
                    }
                    self.abort_guard_pending_exact[participant] = false;
                    if self.truncate_pending[participant] {
                        self.truncate_pending[participant] = false;
                        self.truncated[participant] = true;
                    }
                }
                self.decision = self.retained_semantic_provenance_supports_new();
                self.phase = Phase::Recovering;
                self.goal = Goal::Unknown;
                self.observations = [Observation::None; MAX_PARTICIPANTS];
            }
            ActionKind::DecideLive
                if self.live_prepare() && self.all_prepared() && self.all_guard_done() =>
            {
                self.decision = true;
                self.goal = Goal::New;
                self.phase = Phase::Finalizing;
                self.guard_done_credit = [false; MAX_PARTICIPANTS];
            }
            ActionKind::Acknowledge
                if self.decision
                    && self.phase == Phase::Finalizing
                    && self.all_prepared()
                    && self.all_guard_sync_succeeded() =>
            {
                self.acknowledged = true;
            }
            ActionKind::BeginRecovery if self.phase == Phase::Recovering => {
                self.body_credit = [false; MAX_PARTICIPANTS];
                self.guard_done_credit = [false; MAX_PARTICIPANTS];
                self.abort_credit = [false; MAX_PARTICIPANTS];
                self.phase = Phase::Recovering;
                if self.retained_semantic_provenance_supports_new() {
                    self.decision = true;
                    self.goal = Goal::New;
                } else {
                    self.decision = false;
                    self.goal = Goal::Old;
                }
            }
            ActionKind::TearAbortBody
                if self.member(participant)
                    && !self.decision
                    && self.phase == Phase::Recovering
                    && self.goal == Goal::Old
                    && self.local[participant] != LocalState::Aborted
                    && !self.abort_credit[participant]
                    && !self.independently_final[participant] =>
            {
                if action.landed {
                    self.local[participant] = LocalState::AbortBody;
                    self.abort_body_exact[participant] = true;
                } else if action.survivor_mask & bit(participant) != 0
                    && !self.abort_body_exact[participant]
                {
                    self.local[participant] = LocalState::AbortBody;
                }
            }
            ActionKind::SyncAbortBody
                if self.member(participant)
                    && !self.decision
                    && self.phase == Phase::Recovering
                    && self.goal == Goal::Old
                    && self.local[participant] != LocalState::Aborted
                    && !self.independently_final[participant] =>
            {
                self.local[participant] = LocalState::AbortBody;
                self.abort_body_exact[participant] = true;
                self.abort_credit[participant] = true;
            }
            ActionKind::TearAbortGuard
                if self.member(participant)
                    && !self.decision
                    && self.phase == Phase::Recovering
                    && self.goal == Goal::Old
                    && self.abort_credit[participant] =>
            {
                if action.landed {
                    self.local[participant] = LocalState::Aborted;
                    self.abort_guard_pending_exact[participant] = true;
                }
                self.abort_credit[participant] = false;
            }
            ActionKind::SyncAbortGuard
                if self.member(participant)
                    && !self.decision
                    && self.phase == Phase::Recovering
                    && self.goal == Goal::Old
                    && self.abort_credit[participant] =>
            {
                self.local[participant] = LocalState::Aborted;
                self.abort_guard_pending_exact[participant] = false;
                self.abort_credit[participant] = false;
            }
            ActionKind::TearFinal
                if self.member(participant)
                    && self.decision
                    && matches!(self.phase, Phase::Recovering | Phase::Finalizing)
                    && !self.independently_final[participant] =>
            {
                if action.landed {
                    self.local[participant] = if self.operations[participant] == Operation::Remove {
                        LocalState::Tombstone
                    } else {
                        LocalState::Materialized
                    };
                    self.final_write_survivor[participant] = false;
                    self.final_pending_exact[participant] = true;
                    self.independently_final[participant] = false;
                } else if self.final_write_survivor[participant]
                    || action.survivor_mask & bit(participant) != 0
                {
                    self.local[participant] = LocalState::TornFinal;
                    self.final_write_survivor[participant] = true;
                    self.final_pending_exact[participant] = false;
                    self.independently_final[participant] = false;
                } else {
                    self.local[participant] = LocalState::Prepared;
                    self.final_write_survivor[participant] = false;
                    self.final_pending_exact[participant] = false;
                    self.independently_final[participant] = false;
                }
                self.phase = Phase::Finalizing;
            }
            ActionKind::SyncFinal
                if self.member(participant)
                    && self.decision
                    && matches!(self.phase, Phase::Recovering | Phase::Finalizing)
                    && !self.independently_final[participant] =>
            {
                self.local[participant] = if self.operations[participant] == Operation::Remove {
                    LocalState::Tombstone
                } else {
                    LocalState::Materialized
                };
                self.final_write_survivor[participant] = false;
                self.final_pending_exact[participant] = false;
                self.independently_final[participant] = true;
                self.phase = Phase::Finalizing;
            }
            ActionKind::TearTruncate
                if self.member(participant)
                    && self.decision
                    && matches!(self.phase, Phase::Recovering | Phase::Finalizing)
                    && self.operations[participant] == Operation::Rewind
                    && !self.truncated[participant] =>
            {
                self.truncate_pending[participant] |= action.landed;
            }
            ActionKind::SyncTruncate
                if self.member(participant)
                    && self.decision
                    && matches!(self.phase, Phase::Recovering | Phase::Finalizing)
                    && self.operations[participant] == Operation::Rewind =>
            {
                self.truncated[participant] = true;
                self.truncate_pending[participant] = false;
            }
            ActionKind::MarkFinalized
                if matches!(self.phase, Phase::Recovering | Phase::Finalizing)
                    && ((self.all_independently_final()
                        && self.decision
                        && self.goal == Goal::New
                        && self.all_required_truncations_complete())
                        || self.old_vector_selected()) =>
            {
                self.phase = Phase::Finalized;
            }
            ActionKind::IssueUnlink
                if self.phase == Phase::Finalized
                    && self.decision
                    && self.all_independently_final() =>
            {
                self.unlink_issued = self.removals() & self.names;
            }
            ActionKind::CrashUnlink if self.unlink_issued != 0 => {
                let survives = action.survivor_mask & self.unlink_issued;
                self.names &= !survives;
                for participant in 0..MAX_PARTICIPANTS {
                    if survives & bit(participant) != 0 {
                        self.local[participant] = LocalState::Missing;
                        self.final_write_survivor[participant] = false;
                    }
                }
                self.unlink_issued = 0;
                self.phase = Phase::Recovering;
                self.goal = Goal::Unknown;
                self.observations = [Observation::None; MAX_PARTICIPANTS];
            }
            ActionKind::SyncUnlink if self.unlink_issued != 0 => {
                let removed = self.unlink_issued;
                self.names &= !removed;
                for participant in 0..MAX_PARTICIPANTS {
                    if removed & bit(participant) != 0 {
                        self.local[participant] = LocalState::Missing;
                        self.final_write_survivor[participant] = false;
                    }
                }
                self.unlink_issued = 0;
            }
            ActionKind::AdmitMutation if self.participant_mutable(participant) => {
                self.mutation_admitted[participant] = true;
            }
            ActionKind::Observe if self.phase == Phase::Finalized && self.unlink_issued == 0 => {
                let decoded = core::array::from_fn(|participant| self.decode(participant));
                if (0..MAX_PARTICIPANTS).all(|participant| {
                    !self.member(participant) || decoded[participant] != Observation::None
                }) {
                    self.observations = decoded;
                    self.phase = Phase::Observed;
                }
            }
            ActionKind::Stutter => {}
            _ => {}
        }
        self
    }
}

const fn bit(participant: usize) -> u8 {
    1 << participant
}

const fn member_mask(count: u8) -> u8 {
    (1 << count) - 1
}

const fn action(kind: ActionKind, participant: usize) -> Action {
    Action {
        kind,
        participant: participant as u8,
        landed: false,
        survivor_mask: 0,
    }
}

fn mixed_ard_decided() -> State {
    let mut state = State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
    for participant in 0..3 {
        let mut stage = action(ActionKind::StagePayload, participant);
        stage.landed = true;
        state = state.step(stage);
        state = state.step(action(ActionKind::SyncPrepareBody, participant));
    }
    for participant in 0..3 {
        state = state.step(action(ActionKind::SyncPrepareGuard, participant));
    }
    state = state.step(action(ActionKind::DecideLive, 0));
    state.step(action(ActionKind::Acknowledge, 0))
}

fn mixed_phase_two_crash(guard_survives: [bool; MAX_PARTICIPANTS]) -> State {
    let mut state = State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
    for participant in 0..MAX_PARTICIPANTS {
        let mut stage = action(ActionKind::StagePayload, participant);
        stage.landed = true;
        state = state.step(stage);
        state = state.step(action(ActionKind::SyncPrepareBody, participant));
    }
    for (participant, landed) in guard_survives.into_iter().enumerate() {
        let mut guard = action(ActionKind::TearPrepareGuard, participant);
        guard.landed = landed;
        state = state.step(guard);
    }
    state = state.step(action(ActionKind::Crash, 0));
    state.step(action(ActionKind::BeginRecovery, 0))
}

fn finish_mixed_recovery(mut state: State) -> State {
    if state.decision {
        for participant in 0..MAX_PARTICIPANTS {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        state = state.step(action(ActionKind::SyncUnlink, 0));
    } else {
        for participant in 0..MAX_PARTICIPANTS {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            state = state.step(action(ActionKind::SyncAbortGuard, participant));
        }
        state = state.step(action(ActionKind::MarkFinalized, 0));
    }
    state.step(action(ActionKind::Observe, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_append_rewind_remove_lifecycle_is_atomic() {
        let mut state = mixed_ard_decided();
        assert!(state.invariant());
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        state = state.step(action(ActionKind::SyncUnlink, 0));
        state = state.step(action(ActionKind::Observe, 0));
        assert_eq!(
            state.observations,
            [Observation::New, Observation::New, Observation::Absent]
        );
        assert!(state.invariant());
    }

    #[test]
    fn interrupted_abort_reaches_old_vector() {
        let mut state =
            State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
        for participant in 0..3 {
            let mut stage = action(ActionKind::StagePayload, participant);
            stage.landed = true;
            state = state.step(stage);
            let mut tear = action(ActionKind::TearPrepareBody, participant);
            tear.landed = participant == 0;
            state = state.step(tear);
        }
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            let mut guard = action(ActionKind::TearAbortGuard, participant);
            guard.landed = participant != 1;
            state = state.step(guard);
            if participant == 1 {
                state = state.step(action(ActionKind::SyncAbortBody, participant));
                state = state.step(action(ActionKind::SyncAbortGuard, participant));
            }
        }
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::Observe, 0));
        assert_eq!(state.observations, [Observation::Old; 3]);
        assert!(state.invariant());
    }

    #[test]
    fn one_abort_authority_selects_old_before_peer_normalization() {
        let mut state =
            State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
        for participant in 0..3 {
            let mut stage = action(ActionKind::StagePayload, participant);
            stage.landed = true;
            state = state.step(stage);
            state = state.step(action(ActionKind::SyncPrepareBody, participant));
        }
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::SyncAbortBody, 0));
        state = state.step(action(ActionKind::SyncAbortGuard, 0));

        assert!(state.old_vector_selected());
        assert!(state.participant_mutable(0));
        assert!(!state.participant_mutable(1));
        assert!(!state.participant_mutable(2));
        let blocked = state.step(action(ActionKind::AdmitMutation, 1));
        assert!(!blocked.mutation_admitted[1]);
        let admitted = state.step(action(ActionKind::AdmitMutation, 0));
        assert!(admitted.mutation_admitted[0]);

        let observed = state
            .step(action(ActionKind::MarkFinalized, 0))
            .step(action(ActionKind::Observe, 0));
        assert_eq!(observed.observations, [Observation::Old; 3]);
        assert!(observed.invariant());

        for participant in 1..3 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            state = state.step(action(ActionKind::SyncAbortGuard, participant));
            assert!(state.participant_mutable(participant));
            let admitted = state.step(action(ActionKind::AdmitMutation, participant));
            assert!(admitted.mutation_admitted[participant]);
        }
        assert!(state.all_old_ready());
        assert!(state.invariant());
    }

    #[test]
    fn prepare_guard_completion_credit_is_volatile() {
        let mut state = State::initial(1, [Operation::Append; MAX_PARTICIPANTS]);
        let mut stage = action(ActionKind::StagePayload, 0);
        stage.landed = true;
        state = state.step(stage);
        state = state.step(action(ActionKind::SyncPrepareBody, 0));
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));
        assert!(state.guard_sync_succeeded[0]);
        assert!(state.guard_done_credit[0]);

        state = state.step(action(ActionKind::Crash, 0));
        assert!(state.guard_sync_succeeded[0]);
        assert!(!state.guard_done_credit[0]);
        assert!(state.invariant());
    }

    #[test]
    fn phase_two_crash_cut_selects_only_complete_vectors() {
        for mask in 0u8..8 {
            let guards = core::array::from_fn(|participant| mask & bit(participant) != 0);
            let state = mixed_phase_two_crash(guards);
            let all_guards = mask == 0b111;
            assert_eq!(state.decision, all_guards);
            assert_eq!(state.goal, if all_guards { Goal::New } else { Goal::Old });

            let state = finish_mixed_recovery(state);
            assert_eq!(
                state.observations,
                if all_guards {
                    [Observation::New, Observation::New, Observation::Absent]
                } else {
                    [Observation::Old; MAX_PARTICIPANTS]
                }
            );
            assert!(state.invariant());
        }
    }

    #[test]
    fn exact_abort_root_is_terminal_during_body_repair() {
        let mut state = State::initial(1, [Operation::Append; 3]);
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::SyncAbortBody, 0));
        state = state.step(action(ActionKind::SyncAbortGuard, 0));
        assert_eq!(state.local[0], LocalState::Aborted);

        let before = state;
        let mut tear = action(ActionKind::TearAbortBody, 0);
        tear.landed = false;
        assert_eq!(state.step(tear), before);
        assert_eq!(state.step(action(ActionKind::SyncAbortBody, 0)), before);
    }

    #[test]
    fn empty_abort_body_survival_preserves_the_exact_prepared_source() {
        let mut state = State::initial(2, [Operation::Append; 3]);
        for participant in 0..2 {
            let mut stage = action(ActionKind::StagePayload, participant);
            stage.landed = true;
            state = state.step(stage);
            state = state.step(action(ActionKind::SyncPrepareBody, participant));
        }
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        assert_eq!(state.goal, Goal::Old);
        assert_eq!(state.local[0], LocalState::Prepared);

        let before = state;
        state = state.step(action(ActionKind::TearAbortBody, 0));

        assert_eq!(state, before);
    }

    #[test]
    fn recovery_cannot_promote_a_prepare_guard() {
        let mut state = State::initial(1, [Operation::Append; 3]);
        let mut stage = action(ActionKind::StagePayload, 0);
        stage.landed = true;
        state = state.step(stage);
        state = state.step(action(ActionKind::SyncPrepareBody, 0));
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        let before = state;
        state = state.step(action(ActionKind::SyncPrepareBody, 0));
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));
        assert_eq!(state, before);
        assert!(!state.guard_issued[0]);
        assert!(state.invariant());
    }

    #[test]
    fn a_prepare_guard_waits_for_the_group_body_join() {
        let mut state = State::initial(2, [Operation::Append; 3]);
        let mut stage = action(ActionKind::StagePayload, 0);
        stage.landed = true;
        state = state.step(stage);
        state = state.step(action(ActionKind::SyncPrepareBody, 0));

        let before = state;
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));

        assert_eq!(state, before);
        assert!(!state.guard_issued[0]);
    }

    #[test]
    fn a_published_guard_freezes_every_prepare_body() {
        let mut state = State::initial(2, [Operation::Append; 3]);
        for participant in 0..2 {
            let mut stage = action(ActionKind::StagePayload, participant);
            stage.landed = true;
            state = state.step(stage);
            state = state.step(action(ActionKind::SyncPrepareBody, participant));
        }
        state = state.step(action(ActionKind::SyncPrepareGuard, 0));

        let before = state;
        let mut rewrite = action(ActionKind::TearPrepareBody, 1);
        rewrite.landed = false;
        state = state.step(rewrite);

        assert_eq!(state, before);
        assert!(state.invariant());
    }

    #[test]
    fn torn_final_target_byte_rederives_the_new_recovery_goal() {
        let mut state = mixed_ard_decided();
        let mut tear = action(ActionKind::TearFinal, 0);
        tear.survivor_mask = bit(0);
        state = state.step(tear);
        assert_eq!(state.local[0], LocalState::TornFinal);
        assert!(state.final_write_survivor[0]);

        state = state.step(action(ActionKind::Crash, 0));
        assert!(state.decision);
        state = state.step(action(ActionKind::BeginRecovery, 0));
        assert_eq!(state.goal, Goal::New);
        assert!(state.invariant());
    }

    #[test]
    fn unsynchronized_final_roots_cannot_authorize_unlink() {
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            let mut tear = action(ActionKind::TearFinal, participant);
            tear.landed = true;
            state = state.step(tear);
        }

        assert!(!state.all_independently_final());
        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalizing);
        state = state.step(action(ActionKind::IssueUnlink, 0));
        assert_eq!(state.unlink_issued, 0);

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        assert!(state.all_independently_final());
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        assert_eq!(state.unlink_issued, bit(2));
        assert!(state.invariant());
    }

    #[test]
    fn pending_final_root_must_match_the_operation() {
        let mut state = mixed_ard_decided();
        let mut tear = action(ActionKind::TearFinal, 2);
        tear.landed = true;
        state = state.step(tear);
        state.local[2] = LocalState::Materialized;

        assert!(!state.invariant());
    }

    #[test]
    fn pending_roots_must_remain_in_their_pre_crash_phase() {
        let mut final_state = mixed_ard_decided();
        let mut final_tear = action(ActionKind::TearFinal, 0);
        final_tear.landed = true;
        final_state = final_state.step(final_tear);
        final_state.phase = Phase::Recovering;
        assert!(!final_state.invariant());

        let mut abort_state = State::initial(1, [Operation::Append; 3]);
        abort_state = abort_state.step(action(ActionKind::Crash, 0));
        abort_state = abort_state.step(action(ActionKind::BeginRecovery, 0));
        abort_state = abort_state.step(action(ActionKind::SyncAbortBody, 0));
        let mut abort_tear = action(ActionKind::TearAbortGuard, 0);
        abort_tear.landed = true;
        abort_state = abort_state.step(abort_tear);
        abort_state.phase = Phase::Idle;
        abort_state.goal = Goal::Unknown;
        assert!(!abort_state.invariant());
    }

    #[test]
    fn rewind_truncate_is_required_for_completion() {
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }

        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalizing);

        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalized);
    }

    #[test]
    fn unsynchronized_rewind_truncate_cannot_complete() {
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        let mut truncate = action(ActionKind::TearTruncate, 1);
        truncate.landed = true;
        state = state.step(truncate);

        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalizing);
        assert!(state.truncate_pending[1]);
        assert!(!state.truncated[1]);

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        assert!(!state.truncate_pending[1]);
        assert!(state.truncated[1]);
        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalized);
    }

    #[test]
    fn pending_truncate_requires_a_decided_repair_phase() {
        let mut state = State::initial(1, [Operation::Rewind; 3]);
        state.truncate_pending[0] = true;

        assert!(!state.invariant());
    }

    #[test]
    fn unsynchronized_abort_guards_cannot_release_the_old_vector() {
        let mut state = State::initial(2, [Operation::Append; 3]);
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..2 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            let mut tear = action(ActionKind::TearAbortGuard, participant);
            tear.landed = true;
            state = state.step(tear);
        }

        assert!(!state.all_old_ready());
        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Recovering);

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        assert!(state.all_old_ready());
        state = state.step(action(ActionKind::MarkFinalized, 0));
        assert_eq!(state.phase, Phase::Finalized);
        assert!(state.invariant());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn every_initial_state_satisfies_the_invariant() {
        let count: u8 = kani::any();
        kani::assume((1..=3).contains(&count));
        let operations: [Operation; 3] = kani::any();
        let state = State::initial(count, operations);
        assert!(state.invariant());
    }

    #[kani::proof]
    fn every_transition_preserves_the_invariant() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let action: Action = kani::any();
        let next = state.step(action);
        assert!(next.invariant());
    }

    #[kani::proof]
    fn mixed_append_rewind_remove_reaches_new_vector() {
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        state = state.step(action(ActionKind::SyncUnlink, 0));
        state = state.step(action(ActionKind::Observe, 0));
        let reached =
            state.observations == [Observation::New, Observation::New, Observation::Absent];
        kani::cover!(
            reached,
            "mixed append/rewind/remove new vector is reachable"
        );
        assert!(reached && state.invariant());
    }

    #[kani::proof]
    fn every_operation_vector_reaches_its_intended_new_observation() {
        let count: u8 = kani::any();
        kani::assume((1..=3).contains(&count));
        let operations: [Operation; 3] = kani::any();
        let mut state = State::initial(count, operations);
        for participant in 0..MAX_PARTICIPANTS {
            if participant < count as usize {
                let mut stage = action(ActionKind::StagePayload, participant);
                stage.landed = true;
                state = state.step(stage);
                state = state.step(action(ActionKind::SyncPrepareBody, participant));
            }
        }
        for participant in 0..MAX_PARTICIPANTS {
            if participant < count as usize {
                state = state.step(action(ActionKind::SyncPrepareGuard, participant));
            }
        }
        state = state.step(action(ActionKind::DecideLive, 0));
        for participant in 0..MAX_PARTICIPANTS {
            if participant < count as usize {
                state = state.step(action(ActionKind::SyncFinal, participant));
                if operations[participant] == Operation::Rewind {
                    state = state.step(action(ActionKind::SyncTruncate, participant));
                }
            }
        }
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        state = state.step(action(ActionKind::SyncUnlink, 0));
        state = state.step(action(ActionKind::Observe, 0));
        for participant in 0..MAX_PARTICIPANTS {
            if participant < count as usize {
                assert_eq!(
                    state.observations[participant],
                    state.expected_new(participant)
                );
            }
        }
        kani::cover!(
            count >= 2 && operations[0] == Operation::Append && operations[1] == Operation::Append,
            "append/append is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Append && operations[1] == Operation::Rewind,
            "append/rewind is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Append && operations[1] == Operation::Remove,
            "append/remove is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Rewind && operations[1] == Operation::Append,
            "rewind/append is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Rewind && operations[1] == Operation::Rewind,
            "rewind/rewind is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Rewind && operations[1] == Operation::Remove,
            "rewind/remove is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Remove && operations[1] == Operation::Append,
            "remove/append is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Remove && operations[1] == Operation::Rewind,
            "remove/rewind is reachable"
        );
        kani::cover!(
            count >= 2 && operations[0] == Operation::Remove && operations[1] == Operation::Remove,
            "remove/remove is reachable"
        );
        assert!(state.invariant());
    }

    #[kani::proof]
    fn an_exact_current_prepare_has_durable_body_and_payload_provenance() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let participant: usize = kani::any();
        kani::assume(participant < state.count as usize);
        kani::assume(state.local[participant] == LocalState::Prepared);
        assert!(
            state.guard_issued[participant]
                && state.body_exact[participant]
                && state.body_durable[participant]
                && state.witness_exact[participant]
                && state.payload_valid[participant]
        );
    }

    #[kani::proof]
    fn every_issued_prepare_guard_has_group_body_provenance() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let participant: usize = kani::any();
        kani::assume(participant < state.count as usize);
        kani::assume(state.guard_issued[participant]);
        assert!(state.all_phase_one_durable());
    }

    #[kani::proof]
    fn crash_clears_every_volatile_durability_credit() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let next = state.step(action(ActionKind::Crash, 0));
        assert_eq!(next.body_credit, [false; 3]);
        assert_eq!(next.guard_done_credit, [false; 3]);
        assert_eq!(next.abort_credit, [false; 3]);
        assert_eq!(next.final_pending_exact, [false; 3]);
        assert_eq!(next.abort_guard_pending_exact, [false; 3]);
        assert_eq!(next.truncate_pending, [false; 3]);
        assert_eq!(next.phase, Phase::Recovering);
    }

    #[kani::proof]
    fn recovery_cannot_issue_a_prepare_guard() {
        let state: State = kani::any();
        kani::assume(state.invariant() && state.phase == Phase::Recovering);
        let participant: usize = kani::any();
        kani::assume(participant < state.count as usize);
        kani::assume(!state.guard_issued[participant]);
        let kind: ActionKind = kani::any();
        kani::assume(matches!(
            kind,
            ActionKind::StagePayload
                | ActionKind::TearPrepareBody
                | ActionKind::SyncPrepareBody
                | ActionKind::TearPrepareGuard
                | ActionKind::SyncPrepareGuard
        ));
        let mut candidate = action(kind, participant);
        candidate.landed = kani::any();
        let next = state.step(candidate);
        assert!(!next.guard_issued[participant]);
    }

    #[kani::proof]
    fn exact_abort_root_is_terminal_during_body_repair() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let participant: usize = kani::any();
        kani::assume(participant < state.count as usize);
        kani::assume(state.local[participant] == LocalState::Aborted);
        let kind = if kani::any() {
            ActionKind::TearAbortBody
        } else {
            ActionKind::SyncAbortBody
        };
        let mut repair = action(kind, participant);
        repair.landed = kani::any();
        assert_eq!(state.step(repair), state);
    }

    #[kani::proof]
    fn empty_abort_body_survival_preserves_the_source_classification() {
        let state: State = kani::any();
        kani::assume(state.invariant());
        let participant: usize = kani::any();
        kani::assume(participant < state.count as usize);
        kani::assume(!state.decision);
        kani::assume(state.phase == Phase::Recovering);
        kani::assume(state.goal == Goal::Old);
        kani::assume(state.local[participant] != LocalState::Aborted);
        kani::assume(!state.abort_credit[participant]);
        kani::assume(!state.independently_final[participant]);

        assert_eq!(
            state.step(action(ActionKind::TearAbortBody, participant)),
            state
        );
    }

    #[kani::proof]
    fn recovery_selects_its_goal_from_retained_semantic_provenance() {
        let state: State = kani::any();
        kani::assume(state.invariant() && state.phase == Phase::Recovering);
        let semantic_provenance_supports_new = state.retained_semantic_provenance_supports_new();
        let next = state.step(action(ActionKind::BeginRecovery, 0));
        kani::cover!(
            state.final_write_survivor.iter().any(|survived| *survived),
            "a target-only final byte rederives the new recovery goal"
        );
        assert_eq!(
            next.goal,
            if semantic_provenance_supports_new {
                Goal::New
            } else {
                Goal::Old
            }
        );
        assert_eq!(next.decision, semantic_provenance_supports_new);
    }

    #[kani::proof]
    fn phase_two_guard_crash_cut_selects_only_complete_vectors() {
        let guard_survives: [bool; MAX_PARTICIPANTS] = kani::any();
        let state = mixed_phase_two_crash(guard_survives);
        let all_guards = guard_survives.iter().all(|survived| *survived);
        assert_eq!(state.decision, all_guards);
        assert_eq!(state.goal, if all_guards { Goal::New } else { Goal::Old });
        kani::cover!(
            guard_survives.iter().all(|survived| !*survived),
            "no phase-two guard survives"
        );
        kani::cover!(
            guard_survives.iter().any(|survived| *survived) && !all_guards,
            "a proper phase-two guard subset survives"
        );
        kani::cover!(all_guards, "every phase-two guard survives");

        let state = finish_mixed_recovery(state);
        let expected = if all_guards {
            [Observation::New, Observation::New, Observation::Absent]
        } else {
            [Observation::Old; MAX_PARTICIPANTS]
        };
        assert!(state.observations == expected && state.invariant());
    }

    #[kani::proof]
    fn one_abort_authority_selects_old_before_peer_mutation() {
        let guard_survives: [bool; MAX_PARTICIPANTS] = kani::any();
        kani::assume(!guard_survives.iter().all(|survived| *survived));
        let anchor: usize = kani::any();
        kani::assume(anchor < MAX_PARTICIPANTS);
        let mut state = mixed_phase_two_crash(guard_survives);
        assert_eq!(state.goal, Goal::Old);
        state = state.step(action(ActionKind::SyncAbortBody, anchor));
        state = state.step(action(ActionKind::SyncAbortGuard, anchor));

        assert!(state.old_vector_selected());
        assert!(state.participant_mutable(anchor));
        for participant in 0..MAX_PARTICIPANTS {
            if participant != anchor {
                assert!(!state.participant_mutable(participant));
            }
        }
        let unresolved_peer = (anchor + 1) % MAX_PARTICIPANTS;
        let blocked = state.step(action(ActionKind::AdmitMutation, unresolved_peer));
        assert!(!blocked.mutation_admitted[unresolved_peer]);
        let admitted = state.step(action(ActionKind::AdmitMutation, anchor));
        assert!(admitted.mutation_admitted[anchor]);
        kani::cover!(
            !blocked.mutation_admitted[unresolved_peer],
            "mutation admission rejects an unresolved peer"
        );
        kani::cover!(
            admitted.mutation_admitted[anchor],
            "mutation admission accepts the durable abort authority"
        );
        kani::cover!(anchor == 0, "ordinal zero supplies the abort authority");
        kani::cover!(anchor == 1, "ordinal one supplies the abort authority");
        kani::cover!(anchor == 2, "ordinal two supplies the abort authority");
        kani::cover!(
            guard_survives.iter().all(|survived| !*survived),
            "the abort authority suppresses a guardless ring"
        );
        kani::cover!(
            guard_survives.iter().any(|survived| *survived),
            "the abort authority suppresses a proper prepared subset"
        );

        let observed = state
            .step(action(ActionKind::MarkFinalized, 0))
            .step(action(ActionKind::Observe, 0));
        assert_eq!(observed.observations, [Observation::Old; MAX_PARTICIPANTS]);
        assert!(observed.invariant());

        for participant in 0..MAX_PARTICIPANTS {
            if participant != anchor {
                state = state.step(action(ActionKind::SyncAbortBody, participant));
                state = state.step(action(ActionKind::SyncAbortGuard, participant));
                assert!(state.participant_mutable(participant));
                let admitted = state.step(action(ActionKind::AdmitMutation, participant));
                assert!(admitted.mutation_admitted[participant]);
            }
        }
        assert!(state.all_old_ready() && state.invariant());
    }

    #[kani::proof]
    fn unsynchronized_final_roots_cannot_authorize_unlink() {
        let final_lands: [bool; 3] = kani::any();
        let mut state = mixed_ard_decided();
        for (participant, landed) in final_lands.into_iter().enumerate() {
            let mut final_write = action(ActionKind::TearFinal, participant);
            final_write.landed = landed;
            state = state.step(final_write);
        }

        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        kani::cover!(
            final_lands.iter().all(|landed| *landed),
            "all exact unsynchronized final roots are pending"
        );
        kani::cover!(
            final_lands.iter().any(|landed| *landed) && final_lands.iter().any(|landed| !*landed),
            "a proper subset of exact unsynchronized final roots is pending"
        );
        assert_eq!(state.phase, Phase::Finalizing);
        assert_eq!(state.unlink_issued, 0);
        assert!(!state.all_independently_final());
        assert!(state.invariant());

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        assert_eq!(state.unlink_issued, bit(2));
        assert!(state.invariant());
    }

    #[kani::proof]
    fn unsynchronized_rewind_truncate_cannot_complete() {
        let truncate_lands: bool = kani::any();
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        let mut truncate = action(ActionKind::TearTruncate, 1);
        truncate.landed = truncate_lands;
        state = state.step(truncate);

        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        kani::cover!(
            truncate_lands,
            "an exact unsynchronized rewind truncate is pending"
        );
        kani::cover!(
            !truncate_lands,
            "the unsynchronized rewind truncate is lost"
        );
        assert_eq!(state.phase, Phase::Finalizing);
        assert_eq!(state.unlink_issued, 0);
        assert!(!state.truncated[1]);
        assert!(state.invariant());

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        assert_eq!(state.unlink_issued, bit(2));
        assert!(state.invariant());
    }

    #[kani::proof]
    fn unsynchronized_abort_guards_cannot_release_the_old_vector() {
        let guard_lands: [bool; 3] = kani::any();
        let mut state =
            State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for (participant, landed) in guard_lands.into_iter().enumerate() {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            let mut guard = action(ActionKind::TearAbortGuard, participant);
            guard.landed = landed;
            state = state.step(guard);
        }

        state = state.step(action(ActionKind::MarkFinalized, 0));
        kani::cover!(
            guard_lands.iter().all(|landed| *landed),
            "all exact unsynchronized abort guards are pending"
        );
        kani::cover!(
            guard_lands.iter().any(|landed| *landed) && guard_lands.iter().any(|landed| !*landed),
            "a proper subset of exact unsynchronized abort guards is pending"
        );
        assert_eq!(state.phase, Phase::Recovering);
        assert!(!state.all_old_ready());
        assert!(state.invariant());

        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            state = state.step(action(ActionKind::SyncAbortGuard, participant));
        }
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::Observe, 0));
        assert_eq!(state.observations, [Observation::Old; 3]);
        assert!(state.invariant());
    }

    #[kani::proof]
    fn every_partial_unlink_subset_observes_all_absent() {
        let mut state = State::initial(3, [Operation::Remove; 3]);
        for participant in 0..3 {
            state = state.step(action(ActionKind::StagePayload, participant));
            state = state.step(action(ActionKind::SyncPrepareBody, participant));
        }
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncPrepareGuard, participant));
        }
        state = state.step(action(ActionKind::DecideLive, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        let mask: u8 = kani::any();
        kani::assume(mask & !0b111 == 0);
        let mut crash = action(ActionKind::CrashUnlink, 0);
        crash.survivor_mask = mask;
        state = state.step(crash);
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::Observe, 0));
        let all_absent = state.observations == [Observation::Absent; 3];
        kani::cover!(mask == 0, "no unlink survives");
        kani::cover!(mask == 0b001, "one unlink survives");
        kani::cover!(mask == 0b010, "a different one-link subset survives");
        kani::cover!(mask == 0b100, "the final one-link subset survives");
        kani::cover!(mask == 0b011, "two unlinks survive");
        kani::cover!(mask == 0b101, "a non-prefix two-link subset survives");
        kani::cover!(mask == 0b110, "the final two-link subset survives");
        kani::cover!(mask == 0b111, "all unlinks survive");
        assert!(all_absent && state.invariant());
    }

    #[kani::proof]
    fn interrupted_abort_repair_reaches_only_the_old_vector() {
        let prepare_lands: [bool; 3] = kani::any();
        let abort_body_lands: [bool; 3] = kani::any();
        let abort_body_has_target_byte: [bool; 3] = kani::any();
        let abort_guard_lands: [bool; 3] = kani::any();
        let mut state =
            State::initial(3, [Operation::Append, Operation::Rewind, Operation::Remove]);
        for participant in 0..3 {
            let mut stage = action(ActionKind::StagePayload, participant);
            stage.landed = true;
            state = state.step(stage);
            let mut prepare = action(ActionKind::TearPrepareBody, participant);
            prepare.landed = prepare_lands[participant];
            state = state.step(prepare);
        }
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            let mut body = action(ActionKind::TearAbortBody, participant);
            body.landed = abort_body_lands[participant];
            if abort_body_has_target_byte[participant] {
                body.survivor_mask = bit(participant);
            }
            state = state.step(body);
        }
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            let mut guard = action(ActionKind::TearAbortGuard, participant);
            guard.landed = abort_guard_lands[participant];
            state = state.step(guard);
        }
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncAbortBody, participant));
            state = state.step(action(ActionKind::SyncAbortGuard, participant));
        }
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::Observe, 0));
        let old = state.observations == [Observation::Old; 3];
        kani::cover!(
            prepare_lands.iter().any(|landed| *landed),
            "some prepare-body bytes survive"
        );
        kani::cover!(
            abort_body_lands.iter().any(|landed| *landed),
            "at least one complete abort body survives"
        );
        kani::cover!(
            (0..3).any(|participant| {
                abort_body_has_target_byte[participant] && !abort_body_lands[participant]
            }),
            "a nonempty proper abort-body subset survives"
        );
        kani::cover!(
            abort_guard_lands.iter().any(|landed| *landed),
            "some abort guards survive"
        );
        assert!(old && state.invariant());
    }

    #[kani::proof]
    fn interrupted_final_repair_and_partial_unlink_reach_only_the_new_vector() {
        let final_lands: [bool; 3] = kani::any();
        let final_has_target_byte: [bool; 3] = kani::any();
        let truncate_lands: bool = kani::any();
        let unlink_survivors: u8 = kani::any();
        kani::assume(unlink_survivors & !0b100 == 0);
        let mut state = mixed_ard_decided();
        for participant in 0..3 {
            let mut final_write = action(ActionKind::TearFinal, participant);
            final_write.landed = final_lands[participant];
            if final_has_target_byte[participant] {
                final_write.survivor_mask = bit(participant);
            }
            state = state.step(final_write);
        }
        let mut truncate = action(ActionKind::TearTruncate, 1);
        truncate.landed = truncate_lands;
        state = state.step(truncate);
        state = state.step(action(ActionKind::Crash, 0));
        state = state.step(action(ActionKind::BeginRecovery, 0));
        for participant in 0..3 {
            state = state.step(action(ActionKind::SyncFinal, participant));
        }
        state = state.step(action(ActionKind::SyncTruncate, 1));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::IssueUnlink, 0));
        let mut unlink = action(ActionKind::CrashUnlink, 0);
        unlink.survivor_mask = unlink_survivors;
        state = state.step(unlink);
        state = state.step(action(ActionKind::BeginRecovery, 0));
        state = state.step(action(ActionKind::MarkFinalized, 0));
        state = state.step(action(ActionKind::Observe, 0));
        let expected = [Observation::New, Observation::New, Observation::Absent];
        kani::cover!(
            final_lands.iter().any(|landed| !*landed),
            "at least one final write is interrupted"
        );
        kani::cover!(!truncate_lands, "the rewind truncate is interrupted");
        kani::cover!(
            unlink_survivors == 0b100,
            "the remove unlink survives independently"
        );
        assert!(state.observations == expected && state.invariant());
    }
}
