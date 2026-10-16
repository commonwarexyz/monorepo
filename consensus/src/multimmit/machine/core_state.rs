//! Input queues, lane fairness, and budget in front of the [`Machine`].
//!
//! [`CoreState`] admits typed inputs into bounded lanes, services them in weighted round robin,
//! and hands each one to the machine as an [`InputPass`]. It adds no protocol authority: the
//! machine decides every transition and capability. The core has no `async` function; storage,
//! networking, application calls, cryptography, and rescheduling stay with the voter, its chain
//! planes, and its worker pools.
//!
//! # Lanes
//!
//! ```text
//! +------------------------+--------+
//! | lane                   | weight |
//! +------------------------+--------+
//! | persistence completion |      8 |
//! | local completion       |      8 |
//! | timer                  |      4 |
//! | resolver result        |      4 |
//! | peer observation       |      2 |
//! +------------------------+--------+
//! ```
//!
//! Each unit of weight admits one input per cycle, and unused weight does not carry into the
//! next cycle. Inputs and machine work passes spend one shared core budget; when it runs out, the
//! turn returns and the voter reschedules. A full peer lane stops peer intake while completions
//! and timers keep rotating. Every lane caps its item count, and lanes whose payload sizes peers
//! choose also cap resident bytes. Admission charges an input before it is retained, and servicing
//! releases the charge before the machine reduces it, so a capability can reserve its destination
//! without counting the input twice.
//!
//! # Clock
//!
//! The voter supplies a [`Now`] reading when it admits an input and when it asks for the next
//! action. The admission reading travels with the queued input, so the machine can measure how long
//! an input waited; the action reading is the clock the machine's pass runs at. Durable events
//! never carry either reading.

use super::{
    durability::{DomainEvent, EffectCompletion, ReplayError, Snapshot},
    input::{Input, InputKind, Now, PollResult, Step, StepError, TimerFamily},
    reducer::{InputPass, machine::Machine},
    scheduler::{FairCursor, Lane, ServiceCycle, ServiceError},
};
use crate::multimmit::{
    config::{Profile, ResourceLimits},
    machine::{artifact::IdentifiedArtifact, durability::EffectResult},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::VecDeque, mem::size_of_val, num::NonZeroUsize};

/// Persistence acknowledgements queued at once. The voter delivers one journal response at a time
/// and the machine accepts acknowledgements only in prefix order.
const PERSISTENCE_LANE_ITEMS: usize = 1;

/// Timer inputs queued at once: one tick per timer family.
const TIMER_LANE_ITEMS: usize = TimerFamily::COUNT;

/// Local completions queued beyond in-flight verifications and outbox effects: lifecycle inputs,
/// producer build and custody completions, chain-plane verdicts, and aggregations.
const LOCAL_COMPLETION_HEADROOM: usize = 4;

/// Returns the largest multiple of the artifact byte limit that any core lane's byte bound takes,
/// or `None` when that multiple overflows.
///
/// [`CoreLimits::derive`] sizes every lane from the same resources, so an artifact byte limit
/// whose product with this multiple fits cannot overflow a lane.
pub(crate) fn max_lane_artifacts(resources: &ResourceLimits) -> Option<usize> {
    // One observation retains two artifact ceilings (see `CoreLimits::derive`).
    let batch = resources.max_verification_batch().checked_mul(2)?;
    let local = resources
        .max_inflight_verifications()
        .checked_add(resources.max_outbox_effects())?
        .checked_add(LOCAL_COMPLETION_HEADROOM)?
        .checked_mul(batch)?;
    let peer = resources.max_inflight_verifications().checked_mul(batch)?;
    Some(
        local
            .max(peer)
            .max(resources.max_dependency_waiters())
            .max(TIMER_LANE_ITEMS)
            .max(PERSISTENCE_LANE_ITEMS),
    )
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DriveSource {
    Input,
    Machine,
}

#[derive(Default)]
struct DriveCursor {
    machine_turn: bool,
}

impl DriveCursor {
    const fn select(&self, inputs_ready: bool, machine_ready: bool) -> Option<DriveSource> {
        match (inputs_ready, machine_ready, self.machine_turn) {
            (false, false, _) => None,
            (true, false, _) | (true, true, false) => Some(DriveSource::Input),
            (false, true, _) | (true, true, true) => Some(DriveSource::Machine),
        }
    }

    const fn record(&mut self, source: DriveSource) {
        self.machine_turn = matches!(source, DriveSource::Input);
    }
}

/// Item-and-byte limit for one core input lane.
///
/// The item ceiling binds on every lane. The byte ceiling is admission-enforced only where
/// [`Lane::peer_supplied`] holds; elsewhere it names the per-item residency an aggregate
/// completion is charged.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct LaneLimit {
    items: usize,
    bytes: usize,
}

impl LaneLimit {
    pub(crate) const fn new(items: usize, bytes: usize) -> Self {
        Self { items, bytes }
    }
}

/// Validated limits for all core input lanes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreLimits {
    lanes: [LaneLimit; Lane::COUNT],
    /// Local completion items the admission gate keeps free for outbox deliveries, which
    /// publication enqueues without passing the gate, at most one per outbox effect.
    outbox_reserve: usize,
}

impl CoreLimits {
    /// Derives queue limits from the reducer's already-validated resource profile.
    pub(super) fn derive<H: Hasher, V: Variant>(
        machine: &Machine<H, V>,
    ) -> Result<Self, CoreError> {
        let resources = machine.profile().resources();
        let max_batch = resources.max_verification_batch();
        let artifact_bytes = resources.max_artifact_bytes();
        // One observation retains the artifact plus its fixed committee source and content id.
        // The artifact ceiling dominates either cryptographic identity, so two ceilings per item
        // are a conservative bound without coupling the runtime's public-key type into Machine.
        let batch_bytes = max_batch
            .checked_mul(artifact_bytes)
            .and_then(|bytes| bytes.checked_mul(2))
            .ok_or(CoreError::CapacityOverflow)?;
        let local_items = resources
            .max_inflight_verifications()
            .checked_add(resources.max_outbox_effects())
            .and_then(|items| items.checked_add(LOCAL_COMPLETION_HEADROOM))
            .ok_or(CoreError::CapacityOverflow)?;
        let resolver_items = resources.max_dependency_waiters();
        let peer_items = resources.max_inflight_verifications();
        let local_bytes = local_items
            .checked_mul(batch_bytes)
            .ok_or(CoreError::CapacityOverflow)?;
        let timer_bytes = artifact_bytes
            .checked_mul(TIMER_LANE_ITEMS)
            .ok_or(CoreError::CapacityOverflow)?;
        let resolver_bytes = resolver_items
            .checked_mul(artifact_bytes)
            .ok_or(CoreError::CapacityOverflow)?;
        let peer_bytes = peer_items
            .checked_mul(batch_bytes)
            .ok_or(CoreError::CapacityOverflow)?;

        let lanes = Lane::ALL.map(|lane| match lane {
            Lane::PersistenceCompletion => LaneLimit::new(PERSISTENCE_LANE_ITEMS, artifact_bytes),
            Lane::LocalCompletion => LaneLimit::new(local_items, local_bytes),
            Lane::Timer => LaneLimit::new(TIMER_LANE_ITEMS, timer_bytes),
            Lane::ResolverResult => LaneLimit::new(resolver_items, resolver_bytes),
            Lane::PeerObservation => LaneLimit::new(peer_items, peer_bytes),
        });
        if lanes
            .iter()
            .any(|limit| limit.items == 0 || limit.bytes == 0)
        {
            return Err(CoreError::ZeroCapacity);
        }
        Ok(Self {
            lanes,
            outbox_reserve: resources.max_outbox_effects(),
        })
    }

    const fn lane(self, lane: Lane) -> LaneLimit {
        self.lanes[lane.index()]
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct LaneUsage {
    items: usize,
    bytes: usize,
}

struct QueuedInput<V: Variant, D: Digest> {
    ticket: InputTicket,
    pass: InputPass<V, D>,
    bytes: usize,
}

/// Stable correlation for actor-owned metadata associated with one queued input.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InputTicket(u64);

/// One serviced reducer input.
pub(crate) struct ServicedInput<V: Variant, D: Digest> {
    pub(crate) ticket: InputTicket,
    /// The lane the input was queued on.
    pub(crate) lane: Lane,
    /// The input's kind.
    pub(crate) kind: InputKind,
    /// The clock reading at the input's admission.
    pub(crate) admitted: Now,
    /// Number of observation items consumed from this ticket by the step.
    pub(crate) observed_items: usize,
    /// Whether this ticket has no resumable suffix.
    pub(crate) final_chunk: bool,
    pub(crate) transition: Step<V, D>,
}

/// One bounded action selected by the synchronous core.
pub(crate) enum CoreTurn<V: Variant, D: Digest> {
    Idle,
    YieldRequired,
    Input(ServicedInput<V, D>),
    Work(PollResult<V, D>),
}

/// The serial production scheduler around the deterministic reducer.
pub(crate) struct CoreState<H: Hasher, V: Variant> {
    machine: Machine<H, V>,
    limits: CoreLimits,
    queues: [VecDeque<QueuedInput<V, H::Digest>>; Lane::COUNT],
    usage: [LaneUsage; Lane::COUNT],
    cursor: FairCursor,
    service: ServiceCycle,
    next_ticket: u64,
    yield_required: bool,
    drive: DriveCursor,
}

impl<H: Hasher, V: Variant> CoreState<H, V> {
    /// Constructs the complete protocol owner for a never-started epoch.
    pub(crate) fn fresh(profile: Profile<H::Digest>) -> Result<Self, CoreBootstrapError> {
        Ok(Self::new(Machine::new(profile))?)
    }

    /// Restores the complete protocol owner at one acknowledged snapshot cut.
    pub(crate) fn restore(
        profile: Profile<H::Digest>,
        snapshot: Snapshot<V, H::Digest>,
    ) -> Result<Self, CoreBootstrapError> {
        Ok(Self::new(Machine::restore(profile, snapshot)?)?)
    }

    pub(super) fn new(machine: Machine<H, V>) -> Result<Self, CoreError> {
        let limits = CoreLimits::derive(&machine)?;
        Ok(Self::with_limits(machine, limits))
    }

    fn with_limits(machine: Machine<H, V>, limits: CoreLimits) -> Self {
        Self {
            machine,
            limits,
            queues: std::array::from_fn(|_| VecDeque::new()),
            usage: [LaneUsage::default(); Lane::COUNT],
            cursor: FairCursor::new(),
            service: ServiceCycle::new(),
            next_ticket: 0,
            yield_required: false,
            drive: DriveCursor::default(),
        }
    }

    /// Replays one durable event while the restored core remains externally silent.
    pub(crate) fn replay(&mut self, event: DomainEvent<V, H::Digest>) -> Result<(), ReplayError> {
        self.machine.replay(event)
    }

    /// Queues one decoded observation cohort retaining `resident_bytes`, admitted at `now`.
    pub(crate) fn observe(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<V, H::Digest>>,
        resident_bytes: usize,
        now: Now,
    ) -> Result<InputTicket, CoreError> {
        self.admit(Input::Observe(artifacts), resident_bytes, now)
    }

    /// Queues one reducer input other than an observation.
    ///
    /// An observation carries peer-chosen bytes, so it enters only through [`Self::observe`],
    /// which charges its resident size against the peer lane's byte ceiling.
    pub(crate) fn enqueue(
        &mut self,
        input: Input<V, H::Digest>,
        now: Now,
    ) -> Result<InputTicket, CoreError> {
        if matches!(input, Input::Observe(_)) {
            return Err(CoreError::UnsizedObservation);
        }
        self.admit(input, 1, now)
    }

    /// Reserves lane capacity for `input` and queues it with its admission reading `now`.
    fn admit(
        &mut self,
        input: Input<V, H::Digest>,
        resident_bytes: usize,
        now: Now,
    ) -> Result<InputTicket, CoreError> {
        let lane = input_lane(&input);
        let index = lane.index();
        let limit = self.limits.lane(lane);
        let bytes = input_bytes(&input, resident_bytes, limit)?;
        let usage = self.usage[index];
        let items = usage
            .items
            .checked_add(1)
            .ok_or(CoreError::CapacityOverflow)?;
        let total_bytes = usage
            .bytes
            .checked_add(bytes)
            .ok_or(CoreError::CapacityOverflow)?;
        if items > limit.items {
            return Err(CoreError::LaneItemsFull(lane));
        }
        if lane.peer_supplied() && total_bytes > limit.bytes {
            return Err(CoreError::LaneBytesFull(lane));
        }

        let ticket = InputTicket(self.next_ticket);
        self.next_ticket = self
            .next_ticket
            .checked_add(1)
            .ok_or(CoreError::TicketExhausted)?;
        self.usage[index] = LaneUsage {
            items,
            bytes: total_bytes,
        };
        self.queues[index].push_back(QueuedInput {
            ticket,
            pass: InputPass::new(input, now),
            bytes,
        });
        Ok(ticket)
    }

    /// Selects one admitted input or one machine-owned work quantum and runs it at `now`.
    ///
    /// Machine-owned work runs one work key per action, and `before_poll` sees the machine
    /// immediately before that work runs.
    pub(crate) fn next_action(
        &mut self,
        now: Now,
        before_poll: impl FnOnce(&Machine<H, V>),
    ) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        if self.yield_required {
            return Ok(CoreTurn::YieldRequired);
        }

        let persistence_blocked = !self.machine.has_persistence_capacity();
        let inputs_ready = if persistence_blocked {
            !self.queues[Lane::PersistenceCompletion.index()].is_empty()
        } else {
            self.has_pending_inputs()
        };
        let machine_ready = !persistence_blocked && self.machine.has_component_work();
        match self.drive.select(inputs_ready, machine_ready) {
            None => Ok(CoreTurn::Idle),
            Some(DriveSource::Machine) => {
                before_poll(&self.machine);
                self.poll_machine(now)
            }
            Some(DriveSource::Input) => {
                let action = self.service_input(persistence_blocked, now)?;
                if matches!(action, CoreTurn::Input(_)) {
                    self.drive.record(DriveSource::Input);
                }
                Ok(action)
            }
        }
    }

    fn poll_machine(&mut self, now: Now) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        let result = self.machine.poll(NonZeroUsize::MIN, now)?;
        self.drive.record(DriveSource::Machine);
        Ok(CoreTurn::Work(result))
    }

    fn service_input(
        &mut self,
        persistence_only: bool,
        now: Now,
    ) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        if self.yield_required {
            return Ok(CoreTurn::YieldRequired);
        }

        let ready: [bool; Lane::COUNT] = std::array::from_fn(|index| {
            let lane = Lane::ALL[index];
            (!persistence_only || lane == Lane::PersistenceCompletion)
                && !self.queues[index].is_empty()
                && self.service.remaining_lane(lane) > 0
        });
        let Some(index) = self.cursor.select(&ready) else {
            if self.queues.iter().all(VecDeque::is_empty) {
                return Ok(CoreTurn::Idle);
            }
            return Ok(self.yield_turn());
        };
        let lane = Lane::ALL[index];
        let available =
            usize::try_from(self.service.remaining_core()).map_err(|_| CoreError::CostOverflow)?;
        if available == 0 {
            return Ok(self.yield_turn());
        }

        let queue = &mut self.queues[index];
        let queued = queue.front_mut().ok_or(CoreError::SchedulerInvariant)?;
        let observes = queued.pass.observes();
        let admitted = queued.pass.admitted();
        let kind = queued
            .pass
            .input_kind()
            .ok_or(CoreError::SchedulerInvariant)?;
        debug_assert!(
            admitted <= now,
            "the clock reading applying an input precedes its admission"
        );
        let advance = self.machine.advance(&mut queued.pass, available, now)?;
        let ticket = queued.ticket;
        if advance.processed > available {
            return Err(CoreError::SchedulerInvariant);
        }
        self.service
            .charge(lane, advance.processed)
            .map_err(|error| match error {
                ServiceError::CostOverflow => CoreError::CostOverflow,
                ServiceError::LaneExhausted | ServiceError::CoreBudgetExhausted => {
                    CoreError::SchedulerInvariant
                }
            })?;
        if advance.complete {
            let queued = queue.pop_front().ok_or(CoreError::SchedulerInvariant)?;
            let usage = &mut self.usage[index];
            usage.items = usage
                .items
                .checked_sub(1)
                .ok_or(CoreError::SchedulerInvariant)?;
            usage.bytes = usage
                .bytes
                .checked_sub(queued.bytes)
                .ok_or(CoreError::SchedulerInvariant)?;
        }

        if self.service.remaining_core() == 0 && self.has_pending_inputs() {
            self.yield_required = true;
        }
        Ok(CoreTurn::Input(ServicedInput {
            ticket,
            lane,
            kind,
            admitted,
            observed_items: if observes { advance.processed } else { 0 },
            final_chunk: advance.complete,
            transition: advance.output,
        }))
    }

    /// Requires a yield to the runtime before the next input.
    const fn yield_turn(&mut self) -> CoreTurn<V, H::Digest> {
        self.yield_required = true;
        CoreTurn::YieldRequired
    }

    /// Starts a fresh weighted cycle after the attached runtime has yielded.
    pub(crate) fn resume_after_yield(&mut self) -> Result<(), CoreError> {
        if !self.yield_required {
            return Err(CoreError::UnexpectedResume);
        }
        self.service = ServiceCycle::new();
        self.yield_required = false;
        Ok(())
    }

    pub(crate) fn has_pending_inputs(&self) -> bool {
        self.queues.iter().any(|queue| !queue.is_empty())
    }

    /// Returns whether one action can run without exceeding the persistence bound.
    pub(crate) fn has_runnable_work(&self) -> bool {
        if self.yield_required {
            return true;
        }
        if self.machine.has_persistence_capacity() {
            return self.has_pending_inputs() || self.machine.has_component_work();
        }
        !self.queues[Lane::PersistenceCompletion.index()].is_empty()
    }

    /// Returns the machine this core schedules.
    pub(crate) const fn machine(&self) -> &Machine<H, V> {
        &self.machine
    }

    /// Returns whether one more item can be received without consuming its source.
    ///
    /// Byte admission remains exact in [`Self::admit`] for the peer-supplied lanes. A
    /// source-specific maximum guarantees that any valid single item fits an empty lane, so the
    /// actor uses this item check to leave ready work in its bounded upstream queue while a lane
    /// is occupied.
    ///
    /// The local completion lane admits only up to its outbox reserve, so the deliveries
    /// publication reports outside this check always fit.
    pub(crate) const fn can_admit(&self, lane: Lane) -> bool {
        let index = lane.index();
        let reserve = match lane {
            Lane::LocalCompletion => self.limits.outbox_reserve,
            _ => 0,
        };
        self.usage[index].items.saturating_add(reserve) < self.limits.lane(lane).items
    }
}

const fn input_lane<V: Variant, D: Digest>(input: &Input<V, D>) -> Lane {
    match input {
        Input::Persisted(_) => Lane::PersistenceCompletion,
        Input::Tick(_) => Lane::Timer,
        Input::ResolutionCompleted(_) => Lane::ResolverResult,
        Input::Observe(_) => Lane::PeerObservation,
        Input::Start
        | Input::RecoveryComplete
        | Input::Verified(_)
        | Input::EffectCompleted(_)
        | Input::BlockBuilt(_)
        | Input::BlockCustodied(_)
        | Input::Validated(_)
        | Input::Crypto(_) => Lane::LocalCompletion,
    }
}

fn input_bytes<V: Variant, D: Digest>(
    input: &Input<V, D>,
    supplied: usize,
    lane_limit: LaneLimit,
) -> Result<usize, CoreError> {
    let per_item_limit = lane_limit
        .bytes
        .checked_div(lane_limit.items)
        .ok_or(CoreError::ZeroCapacity)?;
    let measured = match input {
        Input::Observe(_) => return Ok(supplied.max(1)),
        Input::Verified(completion) => completion
            .resident_bytes()
            .ok_or(CoreError::CapacityOverflow)?,
        Input::EffectCompleted(EffectCompletion {
            result: EffectResult::Signed(artifacts),
            ..
        }) => artifacts
            .iter()
            .try_fold(size_of_val(input), |total, artifact| {
                total.checked_add(artifact.encode_size())
            })
            .ok_or(CoreError::CapacityOverflow)?,
        Input::ResolutionCompleted(_) | Input::Crypto(_) => per_item_limit,
        _ => size_of_val(input),
    };
    Ok(measured.max(supplied).max(1))
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CoreError {
    #[error("core capacity arithmetic overflowed")]
    CapacityOverflow,
    #[error("core capacity must be non-zero")]
    ZeroCapacity,
    #[error("core input ticket exhausted")]
    TicketExhausted,
    #[error("core input cost overflowed")]
    CostOverflow,
    #[error("core lane {0:?} exhausted its item capacity")]
    LaneItemsFull(Lane),
    #[error("core lane {0:?} exhausted its byte capacity")]
    LaneBytesFull(Lane),
    #[error("an observation must be queued with its resident bytes")]
    UnsizedObservation,
    #[error("core scheduler accounting is inconsistent")]
    SchedulerInvariant,
    #[error("core was resumed without a required runtime yield")]
    UnexpectedResume,
    #[error("reducer step failed: {0}")]
    Reducer(#[from] StepError),
}

/// Failure while constructing the complete synchronous protocol owner.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CoreBootstrapError {
    #[error("core initialization failed: {0}")]
    Core(#[from] CoreError),
    #[error("core recovery failed: {0}")]
    Recovery(#[from] ReplayError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{Profile, Role, Tuning},
            machine::{
                durability::{BarrierAck, BatchId, Cursor, EffectId},
                input::{BlockValidity, ValidationCompletion},
                job::{Generation, Issued},
                scheduler::CORE_BUDGET,
                verification::{JobId, VerificationCompletion},
            },
            mocks::Committee,
            types::{BlockRef, ChainId},
        },
        types::Height,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};

    type Core = CoreState<Sha256, MinPk>;

    fn observer_core(seed: u64) -> Core {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let profile =
            Profile::new::<MinPk>(committee.config, Role::Observer, Tuning::new()).unwrap();
        CoreState::new(Machine::new(profile)).unwrap()
    }

    /// Returns the queued pass of `ticket` in `lane`, if it is queued there.
    fn queued_in(
        core: &Core,
        lane: Lane,
        ticket: InputTicket,
    ) -> Option<&InputPass<MinPk, <Sha256 as Hasher>::Digest>> {
        core.queues[lane.index()]
            .iter()
            .find(|queued| queued.ticket == ticket)
            .map(|queued| &queued.pass)
    }

    #[test]
    fn inputs_queue_in_their_lanes_with_their_admission_reading() {
        let mut core = observer_core(74);
        let at = Now::from_millis(7);
        let started = core.enqueue(Input::Start, at).unwrap();
        let tick = core.enqueue(Input::Tick(TimerFamily::Update), at).unwrap();
        let persisted = core
            .enqueue(
                Input::Persisted(BarrierAck::new(
                    BatchId::new(0),
                    Generation::new(0),
                    Cursor::zero(),
                )),
                at,
            )
            .unwrap();
        let block = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"block"]));
        let validated = core
            .enqueue(
                Input::Validated(ValidationCompletion::new(
                    Generation::new(0),
                    block,
                    BlockValidity::Valid,
                )),
                at,
            )
            .unwrap();
        let observed = core.observe(Vec::new(), 1, Now::from_millis(9)).unwrap();

        for (lane, ticket) in [
            (Lane::LocalCompletion, started),
            (Lane::Timer, tick),
            (Lane::PersistenceCompletion, persisted),
            (Lane::LocalCompletion, validated),
        ] {
            let pass = queued_in(&core, lane, ticket).expect("input is queued in its lane");
            assert!(pass.pending_input().is_some());
            assert_eq!(pass.admitted(), at);
        }
        let pass = queued_in(&core, Lane::PeerObservation, observed).unwrap();
        assert!(pass.observes());
        assert_eq!(pass.admitted(), Now::from_millis(9));

        // An observation carries peer-chosen bytes, so only the sized path may queue it.
        assert_eq!(
            core.enqueue(Input::Observe(Vec::new()), at),
            Err(CoreError::UnsizedObservation)
        );
        assert_eq!(core.queues[Lane::PeerObservation.index()].len(), 1);
    }

    #[test]
    fn timer_lane_holds_one_tick_per_family() {
        let mut core = observer_core(75);
        for family in TimerFamily::ALL {
            core.enqueue(Input::Tick(family), Now::default()).unwrap();
        }
        assert!(!core.can_admit(Lane::Timer));
        assert_eq!(
            core.enqueue(Input::Tick(TimerFamily::View), Now::default()),
            Err(CoreError::LaneItemsFull(Lane::Timer))
        );
    }

    #[test]
    fn gated_local_completions_leave_room_for_every_outbox_delivery() {
        let mut core = observer_core(78);
        let block = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"block"]));

        // Completions the actor admits only while the gate is open fill the lane up to the gate.
        while core.can_admit(Lane::LocalCompletion) {
            core.enqueue(
                Input::Validated(ValidationCompletion::new(
                    Generation::new(0),
                    block,
                    BlockValidity::Valid,
                )),
                Now::default(),
            )
            .unwrap();
        }

        // Publication reports a first delivery without passing the gate, once per outbox effect.
        let outbox = core.machine().profile().resources().max_outbox_effects();
        for id in 0..outbox as u64 {
            core.enqueue(
                Input::EffectCompleted(EffectCompletion::delivered(Issued::new(
                    EffectId::new(id),
                    Generation::new(0),
                ))),
                Now::default(),
            )
            .expect("an outbox delivery is admitted behind a closed completion gate");
        }
    }

    #[test]
    fn weighted_cycles_service_control_under_peer_flood() {
        let mut credits = ServiceCycle::new();
        let mut cursor = FairCursor::new();
        let mut pending = [1, 1, 1, 1, usize::MAX];
        let mut serviced = [0; Lane::COUNT];
        loop {
            let ready: [bool; Lane::COUNT] = std::array::from_fn(|index| {
                pending[index] > 0 && credits.remaining_lane(Lane::ALL[index]) > 0
            });
            let Some(index) = cursor.select(&ready) else {
                break;
            };
            credits.charge(Lane::ALL[index], 1).unwrap();
            pending[index] -= 1;
            serviced[index] += 1;
        }
        assert_eq!(serviced, [1, 1, 1, 1, 2]);
        assert_eq!(credits.remaining_core(), CORE_BUDGET - 6);
    }

    #[test]
    fn oversized_local_completion_is_admitted_while_peer_bytes_stay_capped() {
        let mut core = observer_core(77);
        let local = core.limits.lane(Lane::LocalCompletion);
        let peer = core.limits.lane(Lane::PeerObservation);

        // The machine issued this verification itself and already counted it against
        // max_inflight_verifications, so an over-count in the completion's resident-byte
        // accounting must not tear the voter down.
        let ticket = core
            .admit(
                Input::Verified(VerificationCompletion::new(
                    Issued::new(JobId::new(0), Generation::new(0)),
                    Vec::new(),
                )),
                local.bytes.saturating_add(1),
                Now::default(),
            )
            .expect("a locally issued completion is admitted past the lane byte ceiling");
        let usage = core.usage[Lane::LocalCompletion.index()];
        assert_eq!(usage.items, 1);
        assert!(usage.bytes > local.bytes);
        assert!(queued_in(&core, Lane::LocalCompletion, ticket).is_some());

        // Peer-supplied bytes keep their ceiling.
        assert_eq!(
            core.observe(Vec::new(), peer.bytes.saturating_add(1), Now::default()),
            Err(CoreError::LaneBytesFull(Lane::PeerObservation)),
        );
    }
}
