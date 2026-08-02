//! Serial protocol composition and bounded executor admission.
//!
//! The core is the only production scheduling boundary around [`Machine`]. It does not add
//! protocol authority: the reducer still decides every transition and capability. The core decides
//! when an already-typed input or reducer-owned work quantum may enter that authority. The attached
//! voter owns runtime tasks and uses this module's bounded permit ledgers for their completions.
//!
//! # Ownership
//!
//! ```text
//!                         one dedicated runtime task
//! +-------------------------------------------------------------------+
//! | CoreState                                                          |
//! |                                                                   |
//! |  bounded input lanes -> weighted scheduler --+                   |
//! |                                               +-> drive cursor    |
//! |  reducer-owned work --------------------------+       |           |
//! |                                                       v           |
//! |                                                 Machine reducer   |
//! |                                             /      |       \      |
//! |                                           DA     View    Finality  |
//! +-------------------------------------------------------------------+
//!                              |
//!                              v
//!           voter-owned journal, shared work, resolver, and egress
//! ```
//!
//! DA, View, and Finality are private fields behind the reducer. A caller cannot run one of them
//! concurrently or create one actor per producer chain. This keeps observation order, durable
//! signing authority, and cross-chain checkpoint agreement under one serial owner.
//!
//! # Input lanes and quanta
//!
//! ```text
//! persistence completion --8--+
//! local completion -------8---+  one credit admits one input
//! timer ------------------4---+-> rotating weighted cycle -> reducer
//! resolver result --------4---+  transition cost also spends core credit
//! peer observation -------2---+
//!
//! full peer lane: stop receiving peers; completions and timers still rotate
//! exhausted cycle/core budget: return YieldRequired; runtime reschedules
//! next cycle: weights reset; unused credit never carries
//! ```
//!
//! Queue limits cover both item count and resident bytes. Admission charges the complete input
//! before it is retained. A serviced input releases that charge before reduction, so a reducer
//! capability may synchronously reserve its bounded destination without double-counting the input.
//!
//! # Tasks and completion reservations
//!
//! ```text
//!                             shared executor
//!                  +--------------------------------+
//! local build ---->| dedicated application slot     |
//! remote validate>| global validation cap           |
//!                  |                                |
//! local signing -->| reserved crypto slot            |
//! aggregation ---->| reserved critical slot          |
//! bulk crypto ---->| remaining crypto slots          |
//!                  +--------------------------------+
//!                         | one reserved return path
//!                         v
//!                  local-completion lane
//! ```
//!
//! The attached voter uses a [`TaskPermit`] to represent both worker occupancy and its completion
//! reservation. Success, failure, cancellation, and a caught panic all terminate the same permit.
//! A reconciliation sweep releases permits whose runtime handle disappeared. Generation changes
//! and shutdown discard every old volatile permit; a late completion is stale and cannot touch new
//! capacity.
//!
//! The local application-build slot is not part of the remote-validation budget. Remote work is
//! queued per producer chain and admitted with one rotating cursor, so a flooded chain cannot
//! repeatedly win the next free slot. Local signing and consensus-critical aggregation likewise
//! retain named slots that bulk verification cannot consume.
//!
//! # Durability pipeline
//!
//! ```text
//! reducer stages events -----> journal append -----> start_sync(prefix)
//!          |                         |                       |
//!          +---- private work ------+                       |
//!          +---- replayable publication                      |
//!                                                            v
//!                                                   exact prefix ack
//!                                                            |
//!                              retain -> install -> retire -> release
//! ```
//!
//! The core contains no `async` function and performs no await. Storage, networking,
//! application calls, cryptography, and `commonware_runtime::utils::reschedule()` remain in the
//! attached voter task.

#[cfg(test)]
use super::contracts::CORE_BUDGET;
use super::{
    Artifact, BarrierAck, BuildCompletion, Capabilities, ChainProgress, CheckpointCut,
    DaRecoveryCompletion, DomainEvent, EffectCompletion, EffectId, IdentifiedArtifact, Input,
    Inspection, LqcAggregateCompletion, Machine, NullificationRecoveryCompletion, PollResult,
    ProductionTimer, Profile, Progress, ReplayError, ResolutionCompletion, SigningBatchPass,
    Snapshot, Step, StepError, StepStatus, Timer, ValidationCompletion, ValidationId,
    ValidationJob, VerificationCompletion, VerificationPass, ViewProof, VqcAggregateCompletion,
    contracts::{FairCursor, LANE_WEIGHTS, Lane, ServiceCycle, ServiceError, TransitionCost},
};
use crate::{
    multimmit::types::{Activity, ChainId, Context},
    types::{Height, View},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, VecDeque},
    mem::size_of_val,
    num::NonZeroUsize,
    sync::Arc,
};

const LANE_COUNT: usize = 5;

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
    lanes: [LaneLimit; LANE_COUNT],
    max_observation_items: usize,
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
            .and_then(|items| items.checked_add(4))
            .ok_or(CoreError::CapacityOverflow)?;
        let resolver_items = resources.max_dependency_waiters();
        let peer_items = resources.max_inflight_verifications();
        let local_bytes = local_items
            .checked_mul(batch_bytes)
            .ok_or(CoreError::CapacityOverflow)?;
        let timer_bytes = artifact_bytes
            .checked_mul(2)
            .ok_or(CoreError::CapacityOverflow)?;
        let resolver_bytes = resolver_items
            .checked_mul(artifact_bytes)
            .ok_or(CoreError::CapacityOverflow)?;
        let peer_bytes = peer_items
            .checked_mul(batch_bytes)
            .ok_or(CoreError::CapacityOverflow)?;

        let lanes = [
            LaneLimit::new(1, artifact_bytes),
            LaneLimit::new(local_items, local_bytes),
            LaneLimit::new(2, timer_bytes),
            LaneLimit::new(resolver_items, resolver_bytes),
            LaneLimit::new(peer_items, peer_bytes),
        ];
        if lanes
            .iter()
            .any(|limit| limit.items == 0 || limit.bytes == 0)
        {
            return Err(CoreError::ZeroCapacity);
        }
        Ok(Self {
            lanes,
            max_observation_items: max_batch,
        })
    }

    const fn lane(self, lane: Lane) -> LaneLimit {
        self.lanes[lane_index(lane)]
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct LaneUsage {
    items: usize,
    bytes: usize,
}

struct QueuedInput<V: Variant, D: Digest> {
    ticket: InputTicket,
    payload: QueuedPayload<V, D>,
    bytes: usize,
    cost: TransitionCost,
    cost_remaining: usize,
}

enum QueuedPayload<V: Variant, D: Digest> {
    Input(Input<V, D>),
    /// Reversed once at admission so prefixes pop from the tail in original order.
    Observe(Vec<super::IdentifiedArtifact<V, D>>),
    Verified(VerificationPass<D>),
    SignedBatch(SigningBatchPass<V, D>),
}

/// Stable correlation for actor-owned metadata associated with one queued input.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct InputTicket(u64);

/// Result of one admitted event transition.
pub(crate) struct CoreTransition<V: Variant, D: Digest> {
    status: StepStatus<D>,
    capabilities: Capabilities<V, D>,
    activities: Vec<Activity<V, D>>,
}

impl<V: Variant, D: Digest> CoreTransition<V, D> {
    fn from_step(step: Step<V, D>) -> Self {
        let (status, capabilities, activities) = step.into_core_parts();
        Self {
            status,
            capabilities,
            activities,
        }
    }

    pub(crate) const fn status(&self) -> &StepStatus<D> {
        &self.status
    }

    #[cfg(test)]
    pub(crate) fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    pub(crate) fn into_parts(self) -> (Capabilities<V, D>, Vec<Activity<V, D>>) {
        (self.capabilities, self.activities)
    }
}

/// Result of one bounded quantum of core-owned semantic work.
pub(crate) struct CoreWork<V: Variant, D: Digest> {
    work_remaining: bool,
    capabilities: Capabilities<V, D>,
    activities: Vec<Activity<V, D>>,
}

impl<V: Variant, D: Digest> CoreWork<V, D> {
    fn from_poll(result: PollResult<V, D>) -> Self {
        let work_remaining = result.work_remaining();
        let (capabilities, activities) = result.into_parts();
        Self {
            work_remaining,
            capabilities,
            activities,
        }
    }

    pub(crate) const fn work_remaining(&self) -> bool {
        self.work_remaining
    }

    pub(crate) const fn capabilities(&self) -> &Capabilities<V, D> {
        &self.capabilities
    }

    #[cfg(test)]
    pub(crate) fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    pub(crate) fn into_parts(self) -> (Capabilities<V, D>, Vec<Activity<V, D>>) {
        (self.capabilities, self.activities)
    }
}

/// One serviced reducer input.
pub(crate) struct ServicedInput<V: Variant, D: Digest> {
    pub(crate) ticket: InputTicket,
    #[cfg(test)]
    pub(crate) lane: Lane,
    #[cfg(test)]
    pub(crate) cycle: u64,
    /// Number of observation items consumed from this ticket by the step.
    pub(crate) observed_items: usize,
    /// Whether this ticket has no resumable suffix.
    pub(crate) final_chunk: bool,
    pub(crate) transition: CoreTransition<V, D>,
}

/// One bounded action selected by the synchronous core.
pub(crate) enum CoreTurn<V: Variant, D: Digest> {
    Idle,
    YieldRequired,
    Input(ServicedInput<V, D>),
    Work(CoreWork<V, D>),
}

/// The serial production scheduler around the deterministic reducer.
pub(crate) struct CoreState<H: Hasher, V: Variant> {
    machine: Machine<H, V>,
    tasks: TaskReservations,
    active_validations: BTreeMap<u32, (ValidationId, Height)>,
    pending_validations: ProducerAdmissions<ValidationJob<V, H::Digest>>,
    limits: CoreLimits,
    queues: [VecDeque<QueuedInput<V, H::Digest>>; LANE_COUNT],
    usage: [LaneUsage; LANE_COUNT],
    cursor: FairCursor,
    service: ServiceCycle,
    cycle: u64,
    next_ticket: u64,
    yield_required: bool,
    drive: DriveCursor,
}

impl<H: Hasher, V: Variant> CoreState<H, V> {
    pub(crate) const MAX_BATCH_EVENTS: usize = Machine::<H, V>::MAX_BATCH_EVENTS;
    pub(crate) const MAX_BATCH_BYTES: usize = Machine::<H, V>::MAX_BATCH_BYTES;
    #[cfg(test)]
    pub(crate) const MAX_STAGED_BARRIERS: usize = Machine::<H, V>::MAX_STAGED_BARRIERS;

    /// Returns the immutable epoch profile owned by this core.
    pub(crate) const fn profile(&self) -> &Profile<H, V> {
        self.machine.profile()
    }

    /// Constructs the complete protocol owner for a never-started epoch.
    pub(crate) fn fresh(
        profile: Profile<H, V>,
        application_tasks: NonZeroUsize,
    ) -> Result<Self, CoreBootstrapError> {
        Ok(Self::new(Machine::new(profile), application_tasks)?)
    }

    /// Restores the complete protocol owner at one acknowledged snapshot cut.
    pub(crate) fn restore(
        profile: Profile<H, V>,
        snapshot: Snapshot<V, H::Digest>,
        application_tasks: NonZeroUsize,
    ) -> Result<Self, CoreBootstrapError> {
        Ok(Self::new(
            Machine::restore(profile, snapshot)?,
            application_tasks,
        )?)
    }

    pub(super) fn new(
        machine: Machine<H, V>,
        application_tasks: NonZeroUsize,
    ) -> Result<Self, CoreError> {
        let limits = CoreLimits::derive(&machine)?;
        let resources = machine.profile().resources();
        let crypto_tasks = resources
            .max_cached_artifacts()
            .saturating_add(resources.max_outbox_effects())
            .max(3);
        let generation = machine.inspect().generation();
        let tasks = TaskReservations::new(
            generation,
            TaskLimits::new(application_tasks.get(), crypto_tasks),
        )?;
        let chains = machine.profile().protocol().codec_config().chains();
        let pending_items = resources.max_cached_artifacts();
        let per_chain_items = resources.max_verification_batch();
        let pending_bytes = pending_items
            .checked_mul(resources.max_artifact_bytes())
            .ok_or(CoreError::CapacityOverflow)?;
        let per_chain_bytes = per_chain_items
            .checked_mul(resources.max_artifact_bytes())
            .ok_or(CoreError::CapacityOverflow)?;
        let pending_validations = ProducerAdmissions::new(
            chains,
            pending_items,
            per_chain_items,
            pending_bytes,
            per_chain_bytes,
        )?;
        Ok(Self::with_limits(
            machine,
            limits,
            tasks,
            pending_validations,
        ))
    }

    fn with_limits(
        machine: Machine<H, V>,
        limits: CoreLimits,
        tasks: TaskReservations,
        pending_validations: ProducerAdmissions<ValidationJob<V, H::Digest>>,
    ) -> Self {
        Self {
            machine,
            tasks,
            active_validations: BTreeMap::new(),
            pending_validations,
            limits,
            queues: std::array::from_fn(|_| VecDeque::new()),
            usage: [LaneUsage::default(); LANE_COUNT],
            cursor: FairCursor::new(),
            service: ServiceCycle::new(),
            cycle: 0,
            next_ticket: 0,
            yield_required: false,
            drive: DriveCursor::default(),
        }
    }

    pub(crate) fn start_fresh(&mut self) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::Start, 1)
    }

    pub(crate) fn finish_recovery(&mut self) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::RecoveryComplete, 1)
    }

    /// Replays one durable event while the restored core remains externally silent.
    pub(crate) fn replay(&mut self, event: DomainEvent<V, H::Digest>) -> Result<(), ReplayError> {
        self.machine.replay(event).map(|_| ())
    }

    /// Returns application payloads that must pass the startup custody gate.
    pub(crate) fn recovered_payloads(&self) -> Vec<(Context<H::Digest>, H::Digest)> {
        self.machine.recovered_payloads()
    }

    pub(crate) fn checkpoint_cut(&self) -> CheckpointCut<H, V> {
        self.machine.checkpoint_cut()
    }

    pub(crate) fn observe(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<V, H::Digest>>,
        resident_bytes: usize,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::Observe(artifacts), resident_bytes)
    }

    pub(crate) fn verification_completed(
        &mut self,
        completion: VerificationCompletion<H::Digest>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::Verified(completion), 1)
    }

    pub(crate) fn persistence_completed(
        &mut self,
        acknowledgement: BarrierAck,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::Persisted(acknowledgement), 1)
    }

    pub(crate) fn publication_delivered(
        &mut self,
        id: EffectId,
        generation: u64,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(
            Input::EffectCompleted(EffectCompletion::Delivered { id, generation }),
            1,
        )
    }

    pub(crate) fn signing_completed(
        &mut self,
        id: EffectId,
        generation: u64,
        artifact: Arc<Artifact<V, H::Digest>>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(
            Input::EffectCompleted(EffectCompletion::Signed {
                id,
                generation,
                artifact,
            }),
            1,
        )
    }

    pub(crate) fn signing_batch_completed(
        &mut self,
        id: EffectId,
        generation: u64,
        artifacts: Vec<Artifact<V, H::Digest>>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(
            Input::EffectCompleted(EffectCompletion::SignedBatch {
                id,
                generation,
                artifacts,
            }),
            1,
        )
    }

    pub(crate) fn leader_timer_fired(&mut self, timer: Timer) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::TimerFired(timer), 1)
    }

    pub(crate) fn producer_wake(&mut self) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::ProducerWake, 1)
    }

    pub(crate) fn producer_build_completed(
        &mut self,
        completion: BuildCompletion<H::Digest>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::BlockBuilt(completion), 1)
    }

    pub(crate) fn producer_validated(
        &mut self,
        completion: ValidationCompletion,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::BlockValidated(completion), 1)
    }

    pub(crate) fn producer_timer_fired(
        &mut self,
        timer: ProductionTimer<H::Digest>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::ProductionTimerFired(timer), 1)
    }

    pub(crate) fn producer_da_recovered(
        &mut self,
        completion: DaRecoveryCompletion<V, H::Digest>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::DaRecovered(completion), 1)
    }

    pub(crate) fn leader_resolution_completed(
        &mut self,
        completion: ResolutionCompletion<V, H::Digest>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::ResolutionCompleted(completion), 1)
    }

    pub(crate) fn leader_nullification_recovered(
        &mut self,
        completion: NullificationRecoveryCompletion<V>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::NullificationRecovered(completion), 1)
    }

    pub(crate) fn leader_vqc_aggregated(
        &mut self,
        completion: Box<VqcAggregateCompletion<V, H::Digest>>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::VqcAggregated(completion), 1)
    }

    pub(crate) fn leader_lqc_aggregated(
        &mut self,
        completion: Box<LqcAggregateCompletion<V, H::Digest>>,
    ) -> Result<InputTicket, CoreError> {
        self.enqueue(Input::LqcAggregated(completion), 1)
    }

    /// Reserves lane capacity and queues one reducer input.
    pub(super) fn enqueue(
        &mut self,
        input: Input<V, H::Digest>,
        resident_bytes: usize,
    ) -> Result<InputTicket, CoreError> {
        let lane = input_lane(&input);
        let cost = input_cost(&input);
        let cost_remaining = usize::try_from(cost.credits().ok_or(CoreError::CostOverflow)?)
            .map_err(|_| CoreError::CostOverflow)?;

        let index = lane_index(lane);
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
        if total_bytes > limit.bytes {
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
        let payload = match input {
            Input::Observe(mut artifacts) => {
                artifacts.reverse();
                QueuedPayload::Observe(artifacts)
            }
            Input::Verified(completion) => {
                QueuedPayload::Verified(VerificationPass::new(completion))
            }
            Input::EffectCompleted(super::EffectCompletion::SignedBatch {
                id,
                generation,
                artifacts,
            }) => QueuedPayload::SignedBatch(SigningBatchPass::new(id, generation, artifacts)),
            input => QueuedPayload::Input(input),
        };
        self.queues[index].push_back(QueuedInput {
            ticket,
            payload,
            bytes,
            cost,
            cost_remaining,
        });
        Ok(ticket)
    }

    /// Selects one admitted input or one machine-owned work quantum.
    pub(crate) fn next_action(
        &mut self,
        machine_budget: NonZeroUsize,
    ) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        if self.yield_required {
            return Ok(CoreTurn::YieldRequired);
        }

        let persistence_blocked = !self.machine.has_persistence_capacity();
        let inputs_ready = if persistence_blocked {
            !self.queues[lane_index(Lane::PersistenceCompletion)].is_empty()
        } else {
            self.has_pending_inputs()
        };
        let machine_ready = !persistence_blocked && self.machine.scheduler.has_work();
        match self.drive.select(inputs_ready, machine_ready) {
            None => Ok(CoreTurn::Idle),
            Some(DriveSource::Machine) => self.poll_machine(machine_budget),
            Some(DriveSource::Input) => {
                let action = self.service_input(persistence_blocked)?;
                if matches!(action, CoreTurn::Input(_)) {
                    self.drive.record(DriveSource::Input);
                }
                Ok(action)
            }
        }
    }

    fn poll_machine(&mut self, budget: NonZeroUsize) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        let result = self.machine.poll(budget)?;
        self.drive.record(DriveSource::Machine);
        Ok(CoreTurn::Work(CoreWork::from_poll(result)))
    }

    fn service_input(
        &mut self,
        persistence_only: bool,
    ) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        if self.yield_required {
            return Ok(CoreTurn::YieldRequired);
        }

        let ready: [bool; LANE_COUNT] = std::array::from_fn(|index| {
            let lane = lane_at(index);
            (!persistence_only || lane == Lane::PersistenceCompletion)
                && !self.queues[index].is_empty()
                && self.service.remaining_lane(lane) > 0
        });
        let Some(index) = self.cursor.select(&ready) else {
            if self.queues.iter().all(VecDeque::is_empty) {
                return Ok(CoreTurn::Idle);
            }
            self.yield_required = true;
            return Ok(CoreTurn::YieldRequired);
        };

        let lane = lane_at(index);
        if matches!(
            self.queues[index]
                .front()
                .expect("a selected core lane is non-empty")
                .payload,
            QueuedPayload::Verified(_) | QueuedPayload::SignedBatch(_)
        ) {
            return self.service_resumable_input(index, lane);
        }
        let queued = self.queues[index]
            .front()
            .expect("a selected core lane is non-empty");
        let (cost, observed_items, final_chunk) = match &queued.payload {
            QueuedPayload::Observe(artifacts) => {
                let available = usize::try_from(self.service.remaining_core())
                    .map_err(|_| CoreError::CostOverflow)?;
                if available == 0 {
                    self.yield_required = true;
                    return Ok(CoreTurn::YieldRequired);
                }
                let remaining = artifacts.len();
                let items = remaining
                    .min(available)
                    .min(self.limits.max_observation_items);
                (
                    TransitionCost::ArtifactItems(items),
                    items,
                    items == remaining,
                )
            }
            _ => {
                let available = usize::try_from(self.service.remaining_core())
                    .map_err(|_| CoreError::CostOverflow)?;
                if available == 0 {
                    self.yield_required = true;
                    return Ok(CoreTurn::YieldRequired);
                }
                let items = queued.cost_remaining.min(available);
                (
                    cost_prefix(queued.cost, items),
                    0,
                    items == queued.cost_remaining,
                )
            }
        };
        match self.service.charge(lane, cost) {
            Ok(()) => {}
            Err(ServiceError::CoreBudgetExhausted) => {
                self.yield_required = true;
                return Ok(CoreTurn::YieldRequired);
            }
            Err(ServiceError::LaneExhausted) => {
                return Err(CoreError::SchedulerInvariant);
            }
            Err(ServiceError::CostOverflow) => return Err(CoreError::CostOverflow),
        }

        if !final_chunk && !matches!(&queued.payload, QueuedPayload::Observe(_)) {
            let queued = self.queues[index]
                .front_mut()
                .expect("a selected core lane is non-empty");
            let charged = cost.credits().ok_or(CoreError::CostOverflow)? as usize;
            queued.cost_remaining = queued
                .cost_remaining
                .checked_sub(charged)
                .ok_or(CoreError::SchedulerInvariant)?;
            self.yield_required = true;
            return Ok(CoreTurn::YieldRequired);
        }

        let (ticket, step) = if final_chunk {
            let queued = self.queues[index]
                .pop_front()
                .expect("a selected core lane is non-empty");
            let usage = &mut self.usage[index];
            usage.items = usage
                .items
                .checked_sub(1)
                .ok_or(CoreError::SchedulerInvariant)?;
            usage.bytes = usage
                .bytes
                .checked_sub(queued.bytes)
                .ok_or(CoreError::SchedulerInvariant)?;
            let step = match queued.payload {
                QueuedPayload::Input(input) => self.machine.step(input)?,
                QueuedPayload::Observe(artifacts) => self
                    .machine
                    .step_observations(artifacts.into_iter().rev())?,
                QueuedPayload::Verified(_) | QueuedPayload::SignedBatch(_) => {
                    return Err(CoreError::SchedulerInvariant);
                }
            };
            (queued.ticket, step)
        } else {
            let machine = &mut self.machine;
            let queued = self.queues[index]
                .front_mut()
                .expect("a selected core lane is non-empty");
            let QueuedPayload::Observe(artifacts) = &mut queued.payload else {
                return Err(CoreError::SchedulerInvariant);
            };
            let start = artifacts
                .len()
                .checked_sub(observed_items)
                .ok_or(CoreError::SchedulerInvariant)?;
            let step = machine.step_observations(artifacts.drain(start..).rev())?;
            (queued.ticket, step)
        };

        if self.service.remaining_core() == 0 && self.has_pending_inputs() {
            self.yield_required = true;
        }
        Ok(CoreTurn::Input(ServicedInput {
            ticket,
            #[cfg(test)]
            lane,
            #[cfg(test)]
            cycle: self.cycle,
            observed_items,
            final_chunk,
            transition: CoreTransition::from_step(step),
        }))
    }

    fn service_resumable_input(
        &mut self,
        index: usize,
        lane: Lane,
    ) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        let available =
            usize::try_from(self.service.remaining_core()).map_err(|_| CoreError::CostOverflow)?;
        if available == 0 {
            self.yield_required = true;
            return Ok(CoreTurn::YieldRequired);
        }

        let advance = {
            let queued = self.queues[index]
                .front_mut()
                .expect("a selected core lane is non-empty");
            match &mut queued.payload {
                QueuedPayload::Verified(pass) => {
                    self.machine.advance_verification_pass(pass, available)?
                }
                QueuedPayload::SignedBatch(pass) => {
                    self.machine.advance_signing_batch_pass(pass, available)?
                }
                QueuedPayload::Input(_) | QueuedPayload::Observe(_) => {
                    return Err(CoreError::SchedulerInvariant);
                }
            }
        };
        if advance.processed == 0 || advance.processed > available {
            return Err(CoreError::SchedulerInvariant);
        }
        self.service
            .charge(lane, TransitionCost::ArtifactItems(advance.processed))
            .map_err(|error| match error {
                ServiceError::CostOverflow => CoreError::CostOverflow,
                ServiceError::LaneExhausted | ServiceError::CoreBudgetExhausted => {
                    CoreError::SchedulerInvariant
                }
            })?;

        let ticket = if advance.complete {
            let queued = self.queues[index]
                .pop_front()
                .expect("the completed resumable input remains queued");
            let usage = &mut self.usage[index];
            usage.items = usage
                .items
                .checked_sub(1)
                .ok_or(CoreError::SchedulerInvariant)?;
            usage.bytes = usage
                .bytes
                .checked_sub(queued.bytes)
                .ok_or(CoreError::SchedulerInvariant)?;
            queued.ticket
        } else {
            self.queues[index]
                .front()
                .expect("the resumable suffix remains queued")
                .ticket
        };

        if self.service.remaining_core() == 0 && self.has_pending_inputs() {
            self.yield_required = true;
        }
        Ok(CoreTurn::Input(ServicedInput {
            ticket,
            #[cfg(test)]
            lane,
            #[cfg(test)]
            cycle: self.cycle,
            observed_items: 0,
            final_chunk: advance.complete,
            transition: CoreTransition::from_step(advance.step),
        }))
    }

    /// Starts a fresh weighted cycle after the attached runtime has yielded.
    pub(crate) fn resume_after_yield(&mut self) -> Result<(), CoreError> {
        if !self.yield_required {
            return Err(CoreError::UnexpectedResume);
        }
        self.cycle = self.cycle.checked_add(1).ok_or(CoreError::CycleExhausted)?;
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
            return self.has_pending_inputs() || self.machine.scheduler.has_work();
        }
        !self.queues[lane_index(Lane::PersistenceCompletion)].is_empty()
    }

    #[cfg(test)]
    pub(super) const fn machine(&self) -> &Machine<H, V> {
        &self.machine
    }

    /// Returns the durable completion-correlation generation.
    pub(crate) const fn generation(&self) -> u64 {
        self.machine.generation()
    }

    /// Projects compact protocol progress for metrics and retention coordination.
    pub(crate) fn progress(&self) -> Progress {
        self.machine.progress()
    }

    /// Projects per-producer-chain progress for periodic metrics refresh.
    pub(crate) fn chain_progress(&self) -> Vec<ChainProgress> {
        self.machine.chain_progress()
    }

    /// Projects normalized diagnostics without exposing reducer internals.
    pub(crate) fn inspection(&self) -> Inspection<H::Digest> {
        self.machine.inspect()
    }

    /// Returns the two retention cardinalities exported as runtime metrics.
    pub(crate) fn retention_profile(&self) -> (usize, u64) {
        (
            self.machine.retained_artifact_references(),
            self.machine.nullification_suffix(),
        )
    }

    /// Reconstructs the resolver's volatile custody projection after startup.
    pub(crate) fn resolver_seed(&self) -> (View, Vec<ViewProof<V, H::Digest>>) {
        (
            self.machine.durable.retired_view,
            self.machine.durable.resolver_proofs().collect(),
        )
    }

    /// Returns unacknowledged persistence batches that fence checkpoint creation.
    pub(crate) fn staged_barriers(&self) -> usize {
        self.machine.staged_barriers()
    }

    /// Mints a checkpoint from the last acknowledged durable cursor.
    pub(crate) fn snapshot(&self) -> Snapshot<V, H::Digest> {
        self.machine.snapshot()
    }

    /// Returns whether one more item can be received without consuming its source.
    ///
    /// Byte admission remains exact in [`Self::enqueue`]. A source-specific maximum guarantees
    /// that any valid single item fits an empty lane, so the actor uses this item check to leave
    /// ready work in its bounded upstream queue while a lane is occupied.
    pub(crate) const fn can_admit(&self, lane: Lane) -> bool {
        let index = lane_index(lane);
        self.usage[index].items < self.limits.lane(lane).items
    }

    pub(crate) fn reserve_task(
        &mut self,
        class: TaskClass,
        units: usize,
    ) -> Result<TaskPermit, TaskError> {
        self.tasks.reserve_units(class, units)
    }

    pub(crate) fn finish_task(
        &mut self,
        permit: TaskPermit,
        terminal: TaskTerminal,
    ) -> Result<(), TaskError> {
        self.tasks.finish(permit, terminal)
    }

    pub(crate) const fn task_generation(&self) -> u64 {
        self.tasks.generation()
    }

    pub(crate) fn advance_task_generation(&mut self, generation: u64) -> Result<usize, TaskError> {
        let released = self.tasks.advance_generation(generation)?;
        self.active_validations.clear();
        self.pending_validations.clear();
        Ok(released)
    }

    pub(crate) fn shutdown_tasks(&mut self) -> usize {
        let released = self.tasks.shutdown();
        self.active_validations.clear();
        self.pending_validations.clear();
        released
    }

    pub(crate) const fn local_build_active(&self) -> bool {
        self.tasks.local_build
    }

    pub(crate) fn schedule_validation(
        &mut self,
        job: ValidationJob<V, H::Digest>,
    ) -> Result<Option<ValidationDispatch<V, H::Digest>>, TaskError> {
        let chain = job.block().header().chain().get();
        match self.start_validation(job)? {
            ValidationStart::Started(dispatch) => Ok(Some(dispatch)),
            ValidationStart::Blocked(job) => {
                let bytes = job.block().encode_size();
                self.pending_validations.admit(chain, job, bytes)?;
                Ok(None)
            }
        }
    }

    fn start_validation(
        &mut self,
        job: ValidationJob<V, H::Digest>,
    ) -> Result<ValidationStart<V, H::Digest>, TaskError> {
        let chain = job.block().header().chain().get();
        if self.active_validations.contains_key(&chain) {
            return Ok(ValidationStart::Blocked(job));
        }
        let permit = match self.tasks.reserve(TaskClass::RemoteValidation) {
            Ok(permit) => permit,
            Err(TaskError::ClassFull) => return Ok(ValidationStart::Blocked(job)),
            Err(error) => return Err(error),
        };
        let active = (job.id(), job.block().header().height());
        let previous = self.active_validations.insert(chain, active);
        debug_assert!(previous.is_none());
        Ok(ValidationStart::Started(ValidationDispatch { permit, job }))
    }

    pub(crate) fn validation_finished(
        &mut self,
        chain: ChainId,
        id: ValidationId,
    ) -> Result<Option<ValidationDispatch<V, H::Digest>>, TaskError> {
        let Some((active, _)) = self.active_validations.remove(&chain.get()) else {
            return Err(TaskError::Accounting);
        };
        if active != id {
            return Err(TaskError::Accounting);
        }
        let active = &self.active_validations;
        let Some(job) = self
            .pending_validations
            .pop_ready(|chain| !active.contains_key(&chain))
        else {
            return Ok(None);
        };
        match self.start_validation(job)? {
            ValidationStart::Started(dispatch) => Ok(Some(dispatch)),
            ValidationStart::Blocked(_) => Err(TaskError::Accounting),
        }
    }

    pub(crate) fn cancel_validations(
        &mut self,
        chain: ChainId,
        through: Height,
    ) -> Option<ValidationId> {
        self.pending_validations.retain(|job| {
            job.block().header().chain() != chain || job.block().header().height() > through
        });
        self.active_validations
            .get(&chain.get())
            .and_then(|(id, height)| (*height <= through).then_some(*id))
    }

    pub(crate) fn validation_counts(&self) -> (usize, usize) {
        (
            self.active_validations.len(),
            self.pending_validations.len(),
        )
    }
}

pub(crate) struct ValidationDispatch<V: Variant, D: Digest> {
    permit: TaskPermit,
    job: ValidationJob<V, D>,
}

enum ValidationStart<V: Variant, D: Digest> {
    Started(ValidationDispatch<V, D>),
    Blocked(ValidationJob<V, D>),
}

impl<V: Variant, D: Digest> ValidationDispatch<V, D> {
    pub(crate) fn into_parts(self) -> (TaskPermit, ValidationJob<V, D>) {
        (self.permit, self.job)
    }
}

const fn input_lane<V: Variant, D: Digest>(input: &Input<V, D>) -> Lane {
    match input {
        Input::Persisted(_) => Lane::PersistenceCompletion,
        Input::TimerFired(_) | Input::ProducerWake | Input::ProductionTimerFired(_) => Lane::Timer,
        Input::ResolutionCompleted(_) => Lane::ResolverResult,
        Input::Observe(_) => Lane::PeerObservation,
        Input::Start
        | Input::RecoveryComplete
        | Input::Verified(_)
        | Input::EffectCompleted(_)
        | Input::BlockBuilt(_)
        | Input::BlockValidated(_)
        | Input::DaRecovered(_)
        | Input::NullificationRecovered(_)
        | Input::VqcAggregated(_)
        | Input::LqcAggregated(_) => Lane::LocalCompletion,
    }
}

fn input_cost<V: Variant, D: Digest>(input: &Input<V, D>) -> TransitionCost {
    match input {
        Input::Observe(artifacts) => TransitionCost::ArtifactItems(artifacts.len().max(1)),
        Input::Verified(completion) => {
            TransitionCost::ArtifactItems(completion.verdicts().len().max(1))
        }
        Input::EffectCompleted(super::EffectCompletion::SignedBatch { artifacts, .. }) => {
            TransitionCost::ArtifactItems(artifacts.len().max(1))
        }
        Input::ResolutionCompleted(_) => TransitionCost::Constant,
        // Recovery and aggregate completions only enter the machine-owned completion FIFO here.
        // Their committee work is charged by the component scheduler when that FIFO is serviced.
        Input::DaRecovered(_)
        | Input::NullificationRecovered(_)
        | Input::VqcAggregated(_)
        | Input::LqcAggregated(_) => TransitionCost::Constant,
        _ => TransitionCost::Constant,
    }
}

const fn cost_prefix(cost: TransitionCost, items: usize) -> TransitionCost {
    match cost {
        TransitionCost::Constant => TransitionCost::Constant,
        TransitionCost::ArtifactItems(_) => TransitionCost::ArtifactItems(items),
        TransitionCost::CommitteePass(_) => TransitionCost::CommitteePass(items),
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
        Input::Observe(_) => supplied,
        Input::Verified(completion) => size_of_val(completion)
            .checked_add(size_of_val(completion.verdicts()))
            .ok_or(CoreError::CapacityOverflow)?,
        Input::EffectCompleted(super::EffectCompletion::Signed { artifact, .. }) => {
            size_of_val(input)
                .checked_add(artifact.encode_size())
                .ok_or(CoreError::CapacityOverflow)?
        }
        Input::EffectCompleted(super::EffectCompletion::SignedBatch { artifacts, .. }) => artifacts
            .iter()
            .try_fold(size_of_val(input), |total, artifact| {
                total.checked_add(artifact.encode_size())
            })
            .ok_or(CoreError::CapacityOverflow)?,
        Input::ResolutionCompleted(_)
        | Input::DaRecovered(_)
        | Input::NullificationRecovered(_)
        | Input::VqcAggregated(_)
        | Input::LqcAggregated(_) => per_item_limit,
        _ => size_of_val(input),
    };
    Ok(measured.max(supplied).max(1))
}

const fn lane_index(lane: Lane) -> usize {
    match lane {
        Lane::PersistenceCompletion => 0,
        Lane::LocalCompletion => 1,
        Lane::Timer => 2,
        Lane::ResolverResult => 3,
        Lane::PeerObservation => 4,
    }
}

const fn lane_at(index: usize) -> Lane {
    LANE_WEIGHTS[index].lane
}

/// One class of asynchronous work issued by the serial authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TaskClass {
    LocalBuild,
    RemoteValidation,
    LocalSigning,
    CriticalAggregation,
    #[allow(dead_code)]
    BulkCrypto,
}

/// The reason one reserved task stopped owning its worker and completion slots.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TaskTerminal {
    Completed,
    Failed,
    #[allow(dead_code)]
    Cancelled,
    #[allow(dead_code)]
    Panicked,
}

/// Exact worker and completion reservation returned by a terminal task.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TaskPermit {
    id: u64,
    generation: u64,
    class: TaskClass,
    units: usize,
}

impl TaskPermit {
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Bounded task policy. Two crypto slots are structurally unavailable to bulk work.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct TaskLimits {
    remote_validations: usize,
    crypto_tasks: usize,
}

impl TaskLimits {
    pub(crate) const fn new(remote_validations: usize, crypto_tasks: usize) -> Self {
        Self {
            remote_validations,
            crypto_tasks,
        }
    }
}

/// Synchronous worker and completion-permit accounting.
pub(crate) struct TaskReservations {
    generation: u64,
    limits: TaskLimits,
    next_id: u64,
    active: BTreeMap<u64, (TaskClass, usize)>,
    remote_validations: usize,
    local_build: bool,
    local_signing: usize,
    critical_aggregation: usize,
    bulk_crypto: usize,
    stopped: bool,
}

impl TaskReservations {
    pub(crate) const fn new(generation: u64, limits: TaskLimits) -> Result<Self, TaskError> {
        if limits.remote_validations == 0 || limits.crypto_tasks < 3 {
            return Err(TaskError::InvalidLimits);
        }
        Ok(Self {
            generation,
            limits,
            next_id: 0,
            active: BTreeMap::new(),
            remote_validations: 0,
            local_build: false,
            local_signing: 0,
            critical_aggregation: 0,
            bulk_crypto: 0,
            stopped: false,
        })
    }

    /// Reserves both execution capacity and one completion return path.
    pub(crate) fn reserve(&mut self, class: TaskClass) -> Result<TaskPermit, TaskError> {
        self.reserve_units(class, 1)
    }

    /// Reserves the actual worker fanout and one correlated completion path.
    pub(crate) fn reserve_units(
        &mut self,
        class: TaskClass,
        units: usize,
    ) -> Result<TaskPermit, TaskError> {
        if self.stopped {
            return Err(TaskError::Stopped);
        }
        if units == 0 {
            return Err(TaskError::InvalidLimits);
        }
        let crypto_used = self
            .local_signing
            .checked_add(self.critical_aggregation)
            .and_then(|used| used.checked_add(self.bulk_crypto))
            .ok_or(TaskError::Accounting)?;
        match class {
            TaskClass::LocalBuild if self.local_build => return Err(TaskError::ClassFull),
            TaskClass::RemoteValidation
                if self.remote_validations >= self.limits.remote_validations =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::LocalSigning
                if crypto_used.saturating_add(units) > self.limits.crypto_tasks
                    || (self.critical_aggregation == 0
                        && crypto_used.saturating_add(units) > self.limits.crypto_tasks - 1) =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::CriticalAggregation
                if units != 1
                    || crypto_used.saturating_add(units) > self.limits.crypto_tasks
                    || (self.local_signing == 0 && crypto_used >= self.limits.crypto_tasks - 1) =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::BulkCrypto
                if self.bulk_crypto.saturating_add(units) > self.limits.crypto_tasks - 2
                    || crypto_used.saturating_add(units) > self.limits.crypto_tasks =>
            {
                return Err(TaskError::ClassFull);
            }
            TaskClass::LocalBuild | TaskClass::RemoteValidation if units != 1 => {
                return Err(TaskError::InvalidLimits);
            }
            _ => {}
        }

        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or(TaskError::IdExhausted)?;
        match class {
            TaskClass::LocalBuild => self.local_build = true,
            TaskClass::RemoteValidation => self.remote_validations += 1,
            TaskClass::LocalSigning => self.local_signing += units,
            TaskClass::CriticalAggregation => self.critical_aggregation += units,
            TaskClass::BulkCrypto => self.bulk_crypto += units,
        }
        self.active.insert(id, (class, units));
        Ok(TaskPermit {
            id,
            generation: self.generation,
            class,
            units,
        })
    }

    /// Reconciles any terminal path. `terminal` is explicit so callers cannot forget panics.
    pub(crate) fn finish(
        &mut self,
        permit: TaskPermit,
        _terminal: TaskTerminal,
    ) -> Result<(), TaskError> {
        if permit.generation != self.generation {
            return Err(TaskError::StaleGeneration);
        }
        let Some((class, units)) = self.active.get(&permit.id).copied() else {
            return Err(TaskError::UnknownPermit);
        };
        if (class, units) != (permit.class, permit.units) {
            return Err(TaskError::MismatchedPermit);
        }
        self.release(permit.id, class, units)
    }

    /// Starts a new process generation and invalidates all old volatile capabilities.
    pub(crate) fn advance_generation(&mut self, generation: u64) -> Result<usize, TaskError> {
        if generation <= self.generation {
            return Err(TaskError::StaleGeneration);
        }
        let released = self.clear();
        self.generation = generation;
        self.stopped = false;
        Ok(released)
    }

    /// Reconciles every permit before the executor shuts down.
    pub(crate) fn shutdown(&mut self) -> usize {
        self.stopped = true;
        self.clear()
    }

    fn clear(&mut self) -> usize {
        let released = self.active.len();
        self.active.clear();
        self.remote_validations = 0;
        self.local_build = false;
        self.local_signing = 0;
        self.critical_aggregation = 0;
        self.bulk_crypto = 0;
        released
    }

    fn release(&mut self, id: u64, class: TaskClass, units: usize) -> Result<(), TaskError> {
        if self.active.remove(&id) != Some((class, units)) {
            return Err(TaskError::MismatchedPermit);
        }
        match class {
            TaskClass::LocalBuild => self.local_build = false,
            TaskClass::RemoteValidation => {
                self.remote_validations = self
                    .remote_validations
                    .checked_sub(units)
                    .ok_or(TaskError::Accounting)?;
            }
            TaskClass::LocalSigning => {
                self.local_signing = self
                    .local_signing
                    .checked_sub(units)
                    .ok_or(TaskError::Accounting)?;
            }
            TaskClass::CriticalAggregation => {
                self.critical_aggregation = self
                    .critical_aggregation
                    .checked_sub(units)
                    .ok_or(TaskError::Accounting)?;
            }
            TaskClass::BulkCrypto => {
                self.bulk_crypto = self
                    .bulk_crypto
                    .checked_sub(units)
                    .ok_or(TaskError::Accounting)?;
            }
        }
        Ok(())
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Bounded per-producer queues serviced by one rotating cursor.
struct ProducerItem<T> {
    item: T,
    bytes: usize,
}

pub(crate) struct ProducerAdmissions<T> {
    queues: Vec<VecDeque<ProducerItem<T>>>,
    next: usize,
    len: usize,
    bytes: usize,
    global_limit: usize,
    per_chain_limit: usize,
    global_byte_limit: usize,
    per_chain_byte_limit: usize,
    chain_bytes: Vec<usize>,
}

impl<T> ProducerAdmissions<T> {
    pub(crate) fn new(
        chains: usize,
        global_limit: usize,
        per_chain_limit: usize,
        global_byte_limit: usize,
        per_chain_byte_limit: usize,
    ) -> Result<Self, TaskError> {
        if chains == 0
            || global_limit == 0
            || per_chain_limit == 0
            || global_byte_limit == 0
            || per_chain_byte_limit == 0
        {
            return Err(TaskError::InvalidLimits);
        }
        Ok(Self {
            queues: (0..chains).map(|_| VecDeque::new()).collect(),
            next: 0,
            len: 0,
            bytes: 0,
            global_limit,
            per_chain_limit,
            global_byte_limit,
            per_chain_byte_limit,
            chain_bytes: vec![0; chains],
        })
    }

    pub(crate) fn admit(&mut self, chain: u32, item: T, bytes: usize) -> Result<(), TaskError> {
        if bytes == 0 {
            return Err(TaskError::InvalidLimits);
        }
        let index = chain as usize;
        let queue = self.queues.get_mut(index).ok_or(TaskError::UnknownChain)?;
        let total_bytes = self.bytes.checked_add(bytes).ok_or(TaskError::Accounting)?;
        let producer_bytes = self.chain_bytes[index]
            .checked_add(bytes)
            .ok_or(TaskError::Accounting)?;
        if self.len >= self.global_limit
            || queue.len() >= self.per_chain_limit
            || total_bytes > self.global_byte_limit
            || producer_bytes > self.per_chain_byte_limit
        {
            return Err(TaskError::ClassFull);
        }
        queue.push_back(ProducerItem { item, bytes });
        self.len += 1;
        self.bytes = total_bytes;
        self.chain_bytes[index] = producer_bytes;
        Ok(())
    }

    /// Returns the next eligible chain's oldest item and rotates past that chain.
    pub(crate) fn pop_ready(&mut self, mut ready: impl FnMut(u32) -> bool) -> Option<T> {
        for offset in 0..self.queues.len() {
            let index = (self.next + offset) % self.queues.len();
            if self.queues[index].is_empty() || !ready(index as u32) {
                continue;
            }
            self.next = (index + 1) % self.queues.len();
            self.len -= 1;
            let queued = self.queues[index]
                .pop_front()
                .expect("a selected producer queue is non-empty");
            self.bytes -= queued.bytes;
            self.chain_bytes[index] -= queued.bytes;
            return Some(queued.item);
        }
        None
    }

    /// Retains queued jobs still owned by their producer chain.
    pub(crate) fn retain(&mut self, mut retain: impl FnMut(&T) -> bool) {
        for (index, queue) in self.queues.iter_mut().enumerate() {
            queue.retain(|entry| {
                if retain(&entry.item) {
                    return true;
                }
                self.len -= 1;
                self.bytes -= entry.bytes;
                self.chain_bytes[index] -= entry.bytes;
                false
            });
        }
    }

    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Drops every queued producer job and returns the released item count.
    pub(crate) fn clear(&mut self) -> usize {
        let released = self.len;
        for queue in &mut self.queues {
            queue.clear();
        }
        self.chain_bytes.fill(0);
        self.len = 0;
        self.bytes = 0;
        self.next = 0;
        released
    }

    #[cfg(test)]
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CoreError {
    #[error("core capacity arithmetic overflowed")]
    CapacityOverflow,
    #[error("core capacity must be non-zero")]
    ZeroCapacity,
    #[error("core input ticket exhausted")]
    TicketExhausted,
    #[error("core service cycle exhausted")]
    CycleExhausted,
    #[error("core input cost overflowed")]
    CostOverflow,
    #[error("core lane {0:?} exhausted its item capacity")]
    LaneItemsFull(Lane),
    #[error("core lane {0:?} exhausted its byte capacity")]
    LaneBytesFull(Lane),
    #[error("core scheduler accounting is inconsistent")]
    SchedulerInvariant,
    #[error("core was resumed without a required runtime yield")]
    UnexpectedResume,
    #[error("core task admission failed: {0}")]
    Task(#[from] TaskError),
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TaskError {
    #[error("task limits are invalid")]
    InvalidLimits,
    #[error("the task class has no available worker and completion reservation")]
    ClassFull,
    #[error("the task reservation id exhausted")]
    IdExhausted,
    #[error("the task permit belongs to a stale process generation")]
    StaleGeneration,
    #[error("the task permit is unknown")]
    UnknownPermit,
    #[error("the task permit does not match its reservation")]
    MismatchedPermit,
    #[error("task permit accounting is inconsistent")]
    Accounting,
    #[error("the task executor is stopped")]
    Stopped,
    #[error("the producer chain is outside the configured committee")]
    UnknownChain,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Limits,
            machine::{
                BarrierAck, Capability, DurabilityCapability, JobId, Profile, ResolutionCompletion,
                ResolutionJob, Role, Tuning, VerificationCompletion,
            },
            mocks::Committee,
            types::Nullification,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        Sha256,
        bls12381::{
            certificate::threshold::Certificate as ThresholdCertificate,
            primitives::variant::{MinPk, Variant},
        },
    };
    use commonware_math::algebra::Additive as _;
    use std::time::Duration;

    fn observer_core(seed: u64) -> CoreState<Sha256, MinPk> {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let profile = Profile::new(
            committee.config,
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap();
        CoreState::new(Machine::new(profile), NonZeroUsize::MIN).unwrap()
    }

    fn queued_input(
        core: &CoreState<Sha256, MinPk>,
        lane: Lane,
        ticket: InputTicket,
    ) -> &Input<MinPk, <Sha256 as Hasher>::Digest> {
        let queued = core.queues[lane_index(lane)]
            .iter()
            .find(|queued| queued.ticket == ticket)
            .expect("the named transition retains its exact ticket");
        let QueuedPayload::Input(input) = &queued.payload else {
            panic!("the named transition must retain one ordinary reducer input");
        };
        input
    }

    #[test]
    fn named_core_transitions_preserve_domain_and_lane() {
        let mut fresh = observer_core(74);
        let started = fresh.start_fresh().unwrap();
        assert!(matches!(
            queued_input(&fresh, Lane::LocalCompletion, started),
            Input::Start
        ));

        let mut recovered = observer_core(75);
        let recovery = recovered.finish_recovery().unwrap();
        assert!(matches!(
            queued_input(&recovered, Lane::LocalCompletion, recovery),
            Input::RecoveryComplete
        ));

        let mut live = observer_core(76);
        let epoch = live.machine().profile().protocol().epoch();
        let producer = live.producer_wake().unwrap();
        let leader = live
            .leader_timer_fired(Timer::new(
                0,
                Round::new(epoch, View::zero()),
                Duration::from_millis(500),
            ))
            .unwrap();
        assert!(matches!(
            queued_input(&live, Lane::Timer, producer),
            Input::ProducerWake
        ));
        assert!(matches!(
            queued_input(&live, Lane::Timer, leader),
            Input::TimerFired(_)
        ));
    }

    #[test]
    fn core_alternates_reducer_work_with_inputs_across_yield() {
        let committee = Committee::<MinPk>::new(73, 6, Limits::new(2, 1).unwrap());
        let profile = Profile::new(
            committee.config,
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap();
        let mut machine = Machine::<Sha256, MinPk>::new(profile);
        let started = machine.step(Input::Start).unwrap();
        let persist = started
            .capabilities()
            .iter()
            .find_map(|capability| match capability {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job),
                _ => None,
            })
            .expect("starting the machine stages its generation");
        machine
            .step(Input::Persisted(BarrierAck::new(
                persist.id(),
                persist.generation(),
                persist.last_cursor(),
            )))
            .unwrap();
        assert!(machine.scheduler.has_work());

        let mut core = CoreState::new(machine, NonZeroUsize::MIN).unwrap();
        for _ in 0..3 {
            core.enqueue(Input::Observe(Vec::new()), 1).unwrap();
        }
        for expected_cycle in [0, 0] {
            let CoreTurn::Input(serviced) = core.next_action(NonZeroUsize::MIN).unwrap() else {
                panic!("an input must precede ready machine work");
            };
            assert_eq!(serviced.lane, Lane::PeerObservation);
            assert_eq!(serviced.cycle, expected_cycle);

            assert!(matches!(
                core.next_action(NonZeroUsize::MIN).unwrap(),
                CoreTurn::Work(_)
            ));
        }

        assert!(matches!(
            core.next_action(NonZeroUsize::MIN).unwrap(),
            CoreTurn::YieldRequired
        ));
        core.resume_after_yield().unwrap();

        let CoreTurn::Input(serviced) = core.next_action(NonZeroUsize::MIN).unwrap() else {
            panic!("the pending input must resume before ready machine work");
        };
        assert_eq!(serviced.lane, Lane::PeerObservation);
        assert_eq!(serviced.cycle, 1);
        assert!(matches!(
            core.next_action(NonZeroUsize::MIN).unwrap(),
            CoreTurn::Work(_)
        ));
        assert!(matches!(
            core.next_action(NonZeroUsize::MIN).unwrap(),
            CoreTurn::Idle
        ));
    }

    #[test]
    fn weighted_cycles_service_control_under_peer_flood() {
        let mut credits = ServiceCycle::new();
        let mut cursor = FairCursor::new();
        let mut pending = [1, 1, 1, 1, usize::MAX];
        let mut serviced = [0; LANE_COUNT];
        loop {
            let ready: [bool; LANE_COUNT] = std::array::from_fn(|index| {
                pending[index] > 0 && credits.remaining_lane(lane_at(index)) > 0
            });
            let Some(index) = cursor.select(&ready) else {
                break;
            };
            credits
                .charge(lane_at(index), TransitionCost::Constant)
                .unwrap();
            pending[index] -= 1;
            serviced[index] += 1;
        }
        assert_eq!(serviced, [1, 1, 1, 1, 2]);
        assert_eq!(credits.remaining_core(), CORE_BUDGET - 6);
    }

    fn continuously_ready_input(
        epoch: Epoch,
        lane: Lane,
        ordinal: u64,
        start_ack: BarrierAck,
    ) -> Input<MinPk, <Sha256 as Hasher>::Digest> {
        match lane {
            Lane::PersistenceCompletion => Input::Persisted(start_ack),
            Lane::LocalCompletion => Input::Verified(VerificationCompletion::new(
                JobId::new(ordinal),
                0,
                Vec::new(),
            )),
            Lane::Timer => Input::TimerFired(Timer::new(
                0,
                Round::new(epoch, View::new(ordinal)),
                Duration::ZERO,
            )),
            Lane::ResolverResult => {
                let view = View::new(ordinal);
                let job = ResolutionJob::fabricate(ordinal, 0, view);
                let proof_view = View::new(ordinal.max(1));
                let proof = ViewProof::Nullification(Box::new(
                    Nullification::new(
                        Round::new(epoch, proof_view),
                        ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
                    )
                    .unwrap(),
                ));
                Input::ResolutionCompleted(ResolutionCompletion::new(
                    job.id(),
                    job.generation(),
                    job.view(),
                    proof,
                ))
            }
            Lane::PeerObservation => Input::Observe(Vec::new()),
        }
    }

    #[test]
    fn core_services_simultaneous_five_source_flood_with_exact_weights() {
        let committee = Committee::<MinPk>::new(73, 6, Limits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let profile = Profile::new(
            committee.config,
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap();
        let mut machine = Machine::<Sha256, MinPk>::new(profile);
        let started = machine.step(Input::Start).unwrap();
        let persist = started
            .capabilities()
            .iter()
            .find_map(|capability| match capability {
                Capability::Durability(DurabilityCapability::Persist(job)) => Some(job),
                _ => None,
            })
            .expect("starting the machine stages its generation");
        let start_ack = BarrierAck::new(persist.id(), persist.generation(), persist.last_cursor());
        machine.step(Input::Persisted(start_ack)).unwrap();
        while machine.poll(NonZeroUsize::MIN).unwrap().work_remaining() {}

        let mut core = CoreState::new(machine, NonZeroUsize::MIN).unwrap();
        let lanes = [
            Lane::PersistenceCompletion,
            Lane::LocalCompletion,
            Lane::Timer,
            Lane::ResolverResult,
            Lane::PeerObservation,
        ];
        let mut next = [0_u64; LANE_COUNT];
        let mut first_cycle = Vec::new();
        let mut due_timer = None;

        loop {
            for (index, lane) in lanes.into_iter().enumerate() {
                if !core.can_admit(lane) {
                    continue;
                }
                let ordinal = next[index];
                let ticket = core
                    .enqueue(continuously_ready_input(epoch, lane, ordinal, start_ack), 1)
                    .unwrap();
                next[index] += 1;
                if lane == Lane::Timer && ordinal == 4 {
                    due_timer = Some(ticket);
                }
            }

            match core.next_action(NonZeroUsize::MIN).unwrap() {
                CoreTurn::Input(serviced) => {
                    assert_eq!(serviced.cycle, 0);
                    first_cycle.push(serviced.lane);
                }
                CoreTurn::Work(_) => {}
                CoreTurn::YieldRequired => break,
                CoreTurn::Idle => panic!("five continuously ready sources cannot idle"),
            }
        }

        let counts = lanes.map(|lane| first_cycle.iter().filter(|seen| **seen == lane).count());
        assert_eq!(counts, [8, 8, 4, 4, 2]);
        assert_eq!(&first_cycle[..5], &lanes);

        let due_timer = due_timer.expect("the fifth timer remains queued at the cycle boundary");
        core.resume_after_yield().unwrap();
        let serviced_cycle = loop {
            match core.next_action(NonZeroUsize::MIN).unwrap() {
                CoreTurn::Input(serviced) if serviced.ticket == due_timer => break serviced.cycle,
                CoreTurn::Input(_) | CoreTurn::Work(_) => {}
                CoreTurn::YieldRequired => core.resume_after_yield().unwrap(),
                CoreTurn::Idle => panic!("the due timer ticket cannot disappear"),
            }
        };
        assert_eq!(serviced_cycle, 1);
    }

    #[test]
    fn oversized_non_observe_cost_yields_to_due_timer() {
        let mut remaining = CORE_BUDGET as usize + 17;
        let mut timer_pending = true;
        let mut timer_cycle = None;
        let mut cycle = 0_u64;
        let mut credits = ServiceCycle::new();
        let mut cursor = FairCursor::new();

        while remaining > 0 || timer_pending {
            let ready = [false, remaining > 0, timer_pending, false, false];
            let index = cursor.select(&ready).expect("completion or timer is ready");
            if index == lane_index(Lane::Timer) {
                credits
                    .charge(Lane::Timer, TransitionCost::Constant)
                    .unwrap();
                timer_pending = false;
                timer_cycle = Some(cycle);
                continue;
            }

            let available = credits.remaining_core() as usize;
            if available == 0 {
                cycle += 1;
                credits = ServiceCycle::new();
                continue;
            }
            let processed = remaining.min(available);
            credits
                .charge(
                    Lane::LocalCompletion,
                    cost_prefix(TransitionCost::ArtifactItems(remaining), processed),
                )
                .unwrap();
            remaining -= processed;
            if credits.remaining_core() == 0 {
                cycle += 1;
                credits = ServiceCycle::new();
            }
        }

        assert_eq!(timer_cycle, Some(1));
        assert_eq!(remaining, 0);
    }

    #[test]
    fn task_saturation_preserves_named_critical_capacity() {
        let mut tasks = TaskReservations::new(7, TaskLimits::new(2, 5)).unwrap();
        let bulk = (0..3)
            .map(|_| tasks.reserve(TaskClass::BulkCrypto).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            tasks.reserve(TaskClass::BulkCrypto),
            Err(TaskError::ClassFull)
        );

        let signing = tasks.reserve(TaskClass::LocalSigning).unwrap();
        let aggregation = tasks.reserve(TaskClass::CriticalAggregation).unwrap();
        tasks.finish(signing, TaskTerminal::Completed).unwrap();
        tasks.finish(aggregation, TaskTerminal::Failed).unwrap();
        for permit in bulk {
            tasks.finish(permit, TaskTerminal::Cancelled).unwrap();
        }
    }

    #[test]
    fn stale_generation_cannot_release_current_capacity() {
        let mut tasks = TaskReservations::new(11, TaskLimits::new(2, 3)).unwrap();
        let old = tasks.reserve(TaskClass::LocalBuild).unwrap();
        assert_eq!(tasks.advance_generation(12).unwrap(), 1);
        let current = tasks.reserve(TaskClass::LocalBuild).unwrap();
        assert_eq!(
            tasks.finish(old, TaskTerminal::Completed),
            Err(TaskError::StaleGeneration)
        );
        tasks.finish(current, TaskTerminal::Completed).unwrap();
    }

    #[test]
    fn shutdown_reconciles_every_permit_and_rejects_new_work() {
        let mut tasks = TaskReservations::new(3, TaskLimits::new(2, 4)).unwrap();
        tasks.reserve(TaskClass::LocalBuild).unwrap();
        tasks.reserve(TaskClass::RemoteValidation).unwrap();
        tasks.reserve(TaskClass::LocalSigning).unwrap();
        assert_eq!(tasks.shutdown(), 3);
        assert_eq!(
            tasks.reserve(TaskClass::CriticalAggregation),
            Err(TaskError::Stopped)
        );
    }

    #[test]
    fn producer_admission_rotates_across_nonempty_chains() {
        let mut queue = ProducerAdmissions::new(3, 8, 4, 80, 40).unwrap();
        queue.admit(0, (0, 'a'), 10).unwrap();
        queue.admit(0, (0, 'b'), 10).unwrap();
        queue.admit(1, (1, 'a'), 10).unwrap();
        queue.admit(2, (2, 'a'), 10).unwrap();

        let order = (0..4)
            .map(|_| queue.pop_ready(|_| true).unwrap().0)
            .collect::<Vec<_>>();
        assert_eq!(order, [0, 1, 2, 0]);
    }

    #[test]
    fn producer_admission_enforces_global_and_per_chain_caps() {
        let mut queue = ProducerAdmissions::new(3, 2, 1, 20, 10).unwrap();
        queue.admit(0, 'a', 10).unwrap();
        assert_eq!(queue.admit(0, 'b', 1), Err(TaskError::ClassFull));
        queue.admit(1, 'a', 10).unwrap();
        assert_eq!(queue.admit(2, 'a', 1), Err(TaskError::ClassFull));
        assert_eq!(queue.bytes(), 20);
    }

    #[test]
    fn local_build_is_independent_of_remote_validation_saturation() {
        let mut tasks = TaskReservations::new(1, TaskLimits::new(2, 3)).unwrap();
        let first = tasks.reserve(TaskClass::RemoteValidation).unwrap();
        let second = tasks.reserve(TaskClass::RemoteValidation).unwrap();
        assert_eq!(
            tasks.reserve(TaskClass::RemoteValidation),
            Err(TaskError::ClassFull)
        );
        tasks.reserve(TaskClass::LocalBuild).unwrap();
        tasks.finish(first, TaskTerminal::Completed).unwrap();
        let replacement = tasks.reserve(TaskClass::RemoteValidation).unwrap();
        tasks.finish(second, TaskTerminal::Cancelled).unwrap();
        tasks.finish(replacement, TaskTerminal::Completed).unwrap();
    }
}
