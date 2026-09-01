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
//! without counting the input twice. A chain plane's DA-vote offer is not an input: the core
//! applies it at once, outside the lanes and the budget.

use super::{
    durability::{DomainEvent, EffectCompletion, ReplayError, Snapshot},
    input::{DaVotesOffer, Input, PollResult, Step, StepError, StepStatus},
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

/// Timer inputs queued at once: a view timer and one producer wake or deadline.
const TIMER_LANE_ITEMS: usize = 2;

/// Local completions queued beyond in-flight verifications and outbox effects: lifecycle inputs
/// and producer build and custody completions.
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
        Ok(Self { lanes })
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
    #[cfg(test)]
    pub(crate) lane: Lane,
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

    /// Queues one decoded observation cohort retaining `resident_bytes`.
    pub(crate) fn observe(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<V, H::Digest>>,
        resident_bytes: usize,
    ) -> Result<InputTicket, CoreError> {
        self.admit(Input::Observe(artifacts), resident_bytes)
    }

    /// Queues one reducer input other than an observation.
    ///
    /// An observation carries peer-chosen bytes, so it enters only through [`Self::observe`],
    /// which charges its resident size against the peer lane's byte ceiling.
    pub(crate) fn enqueue(&mut self, input: Input<V, H::Digest>) -> Result<InputTicket, CoreError> {
        if matches!(input, Input::Observe(_)) {
            return Err(CoreError::UnsizedObservation);
        }
        self.admit(input, 1)
    }

    /// Applies a chain plane's DA-vote offer at once, outside the lanes and the core budget.
    ///
    /// An offer takes no lane turn and spends no core credit, so offers do not reorder the
    /// work around them. The machine still checks the offer's generation and reports a stale one.
    pub(crate) fn offer(&mut self, offer: DaVotesOffer<V, H::Digest>) -> StepStatus<H::Digest> {
        self.machine.offer_da_votes(offer)
    }

    /// Reserves lane capacity for `input` and queues it.
    fn admit(
        &mut self,
        input: Input<V, H::Digest>,
        resident_bytes: usize,
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
            pass: InputPass::new(input),
            bytes,
        });
        Ok(ticket)
    }

    /// Selects one admitted input or one machine-owned work quantum.
    ///
    /// Machine-owned work runs one work key per action, and `before_poll` sees the machine
    /// immediately before that work runs.
    pub(crate) fn next_action(
        &mut self,
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
                self.poll_machine()
            }
            Some(DriveSource::Input) => {
                let action = self.service_input(persistence_blocked)?;
                if matches!(action, CoreTurn::Input(_)) {
                    self.drive.record(DriveSource::Input);
                }
                Ok(action)
            }
        }
    }

    fn poll_machine(&mut self) -> Result<CoreTurn<V, H::Digest>, CoreError> {
        let result = self.machine.poll(NonZeroUsize::MIN)?;
        self.drive.record(DriveSource::Machine);
        Ok(CoreTurn::Work(result))
    }

    fn service_input(
        &mut self,
        persistence_only: bool,
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
        let advance = self.machine.advance(&mut queued.pass, available)?;
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
            #[cfg(test)]
            lane,
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
    pub(crate) const fn can_admit(&self, lane: Lane) -> bool {
        let index = lane.index();
        self.usage[index].items < self.limits.lane(lane).items
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
        | Input::BlockCustodied(_)
        | Input::CustodyCancelled(_)
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
        Epochable as _,
        multimmit::{
            config::{Profile, Role, Tuning},
            machine::{
                capability::Capability,
                durability::BarrierAck,
                input::CryptoCompletion,
                job::{Generation, Issued},
                resolution::{ResolutionCompletion, ResolutionJob},
                scheduler::CORE_BUDGET,
                verification::{JobId, VerificationCompletion},
                view::ViewTimer,
            },
            mocks::Committee,
            types::{ChainId, DaCertificate, Nullification, TransactionBlockHeader, ViewProof},
        },
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Sha256,
        bls12381::{
            certificate::threshold::Certificate as ThresholdCertificate,
            primitives::variant::{MinPk, Variant},
        },
    };
    use commonware_math::algebra::Additive as _;
    use std::{collections::BTreeMap, time::Duration};

    fn observer_core(seed: u64) -> CoreState<Sha256, MinPk> {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let profile = Profile::new::<MinPk>(
            committee.config,
            Role::Observer,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap();
        CoreState::new(Machine::new(profile)).unwrap()
    }

    /// Returns the queued pass of `ticket` in `lane`, if it is queued there.
    fn queued_in(
        core: &CoreState<Sha256, MinPk>,
        lane: Lane,
        ticket: InputTicket,
    ) -> Option<&InputPass<MinPk, <Sha256 as Hasher>::Digest>> {
        core.queues[lane.index()]
            .iter()
            .find(|queued| queued.ticket == ticket)
            .map(|queued| &queued.pass)
    }

    #[test]
    fn inputs_queue_in_their_lanes() {
        let mut fresh = observer_core(74);
        let started = fresh.enqueue(Input::Start).unwrap();
        assert!(matches!(
            queued_in(&fresh, Lane::LocalCompletion, started).and_then(InputPass::pending_input),
            Some(Input::Start)
        ));

        let mut recovered = observer_core(75);
        let recovery = recovered.enqueue(Input::RecoveryComplete).unwrap();
        assert!(matches!(
            queued_in(&recovered, Lane::LocalCompletion, recovery)
                .and_then(InputPass::pending_input),
            Some(Input::RecoveryComplete)
        ));

        let mut live = observer_core(76);
        let epoch = live.machine().profile().protocol().epoch();
        let producer = live.enqueue(Input::ProducerWake).unwrap();
        let leader = live
            .enqueue(Input::TimerFired(ViewTimer::new(
                Generation::new(0),
                Round::new(epoch, View::zero()),
                Duration::from_millis(500),
            )))
            .unwrap();
        assert!(matches!(
            queued_in(&live, Lane::Timer, producer).and_then(InputPass::pending_input),
            Some(Input::ProducerWake)
        ));
        assert!(matches!(
            queued_in(&live, Lane::Timer, leader).and_then(InputPass::pending_input),
            Some(Input::TimerFired(_))
        ));
        let header = TransactionBlockHeader::new(
            epoch,
            ChainId::new(0),
            Height::new(1),
            live.machine().certified_anchor(ChainId::new(0)).digest(),
            Sha256::hash(&[b"recovered block"]),
        )
        .unwrap();
        let recovered_certificate = live
            .enqueue(Input::Crypto(CryptoCompletion::DaCertificate {
                block: header.block_ref::<Sha256>(),
                certificate: DaCertificate::new(
                    header,
                    ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
                ),
            }))
            .unwrap();
        assert!(matches!(
            queued_in(&live, Lane::LocalCompletion, recovered_certificate)
                .and_then(InputPass::pending_input),
            Some(Input::Crypto(CryptoCompletion::DaCertificate { .. }))
        ));
        let observed = live.observe(Vec::new(), 1).unwrap();
        assert!(queued_in(&live, Lane::PeerObservation, observed).is_some_and(InputPass::observes));

        // An observation carries peer-chosen bytes, so only the sized path may queue it.
        assert_eq!(
            live.enqueue(Input::Observe(Vec::new())),
            Err(CoreError::UnsizedObservation)
        );
        assert!(queued_in(&live, Lane::PeerObservation, observed).is_some());
        assert_eq!(live.queues[Lane::PeerObservation.index()].len(), 1);
    }

    #[test]
    fn da_vote_offers_apply_at_once_outside_the_lanes() {
        let mut core = observer_core(77);
        let chain = ChainId::new(0);
        let offer = |core: &CoreState<Sha256, MinPk>, generation| DaVotesOffer {
            generation,
            chain,
            candidates: Vec::new(),
            ready_through: core.machine().certified_anchor(chain).height(),
        };
        let current = core.machine().generation();
        let stale = Generation::new(current.get() + 1);

        assert_eq!(core.offer(offer(&core, stale)), StepStatus::StaleCompletion);
        assert!(!core.machine().has_component_work());
        assert_eq!(core.offer(offer(&core, current)), StepStatus::Accepted);
        assert!(!core.has_pending_inputs());
        assert_eq!(core.service.remaining_core(), CORE_BUDGET);
        assert!(
            core.machine().has_component_work(),
            "a current offer schedules the DA-vote drain"
        );
    }

    #[test]
    fn core_alternates_reducer_work_with_inputs_across_yield() {
        let committee = Committee::<MinPk>::builder(73, 6).build();
        let profile = Profile::new::<MinPk>(
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
                Capability::Journal(job) => Some(job),
                _ => None,
            })
            .expect("starting the machine stages its generation");
        machine.step(Input::Persisted(persist.job.ack())).unwrap();
        assert!(machine.has_component_work());

        let mut core = CoreState::new(machine).unwrap();
        let tickets = (0..3)
            .map(|_| core.observe(Vec::new(), 1).unwrap())
            .collect::<Vec<_>>();
        for ticket in &tickets[..2] {
            let CoreTurn::Input(serviced) = core.next_action(|_| {}).unwrap() else {
                panic!("an input must precede ready machine work");
            };
            assert_eq!(serviced.ticket, *ticket);

            assert!(matches!(
                core.next_action(|_| {}).unwrap(),
                CoreTurn::Work(_)
            ));
        }

        assert!(matches!(
            core.next_action(|_| {}).unwrap(),
            CoreTurn::YieldRequired
        ));
        core.resume_after_yield().unwrap();

        let CoreTurn::Input(serviced) = core.next_action(|_| {}).unwrap() else {
            panic!("the pending input must resume before ready machine work");
        };
        assert_eq!(serviced.ticket, tickets[2]);
        assert!(matches!(
            core.next_action(|_| {}).unwrap(),
            CoreTurn::Work(_)
        ));
        assert!(matches!(core.next_action(|_| {}).unwrap(), CoreTurn::Idle));
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

    fn continuously_ready_input(
        epoch: Epoch,
        lane: Lane,
        ordinal: u64,
        start_ack: BarrierAck,
    ) -> Input<MinPk, <Sha256 as Hasher>::Digest> {
        match lane {
            Lane::PersistenceCompletion => Input::Persisted(start_ack),
            Lane::LocalCompletion => Input::Verified(VerificationCompletion::new(
                Issued::new(JobId::new(ordinal), Generation::new(0)),
                Vec::new(),
            )),
            Lane::Timer => Input::TimerFired(ViewTimer::new(
                Generation::new(0),
                Round::new(epoch, View::new(ordinal)),
                Duration::ZERO,
            )),
            Lane::ResolverResult => {
                let view = View::new(ordinal);
                let job = ResolutionJob::issue(ordinal, Generation::new(0), view);
                let proof_view = View::new(ordinal.max(1));
                let proof = ViewProof::Nullification(Box::new(
                    Nullification::new(
                        Round::new(epoch, proof_view),
                        ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
                    )
                    .unwrap(),
                ));
                Input::ResolutionCompleted(ResolutionCompletion::new(
                    job.issued(),
                    job.view(),
                    proof,
                ))
            }
            Lane::PeerObservation => Input::Observe(Vec::new()),
        }
    }

    #[test]
    fn core_services_simultaneous_five_source_flood_with_exact_weights() {
        let committee = Committee::<MinPk>::builder(73, 6).build();
        let epoch = committee.config.epoch();
        let profile = Profile::new::<MinPk>(
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
                Capability::Journal(job) => Some(job),
                _ => None,
            })
            .expect("starting the machine stages its generation");
        let start_ack = persist.job.ack();
        machine.step(Input::Persisted(start_ack)).unwrap();
        loop {
            machine.poll(NonZeroUsize::MIN).unwrap();
            if !machine.work_remaining() {
                break;
            }
        }

        let mut core = CoreState::new(machine).unwrap();
        let lanes = [
            Lane::PersistenceCompletion,
            Lane::LocalCompletion,
            Lane::Timer,
            Lane::ResolverResult,
            Lane::PeerObservation,
        ];
        let mut next = [0_u64; Lane::COUNT];
        let mut ticket_lanes = BTreeMap::new();
        let mut first_cycle = Vec::new();
        let mut due_timer = None;

        loop {
            for (index, lane) in lanes.into_iter().enumerate() {
                if !core.can_admit(lane) {
                    continue;
                }
                let ordinal = next[index];
                let ticket = match continuously_ready_input(epoch, lane, ordinal, start_ack) {
                    Input::Observe(artifacts) => core.observe(artifacts, 1),
                    input => core.enqueue(input),
                }
                .unwrap();
                next[index] += 1;
                ticket_lanes.insert(ticket, lane);
                if lane == Lane::Timer && ordinal == 4 {
                    due_timer = Some(ticket);
                }
            }

            match core.next_action(|_| {}).unwrap() {
                CoreTurn::Input(serviced) => first_cycle.push(ticket_lanes[&serviced.ticket]),
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
        let mut cycle = 1;
        loop {
            match core.next_action(|_| {}).unwrap() {
                CoreTurn::Input(serviced) if serviced.ticket == due_timer => break,
                CoreTurn::Input(_) | CoreTurn::Work(_) => {}
                CoreTurn::YieldRequired => {
                    core.resume_after_yield().unwrap();
                    cycle += 1;
                }
                CoreTurn::Idle => panic!("the due timer ticket cannot disappear"),
            }
        }
        assert_eq!(cycle, 1);
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
            )
            .expect("a locally issued completion is admitted past the lane byte ceiling");
        let usage = core.usage[Lane::LocalCompletion.index()];
        assert_eq!(usage.items, 1);
        assert!(usage.bytes > local.bytes);

        // The completion is queued for service, not silently dropped.
        assert!(
            core.queues[Lane::LocalCompletion.index()]
                .iter()
                .any(|queued| queued.ticket == ticket)
        );

        // Peer-supplied bytes keep their ceiling.
        assert_eq!(
            core.observe(Vec::new(), peer.bytes.saturating_add(1)),
            Err(CoreError::LaneBytesFull(Lane::PeerObservation)),
        );
    }

    #[test]
    fn ordinary_input_waits_for_one_credit_then_completes() {
        let mut core = observer_core(77);
        let ticket = core.enqueue(Input::Start).unwrap();
        core.service
            .charge(Lane::PeerObservation, CORE_BUDGET as usize)
            .unwrap();
        assert!(matches!(
            core.service_input(false).unwrap(),
            CoreTurn::YieldRequired
        ));
        assert!(queued_in(&core, Lane::LocalCompletion, ticket).is_some());
        core.resume_after_yield().unwrap();
        let CoreTurn::Input(serviced) = core.service_input(false).unwrap() else {
            panic!("the admitted input must consume the replenished credit");
        };
        assert_eq!(serviced.ticket, ticket);
        assert!(serviced.final_chunk);
        assert_eq!(serviced.observed_items, 0);
        assert_eq!(core.service.remaining_core(), CORE_BUDGET - 1);
        assert!(!core.has_pending_inputs());
    }
}
