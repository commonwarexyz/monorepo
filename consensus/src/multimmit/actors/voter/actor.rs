use super::{
    Mailbox, Message, Query, Startup, VoterLimits,
    egress::{Egress, PublicationOrigin, Transmission},
    journal::{
        Admission as JournalAdmission, Durable as JournalDurable, JournalClient, JournalFailure,
        JournalMonitor, Response as JournalResponse,
    },
    metrics::Metrics as ActorMetrics,
};
use crate::{
    Automaton, Epochable as _, Relay, Reporter, Viewable as _,
    multimmit::{
        actors::{
            batcher::{self, Completed, Observed},
            metrics::Traffic,
            resolver::{self, ResolveRequest, Served},
            wire::Plane,
        },
        config::LeaderSchedule,
        machine::{
            Artifact, BlockValidity, BuildCompletion, BuildId, BuildJob, Capabilities, Capability,
            CoreError, CoreState, CoreTransition, CoreTurn, CoreWork, Cursor, DaRecoveryCompletion,
            DurabilityCapability, DurableEffect, EffectId, IdentifiedArtifact, InputTicket, JobId,
            LeaderCapability, LqcAggregateCompletion, NullificationRecoveryCompletion, Observation,
            ObservationStatus, PersistDirective, ProducerCapability, ProducerProgress,
            ProductionTimer, Profile, ResolverCapability, Role, SignRequest, StepError, StepStatus,
            TaskClass, TaskError, TaskPermit, TaskTerminal, Timer, ValidationCompletion,
            ValidationId, ValidationJob, VerificationCapability, VqcAggregateCompletion,
            contracts::Lane,
        },
        scheme::bls12381_threshold::{Error as SchemeError, Scheme},
        storage::{CheckpointError, CheckpointStore},
        types::{Activity, BlockRef, ChainId, Context, SignedTransactionBlock},
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_actor::{Feedback, mailbox};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::{select, select_loop};
use commonware_p2p::{Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Error as RuntimeError, Handle, Metrics, Spawner, Storage,
    telemetry::{
        metrics::{GaugeExt as _, Histogram, HistogramExt as _},
        traces::TracedExt as _,
    },
    utils::reschedule,
};
use commonware_storage::Context as StorageContext;
#[cfg(test)]
use commonware_utils::sync::Mutex;
use commonware_utils::{SystemTimeExt as _, channel::oneshot, futures::Pool};
use futures::FutureExt as _;
#[cfg(test)]
use std::collections::BTreeSet;
use std::{
    collections::{BTreeMap, VecDeque},
    future::pending as pending_forever,
    mem::size_of_val,
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::SystemTime,
};
use tracing::{Instrument as _, Span, debug, debug_span, error, info, info_span, warn};

#[path = "executor.rs"]
mod executor;

/// One reconciled worker result for a bulk-cryptography task.
type CryptoTaskOutcome<V, D> = (
    Span,
    Result<Result<CryptoOutcome<V, D>, SchemeError>, CryptoTaskPanicked>,
);

#[derive(Debug)]
struct CryptoTaskPanicked;

/// Exactly one machine-owned work key may run after the core finds no admitted input.
pub(crate) const POLL_BUDGET: NonZeroUsize = NonZeroUsize::MIN;

/// Publication attempts admitted in one voter turn.
const PUBLICATION_BUDGET: usize = 32;

/// One exact execution attempt for a stable durable-effect identity.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TestDurableAttempt<V: Variant, D: Digest> {
    pub(super) generation: u64,
    pub(super) effect: DurableEffect<V, D>,
}

/// Ordered observations around resolver retention and egress mutation.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TestEvent<V: Variant, D: Digest> {
    Acknowledged {
        ack: crate::multimmit::machine::BarrierAck,
        retired: Vec<EffectId>,
    },
    Retained {
        object: Served<V, D>,
        boundary: RetentionBoundary,
    },
    Installed {
        id: EffectId,
        generation: u64,
    },
    Retired(Vec<EffectId>),
}

/// Causal boundary at which a resolver proof entered process-local serving custody.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RetentionBoundary {
    Staged(crate::multimmit::machine::BarrierId),
    Acknowledged(crate::multimmit::machine::BarrierAck),
    Recovered,
}

/// Every recorded issue attempt for one durable effect, in issue order.
#[cfg(test)]
type DurableAttemptLedger<V, D> = BTreeMap<EffectId, Vec<TestDurableAttempt<V, D>>>;

/// Test-only ledger and cut at typed actor boundaries.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestHooks<V: Variant, D: Digest> {
    durable: Arc<Mutex<DurableAttemptLedger<V, D>>>,
    events: Arc<Mutex<Vec<TestEvent<V, D>>>>,
    services: Arc<Mutex<Vec<(u64, Lane)>>>,
}

#[cfg(test)]
impl<V: Variant, D: Digest> Default for TestHooks<V, D> {
    fn default() -> Self {
        Self {
            durable: Arc::new(Mutex::new(BTreeMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            services: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> TestHooks<V, D> {
    pub(super) fn durable_effects(&self) -> BTreeMap<EffectId, Vec<TestDurableAttempt<V, D>>> {
        self.durable.lock().clone()
    }

    pub(super) fn events(&self) -> Vec<TestEvent<V, D>> {
        self.events.lock().clone()
    }

    pub(super) fn services(&self) -> Vec<(u64, Lane)> {
        self.services.lock().clone()
    }

    pub(super) fn live_publications(&self) -> BTreeSet<EffectId> {
        let mut live = BTreeSet::new();
        for event in self.events.lock().iter() {
            match event {
                TestEvent::Installed { id, .. } => {
                    live.insert(*id);
                }
                TestEvent::Retired(ids) => {
                    for id in ids {
                        live.remove(id);
                    }
                }
                TestEvent::Acknowledged { .. } | TestEvent::Retained { .. } => {}
            }
        }
        live
    }

    fn record_durable(&self, id: EffectId, generation: u64, effect: &DurableEffect<V, D>) {
        self.durable
            .lock()
            .entry(id)
            .or_default()
            .push(TestDurableAttempt {
                generation,
                effect: effect.clone(),
            });
    }

    fn record_service(&self, cycle: u64, lane: Lane) {
        self.services.lock().push((cycle, lane));
    }

    fn record(&self, event: TestEvent<V, D>) {
        self.events.lock().push(event);
    }
}

type PendingConfig<E, H, P, V, A, R, F, T> = Option<Config<E, H, P, V, A, R, F, T>>;

/// Configuration for the voter.
pub struct Config<E, H, P, V, A, R, F, T>
where
    E: Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
{
    /// Scheme holding this replica's exact key material (or verifier-only material).
    pub scheme: Scheme<P, V>,
    /// Execution strategy for CPU-heavy cryptography.
    pub strategy: T,
    /// The attached application automaton.
    pub automaton: A,
    /// The application payload relay.
    pub relay: R,
    /// Non-authoritative sink for machine-authorized activity.
    pub reporter: F,
    /// The machine to drive, fresh or recovered.
    pub startup: Startup<E, H, V>,
    /// Durable machine checkpoints.
    pub checkpoints: CheckpointStore<E, V, H::Digest>,
    /// Bounded execution and retry policy.
    pub limits: VoterLimits,
    /// Control mailbox capacity.
    pub mailbox_size: NonZeroUsize,
}

/// A fatal epoch error: the voter stops and the engine must tear down.
#[derive(Debug, thiserror::Error)]
enum Fatal {
    #[error("machine step failed: {0}")]
    Step(#[from] StepError),
    #[error("core failed: {0}")]
    CoreState(#[from] CoreError),
    #[error("core task admission failed: {0}")]
    Task(#[from] TaskError),
    #[error("safety journal driver failed: {0}")]
    JournalDriver(#[from] JournalFailure),
    #[error("signing or certificate assembly failed: {0}")]
    Scheme(#[from] SchemeError),
    #[error("the automaton dropped a mandatory verification completion")]
    Automaton,
    #[error("a cryptographic worker panicked")]
    CryptoTaskPanicked,
    #[error("background storage synchronization failed: {0}")]
    Sync(#[from] RuntimeError),
    #[error("checkpoint store failed: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("a mandatory control channel closed")]
    Closed,
}

/// One completed asynchronous application job.
enum AppOutcome<V: Variant, D: Digest> {
    Built {
        started_at: SystemTime,
        id: BuildId,
        generation: u64,
        parent: BlockRef<D>,
        result: Option<D>,
    },
    Validated {
        started_at: SystemTime,
        id: ValidationId,
        generation: u64,
        block: Arc<SignedTransactionBlock<V, D>>,
        verdict: Option<bool>,
    },
    ValidationCancelled {
        id: ValidationId,
        chain: ChainId,
    },
}

#[derive(Copy, Clone)]
enum AppCompletionTiming {
    Propose(SystemTime),
    Verify(SystemTime),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AppCompletionKey<D: Digest> {
    Propose {
        chain: u32,
        parent: D,
        commitment: D,
    },
    Verify(D),
}

#[derive(Copy, Clone)]
struct SigningTiming {
    ready_to_sign_at: SystemTime,
    application: Option<AppCompletionTiming>,
}

#[derive(Clone, Copy)]
struct TimedSign {
    id: EffectId,
    at: SystemTime,
}

#[derive(Clone, Copy)]
struct TimedPublication {
    id: EffectId,
    at: SystemTime,
}

#[derive(Clone)]
struct InputContext<D: Digest> {
    span: Span,
    application: Option<(AppCompletionKey<D>, AppCompletionTiming)>,
    sign: Option<TimedSign>,
    publication: Option<TimedPublication>,
}

/// One signature, certificate assembly, or recovery as it returns from the compute pool.
type CryptoResult<V, D> = (TaskPermit, CryptoTaskOutcome<V, D>);

type AppResult<V, D> = (TaskPermit, Span, Result<AppOutcome<V, D>, RuntimeError>);

/// Submits CPU work directly to the configured strategy while the actor awaits its completion.
async fn run_crypto_operation<P, O, T>(
    strategy: P,
    span: Span,
    operation: O,
) -> (Span, Result<T, CryptoTaskPanicked>)
where
    P: Strategy,
    O: FnOnce(P) -> T + Send + 'static,
    T: Send + 'static,
{
    let completion_span = span.clone();
    let worker_span = span.clone();
    let operation = async move {
        strategy
            .spawn(move |strategy| worker_span.in_scope(|| operation(strategy)))
            .await
    };
    let outcome = AssertUnwindSafe(operation)
        .catch_unwind()
        .instrument(span)
        .await
        .map_err(|_| CryptoTaskPanicked);
    (completion_span, outcome)
}

/// One completed asynchronous signature, certificate assembly, or recovery.
enum CryptoOutcome<V: Variant, D: Digest> {
    Signed {
        id: EffectId,
        generation: u64,
        artifact: Arc<Artifact<V, D>>,
        timing: SigningTiming,
    },
    SignedBatch {
        id: EffectId,
        generation: u64,
        artifacts: Vec<Artifact<V, D>>,
        timing: SigningTiming,
    },
    DaRecovered {
        started_at: SystemTime,
        completion: DaRecoveryCompletion<V, D>,
    },
    NullificationRecovered {
        started_at: SystemTime,
        completion: NullificationRecoveryCompletion<V>,
    },
    VqcAggregated {
        view: View,
        completion: Box<VqcAggregateCompletion<V, D>>,
    },
    LqcAggregated {
        view: View,
        completion: Box<LqcAggregateCompletion<V, D>>,
    },
}

struct PendingVerification<P: PublicKey, V: Variant, D: Digest> {
    span: Span,
    round: Round,
    job: crate::multimmit::machine::VerifyJob<V, D>,
    sources: Vec<Option<P>>,
}

struct ObservationSources<P> {
    /// Sources in reverse observation order. Each core prefix consumes the tail, so
    /// resumable observation does not allocate, shift, or copy source metadata.
    items: Vec<P>,
}

fn reset_generation_runtime_correlations<P>(
    active_validations: &mut BTreeMap<ValidationId, Option<oneshot::Sender<()>>>,
    verification_sources: &mut BTreeMap<Observation, P>,
) {
    active_validations.clear();
    verification_sources.clear();
}

/// One checkpoint whose snapshot write runs behind the live pipeline.
struct PendingCheckpoint<E: StorageContext, V: Variant, D: Digest> {
    store: CheckpointProgress<E, V, D>,
    origin: CheckpointOrigin,
    span: Span,
}

/// Journal compaction completing behind the live core after a durable checkpoint.
struct PendingPrune {
    response: JournalResponse<()>,
    span: Span,
}

#[derive(Copy, Clone)]
struct CheckpointOrigin {
    epoch: Epoch,
    view: View,
    cursor: Cursor,
    retired_views: View,
}

impl CheckpointOrigin {
    fn roll_span(self) -> Span {
        info_span!(
            parent: None,
            "multimmit.voter.checkpoint.roll",
            epoch = self.epoch.get().traced(),
            view = self.view.get().traced(),
            cursor = self.cursor.get().traced(),
            retired_views = self.retired_views.get().traced(),
        )
    }

    fn store_span(self) -> Span {
        info_span!(
            parent: None,
            "multimmit.voter.checkpoint.store",
            epoch = self.epoch.get().traced(),
            view = self.view.get().traced(),
            cursor = self.cursor.get().traced(),
            retired_views = self.retired_views.get().traced(),
        )
    }

    fn prune_span(self) -> Span {
        info_span!(
            parent: None,
            "multimmit.voter.checkpoint.prune",
            epoch = self.epoch.get().traced(),
            view = self.view.get().traced(),
            cursor = self.cursor.get().traced(),
            retired_views = self.retired_views.get().traced(),
        )
    }
}

struct PendingJournal<V: Variant, D: Digest> {
    response: JournalResponse<JournalDurable<V, D>>,
    publication: Option<TimedPublication>,
}

struct TimedDurable<V: Variant, D: Digest> {
    durable: JournalDurable<V, D>,
    publication: Option<TimedPublication>,
}

/// One ready runtime source, before it is admitted to the serial protocol owner.
enum RuntimeEvent<P: PublicKey, V: Variant, D: Digest> {
    Persistence(Result<TimedDurable<V, D>, JournalFailure>),
    JournalMonitor(Result<(), JournalFailure>),
    JournalCapacity(Result<(), JournalFailure>),
    Checkpoint(Result<bool, Fatal>),
    Prune(Result<(), JournalFailure>),
    Application(AppResult<V, D>),
    Crypto(CryptoResult<V, D>),
    ViewTimer,
    ProductionTimer,
    Publication,
    Heartbeat,
    Verification(Completed<D>),
    Resolution(Message<V, D>),
    Inspection(Query<D>),
    Observation(Observed<P, V, D>),
    InputClosed,
}

impl<P: PublicKey, V: Variant, D: Digest> RuntimeEvent<P, V, D> {
    const fn core_lane(&self) -> Option<Lane> {
        match self {
            Self::Persistence(_) => Some(Lane::PersistenceCompletion),
            Self::Application(_) | Self::Crypto(_) | Self::Verification(_) => {
                Some(Lane::LocalCompletion)
            }
            Self::ViewTimer | Self::ProductionTimer => Some(Lane::Timer),
            Self::Resolution(_) => Some(Lane::ResolverResult),
            Self::Observation(_) => Some(Lane::PeerObservation),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RuntimeDisposition {
    Continue,
    Stop,
}

/// The snapshot write's progress toward returning the checkpoint store.
enum CheckpointProgress<E: StorageContext, V: Variant, D: Digest> {
    Writing(Handle<Result<CheckpointStore<E, V, D>, CheckpointError>>),
    Durable(CheckpointStore<E, V, D>),
}

/// Waits for every checkpoint sync, or forever when no checkpoint is pending.
///
/// The syncs already run concurrently in the runtime; awaiting them in sequence only orders
/// this observer.
async fn wait_for_checkpoint<E: StorageContext, V: Variant, D: Digest>(
    pending: Option<&mut PendingCheckpoint<E, V, D>>,
    journal_idle: bool,
) -> Result<bool, Fatal> {
    let Some(pending) = pending else {
        return pending_forever().await;
    };
    if let CheckpointProgress::Writing(handle) = &mut pending.store {
        let store = handle.await??;
        pending.store = CheckpointProgress::Durable(store);
        return Ok(false);
    }
    if journal_idle {
        Ok(true)
    } else {
        pending_forever().await
    }
}

async fn next_journal_response<V: Variant, D: Digest>(
    enabled: bool,
    responses: &mut VecDeque<PendingJournal<V, D>>,
) -> Result<TimedDurable<V, D>, JournalFailure> {
    if !enabled {
        return pending_forever().await;
    }
    let pending = responses
        .front_mut()
        .expect("an enabled journal response exists");
    let durable = (&mut pending.response).await?;
    let pending = responses
        .pop_front()
        .expect("the completed journal response remains queued");
    Ok(TimedDurable {
        durable,
        publication: pending.publication,
    })
}

async fn wait_for_journal_monitor(monitor: &mut JournalMonitor) -> Result<(), JournalFailure> {
    monitor.await
}

async fn wait_for_journal_capacity<V: Variant, D: Digest>(
    journal: &JournalClient<V, D>,
    enabled: bool,
) -> Result<(), JournalFailure> {
    if !enabled {
        return pending_forever().await;
    }
    journal.wait_for_capacity().await
}

async fn wait_for_prune(pending: Option<&mut PendingPrune>) -> Result<(), JournalFailure> {
    let Some(pending) = pending else {
        return pending_forever().await;
    };
    (&mut pending.response)
        .instrument(pending.span.clone())
        .await
}

async fn receive_query<D: Digest>(
    queries: &mut mailbox::UnreliableReceiver<Query<D>>,
    enabled: bool,
) -> Query<D> {
    if !enabled {
        return pending_forever().await;
    }
    match queries.recv().await {
        Some(query) => query,
        None => pending_forever().await,
    }
}

/// Waits until `deadline`, or forever when none is armed.
async fn wait_until<E: Clock>(context: &E, deadline: Option<SystemTime>) {
    match deadline {
        Some(at) => context.sleep_until(at).await,
        None => pending_forever::<()>().await,
    }
}

const fn max_unsynced_journal_bytes<H: Hasher, V: Variant>(
    profile: &Profile<H, V>,
) -> NonZeroUsize {
    NonZeroUsize::new(
        profile
            .resources()
            .max_artifact_bytes()
            .saturating_mul(super::journal::MAX_UNSYNCED),
    )
    .expect("artifact bounds reserve non-zero journal bytes")
}

/// The serial machine driver and effect executor for one fixed epoch.
pub struct Actor<E, H, P, V, A, R, F, T>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
{
    context: ContextCell<E>,
    config: PendingConfig<E, H, P, V, A, R, F, T>,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Query<H::Digest>>,

    metrics: ActorMetrics,
    #[cfg(test)]
    journal_gates: super::journal::TestGates,
    #[cfg(test)]
    test_hooks: TestHooks<V, H::Digest>,
}

impl<E, H, P, V, A, R, F, T> Actor<E, H, P, V, A, R, F, T>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
{
    /// Creates the voter and its control mailbox.
    pub fn new(
        context: E,
        config: Config<E, H, P, V, A, R, F, T>,
    ) -> (Self, Mailbox<V, H::Digest>) {
        let chain_count = match &config.startup {
            Startup::Fresh { core, .. } => core.profile().protocol().codec_config().chains(),
            Startup::Recovered(recovered) => {
                recovered.core.profile().protocol().codec_config().chains()
            }
        };
        let metrics = ActorMetrics::new(&context, chain_count);
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let (query_sender, query_receiver) =
            mailbox::new_unreliable(context.child("queries"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                config: Some(config),
                mailbox: receiver,
                queries: query_receiver,
                metrics,
                #[cfg(test)]
                journal_gates: super::journal::TestGates::default(),
                #[cfg(test)]
                test_hooks: TestHooks::default(),
            },
            Mailbox {
                control: sender,
                queries: query_sender,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn new_with_test_hooks(
        context: E,
        config: Config<E, H, P, V, A, R, F, T>,
        journal_gates: super::journal::TestGates,
        test_hooks: TestHooks<V, H::Digest>,
    ) -> (Self, Mailbox<V, H::Digest>) {
        let (mut actor, mailbox) = Self::new(context, config);
        actor.journal_gates = journal_gates;
        actor.test_hooks = test_hooks;
        (actor, mailbox)
    }

    /// Starts the voter over its peers' already-registered fixed-epoch planes.
    ///
    /// `ready` resolves after the startup or recovery durability barrier is acknowledged and one
    /// initial producer wake has been submitted. Ingress queued by the surrounding actors cannot
    /// enter Core until that point.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        mut self,
        ready: oneshot::Sender<()>,
        batcher: mailbox::Sender<batcher::Message<P, V, H::Digest>>,
        observations: mailbox::UnreliableReceiver<Observed<P, V, H::Digest>>,
        completions: mailbox::Receiver<Completed<H::Digest>>,
        resolver: mailbox::Sender<resolver::Message<V, H::Digest>>,
        data: impl Sender<PublicKey = P>,
        consensus: impl Sender<PublicKey = P>,
        certificates: impl Sender<PublicKey = P>,
    ) -> Handle<()> {
        let context = self.context.take();
        context.dedicated().spawn(move |context| {
            self.context.restore(context);
            self.run(
                ready,
                batcher,
                observations,
                completions,
                resolver,
                data,
                consensus,
                certificates,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        mut self,
        ready: oneshot::Sender<()>,
        batcher: mailbox::Sender<batcher::Message<P, V, H::Digest>>,
        mut observations: mailbox::UnreliableReceiver<Observed<P, V, H::Digest>>,
        mut completions: mailbox::Receiver<Completed<H::Digest>>,
        resolver: mailbox::Sender<resolver::Message<V, H::Digest>>,
        data: impl Sender<PublicKey = P>,
        consensus: impl Sender<PublicKey = P>,
        certificates: impl Sender<PublicKey = P>,
    ) {
        let config = self.config.take().expect("voter starts once");
        let (machine, storage_journal, recovered, events_since_checkpoint) = match config.startup {
            Startup::Fresh { core, journal } => (*core, *journal, false, 0),
            Startup::Recovered(recovered) => {
                let recovered = *recovered;
                (
                    recovered.core,
                    recovered.journal,
                    true,
                    recovered.events_since_checkpoint,
                )
            }
        };
        let profile = machine.profile();
        let protocol = profile.protocol();
        let epoch = protocol.epoch();
        let leaders = protocol.leaders().clone();
        let participant = match profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        let initial_view = machine.inspection().view();
        let crypto_task_limit = profile
            .resources()
            .max_cached_artifacts()
            .saturating_add(profile.resources().max_outbox_effects())
            .max(3);
        let journal_capacity = NonZeroUsize::new(profile.resources().max_outbox_effects())
            .expect("validated resources reserve journal commands");
        let max_unsynced_bytes = max_unsynced_journal_bytes(profile);
        let round_span = round_span(epoch, initial_view);
        let view_started_at = if recovered {
            BTreeMap::new()
        } else {
            [(initial_view, self.context.current())]
                .into_iter()
                .collect()
        };
        let verification_queue_limit = profile.resources().max_inflight_verifications();
        let driver_context = self.context.child("driver");
        #[cfg(not(test))]
        let (journal, journal_monitor) = super::journal::spawn(
            driver_context.child("journal"),
            storage_journal,
            journal_capacity,
            max_unsynced_bytes,
            config.limits.retry_initial,
        );
        #[cfg(test)]
        let (journal, journal_monitor) = super::journal::spawn_with_gates(
            driver_context.child("journal"),
            storage_journal,
            journal_capacity,
            max_unsynced_bytes,
            config.limits.retry_initial,
            self.journal_gates.clone(),
        );

        let mut driver = Driver {
            context: driver_context,
            protocol_epoch: epoch,
            leaders,
            participant,
            scheme: Arc::new(config.scheme),
            strategy: config.strategy,
            automaton: config.automaton,
            relay: config.relay,
            reporter: config.reporter,
            machine,
            journal,
            journal_monitor,
            journal_responses: VecDeque::new(),
            pending_checkpoint: None,
            pending_prune: None,
            checkpoints: Some(config.checkpoints),
            egress: Egress::new(epoch, config.limits),
            limits: config.limits,
            batcher,
            resolver,
            data,
            consensus,
            certificates,
            observation_sources: BTreeMap::new(),
            input_spans: BTreeMap::new(),
            verification_sources: BTreeMap::new(),
            jobs: Pool::default(),
            crypto: Pool::default(),
            verification_tasks: BTreeMap::new(),
            pending_verifications: VecDeque::new(),
            verification_queue_limit,
            pending_applications: Vec::with_capacity(
                config.limits.inflight_application.get().saturating_add(1),
            ),
            pending_signs: Vec::with_capacity(crypto_task_limit),
            pending_publication: None,
            pending_inspection: None,
            active_validations: BTreeMap::new(),
            view_timer: None,
            production_timer: None,
            heartbeat_at: self
                .context
                .current()
                .saturating_add_ext(config.limits.heartbeat),
            events_since_checkpoint,
            round_view: initial_view,
            round_span,
            view_started_at,
            last_producer_progress: None,
            producer_blocked_since: None,
            producer_stall_reported: false,
            metrics: self.metrics.clone(),
            #[cfg(test)]
            test_hooks: self.test_hooks.clone(),
        };

        // Gated startup: storage waits run on the journal owner. This authority continues private
        // machine work, then awaits only the exact typed acknowledgement before going live.
        let view = driver.update_progress_gauges();
        driver.update_chain_gauges();
        driver.refresh_round_span(view);
        let startup_started_at = driver.context.current();
        let span = driver.round_span.clone();
        let started = span.in_scope(|| {
            if recovered {
                driver.finish_recovery()
            } else {
                driver.start_fresh()
            }
        });
        if let Err(fatal) = started {
            self.metrics.fatal.inc();
            error!(?fatal, "voter startup failed");
            return;
        }
        loop {
            let can_drive = driver.journal.has_capacity();
            if can_drive {
                let span = driver.round_span.clone();
                if let Err(fatal) = driver.drive_core_cycle().instrument(span).await {
                    self.failed(&fatal);
                    return;
                }
                if driver.machine.has_runnable_work() {
                    continue;
                }
            }
            let Some(pending) = driver.journal_responses.front_mut() else {
                break;
            };
            let durable = match (&mut pending.response).await {
                Ok(durable) => durable,
                Err(failure) => {
                    let fatal = Fatal::JournalDriver(failure);
                    self.failed(&fatal);
                    return;
                }
            };
            let pending = driver
                .journal_responses
                .pop_front()
                .expect("the completed journal response remains queued");
            if let Err(fatal) = driver.persistence_completed(durable, pending.publication) {
                self.failed(&fatal);
                return;
            }
        }
        driver
            .metrics
            .startup_drain_latency
            .observe_between(startup_started_at, driver.context.current());
        if let Err(fatal) = driver.seed_resolver() {
            self.failed(&fatal);
            return;
        }
        let span = driver.round_span.clone();
        if let Err(fatal) = span.in_scope(|| driver.submit_producer_wake()) {
            self.metrics.fatal.inc();
            error!(?fatal, "initial producer wake failed");
            return;
        }
        info!(epoch = epoch.get(), "voter is live");
        let _ = ready.send(());

        let mut readiness = ReadinessCursor::default();
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping voter");
            },
            event = driver.next_runtime_event(
                &mut readiness,
                &mut completions,
                &mut self.mailbox,
                &mut observations,
                &mut self.queries,
            ) => {
                if let Some(event) = event {
                    match driver.handle_runtime_burst(
                        event,
                        &mut readiness,
                        &mut completions,
                        &mut self.mailbox,
                        &mut observations,
                        &mut self.queries,
                    ) {
                        Ok(RuntimeDisposition::Continue) => {}
                        Ok(RuntimeDisposition::Stop) => break,
                        Err(fatal) => {
                            self.failed(&fatal);
                            break;
                        }
                    }
                }
                let span = driver.round_span.clone();
                if let Err(fatal) = driver.drive_core_cycle().instrument(span).await {
                    self.failed(&fatal);
                    break;
                }
            },
        }
        driver.shutdown_tasks();
    }

    /// Records one fatal failure before the voter stops.
    fn failed(&self, fatal: &Fatal) {
        self.metrics.fatal.inc();
        error!(?fatal, "voter failed");
    }
}

/// Returns the stable operation label for one signing request.
const fn sign_request_kind<V: Variant, D: Digest>(request: &SignRequest<V, D>) -> &'static str {
    match request {
        SignRequest::TransactionBlock(_) => "transaction_block",
        SignRequest::DaVote(_) => "da_vote",
        SignRequest::LeaderBlock(_) => "leader_block",
        SignRequest::Vote(_) => "vote",
        SignRequest::NoVote { .. } => "no_vote",
        SignRequest::Nullify { .. } => "nullify",
    }
}

fn application_completion_key<H: Hasher, V: Variant>(
    request: &SignRequest<V, H::Digest>,
) -> Option<AppCompletionKey<H::Digest>> {
    match request {
        SignRequest::TransactionBlock(header) => Some(AppCompletionKey::Propose {
            chain: header.chain().get(),
            parent: header.parent(),
            commitment: header.commitment(),
        }),
        SignRequest::DaVote(request) => {
            Some(AppCompletionKey::Verify(request.header().digest::<H>()))
        }
        _ => None,
    }
}

/// Signs one exact machine-authorized subject with the local key material.
fn sign_request<P: PublicKey, V: Variant, D: Digest>(
    scheme: &Scheme<P, V>,
    request: &SignRequest<V, D>,
) -> Result<Artifact<V, D>, SchemeError> {
    let artifact = match request {
        SignRequest::TransactionBlock(header) => {
            Artifact::TransactionBlock(scheme.sign_transaction_block(header.clone())?)
        }
        SignRequest::DaVote(request) => {
            Artifact::DaVote(scheme.sign_da_vote(request.header().clone())?)
        }
        SignRequest::LeaderBlock(request) => {
            Artifact::LeaderBlock(scheme.sign_leader_block(request.block().clone())?)
        }
        SignRequest::Vote(request) => Artifact::Vote(scheme.sign_vote(request.body().clone())?),
        SignRequest::NoVote { round, .. } => Artifact::NoVote(scheme.sign_novote(*round)?),
        SignRequest::Nullify { round, .. } => Artifact::Nullify(scheme.sign_nullify(*round)?),
    };
    Ok(artifact)
}

/// Creates one view's root span.
pub(super) fn round_span(epoch: Epoch, view: View) -> Span {
    info_span!(
        parent: None,
        "multimmit.voter.round",
        epoch = epoch.get().traced(),
        view = view.get().traced()
    )
}

/// Creates the one child span for a consumed view timer.
pub(super) fn round_timeout_span(parent: &Span, round: Round) -> Span {
    info_span!(
        parent: parent,
        "multimmit.voter.round.timeout",
        epoch = round.epoch().get().traced(),
        view = round.view().get().traced()
    )
}

/// Rotation among runtime sources that are simultaneously ready.
#[derive(Default)]
struct ReadinessCursor {
    source: usize,
    completion_cursor: usize,
    timer_cursor: usize,
}

impl ReadinessCursor {
    const SOURCES: usize = 8;

    const fn advance(&mut self, source: usize) {
        self.source = (source + 1) % Self::SOURCES;
    }
}

/// All state owned by one running voter.
struct Driver<E, H, P, V, A, R, F, T, S1, S2, S3>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    S1: Sender<PublicKey = P>,
    S2: Sender<PublicKey = P>,
    S3: Sender<PublicKey = P>,
{
    context: E,
    protocol_epoch: Epoch,
    leaders: LeaderSchedule,
    participant: Option<Participant>,
    scheme: Arc<Scheme<P, V>>,
    strategy: T,
    automaton: A,
    relay: R,
    reporter: F,
    machine: CoreState<H, V>,
    journal: JournalClient<V, H::Digest>,
    journal_monitor: JournalMonitor,
    journal_responses: VecDeque<PendingJournal<V, H::Digest>>,
    pending_checkpoint: Option<PendingCheckpoint<E, V, H::Digest>>,
    pending_prune: Option<PendingPrune>,
    checkpoints: Option<CheckpointStore<E, V, H::Digest>>,
    egress: Egress<P, H::Digest>,
    limits: VoterLimits,
    batcher: mailbox::Sender<batcher::Message<P, V, H::Digest>>,
    resolver: mailbox::Sender<resolver::Message<V, H::Digest>>,
    data: S1,
    consensus: S2,
    certificates: S3,
    /// Network sources bound to the exact core input ticket that classified them.
    observation_sources: BTreeMap<InputTicket, ObservationSources<P>>,
    /// Ingress context retained until the exact core ticket is fully consumed.
    input_spans: BTreeMap<InputTicket, InputContext<H::Digest>>,
    /// Authenticated network sources keyed by Core's stable pre-verification observation identity.
    verification_sources: BTreeMap<Observation, P>,
    jobs: Pool<AppResult<V, H::Digest>>,
    crypto: Pool<CryptoResult<V, H::Digest>>,
    /// Bulk-verification jobs retain their affine permits until the batcher returns them.
    verification_tasks: BTreeMap<JobId, TaskPermit>,
    pending_verifications: VecDeque<PendingVerification<P, V, H::Digest>>,
    verification_queue_limit: usize,
    /// Bounded volatile timing for completed local signs awaiting their exact journal event.
    pending_signs: Vec<TimedSign>,
    /// Application completions awaiting an exact sign reservation in the immediate machine drain.
    pending_applications: Vec<(AppCompletionKey<H::Digest>, AppCompletionTiming)>,
    /// Timing attached only while the exact persisted input releases its publication.
    pending_publication: Option<TimedPublication>,
    /// One best-effort query that may lose to one already-ready runtime event.
    pending_inspection: Option<(Query<H::Digest>, bool)>,
    /// Runtime cancellation signals keyed by Core's exact validation identity.
    active_validations: BTreeMap<ValidationId, Option<oneshot::Sender<()>>>,
    view_timer: Option<(Timer, SystemTime)>,
    production_timer: Option<(ProductionTimer<H::Digest>, SystemTime, Span)>,
    /// When periodic metrics and producer-stall checks next run.
    ///
    /// This is an absolute deadline rather than a relative sleep because every other arm of the
    /// select loop rebuilds its future on each iteration.
    heartbeat_at: SystemTime,
    events_since_checkpoint: u64,
    round_view: View,
    round_span: Span,
    view_started_at: BTreeMap<View, SystemTime>,
    last_producer_progress: Option<ProducerProgress>,
    producer_blocked_since: Option<SystemTime>,
    producer_stall_reported: bool,
    metrics: ActorMetrics,
    #[cfg(test)]
    test_hooks: TestHooks<V, H::Digest>,
}

impl<E, H, P, V, A, R, F, T, S1, S2, S3> Driver<E, H, P, V, A, R, F, T, S1, S2, S3>
where
    E: Clock + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    S1: Sender<PublicKey = P>,
    S2: Sender<PublicKey = P>,
    S3: Sender<PublicKey = P>,
{
    /// Selects one ready runtime source without owning protocol service policy.
    async fn next_runtime_event(
        &mut self,
        readiness: &mut ReadinessCursor,
        completions: &mut mailbox::Receiver<Completed<H::Digest>>,
        mailbox: &mut mailbox::Receiver<Message<V, H::Digest>>,
        observations: &mut mailbox::UnreliableReceiver<Observed<P, V, H::Digest>>,
        queries: &mut mailbox::UnreliableReceiver<Query<H::Digest>>,
    ) -> Option<RuntimeEvent<P, V, H::Digest>> {
        if let Some((_, deferred)) = self.pending_inspection.as_ref() {
            if *deferred
                && let Some(event) = self.try_ready_event(
                    readiness,
                    completions,
                    mailbox,
                    observations,
                    queries,
                    None,
                )
            {
                self.pending_inspection
                    .as_mut()
                    .expect("the deferred inspection remains pending")
                    .1 = false;
                return Some(event);
            }
            let (query, _) = self
                .pending_inspection
                .take()
                .expect("the accepted inspection remains pending");
            self.answer_inspection(query);
            return None;
        }
        if let Some(event) =
            self.try_ready_event(readiness, completions, mailbox, observations, queries, None)
        {
            return Some(event);
        }
        if self.machine.has_runnable_work() && self.journal.has_capacity() {
            return None;
        }

        let admit_authority = !self.checkpoint_fenced();
        let admit_local = self.can_admit(Lane::LocalCompletion);
        let admit_persistence =
            self.can_admit(Lane::PersistenceCompletion) && !self.journal_responses.is_empty();
        let admit_timer = admit_authority && self.can_admit(Lane::Timer);
        let admit_resolver = admit_authority && self.can_admit(Lane::ResolverResult);
        let admit_peer = admit_authority && self.can_admit(Lane::PeerObservation);
        let journal_idle = self.journal_responses.is_empty();
        let receive_inspection =
            !self.machine.has_runnable_work() && self.pending_inspection.is_none();
        let (source, event) = select! {
            result = next_journal_response(
                admit_persistence,
                &mut self.journal_responses,
            ) => (0, RuntimeEvent::Persistence(result)),
            result = wait_for_journal_monitor(&mut self.journal_monitor) => {
                (ReadinessCursor::SOURCES, RuntimeEvent::JournalMonitor(result))
            },
            result = wait_for_journal_capacity(
                &self.journal,
                !self.journal.has_capacity(),
            ) => (ReadinessCursor::SOURCES, RuntimeEvent::JournalCapacity(result)),
            result = wait_for_checkpoint(
                self.pending_checkpoint.as_mut(),
                journal_idle,
            ) => (ReadinessCursor::SOURCES, RuntimeEvent::Checkpoint(result)),
            result = wait_for_prune(self.pending_prune.as_mut()) => {
                (ReadinessCursor::SOURCES, RuntimeEvent::Prune(result))
            },
            result = async {
                if !admit_local {
                    return pending_forever().await;
                }
                self.jobs.next_completed().await
            } => (1, RuntimeEvent::Application(result)),
            result = async {
                if !admit_local {
                    return pending_forever().await;
                }
                self.crypto.next_completed().await
            } => (1, RuntimeEvent::Crypto(result)),
            () = wait_until(
                &self.context,
                admit_timer
                    .then(|| self.view_timer.as_ref().map(|(_, at)| *at))
                    .flatten(),
            ) => (2, RuntimeEvent::ViewTimer),
            () = wait_until(
                &self.context,
                admit_timer
                    .then(|| self.production_timer.as_ref().map(|(_, at, _)| *at))
                    .flatten(),
            ) => (2, RuntimeEvent::ProductionTimer),
            () = wait_until(&self.context, self.egress.next_attempt()) => {
                (5, RuntimeEvent::Publication)
            },
            () = wait_until(&self.context, Some(self.heartbeat_at)) => {
                (6, RuntimeEvent::Heartbeat)
            },
            completed = async {
                if !admit_local {
                    return pending_forever().await;
                }
                completions.recv().await
            } => (1, completed.map_or(RuntimeEvent::InputClosed, RuntimeEvent::Verification)),
            message = async {
                if !admit_resolver {
                    return pending_forever().await;
                }
                mailbox.recv().await
            } => (3, message.map_or(RuntimeEvent::InputClosed, RuntimeEvent::Resolution)),
            query = receive_query(queries, receive_inspection) => {
                (7, RuntimeEvent::Inspection(query))
            },
            observed = async {
                if !admit_peer {
                    return pending_forever().await;
                }
                observations.recv().await
            } => (4, observed.map_or(RuntimeEvent::InputClosed, RuntimeEvent::Observation)),
        };
        match &event {
            RuntimeEvent::Verification(_) => readiness.completion_cursor = 1,
            RuntimeEvent::Application(_) => readiness.completion_cursor = 2,
            RuntimeEvent::Crypto(_) => readiness.completion_cursor = 0,
            RuntimeEvent::ViewTimer => readiness.timer_cursor = 1,
            RuntimeEvent::ProductionTimer => readiness.timer_cursor = 0,
            _ => {}
        }
        if source < ReadinessCursor::SOURCES {
            readiness.advance(source);
        }
        Some(event)
    }

    fn try_ready_event(
        &mut self,
        readiness: &mut ReadinessCursor,
        completions: &mut mailbox::Receiver<Completed<H::Digest>>,
        mailbox: &mut mailbox::Receiver<Message<V, H::Digest>>,
        observations: &mut mailbox::UnreliableReceiver<Observed<P, V, H::Digest>>,
        queries: &mut mailbox::UnreliableReceiver<Query<H::Digest>>,
        excluded_lane: Option<Lane>,
    ) -> Option<RuntimeEvent<P, V, H::Digest>> {
        if let Some(result) = wait_for_journal_monitor(&mut self.journal_monitor).now_or_never() {
            return Some(RuntimeEvent::JournalMonitor(result));
        }
        if !self.journal.has_capacity()
            && let Some(result) = self.journal.wait_for_capacity().now_or_never()
        {
            return Some(RuntimeEvent::JournalCapacity(result));
        }
        if let Some(result) = wait_for_checkpoint(
            self.pending_checkpoint.as_mut(),
            self.journal_responses.is_empty(),
        )
        .now_or_never()
        {
            return Some(RuntimeEvent::Checkpoint(result));
        }
        if let Some(result) = wait_for_prune(self.pending_prune.as_mut()).now_or_never() {
            return Some(RuntimeEvent::Prune(result));
        }

        for offset in 0..ReadinessCursor::SOURCES {
            let source = (readiness.source + offset) % ReadinessCursor::SOURCES;
            let event = match source {
                0 if excluded_lane != Some(Lane::PersistenceCompletion)
                    && self.can_admit(Lane::PersistenceCompletion) =>
                {
                    let ready = self
                        .journal_responses
                        .front_mut()
                        .and_then(|pending| (&mut pending.response).now_or_never());
                    match ready {
                        Some(Ok(durable)) => {
                            let pending = self
                                .journal_responses
                                .pop_front()
                                .expect("the completed journal response remains queued");
                            Some(RuntimeEvent::Persistence(Ok(TimedDurable {
                                durable,
                                publication: pending.publication,
                            })))
                        }
                        Some(Err(failure)) => {
                            self.journal_responses.pop_front();
                            Some(RuntimeEvent::Persistence(Err(failure)))
                        }
                        None => None,
                    }
                }
                1 if excluded_lane != Some(Lane::LocalCompletion)
                    && self.can_admit(Lane::LocalCompletion) =>
                {
                    let mut completion = None;
                    for inner in 0..3 {
                        let source = (readiness.completion_cursor + inner) % 3;
                        completion = match source {
                            0 => completions.try_recv().ok().map(RuntimeEvent::Verification),
                            1 => self
                                .jobs
                                .next_completed()
                                .now_or_never()
                                .map(RuntimeEvent::Application),
                            _ => self
                                .crypto
                                .next_completed()
                                .now_or_never()
                                .map(RuntimeEvent::Crypto),
                        };
                        if completion.is_some() {
                            readiness.completion_cursor = (source + 1) % 3;
                            break;
                        }
                    }
                    completion
                }
                2 if excluded_lane != Some(Lane::Timer)
                    && !self.checkpoint_fenced()
                    && self.can_admit(Lane::Timer) =>
                {
                    let now = self.context.current();
                    let mut timer = None;
                    for inner in 0..2 {
                        let source = (readiness.timer_cursor + inner) % 2;
                        timer = match source {
                            0 if self.view_timer.as_ref().is_some_and(|(_, at)| *at <= now) => {
                                Some(RuntimeEvent::ViewTimer)
                            }
                            1 if self
                                .production_timer
                                .as_ref()
                                .is_some_and(|(_, at, _)| *at <= now) =>
                            {
                                Some(RuntimeEvent::ProductionTimer)
                            }
                            _ => None,
                        };
                        if timer.is_some() {
                            readiness.timer_cursor = (source + 1) % 2;
                            break;
                        }
                    }
                    timer
                }
                3 if excluded_lane != Some(Lane::ResolverResult)
                    && !self.checkpoint_fenced()
                    && self.can_admit(Lane::ResolverResult) =>
                {
                    mailbox.try_recv().ok().map(RuntimeEvent::Resolution)
                }
                4 if excluded_lane != Some(Lane::PeerObservation)
                    && !self.checkpoint_fenced()
                    && self.can_admit(Lane::PeerObservation) =>
                {
                    observations.try_recv().ok().map(RuntimeEvent::Observation)
                }
                5 if self
                    .egress
                    .next_attempt()
                    .is_some_and(|at| at <= self.context.current()) =>
                {
                    Some(RuntimeEvent::Publication)
                }
                6 if self.heartbeat_at <= self.context.current() => Some(RuntimeEvent::Heartbeat),
                7 if !self.machine.has_runnable_work() && self.pending_inspection.is_none() => {
                    queries.try_recv().ok().map(RuntimeEvent::Inspection)
                }
                _ => None,
            };
            if let Some(event) = event {
                readiness.advance(source);
                return Some(event);
            }
        }
        None
    }

    /// Applies one typed runtime event to the serial protocol owner.
    fn handle_runtime_event(
        &mut self,
        event: RuntimeEvent<P, V, H::Digest>,
    ) -> Result<RuntimeDisposition, Fatal> {
        match event {
            RuntimeEvent::Persistence(result) => match result {
                Ok(TimedDurable {
                    durable,
                    publication,
                }) => self.persistence_completed(durable, publication)?,
                Err(failure) => return Err(failure.into()),
            },
            RuntimeEvent::JournalMonitor(result) => {
                return Err(match result {
                    Ok(()) => Fatal::Closed,
                    Err(failure) => failure.into(),
                });
            }
            RuntimeEvent::JournalCapacity(result) => result?,
            RuntimeEvent::Checkpoint(result) => match result {
                Ok(false) => {}
                Ok(true) => {
                    let pending = self
                        .pending_checkpoint
                        .take()
                        .expect("a checkpoint completion requires a pending checkpoint");
                    let span = pending.span.clone();
                    if let Err(fatal) = self.checkpoint_completed(pending) {
                        self.record_fatal(&span, &fatal);
                        return Ok(RuntimeDisposition::Stop);
                    }
                }
                Err(fatal) => {
                    let span = self
                        .pending_checkpoint
                        .as_ref()
                        .expect("a checkpoint result requires a pending checkpoint")
                        .span
                        .clone();
                    self.record_fatal(&span, &fatal);
                    return Ok(RuntimeDisposition::Stop);
                }
            },
            RuntimeEvent::Prune(result) => {
                let pending = self
                    .pending_prune
                    .take()
                    .expect("a prune completion requires pending compaction");
                if let Err(failure) = result {
                    let fatal = failure.into();
                    self.record_fatal(&pending.span, &fatal);
                    return Ok(RuntimeDisposition::Stop);
                }
            }
            RuntimeEvent::Application((task, span, outcome)) => {
                if let Err(fatal) = self.application_outcome(task, &span, outcome) {
                    self.record_fatal(&span, &fatal);
                    return Ok(RuntimeDisposition::Stop);
                }
            }
            RuntimeEvent::Crypto((task, (span, outcome))) => {
                if let Err(fatal) = self.crypto_completed(task, &span, outcome) {
                    self.record_fatal(&span, &fatal);
                    return Ok(RuntimeDisposition::Stop);
                }
            }
            RuntimeEvent::ViewTimer => {
                let (timer, _) = self.view_timer.take().expect("armed timer fired");
                self.submit_view_timeout(timer)?;
            }
            RuntimeEvent::ProductionTimer => {
                let (timer, _, producer_span) =
                    self.production_timer.take().expect("armed timer fired");
                self.submit_production_timeout(timer, producer_span)?;
            }
            RuntimeEvent::Publication => self.publish_due()?,
            RuntimeEvent::Heartbeat => {
                self.heartbeat_at = self
                    .context
                    .current()
                    .saturating_add_ext(self.limits.heartbeat);
                self.update_chain_gauges();
                self.report_producer_stall();
            }
            RuntimeEvent::Verification(completed) => self.ingest_completed(completed)?,
            RuntimeEvent::Resolution(message) => self.ingest_message(message)?,
            RuntimeEvent::Inspection(query) => {
                debug_assert!(self.pending_inspection.is_none());
                self.pending_inspection = Some((query, true));
            }
            RuntimeEvent::Observation(observed) => self.ingest_observed(observed)?,
            RuntimeEvent::InputClosed => return Ok(RuntimeDisposition::Stop),
        }
        Ok(RuntimeDisposition::Continue)
    }

    /// Stages competing ready protocol lanes so Core remains the service-policy owner.
    fn handle_runtime_burst(
        &mut self,
        first: RuntimeEvent<P, V, H::Digest>,
        readiness: &mut ReadinessCursor,
        completions: &mut mailbox::Receiver<Completed<H::Digest>>,
        mailbox: &mut mailbox::Receiver<Message<V, H::Digest>>,
        observations: &mut mailbox::UnreliableReceiver<Observed<P, V, H::Digest>>,
        queries: &mut mailbox::UnreliableReceiver<Query<H::Digest>>,
    ) -> Result<RuntimeDisposition, Fatal> {
        let mut next = Some(first);
        let mut first_lane = None;
        let mut competing_lanes = false;
        while let Some(event) = next {
            let lane = event.core_lane();
            if self.handle_runtime_event(event)? == RuntimeDisposition::Stop {
                return Ok(RuntimeDisposition::Stop);
            }
            let Some(lane) = lane else {
                break;
            };
            let initial = *first_lane.get_or_insert(lane);
            competing_lanes |= lane != initial;
            if self.pending_inspection.is_none()
                && let Ok(query) = queries.try_recv()
            {
                readiness.advance(7);
                self.handle_runtime_event(RuntimeEvent::Inspection(query))?;
                break;
            }
            next = self.try_ready_event(
                readiness,
                completions,
                mailbox,
                observations,
                queries,
                (!competing_lanes).then_some(initial),
            );
        }
        Ok(RuntimeDisposition::Continue)
    }

    fn record_fatal(&self, span: &Span, fatal: &Fatal) {
        self.metrics.fatal.inc();
        span.in_scope(|| error!(?fatal, "voter failed"));
    }

    /// Drains one bounded Core service cycle, then gives attached runtime tasks one turn.
    async fn drive_core_cycle(&mut self) -> Result<(), Fatal> {
        let mut yielded = false;
        loop {
            if !self.journal.has_capacity() {
                break;
            }
            let action = self.machine.next_action(POLL_BUDGET)?;
            match action {
                CoreTurn::YieldRequired => {
                    reschedule().await;
                    yielded = true;
                    self.machine.resume_after_yield()?;
                    break;
                }
                CoreTurn::Input(serviced) => {
                    #[cfg(test)]
                    self.test_hooks
                        .record_service(serviced.cycle, serviced.lane);
                    if serviced.observed_items > 0 {
                        self.bind_observation_sources(
                            serviced.transition.status(),
                            serviced.ticket,
                            serviced.observed_items,
                            serviced.final_chunk,
                        )?;
                    }
                    let input_context = self
                        .input_spans
                        .get(&serviced.ticket)
                        .cloned()
                        .ok_or(CoreError::SchedulerInvariant)?;
                    let stale = matches!(serviced.transition.status(), StepStatus::StaleCompletion);
                    if !stale
                        && self.participant.is_some()
                        && let Some(application) = input_context.application
                    {
                        if self.pending_applications.len() == self.pending_applications.capacity() {
                            self.pending_applications.remove(0);
                        }
                        self.pending_applications.push(application);
                    }
                    if !stale
                        && let Some(sign) = input_context.sign
                        && self.pending_signs.len() < self.pending_signs.capacity()
                    {
                        self.pending_signs.push(sign);
                    }
                    self.pending_publication = input_context.publication;
                    input_context
                        .span
                        .in_scope(|| self.dispatch_transition(serviced.transition))?;
                    if serviced.final_chunk {
                        self.input_spans
                            .remove(&serviced.ticket)
                            .ok_or(CoreError::SchedulerInvariant)?;
                    }
                    self.maybe_checkpoint().await?;
                }
                CoreTurn::Work(work) => {
                    if !self.dispatch_work(work).await? {
                        break;
                    }
                }
                CoreTurn::Idle => {
                    self.maybe_checkpoint().await?;
                    break;
                }
            }
        }
        if !yielded {
            reschedule().await;
        }
        Ok(())
    }

    async fn dispatch_work(&mut self, work: CoreWork<V, H::Digest>) -> Result<bool, Fatal> {
        let made_progress = work.work_remaining() || !work.capabilities().is_empty();
        let (capabilities, activities) = work.into_parts();
        for activity in activities {
            let _ = self.reporter.report(activity);
        }
        self.execute_capabilities(capabilities)?;
        self.pending_publication = None;
        self.update_retention_gauges();
        let view = self.update_progress_gauges();
        self.refresh_round_span(view);
        self.maybe_checkpoint().await?;
        Ok(made_progress)
    }

    const fn core(&self) -> &CoreState<H, V> {
        &self.machine
    }

    const fn core_mut(&mut self) -> &mut CoreState<H, V> {
        &mut self.machine
    }

    /// Records runtime metadata for one transition already admitted by Core.
    fn track_transition(
        &mut self,
        transition: impl FnOnce(&mut CoreState<H, V>) -> Result<InputTicket, CoreError>,
    ) -> Result<InputTicket, Fatal> {
        let ticket = transition(self.core_mut())?;
        if self
            .input_spans
            .insert(
                ticket,
                InputContext {
                    span: Span::current(),
                    application: None,
                    sign: None,
                    publication: None,
                },
            )
            .is_some()
        {
            return Err(CoreError::SchedulerInvariant.into());
        }
        Ok(ticket)
    }

    fn start_fresh(&mut self) -> Result<(), Fatal> {
        self.track_transition(CoreState::start_fresh)?;
        Ok(())
    }

    fn finish_recovery(&mut self) -> Result<(), Fatal> {
        self.track_transition(CoreState::finish_recovery)?;
        Ok(())
    }

    fn submit_producer_wake(&mut self) -> Result<(), Fatal> {
        self.track_transition(CoreState::producer_wake)?;
        Ok(())
    }

    fn submit_view_timeout(&mut self, timer: Timer) -> Result<(), Fatal> {
        let round = timer.round();
        let view = round.view();
        debug!(view = view.get(), "view timer fired");
        self.metrics.view_timeouts.inc();
        let span = round_timeout_span(&self.round_span, round);
        span.in_scope(|| {
            self.track_transition(|core| core.leader_timer_fired(timer))?;
            Ok(())
        })
    }

    fn submit_production_timeout(
        &mut self,
        timer: ProductionTimer<H::Digest>,
        producer_span: Span,
    ) -> Result<(), Fatal> {
        self.metrics.production_stalls.inc();
        let parent = timer.parent();
        let span = info_span!(
            parent: &producer_span,
            "multimmit.voter.production.timeout",
            epoch = self.protocol_epoch.get().traced(),
            chain = parent.chain().get().traced(),
            height = parent.height().get().traced()
        );
        span.in_scope(|| {
            self.track_transition(|core| core.producer_timer_fired(timer))?;
            Ok(())
        })
    }

    fn track_signing(&mut self, ticket: InputTicket, sign: TimedSign) -> Result<(), Fatal> {
        self.input_spans
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .sign = Some(sign);
        Ok(())
    }

    fn track_application(
        &mut self,
        ticket: InputTicket,
        application: Option<(AppCompletionKey<H::Digest>, AppCompletionTiming)>,
    ) -> Result<(), Fatal> {
        self.input_spans
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .application = application;
        Ok(())
    }

    const fn can_admit(&self, lane: Lane) -> bool {
        self.machine.can_admit(lane)
    }

    fn bind_observation_sources(
        &mut self,
        status: &StepStatus<H::Digest>,
        ticket: InputTicket,
        count: usize,
        final_chunk: bool,
    ) -> Result<(), Fatal> {
        let (scheduled, complete) = {
            let sources = self
                .observation_sources
                .get_mut(&ticket)
                .ok_or(StepError::CompletionMismatch)?;
            let start = sources
                .items
                .len()
                .checked_sub(count)
                .ok_or(StepError::CompletionMismatch)?;
            let scheduled = match status {
                StepStatus::Observed(results) => {
                    if results.len() != count {
                        return Err(StepError::CompletionMismatch.into());
                    }
                    let consumed = sources.items.drain(start..).rev();
                    results
                        .iter()
                        .copied()
                        .zip(consumed)
                        .filter_map(|(result, source)| {
                            (result.status() == ObservationStatus::Scheduled)
                                .then_some((result.observation(), source))
                        })
                        .collect::<Vec<_>>()
                }
                _ => {
                    sources.items.truncate(start);
                    Vec::new()
                }
            };
            (scheduled, sources.items.is_empty())
        };
        if final_chunk != complete {
            return Err(StepError::CompletionMismatch.into());
        }
        if final_chunk {
            self.observation_sources
                .remove(&ticket)
                .ok_or(StepError::CompletionMismatch)?;
        }
        for (observation, source) in scheduled {
            if self
                .verification_sources
                .insert(observation, source)
                .is_some()
            {
                return Err(CoreError::SchedulerInvariant.into());
            }
        }
        Ok(())
    }

    fn dispatch_transition(
        &mut self,
        transition: CoreTransition<V, H::Digest>,
    ) -> Result<(), Fatal> {
        let generation = self.machine.generation();
        if generation > self.core().task_generation() {
            self.jobs.cancel_all();
            self.crypto.cancel_all();
            self.verification_tasks.clear();
            self.pending_verifications.clear();
            self.pending_signs.clear();
            self.pending_applications.clear();
            self.pending_publication = None;
            reset_generation_runtime_correlations(
                &mut self.active_validations,
                &mut self.verification_sources,
            );
            self.view_timer = None;
            self.production_timer = None;
            self.core_mut().advance_task_generation(generation)?;
        }
        if matches!(transition.status(), StepStatus::StaleCompletion) {
            self.metrics.stale.inc();
        }
        let (capabilities, activities) = transition.into_parts();
        self.execute_capabilities(capabilities)?;
        self.update_retention_gauges();
        for activity in activities {
            let _ = self.reporter.report(activity);
        }
        let view = self.update_progress_gauges();
        self.refresh_round_span(view);
        Ok(())
    }

    fn update_progress_gauges(&mut self) -> View {
        let progress = self.machine.progress();
        let _ = self.metrics.current_view.try_set(progress.view.get());
        let _ = self
            .metrics
            .retired_view
            .try_set(progress.retired_view.get());
        let _ = self
            .metrics
            .finality_floor
            .try_set(progress.finality_floor.get());
        let _ = self
            .metrics
            .proposal_anchor_view
            .try_set(progress.proposal_anchor_view.get());
        let _ = self
            .metrics
            .produced_blocks
            .try_set(progress.produced_blocks);
        let (active_validations, pending_validations) = self.core().validation_counts();
        let _ = self
            .metrics
            .active_validations_gauge
            .try_set(active_validations);
        let _ = self
            .metrics
            .pending_validations_gauge
            .try_set(pending_validations);
        let _ = self
            .metrics
            .build_active_gauge
            .try_set(usize::from(self.core().local_build_active()));
        if let Some(producer) = progress.producer {
            let _ = self
                .metrics
                .producer_vote_shares
                .try_set(producer.vote_shares());
            let _ = self
                .metrics
                .producer_pipeline_blocked
                .try_set(usize::from(producer.pipeline_blocked()));
            let _ = self
                .metrics
                .producer_recovery_active
                .try_set(usize::from(producer.active_recovery()));
            self.observe_producer_progress(producer);
        }
        self.view_started_at
            .retain(|view, _| *view > progress.retired_view);
        progress.view
    }

    fn update_chain_gauges(&self) {
        let progress = self.machine.chain_progress();
        assert_eq!(self.metrics.chains.len(), progress.len());
        for (metrics, chain) in self.metrics.chains.iter().zip(&progress) {
            let _ = metrics.finalized.try_set(chain.finalized().get());
            let _ = metrics.certified.try_set(chain.certified().get());
            let _ = metrics.known.try_set(chain.known().get());
        }
    }

    fn observe_producer_progress(&mut self, progress: ProducerProgress) {
        if self.last_producer_progress == Some(progress) {
            return;
        }
        let previously_blocked = self
            .last_producer_progress
            .is_some_and(ProducerProgress::pipeline_blocked);
        let blocked = progress.pipeline_blocked();
        if blocked && !previously_blocked {
            self.producer_blocked_since = Some(self.context.current());
            self.producer_stall_reported = false;
        } else if !blocked && previously_blocked {
            if self.producer_stall_reported {
                info!(
                    chain = progress.chain().get(),
                    produced = progress.produced().get(),
                    certified = progress.certified().get(),
                    "local producer resumed after DA pipeline stall"
                );
            }
            self.producer_blocked_since = None;
            self.producer_stall_reported = false;
        }
        debug!(
            chain = progress.chain().get(),
            produced = progress.produced().get(),
            certified = progress.certified().get(),
            vote_shares = progress.vote_shares(),
            da_quorum = progress.da_quorum(),
            recovery_ready = progress.ready_recovery(),
            recovery_pending = progress.pending_recovery(),
            recovery_active = progress.active_recovery(),
            wake = progress.wake(),
            timer_armed = progress.timer_armed(),
            build_pending = progress.build_pending(),
            production_credit = progress.production_credit(),
            pipeline_blocked = blocked,
            "local producer DA state changed"
        );
        self.last_producer_progress = Some(progress);
    }

    fn report_producer_stall(&mut self) {
        if self.producer_stall_reported {
            return;
        }
        let Some(progress) = self
            .last_producer_progress
            .filter(|progress| progress.pipeline_blocked())
        else {
            return;
        };
        let Some(blocked_since) = self.producer_blocked_since else {
            return;
        };
        let blocked_for = self
            .context
            .current()
            .duration_since(blocked_since)
            .unwrap_or_default();
        if blocked_for < self.limits.heartbeat {
            return;
        }
        warn!(
            chain = progress.chain().get(),
            produced = progress.produced().get(),
            certified = progress.certified().get(),
            vote_shares = progress.vote_shares(),
            da_quorum = progress.da_quorum(),
            recovery_ready = progress.ready_recovery(),
            recovery_pending = progress.pending_recovery(),
            recovery_active = progress.active_recovery(),
            production_credit = progress.production_credit(),
            blocked_for_ms = blocked_for.as_millis(),
            "local producer stalled at DA pipeline limit"
        );
        self.producer_stall_reported = true;
    }

    fn refresh_round_span(&mut self, view: View) {
        if view == self.round_view {
            return;
        }
        // A view's latency is the wall time between entering and leaving it, measured at the
        // transition itself: durability acknowledgement lags application, so observing at the
        // barrier would measure the sync pipeline instead of the view.
        if let Some(started_at) = self.view_started_at.get(&self.round_view) {
            self.metrics
                .round_latency
                .observe_between(*started_at, self.context.current());
        }
        self.round_view = view;
        self.view_started_at.insert(view, self.context.current());
        self.round_span = round_span(self.protocol_epoch, view);
    }

    fn observe_leader_latency(&self, view: View, histogram: &Histogram) {
        if self.participant != Some(self.leaders.leader(view)) {
            return;
        }
        let Some(started_at) = self.view_started_at.get(&view) else {
            return;
        };
        histogram.observe_between(*started_at, self.context.current());
    }

    /// Exports the retention profile behind the durable floors.
    fn update_retention_gauges(&mut self) {
        let _ = self
            .metrics
            .retained_events
            .try_set(self.events_since_checkpoint as usize);

        let (retained_artifacts, nullification_suffix) = self.machine.retention_profile();
        let _ = self.metrics.retained_artifacts.try_set(retained_artifacts);
        let _ = self
            .metrics
            .nullification_suffix
            .try_set(nullification_suffix as usize);
        let _ = self
            .metrics
            .staged_batches
            .try_set(self.machine.staged_barriers());
    }

    /// Frames one exact artifact publication.
    fn frame(
        &self,
        artifact: &Arc<Artifact<V, H::Digest>>,
        recipient: Option<P>,
    ) -> Result<Transmission<P, H::Digest>, Fatal> {
        self.egress
            .frame(artifact, recipient)
            .ok_or(Fatal::Step(StepError::UnauthorizedEffect))
    }

    /// Installs one durable publication and attempts it immediately.
    fn install(
        &mut self,
        id: EffectId,
        generation: u64,
        transmissions: Vec<Transmission<P, H::Digest>>,
    ) {
        let now = self.context.current();
        let sign_ready_at = self
            .pending_publication
            .filter(|publication| publication.id == id)
            .map(|publication| publication.at);
        if sign_ready_at.is_some() {
            self.pending_publication = None;
        }
        let origin = debug_span!(
            parent: &Span::current(),
            "multimmit.voter.publish.install",
            epoch = self.protocol_epoch.get().traced(),
            view = self.round_view.get().traced(),
            id = id.get().traced(),
            generation = generation.traced(),
        );
        origin.in_scope(|| debug!("durable publication installed"));
        self.egress.install(
            id,
            generation,
            transmissions,
            sign_ready_at,
            now,
            PublicationOrigin {
                view: self.round_view,
            },
        );
        #[cfg(test)]
        self.test_hooks
            .record(TestEvent::Installed { id, generation });
        let _ = self.metrics.publications.try_set(self.egress.len());
    }

    /// Attempts every due publication and reports first local acceptance to the machine.
    /// Ingests one authenticated verification cohort from the batcher.
    fn ingest_completed(&mut self, completed: Completed<H::Digest>) -> Result<(), Fatal> {
        let Completed {
            span,
            round,
            completion,
        } = completed;
        if completion.generation() != self.core().task_generation() {
            self.metrics.stale.inc();
            return Ok(());
        }
        let Some(permit) = self.verification_tasks.remove(&completion.job()) else {
            self.metrics.stale.inc();
            return Ok(());
        };
        if !self.finish_task(permit, TaskTerminal::Completed)? {
            return Ok(());
        }
        self.schedule_pending_verifications()?;
        let verified = info_span!(
            parent: &span,
            "multimmit.voter.verify.complete",
            epoch = round.epoch().get().traced(),
            view = round.view().get().traced()
        );
        verified.in_scope(|| {
            self.track_transition(|core| core.verification_completed(completion))?;
            Ok(())
        })
    }

    /// Assigns authenticated network sources to the machine's exact observation sequence.
    fn observe_network(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<V, H::Digest>>,
        mut sources: Vec<P>,
    ) -> Result<(), Fatal> {
        if artifacts.len() != sources.len() {
            return Err(StepError::CompletionMismatch.into());
        }
        let resident_bytes = artifacts.iter().try_fold(0usize, |total, (id, artifact)| {
            total
                .checked_add(id.encode_size())?
                .checked_add(artifact.encode_size())
        });
        let resident_bytes = resident_bytes
            .and_then(|bytes| bytes.checked_add(size_of_val(sources.as_slice())))
            .ok_or(CoreError::CapacityOverflow)?;
        sources.reverse();
        let ticket = self.track_transition(|core| core.observe(artifacts, resident_bytes))?;
        if self
            .observation_sources
            .insert(ticket, ObservationSources { items: sources })
            .is_some()
        {
            return Err(CoreError::SchedulerInvariant.into());
        }
        Ok(())
    }

    /// Ingests one peer observation batch.
    fn ingest_observed(&mut self, observed: Observed<P, V, H::Digest>) -> Result<(), Fatal> {
        let Observed { span, artifacts } = observed;
        let (sources, artifacts) = artifacts.into_iter().unzip();
        let observe = info_span!(
            parent: &self.round_span,
            "multimmit.voter.observe",
            epoch = self.protocol_epoch.get().traced(),
            view = self.round_view.get().traced()
        );
        observe.follows_from(span.id());
        observe.in_scope(|| self.observe_network(artifacts, sources))?;
        if !self
            .batcher
            .enqueue(batcher::Message::ObservationConsumed)
            .accepted()
        {
            return Err(Fatal::Closed);
        }
        Ok(())
    }

    /// Ingests one mailbox request.
    fn ingest_message(&mut self, message: Message<V, H::Digest>) -> Result<(), Fatal> {
        match message {
            Message::Resolution {
                span,
                round,
                completion,
            } => {
                let resolved = info_span!(
                    parent: &span,
                    "multimmit.voter.resolve.complete",
                    epoch = round.epoch().get().traced(),
                    view = round.view().get().traced()
                );
                resolved.in_scope(|| {
                    self.track_transition(|core| core.leader_resolution_completed(completion))?;
                    Ok(())
                })
            }
        }
    }

    fn answer_inspection(&self, query: Query<H::Digest>) {
        let inspection = self.machine.inspection();
        match query {
            Query::Inspect { responder } => {
                let _ = responder.send(inspection);
            }
        }
    }

    fn publish_due(&mut self) -> Result<(), Fatal> {
        let now = self.context.current();
        let due = self.egress.due(now, PUBLICATION_BUDGET);
        for (id, generation, retries, delivered, transmissions, origin) in due {
            let attempt_number = retries.saturating_add(1);
            let attempt = if retries == 0 {
                info_span!(
                    parent: None,
                    "multimmit.voter.publish",
                    epoch = self.protocol_epoch.get().traced(),
                    view = origin.view.get().traced(),
                    id = id.get().traced(),
                    generation = generation.traced(),
                    attempt = attempt_number.traced(),
                    previously_delivered = delivered,
                    relay_ready = tracing::field::Empty,
                    sender_accepted = tracing::field::Empty,
                    first_accepted = tracing::field::Empty,
                )
            } else {
                debug_span!(
                    parent: None,
                    "multimmit.voter.publish.retry",
                    epoch = self.protocol_epoch.get().traced(),
                    view = origin.view.get().traced(),
                    id = id.get().traced(),
                    generation = generation.traced(),
                    attempt = attempt_number.traced(),
                    previously_delivered = delivered,
                    relay_ready = tracing::field::Empty,
                    sender_accepted = tracing::field::Empty,
                    first_accepted = tracing::field::Empty,
                )
            };
            let _guard = attempt.enter();
            let relay_ready = self.relay_ready(&transmissions);
            attempt.record("relay_ready", relay_ready);
            if !relay_ready {
                attempt.record("sender_accepted", false);
                attempt.record("first_accepted", false);
                continue;
            }
            let mut sender_accepted = false;
            for transmission in transmissions.iter() {
                sender_accepted |= self.transmit(transmission);
            }
            attempt.record("sender_accepted", sender_accepted);
            let (first, sign_ready_at) = if sender_accepted && !delivered {
                self.egress.accepted(id)
            } else {
                (false, None)
            };
            attempt.record("first_accepted", first);
            if first {
                if let Some(sign_ready_at) = sign_ready_at {
                    self.metrics
                        .sign_ready_to_wire_latency
                        .observe_between(sign_ready_at, self.context.current());
                }
                self.track_transition(|core| core.publication_delivered(id, generation))?;
            }
        }
        Ok(())
    }

    /// Relays every application payload required by one exact publication attempt.
    fn relay_ready(&mut self, transmissions: &[Transmission<P, H::Digest>]) -> bool {
        for transmission in transmissions {
            let Some(commitment) = transmission.relay else {
                continue;
            };
            if self.relay.broadcast(commitment, ()) == Feedback::Closed {
                return false;
            }
        }
        true
    }

    /// Sends one pre-encoded transmission; returns local acceptance.
    fn transmit(&mut self, transmission: &Transmission<P, H::Digest>) -> bool {
        let recipients = transmission
            .recipient
            .as_ref()
            .map_or(Recipients::All, |peer| Recipients::One(peer.clone()));
        let priority = transmission.plane != Plane::Data;
        let (sent, metric) = match transmission.plane {
            Plane::Data => (
                self.data
                    .send(recipients, transmission.bytes.clone(), priority),
                &Traffic::DATA,
            ),
            Plane::Consensus => (
                self.consensus
                    .send(recipients, transmission.bytes.clone(), priority),
                &Traffic::CONSENSUS,
            ),
            Plane::Certificate => (
                self.certificates
                    .send(recipients, transmission.bytes.clone(), priority),
                &Traffic::CERTIFICATE,
            ),
        };
        let recipients = sent.len() as u64;
        self.metrics
            .transmissions
            .get_or_create(metric)
            .inc_by(recipients);
        self.metrics
            .transmitted_bytes
            .get_or_create(metric)
            .inc_by(recipients * transmission.bytes.len() as u64);
        !sent.is_empty()
    }

    /// Makes one durably admitted checkpoint available to resolver peers.
    fn retain_served(
        &mut self,
        artifact: &Artifact<V, H::Digest>,
        #[cfg(test)] boundary: RetentionBoundary,
    ) -> Result<(), Fatal> {
        let proof = match artifact {
            Artifact::Nullification(certificate) => {
                Served::Nullification(Box::new(certificate.clone()))
            }
            Artifact::Vqc(certificate) => Served::Vqc(Box::new(certificate.clone())),
            Artifact::Lqc(certificate) => Served::Lqc(Box::new(certificate.clone())),
            _ => return Ok(()),
        };
        self.retain(
            proof,
            #[cfg(test)]
            boundary,
        )
    }

    fn seed_resolver(&mut self) -> Result<(), Fatal> {
        let (through, proofs) = self.machine.resolver_seed();
        if !self
            .resolver
            .enqueue(resolver::Message::Prune { through })
            .accepted()
        {
            return Err(Fatal::Closed);
        }
        for proof in proofs {
            self.retain(
                proof,
                #[cfg(test)]
                RetentionBoundary::Recovered,
            )?;
        }
        Ok(())
    }

    fn retain(
        &mut self,
        proof: Served<V, H::Digest>,
        #[cfg(test)] boundary: RetentionBoundary,
    ) -> Result<(), Fatal> {
        #[cfg(test)]
        let observed = proof.clone();
        if !self
            .resolver
            .enqueue(resolver::Message::Retain { proof })
            .accepted()
        {
            return Err(Fatal::Closed);
        }
        #[cfg(test)]
        self.test_hooks.record(TestEvent::Retained {
            object: observed,
            boundary,
        });
        Ok(())
    }

    /// Checkpoints an acknowledged snapshot and compacts the journal behind it.
    async fn maybe_checkpoint(&mut self) -> Result<(), Fatal> {
        // A snapshot is only valid at a quiescent staging pipeline: every staged batch is
        // acknowledged and nothing is emitted-but-unappended. Reaching the checkpoint cadence
        // closes authority-producing ingress until that finite prefix drains and the cut is made.
        if self.events_since_checkpoint < self.limits.checkpoint_interval.get()
            || !self.journal_responses.is_empty()
            || self.pending_checkpoint.is_some()
            || self.pending_prune.is_some()
            || self.machine.staged_barriers() != 0
        {
            return Ok(());
        }
        self.events_since_checkpoint = 0;
        let cut = self.machine.checkpoint_cut();
        let origin = CheckpointOrigin {
            epoch: self.protocol_epoch,
            view: self.round_view,
            cursor: cut.cursor(),
            retired_views: cut.retired_view(),
        };
        let checkpoint = info_span!(
            parent: &self.round_span,
            "multimmit.voter.checkpoint",
            epoch = origin.epoch.get().traced(),
            view = origin.view.get().traced(),
            cursor = origin.cursor.get().traced(),
            retired_views = origin.retired_views.get().traced(),
        );
        // Roll the journal to a fresh section: once the snapshot is durable, every prior
        // section is covered and prunable as a whole.
        let roll_span = origin.roll_span();
        roll_span.follows_from(checkpoint.id());
        let roll = match roll_span.in_scope(|| self.journal.try_roll()) {
            Ok(response) => response,
            Err(JournalAdmission::Full(())) => {
                return Err(CoreError::SchedulerInvariant.into());
            }
            Err(JournalAdmission::Closed(())) => return Err(Fatal::Closed),
        };
        drop(checkpoint);
        roll.instrument(roll_span).await?;
        let checkpoints = self.checkpoints.take().ok_or(Fatal::Closed)?;
        let store_span = origin.store_span();
        let pending_span = store_span.clone();
        let store = self
            .context
            .child("checkpoint")
            .shared(true)
            .spawn(move |_| {
                async move { checkpoints.store(cut.materialize()).await }.instrument(store_span)
            });
        self.pending_checkpoint = Some(PendingCheckpoint {
            store: CheckpointProgress::Writing(store),
            origin,
            span: pending_span,
        });
        Ok(())
    }

    const fn checkpoint_fenced(&self) -> bool {
        self.events_since_checkpoint >= self.limits.checkpoint_interval.get()
            || matches!(
                &self.pending_checkpoint,
                Some(PendingCheckpoint {
                    store: CheckpointProgress::Durable(_),
                    ..
                })
            )
    }

    /// Compacts behind a fully synced checkpoint.
    fn checkpoint_completed(
        &mut self,
        pending: PendingCheckpoint<E, V, H::Digest>,
    ) -> Result<(), Fatal> {
        let PendingCheckpoint {
            store,
            origin,
            span: _,
        } = pending;
        let CheckpointProgress::Durable(store) = store else {
            // The completion arm only fires after `wait_for_checkpoint` saw the write finish.
            return Err(Fatal::Closed);
        };
        self.checkpoints = Some(store);
        let prune_span = origin.prune_span();
        let response = match prune_span.in_scope(|| self.journal.try_prune()) {
            Ok(response) => response,
            Err(JournalAdmission::Full(())) => {
                return Err(CoreError::SchedulerInvariant.into());
            }
            Err(JournalAdmission::Closed(())) => return Err(Fatal::Closed),
        };
        self.pending_prune = Some(PendingPrune {
            response,
            span: prune_span,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        config::Limits,
        machine::{Role, Tuning},
        mocks::Committee,
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_traced;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic, tokio};
    use commonware_utils::sync::Condvar;
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::{Duration, Instant},
    };
    use tracing::{Id, Subscriber};
    use tracing_subscriber::{Layer, layer::Context, prelude::*, registry::LookupSpan};

    #[derive(Clone)]
    struct CloseLayer {
        round_closed: Arc<AtomicBool>,
    }

    impl<S> Layer<S> for CloseLayer
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_close(&self, id: Id, context: Context<'_, S>) {
            let Some(metadata) = context.metadata(&id) else {
                return;
            };
            if metadata.name() == "test.checkpoint_round" {
                self.round_closed.store(true, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn pending_checkpoint_does_not_retain_originating_round_span() {
        let round_closed = Arc::new(AtomicBool::new(false));
        let subscriber = tracing_subscriber::registry().with(CloseLayer {
            round_closed: Arc::clone(&round_closed),
        });

        tracing::subscriber::with_default(subscriber, || {
            deterministic::Runner::default().start(|context| async move {
                let round = tracing::info_span!(parent: None, "test.checkpoint_round");
                let checkpoint = info_span!(parent: &round, "multimmit.voter.checkpoint");
                let origin = CheckpointOrigin {
                    epoch: Epoch::new(7),
                    view: View::new(11),
                    cursor: Cursor::zero(),
                    retired_views: View::new(9),
                };
                let store_span = origin.store_span();
                store_span.follows_from(checkpoint.id());
                drop(checkpoint);
                let pending_span = store_span.clone();
                let store = context.child("pending_store").spawn(|_| {
                    pending_forever::<
                        Result<
                            CheckpointStore<deterministic::Context, MinPk, Sha256Digest>,
                            CheckpointError,
                        >,
                    >()
                    .instrument(store_span)
                });
                let mut pending = PendingCheckpoint {
                    store: CheckpointProgress::Writing(store),
                    origin,
                    span: pending_span,
                };

                drop(round);
                assert!(
                    round_closed.load(Ordering::Relaxed),
                    "pending checkpoint I/O must not own its originating round span"
                );

                let CheckpointProgress::Writing(store) = &mut pending.store else {
                    unreachable!("the checkpoint remains pending")
                };
                store.abort();
                let _ = store.await;
            });
        });
    }

    #[test]
    fn extreme_artifact_bound_saturates_journal_byte_budget() {
        let committee = Committee::<MinPk>::new(80, 6, Limits::new(2, 1).unwrap());
        let profile = Profile::<Sha256, MinPk>::new(
            committee.config,
            Role::Observer,
            Tuning {
                max_artifact_bytes: NonZeroUsize::new(usize::MAX).unwrap(),
                ..Tuning::default()
            },
        )
        .unwrap();

        assert_eq!(max_unsynced_journal_bytes(&profile).get(), usize::MAX);
    }

    #[derive(Default)]
    struct CryptoServiceProbe {
        state: Mutex<CryptoServiceState>,
        changed: Condvar,
    }

    #[derive(Default)]
    struct CryptoServiceState {
        crypto_started: bool,
        services_armed: bool,
        serviced: usize,
        crypto_released: bool,
    }

    impl CryptoServiceProbe {
        fn block_crypto(&self) {
            let mut state = self.state.lock();
            state.crypto_started = true;
            self.changed.notify_all();
            while !state.crypto_released {
                self.changed.wait(&mut state);
            }
        }

        fn arm_services(&self) {
            let mut state = self.state.lock();
            state.services_armed = true;
            self.changed.notify_all();
        }

        fn record_service(&self) {
            let mut state = self.state.lock();
            state.serviced += 1;
            self.changed.notify_all();
        }

        fn observe_then_release(&self, expected: usize) -> bool {
            let mut state = self.state.lock();
            while !state.crypto_started || !state.services_armed {
                self.changed.wait(&mut state);
            }

            let deadline = Instant::now() + Duration::from_secs(2);
            while state.serviced < expected {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if self.changed.wait_for(&mut state, remaining).timed_out() {
                    break;
                }
            }

            let serviced = state.serviced == expected;
            state.crypto_released = true;
            self.changed.notify_all();
            serviced
        }
    }

    #[test_traced]
    fn crypto_strategy_keeps_async_executor_serviceable() {
        const EXPECTED_SERVICES: usize = 4;

        let runner = tokio::Runner::new(tokio::Config::default().with_worker_threads(1));
        let serviced = runner.start(|context| async move {
            let probe = Arc::new(CryptoServiceProbe::default());
            let observer = {
                let probe = Arc::clone(&probe);
                thread::spawn(move || probe.observe_then_release(EXPECTED_SERVICES))
            };

            let crypto_probe = Arc::clone(&probe);
            let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts");
            let operation =
                run_crypto_operation(strategy, Span::none(), move |_| crypto_probe.block_crypto());
            let crypto = context.child("crypto").spawn(move |_| operation);

            let control = {
                let probe = Arc::clone(&probe);
                context.child("control").spawn(move |_| async move {
                    probe.record_service();
                })
            };

            let (resolve, resolved) = oneshot::channel::<()>();
            let resolver = {
                let probe = Arc::clone(&probe);
                context.child("resolver").spawn(move |_| async move {
                    resolved.await.expect("resolver control remains open");
                    probe.record_service();
                })
            };
            resolve.send(()).expect("resolver remains active");

            let journal = {
                let probe = Arc::clone(&probe);
                context.child("journal").spawn(move |context| async move {
                    context.sleep(Duration::from_millis(10)).await;
                    probe.record_service();
                })
            };

            let timer = {
                let probe = Arc::clone(&probe);
                context.child("timer").spawn(move |context| async move {
                    context.sleep(Duration::from_millis(20)).await;
                    probe.record_service();
                })
            };

            let shutdown = {
                let probe = Arc::clone(&probe);
                context.child("shutdown").spawn(move |context| async move {
                    context.stopped().await.expect("shutdown remains active");
                    probe.record_service();
                })
            };

            probe.arm_services();
            context
                .stop(0, Some(Duration::from_secs(4)))
                .await
                .expect("runtime shuts down after crypto returns");

            crypto
                .await
                .expect("crypto task completes")
                .1
                .expect("crypto worker completes");
            control.await.expect("control task completes");
            resolver.await.expect("resolver task completes");
            journal.await.expect("journal task completes");
            timer.await.expect("timer task completes");
            shutdown.await.expect("shutdown task completes");
            observer.join().expect("service observer completes")
        });

        assert!(
            serviced,
            "crypto occupied the async executor before journal, resolver, control, and timer service"
        );
    }

    #[test_traced]
    fn crypto_strategy_panic_is_reconciled() {
        tokio::Runner::default().start(|_| async move {
            let outcome = run_crypto_operation(Sequential, Span::none(), |_| -> () {
                panic!("worker panic")
            })
            .await;
            assert!(matches!(outcome.1, Err(CryptoTaskPanicked)));
        });
    }

    #[test]
    fn generation_reset_releases_actor_runtime_correlations() {
        let (cancel, _cancelled) = oneshot::channel();
        let mut active_validations = BTreeMap::from([(ValidationId::fabricate(0), Some(cancel))]);
        let mut verification_sources = BTreeMap::from([(Observation::new(1, 0), 7_u8)]);

        reset_generation_runtime_correlations(&mut active_validations, &mut verification_sources);

        assert!(active_validations.is_empty());
        assert!(verification_sources.is_empty());
    }
}
