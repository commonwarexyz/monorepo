use crate::stateful::{
    Application, Input,
    actor::{
        core::{
            mailbox::{Message, Proposal, ProposalRequest},
            until_stopped,
            verifications::{Handler as Verifications, Request, VerificationRequest},
        },
        processor::{Applied, Processor, Prune},
    },
    db::Barrier,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Heightable,
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
};
use commonware_macros::{boxed, select, select_loop};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner};
use commonware_utils::{
    Acknowledgement as _, acknowledgement::Exact, channel::fallible::OneshotExt,
};
use futures::{
    FutureExt as _,
    future::{Either, pending, ready},
};
use std::{collections::VecDeque, sync::mpsc::TryRecvError};
use tracing::{Instrument as _, debug, info_span, warn};

/// Work selected for one iteration of the processing loop.
enum Step<M, P> {
    /// An external request or a locally ready build.
    Action(M),
    /// A pending prune selected to run.
    Prune(P),
    /// Completion of the active barrier (see [`Durability::completion`]).
    Barrier(Option<Height>),
}

/// Work the processing loop handles in order.
pub(super) enum Action<E, A: Application<E>> {
    /// A mailbox message.
    Message(Message<E, A>),
    /// A proposal whose parent state has been recovered.
    Build(ProposalRequest<E, A>),
}

/// Tracks the durable database prefix and marshal acknowledgements awaiting it.
///
/// At most one barrier covers a captured prefix. Applied heights beyond that prefix remain queued
/// for a successor barrier.
struct Durability {
    /// Highest applied height known to be durable.
    durable: Height,
    /// Applied heights whose marshal acknowledgements await durability, in nondecreasing order.
    acknowledgements: VecDeque<(Height, Exact)>,
    /// Active barrier, whose output is the height of its captured prefix once durable.
    barrier: Option<Handle<Option<Height>>>,
}

impl Durability {
    /// Initializes tracking at a height already known to be durable.
    const fn new(height: Height) -> Self {
        Self {
            durable: height,
            acknowledgements: VecDeque::new(),
            barrier: None,
        }
    }

    /// Returns the highest applied height (the durable height when no acknowledgement is pending).
    fn applied(&self) -> Height {
        self.acknowledgements
            .back()
            .map_or(self.durable, |(height, _)| *height)
    }

    /// Holds the acknowledgement for a newly applied `height` until it is durable.
    ///
    /// Panics unless `height` is above every applied height.
    fn record(&mut self, height: Height, acknowledgement: Exact) {
        assert!(height > self.applied(), "finalized heights must increase");
        self.acknowledgements.push_back((height, acknowledgement));
    }

    /// Holds a duplicate receipt until its height is durable (acknowledging it at once if it
    /// already is).
    ///
    /// Panics if `height` is neither durable nor applied.
    fn record_duplicate(&mut self, height: Height, acknowledgement: Exact) {
        if self.covers(height) {
            acknowledgement.acknowledge();
            return;
        }
        let index = self
            .acknowledgements
            .iter()
            .rposition(|(applied, _)| *applied == height)
            .expect("an undurable applied height must retain its acknowledgement");
        self.acknowledgements
            .insert(index + 1, (height, acknowledgement));
    }

    /// Returns whether applied state is not yet durable and no barrier is active.
    fn needs_barrier(&self) -> bool {
        self.barrier.is_none() && self.durable < self.applied()
    }

    /// Tracks `barrier` as covering applied state through `height`.
    ///
    /// Panics if a barrier is active or `height` is not above the durable height and at or below
    /// the applied height.
    fn set_barrier(&mut self, height: Height, barrier: Barrier) {
        assert!(self.barrier.is_none(), "barrier already active");
        assert!(height > self.durable && height <= self.applied());
        self.barrier = Some(Handle::from_future(async move {
            Ok(barrier.durable().await.then_some(height))
        }));
    }

    /// Awaits the active barrier, staying pending when none is active so callers can select on it
    /// unconditionally.
    ///
    /// Resolves to the covered height, or `None` if shutdown interrupted the barrier.
    async fn completion(&mut self) -> Option<Height> {
        let Some(barrier) = &mut self.barrier else {
            return pending().await;
        };
        barrier.await.expect("internal barrier handle cannot fail")
    }

    /// Clears the active barrier and acknowledges every height it made durable.
    ///
    /// Returns `false` without advancing the durable height if `completion` is `None`, which only
    /// a runtime shutdown causes. Panics if no barrier is active, or if `completion` is `None`
    /// while the actor is not `stopping`.
    fn complete(&mut self, completion: Option<Height>, stopping: bool) -> bool {
        assert!(self.barrier.take().is_some(), "barrier not active");
        let Some(height) = completion else {
            assert!(stopping, "barrier ended without durability while running");
            return false;
        };
        assert!(height > self.durable && height <= self.applied());
        self.durable = height;
        let covered = self
            .acknowledgements
            .iter()
            .take_while(|(height, _)| *height <= self.durable)
            .count();
        for (_, acknowledgement) in self.acknowledgements.drain(..covered) {
            acknowledgement.acknowledge();
        }
        true
    }

    /// Returns whether `height` lies within the known durable prefix.
    fn covers(&self, height: Height) -> bool {
        self.durable >= height
    }
}

/// Starts a barrier covering all applied state.
///
/// Speculative work keeps running while the barrier waits for database access. Returns `false` if
/// the actor stops before the barrier starts. Panics unless [`Durability::needs_barrier`] holds.
async fn start_barrier<E, A, V, T>(
    context: &E,
    durability: &mut Durability,
    verifications: &mut Verifications<E, A, V>,
    actions: &mut VecDeque<Action<E, A>>,
    processor: &mut Processor<E, A, T>,
) -> bool
where
    E: Spawner + Clock,
    A: Application<E>,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<A::SigningScheme, V>: BlockProvider<Block = A::Block>,
    T: Strategy,
{
    assert!(
        durability.needs_barrier(),
        "barrier requires uncovered applied state and no active barrier",
    );

    let height = durability.applied();
    let barrier = select! {
        _ = context.stopped() => return false,
        barrier = verifications.drive(processor.start_sync(), actions) => barrier,
    };
    durability.set_barrier(height, barrier);
    true
}

/// Serves proposals, verifications, and finalizations against the live database set.
pub(super) struct Processing<E, A, V, T>
where
    A: Application<E>,
    V: Variant,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,
    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,
    /// Provider cloned into each proposal.
    pub(super) provider: A::Provider,
    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<A::SigningScheme, V>,
    /// The processing state of the actor.
    pub(super) processor: Processor<E, A, T>,

    /// Verification requests deferred until processing starts.
    pub(super) deferred_verifications: Vec<VerificationRequest<E, A>>,
}

impl<E, A, V, T> Processing<E, A, V, T>
where
    E: Spawner + Clock,
    A: Application<E>,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<A::SigningScheme, V>: BlockProvider<Block = A::Block>,
    T: Strategy,
{
    /// Serves requests until the mailbox closes or the actor stops.
    ///
    /// At most one barrier is active, and blocks finalized while it runs are covered by a later
    /// barrier. A marshal acknowledgement is released only once its block is durable. If shutdown
    /// interrupts a barrier, processing stops and every pending acknowledgement is cancelled.
    #[boxed]
    pub async fn run(mut self) {
        let mut pending_prune = None;
        let mut actions = VecDeque::new();
        let mut verifications = Verifications::new(
            self.marshal.clone(),
            self.processor.verifier(),
            self.context.as_present().child("verifications"),
        );
        for request in std::mem::take(&mut self.deferred_verifications) {
            verifications.schedule(Request::Verify(request));
        }

        let mut durability = Durability::new(self.processor.branch_anchor().height);
        select_loop! {
            self.context,
            on_start => {
                if let Some(completion) = durability.completion().now_or_never()
                    && !durability.complete(completion, self.context.stopped().now_or_never().is_some())
                {
                    return;
                }

                // A prune is ready once no barrier is active and a completed barrier covers its
                // target. Until then the loop keeps working and barriers start as usual, which
                // makes the target durable. A ready prune runs before the next barrier starts, so
                // a steady stream of finalized blocks cannot postpone it forever.
                let prune_ready = pending_prune.as_ref().is_some_and(|prune: &Prune<_>| {
                    durability.barrier.is_none() && durability.covers(prune.barrier_height)
                });
                if !prune_ready
                    && durability.needs_barrier()
                    && !start_barrier(
                        self.context.as_present(),
                        &mut durability,
                        &mut verifications,
                        &mut actions,
                        &mut self.processor,
                    ).await
                {
                    return;
                }

                // Publish ready verdicts before admitting another action when possible. The
                // stream may yield while other requests are still ready.
                verifications.complete_ready(&mut actions);

                // A ready prune runs before queued work. Otherwise work that is already available
                // runs at once, a closed mailbox stops the loop, and an empty one waits for the
                // first of a request completing, a message arriving, or the active barrier
                // finishing.
                let action = if prune_ready {
                    Err(TryRecvError::Empty)
                } else if let Some(action) = actions.pop_front() {
                    Ok(action)
                } else {
                    self.mailbox.try_recv().map(Action::Message)
                };
                let next = match action {
                    Ok(action) => Either::Left(ready(Some(Step::Action(action)))),
                    Err(error) => match (prune_ready, error) {
                        (true, _) => Either::Left(ready(Some(Step::Prune(
                            pending_prune.take().expect("ready prune must be pending"),
                        )))),
                        (false, TryRecvError::Disconnected) if pending_prune.is_none() => {
                            debug!("mailbox closed, stopping processing");
                            return;
                        }
                        // A closed mailbox still lets a scheduled prune finish: wait for the
                        // barrier that makes its target durable.
                        (false, TryRecvError::Disconnected) => {
                            let durability = &mut durability;
                            let verifications = &mut verifications;
                            let actions = &mut actions;
                            Either::Right(Either::Left(async move {
                                loop {
                                    select! {
                                        _ = verifications.complete_next(actions) => {
                                            if let Some(action) = actions.pop_front() {
                                                break Some(Step::Action(action));
                                            }
                                        },
                                        completion = durability.completion() => {
                                            break Some(Step::Barrier(completion));
                                        },
                                    }
                                }
                            }))
                        }
                        (false, TryRecvError::Empty) => {
                            let mailbox = &mut self.mailbox;
                            let durability = &mut durability;
                            let verifications = &mut verifications;
                            let actions = &mut actions;
                            Either::Right(Either::Right(async move {
                                loop {
                                    select! {
                                        _ = verifications.complete_next(actions) => {
                                            if let Some(action) = actions.pop_front() {
                                                break Some(Step::Action(action));
                                            }
                                        },
                                        message = mailbox.recv() => {
                                            break message.map(|message| Step::Action(Action::Message(message)));
                                        },
                                        completion = durability.completion() => {
                                            break Some(Step::Barrier(completion));
                                        },
                                    }
                                }
                            }))
                        }
                    },
                };
            },
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
            },
            Some(step) = next else {
                debug!("mailbox closed, stopping processing");
                break;
            } => match step {
                Step::Action(Action::Message(Message::Propose(request))) => {
                    verifications.schedule(Request::Recover(request));
                }
                Step::Action(Action::Build(ProposalRequest {
                    span,
                    context,
                    ancestry,
                    upstream,
                    proposal,
                })) => {
                    let process = match &proposal {
                        Proposal::Prepare(_) => info_span!(parent: &span, "stateful.actor.prepare"),
                        Proposal::Propose(_) => info_span!(parent: &span, "stateful.actor.propose"),
                    };
                    let input = Input {
                        upstream,
                        provider: self.provider.clone(),
                    };
                    let actor_context = self.context.as_present();
                    let build = self
                        .processor
                        .propose(
                            actor_context,
                            context,
                            ancestry,
                            input,
                            proposal,
                        )
                        .instrument(process);
                    futures::pin_mut!(build);

                    // Verifications start as they arrive, since one may certify the parent this
                    // build needs. Other messages and newly ready builds queue in order until the
                    // build finishes. The active barrier still completes, so acknowledgements do
                    // not wait for the build.
                    let mut receive_messages = true;
                    loop {
                        if receive_messages {
                            select! {
                                _ = self.context.stopped() => return,
                                _ = &mut build => break,
                                _ = verifications.complete_next(&mut actions) => {},
                                completion = durability.completion() => {
                                    if !durability.complete(completion, self.context.stopped().now_or_never().is_some()) {
                                        return;
                                    }
                                },
                                message = self.mailbox.recv() => match message {
                                    Some(Message::Verify(request)) => {
                                        verifications.schedule(Request::Verify(request));
                                    }
                                    Some(message) => actions.push_back(Action::Message(message)),
                                    None => receive_messages = false,
                                },
                            }
                        } else {
                            select! {
                                _ = self.context.stopped() => return,
                                _ = &mut build => break,
                                _ = verifications.complete_next(&mut actions) => {},
                                completion = durability.completion() => {
                                    if !durability.complete(completion, self.context.stopped().now_or_never().is_some()) {
                                        return;
                                    }
                                },
                            }
                        }
                    }
                }
                Step::Action(Action::Message(Message::Verify(request))) => {
                    verifications.schedule(Request::Verify(request));
                }
                Step::Action(Action::Message(Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                })) => {
                    // Redelivery waits for durability and leaves speculative work running.
                    if self.processor.redelivered(&block) {
                        durability.record_duplicate(block.height(), acknowledgement);
                    } else {
                        // Requests keep running while the block applies. Those on a competing
                        // branch go stale and start over against the new branch anchor.
                        // A shutdown mid-finalization leaves the block unacknowledged, so marshal
                        // redelivers it after restart.
                        let process = info_span!(parent: &span, "stateful.actor.finalized");
                        let finalize = verifications
                            .drive(
                                self.processor.finalize(
                                    &self.context,
                                    &self.marshal,
                                    &block,
                                    durability.barrier.is_none(),
                                ),
                                &mut actions,
                            )
                            .instrument(process.clone());
                        let Some(Applied { barrier, prune }) =
                            until_stopped(self.context.as_present(), finalize).await
                        else {
                            warn!(height = block.height().get(), "stopped mid-finalization");
                            return;
                        };
                        let _process = process.enter();
                        debug!(height = block.height().get(), "applied finalized database batch");

                        // Acknowledge once a barrier covers this height, so marshal's processed
                        // height never passes durable state and a restart replays the unsynced
                        // suffix.
                        let height = block.height();
                        durability.record(height, acknowledgement);
                        if let Some(barrier) = barrier {
                            durability.set_barrier(height, barrier);
                        }
                        if let Some(prune) = prune {
                            pending_prune = Some(prune);
                        }
                    }
                }
                Step::Action(Action::Message(Message::SubscribeDatabases { response })) => {
                    response.send_lossy(self.processor.readers());
                }
                Step::Prune(prune) => {
                    // A prune runs only once no barrier is active and its target is durable. It
                    // removes only history below that target, which no branch descending from the
                    // anchor reads, so requests keep running.
                    assert!(
                        durability.barrier.is_none() && durability.covers(prune.barrier_height),
                        "prune must wait for a completed barrier covering its target",
                    );
                    let pruned = verifications
                        .drive(self.processor.prune(prune, &self.marshal), &mut actions);
                    if until_stopped(self.context.as_present(), pruned).await.is_none() {
                        return;
                    }
                    // The published snapshots predate this prune and pin the pruned storage, so
                    // capture and publish afresh right away. Starting the successor barrier now
                    // does both.
                    if durability.needs_barrier() {
                        if !start_barrier(
                            self.context.as_present(),
                            &mut durability,
                            &mut verifications,
                            &mut actions,
                            &mut self.processor,
                        ).await {
                            return;
                        }
                    } else {
                        let published = verifications
                            .drive(self.processor.publish_snapshot(), &mut actions);
                        if until_stopped(self.context.as_present(), published).await.is_none() {
                            return;
                        }
                    }
                }
                Step::Barrier(completion) => {
                    if !durability.complete(completion, self.context.stopped().now_or_never().is_some()) {
                        return;
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Processing};
    use crate::stateful::{
        Application, ExecutionError, Finality, Input, Proposed, PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
        },
        db::{DatabaseSet, Publisher, Reader, Single, Subscriber},
        tests::{
            fixtures,
            mocks::{
                FlushControl, TestApp, TestBlock, TestDatabases, TestDb, TestMerkleized,
                TestScheme, TestUnmerkleized, TestVariant, anchor, digested, test_databases,
            },
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Application as _, Automaton as _, Block as _, CertifiableAutomaton as _,
        CertifiableBlock as _, Handoff, Heightable as _, Reporter as _, Reporters,
        marshal::{
            Update,
            ancestry::{self, Ancestry, BoxedAncestry},
            core::{Mailbox as MarshalMailbox, Processed},
            standard::Deferred,
        },
        simplex::{mocks::scheme as scheme_mocks, types::Activity},
        types::{FixedEpocher, Height},
    };
    use commonware_cryptography::{Digested, Digestible as _};
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Metrics as _, Name, Runner as _,
        Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZU64, NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
        channel::oneshot,
        sync::Mutex,
    };
    use futures::{Stream, StreamExt as _, poll};
    use std::{
        collections::{BTreeMap, VecDeque},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Waker},
        time::Duration,
    };

    struct ApplicationGate {
        started: oneshot::Sender<()>,
        release: futures::future::BoxFuture<'static, ()>,
    }

    /// Counts calls to [`Application::process`] by block height.
    #[derive(Clone, Default)]
    struct ProcessCalls(Arc<Mutex<BTreeMap<Height, usize>>>);

    impl ProcessCalls {
        fn record(&self, height: Height) {
            *self.0.lock().entry(height).or_default() += 1;
        }

        fn at(&self, height: Height) -> usize {
            self.0.lock().get(&height).copied().unwrap_or_default()
        }
    }

    #[derive(Clone)]
    struct GatedApp {
        process_gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        proposal_gate: Arc<Mutex<Option<ApplicationGate>>>,
        process_valid: bool,
        observed_contexts: Arc<Mutex<Vec<Name>>>,
    }

    impl GatedApp {
        /// Holds a build on the proposal gate, if one is set, until the test releases it.
        async fn hold_proposal(&self) {
            let gate = self.proposal_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
        }
    }

    impl Application<deterministic::Context> for GatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Captured = ();
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("gated application genesis is not used")
        }

        async fn prepare(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Handoff<Proposed<Self, deterministic::Context>>, ExecutionError> {
            self.hold_proposal().await;
            Ok(Handoff::Wait)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            self.hold_proposal().await;
            Ok(None)
        }

        async fn process(
            &mut self,
            context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            finality: Finality,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            if ancestry.next().await.is_none() {
                return Ok(None);
            }
            if finality == Finality::Finalized {
                return Ok(Some(TestMerkleized));
            }
            self.observed_contexts.lock().push(context.0.name());
            let mut gate = self
                .process_gates
                .lock()
                .pop_front()
                .expect("every process call must have a gate");
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
            Ok(self.process_valid.then_some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
        }
    }

    #[derive(Clone)]
    struct ReadGatedApp {
        database: Reader<TestDb>,
        gate_height: Height,
        gate: Arc<Mutex<Option<ApplicationGate>>>,
    }

    impl Application<deterministic::Context> for ReadGatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Captured = ();
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("read-gated application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            panic!("read-gated application proposal is not used")
        }

        async fn process(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _finality: Finality,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            let Some(block) = ancestry.next().await else {
                return Ok(None);
            };
            if block.height() != self.gate_height {
                return Ok(Some(TestMerkleized));
            }
            let database = self.database.read().await;
            let Some(mut gate) = self.gate.lock().take() else {
                return std::future::pending().await;
            };
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
            drop(database);
            Ok(Some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
        }
    }

    /// Gates taken, in order, by `process` calls for blocks at each height.
    type ProcessGates = Arc<Mutex<BTreeMap<Height, VecDeque<ApplicationGate>>>>;

    #[derive(Clone)]
    struct ReplayGatedApp {
        gates: ProcessGates,
        proposal_gate: Arc<Mutex<Option<ApplicationGate>>>,
        finalized_gate: Arc<Mutex<Option<ApplicationGate>>>,
        unexecutable: Option<Height>,
        process_calls: ProcessCalls,
        finalized_calls: ProcessCalls,
        capture_calls: Arc<AtomicUsize>,
        applied_finalizations: Arc<Mutex<Vec<Height>>>,
    }

    impl ReplayGatedApp {
        /// Returns an application whose `process` of a block at `gate_height` takes the next of
        /// `gates`.
        fn new(gate_height: Height, gates: impl IntoIterator<Item = ApplicationGate>) -> Self {
            Self {
                gates: Arc::default(),
                proposal_gate: Arc::default(),
                finalized_gate: Arc::default(),
                unexecutable: None,
                process_calls: ProcessCalls::default(),
                finalized_calls: ProcessCalls::default(),
                capture_calls: Arc::default(),
                applied_finalizations: Arc::default(),
            }
            .with_gates(gate_height, gates)
        }

        /// Adds `gates` for `process` calls of blocks at `height`.
        fn with_gates(
            self,
            height: Height,
            gates: impl IntoIterator<Item = ApplicationGate>,
        ) -> Self {
            self.gates.lock().entry(height).or_default().extend(gates);
            self
        }
    }

    impl Application<deterministic::Context> for ReplayGatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Captured = Height;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("replay-gated application genesis is not used")
        }

        async fn prepare(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            batches: TestUnmerkleized,
            input: Input<Self::Input, Self::Provider>,
        ) -> Result<Handoff<Proposed<Self, deterministic::Context>>, ExecutionError> {
            Ok(self
                .propose(context, ancestry, batches, input)
                .await?
                .map_or(Handoff::Wait, Handoff::Vote))
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            let gate = self.proposal_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            let mut ancestry = Box::pin(ancestry);
            let Some(parent) = ancestry.next().await else {
                return Ok(None);
            };
            Ok(Some(Proposed {
                block: TestBlock::child(parent.inner(), 9),
                merkleized: TestMerkleized,
            }))
        }

        async fn process(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            finality: Finality,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            let Some(block) = ancestry.next().await else {
                return Ok(None);
            };
            self.process_calls.record(block.height());
            if finality == Finality::Finalized {
                self.finalized_calls.record(block.height());
            }
            let gate = self
                .gates
                .lock()
                .get_mut(&block.height())
                .and_then(VecDeque::pop_front);
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            Ok((self.unexecutable != Some(block.height())).then_some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) -> Self::Captured {
            self.capture_calls.fetch_add(1, Ordering::SeqCst);
            block.height()
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            height: Self::Captured,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
            self.applied_finalizations.lock().push(height);
            let gate = self.finalized_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
        }
    }

    fn application_gate() -> (ApplicationGate, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        (
            ApplicationGate {
                started,
                release: Box::pin(async move {
                    let _ = release_rx.await;
                }),
            },
            started_rx,
            release,
        )
    }

    /// Queues an empty proposal, which marks a position in mailbox order. Once the actor reaches
    /// it, it declines without calling the application or reading the databases.
    fn queue_marker<A>(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, A>,
    ) -> Pin<Box<impl Future<Output = Option<Digested<TestBlock>>> + use<A>>>
    where
        A: Application<
                deterministic::Context,
                Block = TestBlock,
                Context = <TestApp as Application<deterministic::Context>>::Context,
                Input = (),
            >,
    {
        let mut mailbox = mailbox.clone();
        let context = context.child("marker");
        Box::pin(async move {
            mailbox
                .propose(
                    (context, TestBlock::new(0, 0).context()),
                    ancestry::from_iter(std::iter::empty::<Digested<TestBlock>>()),
                    (),
                )
                .await
        })
    }

    /// Waits until the actor has handled every earlier mailbox message.
    async fn processing_fence<A>(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, A>,
    ) where
        A: Application<
                deterministic::Context,
                Block = TestBlock,
                Context = <TestApp as Application<deterministic::Context>>::Context,
                Input = (),
            >,
    {
        assert!(queue_marker(context, mailbox).await.is_none());
    }

    /// A timed runner whose spawned tasks' panics resolve their handles with an error.
    fn panicking_runner() -> deterministic::Runner {
        deterministic::Runner::new(
            deterministic::Config::default()
                .with_timeout(Some(Duration::from_secs(10)))
                .with_catch_panics(true),
        )
    }

    async fn spawn_gated_application(
        context: &deterministic::Context,
        prefix: &str,
        app: GatedApp,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        let mut signing = context.child("signing");
        let scheme =
            scheme_mocks::fixture(&mut signing, b"gated-application", 1).schemes[0].clone();
        let marshal = fixtures::marshal_fixture(
            context.child("marshal"),
            prefix,
            scheme,
            None,
            NZUsize!(1),
            false,
        )
        .await;
        let processor = Processor::new(
            app,
            test_databases(),
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
            crate::stateful::db::Publisher::new(context).0,
            Sequential,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            processor,
            deferred_verifications: Vec::new(),
        };
        let actor = context.child("loop").spawn(move |_| processing.run());
        (Mailbox::new(sender), marshal.guards, actor)
    }

    /// Spawn a [`Processing`] loop over a gated [`TestDb`], returning its
    /// mailbox, flush controls, a guard keeping the (never-started) marshal
    /// actor's mailbox open, and the processing actor handle.
    async fn spawn_processing(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        FlushControl,
        Subscriber<u64>,
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        spawn_processing_with_gates(context, prefix, prune_config, VecDeque::new(), None).await
    }

    async fn spawn_processing_with_gates(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
        process_gates: VecDeque<ApplicationGate>,
        proposal_gate: Option<ApplicationGate>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        FlushControl,
        Subscriber<u64>,
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        let mut signing = context.child("signing");
        let scheme_fixture = scheme_mocks::fixture(&mut signing, b"gated", 1);
        let marshal = fixtures::marshal_fixture(
            context.child("marshal_fixture"),
            prefix,
            scheme_fixture.schemes[0].clone(),
            None,
            NZUsize!(1),
            false,
        )
        .await;

        let control = FlushControl::default();
        let databases = Single::from(TestDb::gated(control.clone()));
        let pruning =
            prune_config.map(|config| Pruning::new(config, marshal.mailbox.max_pending_acks(), 0));
        let app = GatedApp {
            process_gates: Arc::new(Mutex::new(process_gates)),
            proposal_gate: Arc::new(Mutex::new(proposal_gate)),
            process_valid: true,
            observed_contexts: Arc::default(),
        };
        let (publisher, subscriber) = Publisher::new(context);
        let mut processor = Processor::new(
            app,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
            publisher,
            Sequential,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        processor.publish_snapshot().await;
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            processor,
            deferred_verifications: Vec::new(),
        };
        let actor = context.child("loop").spawn(move |_| processing.run());
        (
            Mailbox::new(sender),
            control,
            subscriber,
            marshal.guards,
            actor,
        )
    }

    /// The value of the `publications` counter.
    fn publications(context: &deterministic::Context) -> u64 {
        context
            .encode()
            .lines()
            .find_map(|line| line.strip_prefix("publications_total "))
            .expect("counter must be registered")
            .parse()
            .expect("counter must be an integer")
    }

    async fn spawn_read_gated_processing(
        context: &deterministic::Context,
        prefix: &str,
        gate: ApplicationGate,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, ReadGatedApp>,
        FlushControl,
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        let mut signing = context.child("signing");
        let scheme_fixture = scheme_mocks::fixture(&mut signing, b"read-gated", 1);
        let marshal = fixtures::marshal_fixture(
            context.child("marshal_fixture"),
            prefix,
            scheme_fixture.schemes[0].clone(),
            None,
            NZUsize!(1),
            false,
        )
        .await;

        let control = FlushControl::default();
        let databases = Single::from(TestDb::gated(control.clone()));
        let app = ReadGatedApp {
            database: databases.reader(),
            gate_height: Height::new(3),
            gate: Arc::new(Mutex::new(Some(gate))),
        };
        let pruning =
            prune_config.map(|config| Pruning::new(config, marshal.mailbox.max_pending_acks(), 0));
        let processor = Processor::new(
            app,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
            crate::stateful::db::Publisher::new(context).0,
            Sequential,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            processor,
            deferred_verifications: Vec::new(),
        };
        let actor = context.child("loop").spawn(move |_| processing.run());
        (Mailbox::new(sender), control, marshal.guards, actor)
    }

    #[test]
    fn independent_verifications_do_not_block_each_other() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (first_gate, first_started, first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "concurrent-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let first_block = TestBlock::child(&genesis, 1);
            let first_genesis = genesis.clone();
            let mut first_mailbox = mailbox.clone();
            let first = context.child("first").spawn(move |task_context| {
                let consensus_context = first_block.context();
                async move {
                    first_mailbox
                        .verify(
                            (task_context, consensus_context),
                            ancestry::from_iter([digested(first_block), digested(first_genesis)]),
                        )
                        .await
                }
            });
            first_started
                .await
                .expect("first verification should start");

            let second_block = TestBlock::child(&genesis, 2);
            let second = context.child("second").spawn(move |task_context| {
                let consensus_context = second_block.context();
                async move {
                    mailbox
                        .verify(
                            (task_context, consensus_context),
                            ancestry::from_iter([digested(second_block), digested(genesis)]),
                        )
                        .await
                }
            });
            second_started
                .await
                .expect("second verification must start while the first remains pending");

            first_release
                .send(())
                .expect("first verification should remain active");
            second_release
                .send(())
                .expect("second verification should remain active");
            assert!(first.await.expect("first verification failed"));
            assert!(second.await.expect("second verification failed"));
            actor.abort();
        });
    }

    /// Shared processing runs under the actor's runtime context, so a request's attributes do not
    /// reach the application.
    #[test]
    fn processing_runs_on_the_actor_context() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let observed_contexts = Arc::new(Mutex::new(Vec::new()));
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: observed_contexts.clone(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "verify-attributes", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let block_context = block.context();
            let request_context = context
                .child("request")
                .with_attribute("round", "request-round")
                .with_attribute("owner", "request")
                .with_attribute("shard", 4);
            let mut verify = Box::pin(mailbox.verify(
                (request_context, block_context),
                ancestry::from_iter([digested(block), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            // The processing runs under the actor's context, since several requests may share
            // it, so the request's attributes do not reach the application.
            {
                let observed = observed_contexts.lock();
                assert_eq!(observed.len(), 1);
                assert!(
                    observed[0].label.ends_with("process"),
                    "{}",
                    observed[0].label
                );
                assert!(observed[0].attributes.is_empty());
            }

            release.send(()).expect("verification should remain active");
            assert!(verify.await);
            actor.abort();
        });
    }

    /// A caller's cancellation ends its verification while executing or acquiring blocks.
    #[test]
    fn abandoned_verification_cancels_with_caller() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, mut release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "caller-cancellation", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let block_context = block.context();
            let mut verify = Box::pin(mailbox.verify(
                (context.child("caller"), block_context),
                ancestry::from_iter([digested(block), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("application task should start");

            // The application's release gate closes once the actor drops the abandoned
            // verification's processing.
            drop(verify);
            release.closed().await;

            // A verification whose blocks never arrive is still acquiring them once the actor has
            // answered a later database subscription. Its caller's cancellation drops that
            // acquisition along with the ancestry it holds.
            let subscriber = mailbox.clone();
            let pending = TestBlock::new(2, 2);
            let (unavailable, _gate, released) = GatedAncestry::new([]);
            let mut acquiring = Box::pin(
                mailbox.verify((context.child("acquiring"), pending.context()), unavailable),
            );
            assert!(poll!(&mut acquiring).is_pending());
            processing_fence(&context, &subscriber).await;
            drop(acquiring);
            released
                .await
                .expect("cancellation must drop the acquisition");
            actor.abort();
        });
    }

    #[test]
    fn abandoned_incomplete_verifications_do_not_block_later_work() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (first_gate, first_started, first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "incomplete-verify", app).await;
            let subscriber = mailbox.clone();

            // Each incomplete verification is dropped only after the actor has answered a later
            // database subscription, and so has received the verification and started acquiring
            // its blocks.
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let mut incomplete = Box::pin(mailbox.verify(
                (context.child("empty"), block1.context()),
                ancestry::from_iter([]),
            ));
            assert!(poll!(&mut incomplete).is_pending());
            processing_fence(&context, &subscriber).await;
            drop(incomplete);

            let mut first = Box::pin(mailbox.verify(
                (context.child("first"), block1.context()),
                ancestry::from_iter([digested(block1.clone()), digested(genesis)]),
            ));
            assert!(poll!(&mut first).is_pending());
            first_started
                .await
                .expect("later verification should start");
            first_release
                .send(())
                .expect("later verification should remain active");
            assert!(first.await);

            let block2 = TestBlock::child(&block1, 2);
            let mut incomplete = Box::pin(mailbox.verify(
                (context.child("missing_parent"), block2.context()),
                ancestry::from_iter([digested(block2.clone())]),
            ));
            assert!(poll!(&mut incomplete).is_pending());
            processing_fence(&context, &subscriber).await;
            drop(incomplete);

            let mut second = Box::pin(mailbox.verify(
                (context.child("second"), block2.context()),
                ancestry::from_iter([digested(block2), digested(block1)]),
            ));
            assert!(poll!(&mut second).is_pending());
            second_started
                .await
                .expect("later verification should start");
            second_release
                .send(())
                .expect("later verification should remain active");
            assert!(second.await);
            actor.abort();
        });
    }

    #[test]
    fn application_rejection_returns_false() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: false,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "rejected-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), block.context()),
                ancestry::from_iter([digested(block), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");
            release.send(()).expect("verification should remain active");
            assert!(!verify.await);
            actor.abort();
        });
    }

    /// A parent recovered for its child's verification answers its own verification without
    /// being processed again.
    #[test]
    fn recovered_parent_answers_its_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let app = ReplayGatedApp::new(parent.height(), []);
            let process_calls = app.process_calls.clone();
            let (mut mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "replayed-parent", &genesis, app).await;

            // Verifying the child recovers its missing parent, processing both once.
            assert!(
                mailbox
                    .verify(
                        (context.child("verify_child"), child.context()),
                        ancestry::from_iter([digested(child.clone()), digested(parent.clone())]),
                    )
                    .await
            );
            assert_eq!(process_calls.at(parent.height()), 1);
            assert_eq!(process_calls.at(child.height()), 1);

            // The recovered state answers the parent's own verifications from the cache.
            for label in ["verify_parent", "verify_parent_again"] {
                assert!(
                    mailbox
                        .verify(
                            (context.child(label), parent.context()),
                            ancestry::from_iter([
                                digested(parent.clone()),
                                digested(genesis.clone())
                            ]),
                        )
                        .await
                );
            }
            assert_eq!(process_calls.at(parent.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// Starts a processing loop for `app` over a marshal that has finalized `genesis`, and
    /// returns the loop's mailbox and the marshal's.
    async fn spawn_replay_gated_processing(
        context: &deterministic::Context,
        prefix: &str,
        genesis: &TestBlock,
        app: ReplayGatedApp,
    ) -> (
        Mailbox<deterministic::Context, ReplayGatedApp>,
        MarshalMailbox<TestScheme, TestVariant>,
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        let mut signing = context.child("signing");
        let scheme = scheme_mocks::fixture(&mut signing, prefix.as_bytes(), 1).schemes[0].clone();
        let marshal = fixtures::marshal_fixture_with_finalized_block(
            context.child("marshal"),
            prefix,
            scheme,
            genesis,
            NZUsize!(1),
            true,
        )
        .await;
        let processor = Processor::new(
            app,
            test_databases(),
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
            crate::stateful::db::Publisher::new(context).0,
            Sequential,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox.clone(),
            processor,
            deferred_verifications: Vec::new(),
        };
        let actor = context.child("loop").spawn(move |_| processing.run());
        (Mailbox::new(sender), marshal.mailbox, marshal.guards, actor)
    }

    /// Resolves once the actor has received every earlier message and handled marshal's replies
    /// to the requests those messages started. The actor and marshal each answer in order: the
    /// first fence shows that the actor has received the messages and sent their marshal requests,
    /// the marshal query that marshal has answered those requests, and the second fence that the
    /// actor has handled the answers.
    async fn await_marshal_replies<A>(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, A>,
        marshal: &MarshalMailbox<TestScheme, TestVariant>,
    ) where
        A: Application<
                deterministic::Context,
                Block = TestBlock,
                Context = <TestApp as Application<deterministic::Context>>::Context,
                Input = (),
            >,
    {
        processing_fence(context, mailbox).await;
        marshal.get_processed().await;
        processing_fence(context, mailbox).await;
    }

    /// A proposal whose parent a verification is already replaying waits for that replay and
    /// builds once it completes, so the parent is processed only once.
    #[test]
    fn proposal_shares_parent_replay_with_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let (apply_gate, apply_started, apply_release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [apply_gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "shared-parent-replay", &genesis, app)
                    .await;

            // Verifying the child replays the missing parent, and the gate holds that replay in
            // `process`.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([digested(child), digested(parent.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            apply_started.await.expect("parent replay should start");

            // A proposal on the parent fetches the parent's ancestor from marshal and then joins
            // that replay without processing the parent again.
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&parent, 3).context(),
                ),
                ancestry::from_iter([digested(parent.clone()), digested(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            await_marshal_replies(&context, &mailbox, &marshal).await;
            assert!(poll!(&mut proposal).is_pending());
            assert_eq!(process_calls.at(parent.height()), 1);

            apply_release
                .send(())
                .expect("parent replay should remain active");
            assert!(verify.await);
            assert!(proposal.await.is_some());
            assert_eq!(process_calls.at(parent.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// A verification whose parent a proposal is already replaying waits for that replay, and
    /// the replay keeps running for the verification when the proposal is cancelled.
    #[test]
    fn verification_keeps_cancelled_proposal_replay_running() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let (gate, started, release) = application_gate();
            let (duplicate_gate, mut duplicate_started, _duplicate_release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [gate, duplicate_gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "cancelled-parent-replay", &genesis, app)
                    .await;

            // The gate holds the proposal's processing of the missing parent, and a second gate
            // detects any repeated processing.
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&parent, 3).context(),
                ),
                ancestry::from_iter([digested(parent.clone()), digested(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            started.await.expect("parent replay must start");

            // Verifying the child fetches the parent's ancestor from marshal and then waits for
            // the proposal's replay of their parent.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([digested(child), digested(parent.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            await_marshal_replies(&context, &mailbox, &marshal).await;
            assert!(poll!(&mut verify).is_pending());
            assert_eq!(process_calls.at(parent.height()), 1);

            // Cancelling the proposal leaves the replay running. Once the actor answers a later
            // database subscription it has observed the cancellation, and releasing the replay
            // answers the verification without processing the parent again.
            drop(proposal);
            processing_fence(&context, &mailbox).await;
            assert!(!release.is_closed());
            release
                .send(())
                .expect("replay must keep running for the verification");
            assert!(verify.await);
            assert_eq!(process_calls.at(parent.height()), 1);
            assert!(poll!(&mut duplicate_started).is_pending());
            actor.abort();
            drop(guards);
        });
    }

    type PendingRequest = Pin<Box<dyn Future<Output = bool> + Send>>;
    type PendingPrepare = Pin<Box<dyn Future<Output = Handoff<Digested<TestBlock>>> + Send>>;

    /// Speculative requests that share parent recovery and execution.
    #[derive(Clone, Copy)]
    enum Managed {
        Verify,
        Prepare,
        Propose,
    }

    /// Sends `request` for the first block of `blocks`. Resolves to the verification's verdict,
    /// or to whether the build produced a child of the block.
    fn send_managed(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, ReplayGatedApp>,
        request: Managed,
        blocks: Vec<Digested<TestBlock>>,
    ) -> PendingRequest {
        let block = blocks[0].clone();
        let label = match request {
            Managed::Verify => "verify",
            Managed::Prepare => "prepare",
            Managed::Propose => "propose",
        };
        let runtime = context.child(label);
        let build_context = TestBlock::child(block.inner(), 0xff).context();
        let ancestry = ancestry::from_iter(blocks);
        let mut mailbox = mailbox.clone();
        Box::pin(async move {
            match request {
                Managed::Verify => mailbox.verify((runtime, block.context()), ancestry).await,
                Managed::Prepare => match mailbox
                    .prepare((runtime, build_context), ancestry, ())
                    .await
                {
                    Handoff::Vote(built) => built.parent() == block.digest(),
                    _ => false,
                },
                Managed::Propose => mailbox
                    .propose((runtime, build_context), ancestry, ())
                    .await
                    .is_some_and(|built| built.parent() == block.digest()),
            }
        })
    }

    /// Sends the verification of `block` and a handoff build on it, the verification first if
    /// `verify_first`. The second request is sent once `started` reports that the first has
    /// reached the application, and both are returned once the second has fetched its blocks from
    /// marshal and joined the first's execution.
    async fn send_handoff_requests(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, ReplayGatedApp>,
        marshal: &MarshalMailbox<TestScheme, TestVariant>,
        block: &TestBlock,
        parent: &TestBlock,
        verify_first: bool,
        started: oneshot::Receiver<()>,
    ) -> (PendingRequest, PendingPrepare) {
        let blocks = [digested(block.clone()), digested(parent.clone())];
        let mut verifier = mailbox.clone();
        let verify_context = (context.child("verify"), block.context());
        let verify_blocks = blocks.clone();
        let mut verify: PendingRequest = Box::pin(async move {
            verifier
                .verify(verify_context, ancestry::from_iter(verify_blocks))
                .await
        });
        let mut proposer = mailbox.clone();
        let prepare_context = (
            context.child("prepare"),
            TestBlock::child(block, 0xff).context(),
        );
        let mut prepare: PendingPrepare = Box::pin(async move {
            proposer
                .prepare(prepare_context, ancestry::from_iter(blocks), ())
                .await
        });
        if verify_first {
            assert!(poll!(&mut verify).is_pending());
            started
                .await
                .expect("verification must reach the application");
            assert!(poll!(&mut prepare).is_pending());
        } else {
            assert!(poll!(&mut prepare).is_pending());
            started.await.expect("handoff must execute its parent");
            assert!(poll!(&mut verify).is_pending());
        }

        // The second request joins the first's execution once marshal has answered its ancestry
        // request.
        await_marshal_replies(context, mailbox, marshal).await;
        (verify, prepare)
    }

    /// A handoff build on an uncertified parent and the parent's own verification execute the
    /// parent once, whichever request reaches the actor first.
    #[rstest::rstest]
    #[case::verify_first(true)]
    #[case::prepare_first(false)]
    fn handoff_and_parent_verification_execute_parent_once(#[case] verify_first: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "handoff-parent-execution", &genesis, app)
                    .await;

            // The first request starts the parent's execution, and the second joins it without
            // executing the parent itself.
            let (mut verify, mut prepare) = send_handoff_requests(
                &context,
                &mailbox,
                &marshal,
                &parent,
                &genesis,
                verify_first,
                started,
            )
            .await;
            assert!(poll!(&mut verify).is_pending());
            assert!(poll!(&mut prepare).is_pending());
            assert_eq!(process_calls.at(parent.height()), 1);

            release.send(()).expect("parent execution must remain held");
            assert!(verify.await);
            let Handoff::Vote(block) = prepare.await else {
                panic!("handoff must build on the parent");
            };
            assert_eq!(block.parent(), parent.digest());
            assert_eq!(process_calls.at(parent.height()), 1);

            // The parent's state and the built child's state are pending.
            assert!(
                context
                    .encode()
                    .lines()
                    .any(|line| line == "pending_blocks 2")
            );
            actor.abort();
            drop(guards);
        });
    }

    /// Cancelling either the request that started the handoff parent's execution or the one that
    /// joined it leaves the execution running for the other.
    #[rstest::rstest]
    #[case::verify_first_cancel_starter(true, true)]
    #[case::verify_first_cancel_joiner(true, false)]
    #[case::prepare_first_cancel_starter(false, true)]
    #[case::prepare_first_cancel_joiner(false, false)]
    fn shared_parent_execution_survives_cancellation(
        #[case] verify_first: bool,
        #[case] cancel_starter: bool,
    ) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let (gate, started, release) = application_gate();
            let (duplicate_gate, mut duplicate_started, _duplicate_release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [gate, duplicate_gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) = spawn_replay_gated_processing(
                &context,
                "cancelled-parent-execution",
                &genesis,
                app,
            )
            .await;

            // The first request sent starts the parent's execution and the second joins it while
            // the gate holds it. A second gate detects any repeated execution.
            let (verify, prepare) = send_handoff_requests(
                &context,
                &mailbox,
                &marshal,
                &parent,
                &genesis,
                verify_first,
                started,
            )
            .await;
            let (mut verify, mut prepare) = (Some(verify), Some(prepare));

            // Cancel either the request that started the execution or the one that joined it.
            if verify_first == cancel_starter {
                verify = None;
            } else {
                prepare = None;
            }

            // Once the actor answers a later database subscription, it has observed the
            // cancellation, and the execution is still running for the remaining request.
            processing_fence(&context, &mailbox).await;
            assert!(!release.is_closed());
            release
                .send(())
                .expect("execution must outlive the cancelled request");
            if let Some(verify) = verify {
                assert!(verify.await);
            }
            if let Some(prepare) = prepare {
                let Handoff::Vote(block) = prepare.await else {
                    panic!("handoff must build on the parent");
                };
                assert_eq!(block.parent(), parent.digest());
            }
            assert_eq!(process_calls.at(parent.height()), 1);
            assert!(poll!(&mut duplicate_started).is_pending());
            actor.abort();
            drop(guards);
        });
    }

    /// A handoff parent that cannot be executed fails the build and the parent's verification
    /// with one execution, whichever request reaches the actor first.
    #[rstest::rstest]
    #[case::verify_first(true)]
    #[case::prepare_first(false)]
    fn unexecutable_handoff_parent_executes_once(#[case] verify_first: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp {
                unexecutable: Some(parent.height()),
                ..ReplayGatedApp::new(parent.height(), [gate])
            };
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) = spawn_replay_gated_processing(
                &context,
                "unexecutable-handoff-parent",
                &genesis,
                app,
            )
            .await;
            let (verify, prepare) = send_handoff_requests(
                &context,
                &mailbox,
                &marshal,
                &parent,
                &genesis,
                verify_first,
                started,
            )
            .await;

            release.send(()).expect("parent execution must remain held");
            assert!(!verify.await);
            assert!(prepare.await.is_wait());
            assert_eq!(process_calls.at(parent.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// Two verifications of the same block share one processing and answer with its verdict.
    #[rstest::rstest]
    #[case::accept(true)]
    #[case::reject(false)]
    fn concurrent_verifications_share_one_processing(#[case] verdict: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp {
                unexecutable: (!verdict).then_some(block.height()),
                ..ReplayGatedApp::new(block.height(), [gate])
            };
            let process_calls = app.process_calls.clone();
            let (mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "shared-verdict", &genesis, app).await;
            let blocks = [digested(block.clone()), digested(genesis)];

            // The first verification's processing is held, and the second joins it. The actor has
            // received the second once it answers a later database subscription.
            let mut first_verifier = mailbox.clone();
            let mut first = Box::pin(first_verifier.verify(
                (context.child("first"), block.context()),
                ancestry::from_iter(blocks.clone()),
            ));
            assert!(poll!(&mut first).is_pending());
            started
                .await
                .expect("first verification must process the block");
            let mut second_verifier = mailbox.clone();
            let mut second = Box::pin(second_verifier.verify(
                (context.child("second"), block.context()),
                ancestry::from_iter(blocks),
            ));
            assert!(poll!(&mut second).is_pending());
            processing_fence(&context, &mailbox).await;
            assert!(poll!(&mut second).is_pending());
            assert_eq!(process_calls.at(block.height()), 1);

            // Both answer with the shared processing's verdict.
            release.send(()).expect("processing must remain held");
            assert_eq!(first.await, verdict);
            assert_eq!(second.await, verdict);
            assert_eq!(process_calls.at(block.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// Finalization joins the winning execution and applies its cached result.
    #[test]
    fn finalization_joins_and_reuses_winning_execution() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let (candidate_gate, candidate_started, candidate_release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                ..ReplayGatedApp::new(block.height(), [candidate_gate])
            };
            let finalized_calls = app.finalized_calls.clone();
            let (process_calls, capture_calls) =
                (app.process_calls.clone(), app.capture_calls.clone());
            let (mut mailbox, _, guards, actor) = spawn_replay_gated_processing(
                &context,
                "finalize-processing-winner",
                &genesis,
                app,
            )
            .await;

            // The first gate holds the verification's processing of the block.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block.context()),
                ancestry::from_iter([digested(block.clone()), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            candidate_started
                .await
                .expect("verification must process the block");

            // Finalizing the block waits for that processing to finish and reuses its result. A
            // second verification never acquires its block and reports when finalization pauses
            // it, so the report shows the finalization has started waiting.
            let (unavailable, _, _) = GatedAncestry::new([]);
            let mut acquiring_verifier = mailbox.clone();
            let mut acquiring = Box::pin(
                acquiring_verifier
                    .verify((context.child("acquiring"), block.context()), unavailable),
            );
            assert!(poll!(&mut acquiring).is_pending());
            let (acknowledgement, waiter) = Exact::handle();
            let mut waiter = Box::pin(waiter);
            let _ = mailbox.report(Update::Block(digested(block.clone()), acknowledgement));
            // Let the actor run until finalization waits.
            context.sleep(Duration::from_millis(10)).await;
            assert!(poll!(&mut waiter).is_pending());
            assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
            assert!(!candidate_release.is_closed());
            candidate_release.send(()).unwrap();
            finalized_started
                .await
                .expect("finalization must reach its hook");
            assert!(poll!(&mut waiter).is_pending());
            finalized_release
                .send(())
                .expect("finalized hook must remain held");
            waiter.await.expect("finalized block must be acknowledged");
            assert!(verify.await, "verification must accept the canonical block");
            assert_eq!(process_calls.at(block.height()), 1);
            assert_eq!(finalized_calls.at(block.height()), 0);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
            drop(acquiring);
            actor.abort();
            drop(guards);
        });
    }

    /// A request whose processing of the finalized block finishes during finalization goes on to
    /// process the block's child before the finalized hook completes.
    #[test]
    fn finalized_block_request_continues_during_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&block, 2);
            let (block_gate, block_started, block_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                ..ReplayGatedApp::new(block.height(), [block_gate])
            }
            .with_gates(child.height(), [child_gate]);
            let process_calls = app.process_calls.clone();
            let (mut mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "finalized-block-continues", &genesis, app)
                    .await;

            // Verifying the child first recovers the uncached block, and the gate holds that
            // processing.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), child.context()),
                ancestry::from_iter([digested(child.clone()), digested(block.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            block_started
                .await
                .expect("recovery must process the block");

            // A second verification never acquires its block and reports when finalization pauses
            // it, so the report shows the finalization is waiting for the block's processing.
            let (unavailable, _, _) = GatedAncestry::new([]);
            let mut acquiring_verifier = mailbox.clone();
            let mut acquiring = Box::pin(
                acquiring_verifier
                    .verify((context.child("acquiring"), child.context()), unavailable),
            );
            assert!(poll!(&mut acquiring).is_pending());
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block.clone()), acknowledgement));
            // Let the actor run until finalization waits.
            context.sleep(Duration::from_millis(10)).await;

            // Once the block's processing finishes, the request processes the child and accepts it
            // while the finalized hook is still held.
            block_release
                .send(())
                .expect("block processing must remain held");
            finalized_started
                .await
                .expect("finalization must reach its hook");
            child_started
                .await
                .expect("the child must be processed during finalization");
            child_release
                .send(())
                .expect("child processing must remain held");
            assert!(verify.await, "verification must accept the child");
            finalized_release
                .send(())
                .expect("finalized hook must remain held");
            waiter.await.expect("finalized block must be acknowledged");
            assert_eq!(process_calls.at(block.height()), 1);
            assert_eq!(process_calls.at(child.height()), 1);
            drop(acquiring);
            actor.abort();
            drop(guards);
        });
    }

    /// A competing finalization does not wait for a request executing another block. Once that
    /// execution finishes, its result is stale and the request is rejected. A verification votes
    /// `false`, and a build on the block declines.
    #[rstest::rstest]
    #[case::verify(Managed::Verify)]
    #[case::prepare(Managed::Prepare)]
    #[case::propose(Managed::Propose)]
    fn competing_finalization_rejects_executing_request(#[case] request: Managed) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let competing = TestBlock::child(&genesis, 2);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp::new(block.height(), [gate]);
            let capture_calls = app.capture_calls.clone();
            let (mut mailbox, _, guards, actor) = spawn_replay_gated_processing(
                &context,
                "competing-finalization-execution",
                &genesis,
                app,
            )
            .await;

            // The gate holds the request's execution of the block.
            let mut request = send_managed(
                &context,
                &mailbox,
                request,
                vec![digested(block), digested(genesis)],
            );
            assert!(poll!(&mut request).is_pending());
            started.await.expect("request must execute the block");

            // The competing block applies while the execution is still held.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(competing), acknowledgement));
            waiter.await.expect("competing block must be acknowledged");
            assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
            assert!(poll!(&mut request).is_pending());

            // The released execution finds its parent discarded, and the request starts over
            // against the competing block and is rejected.
            release.send(()).unwrap();
            assert!(!request.await);
            actor.abort();
            drop(guards);
        });
    }

    /// A fork from the applied databases that is still creating its batches when a competing block
    /// applies is refused, so the block is never processed on the winner's state. The request
    /// starts over and votes `false`.
    #[test]
    fn fork_from_anchor_is_refused_after_competing_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let winner = TestBlock::child(&genesis, 2);
            let height = block.height();
            let app = ReplayGatedApp::new(height, []);
            let process_calls = app.process_calls.clone();
            let (mut mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "fork-gate", &genesis, app).await;

            // The verification forks from the anchor and parks while creating its batches.
            let (forking, release) = TestDb::gate_next_new_batch();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block.context()),
                ancestry::from_iter([digested(block), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            forking
                .await
                .expect("verification must fork from the anchor");

            // The competing block applies, and the parked fork then finds the anchor moved.
            let (acknowledgement, receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            receipt.await.expect("winner must be acknowledged");
            release.send(()).unwrap();
            assert!(!verify.await);

            // Only the winner's reconstruction processed a block at this height.
            assert_eq!(process_calls.at(height), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// Compatible execution advances through its remaining steps while finalization is pending.
    #[rstest::rstest]
    #[case::one_step(false)]
    #[case::recovered_parent(true)]
    fn retained_verification_finishes_during_finalization(#[case] recover_parent: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let losing = TestBlock::child(&first, 2);
            let winner = TestBlock::child(&first, 3);
            let tip = TestBlock::child(&losing, 4);
            let (gate, started, release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                ..ReplayGatedApp::new(losing.height(), [gate])
            };
            let process_calls = app.process_calls.clone();
            let (mut mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "retained-progress", &genesis, app).await;

            assert!(
                marshal
                    .verified(first.context().round, digested(first.clone()))
                    .await
            );

            // Cache the parent so its finalization retains the child's processing.
            let mut first_verifier = mailbox.clone();
            assert!(
                first_verifier
                    .verify(
                        (context.child("verify_first"), first.context()),
                        ancestry::from_iter([digested(first.clone()), digested(genesis)]),
                    )
                    .await
            );
            let (block, parent) = if recover_parent {
                (tip.clone(), losing.clone())
            } else {
                (losing.clone(), first.clone())
            };
            let mut losing_verifier = mailbox.clone();
            let mut verify_losing = Box::pin(losing_verifier.verify(
                (context.child("verify_losing"), block.context()),
                ancestry::from_iter([digested(block), digested(parent)]),
            ));
            assert!(poll!(&mut verify_losing).is_pending());
            started.await.expect("child processing must start");

            // Hold the first finalized hook while the child completes and another finalization
            // waits.
            let (acknowledgement, first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(first), acknowledgement));
            let (acknowledgement, winner_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            finalized_started
                .await
                .expect("first finalized hook must start");
            release
                .send(())
                .expect("retained processing must remain active");
            assert!(
                verify_losing.await,
                "retained verification must remain valid"
            );
            assert_eq!(process_calls.at(losing.height()), 1);
            assert_eq!(process_calls.at(tip.height()), usize::from(recover_parent));
            finalized_release
                .send(())
                .expect("finalized hook must remain active");
            first_waiter
                .await
                .expect("first block must be acknowledged");
            winner_waiter.await.expect("winner must be acknowledged");
            actor.abort();
            drop(guards);
        });
    }

    /// Finalization waits for a parent's shared execution and reuses its state. The original
    /// verification accepts the parent, and the waiting build caches a child of it.
    #[rstest::rstest]
    #[case::prepare(Managed::Prepare, None)]
    #[case::propose(Managed::Propose, None)]
    #[case::verify_then_prepare(Managed::Prepare, Some(true))]
    #[case::verify_then_propose(Managed::Propose, Some(true))]
    #[case::prepare_then_verify(Managed::Prepare, Some(false))]
    #[case::propose_then_verify(Managed::Propose, Some(false))]
    fn finalization_completes_build_processing_finalized_parent(
        #[case] build: Managed,
        #[case] verify_first: Option<bool>,
    ) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [gate]);
            let (process_calls, finalized_calls, capture_calls, applied_finalizations) = (
                app.process_calls.clone(),
                app.finalized_calls.clone(),
                app.capture_calls.clone(),
                app.applied_finalizations.clone(),
            );
            let (mut mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "finalized-build-parent", &genesis, app)
                    .await;

            // The gate holds the first request's candidate processing of the uncached parent, and
            // a second request on the parent, if any, fetches its blocks from marshal and then
            // waits for that processing.
            let blocks = vec![digested(parent.clone()), digested(genesis)];
            let build = send_managed(&context, &mailbox, build, blocks.clone());
            let (mut first, mut second) = match verify_first {
                None => (build, None),
                Some(true) => (
                    send_managed(&context, &mailbox, Managed::Verify, blocks),
                    Some(build),
                ),
                Some(false) => (
                    build,
                    Some(send_managed(&context, &mailbox, Managed::Verify, blocks)),
                ),
            };
            assert!(poll!(&mut first).is_pending());
            started
                .await
                .expect("first request must process the parent");
            if let Some(second) = &mut second {
                assert!(poll!(&mut *second).is_pending());
                await_marshal_replies(&context, &mailbox, &marshal).await;
                assert!(poll!(&mut *second).is_pending());
            }
            assert_eq!(process_calls.at(parent.height()), 1);

            // Finalization joins the shared parent execution before applying its state. A
            // verification that never acquires its block reports when finalization pauses it,
            // which happens once the finalization has started waiting.
            let (unavailable, _, _) = GatedAncestry::new([]);
            let mut acquiring_verifier = mailbox.clone();
            let mut acquiring = Box::pin(
                acquiring_verifier
                    .verify((context.child("acquiring"), parent.context()), unavailable),
            );
            assert!(poll!(&mut acquiring).is_pending());
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(parent.clone()), acknowledgement));
            // Let the actor run until finalization waits.
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
            assert!(!release.is_closed());
            release.send(()).unwrap();
            waiter.await.expect("finalized parent must be acknowledged");
            assert_eq!(finalized_calls.at(parent.height()), 0);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
            assert_eq!(applied_finalizations.lock().as_slice(), [parent.height()]);

            // The same requests complete on the finalized parent without processing it again.
            assert!(
                first.await,
                "first request must complete on the finalized parent"
            );
            if let Some(second) = second {
                assert!(
                    second.await,
                    "second request must complete on the finalized parent"
                );
            }
            assert_eq!(process_calls.at(parent.height()), 1);

            // The build cached the state of its block.
            let built = TestBlock::child(&parent, 9);
            assert!(
                mailbox
                    .verify(
                        (context.child("verify_built"), built.context()),
                        ancestry::from_iter([digested(built.clone()), digested(parent)]),
                    )
                    .await
            );
            assert_eq!(process_calls.at(built.height()), 0);
            drop(acquiring);
            actor.abort();
            drop(guards);
        });
    }

    /// With neither the handoff parent nor its parent cached, as after a restart, the parent's
    /// verification and a handoff build on it execute each block once, whichever request
    /// reaches the actor first.
    #[rstest::rstest]
    #[case::verify_first(true)]
    #[case::prepare_first(false)]
    fn recovered_handoff_ancestry_executes_once(#[case] verify_first: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let grandparent = TestBlock::child(&genesis, 1);
            let parent = TestBlock::child(&grandparent, 2);
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp::new(parent.height(), [gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, marshal, guards, actor) = spawn_replay_gated_processing(
                &context,
                "recovered-handoff-ancestry",
                &genesis,
                app,
            )
            .await;

            // Marshal holds the grandparent, and the actor has cached neither it nor the parent.
            assert!(
                marshal
                    .verified(grandparent.context().round, digested(grandparent.clone()))
                    .await
            );

            let (mut verify, mut prepare) = send_handoff_requests(
                &context,
                &mailbox,
                &marshal,
                &parent,
                &grandparent,
                verify_first,
                started,
            )
            .await;
            assert!(poll!(&mut verify).is_pending());
            assert!(poll!(&mut prepare).is_pending());

            release.send(()).expect("parent execution must remain held");
            assert!(verify.await);
            assert!(matches!(prepare.await, Handoff::Vote(_)));
            assert_eq!(process_calls.at(grandparent.height()), 1);
            assert_eq!(process_calls.at(parent.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    #[test]
    fn unexecutable_parent_rejects_child() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let app = ReplayGatedApp {
                unexecutable: Some(parent.height()),
                ..ReplayGatedApp::new(parent.height(), [])
            };
            let process_calls = app.process_calls.clone();
            let (mut mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "unexecutable-parent", &genesis, app).await;

            // A parent that cannot be processed invalidates the child's ancestry before the
            // child is processed.
            assert!(
                !mailbox
                    .verify(
                        (context.child("verify_child"), child.context()),
                        ancestry::from_iter([digested(child.clone()), digested(parent.clone())]),
                    )
                    .await
            );
            assert_eq!(process_calls.at(parent.height()), 1);
            assert_eq!(process_calls.at(child.height()), 0);
            actor.abort();
            drop(guards);
        });
    }

    #[test]
    fn conflicting_processed_block_is_rejected() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "conflicting-processed", None).await;
            let genesis = TestBlock::new(0, 0);
            let canonical = TestBlock::child(&genesis, 1);
            let conflicting = TestBlock::child(&genesis, 2);

            // Finalize the canonical block and make it durable.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(canonical), acknowledgement));
            control
                .next_flush()
                .await
                .send(Ok(()))
                .expect("finalized block barrier must remain pending");
            waiter.await.expect("finalized block must be acknowledged");

            // A different block at the finalized height fails verification.
            assert!(
                !mailbox
                    .verify(
                        (context.child("verify"), conflicting.context()),
                        ancestry::from_iter([digested(conflicting), digested(genesis)]),
                    )
                    .await,
                "conflicting block at the processed height must be rejected",
            );
            actor.abort();
        });
    }

    /// Ancestry that never yields a block and reports the first time it is cloned. The actor
    /// clones a verification's ancestry when it receives the request and starts acquiring its
    /// blocks, so the report shows that every message sent earlier has also been received.
    struct AcquiredAncestry(Arc<Mutex<Option<oneshot::Sender<()>>>>);

    impl AcquiredAncestry {
        /// Returns the ancestry and the signal that the actor has started acquiring it.
        fn new() -> (Self, oneshot::Receiver<()>) {
            let (acquired, receiver) = oneshot::channel();
            (Self(Arc::new(Mutex::new(Some(acquired)))), receiver)
        }
    }

    impl Clone for AcquiredAncestry {
        fn clone(&self) -> Self {
            if let Some(acquired) = self.0.lock().take() {
                let _ = acquired.send(());
            }
            Self(self.0.clone())
        }
    }

    impl Stream for AcquiredAncestry {
        type Item = Digested<TestBlock>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Ancestry<TestBlock> for AcquiredAncestry {
        fn peek(&self) -> Option<&Digested<TestBlock>> {
            None
        }
    }

    #[test]
    fn pending_proposal_does_not_block_active_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "propose-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let mut verifier = mailbox.clone();
            let verify_genesis = genesis.clone();
            let consensus_context = block.context();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([digested(block), digested(verify_genesis)]),
            ));
            let subscriber = mailbox.clone();
            assert!(poll!(&mut verify).is_pending());
            verify_started.await.expect("verification should start");

            let proposal_context = TestBlock::child(&genesis, 2).context();
            let mut proposal = Box::pin(mailbox.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([digested(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");

            // The build queues the database subscription. A later verification starts acquiring
            // its blocks once the actor has received both, so the subscription is queued before
            // the active verification completes.
            let mut databases = queue_marker(&context, &subscriber);
            assert!(poll!(&mut databases).is_pending());
            let (acquiring_ancestry, acquired) = AcquiredAncestry::new();
            let mut acquiring_verifier = subscriber.clone();
            let mut acquiring = Box::pin(acquiring_verifier.verify(
                (
                    context.child("acquiring"),
                    TestBlock::child(&TestBlock::new(0, 0), 3).context(),
                ),
                acquiring_ancestry,
            ));
            assert!(poll!(&mut acquiring).is_pending());
            acquired
                .await
                .expect("actor must start acquiring the later verification");

            // The active verification answers while the proposal remains held.
            verify_release
                .send(())
                .expect("verification should remain active");
            assert!(verify.await);
            assert!(poll!(&mut databases).is_pending());

            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            drop(databases.await);
            drop(acquiring);
            actor.abort();
        });
    }

    /// A build waiting on a verification lets that verification answer before the loop has received
    /// every queued message.
    #[test]
    fn pending_proposal_polls_ready_verification_before_ingress() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            const BACKLOG: usize = 16;

            // The build's gate holds the build until the verification answers, then records how
            // many queued verifications had been admitted.
            let admissions = Arc::new(AtomicUsize::new(0));
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_entered, proposal_started) = oneshot::channel();
            let (send_verification, verification_for_build) = oneshot::channel::<PendingRequest>();
            let (record_completion, completion) = oneshot::channel();
            let admissions_at_build = admissions.clone();
            let proposal_gate = ApplicationGate {
                started: proposal_entered,
                release: Box::pin(async move {
                    let verification = verification_for_build
                        .await
                        .expect("build must receive its verification");
                    assert!(verification.await);
                    record_completion
                        .send(admissions_at_build.load(Ordering::SeqCst))
                        .expect("test must await build completion");
                }),
            };
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mailbox, marshal, actor) =
                spawn_gated_application(&context, "build-ready-work", app).await;

            // The verification's processing is held, and the build's gate receives the pending
            // verification.
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let queued_context = block.context();
            let verification_context = (context.child("needed_verify"), block.context());
            let verify_genesis = genesis.clone();
            let mut verifier = mailbox.clone();
            let mut verification: PendingRequest = Box::pin(async move {
                verifier
                    .verify(
                        verification_context,
                        ancestry::from_iter([digested(block), digested(verify_genesis)]),
                    )
                    .await
            });
            assert!(poll!(&mut verification).is_pending());
            verify_started.await.expect("verification must start");
            assert!(send_verification.send(verification).is_ok());

            // The build starts and waits on the verification.
            let proposal_context = TestBlock::child(&genesis, 2).context();
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([digested(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("build must start");

            // Queue a backlog of verifications whose ancestry counts each attempt to acquire it.
            // Their callers stay alive so none is dropped as cancelled.
            let mut queued = Vec::with_capacity(BACKLOG);
            for _ in 0..BACKLOG {
                let mut caller = mailbox.clone();
                let request_context = (context.child("queued_verify"), queued_context.clone());
                let ancestry = PendingAncestry(admissions.clone());
                let mut request: PendingRequest =
                    Box::pin(async move { caller.verify(request_context, ancestry).await });
                assert!(poll!(&mut request).is_pending());
                queued.push(request);
            }
            assert_eq!(admissions.load(Ordering::SeqCst), 0);

            // The ready verification lets the build finish before the loop has received the whole
            // backlog.
            verify_release
                .send(())
                .expect("verification must remain active");
            let admitted = completion.await.expect("build must complete");
            assert!(
                admitted < BACKLOG,
                "ready verification must unblock the build before ingress is drained",
            );
            assert!(proposal.await.is_none());

            drop(queued);
            drop(proposer);
            drop(mailbox);
            actor.await.expect("processing actor must stop");
            drop(marshal);
        });
    }

    #[test]
    fn pending_proposal_does_not_block_new_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "propose-new-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let proposal_context = TestBlock::child(&genesis, 1).context();
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([digested(genesis.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");

            let block = TestBlock::child(&genesis, 2);
            let consensus_context = block.context();
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([digested(block), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification must start while the proposal remains pending");

            verify_release
                .send(())
                .expect("verification should remain active");
            assert!(verify.await);
            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            actor.abort();
        });
    }

    #[test]
    fn cancelled_handoff_proposal_unblocks_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (proposal_gate, proposal_started, mut proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::default(),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"cancelled-handoff", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "cancelled-handoff",
                scheme,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());
            let mut mailbox = Mailbox::new(sender);
            let mut deferred = Deferred::new(
                context.child("deferred"),
                mailbox.clone(),
                marshal.mailbox.clone(),
                FixedEpocher::new(NZU64!(u64::MAX)),
            );
            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let proposal = deferred.prepare(winner.context()).await;
            proposal_started.await.expect("proposal should start");

            // The finalization queues behind the held build. A later verification starts
            // acquiring its blocks once the actor has received both.
            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            let (acquiring_ancestry, acquired) = AcquiredAncestry::new();
            let mut acquiring_verifier = mailbox.clone();
            let mut acquiring = Box::pin(acquiring_verifier.verify(
                (
                    context.child("acquiring"),
                    TestBlock::child(&genesis, 2).context(),
                ),
                acquiring_ancestry,
            ));
            assert!(poll!(&mut acquiring).is_pending());
            acquired
                .await
                .expect("actor must start acquiring the later verification");
            assert!(poll!(&mut waiter).is_pending());
            assert!(!proposal_release.is_closed());

            drop(proposal);
            waiter
                .await
                .expect("queued finalization should be acknowledged after cancellation");
            proposal_release.closed().await;
            drop(acquiring);
            actor.abort();
            let _ = actor.await;
            marshal.abort().await;
        });
    }

    /// A proposal whose ancestor subscription ends declines at once, because marshal can no
    /// longer obtain the ancestor. Messages received while the proposal recovers its parent
    /// do not wait for it.
    #[test]
    fn incomplete_proposal_ancestry_declines() {
        // The runner budget is only a hang guard. A proposal held on its incomplete ancestry
        // would never resolve, and neither would a subscription that waited for it.
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let app = GatedApp {
                process_gates: Arc::default(),
                proposal_gate: Arc::default(),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"incomplete-proposal", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "incomplete-proposal",
                scheme,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());
            let mailbox = Mailbox::new(sender);

            // The parent's own parent is neither cached nor held by marshal, so the proposal
            // waits on marshal for it, even after marshal has answered later requests, while
            // database subscriptions received after the proposal resolve.
            let genesis = TestBlock::new(0, 0);
            let outgoing = TestBlock::child(&genesis, 1);
            let parent = TestBlock::child(&outgoing, 2);
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&parent, 3).context(),
                ),
                ancestry::from_iter([digested(parent)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            await_marshal_replies(&context, &mailbox, &marshal.mailbox).await;
            assert!(poll!(&mut proposal).is_pending());

            // Ending the ancestor subscription declines the proposal.
            marshal.abort().await;
            assert!(proposal.await.is_none(), "incomplete ancestry must decline");
            actor.abort();
            let _ = actor.await;
        });
    }

    /// A handoff build does not hold back certification of its own parent. The build is queued
    /// ahead of a finalization report, which is queued ahead of the parent's verification. The
    /// parent still verifies and certifies while the build is held, and the finalization applies
    /// once the build ends.
    #[test]
    fn parent_certification_overtakes_deferred_finalization() {
        // The runner budget is only a hang guard. The build stays held until the parent
        // certifies, so a verification that waited for the build would never start.
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (outgoing_gate, outgoing_started, outgoing_release) = application_gate();
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([outgoing_gate, parent_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"handoff-parent-certification", 1)
                .schemes[0]
                .clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "handoff-parent-certification",
                scheme,
                None,
                NZUsize!(8),
                true,
            )
            .await;
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());
            let mut mailbox = Mailbox::new(sender);
            let mut deferred = Deferred::new(
                context.child("deferred"),
                mailbox.clone(),
                marshal.mailbox.clone(),
                FixedEpocher::new(NZU64!(u64::MAX)),
            );
            let genesis = TestBlock::new(0, 0);
            let outgoing = TestBlock::child(&genesis, 1);
            let parent = TestBlock::child(&outgoing, 2);
            for block in [&outgoing, &parent] {
                assert!(
                    marshal
                        .mailbox
                        .verified(block.context().round, digested(block.clone()))
                        .await
                );
            }

            // The proposer has already verified the outgoing term's earlier block.
            let mut verifier = mailbox.clone();
            let mut verify_outgoing = Box::pin(verifier.verify(
                (context.child("outgoing"), outgoing.context()),
                ancestry::from_iter([digested(outgoing.clone()), digested(genesis.clone())]),
            ));
            assert!(poll!(&mut verify_outgoing).is_pending());
            outgoing_started
                .await
                .expect("outgoing verification should start");
            outgoing_release
                .send(())
                .expect("outgoing verification should remain active");
            assert!(verify_outgoing.await);

            // The handoff build on the uncertified parent processes the parent and is then held,
            // and a finalization report queues behind it ahead of the parent's verification.
            let mut handoff = deferred
                .prepare(TestBlock::child(&parent, 3).context())
                .await;
            parent_started
                .await
                .expect("handoff build must process its parent");
            parent_release
                .send(())
                .expect("parent processing must remain active");
            proposal_started.await.expect("handoff build should start");
            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(outgoing.clone()), acknowledgement));

            // The parent verifies and certifies from its processed state while the build is held.
            let optimistic = deferred.verify(parent.context(), parent.digest()).await;
            assert_eq!(optimistic.await, Ok(true));
            let certify = deferred
                .certify(parent.context().round, parent.digest())
                .await;
            assert_eq!(certify.await, Ok(true));
            assert!(poll!(&mut handoff).is_pending());
            assert!(poll!(&mut waiter).is_pending());

            // The deferred finalization applies once the build ends.
            proposal_release
                .send(())
                .expect("handoff build should remain active");
            waiter.await.expect("finalization should be acknowledged");
            assert!(handoff.await.expect("handoff should resolve").is_wait());
            actor.abort();
            let _ = actor.await;
            marshal.abort().await;
        });
    }

    /// Messages deferred behind a proposal run in mailbox order once it ends, while a
    /// verification queued after them starts during the proposal.
    #[test]
    fn deferred_messages_keep_mailbox_order() {
        // The runner budget is only a hang guard. The proposal stays active until the
        // verification completes, so a verification waiting for it never starts.
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let second = TestBlock::child(&first, 2);
            let other = TestBlock::child(&genesis, 3);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"deferred-order", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "deferred-order",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (proposal_gate, proposal_started, _proposal_release) = application_gate();
            let (apply_gate, apply_started, apply_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                applied_finalizations: applied_finalizations.clone(),
                ..ReplayGatedApp::new(second.height(), [apply_gate])
            }
            .with_gates(other.height(), [verify_gate]);
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            // The application holds a build on genesis until its caller cancels it.
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&genesis, 4).context(),
                ),
                ancestry::from_iter([digested(genesis.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started
                .await
                .expect("application build must start on genesis");

            // Finalizations and subscriptions queue behind the proposal, then a verification.
            let (acknowledgement, first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(first), acknowledgement));
            let first_subscriber = mailbox.clone();
            let mut first_databases = queue_marker(&context, &first_subscriber);
            assert!(poll!(&mut first_databases).is_pending());
            let (acknowledgement, mut second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(second), acknowledgement));
            let second_subscriber = mailbox.clone();
            let mut second_databases = queue_marker(&context, &second_subscriber);
            assert!(poll!(&mut second_databases).is_pending());
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), other.context()),
                ancestry::from_iter([digested(other), digested(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());

            // The verification overtakes every deferred message.
            verify_started
                .await
                .expect("verification should start during the proposal");
            verify_release
                .send(())
                .expect("verification should remain active");
            assert!(verify.await);
            assert!(poll!(&mut first_databases).is_pending());
            assert!(poll!(&mut second_databases).is_pending());
            assert!(poll!(&mut second_waiter).is_pending());
            assert!(applied_finalizations.lock().is_empty());

            // Cancelling the proposal runs the deferred messages in order. Reconstructing the
            // second finalized block holds the actor between the two subscriptions.
            drop(proposal);
            apply_started
                .await
                .expect("second finalization should start");
            assert_eq!(applied_finalizations.lock().as_slice(), [Height::new(1)]);
            assert!(poll!(&mut first_databases).is_ready());
            assert!(poll!(&mut second_databases).is_pending());
            apply_release
                .send(())
                .expect("second finalization should remain active");
            drop(second_databases.await);
            assert_eq!(
                applied_finalizations.lock().as_slice(),
                [Height::new(1), Height::new(2)]
            );
            first_waiter
                .await
                .expect("first finalization should be acknowledged");
            second_waiter
                .await
                .expect("second finalization should be acknowledged");
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// A finalization queued behind a proposal fences verifications that start after it. Work on
    /// the finalized branch continues, work on a competing branch is rejected, and finalization
    /// joins and reuses the winner's execution.
    #[test]
    fn deferred_finalization_fences_later_verifications() {
        // The runner budget is only a hang guard. The proposal stays active until processing starts
        // for the winner and the losing parent.
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let losing = TestBlock::child(&genesis, 2);
            let child = TestBlock::child(&winner, 3);
            let losing_child = TestBlock::child(&losing, 4);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"deferred-fence", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "deferred-fence",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (winner_gate, winner_started, winner_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (losing_gate, losing_started, losing_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([
                    winner_gate,
                    losing_gate,
                    child_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            // Hold a proposal and queue the winner's finalization behind it.
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&genesis, 5).context(),
                ),
                ancestry::from_iter([digested(genesis.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");
            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner.clone()), acknowledgement));

            // Verifications queued after the finalization start during the proposal. The winner's
            // verification holds the winner's processing, the child's verification waits on it,
            // and the losing child's verification holds the processing of its parent.
            let mut winner_verifier = mailbox.clone();
            let mut verify_winner = Box::pin(winner_verifier.verify(
                (context.child("verify_winner"), winner.context()),
                ancestry::from_iter([digested(winner.clone()), digested(genesis)]),
            ));
            assert!(poll!(&mut verify_winner).is_pending());
            winner_started
                .await
                .expect("winner verification should start");
            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([digested(child), digested(winner)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            let mut losing_verifier = mailbox.clone();
            let mut verify_losing = Box::pin(losing_verifier.verify(
                (context.child("verify_losing"), losing_child.context()),
                ancestry::from_iter([digested(losing_child), digested(losing)]),
            ));
            assert!(poll!(&mut verify_losing).is_pending());
            losing_started
                .await
                .expect("losing parent must be processed");
            assert!(poll!(&mut verify_child).is_pending());
            assert!(poll!(&mut waiter).is_pending());

            // Once the build answers, the loop starts the queued finalization. The finalization
            // waits for the processing of both the winner and the losing parent.
            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            assert!(poll!(&mut waiter).is_pending());
            assert!(!winner_release.is_closed());
            assert!(!losing_release.is_closed());
            winner_release.send(()).unwrap();
            losing_release.send(()).unwrap();
            waiter
                .await
                .expect("finalized winner should be acknowledged");
            assert!(!verify_losing.await, "competing branch must be rejected");
            assert!(verify_winner.await, "finalized block must be accepted");

            // The child continues from its parent's finalized state.
            child_started
                .await
                .expect("child verification must continue after the finalization");
            child_release
                .send(())
                .expect("compatible verification should remain active");
            assert!(verify_child.await);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn deferred_finalization_does_not_block_completed_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([parent_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "proposal-finalization", app).await;

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let losing_parent = TestBlock::child(&genesis, 2);
            let losing_child = TestBlock::child(&losing_parent, 3);

            let mut parent_verifier = mailbox.clone();
            let mut verify_parent = Box::pin(parent_verifier.verify(
                (context.child("verify_parent"), losing_parent.context()),
                ancestry::from_iter([digested(losing_parent.clone()), digested(genesis.clone())]),
            ));
            assert!(poll!(&mut verify_parent).is_pending());
            parent_started
                .await
                .expect("losing parent verification should start");
            parent_release
                .send(())
                .expect("losing parent verification should remain active");
            assert!(verify_parent.await);

            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&genesis, 4).context(),
                ),
                ancestry::from_iter([digested(genesis.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), losing_child.context()),
                ancestry::from_iter([digested(losing_child), digested(losing_parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("losing child verification should start");

            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));

            // The build queues the finalization. A verification of the applied genesis sent after
            // the report answers once the loop has received both.
            assert!(
                mailbox
                    .verify(
                        (context.child("verify_genesis"), genesis.context()),
                        ancestry::from_iter([digested(genesis)]),
                    )
                    .await,
                "the applied genesis must verify during the build",
            );
            assert!(poll!(&mut waiter).is_pending());

            child_release
                .send(())
                .expect("losing child verification should remain active");
            assert!(
                verify_child.await,
                "completed branch-relative verification must remain valid",
            );

            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            waiter
                .await
                .expect("conflicting finalized block should be acknowledged");
            actor.abort();
        });
    }

    #[test]
    fn finalization_keeps_compatible_verification_active() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([parent_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "finalize-compatible", app).await;

            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let mut parent_verifier = mailbox.clone();
            let parent_genesis = genesis.clone();
            let parent_context = parent.context();
            let mut verify_parent = Box::pin(parent_verifier.verify(
                (context.child("verify_parent"), parent_context),
                ancestry::from_iter([digested(parent.clone()), digested(parent_genesis)]),
            ));
            assert!(poll!(&mut verify_parent).is_pending());
            parent_started
                .await
                .expect("parent verification should start");
            parent_release
                .send(())
                .expect("parent verification should remain active");
            assert!(verify_parent.await);

            let child_context = child.context();
            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child_context),
                ancestry::from_iter([digested(child), digested(parent.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("child verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(parent), acknowledgement));
            waiter.await.expect("finalized parent must be acknowledged");
            child_release
                .send(())
                .expect("compatible verification should remain active");
            assert!(verify_child.await);
            actor.abort();
        });
    }

    /// Finalization does not wait for a verification on a losing fork, which fails once its
    /// processing ends.
    #[test]
    fn finalization_proceeds_past_incompatible_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (fork_gate, fork_started, fork_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([fork_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "finalize-incompatible", app).await;

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let losing_parent = TestBlock::child(&genesis, 2);
            let losing_child = TestBlock::child(&losing_parent, 3);
            let mut fork_verifier = mailbox.clone();
            let fork_genesis = genesis.clone();
            let fork_context = losing_parent.context();
            let mut verify_fork = Box::pin(fork_verifier.verify(
                (context.child("verify_fork"), fork_context),
                ancestry::from_iter([digested(losing_parent.clone()), digested(fork_genesis)]),
            ));
            assert!(poll!(&mut verify_fork).is_pending());
            fork_started.await.expect("fork verification should start");
            fork_release
                .send(())
                .expect("fork verification should remain active");
            assert!(verify_fork.await);

            let child_context = losing_child.context();
            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child_context),
                ancestry::from_iter([digested(losing_child), digested(losing_parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("losing child verification should start");

            // The winner applies while the losing processing is still held.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            waiter.await.expect("winning block should be acknowledged");

            // The released processing is stale, and the verification starts over and fails.
            assert!(!child_release.is_closed());
            child_release.send(()).unwrap();
            assert!(
                !verify_child.await,
                "verification on a finalized-away fork must fail",
            );
            actor.abort();
        });
    }

    /// A verification three blocks deep on a losing fork never votes `true` after the winner
    /// applies. Without the fork's ancestors it abstains.
    #[test]
    fn finalization_abstains_on_deep_incompatible_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (grandchild_gate, grandchild_started, grandchild_release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([
                    parent_gate,
                    child_gate,
                    grandchild_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "finalize-deep-incompatible", app).await;

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let losing_parent = TestBlock::child(&genesis, 2);
            let losing_child = TestBlock::child(&losing_parent, 3);
            let losing_grandchild = TestBlock::child(&losing_child, 4);

            let mut parent_verifier = mailbox.clone();
            let mut verify_parent = Box::pin(parent_verifier.verify(
                (context.child("verify_parent"), losing_parent.context()),
                ancestry::from_iter([digested(losing_parent.clone()), digested(genesis.clone())]),
            ));
            assert!(poll!(&mut verify_parent).is_pending());
            parent_started
                .await
                .expect("losing parent verification should start");
            parent_release
                .send(())
                .expect("losing parent verification should remain active");
            assert!(verify_parent.await);

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), losing_child.context()),
                ancestry::from_iter([digested(losing_child.clone()), digested(losing_parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("losing child verification should start");
            child_release
                .send(())
                .expect("losing child verification should remain active");
            assert!(verify_child.await);

            let mut grandchild_verifier = mailbox.clone();
            let mut verify_grandchild = Box::pin(grandchild_verifier.verify(
                (
                    context.child("verify_grandchild"),
                    losing_grandchild.context(),
                ),
                ancestry::from_iter([digested(losing_grandchild), digested(losing_child.clone())]),
            ));
            assert!(poll!(&mut verify_grandchild).is_pending());
            grandchild_started
                .await
                .expect("losing grandchild verification should start");

            // The winner applies while the losing processing is still held.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            waiter.await.expect("winning block should be acknowledged");

            // The released processing is stale, and the verification starts over. Its new
            // acquisition needs the losing parent, which this marshal cannot serve, so it never
            // votes `true` and abstains until its caller drops it.
            assert!(!grandchild_release.is_closed());
            grandchild_release.send(()).unwrap();
            context.sleep(Duration::from_millis(10)).await;
            assert!(poll!(&mut verify_grandchild).is_pending());
            drop(verify_grandchild);
            actor.abort();
        });
    }

    #[test]
    fn anchor_redelivery_keeps_retained_verification_progressing() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&finalized, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"skip-finalized", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "skip-finalized",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let (verify_gate, verify_started, verify_release) = application_gate();
            let process_calls = ProcessCalls::default();
            let capture_calls = Arc::new(AtomicUsize::new(0));
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                process_calls: process_calls.clone(),
                capture_calls: capture_calls.clone(),
                applied_finalizations: applied_finalizations.clone(),
                ..ReplayGatedApp::new(child.height(), [verify_gate])
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(1, 1),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            let mut verifier = mailbox.clone();
            let mut verify_child = Box::pin(verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([digested(child), digested(finalized.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            verify_started
                .await
                .expect("child verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(finalized.clone()), acknowledgement));
            waiter
                .await
                .expect("redelivered anchor should be acknowledged");

            assert!(
                poll!(&mut verify_child).is_pending(),
                "anchor redelivery must not resolve a retained verification",
            );
            verify_release
                .send(())
                .expect("child verification should remain active");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(valid);
            assert_eq!(process_calls.at(finalized.height()), 0);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
            assert!(applied_finalizations.lock().is_empty());
        });
    }

    #[test]
    fn fresh_boot_genesis_skips_hooks() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"fresh-boot-genesis", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "fresh-boot-genesis",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let process_calls = ProcessCalls::default();
            let capture_calls = Arc::new(AtomicUsize::new(0));
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                process_calls: process_calls.clone(),
                capture_calls: capture_calls.clone(),
                applied_finalizations: applied_finalizations.clone(),
                ..ReplayGatedApp::new(genesis.height(), [])
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(genesis.clone()), acknowledgement));
            waiter.await.expect("genesis should be acknowledged");

            assert_eq!(process_calls.at(genesis.height()), 0);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 0);
            assert!(applied_finalizations.lock().is_empty());
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn deferred_verification_resumes_after_sync() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                process_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                process_valid: true,
                observed_contexts: Arc::default(),
            };
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"deferred-verify", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "deferred-verify",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );

            // Defer a verification as the syncing actor does before its
            // database set is ready.
            let (sender, mut receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let deferred = context.child("deferred").spawn(move |task_context| {
                let consensus_context = block.context();
                async move {
                    mailbox
                        .verify(
                            (task_context, consensus_context),
                            ancestry::from_iter([digested(block), digested(genesis)]),
                        )
                        .await
                }
            });
            let request = match receiver.recv().await {
                Some(Message::Verify(request)) => request,
                _ => panic!("deferred verification request must arrive"),
            };

            // Resume the deferred verification after state sync.
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: vec![request],
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            started.await.expect("deferred verification should resume");
            release
                .send(())
                .expect("deferred verification should remain active");
            assert!(
                deferred
                    .await
                    .expect("deferred verification should resolve")
            );
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// Finalization reuses a parent's shared execution, then its waiting children continue.
    #[test]
    fn finalization_reuses_shared_parent_recovery() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let first_child = TestBlock::child(&parent, 2);
            let second_child = TestBlock::child(&parent, 3);
            let (gate, apply_started, apply_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                ..ReplayGatedApp::new(parent.height(), [gate])
            }
            .with_gates(first_child.height(), [verify_gate]);
            let process_calls = app.process_calls.clone();
            let (mut mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "finalize-replay", &genesis, app).await;

            // Both children's verifications share one execution of their missing parent, and the
            // gate holds it.
            let consensus_context = first_child.context();
            let mut first_verifier = mailbox.clone();
            let mut first = Box::pin(first_verifier.verify(
                (context.child("first_verify"), consensus_context.clone()),
                ancestry::from_iter([digested(first_child), digested(parent.clone())]),
            ));
            let mut second_verifier = mailbox.clone();
            let mut second = Box::pin(second_verifier.verify(
                (context.child("second_verify"), consensus_context),
                ancestry::from_iter([digested(second_child), digested(parent.clone())]),
            ));
            assert!(poll!(&mut first).is_pending());
            assert!(poll!(&mut second).is_pending());
            apply_started.await.expect("replay must start");

            // A verification whose ancestry never yields a block reports when finalization pauses
            // its acquisition.
            let (unavailable, _gate, _) = GatedAncestry::new([]);
            let mut prober = mailbox.clone();
            let mut acquiring = Box::pin(
                prober.verify((context.child("acquiring"), parent.context()), unavailable),
            );
            assert!(poll!(&mut acquiring).is_pending());

            // Once finalization pauses the acquisition, it waits for the shared parent execution to
            // finish and then reuses it.
            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(parent.clone()), acknowledgement));
            // Let the actor run until finalization waits.
            context.sleep(Duration::from_millis(10)).await;
            assert!(!apply_release.is_closed());
            assert!(poll!(&mut waiter).is_pending());
            apply_release.send(()).unwrap();
            finalized_started
                .await
                .expect("finalization hook must start");
            finalized_release
                .send(())
                .expect("finalization hook must remain active");
            waiter.await.expect("finalized parent must be acknowledged");

            // The waiting verifications process their blocks on the finalized state.
            verify_started
                .await
                .expect("waiting verification must process its block");
            verify_release
                .send(())
                .expect("waiting verification must remain active");
            assert!(first.await);
            assert!(second.await);
            assert_eq!(process_calls.at(parent.height()), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// A descendant request advances across consecutive finalizations without repeating its
    /// completed ancestor execution.
    #[rstest::rstest]
    #[case::verify(Managed::Verify)]
    #[case::propose(Managed::Propose)]
    fn consecutive_finalizations_preserve_descendant_replay(#[case] request: Managed) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let second = TestBlock::child(&first, 2);
            let child = TestBlock::child(&second, 3);
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"finalize-previous-replay", 1)
                .schemes[0]
                .clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "finalize-previous-replay",
                scheme,
                &first,
                NZUsize!(1),
                true,
            )
            .await;

            // A build on `child` needs its parent available through marshal.
            assert!(
                marshal
                    .mailbox
                    .verified(second.context().round, digested(second.clone()))
                    .await
            );

            let (replay_gate, replay_started, replay_release) = application_gate();
            let app = ReplayGatedApp::new(first.height(), [replay_gate]);
            let (gates, process_calls) = (app.gates.clone(), app.process_calls.clone());
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            // A verification of the child or a build on it recovers the child's ancestors.
            let mut descendant = send_managed(
                &context,
                &mailbox,
                request,
                vec![digested(child.clone()), digested(second.clone())],
            );
            assert!(poll!(&mut descendant).is_pending());
            replay_started
                .await
                .expect("the first block's replay must start");

            // An independent verification of the first block joins its replay, so it is still
            // pending once the loop has answered a later database subscription.
            let mut first_verifier = mailbox.clone();
            let mut verify_first = Box::pin(first_verifier.verify(
                (context.child("verify_first"), first.context()),
                ancestry::from_iter([digested(first.clone()), digested(genesis)]),
            ));
            assert!(poll!(&mut verify_first).is_pending());
            processing_fence(&context, &mailbox).await;
            assert!(poll!(&mut verify_first).is_pending());

            // The descendant's own processing is held once its ancestors are recovered.
            let (gate, verify_started, verify_release) = application_gate();
            gates
                .lock()
                .entry(child.height())
                .or_default()
                .push_back(gate);

            // A verification whose ancestry never yields a block reports when finalization pauses
            // its acquisition.
            let (unavailable, _gate, _) = GatedAncestry::new([]);
            let mut prober = mailbox.clone();
            let mut acquiring =
                Box::pin(prober.verify((context.child("acquiring"), first.context()), unavailable));
            assert!(poll!(&mut acquiring).is_pending());

            // Once the first finalization pauses the acquisition, it waits for the shared execution
            // to finish and reuses it, then the descendant advances.
            let (acknowledgement, mut first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(first.clone()), acknowledgement));
            // Let the actor run until finalization waits.
            context.sleep(Duration::from_millis(10)).await;
            assert!(!replay_release.is_closed());
            assert!(poll!(&mut first_waiter).is_pending());
            replay_release.send(()).unwrap();
            first_waiter
                .await
                .expect("first finalized block must be acknowledged");
            assert!(verify_first.await);
            verify_started
                .await
                .expect("descendant processing must start");
            assert!(poll!(&mut descendant).is_pending());

            // The second finalization keeps the descendant's processing running, and the request
            // then completes.
            let (acknowledgement, second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(second.clone()), acknowledgement));
            second_waiter
                .await
                .expect("second finalized block must be acknowledged");
            verify_release
                .send(())
                .expect("descendant processing must remain active");
            let valid = descendant.await;
            actor.abort();
            drop(marshal.guards);
            assert!(
                valid,
                "descendant replay must remain valid across consecutive finalizations",
            );
            assert_eq!(process_calls.at(first.height()), 1);
            assert_eq!(process_calls.at(second.height()), 1);
        });
    }

    /// Pruning waits for the flush that covers its target without waiting for newer state.
    #[test]
    fn prune_starts_after_target_barrier() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Marshal only receives prune requests here. Its actor never runs.
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, _subscriber, _marshal, _actor) =
                spawn_processing_with_gates(
                    &context,
                    "gated-prune",
                    Some(PruneConfig {
                        maintenance_interval: NZUsize!(1),
                        retained_marshal_blocks: 0,
                        retained_qmdb_blocks: 0,
                    }),
                    VecDeque::from([verify_gate]),
                    None,
                )
                .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let block3 = TestBlock::child(&block2, 3);

            // Apply blocks 1 and 2 without releasing any flush: the loop must
            // stay live (both blocks applied) while no acknowledgement fires.
            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block1), acknowledgement));
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block2.clone()), acknowledgement));

            // Queue a verification before pruning starts, then hold it in the
            // application until the prune is waiting on durability.
            let consensus_context = block3.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([digested(block3), digested(block2)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should start before pruning");

            // Block 2 filled the retention window, but once both blocks are applied, pruning stays
            // blocked behind the target at block 1.
            control.applied_at_least(2).await;
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(control.pruned.lock().is_empty());
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must wait for pending flushes",
            );
            verify_release
                .send(())
                .expect("verification should remain active");
            assert!(
                verify.await,
                "pending prune must not block active verification",
            );
            assert!(control.pruned.lock().is_empty());

            // Releasing block 1 makes the prune target durable. Stateful prunes before starting the
            // tracked successor for replayable block 2.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            control.pruned_at_least(1).await;
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            assert!(
                poll!(&mut waiter2).is_pending(),
                "block 2 must stay unacknowledged while its flush is pending",
            );

            // Releasing block 2's flush releases its acknowledgement.
            let _ = control.next_flush().await.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    #[test]
    fn finalized_handoff_survives_pending_barrier() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"handoff-barrier-order", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "handoff-barrier-order",
                scheme,
                None,
                NZUsize!(2),
                false,
            )
            .await;
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let capture_calls = Arc::new(AtomicUsize::new(0));
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                capture_calls: capture_calls.clone(),
                applied_finalizations: applied_finalizations.clone(),
                ..ReplayGatedApp::new(block1.height(), [])
            };
            let control = FlushControl::default();
            let processor = Processor::new(
                app,
                Single::from(TestDb::gated(control.clone())),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
                crate::stateful::db::Publisher::new(&context).0,
                Sequential,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(2));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                processor,
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block1), acknowledgement));
            finalized_started
                .await
                .expect("finalized handoff should start");
            assert_eq!(control.applied.load(Ordering::Relaxed), 1);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
            assert_eq!(applied_finalizations.lock().as_slice(), &[Height::new(1)]);
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(poll!(&mut waiter1).is_pending());

            finalized_release
                .send(())
                .expect("finalized handoff should remain active");

            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block2), acknowledgement));
            control.applied_at_least(2).await;
            assert_eq!(capture_calls.load(Ordering::SeqCst), 2);
            assert_eq!(
                applied_finalizations.lock().as_slice(),
                &[Height::new(1), Height::new(2)],
            );
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(poll!(&mut waiter1).is_pending());
            assert!(poll!(&mut waiter2).is_pending());

            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("first barrier should remain pending");
            waiter1.await.expect("block 1 should be acknowledged");
            assert!(poll!(&mut waiter2).is_pending());

            control
                .next_flush()
                .await
                .send(Ok(()))
                .expect("successor barrier should remain pending");
            waiter2.await.expect("block 2 should be acknowledged");

            actor.abort();
            drop(marshal.guards);
        });
    }

    /// A redelivered receipt for an applied height waits for the flush that covers it.
    #[rstest::rstest]
    #[case::success(true)]
    #[case::failure(false)]
    fn duplicate_reports_wait_for_durability(#[case] succeeds: bool) {
        panicking_runner().start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "duplicate-durability", None).await;

            // Apply block 1 with its flush held, then report it again.
            let first = TestBlock::child(&TestBlock::new(0, 0), 1);
            let (ack, _waiter) = Exact::handle();
            mailbox.report(Update::Block(digested(first.clone()), ack));
            processing_fence(&context, &mailbox).await;
            let (ack, mut duplicate) = Exact::handle();
            mailbox.report(Update::Block(digested(first.clone()), ack));

            // The subscription is a FIFO fence after both reports have been handled.
            processing_fence(&context, &mailbox).await;
            assert_eq!(control.applied.load(Ordering::Relaxed), 1);
            assert!(poll!(&mut duplicate).is_pending());
            assert_eq!(control.flushes.lock().len(), 1);

            let release = control.flushes.lock().remove(0);
            if !succeeds {
                // A flush that ends without durability while running panics, which cancels the
                // duplicate receipt.
                drop(release);
                assert!(actor.await.is_err(), "an aborted flush must panic");
                assert!(duplicate.await.is_err());
                return;
            }

            // A successful flush releases the duplicate without applying block 1 again.
            release.send(Ok(())).unwrap();
            duplicate.await.unwrap();
            assert!(control.flushes.lock().is_empty());
            assert_eq!(control.applied.load(Ordering::Relaxed), 1);
            actor.abort();
            let _ = actor.await;
        });
    }

    /// A live floor redelivers an applied suffix. Fresh receipts wait for the flushes that cover
    /// their heights, and verification of the tip's child continues undisturbed.
    #[rstest::rstest]
    #[case::unprocessed_genesis(1, false)]
    #[case::same_start(1, true)]
    #[case::forward_start(2, true)]
    fn live_floor_fences_suffix_ack(#[case] floor_height: u64, #[case] genesis_processed: bool) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let fixture =
                scheme_mocks::fixture(&mut signing, b"_COMMONWARE_GLUE_PROCESSING_LIVE_FLOOR", 1);

            // Build the chain through F+2 and the finalization that installs F.
            let mut blocks = vec![TestBlock::new(0, 0)];
            for view in 1..=floor_height + 2 {
                blocks.push(TestBlock::child(
                    blocks.last().unwrap(),
                    view.try_into().unwrap(),
                ));
            }
            let floor_finalization = fixtures::finalization(
                &fixture,
                floor_height,
                blocks[floor_height as usize].digest(),
            );

            // These are the receipts the observer still holds when the floor is installed.
            let heights: Vec<_> = blocks[usize::from(genesis_processed)..]
                .iter()
                .map(|block| block.height())
                .collect();
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mailbox = Mailbox::<_, GatedApp>::new(sender);

            // The fanout observer keeps Marshal behind the durable application anchor.
            let observer = fixtures::FixtureReporter::new(false);
            let marshal = fixtures::marshal_fixture_with_reporter(
                context.child("marshal"),
                "floor-redelivery",
                fixture.schemes[0].clone(),
                heights.len().try_into().unwrap(),
                Reporters::from((mailbox.clone(), observer.clone())),
            )
            .await;

            // Gate every database flush and the first verification.
            let control = FlushControl::default();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let observed_contexts = Arc::default();
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                processor: Processor::new(
                    GatedApp {
                        process_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                        proposal_gate: Arc::default(),
                        process_valid: true,
                        observed_contexts: Arc::clone(&observed_contexts),
                    },
                    Single::from(TestDb::gated(control.clone())),
                    anchor(0, 0),
                    StatefulMetrics::new(&context),
                    None,
                    crate::stateful::db::Publisher::new(&context).0,
                    Sequential,
                ),
                deferred_verifications: Vec::new(),
            };
            let actor = context.child("loop").spawn(move |_| processing.run());

            // Marshal reports genesis on startup. Cases with a processed genesis acknowledge it.
            assert_eq!(marshal.mailbox.get_processed().await, None);
            processing_fence(&context, &mailbox).await;
            assert_eq!(observer.pending_ack_heights(), [Height::zero()]);
            if genesis_processed {
                assert_eq!(observer.acknowledge_next(), Some(Height::zero()));
                assert_eq!(
                    marshal.mailbox.get_processed().await,
                    Some(Processed::Block(Height::zero()))
                );
            }

            // Finalize blocks 1 through F+2. Flushes through F are released, so F+1 and F+2
            // are applied but not durable.
            let mut ingress = marshal.mailbox.clone();
            for block in &blocks[1..] {
                assert!(
                    ingress
                        .verified(block.context().round, digested(block.clone()))
                        .await
                );
                let finalization = if block.height().get() == floor_height {
                    floor_finalization.clone()
                } else {
                    fixtures::finalization(&fixture, block.height().get(), block.digest())
                };
                ingress.report(Activity::Finalization(finalization));
                let _ = marshal.mailbox.get_processed().await;
                processing_fence(&context, &mailbox).await;
                assert_eq!(control.flushes.lock().len(), 1);
                if block.height().get() <= floor_height {
                    control.flushes.lock().remove(0).send(Ok(())).unwrap();
                    processing_fence(&context, &mailbox).await;
                }
            }

            // The observer holds every receipt, so marshal has not advanced.
            assert_eq!(observer.pending_ack_heights(), heights);
            assert_eq!(
                marshal.mailbox.get_processed().await,
                genesis_processed.then_some(Processed::Block(Height::zero()))
            );

            assert_eq!(
                control.applied.load(Ordering::Relaxed),
                floor_height as usize + 2
            );
            assert_eq!(control.flushes.lock().len(), 1);

            // A child of the applied tip remains valid while older heights are redelivered.
            let tip = blocks.last().unwrap();
            let child = TestBlock::child(tip, (floor_height + 3).try_into().unwrap());
            let mut verifier = mailbox.clone();
            let mut verify_child = Box::pin(verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([digested(child), digested(tip.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            verify_started
                .await
                .expect("child verification should start");

            // Installing F records F-1 as processed and redelivers F through F+2 with fresh
            // receipts. Nothing is applied again and no flush is added.
            marshal.mailbox.set_floor(floor_finalization);
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(floor_height - 1)))
            );
            processing_fence(&context, &mailbox).await;
            let mut expected = heights.clone();
            expected.extend((floor_height..=floor_height + 2).map(Height::new));
            assert_eq!(observer.pending_ack_heights(), expected);
            assert_eq!(
                control.applied.load(Ordering::Relaxed),
                floor_height as usize + 2
            );
            assert_eq!(control.flushes.lock().len(), 1);

            // The verification survives the redelivery and is not restarted.
            assert!(poll!(&mut verify_child).is_pending());
            verify_release
                .send(())
                .expect("redelivery must retain the active verification");
            assert!(verify_child.await);
            assert_eq!(observed_contexts.lock().len(), 1);

            // Release the observer's copies of the receipts from before the floor.
            for height in heights {
                assert_eq!(observer.acknowledge_next(), Some(height));
            }

            // Retired receipts cannot advance the active processed prefix.
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(floor_height - 1)))
            );

            // Release the observer's copies of the fresh receipts. Stateful still holds F+1 and
            // F+2.
            for height in floor_height..=floor_height + 2 {
                assert_eq!(observer.acknowledge_next(), Some(Height::new(height)));
            }

            // The floor block is durable. Its two successors await separate flushes.
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(floor_height)))
            );

            // Releasing F+1's flush acknowledges it and starts the flush for F+2.
            control.flushes.lock().remove(0).send(Ok(())).unwrap();
            processing_fence(&context, &mailbox).await;
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(floor_height + 1))),
            );
            assert_eq!(control.flushes.lock().len(), 1);

            // Releasing F+2's flush acknowledges it without applying any block again.
            control.flushes.lock().remove(0).send(Ok(())).unwrap();
            processing_fence(&context, &mailbox).await;
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(floor_height + 2))),
            );
            assert_eq!(
                control.applied.load(Ordering::Relaxed),
                floor_height as usize + 2
            );
            assert!(control.flushes.lock().is_empty());
            actor.abort();
            let _ = actor.await;
            marshal.abort().await;
        });
    }

    /// A live floor above the successor of the applied tip makes marshal deliver a block that
    /// skips an unapplied height. Processing panics instead of applying it.
    #[test]
    #[should_panic(expected = "finalized block skips unapplied heights")]
    fn live_floor_skip_panics() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let fixture =
                scheme_mocks::fixture(&mut signing, b"_COMMONWARE_GLUE_PROCESSING_SKIP", 1);

            // Build the chain through the floor block, two heights above genesis.
            let genesis = TestBlock::new(0, 0);
            let floor = TestBlock::child(&TestBlock::child(&genesis, 1), 2);

            // Marshal delivers finalized blocks to processing anchored at genesis.
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mailbox = Mailbox::<_, GatedApp>::new(sender);
            let marshal = fixtures::marshal_fixture_with_reporter(
                context.child("marshal"),
                "live-floor-skip",
                fixture.schemes[0].clone(),
                NZUsize!(1),
                mailbox.clone(),
            )
            .await;
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                processor: Processor::new(
                    GatedApp {
                        process_gates: Arc::default(),
                        proposal_gate: Arc::default(),
                        process_valid: true,
                        observed_contexts: Arc::default(),
                    },
                    test_databases(),
                    anchor(0, 0),
                    StatefulMetrics::new(&context),
                    None,
                    crate::stateful::db::Publisher::new(&context).0,
                    Sequential,
                ),
                deferred_verifications: Vec::new(),
            };
            let _actor = context.child("loop").spawn(move |_| processing.run());

            // Genesis is the applied tip, so its startup delivery is acknowledged.
            while marshal.mailbox.get_processed().await != Some(Processed::Block(Height::zero())) {}

            // Installing the floor records the never-stored height 1 as processed, then delivers
            // the floor block.
            assert!(
                marshal
                    .mailbox
                    .verified(floor.context().round, digested(floor.clone()))
                    .await
            );
            marshal
                .mailbox
                .set_floor(fixtures::finalization(&fixture, 2, floor.digest()));
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Absent(Height::new(1)))
            );

            // Processing handles the floor block before this request and panics.
            processing_fence(&context, &mailbox).await;
        });
    }

    #[test]
    fn stable_leader_finalizations_coalesce_while_barrier_pending() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, _actor) =
                spawn_processing(&context, "gated-coalesced-barrier", None).await;

            const BLOCKS: u64 = 3;

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let release1 = control.next_flush().await;

            let mut waiters = Vec::with_capacity(BLOCKS as usize - 1);
            let mut parent = TestBlock::new(1, 1);
            for height in 2..=BLOCKS {
                let block = TestBlock::child(&parent, height as u8);
                let (acknowledgement, waiter) = Exact::handle();
                let _ = mailbox.report(Update::Block(digested(block.clone()), acknowledgement));
                waiters.push(waiter);
                parent = block;
            }
            control.applied_at_least(BLOCKS as usize).await;

            assert!(
                control.flushes.lock().is_empty(),
                "a pending barrier must coalesce later finalized state instead of starting a second barrier",
            );
            assert!(poll!(&mut waiter1).is_pending());
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }

            release1
                .send(Ok(()))
                .expect("first barrier should remain pending");
            waiter1.await.expect("first block acknowledgement");
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }

            let release2 = control.next_flush().await;
            assert!(
                control.flushes.lock().is_empty(),
                "one successor barrier must cover every coalesced block",
            );
            release2
                .send(Ok(()))
                .expect("successor barrier should remain pending");
            for acknowledgement in futures::future::join_all(waiters).await {
                acknowledgement.expect("stable-leader block acknowledgement");
            }
            assert!(control.flushes.lock().is_empty());
        });
    }

    #[test]
    fn successor_barrier_drives_verification_holding_database_read() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, _marshal, _actor) = spawn_read_gated_processing(
                &context,
                "successor-barrier-read-owner",
                verify_gate,
                None,
            )
            .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block1.clone()), acknowledgement));
            let release1 = control.next_flush().await;

            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block2.clone()), acknowledgement));
            control.applied_at_least(2).await;

            let block3 = TestBlock::child(&block2, 3);
            let consensus_context = block3.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([digested(block3), digested(block2)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should acquire the database read");

            release1
                .send(Ok(()))
                .expect("first barrier should remain pending");
            waiter1.await.expect("first block acknowledgement");
            assert!(poll!(&mut waiter2).is_pending());

            // The successor barrier waits for the read lock while it keeps polling the verification
            // that holds it, so the verification can finish and the barrier can then flush.
            verify_release
                .send(())
                .expect("verification should remain active");
            assert!(verify.await, "the read-holding verification must pass");

            control
                .next_flush()
                .await
                .send(Ok(()))
                .expect("successor barrier should remain pending");
            waiter2.await.expect("second block acknowledgement");
        });
    }

    #[test]
    fn shutdown_preempts_successor_barrier_waiting_for_verification_reader() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (verify_gate, verify_started, _verify_release) = application_gate();
            let (mut mailbox, control, _marshal, actor) = spawn_read_gated_processing(
                &context,
                "successor-barrier-shutdown",
                verify_gate,
                None,
            )
            .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block1.clone()), acknowledgement));
            let release1 = control.next_flush().await;

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(block2.clone()), acknowledgement));
            control.applied_at_least(2).await;

            let block3 = TestBlock::child(&block2, 3);
            let mut verifier = mailbox.clone();
            let verify = verifier.verify(
                (context.child("verify"), block3.context()),
                ancestry::from_iter([digested(block3), digested(block2)]),
            );
            futures::pin_mut!(verify);
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should acquire the database read");

            release1
                .send(Ok(()))
                .expect("first barrier should remain pending");
            waiter1.await.expect("first block acknowledgement");

            let stopper = context.child("stopper");
            let stop = context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, Some(Duration::from_millis(100))).await });
            assert!(
                stop.await.expect("stop task should finish").is_ok(),
                "shutdown must preempt successor barrier acquisition",
            );
            actor.await.expect("processing actor should stop cleanly");
            assert!(
                waiter2.await.is_err(),
                "shutdown must cancel the dirty acknowledgement",
            );
        });
    }

    /// An aborted target flush must stop processing before pruning can discard its recovery state.
    #[test]
    fn aborted_target_flush_prevents_prune() {
        panicking_runner().start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) = spawn_processing(
                &context,
                "gated-aborted-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            control.applied_at_least(2).await;
            assert_eq!(control.flushes.lock().len(), 1);

            drop(control.flushes.lock().remove(0));
            assert!(actor.await.is_err(), "an aborted flush must panic");
            assert!(
                waiter1.await.is_err(),
                "aborted target flush must cancel the first acknowledgement",
            );
            assert!(
                waiter2.await.is_err(),
                "aborted target flush must cancel the second acknowledgement",
            );
            assert!(
                control.pruned.lock().is_empty(),
                "aborted flush must prevent pruning",
            );
        });
    }

    /// A prune publishes fresh snapshots, so serving stops pinning the pruned
    /// state.
    #[test]
    fn prune_publishes_fresh_snapshots() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, _actor) = spawn_processing(
                &context,
                "gated-prune-snapshots",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Blocks 1 and 2 fill the retention window, scheduling a prune at block 1.
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            control.applied_at_least(2).await;
            let release = control.next_flush().await;
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            control.pruned_at_least(1).await;
            assert_eq!(control.pruned.lock().clone(), vec![1]);

            // The prune publishes fresh snapshots right away. Block 2 is not yet durable, so
            // the successor sync starts at once and its capture is that publication: startup,
            // block 1's sync, then block 2's successor sync, with no separate capture.
            while publications(&context) < 3 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                subscriber.latest(),
                Some(2),
                "the fresh snapshots must serve block 2's state"
            );

            // The successor sync covers block 2's dirty suffix.
            let release = control.next_flush().await;
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            assert_eq!(publications(&context), 3);
        });
    }

    /// A prune whose applied state is already durable publishes fresh snapshots itself.
    #[test]
    fn durable_prune_publishes_fresh_snapshots() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, _actor) = spawn_processing(
                &context,
                "gated-durable-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Block 1 applies and becomes durable.
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let release = control.next_flush().await;
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");

            // Block 2 fills the retention window, scheduling a prune at block 1, and starts its
            // own flush. Startup, block 1's sync, and block 2's sync have published.
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            let release = control.next_flush().await;
            assert_eq!(publications(&context), 3);
            assert!(
                control.pruned.lock().is_empty(),
                "the prune waits for the active flush"
            );

            // Once block 2 is durable, the prune runs and publishes on its own.
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            control.pruned_at_least(1).await;
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            while publications(&context) < 4 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(subscriber.latest(), Some(2));
        });
    }

    /// Snapshots serve at apply, ahead of their flushes. Acknowledgements still
    /// release only as flushes complete.
    #[test]
    fn snapshots_serve_before_their_flushes_complete() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, _actor) =
                spawn_processing(&context, "gated-out-of-order", None).await;

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            control.applied_at_least(2).await;

            // Block 1's snapshots already published while its flush is parked.
            assert_eq!(
                subscriber.latest(),
                Some(1),
                "snapshots must serve before their flush completes",
            );
            assert!(poll!(&mut waiter1).is_pending());

            // Completing the first sync acknowledges block 1. The successor sync
            // publishes block 2's snapshots when it starts, ahead of its own flush.
            let release = control.next_flush().await;
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");

            let release = control.next_flush().await;
            assert_eq!(
                subscriber.latest(),
                Some(2),
                "the successor sync must publish block 2's snapshots at start",
            );
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    /// While the loop is idle, a completed flush must release its acknowledgement without
    /// displacing a simultaneously reported block, while an incomplete flush must cancel its
    /// acknowledgement when processing stops.
    #[test]
    fn idle_acks_follow_flush_outcome() {
        panicking_runner().start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-idle", None).await;

            // Park the loop idle with block 1's flush pending. The flush starting means the loop
            // has already reached its next blocking point.
            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let release1 = control.next_flush().await;
            assert!(poll!(&mut waiter1).is_pending());

            // Release the flush and report block 2 in the same scheduling
            // window: the completion must fire block 1's acknowledgement
            // without displacing the new message.
            let _ = release1.send(Ok(()));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            waiter1.await.expect("block 1 acknowledgement");
            let release2 = control.next_flush().await;

            // With the loop parked idle on block 2's flush, dropping its release resolves the
            // flush as shutdown. The acknowledgement is canceled so marshal stops without
            // advancing its floor past unflushed state.
            drop(release2);
            assert!(actor.await.is_err(), "an aborted flush must panic");
            assert!(
                waiter2.await.is_err(),
                "unflushed block acknowledgement must be canceled",
            );
        });
    }

    #[test]
    fn ready_aborted_flush_stops_processing() {
        panicking_runner().start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-ready-abort", None).await;

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let release1 = control.next_flush().await;

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::child(&TestBlock::new(1, 1), 2)),
                acknowledgement,
            ));
            control.applied_at_least(2).await;
            assert!(
                control.flushes.lock().is_empty(),
                "the pending barrier must cover block 2 without starting a second flush",
            );
            drop(release1);

            assert!(actor.await.is_err(), "an aborted flush must panic");
            assert!(control.flushes.lock().is_empty());
            assert!(
                waiter1.await.is_err(),
                "the active unflushed acknowledgement must be canceled",
            );
            assert!(
                waiter2.await.is_err(),
                "the queued unflushed acknowledgement must be canceled",
            );
        });
    }

    /// A prune waiting for the barrier that covers its target leaves the mailbox open.
    #[test]
    fn waiting_prune_leaves_mailbox_open() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) = spawn_processing(
                &context,
                "waiting-prune-mailbox",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Both blocks apply under block 1's held flush, so the due prune waits.
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let second = TestBlock::child(&first, 2);
            let (first_ack, first_receipt) = Exact::handle();
            let (second_ack, _second_receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(first), first_ack));
            let _ = mailbox.report(Update::Block(digested(second), second_ack));
            control.applied_at_least(2).await;

            // The loop still answers the mailbox while the prune waits.
            processing_fence(&context, &mailbox).await;
            assert!(control.pruned.lock().is_empty());
            assert_eq!(control.flushes.lock().len(), 1);

            // Completing the barrier lets the prune run.
            control.next_flush().await.send(Ok(())).unwrap();
            first_receipt.await.expect("block 1 must be acknowledged");
            control.pruned_at_least(1).await;
            actor.abort();
        });
    }

    /// The active barrier completes and acknowledges its block while a proposal build is held.
    #[test]
    fn barrier_completes_during_held_proposal() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let (mut mailbox, control, _subscriber, _marshal, actor) = spawn_processing_with_gates(
                &context,
                "barrier-during-proposal",
                None,
                VecDeque::new(),
                Some(gate),
            )
            .await;

            // Block 1 applies with its flush held.
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let (acknowledgement, receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(first.clone()), acknowledgement));
            control.applied_at_least(1).await;

            // A build on block 1 holds the loop inside the proposal.
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (
                    context.child("propose"),
                    TestBlock::child(&first, 2).context(),
                ),
                ancestry::from_iter([digested(first)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            started.await.expect("the build must start");

            // Completing the flush acknowledges block 1 while the build is still held.
            control.next_flush().await.send(Ok(())).unwrap();
            receipt
                .await
                .expect("block 1 must be acknowledged during the build");
            assert!(poll!(&mut proposal).is_pending());
            release.send(()).unwrap();
            assert!(proposal.await.is_none());
            actor.abort();
        });
    }

    /// A prune scheduled before ingress closes still runs once its target is durable, and
    /// processing then stops.
    #[test]
    fn mailbox_eof_finishes_scheduled_prune() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, marshal, actor) = spawn_processing(
                &context,
                "eof-pending-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;
            let mut actor = Box::pin(actor);
            let (mut prune_started, prune_release) = control.gate_prune();

            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let second = TestBlock::child(&first, 2);
            let (first_ack, first_receipt) = Exact::handle();
            let (second_ack, second_receipt) = Exact::handle();
            let mut first_receipt = Box::pin(first_receipt);
            let mut second_receipt = Box::pin(second_receipt);

            // Queue both reports and close ingress before yielding to the actor.
            let _ = mailbox.report(Update::Block(digested(first), first_ack));
            let _ = mailbox.report(Update::Block(digested(second), second_ack));
            drop(mailbox);

            // Both blocks apply, and the scheduled prune waits for the barrier that covers block 1.
            select! {
                result = &mut actor => {
                    panic!("actor must complete its scheduled prune before exiting: {result:?}");
                },
                _ = control.applied_at_least(2) => {},
            }

            assert!(poll!(&mut actor).is_pending());
            assert!(poll!(&mut first_receipt).is_pending());
            assert!(poll!(&mut second_receipt).is_pending());
            assert!(poll!(&mut prune_started).is_pending());
            assert!(control.pruned.lock().is_empty());
            assert_eq!(control.flushes.lock().len(), 1);

            // Completing that barrier acknowledges block 1 and starts the prune.
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("the prune target barrier must remain active after EOF");

            select! {
                result = &mut prune_started => {
                    result.expect("scheduled prune must start after its target is durable");
                },
                result = &mut actor => {
                    panic!("EOF must not discard the scheduled prune: {result:?}");
                },
            }
            first_receipt
                .await
                .expect("the durable prune target must be acknowledged");
            assert!(poll!(&mut second_receipt).is_pending());
            assert!(control.pruned.lock().is_empty());
            assert!(poll!(&mut actor).is_pending());

            // Processing stops after the prune, before any barrier makes block 2 durable, so its
            // acknowledgement is cancelled.
            prune_release
                .send(())
                .expect("scheduled prune must remain active");
            actor.await.expect("actor must stop after completing prune");
            assert_eq!(control.pruned.lock().as_slice(), [1]);
            assert!(
                second_receipt.await.is_err(),
                "EOF must cancel the newer acknowledgement without a completed barrier",
            );
            drop(marshal);
        });
    }

    /// Stopping processing with a flush in flight must cancel marshal's acknowledgement.
    #[test]
    fn shutdown_cancels_pending_flush_ack() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-shutdown", None).await;

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let release = control.next_flush().await;

            drop(mailbox);
            actor.await.expect("processing actor should stop");
            assert!(
                waiter.await.is_err(),
                "shutdown must cancel in-flight acknowledgements",
            );
            drop(release);
        });
    }

    /// A flush failure must panic the processing loop with the database identified and leave the
    /// block unacknowledged.
    #[test]
    #[should_panic(expected = "database sync failed (type")]
    fn flush_failure_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-failure", None).await;

            let (acknowledgement, _waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                digested(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let _ = control
                .next_flush()
                .await
                .send(Err(RuntimeError::WriteFailed));

            // The active barrier panics when the loop next polls it, so the runtime fails before
            // the actor can finish.
            let _ = actor.await;
            unreachable!("processing must panic on the failed flush");
        });
    }

    /// Ancestry that never yields a block and counts its clones (one per verification attempt).
    struct PendingAncestry(Arc<AtomicUsize>);

    impl Clone for PendingAncestry {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::SeqCst);
            Self(self.0.clone())
        }
    }

    impl Stream for PendingAncestry {
        type Item = Digested<TestBlock>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Ancestry<TestBlock> for PendingAncestry {
        fn peek(&self) -> Option<&Digested<TestBlock>> {
            None
        }
    }

    /// A verification whose block or parent never arrives keeps acquiring across a finalization
    /// without delaying it.
    #[rstest::rstest]
    #[case::block(false)]
    #[case::parent(true)]
    fn unavailable_ancestry_does_not_block_finalization(#[case] block_available: bool) {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _subscriber, marshal, actor) =
                spawn_processing(&context, "unavailable-ancestry", None).await;
            let parent = TestBlock::child(&TestBlock::new(0, 0), 1);
            let child = TestBlock::child(&parent, 2);

            // The ancestry never yields the block, or yields it but never its parent.
            let clones = Arc::new(AtomicUsize::new(0));
            let unavailable = PendingAncestry(clones.clone());
            let ancestry = if block_available {
                BoxedAncestry::new(ancestry::with_prefix(
                    [digested(child.clone())],
                    unavailable,
                ))
            } else {
                BoxedAncestry::new(unavailable)
            };
            let mut verifier = mailbox.clone();
            let mut verification =
                Box::pin(verifier.verify((context.child("verify"), child.context()), ancestry));
            assert!(poll!(&mut verification).is_pending());
            processing_fence(&context, &mailbox).await;
            let acquisitions = clones.load(Ordering::SeqCst);
            assert!(acquisitions > 0);

            // Finalization completes while the acquisition keeps running untouched.
            let (acknowledgement, receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(parent), acknowledgement));
            control.next_flush().await.send(Ok(())).unwrap();
            receipt.await.expect("available finalization must complete");
            assert!(poll!(&mut verification).is_pending());
            assert_eq!(clones.load(Ordering::SeqCst), acquisitions);

            drop(verification);
            drop(verifier);
            drop(mailbox);
            actor.await.expect("processing actor must stop");
            drop(marshal);
        });
    }

    /// A redelivered applied tip leaves a verification that is still acquiring its block running.
    #[test]
    fn tip_redelivery_keeps_acquiring_verification() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, _control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "tip-redelivery-acquiring", None).await;

            // Start a verification whose ancestry never yields its block.
            let clones = Arc::new(AtomicUsize::new(0));
            let block = TestBlock::child(&TestBlock::new(0, 0), 1);
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block.context()),
                PendingAncestry(clones.clone()),
            ));
            assert!(poll!(&mut verify).is_pending());
            processing_fence(&context, &mailbox).await;
            let attempts = clones.load(Ordering::SeqCst);

            // Observe the redelivery before checking that acquisition was left running.
            let (ack, waiter) = Exact::handle();
            mailbox.report(Update::Block(digested(TestBlock::new(0, 0)), ack));
            waiter.await.expect("redelivered tip must be acknowledged");
            processing_fence(&context, &mailbox).await;
            assert_eq!(
                clones.load(Ordering::SeqCst),
                attempts,
                "tip redelivery must not restart an acquiring verification",
            );
            assert!(poll!(&mut verify).is_pending());
            actor.abort();
        });
    }

    /// Blocks that become available only once the test opens the gate, and a signal for the first
    /// time an acquisition holding a clone is dropped. Maintenance drops the acquisition when it
    /// pauses it.
    #[derive(Default)]
    struct AncestryGate {
        open: bool,
        wakers: Vec<Waker>,
        parked: Option<oneshot::Sender<()>>,
    }

    impl AncestryGate {
        /// Makes the blocks available to every current and later acquisition.
        fn open(gate: &Mutex<Self>) {
            let wakers = {
                let mut gate = gate.lock();
                gate.open = true;
                std::mem::take(&mut gate.wakers)
            };
            for waker in wakers {
                waker.wake();
            }
        }
    }

    /// Ancestry held behind an [`AncestryGate`]. The caller keeps the original, and each
    /// acquisition holds a clone.
    struct GatedAncestry {
        blocks: VecDeque<Digested<TestBlock>>,
        gate: Arc<Mutex<AncestryGate>>,
        acquisition: bool,
    }

    impl GatedAncestry {
        /// Returns the ancestry, its gate, and the signal that an acquisition of it was paused.
        fn new(
            blocks: impl IntoIterator<Item = Digested<TestBlock>>,
        ) -> (Self, Arc<Mutex<AncestryGate>>, oneshot::Receiver<()>) {
            let (parked, parked_receiver) = oneshot::channel();
            let gate = Arc::new(Mutex::new(AncestryGate {
                parked: Some(parked),
                ..AncestryGate::default()
            }));
            let ancestry = Self {
                blocks: blocks.into_iter().collect(),
                gate: gate.clone(),
                acquisition: false,
            };
            (ancestry, gate, parked_receiver)
        }
    }

    impl Clone for GatedAncestry {
        fn clone(&self) -> Self {
            Self {
                blocks: self.blocks.clone(),
                gate: self.gate.clone(),
                acquisition: true,
            }
        }
    }

    impl Drop for GatedAncestry {
        fn drop(&mut self) {
            if self.acquisition
                && let Some(parked) = self.gate.lock().parked.take()
            {
                let _ = parked.send(());
            }
        }
    }

    impl Stream for GatedAncestry {
        type Item = Digested<TestBlock>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            let mut gate = this.gate.lock();
            if !gate.open {
                gate.wakers.push(cx.waker().clone());
                return Poll::Pending;
            }
            Poll::Ready(this.blocks.pop_front())
        }
    }

    impl Ancestry<TestBlock> for GatedAncestry {
        fn peek(&self) -> Option<&Digested<TestBlock>> {
            self.gate.lock().open.then(|| self.blocks.front()).flatten()
        }
    }

    /// A request admitted before an earlier caller's cancellation keeps their shared processing.
    #[test]
    fn admitted_verification_keeps_processing_alive() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let height = block.height();
            let (process_gate, process_started, process_release) = application_gate();
            let (repeat_gate, mut repeat_started, _repeat_release) = application_gate();
            let app = ReplayGatedApp::new(height, [process_gate, repeat_gate]);
            let process_calls = app.process_calls.clone();
            let (mailbox, _, guards, actor) =
                spawn_replay_gated_processing(&context, "admitted-verification", &genesis, app)
                    .await;

            let mut first_mailbox = mailbox.clone();
            let mut first = Box::pin(first_mailbox.verify(
                (context.child("first"), block.context()),
                ancestry::from_iter([digested(block.clone()), digested(genesis.clone())]),
            ));
            assert!(poll!(&mut first).is_pending());
            process_started.await.expect("first processing must start");

            let (ancestry, ancestry_gate, _parked) =
                GatedAncestry::new([digested(block.clone()), digested(genesis)]);
            let mut second_mailbox = mailbox.clone();
            let mut second = Box::pin(
                second_mailbox.verify((context.child("second"), block.context()), ancestry),
            );
            assert!(poll!(&mut second).is_pending());
            processing_fence(&context, &mailbox).await;
            assert!(
                !ancestry_gate.lock().wakers.is_empty(),
                "second acquisition must have registered its wakeup",
            );

            // Both wakeups enter the actor's ready queue in this order before it can poll.
            // Acquisition admits the second step, then cancellation removes the first holder.
            AncestryGate::open(&ancestry_gate);
            drop(first);
            processing_fence(&context, &mailbox).await;

            assert!(
                !process_release.is_closed(),
                "admitted verification must keep the original processing alive",
            );
            assert!(poll!(&mut repeat_started).is_pending());
            assert_eq!(process_calls.at(height), 1);
            process_release
                .send(())
                .expect("processing must remain alive");
            assert!(second.await);
            assert_eq!(process_calls.at(height), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// A verification whose block arrives only after the block finalized answers from the
    /// canonical chain without processing it, while a held competing execution does not delay
    /// the finalization.
    #[test]
    fn late_block_verifies_after_its_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let losing = TestBlock::child(&genesis, 1);
            let winner = TestBlock::child(&genesis, 2);
            let height = winner.height();
            let (gate, started, release) = application_gate();
            let app = ReplayGatedApp::new(height, [gate]);
            let process_calls = app.process_calls.clone();
            let finalized_calls = app.finalized_calls.clone();
            let capture_calls = app.capture_calls.clone();
            let (mut mailbox, _, guards, actor) = spawn_replay_gated_processing(
                &context,
                "paused-acquisition-restart",
                &genesis,
                app,
            )
            .await;

            // The gate holds the losing request's execution while the winner's verification waits
            // for its block.
            let mut losing_request = send_managed(
                &context,
                &mailbox,
                Managed::Verify,
                vec![digested(losing), digested(genesis.clone())],
            );
            assert!(poll!(&mut losing_request).is_pending());
            started
                .await
                .expect("losing request must execute its block");
            let (unavailable, gate, _) =
                GatedAncestry::new([digested(winner.clone()), digested(genesis)]);
            let mut verifier = mailbox.clone();
            let mut verification =
                Box::pin(verifier.verify((context.child("winner"), winner.context()), unavailable));
            assert!(poll!(&mut verification).is_pending());

            // The winner finalizes while the losing execution is held and its verification still
            // waits for the block.
            let (acknowledgement, receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(winner), acknowledgement));
            receipt.await.expect("winner must be acknowledged");

            // The block then arrives, and the acquisition finds the winner applied and verifies
            // it without processing it as a candidate. The losing execution goes stale.
            AncestryGate::open(&gate);
            assert!(verification.await);
            release.send(()).unwrap();
            assert!(!losing_request.await);
            assert_eq!(process_calls.at(height), 2);
            assert_eq!(finalized_calls.at(height), 1);
            assert_eq!(capture_calls.load(Ordering::SeqCst), 1);
            actor.abort();
            drop(guards);
        });
    }

    /// A retained step's successor with a round at or before the finalized round is rejected
    /// before the application processes it.
    #[test]
    fn finalization_rejects_next_step_with_stale_round() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let retained = TestBlock::child(&finalized, 2);
            let stale = TestBlock::child(&retained, 3).with_view(1);
            let (gate, started, release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                ..ReplayGatedApp::new(retained.height(), [gate])
            };
            let process_calls = app.process_calls.clone();
            let (mut mailbox, marshal, guards, actor) =
                spawn_replay_gated_processing(&context, "stale-round-next-step", &genesis, app)
                    .await;

            // The finalized block is cached through its verification, and marshal serves the
            // other blocks to the handoff's recovery walk.
            let mut verifier = mailbox.clone();
            assert!(
                verifier
                    .verify(
                        (context.child("verify_finalized"), finalized.context()),
                        ancestry::from_iter([
                            digested(finalized.clone()),
                            digested(genesis.clone())
                        ]),
                    )
                    .await
            );
            assert!(
                marshal
                    .verified(finalized.context().round, digested(finalized.clone()))
                    .await
            );
            assert!(
                marshal
                    .verified(retained.context().round, digested(retained.clone()))
                    .await
            );

            // The gate holds the recovery's processing of the retained block.
            let mut prepare = send_managed(
                &context,
                &mailbox,
                Managed::Prepare,
                vec![digested(stale.clone()), digested(retained.clone())],
            );
            assert!(poll!(&mut prepare).is_pending());
            started
                .await
                .expect("recovery must process the retained block");

            // Finalization retains that processing. Its hook stays open, so the retained step
            // finishes and selects the stale block while the finalization is still active.
            let (acknowledgement, receipt) = Exact::handle();
            let _ = mailbox.report(Update::Block(digested(finalized), acknowledgement));
            finalized_started
                .await
                .expect("finalization must reach its hook");
            release
                .send(())
                .expect("retained processing must remain held");
            assert!(!prepare.await, "handoff on the stale block must decline");
            finalized_release
                .send(())
                .expect("finalized hook must remain held");
            receipt.await.expect("finalized block must be acknowledged");
            assert_eq!(process_calls.at(retained.height()), 1);
            assert_eq!(process_calls.at(stale.height()), 0);
            actor.abort();
            drop(guards);
        });
    }
}
