use crate::stateful::{
    Application, Input,
    actor::{
        core::{
            mailbox::Message,
            verifications::{Handler as Verifications, Request as VerificationRequest},
        },
        processor::{Applied, Processor, Verifier},
        syncer::StateSyncMetadata,
    },
    db::DatabaseSet,
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
use commonware_cryptography::certificate::Scheme;
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_storage::Context;
use commonware_utils::{Acknowledgement as _, channel::fallible::OneshotExt};
use futures::future::{Either, pending, ready};
use rand_core::Rng;
use std::{future::Future, sync::mpsc::TryRecvError};
use tracing::{Instrument as _, debug, info_span};

enum Step<M, P> {
    Message(M),
    Prune(P),
}

fn requeue_verifications<E, A>(
    mailbox: &(dyn Fn(Message<E, A>) + Send + Sync),
    requests: Vec<VerificationRequest<E, A>>,
) where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    // FIFO puts each retry behind work accepted while the mutation ran and
    // ahead of later arrivals, without waiting for the mailbox to become idle.
    for VerificationRequest {
        span,
        context,
        ancestry,
        verification,
    } in requests
    {
        if verification.is_cancelled() {
            continue;
        }
        mailbox(Message::Verify {
            span,
            context,
            ancestry,
            verification,
        });
    }
}

fn handle_proposal_message<E, A, S, V>(
    message: Option<Message<E, A>>,
    verifications: &mut Verifications<E, A, S, V>,
    verifier: &Verifier<E, A>,
    deferred_message: &mut Option<Message<E, A>>,
) -> bool
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    match message {
        Some(Message::Verify {
            span,
            context,
            ancestry,
            verification,
        }) => {
            verifications.schedule(
                verifier.clone(),
                VerificationRequest {
                    span,
                    context,
                    ancestry,
                    verification,
                },
            );
            true
        }
        Some(message) => {
            // Only verification may overtake an active proposal. The first other
            // message remains the FIFO barrier for later mailbox work.
            *deferred_message = Some(message);
            false
        }
        None => false,
    }
}

async fn receive_proposal_message<E, A>(
    mailbox: &mut actor_mailbox::Receiver<Message<E, A>>,
    enabled: bool,
) -> Option<Message<E, A>>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    if enabled {
        mailbox.recv().await
    } else {
        pending().await
    }
}

async fn drive_proposal<E, A, S, V, P>(
    mailbox: &mut actor_mailbox::Receiver<Message<E, A>>,
    verifications: &mut Verifications<E, A, S, V>,
    verifier: Verifier<E, A>,
    deferred_message: &mut Option<Message<E, A>>,
    proposal: P,
) where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    P: Future<Output = ()>,
{
    futures::pin_mut!(proposal);
    let mut receive_messages = deferred_message.is_none();

    loop {
        select! {
            _ = &mut proposal => break,
            message = receive_proposal_message(mailbox, receive_messages) => {
                receive_messages = handle_proposal_message(
                    message,
                    verifications,
                    &verifier,
                    deferred_message,
                );
            },
            _ = verifications.next_completed() => {},
        }
    }
}

pub(super) struct Processing<E, A, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Provider cloned into each proposal.
    pub(super) provider: A::Provider,

    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// Durable base from which finalized history can reconstruct the databases.
    pub(super) sync_metadata: StateSyncMetadata<E, S, V::Commitment>,

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Verification requests deferred until processing starts.
    pub(super) deferred_verifications: Vec<VerificationRequest<E, A>>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and must not be applied again.
    pub(super) skip_finalized_until: Option<Height>,

    /// Exclusive lower bound of skipped startup-replay blocks whose application finalized hooks
    /// already ran. State-sync anchors leave this unset so their redelivery supplies the hook.
    pub(super) replayed_finalized_after: Option<Height>,
}

impl<E, A, S, V> Processing<E, A, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        let mut pending_prune = None;
        let mut deferred_message = None;
        let mut verifications = Verifications::new(self.marshal.clone());
        for request in std::mem::take(&mut self.deferred_verifications) {
            verifications.schedule(self.processor.verifier(), request);
        }
        select_loop! {
            self.context,
            on_start => {
                // Publish completed verdicts before admitting another message.
                // A later finalization cannot retroactively invalidate them.
                verifications.complete_ready();

                let message = if pending_prune.is_some() {
                    Err(TryRecvError::Empty)
                } else {
                    match deferred_message.take() {
                        Some(message) => Ok(message),
                        None => self.mailbox.try_recv(),
                    }
                };

                let next = if pending_prune.is_some() {
                    Either::Left(ready(Some(Step::Prune(
                        pending_prune.take().expect("pending prune must exist"),
                    ))))
                } else {
                    match message {
                        Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                        Err(TryRecvError::Empty) => {
                            let mailbox = &mut self.mailbox;
                            let verifications = &mut verifications;
                            Either::Right(async move {
                                loop {
                                    select! {
                                        message = mailbox.recv() => {
                                            break message.map(Step::Message);
                                        },
                                        _ = verifications.next_completed() => {
                                            continue;
                                        },
                                    }
                                }
                            })
                        }
                        Err(TryRecvError::Disconnected) => {
                            debug!("mailbox closed, stopping processing");
                            return;
                        }
                    }
                };
            },
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
            },
            Some(step) = next else {
                debug!("mailbox closed, stopping processing");
                break;
            } => match step {
                Step::Message(Message::Propose {
                        span,
                        context,
                        ancestry,
                        upstream,
                        response,
                    }) => {
                    if response.is_closed() {
                        continue;
                    }
                    let process = info_span!(parent: &span, "stateful.actor.propose");
                    let input = Input {
                        upstream,
                        provider: self.provider.clone(),
                    };
                    let verifier = self.processor.verifier();
                    let actor_context = self.context.as_present();
                    let marshal = self.marshal.clone();
                    let proposal = self
                        .processor
                        .propose(
                            actor_context,
                            marshal.clone(),
                            context,
                            ancestry,
                            input,
                            response,
                        )
                        .instrument(process);
                    drive_proposal(
                        &mut self.mailbox,
                        &mut verifications,
                        verifier,
                        &mut deferred_message,
                        proposal,
                    )
                    .await;
                }
                Step::Message(Message::Verify {
                    span,
                    context,
                    ancestry,
                    verification,
                }) => {
                    verifications.schedule(
                        self.processor.verifier(),
                        VerificationRequest {
                            span,
                            context,
                            ancestry,
                            verification,
                        },
                    );
                }
                Step::Message(Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                    retry_mailbox,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.finalized");
                    let finalized_was_replayed = self
                        .replayed_finalized_after
                        .is_some_and(|base| block.height() > base);
                    let skip = skip_finalized_block(
                        &mut self.skip_finalized_until,
                        block.height(),
                    );
                    if self.skip_finalized_until.is_none() {
                        self.replayed_finalized_after = None;
                    }
                    if skip {
                        async {
                            if !finalized_was_replayed {
                                verifications
                                    .drive(self.processor.notify_finalized(
                                        self.context.as_present(),
                                        block.as_ref(),
                                    ))
                                    .await;
                            }
                            acknowledgement.acknowledge();
                        }
                        .instrument(process)
                        .await;
                    } else {
                        let boundary = self.processor.finalization_boundary(block.as_ref());
                        let (retry, reject) = verifications
                            .quiesce_where(|progress| boundary.disposition(progress))
                            .await;
                        drop(boundary);
                        async {
                            let applied = verifications
                                .drive(self.processor.finalize_inline(&self.context, block.clone()))
                                .await;
                            let Some(Applied { prune, .. }) = applied else {
                                // Duplicate report: marshal redelivers a processed
                                // height only after a restart, where startup aligned
                                // the databases to durable state.
                                acknowledgement.acknowledge();
                                return;
                            };
                            acknowledgement.acknowledge();
                            if let Some(prune) = prune {
                                assert!(
                                    pending_prune.is_none(),
                                    "ordered finalization produced overlapping prune work",
                                );
                                pending_prune = Some((prune, retry_mailbox.clone()));
                            }
                        }
                        .instrument(process)
                        .await;
                        for verification in reject {
                            verification.respond(false);
                        }
                        requeue_verifications(retry_mailbox.as_ref(), retry);
                    }
                }
                Step::Message(Message::SubscribeDatabases { response }) => {
                    response.send_lossy(self.processor.databases().clone());
                }
                Step::Prune((prune, retry_mailbox)) => {
                    let retry = verifications.quiesce().await;
                    assert!(
                        self.processor.replays_idle(),
                        "pending-state flight remained active after quiescence"
                    );

                    let barrier = self.processor.databases().finalize().await;
                    if !barrier.durable().await {
                        return;
                    }
                    self.sync_metadata = self
                        .sync_metadata
                        .set_complete(prune.barrier_height)
                        .await;
                    prune
                        .run(self.processor.databases(), &self.marshal)
                        .await;
                    requeue_verifications(retry_mailbox.as_ref(), retry);
                }
            },
        }
    }
}

fn skip_finalized_block(skip_until: &mut Option<Height>, height: Height) -> bool {
    let Some(target) = *skip_until else {
        return false;
    };
    if height > target {
        *skip_until = None;
        return false;
    }
    if height == target {
        *skip_until = None;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{Message, Processing, VerificationRequest, skip_finalized_block};
    use crate::stateful::{
        Application, Input, Proposed, PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
            syncer::StateSyncMetadata,
        },
        db::{DatabaseSet, Shared},
        tests::{
            fixtures,
            mocks::{
                FlushControl, TestApp, TestBlock, TestDatabases, TestDb, TestMerkleized,
                TestScheme, TestUnmerkleized, anchor, test_databases,
            },
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Heightable as _, Reporter as _,
        marshal::{
            Update,
            ancestry::{self, Ancestry},
        },
        simplex::mocks::scheme as scheme_mocks,
        types::Height,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::select;
    use commonware_runtime::{
        Clock as _, ContextCell, Handle, Metrics as _, Name, Runner as _, Spawner as _,
        Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
        channel::oneshot,
        sync::Mutex,
    };
    use futures::{Stream, StreamExt as _, poll, task::AtomicWaker};
    use std::{
        collections::VecDeque,
        num::NonZeroUsize,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context as TaskContext, Poll},
        time::Duration,
    };

    struct ApplicationGate {
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    }

    #[derive(Clone)]
    struct GatedApp {
        verify_gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        proposal_gate: Arc<Mutex<Option<ApplicationGate>>>,
        verify_valid: bool,
        observed_contexts: Arc<Mutex<Vec<Name>>>,
        finalized: Arc<Mutex<Vec<u64>>>,
    }

    impl Application<deterministic::Context> for GatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("gated application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            let gate = self.proposal_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            None
        }

        async fn verify(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
            self.observed_contexts.lock().push(context.0.name());
            let mut ancestry = Box::pin(ancestry);
            let _block = ancestry.next().await?;
            let mut gate = self
                .verify_gates
                .lock()
                .pop_front()
                .expect("unexpected verification");
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
            self.verify_valid.then_some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> TestMerkleized {
            TestMerkleized
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
            self.finalized.lock().push(block.height().get());
        }
    }

    #[derive(Clone)]
    struct ReplayGatedApp {
        gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        verify_gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        finalized_gate: Arc<Mutex<Option<ApplicationGate>>>,
        gate_height: Height,
        apply_calls: Arc<AtomicUsize>,
        verify_calls: Arc<AtomicUsize>,
    }

    impl Application<deterministic::Context> for ReplayGatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("replay-gated application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            panic!("replay-gated application proposal is not used")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.verify_gates.lock().pop_front();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            Some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> TestMerkleized {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            let gate = (block.height() == self.gate_height)
                .then(|| self.gates.lock().pop_front())
                .flatten();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            TestMerkleized
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
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
                release: release_rx,
            },
            started_rx,
            release,
        )
    }

    struct ParentGate {
        started: Mutex<Option<oneshot::Sender<()>>>,
        released: AtomicBool,
        waker: AtomicWaker,
    }

    impl ParentGate {
        fn release(&self) {
            self.released.store(true, Ordering::Release);
            self.waker.wake();
        }
    }

    #[derive(Clone)]
    struct ParentGatedAncestry {
        blocks: VecDeque<Arc<TestBlock>>,
        parent_gate: Arc<ParentGate>,
        candidate_deliveries: Arc<AtomicUsize>,
    }

    impl Ancestry<TestBlock> for ParentGatedAncestry {
        fn peek(&self) -> Option<&TestBlock> {
            self.blocks.front().map(Arc::as_ref)
        }
    }

    impl Stream for ParentGatedAncestry {
        type Item = Arc<TestBlock>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            context: &mut TaskContext<'_>,
        ) -> Poll<Option<Self::Item>> {
            if self.blocks.len() == 2 {
                self.candidate_deliveries.fetch_add(1, Ordering::SeqCst);
                return Poll::Ready(self.blocks.pop_front());
            }

            if self.blocks.len() == 1 && !self.parent_gate.released.load(Ordering::Acquire) {
                if let Some(started) = self.parent_gate.started.lock().take() {
                    let _ = started.send(());
                }
                self.parent_gate.waker.register(context.waker());
                if !self.parent_gate.released.load(Ordering::Acquire) {
                    return Poll::Pending;
                }
            }

            Poll::Ready(self.blocks.pop_front())
        }
    }

    fn parent_gated_ancestry(
        candidate: TestBlock,
        parent: TestBlock,
    ) -> (
        ParentGatedAncestry,
        oneshot::Receiver<()>,
        Arc<ParentGate>,
        Arc<AtomicUsize>,
    ) {
        let (started, started_rx) = oneshot::channel();
        let parent_gate = Arc::new(ParentGate {
            started: Mutex::new(Some(started)),
            released: AtomicBool::new(false),
            waker: AtomicWaker::new(),
        });
        let candidate_deliveries = Arc::new(AtomicUsize::new(0));
        (
            ParentGatedAncestry {
                blocks: VecDeque::from([Arc::new(candidate), Arc::new(parent)]),
                parent_gate: parent_gate.clone(),
                candidate_deliveries: candidate_deliveries.clone(),
            },
            started_rx,
            parent_gate,
            candidate_deliveries,
        )
    }

    fn running_tasks_with_suffix(metrics: &str, suffix: &str) -> u64 {
        let exact_name = format!("name=\"{suffix}\"");
        let name_suffix = format!("_{suffix}\"");
        metrics
            .lines()
            .filter(|line| {
                line.starts_with("runtime_tasks_running{")
                    && (line.contains(&exact_name) || line.contains(&name_suffix))
            })
            .filter_map(|line| line.rsplit_once(' '))
            .filter_map(|(_, value)| value.trim().parse::<u64>().ok())
            .sum()
    }

    async fn test_sync_metadata(
        context: &deterministic::Context,
        prefix: &str,
    ) -> StateSyncMetadata<deterministic::Context, TestScheme, Sha256Digest> {
        StateSyncMetadata::init(context, format!("{prefix}-processing-")).await
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
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            sync_metadata: test_sync_metadata(context, prefix).await,
            processor,
            deferred_verifications: Vec::new(),
            skip_finalized_until: None,
            replayed_finalized_after: None,
        };
        let actor = context.child("loop").spawn(move |_| processing.start());
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
        Box<dyn std::any::Any>,
        Handle<()>,
    ) {
        spawn_processing_with_gates(context, prefix, prune_config, VecDeque::new(), None).await
    }

    async fn spawn_processing_with_gates(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
        verify_gates: VecDeque<ApplicationGate>,
        proposal_gate: Option<ApplicationGate>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        FlushControl,
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
        let databases = Shared::new("test", TestDb::gated(control.clone()));
        let pruning = prune_config
            .map(|config| Pruning::build(config, marshal.mailbox.max_pending_acks(), 0));
        let app = GatedApp {
            verify_gates: Arc::new(Mutex::new(verify_gates)),
            proposal_gate: Arc::new(Mutex::new(proposal_gate)),
            verify_valid: true,
            observed_contexts: Arc::default(),
            finalized: control.finalized.clone(),
        };
        let processor = Processor::new(
            app,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            sync_metadata: test_sync_metadata(context, prefix).await,
            processor,
            deferred_verifications: Vec::new(),
            skip_finalized_until: None,
            replayed_finalized_after: None,
        };
        let actor = context.child("loop").spawn(move |_| processing.start());
        (Mailbox::new(sender), control, marshal.guards, actor)
    }

    #[test]
    fn independent_verifications_do_not_block_each_other() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (first_gate, first_started, first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                            ancestry::from_iter([Arc::new(first_block), Arc::new(first_genesis)]),
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
                            ancestry::from_iter([Arc::new(second_block), Arc::new(genesis)]),
                        )
                        .await
                }
            });
            select! {
                result = second_started => {
                    result.expect("second verification should start while first remains pending");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("pending verification blocked unrelated verification");
                },
            }

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

    #[test]
    fn verification_preserves_request_attributes() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let observed_contexts = Arc::new(Mutex::new(Vec::new()));
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: observed_contexts.clone(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            {
                let observed = observed_contexts.lock();
                assert_eq!(observed.len(), 1);
                assert_eq!(
                    observed[0].attributes,
                    vec![
                        ("owner".to_string(), "request".to_string()),
                        ("round".to_string(), "request-round".to_string()),
                        ("shard".to_string(), "4".to_string()),
                    ]
                );
            }

            release.send(()).expect("verification should remain active");
            assert!(verify.await);
            actor.abort();
        });
    }

    #[test]
    fn abandoned_verification_cancels_with_caller() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "caller-cancellation", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let block_context = block.context();
            let mut verify = Box::pin(mailbox.verify(
                (context.child("caller"), block_context),
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("application task should start");

            drop(verify);
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                release.send(()).is_err(),
                "application verification should stop with its caller"
            );
            actor.abort();
        });
    }

    #[test]
    fn abandoned_incomplete_verifications_do_not_block_later_work() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (first_gate, first_started, first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "incomplete-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let mut incomplete = Box::pin(mailbox.verify(
                (context.child("empty"), block1.context()),
                ancestry::from_iter([]),
            ));
            assert!(poll!(&mut incomplete).is_pending());
            context.sleep(Duration::from_millis(10)).await;
            drop(incomplete);

            let mut first = Box::pin(mailbox.verify(
                (context.child("first"), block1.context()),
                ancestry::from_iter([Arc::new(block1.clone()), Arc::new(genesis)]),
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
                ancestry::from_iter([Arc::new(block2.clone())]),
            ));
            assert!(poll!(&mut incomplete).is_pending());
            context.sleep(Duration::from_millis(10)).await;
            drop(incomplete);

            let mut second = Box::pin(mailbox.verify(
                (context.child("second"), block2.context()),
                ancestry::from_iter([Arc::new(block2), Arc::new(block1)]),
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
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: false,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "rejected-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), block.context()),
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");
            release.send(()).expect("verification should remain active");
            assert!(!verify.await);
            actor.abort();
        });
    }

    #[test]
    fn conflicting_processed_block_is_rejected() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, _control, _marshal, actor) =
                spawn_processing(&context, "conflicting-processed", None).await;
            let genesis = TestBlock::new(0, 0);
            let canonical = TestBlock::child(&genesis, 1);
            let conflicting = TestBlock::child(&genesis, 2);

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(canonical), acknowledgement));
            waiter
                .await
                .expect("finalized block should be acknowledged");

            assert!(
                !mailbox
                    .verify(
                        (context.child("verify"), conflicting.context()),
                        ancestry::from_iter([Arc::new(conflicting), Arc::new(genesis)]),
                    )
                    .await,
                "conflicting block at the processed height must be rejected",
            );
            actor.abort();
        });
    }

    #[test]
    fn pending_proposal_does_not_block_active_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(block), Arc::new(verify_genesis)]),
            ));
            let subscriber = mailbox.clone();
            assert!(poll!(&mut verify).is_pending());
            verify_started.await.expect("verification should start");

            let proposal_context = TestBlock::child(&genesis, 2).context();
            let mut proposal = Box::pin(mailbox.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([Arc::new(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");
            let mut databases = Box::pin(subscriber.subscribe_databases());
            assert!(poll!(&mut databases).is_pending());
            context.sleep(Duration::from_millis(10)).await;
            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                result = &mut verify => {
                    assert!(result);
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("pending proposal blocked active verification");
                },
            }
            assert!(poll!(&mut databases).is_pending());

            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            drop(databases.await);
            actor.abort();
        });
    }

    #[test]
    fn pending_proposal_does_not_block_new_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "propose-new-verify", app).await;

            let genesis = TestBlock::new(0, 0);
            let proposal_context = TestBlock::child(&genesis, 1).context();
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([Arc::new(genesis.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");

            let block = TestBlock::child(&genesis, 2);
            let consensus_context = block.context();
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            select! {
                result = verify_started => {
                    result.expect("verification should start while proposal remains pending");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("pending proposal blocked new verification");
                },
            }

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
    fn deferred_finalization_does_not_block_completed_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([parent_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(losing_parent.clone()), Arc::new(genesis.clone())]),
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
                ancestry::from_iter([Arc::new(genesis)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            proposal_started.await.expect("proposal should start");

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), losing_child.context()),
                ancestry::from_iter([Arc::new(losing_child), Arc::new(losing_parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("losing child verification should start");

            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
            context.sleep(Duration::from_millis(10)).await;
            assert!(poll!(&mut waiter).is_pending());

            child_release
                .send(())
                .expect("losing child verification should remain active");
            select! {
                valid = &mut verify_child => {
                    assert!(valid, "completed branch-relative verification must remain valid");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("deferred finalization blocked completed verification");
                },
            }

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
    fn finalized_apply_is_owned_by_processing_actor() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "ordered-finalized-apply", None).await;
            let (apply_started, apply_release) = control.gate_apply();

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
            apply_started.await.expect("finalized apply should start");

            let metrics = context.encode();
            assert_eq!(
                running_tasks_with_suffix(&metrics, "finalized_flusher"),
                0,
                "finalized database apply must not escape into a detached worker: {metrics}",
            );
            assert_eq!(
                running_tasks_with_suffix(&metrics, "loop"),
                1,
                "the processing actor must own the active database apply: {metrics}",
            );

            apply_release
                .send(())
                .expect("finalized apply should remain active");
            waiter
                .await
                .expect("finalized block should be acknowledged");
            assert!(control.flushes.lock().is_empty());
            actor.abort();
        });
    }

    #[test]
    fn proposal_and_verification_wait_for_finalized_apply_flush() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, _marshal, actor) = spawn_processing_with_gates(
                &context,
                "finalized-logical-tip",
                None,
                VecDeque::from([verify_gate]),
                Some(proposal_gate),
            )
            .await;
            let (apply_started, apply_release) = control.gate_apply();

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let child = TestBlock::child(&block2, 3);
            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            apply_started.await.expect("first apply should start");
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));

            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), child.context()),
                ancestry::from_iter([Arc::new(block2.clone())]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());

            let mut verifier = mailbox.clone();
            let mut verification = Box::pin(verifier.verify(
                (context.child("verify"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(block2)]),
            ));
            assert!(poll!(&mut verification).is_pending());

            let mut proposal_started = Box::pin(proposal_started);
            let mut verify_started = Box::pin(verify_started);
            select! {
                started = &mut proposal_started => {
                    started.expect("proposal start signal should remain connected");
                    panic!("proposal entered the application while finalized apply was active");
                },
                started = &mut verify_started => {
                    started.expect("verification start signal should remain connected");
                    panic!("verification entered the application while finalized apply was active");
                },
                _ = context.sleep(Duration::from_millis(100)) => {},
            }
            assert!(poll!(&mut waiter1).is_pending());
            assert!(poll!(&mut waiter2).is_pending());
            assert_eq!(control.applied.load(Ordering::Relaxed), 0);
            assert!(control.finalized.lock().is_empty());

            apply_release
                .send(())
                .expect("first apply should remain active");

            select! {
                started = &mut proposal_started => {
                    started.expect("proposal should start after finalized apply");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("proposal did not start after finalized apply completed");
                },
            }
            select! {
                started = &mut verify_started => {
                    started.expect("verification should start after finalized apply");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("verification did not start after finalized apply completed");
                },
            }

            proposal_release
                .send(())
                .expect("proposal should remain active");
            select! {
                result = &mut proposal => assert!(result.is_none()),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("proposal did not finish after finalized apply completed");
                },
            }
            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                valid = &mut verification => assert!(valid),
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("verification did not finish after finalized apply completed");
                },
            }
            select! {
                result = futures::future::join(&mut waiter1, &mut waiter2) => {
                    result.0.expect("block 1 acknowledgement");
                    result.1.expect("block 2 acknowledgement");
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("finalized apply suffix did not drain");
                },
            }
            assert_eq!(control.applied.load(Ordering::Relaxed), 2);
            assert_eq!(control.finalized.lock().as_slice(), [1, 2]);
            assert!(control.flushes.lock().is_empty());
            actor.abort();
        });
    }

    #[test]
    fn cancelled_proposal_is_not_started_after_finalized_apply() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (proposal_gate, mut proposal_started, _proposal_release) = application_gate();
            let (mut mailbox, control, _marshal, actor) = spawn_processing_with_gates(
                &context,
                "cancelled-proposal-after-apply",
                None,
                VecDeque::new(),
                Some(proposal_gate),
            )
            .await;
            let (apply_started, apply_release) = control.gate_apply();

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&winner, 2);
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner.clone()), acknowledgement));
            apply_started.await.expect("finalized apply should start");

            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), child.context()),
                ancestry::from_iter([Arc::new(winner)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            drop(proposal);

            apply_release
                .send(())
                .expect("finalized apply should remain active");
            waiter.await.expect("finalized block acknowledgement");
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                poll!(&mut proposal_started).is_pending(),
                "a cancelled deferred proposal must not enter the application"
            );
            actor.abort();
        });
    }

    #[test]
    fn consecutive_finalized_batches_apply_and_flush_in_order() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "finalized-continuous-drain", None).await;
            let (apply_started, apply_release) = control.gate_apply();

            let mut parent = TestBlock::new(0, 0);
            let mut waiters = Vec::new();
            for digest in 1..=3 {
                let block = TestBlock::child(&parent, digest);
                let (acknowledgement, waiter) = Exact::handle();
                let _ = mailbox.report(Update::Block(Arc::new(block.clone()), acknowledgement));
                parent = block;
                waiters.push(waiter);
            }
            apply_started.await.expect("first apply should start");
            apply_release
                .send(())
                .expect("first apply should remain active");

            select! {
                acknowledgements = futures::future::join_all(waiters) => {
                    for acknowledgement in acknowledgements {
                        acknowledgement.expect("ordered finalized acknowledgement");
                    }
                },
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("processing actor did not drain the finalized suffix");
                },
            }
            assert_eq!(control.applied.load(Ordering::Relaxed), 3);
            assert_eq!(control.memory_flushes.load(Ordering::Relaxed), 3);
            assert_eq!(control.finalized.lock().as_slice(), [1, 2, 3]);
            assert!(control.flushes.lock().is_empty());
            actor.abort();
        });
    }

    #[test]
    fn next_finalization_waits_for_prior_finalized_hook() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut signing = context.child("signing");
            let scheme_fixture = scheme_mocks::fixture(&mut signing, b"hook-before-next-apply", 1);
            let marshal = fixtures::marshal_fixture(
                context.child("marshal_fixture"),
                "hook-before-next-apply",
                scheme_fixture.schemes[0].clone(),
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let control = FlushControl::default();
            let databases = Shared::new("test", TestDb::gated(control.clone()));
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::default(),
                verify_gates: Arc::default(),
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                gate_height: Height::zero(),
                apply_calls: apply_calls.clone(),
                verify_calls: Arc::default(),
            };
            let processor = Processor::new(
                app,
                databases,
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "hook-before-next-apply").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let (first_apply_started, first_apply_release) = control.gate_apply();
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            first_apply_started.await.expect("first apply should start");

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2), acknowledgement));
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                1,
                "the next finalization must remain queued behind the active database apply",
            );
            first_apply_release
                .send(())
                .expect("first apply should remain active");
            finalized_started
                .await
                .expect("first finalized hook should start");
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                control.applied.load(Ordering::SeqCst),
                1,
                "the next finalization must not replace state visible to the active hook",
            );
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                1,
                "the next block must not be reconstructed while the prior hook is active",
            );

            finalized_release
                .send(())
                .expect("first finalized hook should remain active");
            let acknowledgements = futures::future::join(waiter1, waiter2).await;
            acknowledgements.0.expect("first acknowledgement");
            acknowledgements.1.expect("second acknowledgement");
            assert_eq!(control.applied.load(Ordering::SeqCst), 2);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 2);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn prune_is_the_only_durability_boundary() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) = spawn_processing(
                &context,
                "prune-durability-boundary",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;
            let (prune_started, prune_release) = control.gate_prune();

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            waiter1.await.expect("routine block acknowledgement");
            assert!(control.flushes.lock().is_empty());

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2), acknowledgement));
            waiter2
                .await
                .expect("prune-triggering block acknowledgement");
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(control.pruned.lock().is_empty());

            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("prune barrier should remain active");
            prune_started.await.expect("prune should follow durability");
            assert!(control.pruned.lock().is_empty());
            prune_release.send(()).expect("prune should remain active");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().as_slice(), [1]);
            assert!(control.flushes.lock().is_empty());
            actor.abort();
        });
    }

    #[test]
    fn finalized_apply_failure_is_supervised() {
        let config = deterministic::Config::default()
            .with_timeout(Some(Duration::from_secs(5)))
            .with_catch_panics(true);
        deterministic::Runner::new(config).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "finalized-apply-failure", None).await;
            control.fail_next_apply();
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));

            assert!(actor.await.is_err(), "apply failure must stop processing");
            assert!(waiter.await.is_err(), "failed apply must not acknowledge");
        });
    }

    #[test]
    fn verification_waits_for_finalizing_winner_apply() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "verify-finalizing-winner", None).await;
            let (apply_started, apply_release) = control.gate_apply();

            let genesis = TestBlock::new(0, 0);
            let winner = TestBlock::child(&genesis, 1);
            let winner_context = winner.context();
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner.clone()), acknowledgement));
            apply_started.await.expect("finalized apply should start");

            let mut verifier = mailbox.clone();
            let mut verification = Box::pin(verifier.verify(
                (context.child("verify"), winner_context),
                ancestry::from_iter([Arc::new(winner), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verification).is_pending());
            context.sleep(Duration::from_millis(10)).await;
            assert!(
                poll!(&mut verification).is_pending(),
                "verification must remain queued while the finalized batch is applied",
            );

            apply_release
                .send(())
                .expect("finalized apply should remain active");
            assert!(
                verification.await,
                "the exact finalized winner should remain valid after its batch is applied",
            );
            waiter
                .await
                .expect("finalized block should be acknowledged");
            assert!(control.flushes.lock().is_empty());
            actor.abort();
        });
    }

    #[test]
    fn compatible_finalization_retries_acquisition_without_reexecuting_application() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let observed_contexts = Arc::new(Mutex::new(Vec::new()));
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: observed_contexts.clone(),
                finalized: Arc::default(),
            };
            let (mut mailbox, _marshal, actor) =
                spawn_gated_application(&context, "finalize-during-acquisition", app).await;

            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let candidate = TestBlock::child(&finalized, 2);
            let candidate_context = candidate.context();
            let (ancestry, parent_started, parent_gate, candidate_deliveries) =
                parent_gated_ancestry(candidate, finalized.clone());

            let mut verifier = mailbox.clone();
            let mut verification =
                Box::pin(verifier.verify((context.child("verify"), candidate_context), ancestry));
            assert!(poll!(&mut verification).is_pending());
            parent_started
                .await
                .expect("candidate verification should request its parent");
            assert_eq!(candidate_deliveries.load(Ordering::SeqCst), 1);

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(finalized), acknowledgement));
            waiter
                .await
                .expect("compatible finalization should be acknowledged");

            parent_gate.release();
            verify_started
                .await
                .expect("candidate application verification should start");
            verify_release
                .send(())
                .expect("candidate verification should remain active");
            assert!(verification.await);
            assert_eq!(
                observed_contexts.lock().len(),
                1,
                "compatible retry must execute Application::verify exactly once",
            );
            actor.abort();
        });
    }

    #[test]
    fn finalization_keeps_compatible_verification_active() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (retry_gate, _retry_started, _retry_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([
                    parent_gate,
                    child_gate,
                    retry_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(parent.clone()), Arc::new(parent_genesis)]),
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
                ancestry::from_iter([Arc::new(child), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("child verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            waiter
                .await
                .expect("finalized parent should be acknowledged");
            child_release
                .send(())
                .expect("compatible verification should remain active");
            assert!(verify_child.await);
            actor.abort();
        });
    }

    #[test]
    fn finalization_invalidates_incompatible_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (fork_gate, fork_started, fork_release) = application_gate();
            let (child_gate, child_started, mut child_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([fork_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(losing_parent.clone()), Arc::new(fork_genesis)]),
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
                ancestry::from_iter([Arc::new(losing_child), Arc::new(losing_parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            child_started
                .await
                .expect("losing child verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
            select! {
                _ = child_release.closed() => {},
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("incompatible verification was not cancelled");
                },
            }
            let mut waiter = Box::pin(waiter);
            select! {
                result = &mut waiter => {
                    result.expect("winning block should be acknowledged");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("winning block was not acknowledged");
                },
            }
            select! {
                valid = &mut verify_child => {
                    assert!(!valid, "verification on a finalized-away fork must fail");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("incompatible verification retry did not resolve");
                },
            }
            actor.abort();
        });
    }

    #[test]
    fn finalization_rejects_deep_incompatible_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (grandchild_gate, grandchild_started, mut grandchild_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([
                    parent_gate,
                    child_gate,
                    grandchild_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                ancestry::from_iter([Arc::new(losing_parent.clone()), Arc::new(genesis.clone())]),
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
                ancestry::from_iter([Arc::new(losing_child.clone()), Arc::new(losing_parent)]),
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
                ancestry::from_iter([Arc::new(losing_grandchild), Arc::new(losing_child)]),
            ));
            assert!(poll!(&mut verify_grandchild).is_pending());
            grandchild_started
                .await
                .expect("losing grandchild verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
            grandchild_release.closed().await;
            waiter.await.expect("winning block should be acknowledged");

            let result = select! {
                valid = &mut verify_grandchild => Some(valid),
                _ = context.sleep(Duration::from_millis(100)) => None,
            };
            actor.abort();
            assert_eq!(
                result,
                Some(false),
                "verification on a pruned deep fork must resolve false",
            );
        });
    }

    #[test]
    fn skipped_finalization_keeps_retained_verification_progressing() {
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
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::new())),
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                gate_height: finalized.height(),
                apply_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(1, 1),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "skip-finalized").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: Some(finalized.height()),
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let mut verifier = mailbox.clone();
            let mut verify_child = Box::pin(verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(finalized.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            verify_started
                .await
                .expect("child verification should start");

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(finalized), acknowledgement));
            finalized_started
                .await
                .expect("finalized hook should start");
            verify_release
                .send(())
                .expect("child verification should remain active");
            let result = select! {
                valid = &mut verify_child => Some(valid),
                _ = context.sleep(Duration::from_millis(100)) => None,
            };

            finalized_release
                .send(())
                .expect("finalized hook should remain active");
            waiter
                .await
                .expect("skipped finalized block should be acknowledged");
            let valid = match result {
                Some(valid) => valid,
                None => verify_child.await,
            };
            actor.abort();
            drop(marshal.guards);
            assert!(valid);
            assert!(
                result.is_some(),
                "skipped finalization stalled a retained verification",
            );
        });
    }

    #[test]
    fn startup_replayed_finalization_hook_is_not_repeated() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"replayed-finalized", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "replayed-finalized",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let finalized_heights = Arc::new(Mutex::new(vec![finalized.height().get()]));
            let app = GatedApp {
                verify_gates: Arc::default(),
                proposal_gate: Arc::default(),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::clone(&finalized_heights),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(1, 1),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "replayed-finalized").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: Some(finalized.height()),
                replayed_finalized_after: Some(Height::zero()),
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(finalized), acknowledgement));
            waiter
                .await
                .expect("replayed finalized block should be acknowledged");

            actor.abort();
            drop(marshal.guards);
            assert_eq!(
                *finalized_heights.lock(),
                [1],
                "startup replay already ran the finalized hook",
            );
        });
    }

    #[test]
    fn deferred_verification_resumes_after_sync() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
                finalized: Arc::default(),
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
                            ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
                        )
                        .await
                }
            });
            let request = match receiver.recv().await {
                Some(Message::Verify {
                    span,
                    context: request_context,
                    ancestry,
                    verification,
                }) => VerificationRequest {
                    span,
                    context: request_context,
                    ancestry,
                    verification,
                },
                _ => panic!("deferred verification request must arrive"),
            };

            // Resume the deferred verification after state sync.
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "deferred-verification").await,
                processor,
                deferred_verifications: vec![request],
                skip_finalized_until: Some(Height::new(0)),
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

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

    #[test]
    fn finalization_reuses_active_replay() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let first_child = TestBlock::child(&parent, 2);
            let second_child = TestBlock::child(&parent, 3);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"finalize-replay", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "finalize-replay",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (gate, apply_started, apply_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "reuse-active-replay").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let consensus_context = first_child.context();
            let mut first_verifier = mailbox.clone();
            let mut first = Box::pin(first_verifier.verify(
                (context.child("first_verify"), consensus_context.clone()),
                ancestry::from_iter([Arc::new(first_child), Arc::new(parent.clone())]),
            ));
            let mut second_verifier = mailbox.clone();
            let mut second = Box::pin(second_verifier.verify(
                (context.child("second_verify"), consensus_context),
                ancestry::from_iter([Arc::new(second_child), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut first).is_pending());
            assert!(poll!(&mut second).is_pending());
            apply_started.await.expect("replay should start");
            context.sleep(Duration::from_millis(10)).await;

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            context.sleep(Duration::from_millis(10)).await;
            apply_release
                .send(())
                .expect("finalization should keep the replay active");
            verify_started
                .await
                .expect("compatible verification should start");
            finalized_started
                .await
                .expect("finalization hook should start");
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            verify_release
                .send(())
                .expect("compatible verification should remain active");
            assert!(first.await);
            finalized_release
                .send(())
                .expect("finalization hook should remain active");
            waiter
                .await
                .expect("finalized parent should be acknowledged");
            assert!(second.await);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn child_replay_is_not_blocked_by_parent_verifiers() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"multiple-parent-verification-producers", 1)
                    .schemes[0]
                    .clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "multiple-parent-verification-producers",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (first_gate, first_started, mut first_release) = application_gate();
            let (second_gate, second_started, mut second_release) = application_gate();
            let (replay_gate, mut replay_started, replay_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(
                    &context,
                    "multiple-parent-verification-producers",
                )
                .await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let mut first_verifier = mailbox.clone();
            let mut first_parent = Box::pin(first_verifier.verify(
                (context.child("first_parent"), parent.context()),
                ancestry::from_iter([Arc::new(parent.clone()), Arc::new(genesis.clone())]),
            ));
            let mut second_verifier = mailbox.clone();
            let mut second_parent = Box::pin(second_verifier.verify(
                (context.child("second_parent"), parent.context()),
                ancestry::from_iter([Arc::new(parent.clone()), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut first_parent).is_pending());
            assert!(poll!(&mut second_parent).is_pending());
            first_started
                .await
                .expect("first parent verification should start");
            second_started
                .await
                .expect("second parent verification should start");

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("child"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(parent)]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            select! {
                result = &mut replay_started => {
                    result.expect("child replay should start independently");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("parent verifiers transitively blocked child recovery");
                },
            }
            replay_release
                .send(())
                .expect("child replay should remain active");
            assert!(verify_child.await);

            drop(first_parent);
            select! {
                _ = first_release.closed() => {},
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("first abandoned parent verification remained active");
                },
            }
            drop(second_parent);
            select! {
                _ = second_release.closed() => {},
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("second abandoned parent verification remained active");
                },
            }
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 3);

            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn verified_state_supersedes_stale_replay_for_waiter_and_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"verified-state-supersedes-replay", 1).schemes
                    [0]
                .clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "verified-state-supersedes-replay",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (replay_gate, replay_started, mut replay_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gates: Arc::new(Mutex::new(VecDeque::new())),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "verified-state-supersedes-replay")
                    .await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            replay_started.await.expect("parent replay should start");

            let mut parent_verifier = mailbox.clone();
            assert!(
                parent_verifier
                    .verify(
                        (context.child("verify_parent"), parent.context()),
                        ancestry::from_iter([Arc::new(parent.clone()), Arc::new(genesis)]),
                    )
                    .await,
                "independent parent verification should publish valid state",
            );

            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            select! {
                result = futures::future::join(&mut verify_child, &mut waiter) => {
                    assert!(result.0, "descendant should reuse independently verified state");
                    result.1.expect("finalization should reuse independently verified state");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("stale replay owner blocked descendant verification and finalization");
                },
            }
            select! {
                _ = replay_release.closed() => {},
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("redundant speculative replay remained active after state publication");
                },
            }
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn consecutive_finalizations_preserve_descendant_replay() {
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
            let (replay_gate, replay_started, mut replay_release) = application_gate();
            let verify_gates = Arc::new(Mutex::new(VecDeque::new()));
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gates: verify_gates.clone(),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: first.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "consecutive-finalizations").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(second.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            replay_started
                .await
                .expect("first-block replay should start");

            let (first_gate, first_verify_started, first_verify_release) = application_gate();
            verify_gates.lock().push_back(first_gate);
            let mut first_verifier = mailbox.clone();
            let mut verify_first = Box::pin(first_verifier.verify(
                (context.child("verify_first"), first.context()),
                ancestry::from_iter([Arc::new(first.clone()), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify_first).is_pending());
            first_verify_started
                .await
                .expect("independent verification should start");
            let (gate, verify_started, verify_release) = application_gate();
            verify_gates.lock().push_back(gate);
            first_verify_release
                .send(())
                .expect("independent verification should remain active");
            assert!(
                verify_first.await,
                "independent verification should cache the first finalized block",
            );

            let (acknowledgement, first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(first), acknowledgement));
            select! {
                _ = replay_release.closed() => {},
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("independently supplied state did not stop the redundant replay");
                },
            }
            select! {
                result = first_waiter => {
                    result.expect("first finalized block should be acknowledged");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("first finalized block was not acknowledged");
                },
            }
            select! {
                result = verify_started => {
                    result.expect("descendant verification should start");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("descendant verification did not start");
                },
            }
            assert!(poll!(&mut verify_child).is_pending());

            let (acknowledgement, second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(second), acknowledgement));
            select! {
                result = second_waiter => {
                    result.expect("second finalized block should be acknowledged");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("second finalized block was not acknowledged");
                },
            }
            verify_release
                .send(())
                .expect("descendant verification should remain active");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(
                valid,
                "descendant replay must remain valid across consecutive finalizations",
            );
            assert_eq!(apply_calls.load(Ordering::SeqCst), 2);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
        });
    }

    async fn assert_retained_verification_finishes_before_queued_finalization(
        context: &deterministic::Context,
        max_pending_acks: NonZeroUsize,
        prefix: &str,
    ) {
        let genesis = TestBlock::new(0, 0);
        let first = TestBlock::child(&genesis, 1);
        let losing = TestBlock::child(&first, 2);
        let winner = TestBlock::child(&first, 3);
        let mut signing = context.child("signing");
        let scheme =
            scheme_mocks::fixture(&mut signing, b"finalize-retry-order", 1).schemes[0].clone();
        let marshal = fixtures::marshal_fixture_with_finalized_block(
            context.child("marshal"),
            prefix,
            scheme,
            &genesis,
            max_pending_acks,
            true,
        )
        .await;
        let (replay_gate, replay_started, replay_release) = application_gate();
        let (verify_gate, verify_started, verify_release) = application_gate();
        let (finalized_gate, finalized_started, finalized_release) = application_gate();
        let app = ReplayGatedApp {
            gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
            verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
            finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
            gate_height: first.height(),
            apply_calls: Arc::new(AtomicUsize::new(0)),
            verify_calls: Arc::new(AtomicUsize::new(0)),
        };
        let processor = Processor::new(
            app,
            test_databases(),
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let mut mailbox = Mailbox::new(sender);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            sync_metadata: test_sync_metadata(context, prefix).await,
            processor,
            deferred_verifications: Vec::new(),
            skip_finalized_until: None,
            replayed_finalized_after: None,
        };
        let actor = context.child("loop").spawn(move |_| processing.start());

        let mut first_verifier = mailbox.clone();
        let mut first_attempt = Box::pin(first_verifier.verify(
            (context.child("first_attempt"), losing.context()),
            ancestry::from_iter([Arc::new(losing.clone()), Arc::new(first.clone())]),
        ));
        assert!(poll!(&mut first_attempt).is_pending());
        replay_started.await.expect("winner replay should start");

        let mut retried_verifier = mailbox.clone();
        let mut retried = Box::pin(retried_verifier.verify(
            (context.child("retried"), losing.context()),
            ancestry::from_iter([Arc::new(losing), Arc::new(first.clone())]),
        ));
        assert!(poll!(&mut retried).is_pending());
        context.sleep(Duration::from_millis(10)).await;

        let (acknowledgement, first_waiter) = Exact::handle();
        let _ = mailbox.report(Update::Block(Arc::new(first), acknowledgement));
        let (acknowledgement, winner_waiter) = Exact::handle();
        let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
        replay_release
            .send(())
            .expect("finalization should retain the replay owner");
        verify_release
            .send(())
            .expect("retained verification should remain active");
        verify_started
            .await
            .expect("retained verification should start");
        finalized_started
            .await
            .expect("first finalization hook should start");

        let valid = select! {
            valid = &mut first_attempt => {
                valid
            },
            _ = context.sleep(Duration::from_millis(100)) => {
                panic!("queued finalization blocked retained verification");
            },
        };
        assert!(
            valid,
            "retained branch-relative verification must remain valid"
        );
        finalized_release
            .send(())
            .expect("first finalization hook should remain active");

        assert!(
            retried.await,
            "completed branch-relative verdict must remain valid"
        );
        first_waiter
            .await
            .expect("first block should be acknowledged");
        winner_waiter.await.expect("winner should be acknowledged");
        actor.abort();
        drop(marshal.guards);
    }

    #[test]
    fn retained_verification_can_finish_before_queued_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            assert_retained_verification_finishes_before_queued_finalization(
                &context,
                NZUsize!(2),
                "retained-verification-depth-2",
            )
            .await;
            assert_retained_verification_finishes_before_queued_finalization(
                &context,
                NZUsize!(8),
                "retained-verification-depth-8",
            )
            .await;
        });
    }

    #[test]
    fn pruning_quiesces_replay_before_database_prune() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let parent = TestBlock::child(&block2, 3);
            let child = TestBlock::child(&parent, 4);
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"prune-replay", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "prune-replay",
                scheme,
                &block2,
                NZUsize!(1),
                true,
            )
            .await;
            let (first_gate, first_started, mut first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                verify_gates: Arc::new(Mutex::new(VecDeque::new())),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let control = FlushControl::default();
            let (prune_started, prune_release) = control.gate_prune();
            let databases = Shared::new("prune-replay", TestDb::gated(control.clone()));
            let pruning = Pruning::build(
                PruneConfig {
                    maintenance_interval: NZUsize!(2),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                },
                1,
                0,
            );
            let processor = Processor::new(
                app,
                databases,
                anchor(0, 0),
                StatefulMetrics::new(&context),
                Some(pruning),
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                sync_metadata: test_sync_metadata(&context, "pruning-quiesces-replay").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1.clone()), acknowledgement));
            waiter1.await.expect("first block should be acknowledged");
            assert!(control.flushes.lock().is_empty());

            let mut block2_verifier = mailbox.clone();
            let mut verify_block2 = Box::pin(block2_verifier.verify(
                (context.child("verify_block2"), block2.context()),
                ancestry::from_iter([Arc::new(block2.clone()), Arc::new(block1)]),
            ));
            select! {
                valid = &mut verify_block2 => {
                    assert!(valid, "block 2 should be cached before descendant replay");
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("block 2 verification did not complete");
                },
            }

            let consensus_context = child.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(child), Arc::new(parent)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            select! {
                started = first_started => {
                    started.expect("verification should start before finalization");
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("descendant replay did not start before finalization");
                },
            }

            let (apply_started, apply_release) = control.gate_apply();
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));
            apply_started
                .await
                .expect("second database apply should start");

            apply_release
                .send(())
                .expect("second database apply should remain active");
            waiter2.await.expect("second block should be acknowledged");
            first_release.closed().await;
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(control.pruned.lock().is_empty());
            let release = control.flushes.lock().remove(0);
            release
                .send(Ok(()))
                .expect("prune barrier should be pending");
            prune_started.await.expect("prune should start");
            assert!(control.flushes.lock().is_empty());
            prune_release.send(()).expect("prune should remain active");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            second_started
                .await
                .expect("live replay should restart after pruning");
            second_release
                .send(())
                .expect("restarted replay should remain active");
            assert!(verify.await);
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 3);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
            assert!(control.flushes.lock().is_empty());
            actor.abort();
            marshal.abort();
        });
    }

    #[test]
    fn prune_retries_wait_for_queued_finalization() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let losing = TestBlock::child(&block2, 3);
            let winner = TestBlock::child(&block2, 4);
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"prune-retry", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "prune-retry",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let (block2_gate, block2_started, block2_release) = application_gate();
            let (verify_gate, verify_started, mut verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let observed_contexts: Arc<Mutex<Vec<Name>>> = Arc::default();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([block2_gate, verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                observed_contexts: observed_contexts.clone(),
                finalized: Arc::default(),
            };
            let control = FlushControl::default();
            let (prune_started, prune_release) = control.gate_prune();
            let databases = Shared::new("prune-retry", TestDb::gated(control.clone()));
            let pruning = Pruning::build(
                PruneConfig {
                    maintenance_interval: NZUsize!(2),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                },
                1,
                0,
            );
            let processor = Processor::new(
                app,
                databases,
                anchor(0, 0),
                StatefulMetrics::new(&context),
                Some(pruning),
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                sync_metadata: test_sync_metadata(&context, "prune-retries-finalization").await,
                processor,
                deferred_verifications: Vec::new(),
                skip_finalized_until: None,
                replayed_finalized_after: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1.clone()), acknowledgement));
            waiter1.await.expect("first block should be acknowledged");

            let mut block2_verifier = mailbox.clone();
            let mut verify_block2 = Box::pin(block2_verifier.verify(
                (context.child("verify_block2"), block2.context()),
                ancestry::from_iter([Arc::new(block2.clone()), Arc::new(block1)]),
            ));
            assert!(poll!(&mut verify_block2).is_pending());
            block2_started
                .await
                .expect("block 2 verification should reach the application");
            block2_release
                .send(())
                .expect("block 2 verification should remain active");
            select! {
                valid = &mut verify_block2 => assert!(valid),
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("block 2 verification did not complete");
                },
            }

            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), losing.context()),
                ancestry::from_iter([Arc::new(losing), Arc::new(block2.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            select! {
                started = verify_started => {
                    started.expect("verification should start before finalization");
                },
                _ = context.sleep(Duration::from_secs(2)) => {
                    panic!("losing verification did not start before finalization");
                },
            }

            let (apply_started, apply_release) = control.gate_apply();
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));
            apply_started
                .await
                .expect("second database apply should start");

            apply_release
                .send(())
                .expect("second database apply should remain active");
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            waiter2.await.expect("second block should be acknowledged");
            verify_release.closed().await;
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("prune barrier should remain pending");
            prune_started.await.expect("prune should start");

            let (acknowledgement, winner_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner.clone()), acknowledgement));
            let proposal_context = TestBlock::child(&winner, 5).context();
            let mut proposer = mailbox.clone();
            let mut proposal = Box::pin(proposer.propose(
                (context.child("propose"), proposal_context),
                ancestry::from_iter([Arc::new(winner)]),
                (),
            ));
            assert!(poll!(&mut proposal).is_pending());
            prune_release.send(()).expect("prune should remain active");
            proposal_started
                .await
                .expect("proposal queued behind finalization should start");

            let subscriber = mailbox.clone();
            let mut databases = Box::pin(subscriber.subscribe_databases());
            assert!(poll!(&mut databases).is_pending());

            let result = select! {
                valid = &mut verify => Some(valid),
                _ = context.sleep(Duration::from_millis(100)) => None,
            };
            assert_eq!(
                result,
                Some(false),
                "prune retry must observe the queued finalization",
            );
            assert!(poll!(&mut databases).is_pending());
            assert_eq!(observed_contexts.lock().len(), 2);
            assert_eq!(control.pruned.lock().as_slice(), [1]);

            proposal_release
                .send(())
                .expect("proposal should remain active");
            assert!(proposal.await.is_none());
            drop(databases.await);
            winner_waiter.await.expect("winner should be acknowledged");
            assert!(control.flushes.lock().is_empty());
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn skip_finalized_block_skips_through_target_height() {
        let mut skip_until = Some(Height::new(3));

        assert!(skip_finalized_block(&mut skip_until, Height::new(1)));
        assert_eq!(skip_until, Some(Height::new(3)));
        assert!(skip_finalized_block(&mut skip_until, Height::new(3)));
        assert_eq!(skip_until, None);
        assert!(!skip_finalized_block(&mut skip_until, Height::new(4)));
    }

    #[test]
    fn skip_finalized_block_clears_stale_target() {
        let mut skip_until = Some(Height::new(3));

        assert!(!skip_finalized_block(&mut skip_until, Height::new(4)));
        assert_eq!(skip_until, None);
    }
}
