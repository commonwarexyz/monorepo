use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::{Message, Verification},
        processor::{
            Applied, PendingDigest, Processor, VerificationDisposition, VerificationProgress,
            Verifier,
        },
    },
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Heightable,
    marshal::{
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::Pool,
};
use futures::{
    FutureExt as _,
    future::{Either, ready},
    poll,
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::mpsc::TryRecvError,
    task::Poll,
};
use tracing::{Instrument as _, Span, debug, info_span};

/// Verification work retained across actor state transitions.
pub(super) struct VerificationRequest<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) span: Span,
    pub(super) context: (E, A::Context),
    pub(super) ancestry: BoxedAncestry<A::Block>,
    pub(super) verification: Verification,
}

/// A single unit of work for the processing loop: either a mailbox message to
/// handle or a deferred prune to run while the mailbox is idle.
enum Step<M, P, J> {
    Message(M),
    Prune(P),
    Verification(J),
}

enum VerificationResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    Finished {
        id: u64,
    },
    Invalidated {
        id: u64,
        request: VerificationRequest<E, A>,
    },
}

struct VerificationControl<D: Copy> {
    invalidation: Option<oneshot::Sender<()>>,
    progress: VerificationProgress<D>,
}

impl<E, A> VerificationResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    const fn id(&self) -> u64 {
        match self {
            Self::Finished { id } | Self::Invalidated { id, .. } => *id,
        }
    }
}

/// Records a tracked flush completion and returns whether it is durable.
fn complete(pending: &mut BTreeSet<Height>, (height, durable): (Height, bool)) -> bool {
    assert!(
        pending.remove(&height),
        "completed flush must have a pending height",
    );
    durable
}

pub(super) struct Processing<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
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

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Verify requests collected before the processor became available.
    pub(super) initial_verifications: Vec<VerificationRequest<E, A>>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and should be acknowledged only.
    pub(super) skip_finalized_until: Option<Height>,
}

impl<E, A, S, V> Processing<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
    A::Context: Clone,
{
    pub async fn start(mut self) {
        let mut pending_prune = None;
        let mut deferred_message = None;
        let mut verifications = Pool::default();
        let mut invalidations = BTreeMap::new();
        let mut next_verification_id = 0u64;
        for request in std::mem::take(&mut self.initial_verifications) {
            self.schedule_verification(
                &mut verifications,
                &mut invalidations,
                &mut next_verification_id,
                request,
            );
        }

        // Deferred finalize flushes, each releasing its block's marshal
        // acknowledgement once the flush completes (see `Barrier`).
        let mut syncs = Pool::<(Height, bool)>::default();
        let mut pending_syncs = BTreeSet::new();
        select_loop! {
            self.context,
            on_start => {
                while let Poll::Ready(result) = poll!(verifications.next_completed()) {
                    Self::handle_verification_result(&mut invalidations, result);
                }

                // Observe every already-completed flush (releasing its marshal
                // acknowledgement) before taking the next unit of work, so
                // acknowledgements keep flowing even while the mailbox is
                // never idle.
                while let Some(completion) = syncs.next_completed().now_or_never() {
                    if !complete(&mut pending_syncs, completion) {
                        return;
                    }
                }

                // Pruning is non-critical work. We only run it when the mailbox is idle, and
                // it is never raced against the mailbox due to its internal lock acquisition.
                // If a message is ready, it is always processed immediately.
                let next = match deferred_message.take() {
                    Some(message) => Either::Left(ready(Some(Step::Message(message)))),
                    None => match self.mailbox.try_recv() {
                        // A message is ready: handle it now, regardless of any queued prune.
                        Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                        Err(TryRecvError::Empty) => match pending_prune.take() {
                            // No message, but a prune is queued: run it.
                            Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                            // No message and nothing to prune: wait on the mailbox, driving flush
                            // completions while idle.
                            None => {
                                let mailbox = &mut self.mailbox;
                                let syncs = &mut syncs;
                                let pending_syncs = &mut pending_syncs;
                                let verifications = &mut verifications;
                                Either::Right(async move {
                                    loop {
                                        select! {
                                            message = mailbox.recv() => {
                                                break message.map(Step::Message);
                                            },
                                            completion = syncs.next_completed() => {
                                                if !complete(pending_syncs, completion) {
                                                    return None;
                                                }
                                            },
                                            result = verifications.next_completed() => {
                                                break Some(Step::Verification(result));
                                            },
                                        }
                                    }
                                })
                            }
                        },
                        Err(TryRecvError::Disconnected) => {
                            debug!("mailbox closed, stopping processing");
                            return;
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
                Step::Message(Message::Propose {
                    span,
                    context,
                    ancestry,
                    upstream,
                    response,
                }) => {
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
                    futures::pin_mut!(proposal);
                    let mut receive_messages = true;
                    loop {
                        if receive_messages {
                            select! {
                                _ = &mut proposal => break,
                                result = verifications.next_completed() => {
                                    Self::handle_verification_result(&mut invalidations, result);
                                },
                                message = self.mailbox.recv() => match message {
                                    Some(Message::Verify {
                                        span,
                                        context,
                                        ancestry,
                                        verification,
                                    }) => Self::schedule_verification_with(
                                        verifier.clone(),
                                        actor_context.child("verify"),
                                        marshal.clone(),
                                        &mut verifications,
                                        &mut invalidations,
                                        &mut next_verification_id,
                                        VerificationRequest {
                                            span,
                                            context,
                                            ancestry,
                                            verification,
                                        },
                                    ),
                                    Some(message) => {
                                        // Only verification may overtake an active proposal. The
                                        // first other message is a FIFO barrier, so later
                                        // verifications must not cross it.
                                        deferred_message = Some(message);
                                        receive_messages = false;
                                    }
                                    None => receive_messages = false,
                                },
                            }
                        } else {
                            select! {
                                _ = &mut proposal => break,
                                result = verifications.next_completed() => {
                                    Self::handle_verification_result(&mut invalidations, result);
                                },
                            }
                        }
                    }
                }
                Step::Message(Message::Verify {
                    span,
                    context,
                    ancestry,
                    verification,
                }) => {
                    self.schedule_verification(
                        &mut verifications,
                        &mut invalidations,
                        &mut next_verification_id,
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
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.finalized");
                    if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                        async {
                            Self::drive_verifications(
                                self.processor.notify_finalized(
                                    self.context.as_present(),
                                    block.as_ref(),
                                ),
                                &mut verifications,
                                &mut invalidations,
                            )
                            .await;
                            acknowledgement.acknowledge();
                        }
                        .instrument(process)
                        .await;
                    } else {
                        let boundary = self.processor.finalization_boundary(block.as_ref());
                        let (retry, reject) = Self::quiesce_verifications_where(
                            &mut verifications,
                            &mut invalidations,
                            |progress| boundary.disposition(progress),
                        )
                        .await;
                        drop(boundary);
                        async {
                            let applied = Self::drive_verifications(
                                self.processor.finalize(&self.context, block.as_ref()),
                                &mut verifications,
                                &mut invalidations,
                            )
                            .await;
                            let Some(Applied { barrier, prune }) = applied else {
                                // Duplicate report: marshal redelivers a processed
                                // height only after a restart, where startup aligned
                                // the databases to durable state.
                                acknowledgement.acknowledge();
                                return;
                            };
                            debug!(
                                height = block.height().get(),
                                "applied finalized database batch"
                            );

                            // Acknowledge marshal only once the batch's flush
                            // completes, so marshal's processed floor never runs
                            // ahead of flushed database state (the startup rewind
                            // contract), without blocking the loop on the flush.
                            // Marshal's ack window bounds the flush backlog. A
                            // false `Barrier::durable` leaves the block
                            // unacknowledged, and marshal redelivers it on restart.
                            let height = block.height();
                            assert!(
                                pending_syncs.insert(height),
                                "finalize flush height must be unique",
                            );
                            syncs.push(async move {
                                let durable = barrier.durable().await;
                                if durable {
                                    acknowledgement.acknowledge();
                                }
                                (height, durable)
                            });
                            if let Some(prune) = prune {
                                pending_prune = Some(prune);
                            }
                        }
                        .instrument(process)
                        .await;
                        for verification in reject {
                            verification.respond(false);
                        }
                        for request in retry {
                            self.schedule_verification(
                                &mut verifications,
                                &mut invalidations,
                                &mut next_verification_id,
                                request,
                            );
                        }
                    }
                }
                Step::Message(Message::SubscribeDatabases { response }) => {
                    response.send_lossy(self.processor.databases().clone());
                }
                Step::Prune(prune) => {
                    // The prune target must be durable, but later blocks remain available in
                    // marshal for replay and do not delay maintenance.
                    while pending_syncs
                        .first()
                        .is_some_and(|height| *height <= prune.barrier_height)
                    {
                        select! {
                            completion = syncs.next_completed() => {
                                if !complete(&mut pending_syncs, completion) {
                                    return;
                                }
                            },
                            result = verifications.next_completed() => {
                                Self::handle_verification_result(&mut invalidations, result);
                            },
                        }
                    }
                    let retry = Self::quiesce_verifications(
                        &mut verifications,
                        &mut invalidations,
                    )
                    .await;
                    assert!(
                        self.processor.replays_idle(),
                        "verification replay remained active after quiescence"
                    );
                    prune
                        .run(self.processor.databases_mut(), &self.marshal)
                        .await;
                    for request in retry {
                        self.schedule_verification(
                            &mut verifications,
                            &mut invalidations,
                            &mut next_verification_id,
                            request,
                        );
                    }
                }
                Step::Verification(result) => {
                    Self::handle_verification_result(&mut invalidations, result);
                }
            },
        }
    }

    fn schedule_verification(
        &self,
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
        next_id: &mut u64,
        request: VerificationRequest<E, A>,
    ) {
        Self::schedule_verification_with(
            self.processor.verifier(),
            self.context.as_present().child("verify"),
            self.marshal.clone(),
            verifications,
            invalidations,
            next_id,
            request,
        );
    }

    fn schedule_verification_with(
        mut verifier: Verifier<E, A>,
        actor_context: E,
        marshal: MarshalMailbox<S, V>,
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
        next_id: &mut u64,
        mut request: VerificationRequest<E, A>,
    ) {
        let id = *next_id;
        *next_id = next_id
            .checked_add(1)
            .expect("verification request ID overflowed");
        let (invalidate, invalidated) = oneshot::channel();
        let progress = VerificationProgress::default();
        assert!(
            invalidations
                .insert(
                    id,
                    VerificationControl {
                        invalidation: Some(invalidate),
                        progress: progress.clone(),
                    },
                )
                .is_none()
        );

        let process = info_span!(parent: &request.span, "stateful.actor.verify");
        verifications.push(
            async move {
                let ancestry = request.ancestry.clone();
                let attempt_context = (
                    actor_context.child("application"),
                    request.context.1.clone(),
                );
                let result = select! {
                    _ = invalidated => None,
                    result = verifier.verify(
                        &actor_context,
                        marshal,
                        attempt_context,
                        ancestry,
                        &progress,
                        &mut request.verification,
                    ) => Some(result),
                };
                match result {
                    Some(Some(valid)) => {
                        request.verification.respond(valid);
                        VerificationResult::Finished { id }
                    }
                    Some(None) => VerificationResult::Finished { id },
                    None => VerificationResult::Invalidated { id, request },
                }
            }
            .instrument(process),
        );
    }

    async fn drive_verifications<T>(
        operation: impl Future<Output = T>,
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
    ) -> T {
        futures::pin_mut!(operation);
        loop {
            select! {
                output = &mut operation => break output,
                result = verifications.next_completed() => {
                    Self::handle_verification_result(invalidations, result);
                },
            }
        }
    }

    fn handle_verification_result(
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
        result: VerificationResult<E, A>,
    ) {
        let control = invalidations
            .remove(&result.id())
            .expect("completed verification must have an invalidation handle");
        assert!(control.invalidation.is_some());
        assert!(
            matches!(result, VerificationResult::Finished { .. }),
            "verification cannot finish through the actor loop after invalidation",
        );
    }

    async fn quiesce_verifications(
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
    ) -> Vec<VerificationRequest<E, A>> {
        let (retry, reject) =
            Self::quiesce_verifications_where(verifications, invalidations, |_| {
                VerificationDisposition::Retry
            })
            .await;
        assert!(reject.is_empty());
        retry
    }

    async fn quiesce_verifications_where(
        verifications: &mut Pool<VerificationResult<E, A>>,
        invalidations: &mut BTreeMap<u64, VerificationControl<PendingDigest<A, E>>>,
        disposition: impl Fn(&VerificationProgress<PendingDigest<A, E>>) -> VerificationDisposition,
    ) -> (Vec<VerificationRequest<E, A>>, Vec<Verification>) {
        let mut pending = BTreeMap::new();
        for (&id, control) in invalidations.iter_mut() {
            let disposition = disposition(&control.progress);
            if disposition == VerificationDisposition::Retain {
                continue;
            }
            assert!(control.invalidation.take().is_some());
            assert!(pending.insert(id, disposition).is_none());
        }

        let mut retry = Vec::with_capacity(pending.len());
        let mut reject = Vec::with_capacity(pending.len());
        while !pending.is_empty() {
            let result = verifications.next_completed().await;
            let id = result.id();
            let disposition = pending.remove(&id);
            let control = invalidations
                .remove(&id)
                .expect("completed verification must have an invalidation handle");
            match result {
                VerificationResult::Finished { .. } => {}
                VerificationResult::Invalidated { request, .. } => {
                    let disposition = disposition.expect("verification must be invalidated");
                    assert!(control.invalidation.is_none());
                    match disposition {
                        VerificationDisposition::Retain => {
                            unreachable!("retained verification cannot be invalidated")
                        }
                        VerificationDisposition::Retry => {
                            if !request.verification.is_cancelled() {
                                retry.push(request);
                            }
                        }
                        VerificationDisposition::Reject => {
                            reject.push(request.verification);
                        }
                    }
                }
            }
        }
        (retry, reject)
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
    use super::{Processing, skip_finalized_block};
    use crate::stateful::{
        Application, Input, Proposed, PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
        },
        db::Shared,
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
    use commonware_macros::select;
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
        channel::oneshot,
        sync::Mutex,
    };
    use futures::{StreamExt as _, poll};
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
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
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
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
    }

    #[derive(Clone)]
    struct ReplayGatedApp {
        gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        verify_gate: Arc<Mutex<Option<ApplicationGate>>>,
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
            let gate = self.verify_gate.lock().take();
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
            _databases: &Self::Databases,
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
            processor,
            initial_verifications: Vec::new(),
            skip_finalized_until: None,
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
        spawn_processing_with_gates(context, prefix, prune_config, VecDeque::new()).await
    }

    async fn spawn_processing_with_gates(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
        verify_gates: VecDeque<ApplicationGate>,
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
            proposal_gate: Arc::new(Mutex::new(None)),
            verify_valid: true,
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
            processor,
            initial_verifications: Vec::new(),
            skip_finalized_until: None,
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
    fn abandoned_incomplete_verifications_cancel_after_supersession() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (first_gate, first_started, first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
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
                .expect("superseding verification should start");
            first_release
                .send(())
                .expect("superseding verification should remain active");
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
                .expect("superseding verification should start");
            second_release
                .send(())
                .expect("superseding verification should remain active");
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
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "conflicting-processed", None).await;
            let genesis = TestBlock::new(0, 0);
            let canonical = TestBlock::child(&genesis, 1);
            let conflicting = TestBlock::child(&genesis, 2);

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(canonical), acknowledgement));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("finalized block flush should remain pending");
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
                verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
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
                processor,
                initial_verifications: Vec::new(),
                skip_finalized_until: Some(finalized.height()),
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
                verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
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
                processor,
                initial_verifications: Vec::new(),
                skip_finalized_until: None,
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
    fn finalization_does_not_bypass_active_winner_replay() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&finalized, 2);
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"finalize-pending-replay", 1).schemes
                [0]
            .clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "finalize-pending-replay",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (replay_gate, replay_started, replay_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gate: Arc::new(Mutex::new(None)),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: finalized.height(),
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
                processor,
                initial_verifications: Vec::new(),
                skip_finalized_until: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let mut child_verifier = mailbox.clone();
            let mut verify_child = Box::pin(child_verifier.verify(
                (context.child("verify_child"), child.context()),
                ancestry::from_iter([Arc::new(child), Arc::new(finalized.clone())]),
            ));
            assert!(poll!(&mut verify_child).is_pending());
            replay_started.await.expect("winner replay should start");

            let mut winner_verifier = mailbox.clone();
            assert!(
                winner_verifier
                    .verify(
                        (context.child("verify_winner"), finalized.context()),
                        ancestry::from_iter([Arc::new(finalized.clone()), Arc::new(genesis),]),
                    )
                    .await,
                "independent winner verification should cache its batch",
            );

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(finalized), acknowledgement));
            waiter
                .await
                .expect("cached winner should finalize without the replay");
            assert!(poll!(&mut verify_child).is_pending());

            replay_release
                .send(())
                .expect("winner replay should remain active");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(valid, "late winner replay must not invalidate its child");
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn next_finalization_retries_replay_of_previous_anchor() {
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
            let (replay_gate, replay_started, replay_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gate: Arc::new(Mutex::new(None)),
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
                processor,
                initial_verifications: Vec::new(),
                skip_finalized_until: None,
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

            let mut first_verifier = mailbox.clone();
            assert!(
                first_verifier
                    .verify(
                        (context.child("verify_first"), first.context()),
                        ancestry::from_iter([Arc::new(first.clone()), Arc::new(genesis)]),
                    )
                    .await,
                "independent verification should cache the first finalized block",
            );

            let (acknowledgement, first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(first), acknowledgement));
            first_waiter
                .await
                .expect("first finalized block should be acknowledged");
            assert!(poll!(&mut verify_child).is_pending());

            let (acknowledgement, second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(second), acknowledgement));
            second_waiter
                .await
                .expect("second finalized block should be acknowledged");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            drop(replay_release);
            assert!(
                valid,
                "replay of the previous anchor must retry across the next finalization",
            );
            assert_eq!(apply_calls.load(Ordering::SeqCst), 2);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
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
                verify_gate: Arc::new(Mutex::new(None)),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let control = FlushControl::default();
            let databases = Shared::new("prune-replay", TestDb::gated(control.clone()));
            let pruning = Pruning::build(
                PruneConfig {
                    maintenance_interval: NZUsize!(1),
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
                processor,
                initial_verifications: Vec::new(),
                skip_finalized_until: None,
            };
            let actor = context.child("loop").spawn(move |_| processing.start());

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));
            let consensus_context = child.context();
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(child), Arc::new(parent)]),
            ));
            assert!(poll!(&mut verify).is_pending());

            select! {
                result = first_started => result.expect("verification should start before pruning"),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!(
                        "verification did not start: flushes={} pruned={}",
                        control.flushes.lock().len(),
                        control.pruned.lock().len(),
                    );
                },
            }
            assert!(control.pruned.lock().is_empty());
            let release = control.flushes.lock().remove(0);
            release
                .send(Ok(()))
                .expect("target flush should be pending");
            waiter1.await.expect("target block should be acknowledged");
            first_release.closed().await;
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
            assert_eq!(apply_calls.load(Ordering::SeqCst), 4);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

            let release = control.flushes.lock().remove(0);
            release.send(Ok(())).expect("newer flush should be pending");
            waiter2.await.expect("newer block should be acknowledged");
            actor.abort();
            marshal.abort();
        });
    }

    /// Pruning waits for the flush that covers its target without waiting for newer state.
    #[test]
    fn prune_waits_only_for_target_flush() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Marshal only receives prune requests here. Its actor never runs.
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, _marshal, _actor) = spawn_processing_with_gates(
                &context,
                "gated-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
                VecDeque::from([verify_gate]),
            )
            .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let block3 = TestBlock::child(&block2, 3);

            // Apply blocks 1 and 2 without releasing any flush: the loop must
            // stay live (both blocks applied) while no acknowledgement fires.
            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));

            // Queue a verification before pruning starts, then hold it in the
            // application until the prune is waiting on durability.
            let consensus_context = block3.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(block3), Arc::new(block2)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should start before pruning");

            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must wait for pending flushes",
            );

            // Block 2 filled the retention window, but pruning must remain blocked behind the
            // target at block 1.
            context.sleep(Duration::from_millis(50)).await;
            assert!(control.pruned.lock().is_empty());
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must keep waiting for pending flushes",
            );
            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                result = &mut verify => assert!(result),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("pending prune blocked active verification");
                },
            }
            assert!(control.pruned.lock().is_empty());

            // Releasing block 1 makes the prune target durable. Block 2 remains retained in
            // marshal and must not delay pruning.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            assert!(
                poll!(&mut waiter2).is_pending(),
                "block 2 must stay unacknowledged while its flush is pending",
            );

            // Releasing block 2's flush releases its acknowledgement.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    /// An aborted target flush must stop processing before pruning can discard its recovery state.
    #[test]
    fn aborted_target_flush_prevents_prune() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) = spawn_processing(
                &context,
                "gated-aborted-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            drop(control.flushes.lock().remove(0));
            actor.await.expect("processing actor should stop");
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "aborted target flush must leave acknowledgements pending",
            );
            assert!(
                control.pruned.lock().is_empty(),
                "aborted flush must prevent pruning",
            );
        });
    }

    /// While the loop is idle, a completed flush must release its acknowledgement without
    /// displacing a simultaneously reported block, while an incomplete flush must leave its block
    /// unacknowledged.
    #[test]
    fn idle_acks_follow_flush_outcome() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "gated-idle", None).await;

            // Park the loop idle with block 1's flush pending.
            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(poll!(&mut waiter1).is_pending());
            context.sleep(Duration::from_millis(50)).await;

            // Release the flush and report block 2 in the same scheduling
            // window: the completion must fire block 1's acknowledgement
            // without displacing the new message.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            waiter1.await.expect("block 1 acknowledgement");
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            context.sleep(Duration::from_millis(50)).await;

            // Dropping block 2's release resolves its flush as shutdown. The
            // acknowledgement must be withheld so marshal's floor cannot pass
            // unflushed state.
            drop(control.flushes.lock().remove(0));
            actor.await.expect("processing actor should stop");
            assert!(
                poll!(&mut waiter2).is_pending(),
                "unflushed block acknowledgement must remain pending",
            );
        });
    }

    #[test]
    fn ready_aborted_flush_stops_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "gated-ready-abort", None).await;

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            drop(control.flushes.lock().remove(0));

            actor.await.expect("processing actor should stop");
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "unflushed acknowledgements must remain pending",
            );
        });
    }

    /// Stopping processing with a flush in flight must not cancel marshal's acknowledgement.
    #[test]
    fn shutdown_keeps_pending_flush_ack_pending() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal, actor) =
                spawn_processing(&context, "gated-shutdown", None).await;

            let (acknowledgement, mut waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            drop(mailbox);
            actor.await.expect("processing actor should stop");
            assert!(
                poll!(&mut waiter).is_pending(),
                "shutdown must leave in-flight acknowledgements pending",
            );
        });
    }

    /// A flush failure must panic the processing loop with the database identified and leave the
    /// block unacknowledged.
    #[test]
    #[should_panic(expected = "database finalize flush failed (type")]
    fn flush_failure_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal, _actor) =
                spawn_processing(&context, "gated-failure", None).await;

            let (acknowledgement, _waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Err(RuntimeError::WriteFailed));

            // The pooled flush future panics when the loop next polls it.
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
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
