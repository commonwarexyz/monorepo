//! The post-sync processing loop of the stateful actor.
//!
//! The loop drives the [`Processor`], which owns the database set and mutates
//! it only through its own methods. Verification jobs hold readers, so an
//! apply never cancels one: a job mid-read finishes that read and continues
//! against the new state. A job on the losing side of the apply is refused at
//! its next batch operation
//! ([`ExecutionError::Stale`](crate::stateful::ExecutionError::Stale)) and
//! answered from the canonical chain.
//!
//! Each finalized block is applied immediately. Snapshots are captured and
//! published when a durability sync starts, and one active sync covers every
//! block applied behind it (see [`Publisher`](crate::stateful::db::Publisher)).
//! The block is acknowledged to
//! marshal only once a sync proves it durable. A queued prune owns the next
//! storage-mutation boundary. It waits until the pruned range is durable,
//! prunes, and publishes fresh snapshots right away.

use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::{Message, Request as VerificationRequest},
        processor::{Marshal, Processor},
    },
    db::Barrier,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{Heightable, types::Height};
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use futures::{
    FutureExt as _,
    future::{Either, pending, ready},
};
use rand_core::Rng;
use std::{collections::VecDeque, sync::mpsc::TryRecvError};
use tracing::{Instrument as _, debug, info_span, warn};

/// Work selected for one iteration of the processing actor.
enum Step<M, P> {
    /// A message received from the actor mailbox.
    Message(M),
    /// Deferred pruning work ready for its database mutation boundary.
    Prune(P),
    /// Completion of the active database durability barrier.
    Sync((Height, bool)),
}

/// Tracks the durable database prefix and marshal acknowledgements awaiting it.
///
/// At most one sync covers a captured prefix. Applied heights beyond that prefix remain queued
/// for a successor sync.
struct Durability {
    /// Highest applied height known to be durable.
    durable: Height,
    /// Applied heights whose marshal acknowledgements await durability.
    acknowledgements: VecDeque<(Height, Exact)>,
    /// Active barrier, whose output includes the height of its captured prefix.
    sync: Option<Handle<(Height, bool)>>,
}

impl Durability {
    /// Initialize tracking at a height already known to be durable.
    const fn new(height: Height) -> Self {
        Self {
            durable: height,
            acknowledgements: VecDeque::new(),
            sync: None,
        }
    }

    /// Return the highest applied height, or the durable floor when none are pending.
    fn latest_applied(&self) -> Height {
        self.acknowledgements
            .back()
            .map_or(self.durable, |(height, _)| *height)
    }

    /// Record a newly applied height and retain its acknowledgement until durability.
    ///
    /// Heights must be recorded in strictly increasing order.
    fn applied(&mut self, height: Height, acknowledgement: Exact) {
        assert!(
            height > self.latest_applied(),
            "finalized heights must increase"
        );
        self.acknowledgements.push_back((height, acknowledgement));
    }

    /// Return whether applied state remains uncovered and no sync is active.
    fn needs_sync(&self) -> bool {
        self.sync.is_none() && self.durable < self.latest_applied()
    }

    /// Record a barrier covering applied state through `height`.
    ///
    /// Only one barrier may be active, and `height` must extend the durable prefix without
    /// exceeding the latest applied height.
    fn started(&mut self, (height, barrier): (Height, Barrier)) {
        assert!(self.sync.is_none(), "sync already active");
        assert!(height > self.durable && height <= self.latest_applied());
        self.sync = Some(Handle::from_future(async move {
            Ok((height, barrier.durable().await))
        }));
    }

    /// Complete the active sync and acknowledge every height it made durable.
    ///
    /// Returns false without advancing the durable prefix when durability was not established.
    fn complete(&mut self, (height, durable): (Height, bool)) -> bool {
        assert!(self.sync.take().is_some(), "sync not active");
        if !durable {
            return false;
        }
        assert!(height > self.durable && height <= self.latest_applied());
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

    /// Return whether `height` lies within the known durable prefix.
    fn covers(&self, height: Height) -> bool {
        self.durable >= height
    }

    /// Return whether a barrier is active.
    const fn syncing(&self) -> bool {
        self.sync.is_some()
    }

    /// Await the active barrier, remaining pending while none is active so callers can select
    /// unconditionally.
    async fn completion(&mut self) -> (Height, bool) {
        let Some(sync) = &mut self.sync else {
            return pending().await;
        };
        sync.await.expect("internal sync handle cannot fail")
    }
}

/// Start a durability barrier for pending applied state.
///
/// Verification work remains driven while the database writer is acquired. Returns false if the
/// actor stops before the barrier starts, dropping the in-flight capture.
async fn start_sync<E, A, P>(
    shutdown: &mut (impl Future + Unpin),
    durability: &mut Durability,
    processor: &mut Processor<E, A, P>,
) -> bool
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E> + 'static,
    P: Marshal<Block = A::Block>,
{
    // A requested successor is a no-op when no applied suffix remains uncovered.
    if !durability.needs_sync() {
        return true;
    }

    // Drive verification jobs until the barrier starts, then bind its completion to exactly the
    // prefix it captured.
    select! {
        _ = &mut *shutdown => false,
        started = processor.sync() => {
            durability.started(started);
            true
        },
    }
}

pub(super) struct Processing<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Provider cloned into each proposal.
    pub(super) provider: A::Provider,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and are reported to the application and
    /// acknowledged without reapplying them.
    pub(super) skip_finalized_until: Option<Height>,
}

impl<E, A> Processing<E, A>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E> + 'static,
{
    /// Run the loop until shutdown.
    ///
    /// `queued` holds verification requests that arrived during state sync
    /// and have not started yet.
    pub async fn start<P: Marshal<Block = A::Block>>(
        mut self,
        mut processor: Processor<E, A, P>,
        queued: Vec<VerificationRequest<E, A>>,
    ) {
        let mut pending_prune = None;
        let mut held_message = None;
        for request in queued {
            processor.schedule(request);
        }

        // One database sync stays active while later finalized state accumulates behind it.
        // Completion starts a successor for that suffix unless a pending prune must establish
        // the next storage-mutation boundary first.
        let mut durability = Durability::new(processor.processed_height());

        // `select_loop!` creates one shutdown signal for the actor's whole life.
        // Re-creating it per iteration would record an extra auditor event on the
        // deterministic runtime each time.
        select_loop! {
            self.context,
            on_start => {
            // Observe completed durability before taking more work. A queued prune suppresses
            // the automatic dirty-suffix successor until the prune has run at its own
            // mutation boundary.
            if let Some(completion) = durability.completion().now_or_never()
                && !durability.complete(completion)
            {
                return;
            }
            if pending_prune.is_none()
                && !start_sync(&mut shutdown, &mut durability, &mut processor).await
            {
                return;
            }

            // Step the jobs that finished before admitting another message, so
            // mailbox traffic cannot starve them.
            processor.step_ready();

            // A message held back by an active proposal is the FIFO barrier
            // for subsequent mailbox work, so handle it before later arrivals.
            let prune_needs_sync = pending_prune.is_some() && durability.needs_sync();
            let message = if prune_needs_sync {
                // The suppressed successor sync would defer durability, and the acks
                // behind it, until the mailbox went idle. Run the prune's boundary now.
                Err(TryRecvError::Empty)
            } else {
                match held_message.take() {
                    Some(message) => Ok(message),
                    None => self.mailbox.try_recv(),
                }
            };

            // A prune remains idle work unless it owns the next dirty-suffix mutation boundary.
            let next = match message {
                // A message is ready. Handle it now, regardless of any queued prune.
                Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                Err(TryRecvError::Empty) => match pending_prune.take() {
                    Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                    // No message and nothing to prune. Wait on the mailbox, driving
                    // the active sync and verification jobs while idle.
                    None => {
                        let mailbox = &mut self.mailbox;
                        let durability = &mut durability;
                        let processor = &mut processor;
                        Either::Right(async move {
                            loop {
                                select! {
                                    message = mailbox.recv() => {
                                        if message.is_none() {
                                            debug!("mailbox closed, stopping processing");
                                        }
                                        break message.map(Step::Message);
                                    },
                                    completion = durability.completion() => {
                                        break Some(Step::Sync(completion));
                                    },
                                    _ = processor.step_next() => continue,
                                }
                            }
                        })
                    }
                },
                Err(TryRecvError::Disconnected) => {
                    debug!("mailbox closed, stopping processing");
                    return;
                }
            };

            },
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
                return;
            },
            step = next => {
                let Some(step) = step else {
                    return;
                };

                match step {
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
                        processor.propose(process, context, ancestry, input, response);
                        let mut receive_messages = true;
                        while processor.proposing() {
                            if receive_messages {
                                select! {
                                    _ = &mut shutdown => {
                                        debug!("shutdown signal received, stopping processing");
                                        return;
                                    },
                                    message = self.mailbox.recv() => match message {
                                        Some(Message::Verify(request)) => processor.schedule(request),
                                        Some(message) => {
                                            // Only verification may overtake an active proposal. The
                                            // first other message becomes a FIFO barrier for later
                                            // mailbox work.
                                            held_message = Some(message);
                                            receive_messages = false;
                                        }
                                        None => receive_messages = false,
                                    },
                                    _ = processor.step_next() => {},
                                }
                            } else {
                                select! {
                                    _ = &mut shutdown => {
                                        debug!("shutdown signal received, stopping processing");
                                        return;
                                    },
                                    _ = processor.step_next() => {},
                                }
                            }
                        }
                    }
                    Step::Message(Message::Verify(request)) => processor.schedule(request),
                    Step::Message(Message::Finalized {
                        span,
                        block,
                        acknowledgement,
                    }) => {
                        let process = info_span!(parent: &span, "stateful.actor.finalized");
                        let context = self.context.as_present();
                        if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                            // `Application::finalized` is at-least-once. Exiting on
                            // stop leaves the block unacknowledged, and marshal
                            // redelivers it after restart.
                            select! {
                                _ = &mut shutdown => {
                                    debug!("shutdown signal received, stopping processing");
                                    return;
                                },
                                _ = processor
                                    .notify_finalized(context, block.as_ref())
                                    .instrument(process) => {
                                    acknowledgement.acknowledge();
                                },
                            }
                            continue;
                        }

                        if processor.processed(&block) {
                            // A duplicate report. Marshal redelivers a processed height
                            // only after a restart, where startup aligned the databases
                            // to durable state.
                            acknowledgement.acknowledge();
                            continue;
                        }

                        // Verification jobs keep running during the apply,
                        // pausing at their next batch read. Exiting on stop drops
                        // the un-applied batches, and marshal redelivers the
                        // unacknowledged block after restart.
                        let should_start_sync = !durability.syncing();
                        let (prune, started);
                        select! {
                            _ = &mut shutdown => {
                                warn!(
                                    height = block.height().get(),
                                    "exiting mid-finalize on shutdown"
                                );
                                return;
                            },
                            driven = async {
                                let prune = processor.finalize(context, block.as_ref()).await;
                                let started = if should_start_sync {
                                    Some(processor.sync().await)
                                } else {
                                    None
                                };
                                processor.notify_finalized(context, block.as_ref()).await;
                                (prune, started)
                            }
                            .instrument(process.clone()) => {
                                (prune, started) = driven;
                            },
                        }

                        // Keep the publication bookkeeping under the same span.
                        let _span = process.entered();
                        debug!(
                            height = block.height().get(),
                            "applied finalized database batch"
                        );

                        // Retain marshal acknowledgements until a barrier makes their database
                        // prefix durable. This keeps marshal's processed floor within
                        // recoverable database state while later work proceeds. The
                        // acknowledgement window bounds the queue; a barrier that returns false
                        // leaves the suffix unacknowledged for restart replay.
                        let height = block.height();
                        durability.applied(height, acknowledgement);

                        if let Some(started) = started {
                            durability.started(started);
                        }

                        // Defer pruning to the loop so it can settle durability at one
                        // database mutation boundary.
                        if let Some(prune) = prune {
                            pending_prune = Some(prune);
                        }
                    }
                    Step::Prune(prune) => {
                        // Pruning owns a strict database mutation boundary: no sync active and the
                        // pruned range durable. Step jobs while waiting. At most two syncs complete
                        // here, since the prune target was applied before the prune was queued and
                        // no finalization arrives inside this arm.
                        loop {
                            if !durability.syncing() {
                                if durability.covers(prune.barrier_height) {
                                    break;
                                }
                                assert!(
                                    durability.needs_sync(),
                                    "uncovered prune target must have unapplied durability",
                                );
                                if !start_sync(&mut shutdown, &mut durability, &mut processor).await
                                {
                                    return;
                                }
                            }
                            select! {
                                _ = &mut shutdown => {
                                    debug!("shutdown signal received, stopping processing");
                                    return;
                                },
                                completion = durability.completion() => {
                                    if !durability.complete(completion) {
                                        return;
                                    }
                                },
                                _ = processor.step_next() => {},
                            }
                        }
                        // Prune mutates storage and can take a while. Race it against
                        // shutdown so a stop signal is not blocked past its deadline; the
                        // prune is safe to drop mid-flight and re-runs on restart.
                        select! {
                            _ = &mut shutdown => {
                                debug!("shutdown signal received, stopping processing");
                                return;
                            },
                            _ = processor.prune(prune) => {},
                        }
                        // The published snapshots predate this prune and pin the pruned
                        // storage, so capture and publish afresh right away.
                        select! {
                            _ = &mut shutdown => {
                                debug!("shutdown signal received, stopping processing");
                                return;
                            },
                            _ = processor.publish_snapshot() => {},
                        }
                    }
                    Step::Sync(completion) => {
                        if !durability.complete(completion) {
                            return;
                        }
                    }
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
    use super::{Message, Processing, skip_finalized_block};
    use crate::stateful::{
        Application, ExecutionError, Input, Proposed, PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
        },
        db::{Publisher, Reader, ReadersOf, Single, SnapshotsOf, Subscriber},
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
        Clock as _, ContextCell, Error as RuntimeError, Handle, Metrics as _, Name, Runner as _,
        Spawner as _, Supervisor as _, deterministic,
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
        /// Verifications that return [`ExecutionError::Stale`] after their gate
        /// releases, standing in for a batch read refused by a competing
        /// finalization.
        stale_verifies: Arc<Mutex<usize>>,
        observed_contexts: Arc<Mutex<Vec<Name>>>,
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
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            let gate = self.proposal_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            Ok(None)
        }

        async fn verify(
            &mut self,
            context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.observed_contexts.lock().push(context.0.name());
            let mut ancestry = Box::pin(ancestry);
            let Some(_block) = ancestry.next().await else {
                return Ok(None);
            };
            let mut gate = self
                .verify_gates
                .lock()
                .pop_front()
                .expect("unexpected verification");
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
            {
                let mut stale = self.stale_verifies.lock();
                if *stale > 0 {
                    *stale -= 1;
                    return Err(ExecutionError::Stale);
                }
            }
            Ok(self.verify_valid.then_some(TestMerkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            Ok(TestMerkleized)
        }
    }

    #[derive(Clone)]
    struct ReadGatedApp {
        database: Reader<TestDb>,
        verify_gate_height: Height,
        verify_gate: Arc<Mutex<Option<ApplicationGate>>>,
    }

    impl Application<deterministic::Context> for ReadGatedApp {
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

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            let mut ancestry = Box::pin(ancestry);
            let Some(block) = ancestry.next().await else {
                return Ok(None);
            };
            if block.height() != self.verify_gate_height {
                return Ok(Some(TestMerkleized));
            }
            let database = self.database.read().await;
            let Some(mut gate) = self.verify_gate.lock().take() else {
                return std::future::pending().await;
            };
            let _ = gate.started.send(());
            let _ = (&mut gate.release).await;
            drop(database);
            Ok(Some(TestMerkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            Ok(TestMerkleized)
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
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            panic!("replay-gated application proposal is not used")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.verify_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            Ok(Some(TestMerkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            let gate = (block.height() == self.gate_height)
                .then(|| self.gates.lock().pop_front())
                .flatten();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            Ok(TestMerkleized)
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
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

    /// Rejects `verify` for one height while `apply` accepts everything, so a
    /// replayed (applied) ancestor diverges from what verification would decide.
    #[derive(Clone)]
    struct RejectVerifyApp {
        rejected_height: Height,
        apply_calls: Arc<AtomicUsize>,
        verify_calls: Arc<AtomicUsize>,
    }

    impl Application<deterministic::Context> for RejectVerifyApp {
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
            panic!("reject-verify application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            panic!("reject-verify application proposal is not used")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            let mut ancestry = Box::pin(ancestry);
            let block = ancestry
                .next()
                .await
                .expect("verification should receive a candidate block");
            if block.height() == self.rejected_height {
                return Ok(None);
            }
            Ok(Some(TestMerkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TestMerkleized)
        }
    }

    /// A directly-notarized but application-invalid parent, replayed via `apply`
    /// while verifying an optimistic child, must not be laundered into a verified
    /// verdict. A later verification (which is what certification recovery drives
    /// after a restart drops the in-memory gate) must run `Application::verify` on
    /// the parent and reject it, rather than short-circuiting on the cached replay
    /// state.
    #[test]
    fn replayed_parent_does_not_short_circuit_later_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);

            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"replayed-parent-bypass", 1).schemes
                [0]
            .clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "replayed-parent-bypass",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;

            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = RejectVerifyApp {
                rejected_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));
            let mut mailbox = Mailbox::new(sender);

            // Verifying the child reconstructs the parent's state with `apply`.
            assert!(
                mailbox
                    .verify(
                        (context.child("verify_child"), child.context()),
                        ancestry::from_iter([
                            Arc::new(child),
                            Arc::new(parent.clone()),
                            Arc::new(genesis.clone()),
                        ]),
                    )
                    .await,
                "child verification should succeed after replaying its parent",
            );
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

            // The parent was only replayed, never verified. Certification
            // recovery must run `verify` on it and reject the invalid block.
            assert!(
                !mailbox
                    .verify(
                        (context.child("verify_parent"), parent.context()),
                        ancestry::from_iter([Arc::new(parent), Arc::new(genesis)]),
                    )
                    .await,
                "parent verification must reject the application-invalid block",
            );
            assert_eq!(
                verify_calls.load(Ordering::SeqCst),
                2,
                "certification recovery must run Application::verify on the replayed parent",
            );

            actor.abort();
            drop(marshal.guards);
        });
    }

    /// A spawned gated application's mailbox, snapshot subscriber, marshal
    /// guard, and actor handle.
    type GatedApplication = (
        Mailbox<deterministic::Context, GatedApp>,
        Subscriber<SnapshotsOf<TestDatabases, deterministic::Context>>,
        Box<dyn std::any::Any>,
        Handle<()>,
    );

    async fn spawn_gated_application(
        context: &deterministic::Context,
        prefix: &str,
        app: GatedApp,
    ) -> GatedApplication {
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
        spawn_gated_application_over(context, app, marshal)
    }

    /// Spawn the gated application's processing loop over a caller-supplied
    /// marshal fixture.
    fn spawn_gated_application_over(
        context: &deterministic::Context,
        app: GatedApp,
        marshal: fixtures::MarshalFixture,
    ) -> GatedApplication {
        let publication_context = context.child("publication");
        let (publisher, reader) = Publisher::new(&publication_context);
        let processor = Processor::new(
            app,
            test_databases(),
            marshal.mailbox.clone(),
            publisher,
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            skip_finalized_until: None,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.start(processor, Vec::new()));
        (Mailbox::new(sender), reader, marshal.guards, actor)
    }

    /// Spawn a [`Processing`] loop over a gated [`TestDb`], returning its
    /// mailbox, flush controls, the snapshot subscriber, a guard keeping the
    /// (never-started) marshal actor's mailbox open, and the processing actor
    /// handle.
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
        let pruning = prune_config
            .map(|config| Pruning::build(config, marshal.mailbox.max_pending_acks(), 0));
        let app = GatedApp {
            verify_gates: Arc::new(Mutex::new(verify_gates)),
            proposal_gate: Arc::new(Mutex::new(None)),
            verify_valid: true,
            stale_verifies: Arc::default(),
            observed_contexts: Arc::default(),
        };
        let (publisher, reader) = Publisher::new(context);
        let mut processor = Processor::new(
            app,
            databases,
            marshal.mailbox.clone(),
            publisher,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        processor.publish_snapshot().await;
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            skip_finalized_until: None,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.start(processor, Vec::new()));
        (Mailbox::new(sender), control, reader, marshal.guards, actor)
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
        verify_gate: ApplicationGate,
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
            database: <Single<TestDb> as crate::stateful::db::DatabaseSet<
                deterministic::Context,
            >>::readers(&databases),
            verify_gate_height: Height::new(3),
            verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
        };
        let pruning = prune_config
            .map(|config| Pruning::build(config, marshal.mailbox.max_pending_acks(), 0));
        let (publisher, _subscriber) = Publisher::new(context);
        let mut processor = Processor::new(
            app,
            databases,
            marshal.mailbox.clone(),
            publisher,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        processor.publish_snapshot().await;
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            skip_finalized_until: None,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.start(processor, Vec::new()));
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
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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

    /// A verification that goes stale because its own block finalized mid-execution
    /// is answered from the canonical chain as true, not false.
    #[test]
    fn stale_verification_of_finalized_block_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::new(Mutex::new(1)),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, marshal, actor) =
                spawn_gated_application(&context, "stale-self-finalized", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let block_context = block.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block_context),
                ancestry::from_iter([Arc::new(block.clone()), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            // The block itself finalizes while its verification is parked.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block), acknowledgement));
            waiter.await.expect("finalization should be acknowledged");

            // The parked execution resumes and refuses with Stale, and the verifier
            // re-checks canonical state and answers true.
            release.send(()).expect("verification should remain active");
            assert!(verify.await);
            actor.abort();
            drop(marshal);
        });
    }

    /// A valid verification overtaken by its own descendant's finalization
    /// still answers true.
    #[test]
    fn overtaken_verification_of_finalized_block_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::new(Mutex::new(0)),
                observed_contexts: Arc::default(),
            };
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&block, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"gated-application", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "overtaken-canonical",
                scheme,
                &block,
                NZUsize!(1),
                true,
            )
            .await;
            let (mut mailbox, _subscriber, marshal_guards, actor) =
                spawn_gated_application_over(&context, app, marshal);

            let block_context = block.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block_context),
                ancestry::from_iter([Arc::new(block.clone()), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            // The candidate and then its child finalize while the verification
            // is parked, moving the anchor past the candidate's height.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block), acknowledgement));
            waiter
                .await
                .expect("candidate finalization should be acknowledged");
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(child), acknowledgement));
            waiter
                .await
                .expect("child finalization should be acknowledged");

            // The resumed execution succeeds with no stale read to surface, and
            // the refused cache does not change the verdict.
            release.send(()).expect("verification should remain active");
            assert!(verify.await);
            actor.abort();
            drop(marshal_guards);
        });
    }

    /// A verification that goes stale because a competing block finalized is
    /// answered from the canonical chain as false.
    #[test]
    fn stale_verification_of_competing_block_answers_false() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::new(Mutex::new(1)),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, marshal, actor) =
                spawn_gated_application(&context, "stale-competing", app).await;

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let winner = TestBlock::child(&genesis, 2);
            let block_context = block.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block_context),
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            // A competing block at the same height finalizes while the
            // verification is parked.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(winner), acknowledgement));
            waiter.await.expect("finalization should be acknowledged");

            release.send(()).expect("verification should remain active");
            assert!(!verify.await);
            actor.abort();
            drop(marshal);
        });
    }

    /// A stale attempt whose candidate is still above the new anchor re-executes
    /// against the post-finalization state and completes with a verdict.
    #[test]
    fn stale_verification_reexecutes_and_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (first, first_started, first_release) = application_gate();
            let (second, second_started, second_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([parent_gate, first, second]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let staleness = app.stale_verifies.clone();
            let (mut mailbox, _subscriber, marshal, actor) =
                spawn_gated_application(&context, "stale-reexecute", app).await;

            // Verify the parent first so the candidate forks from pending state.
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let block = TestBlock::child(&parent, 2);
            let mut parent_verifier = mailbox.clone();
            let mut parent_verify = Box::pin(parent_verifier.verify(
                (context.child("verify_parent"), parent.context()),
                ancestry::from_iter([Arc::new(parent.clone()), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut parent_verify).is_pending());
            parent_started
                .await
                .expect("parent verification should start");
            parent_release
                .send(())
                .expect("parent verification should remain active");
            assert!(parent_verify.await);

            let block_context = block.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), block_context),
                ancestry::from_iter([Arc::new(block), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            first_started.await.expect("verification should start");
            *staleness.lock() = 1;

            // The candidate's parent finalizes while the candidate executes.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            waiter.await.expect("finalization should be acknowledged");

            // The stale attempt re-classifies (still above the anchor) and
            // re-executes against the new state.
            first_release
                .send(())
                .expect("verification should remain active");
            second_started.await.expect("retry should re-execute");
            second_release.send(()).expect("retry should remain active");
            assert!(verify.await);
            actor.abort();
            drop(marshal);
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
                stale_verifies: Arc::default(),
                observed_contexts: observed_contexts.clone(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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

    /// A candidate at the processed height is decided from the anchor before
    /// its parent is read, so an ancestry that ends at the candidate still
    /// answers.
    #[test]
    fn processed_candidate_is_decided_before_its_parent_is_read() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::new())),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _guards, actor) =
                spawn_gated_application(&context, "processed-candidate", app).await;
            let anchor_block = TestBlock::new(0, 0);
            let conflicting = TestBlock::new(0, 9);

            assert!(
                mailbox
                    .verify(
                        (context.child("canonical"), anchor_block.context()),
                        ancestry::from_iter([Arc::new(anchor_block)]),
                    )
                    .await
            );
            assert!(
                !mailbox
                    .verify(
                        (context.child("conflicting"), conflicting.context()),
                        ancestry::from_iter([Arc::new(conflicting)]),
                    )
                    .await
            );
            actor.abort();
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
                .expect("finalized block sync should remain pending");
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
    fn pending_proposal_does_not_block_new_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
    fn finalization_keeps_compatible_verification_running() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([parent_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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

            // The apply does not touch the child's attempt. It is still waiting
            // in the application and answers from that same attempt.
            child_release
                .send(())
                .expect("the attempt should still be live after the apply");
            assert!(verify_child.await);
            actor.abort();
        });
    }

    #[test]
    fn finalized_away_fork_verification_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (fork_gate, fork_started, fork_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([fork_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
            let mut waiter = Box::pin(waiter);
            select! {
                result = &mut waiter => {
                    result.expect("winning block should be acknowledged");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("winning block was not acknowledged");
                },
            }

            // The losing child runs to completion. Its parent is gone from the
            // pending set, so caching its result is refused, and the verdict
            // is unchanged.
            child_release
                .send(())
                .expect("the attempt should still be live after the apply");
            select! {
                valid = &mut verify_child => {
                    assert!(valid, "a branch-valid verification answers true on a finalized-away fork");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("incompatible verification did not resolve");
                },
            }
            actor.abort();
        });
    }

    /// A verification whose fork a finalization dropped still answers its
    /// branch-relative verdict.
    #[test]
    fn pruned_deep_fork_verification_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let (grandchild_gate, grandchild_started, grandchild_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([
                    parent_gate,
                    child_gate,
                    grandchild_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _subscriber, _marshal, actor) =
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
            waiter.await.expect("winning block should be acknowledged");
            grandchild_release
                .send(())
                .expect("the attempt should still be live after the apply");

            let result = select! {
                valid = &mut verify_grandchild => Some(valid),
                _ = context.sleep(Duration::from_millis(100)) => None,
            };
            actor.abort();
            assert_eq!(
                result,
                Some(true),
                "a branch-valid verification answers true even after its fork is pruned",
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: Some(finalized.height()),
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
    fn deferred_verification_resumes_after_sync() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                stale_verifies: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                Some(Message::Verify(request)) => request,
                _ => panic!("deferred verification request must arrive"),
            };

            // Resume the deferred verification after state sync.
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                skip_finalized_until: Some(Height::new(0)),
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, vec![request]));

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
    fn finalization_does_not_wait_for_a_shared_replay() {
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                1,
                "siblings needing the same parent should share one replay",
            );

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            context.sleep(Duration::from_millis(10)).await;

            // The apply does not wait for the shared replay. Because that replay
            // has not cached the winner yet, the finalization reconstructs it.
            finalized_started
                .await
                .expect("finalization hook should start");
            finalized_release
                .send(())
                .expect("finalization hook should remain active");
            waiter
                .await
                .expect("finalized parent should be acknowledged");

            // The shared replay is still live afterward. Its parent is now the
            // processed anchor, so both siblings continue from it.
            apply_release
                .send(())
                .expect("the shared replay should still be live after the apply");
            verify_started
                .await
                .expect("verification should reach the application");
            let _ = verify_release.send(());
            assert!(first.await);
            assert!(second.await);
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                2,
                "the finalization reconstructs the winner once, and the siblings \
                 need no further replay",
            );
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// When the job replaying a shared parent is cancelled, a waiting sibling
    /// takes the replay over instead of failing.
    #[test]
    fn cancelled_replay_owner_hands_the_replay_to_a_waiter() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let first_child = TestBlock::child(&parent, 2);
            let second_child = TestBlock::child(&parent, 3);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"replay-owner-cancel", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "replay-owner-cancel",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (first_gate, first_started, _first_release) = application_gate();
            let (second_gate, second_started, second_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([first_gate, second_gate]))),
                verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

            let mut first_verifier = mailbox.clone();
            let mut first = Box::pin(first_verifier.verify(
                (context.child("first_verify"), first_child.context()),
                ancestry::from_iter([Arc::new(first_child), Arc::new(parent.clone())]),
            ));
            let mut second_verifier = mailbox.clone();
            let mut second = Box::pin(second_verifier.verify(
                (context.child("second_verify"), second_child.context()),
                ancestry::from_iter([Arc::new(second_child), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut first).is_pending());
            assert!(poll!(&mut second).is_pending());
            first_started
                .await
                .expect("the first sibling should own the replay");
            context.sleep(Duration::from_millis(10)).await;
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                1,
                "siblings needing the same parent should share one replay",
            );

            // Dropping the owner's request cancels its replay mid-apply.
            drop(first);
            second_started
                .await
                .expect("the waiting sibling should take the replay over");
            second_release
                .send(())
                .expect("the replay should remain active");
            verify_started
                .await
                .expect("verification should reach the application");
            let _ = verify_release.send(());
            assert!(second.await);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 2);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 1);
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// A candidate whose own finalization completes while its parent replay is
    /// parked is answered true from the canonical chain, even though the replay
    /// resolves as invalid ancestry afterward.
    #[test]
    fn candidate_finalized_during_parent_replay_answers_true() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let candidate = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"finalized-mid-replay", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "finalized-mid-replay",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (gate, apply_started, apply_release) = application_gate();
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                verify_gate: Arc::new(Mutex::new(None)),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

            // The candidate's verification parks inside the shared replay of its
            // unknown parent.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), candidate.context()),
                ancestry::from_iter([Arc::new(candidate.clone()), Arc::new(parent)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            apply_started.await.expect("parent replay should start");

            // The candidate itself finalizes (reconstructed by the finalization,
            // since the parked replay has not cached its parent).
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(candidate), acknowledgement));
            waiter
                .await
                .expect("finalized candidate should be acknowledged");

            // The replay resumes, resolves as invalid ancestry (its parent is
            // below the new anchor), and the verifier answers from the canonical
            // chain instead of voting false.
            apply_release
                .send(())
                .expect("the parent replay should still be live");
            assert!(verify.await);
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// A valid descendant whose parent replay crosses the parent's own
    /// finalization continues from the new anchor, not answered false.
    #[test]
    fn parent_finalized_during_replay_continues_from_the_anchor() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let candidate = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"anchor-mid-replay", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "anchor-mid-replay",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let (gate, apply_started, apply_release) = application_gate();
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                verify_gate: Arc::new(Mutex::new(None)),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

            // The candidate's verification parks inside the shared replay of its
            // unknown parent.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), candidate.context()),
                ancestry::from_iter([Arc::new(candidate.clone()), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            apply_started.await.expect("parent replay should start");

            // The parent finalizes while the replay is parked, moving the
            // anchor past the walk this attempt started from. The candidate
            // remains a valid, unfinalized descendant of the new anchor.
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(parent), acknowledgement));
            waiter
                .await
                .expect("finalized parent should be acknowledged");

            // The replay of the block that became the anchor is already
            // reflected, so the job forks the candidate from it and answers true.
            apply_release
                .send(())
                .expect("the parent replay should still be live");
            assert!(verify.await);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn finalization_uses_cached_winner_while_replay_remains_active() {
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
                .expect("the cached winner should finalize while its replay runs");
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
    fn consecutive_finalizations_replay_the_descendant_once() {
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
            let verify_gate = Arc::new(Mutex::new(None));
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gate: verify_gate.clone(),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: first.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
            let (gate, verify_started, verify_release) = application_gate();
            assert!(verify_gate.lock().replace(gate).is_none());

            let (acknowledgement, first_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(first), acknowledgement));
            replay_release
                .send(())
                .expect("first-block replay should remain active");
            first_waiter
                .await
                .expect("first finalized block should be acknowledged");
            verify_started
                .await
                .expect("descendant verification should start after the first finalization");

            let (acknowledgement, second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(second), acknowledgement));
            second_waiter
                .await
                .expect("second finalized block should be acknowledged");
            verify_release
                .send(())
                .expect("the descendant verification should be held");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(
                valid,
                "a descendant of both finalized blocks must verify, not be rejected",
            );
            assert!(
                verify_calls.load(Ordering::SeqCst) > 1,
                "both the independent and the descendant verification should have run",
            );
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                2,
                "replay should not repeat work already cached as pending state",
            );
        });
    }

    #[test]
    fn retained_verification_can_finish_before_queued_finalization() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let losing = TestBlock::child(&first, 2);
            let winner = TestBlock::child(&first, 3);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"finalize-retry-order", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "finalize-retry-order",
                scheme,
                &genesis,
                NZUsize!(2),
                true,
            )
            .await;
            let (replay_gate, replay_started, replay_release) = application_gate();
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (finalized_gate, finalized_started, finalized_release) = application_gate();
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                gate_height: first.height(),
                apply_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
            };
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
        });
    }

    #[test]
    fn pruning_does_not_disturb_a_live_replay() {
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
            let (replay_gate, replay_started, replay_release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([replay_gate]))),
                verify_gate: Arc::new(Mutex::new(None)),
                finalized_gate: Arc::new(Mutex::new(None)),
                gate_height: parent.height(),
                apply_calls: apply_calls.clone(),
                verify_calls: verify_calls.clone(),
            };
            let control = FlushControl::default();
            let (prune_started, prune_release) = control.gate_prune();
            let databases = Single::from(TestDb::gated(control.clone()));
            let pruning = Pruning::build(
                PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                },
                1,
                0,
            );
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                app,
                databases,
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

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
                result = replay_started => {
                    result.expect("verification should start before pruning");
                },
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

            // The prune runs while the replay is still parked in the
            // application, and the replay then finishes on its first attempt.
            prune_started.await.expect("prune should start");
            assert_eq!(
                control.flushes.lock().len(),
                0,
                "the dirty successor must not overlap the conservative database prune",
            );
            prune_release.send(()).expect("prune should remain active");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            replay_release
                .send(())
                .expect("the replay should still be live after pruning");
            assert!(verify.await);
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                3,
                "two finalizations reconstruct their own blocks, plus the replay",
            );
            assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            release.send(Ok(())).expect("newer flush should be pending");
            waiter2.await.expect("newer block should be acknowledged");
            actor.abort();
            marshal.abort();
        });
    }

    /// Pruning waits for the flush that covers its target without waiting for newer state.
    #[test]
    fn prune_starts_after_target_sync() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Marshal only receives prune requests here. Its actor never runs.
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, subscriber, _marshal, _actor) = spawn_processing_with_gates(
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

            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must wait for pending flushes",
            );
            assert_eq!(
                subscriber.latest(),
                Some(1),
                "snapshots serve when their sync starts, ahead of its flush",
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

            // Releasing block 1 makes the prune target durable. Glue prunes before starting the
            // tracked successor for replayable block 2.
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
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    /// A verification keeps making progress while a queued prune waits for the
    /// covering durability sync over its coalesced target.
    #[test]
    fn verification_completes_while_prune_awaits_covering_sync() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, subscriber, _marshal, _actor) = spawn_processing_with_gates(
                &context,
                "gated-covering-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(3),
                    retained_marshal_blocks: 1,
                    retained_qmdb_blocks: 0,
                }),
                VecDeque::from([verify_gate]),
            )
            .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let block3 = TestBlock::child(&block2, 3);

            // Block 1 starts the only tracked sync, and its flush stays parked.
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));

            // Hold a live verification inside the application before the prune
            // queues.
            let consensus_context = block3.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(block3.clone()), Arc::new(block2)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should start before the prune queues");

            // Block 3 coalesces behind block 1's parked flush and queues a
            // prune whose barrier height (2) never got a sync of its own.
            let (acknowledgement, waiter3) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block3), acknowledgement));
            while control.applied.load(Ordering::Relaxed) < 3 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);

            // Releasing block 1's flush leaves durability (1) short of the
            // prune target (2), so the prune starts the covering sync inline
            // and waits on its parked flush.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                subscriber.latest(),
                Some(3),
                "the covering sync publishes the coalesced suffix",
            );
            assert!(control.pruned.lock().is_empty());

            // The verification must resolve while the prune waits on the
            // covering flush.
            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                result = &mut verify => assert!(result),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("covering-sync wait blocked active verification");
                },
            }

            // Releasing the covering flush makes the target durable. The acks
            // drain and the prune runs at its boundary.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            waiter3.await.expect("block 3 acknowledgement");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![2]);
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
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![1]);

            // The prune publishes fresh snapshots right away. They carry the
            // same content as later publishes, so count publications instead
            // (startup, block 1's sync, the post-prune publish, then block 2's
            // successor sync).
            while publications(&context) < 4 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                subscriber.latest(),
                Some(2),
                "the fresh snapshots must serve block 2's state"
            );

            // The successor sync covers block 2's dirty suffix.
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    #[test]
    fn stable_leader_finalizations_coalesce_while_sync_pending() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, _actor) =
                spawn_processing(&context, "gated-coalesced-sync", None).await;

            const BLOCKS: u64 = 3;

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let mut waiters = Vec::with_capacity(BLOCKS as usize - 1);
            for height in 2..=BLOCKS {
                let (acknowledgement, waiter) = Exact::handle();
                let _ = mailbox.report(Update::Block(
                    Arc::new(TestBlock::new(height, height as u8)),
                    acknowledgement,
                ));
                waiters.push(waiter);
            }
            while control.applied.load(Ordering::Relaxed) < BLOCKS as usize {
                context.sleep(Duration::from_millis(10)).await;
            }

            assert_eq!(
                control.flushes.lock().len(),
                1,
                "a pending sync must coalesce later finalized state instead of starting a second sync",
            );
            assert!(poll!(&mut waiter1).is_pending());
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }

            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("first sync should remain pending");
            waiter1.await.expect("first block acknowledgement");
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }

            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("successor sync should remain pending");
            for acknowledgement in futures::future::join_all(waiters).await {
                acknowledgement.expect("stable-leader block acknowledgement");
            }
            assert!(control.flushes.lock().is_empty());
        });
    }

    #[test]
    fn successor_sync_drives_verification_holding_database_read() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (mut mailbox, control, _marshal, _actor) = spawn_read_gated_processing(
                &context,
                "successor-sync-read-owner",
                verify_gate,
                None,
            )
            .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(block1.clone()),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(block2.clone()),
                acknowledgement,
            ));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            let block3 = TestBlock::child(&block2, 3);
            let consensus_context = block3.context();
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(block3), Arc::new(block2)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should acquire the database read");

            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("first sync should remain pending");
            waiter1.await.expect("first block acknowledgement");
            assert!(poll!(&mut waiter2).is_pending());

            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                result = &mut verify => assert!(result),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("successor sync stopped polling the verification that owned its read lock");
                },
            }

            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("successor sync should remain pending");
            waiter2.await.expect("second block acknowledgement");
        });
    }

    #[test]
    fn shutdown_preempts_successor_sync_waiting_for_verification_reader() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (verify_gate, verify_started, _verify_release) = application_gate();
            let (mut mailbox, control, _marshal, actor) =
                spawn_read_gated_processing(&context, "successor-sync-shutdown", verify_gate, None)
                    .await;

            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1.clone()), acknowledgement));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2.clone()), acknowledgement));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            let block3 = TestBlock::child(&block2, 3);
            let mut verifier = mailbox.clone();
            let verify = verifier.verify(
                (context.child("verify"), block3.context()),
                ancestry::from_iter([Arc::new(block3), Arc::new(block2)]),
            );
            futures::pin_mut!(verify);
            assert!(poll!(&mut verify).is_pending());
            verify_started
                .await
                .expect("verification should acquire the database read");

            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("first sync should remain pending");
            waiter1.await.expect("first block acknowledgement");

            let stopper = context.child("stopper");
            let stop = context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, Some(Duration::from_millis(100))).await });
            assert!(
                stop.await.expect("stop task should finish").is_ok(),
                "shutdown must preempt successor sync acquisition",
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
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, actor) = spawn_processing(
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
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);

            drop(control.flushes.lock().remove(0));
            actor.await.expect("processing actor should stop");
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
            assert!(
                subscriber.latest().is_none(),
                "serving must shut off after an aborted flush",
            );
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
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Block 1's snapshots already published while its flush is parked.
            assert_eq!(
                subscriber.latest(),
                Some(1),
                "snapshots must serve before their flush completes",
            );
            assert!(poll!(&mut waiter1).is_pending());

            // Completing the first sync acknowledges block 1. The successor sync
            // publishes block 2's snapshots when it starts, ahead of its own flush.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");

            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                subscriber.latest(),
                Some(2),
                "the successor sync must publish block 2's snapshots at start",
            );
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
        });
    }

    /// While the loop is idle, a completed flush must release its acknowledgement without
    /// displacing a simultaneously reported block, while an incomplete flush must cancel its
    /// acknowledgement when processing stops.
    #[test]
    fn idle_acks_follow_flush_outcome() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, actor) =
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
            let (acknowledgement, waiter2) = Exact::handle();
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
            // acknowledgement is canceled so marshal stops without advancing
            // its floor past unflushed state.
            drop(control.flushes.lock().remove(0));
            actor.await.expect("processing actor should stop");
            assert!(
                waiter2.await.is_err(),
                "unflushed block acknowledgement must be canceled",
            );
            assert!(
                subscriber.latest().is_none(),
                "sources must decline after the loop stops",
            );
        });
    }

    #[test]
    fn ready_aborted_flush_stops_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-ready-abort", None).await;

            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.flushes.lock().len(), 1);
            drop(control.flushes.lock().remove(0));

            actor.await.expect("processing actor should stop");
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

    /// Stopping processing with a flush in flight must cancel marshal's acknowledgement.
    #[test]
    fn shutdown_cancels_pending_flush_ack() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, actor) =
                spawn_processing(&context, "gated-shutdown", None).await;

            let (acknowledgement, waiter) = Exact::handle();
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
                waiter.await.is_err(),
                "shutdown must cancel in-flight acknowledgements",
            );
            assert!(
                subscriber.latest().is_none(),
                "serving must shut off once the actor stops",
            );
        });
    }

    /// A flush failure must panic the processing loop with the database identified and leave the
    /// block unacknowledged.
    #[test]
    #[should_panic(expected = "database sync failed (type")]
    fn flush_failure_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, _actor) =
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

            // The active sync panics when the loop next polls it.
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    /// An application whose proposal path observes fatal storage.
    #[derive(Clone)]
    struct FatalProposeApp;

    impl Application<deterministic::Context> for FatalProposeApp {
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
            panic!("fatal-propose application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            Err(ExecutionError::Fatal("disk failed".into()))
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            panic!("fatal-propose application verify is not used")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            Ok(TestMerkleized)
        }
    }

    /// Fatal storage observed during a proposal takes the actor down instead
    /// of masking a broken database behind an ordinary decline.
    #[test]
    #[should_panic(expected = "application proposal failed")]
    fn fatal_proposal_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"fatal-propose", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal_fixture"),
                "fatal-propose",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processor = Processor::new(
                FatalProposeApp,
                test_databases(),
                marshal.mailbox.clone(),
                publisher,
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
                skip_finalized_until: None,
            };
            let _actor = context
                .child("loop")
                .spawn(move |_| processing.start(processor, Vec::new()));

            let genesis = TestBlock::new(0, 0);
            let proposal_context = TestBlock::child(&genesis, 1).context();
            let _ = mailbox
                .propose(
                    (context.child("propose"), proposal_context),
                    ancestry::from_iter([Arc::new(genesis)]),
                    (),
                )
                .await;

            // The actor panics while handling the proposal.
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    /// An application still parked inside execution when shutdown begins.
    #[derive(Clone)]
    struct ParkedApp {
        /// Signals entry into `verify` or `apply`.
        started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    }

    impl Application<deterministic::Context> for ParkedApp {
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
            panic!("shutdown application genesis is not used")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            panic!("shutdown application propose is not used")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            mut ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            let _ = ancestry.next().await;
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            std::future::pending().await
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<TestMerkleized, ExecutionError> {
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            std::future::pending().await
        }
    }

    /// A spawned parked application's mailbox, execution entry signal, marshal
    /// guard, and actor handle.
    type SpawnedParkedApplication = (
        Mailbox<deterministic::Context, ParkedApp>,
        oneshot::Receiver<()>,
        Box<dyn std::any::Any>,
        Handle<()>,
    );

    fn spawn_parked_application(
        context: &deterministic::Context,
        marshal: fixtures::MarshalFixture,
    ) -> SpawnedParkedApplication {
        let (started_tx, started) = oneshot::channel();
        let publication_context = context.child("publication");
        let (publisher, _subscriber) = Publisher::new(&publication_context);
        let processor = Processor::new(
            ParkedApp {
                started: Arc::new(Mutex::new(Some(started_tx))),
            },
            test_databases(),
            marshal.mailbox.clone(),
            publisher,
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            skip_finalized_until: None,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.start(processor, Vec::new()));
        (Mailbox::new(sender), started, marshal.guards, actor)
    }

    /// A stop mid-replay exits the actor loop. The block stays unacknowledged
    /// so marshal redelivers it after a restart.
    #[test]
    fn shutdown_interrupts_a_parked_finalize() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"shutdown-app", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "finalize-shutdown",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let (mut mailbox, started, guards, actor) = spawn_parked_application(&context, marshal);

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block), acknowledgement));
            started.await.expect("finalize replay should start");

            let stopper = context.child("stopper");
            context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });
            assert!(
                waiter.await.is_err(),
                "an interrupted finalize must leave the block unacknowledged",
            );
            actor.await.expect("the actor should exit cleanly");
            drop(guards);
        });
    }

    /// A verification in flight at shutdown never resolves for its caller,
    /// before or after the actor exits.
    #[test]
    fn verify_caller_parks_across_shutdown() {
        deterministic::Runner::default().start(|context| async move {
            let mut signing = context.child("signing");
            let scheme = scheme_mocks::fixture(&mut signing, b"shutdown-app", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture(
                context.child("marshal"),
                "verify-shutdown",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let (mut mailbox, started, guards, actor) = spawn_parked_application(&context, marshal);

            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let mut verify = Box::pin(mailbox.verify(
                (context.child("verify"), block.context()),
                ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
            ));
            assert!(poll!(&mut verify).is_pending());
            started.await.expect("verification should start");

            let stopper = context.child("stopper");
            context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });
            actor.await.expect("the actor should exit cleanly");
            for _ in 0..64 {
                assert!(
                    poll!(&mut verify).is_pending(),
                    "an unanswered verify must park its caller",
                );
                context.sleep(Duration::from_millis(1)).await;
            }
            drop(guards);
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
