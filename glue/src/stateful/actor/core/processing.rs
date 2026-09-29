//! The post-sync processing loop of the stateful actor.
//!
//! The loop owns the database set and is the only thing that mutates it.
//! Verification jobs hold readers, so an apply never cancels one: a job
//! mid-read finishes that read and continues against the new state. A job on
//! the losing side of the apply is refused at its next batch operation
//! ([`ExecutionError::Stale`](crate::stateful::ExecutionError::Stale)) and
//! answered from the canonical chain.
//!
//! Each finalized block is applied immediately. Snapshots are captured and
//! published when a barrier starts, and one active barrier covers every
//! block applied behind it (see [`Publisher`]). The block is acknowledged to
//! marshal only once a barrier proves it durable. A queued prune owns the next
//! storage-mutation boundary. It waits until the pruned range is durable,
//! prunes, and publishes fresh snapshots right away.

use crate::stateful::{
    Application, Input,
    actor::{
        SyncTargets,
        core::{
            mailbox::Message,
            verifications::{Handler as Verifications, Request as VerificationRequest},
        },
        processor::{Applied, Processor, Prune, Publication},
    },
    db::{Barrier, Publisher, SnapshotsOf},
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
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use futures::{
    FutureExt as _,
    future::{Either, pending, ready},
};
use rand_core::Rng;
use std::{collections::VecDeque, sync::mpsc::TryRecvError};
use tracing::{Instrument as _, debug, error, info_span, warn};

/// Work selected for one iteration of the processing loop.
enum Step<M, P> {
    /// A message from the actor mailbox.
    Message(M),
    /// A pending prune selected to run.
    Prune(P),
    /// Completion of the active barrier (see [`Durability::completion`]).
    Barrier(Option<Height>),
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
    /// Returns `false` without advancing the durable height if `completion` is `None`, logging an
    /// error unless `shutdown` has fired. Panics if no barrier is active.
    fn complete(
        &mut self,
        completion: Option<Height>,
        shutdown: &mut (impl Future + Unpin),
    ) -> bool {
        assert!(self.barrier.take().is_some(), "barrier not active");
        let Some(height) = completion else {
            if shutdown.now_or_never().is_none() {
                error!("database barrier aborted without shutdown, stopping processing");
            }
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
/// Verifications keep running while the barrier waits for database access. Returns `None` if the
/// actor stops before the barrier starts, dropping the in-flight capture. Panics unless
/// [`Durability::needs_barrier`] holds.
async fn start_barrier<E, A, S, V>(
    shutdown: &mut (impl Future + Unpin),
    durability: &mut Durability,
    verifications: &mut Verifications<S, V>,
    processor: Processor<E, A>,
    publisher: &mut Publisher<SnapshotsOf<A::Databases, E>>,
) -> Option<Processor<E, A>>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E> + 'static,
    S: Scheme + 'static,
    V: Variant<ApplicationBlock = A::Block> + 'static,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    assert!(
        durability.needs_barrier(),
        "barrier requires uncovered applied state and no active barrier",
    );

    let height = durability.applied();
    let (processor, snapshots, barrier) = select! {
        _ = &mut *shutdown => return None,
        result = verifications.drive(processor.sync()) => result,
    };

    // The snapshots serve immediately; peers verify what they fetch against a
    // finalized root, so serving safely runs ahead of disk.
    publisher.publish(height, snapshots);
    durability.set_barrier(height, barrier);
    Some(processor)
}

/// Serves proposals, verifications, and finalizations against the live database set.
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
    /// Publishes the latest snapshots for serving.
    pub(super) snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,
}

impl<E, A, S, V> Processing<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E> + 'static,
    S: Scheme + 'static,
    V: Variant<ApplicationBlock = A::Block> + 'static,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    /// Serves requests with `processor` until the mailbox closes or the actor stops.
    ///
    /// `deferred` holds verification requests that arrived during state sync and have not started
    /// yet, and `pending_prune` a prune that became due during the state-sync handoff. At most one
    /// barrier is active, and blocks finalized while it runs are covered by a later barrier. A
    /// marshal acknowledgement is released only once its block is durable. If shutdown
    /// interrupts a barrier, processing stops and every pending acknowledgement is cancelled.
    pub async fn run(
        mut self,
        mut processor: Processor<E, A>,
        deferred: Vec<VerificationRequest<E, A>>,
        pending_prune: Option<Prune<SyncTargets<A, E>>>,
    ) {
        let mut pending_prune = pending_prune;
        let mut deferred_message = None;
        let mut verifications = Verifications::new(self.marshal.clone());
        for request in deferred {
            verifications.schedule(processor.verifier(), request);
        }

        let mut durability = Durability::new(processor.processed_height());

        // `select_loop!` creates one shutdown signal for the actor's whole life.
        // Re-creating it per iteration would record an extra auditor event on the
        // deterministic runtime each time.
        select_loop! {
            self.context,
            on_start => {
                // Stop before taking up more work, including work this iteration would start
                // before its select observes the stop.
                if (&mut shutdown).now_or_never().is_some() {
                    debug!("shutdown signal received, stopping processing");
                    return;
                }
                if let Some(completion) = durability.completion().now_or_never()
                    && !durability.complete(completion, &mut shutdown)
                {
                    return;
                }

                // A pending prune suppresses successor barriers.
                if pending_prune.is_none() && durability.needs_barrier() {
                    let Some(driven) = start_barrier(
                        &mut shutdown,
                        &mut durability,
                        &mut verifications,
                        processor,
                        &mut self.snapshot_publisher,
                    )
                    .await
                    else {
                        return;
                    };
                    processor = driven;
                }

                // Publish completed verdicts before admitting another message, so
                // mailbox traffic cannot starve them.
                verifications.complete_ready();

                // While applied state is not durable, a pending prune runs before the next message
                // so durability does not wait for an empty mailbox. Otherwise it waits for one.
                let prune_needs_barrier = pending_prune.is_some() && durability.needs_barrier();
                let message = if prune_needs_barrier {
                    Err(TryRecvError::Empty)
                } else {
                    match deferred_message.take() {
                        Some(message) => Ok(message),
                        None => self.mailbox.try_recv(),
                    }
                };

                let next = match message {
                    Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                        // No message and nothing to prune. Wait on the mailbox, driving
                        // the active barrier and verification jobs while idle.
                        None => {
                            let mailbox = &mut self.mailbox;
                            let durability = &mut durability;
                            let verifications = &mut verifications;
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
                                            break Some(Step::Barrier(completion));
                                        },
                                        _ = verifications.complete_next() => {
                                            continue;
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
                        let actor_context = self.context.as_present();
                        let proposal = processor
                            .propose(
                                actor_context,
                                self.marshal.clone(),
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
                                    _ = &mut shutdown => {
                                        debug!("shutdown signal received, stopping processing");
                                        return;
                                    },
                                    _ = &mut proposal => break,
                                    message = self.mailbox.recv() => match message {
                                        Some(Message::Verify {
                                            span,
                                            context,
                                            ancestry,
                                            verification,
                                        }) => verifications.schedule(
                                            processor.verifier(),
                                            VerificationRequest {
                                                span,
                                                context,
                                                ancestry,
                                                verification,
                                            },
                                        ),
                                        Some(message) => {
                                            // Only verifications overtake an active proposal. The
                                            // first other message waits for it, and later messages
                                            // wait behind that one.
                                            deferred_message = Some(message);
                                            receive_messages = false;
                                        }
                                        None => receive_messages = false,
                                    },
                                    _ = verifications.complete_next() => {},
                                }
                            } else {
                                select! {
                                    _ = &mut shutdown => {
                                        debug!("shutdown signal received, stopping processing");
                                        return;
                                    },
                                    _ = &mut proposal => break,
                                    _ = verifications.complete_next() => {},
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
                        verifications.schedule(
                            processor.verifier(),
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
                        // Redelivery still waits for durability but leaves active verifications
                        // running.
                        if processor.redelivered(block.as_ref()) {
                            durability.record_duplicate(block.height(), acknowledgement);
                            continue;
                        }
                        let process = info_span!(parent: &span, "stateful.actor.finalized");

                        // Verification jobs keep running during the apply,
                        // pausing at their next batch read. Exiting on stop drops
                        // the un-applied batches, and marshal redelivers the
                        // unacknowledged block after restart.
                        let barrier_idle = durability.barrier.is_none();
                        let applied;
                        select! {
                            _ = &mut shutdown => {
                                warn!(
                                    height = block.height().get(),
                                    "exiting mid-finalize on shutdown"
                                );
                                return;
                            },
                            driven = verifications
                                .drive(processor.finalize(
                                    self.context.as_present(),
                                    block.as_ref(),
                                    barrier_idle,
                                ))
                                .instrument(process.clone()) => {
                                (processor, applied) = driven;
                            },
                        }

                        // Keep the publication bookkeeping under the same span.
                        let _span = process.entered();
                        let Applied { publication, prune } = applied;
                        debug!(
                            height = block.height().get(),
                            "applied finalized database batch"
                        );

                        // Acknowledge only once a barrier covers this height, so marshal's
                        // processed height never passes durable state and an unsynced suffix
                        // is replayed after restart.
                        let height = block.height();
                        durability.record(height, acknowledgement);

                        // Snapshots serve immediately, ahead of the barrier that covers them.
                        match publication {
                            Publication::None => {}
                            Publication::Snapshot(snapshots) => {
                                self.snapshot_publisher.publish(height, snapshots);
                            }
                            Publication::WithBarrier(snapshots, barrier) => {
                                self.snapshot_publisher.publish(height, snapshots);
                                durability.set_barrier(height, barrier);
                            }
                        }

                        // Defer pruning to the loop so it can settle durability at one
                        // database mutation boundary.
                        if let Some(prune) = prune {
                            pending_prune = Some(prune);
                        }
                    }
                    Step::Prune(prune) => {
                        // Pruning requires a durable prune target and no active barrier.
                        while durability.barrier.is_some() {
                            select! {
                                _ = &mut shutdown => {
                                    debug!("shutdown signal received, stopping processing");
                                    return;
                                },
                                completion = durability.completion() => {
                                    if !durability.complete(completion, &mut shutdown) {
                                        return;
                                    }
                                },
                                _ = verifications.complete_next() => {},
                            }
                        }

                        // A prune target applied after the last barrier started is not yet durable.
                        if !durability.covers(prune.barrier_height) {
                            assert!(
                                durability.needs_barrier(),
                                "uncovered prune target must have unapplied durability",
                            );
                            let Some(driven) = start_barrier(
                                &mut shutdown,
                                &mut durability,
                                &mut verifications,
                                processor,
                                &mut self.snapshot_publisher,
                            )
                            .await
                            else {
                                return;
                            };
                            processor = driven;
                            loop {
                                select! {
                                    _ = &mut shutdown => {
                                        debug!("shutdown signal received, stopping processing");
                                        return;
                                    },
                                    completion = durability.completion() => {
                                        if !durability.complete(completion, &mut shutdown) {
                                            return;
                                        }
                                        break;
                                    },
                                    _ = verifications.complete_next() => {},
                                }
                            }
                            assert!(durability.covers(prune.barrier_height));
                        }
                        // Prune mutates storage and can take a while. Race it against
                        // shutdown so a stop signal is not blocked past its deadline. A
                        // dropped prune leaves storage recoverable, and after a restart the
                        // next due prune covers its target.
                        select! {
                            _ = &mut shutdown => {
                                debug!("shutdown signal received, stopping processing");
                                return;
                            },
                            driven = verifications.drive(processor.prune(prune, &self.marshal)) => {
                                processor = driven;
                            },
                        }
                        // The published snapshots predate this prune and pin the pruned
                        // storage, so capture and publish afresh right away.
                        select! {
                            _ = &mut shutdown => {
                                debug!("shutdown signal received, stopping processing");
                                return;
                            },
                            driven = verifications
                                .drive(processor.publish_snapshot(&mut self.snapshot_publisher)) => {
                                processor = driven;
                            },
                        }
                    }
                    Step::Barrier(completion) => {
                        if !durability.complete(completion, &mut shutdown) {
                            return;
                        }
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Message, Processing, VerificationRequest};
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
        Application as _, CertifiableBlock as _, Heightable as _, Reporter as _, Reporters,
        marshal::{
            Update,
            ancestry::{self, Ancestry},
            core::Processed,
        },
        simplex::{mocks::scheme as scheme_mocks, types::Activity},
        types::Height,
    };
    use commonware_cryptography::Digestible as _;
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
    use futures::{FutureExt as _, Stream, StreamExt as _, poll};
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
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
        type Captured = ();
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
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            Ok(Some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
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
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            Ok(Some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }
    }

    #[derive(Clone)]
    struct ReplayGatedApp {
        gates: Arc<Mutex<VecDeque<ApplicationGate>>>,
        verify_gate: Arc<Mutex<Option<ApplicationGate>>>,
        finalized_gate: Arc<Mutex<Option<ApplicationGate>>>,
        gate_height: Height,
        unexecutable: Option<Height>,
        /// Height whose `apply` and `verify` return [`ExecutionError::Invalid`].
        invalid: Option<Height>,
        apply_calls: Arc<AtomicUsize>,
        capture_calls: Arc<AtomicUsize>,
        verify_calls: Arc<AtomicUsize>,
        applied_finalizations: Arc<Mutex<Vec<Height>>>,
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
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            let gate = self.verify_gate.lock().take();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            if self.invalid.is_some() && self.invalid == ancestry.peek().map(|block| block.height())
            {
                return Err(ExecutionError::Invalid("test".into()));
            }
            Ok(Some(TestMerkleized))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            if self.unexecutable == Some(block.height()) {
                return Ok(None);
            }
            let gate = (block.height() == self.gate_height)
                .then(|| self.gates.lock().pop_front())
                .flatten();
            if let Some(mut gate) = gate {
                let _ = gate.started.send(());
                let _ = (&mut gate.release).await;
            }
            if self.invalid == Some(block.height()) {
                return Err(ExecutionError::Invalid("test".into()));
            }
            Ok(Some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) -> Self::Captured {
            self.capture_calls.fetch_add(1, Ordering::SeqCst);
            block.height()
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            height: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
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
        type Captured = ();

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
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some(TestMerkleized))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
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
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));
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
        let processor = Processor::new(
            app,
            test_databases(),
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let publication_context = context.child("publication");
        let (publisher, reader) = Publisher::new(&publication_context);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));
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
        let pruning =
            prune_config.map(|config| Pruning::new(config, marshal.mailbox.max_pending_acks(), 0));
        let app = GatedApp {
            verify_gates: Arc::new(Mutex::new(verify_gates)),
            proposal_gate: Arc::new(Mutex::new(None)),
            verify_valid: true,
            stale_verifies: Arc::default(),
            observed_contexts: Arc::default(),
        };
        let processor = Processor::new(
            app,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        let (mut publisher, reader) = Publisher::new(context);
        let processor = processor.publish_snapshot(&mut publisher).await;
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));
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
        let pruning =
            prune_config.map(|config| Pruning::new(config, marshal.mailbox.max_pending_acks(), 0));
        let processor = Processor::new(
            app,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        let (mut publisher, _subscriber) = Publisher::new(context);
        let processor = processor.publish_snapshot(&mut publisher).await;
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));
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

    #[test]
    fn replayed_parent_is_not_a_verdict() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"replayed-parent", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "replayed-parent",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::default(),
                verify_gate: Arc::default(),
                finalized_gate: Arc::default(),
                gate_height: parent.height(),
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            // Verifying the child replays its missing parent through apply.
            assert!(
                mailbox
                    .verify(
                        (context.child("verify_child"), child.context()),
                        ancestry::from_iter([Arc::new(child), Arc::new(parent.clone())]),
                    )
                    .await
            );
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 1);

            // Replayed state is reusable parent state, not a verdict: verifying the
            // parent asks the application once and then settles from the cache.
            for label in ["verify_parent", "verify_parent_again"] {
                assert!(
                    mailbox
                        .verify(
                            (context.child(label), parent.context()),
                            ancestry::from_iter([
                                Arc::new(parent.clone()),
                                Arc::new(genesis.clone())
                            ]),
                        )
                        .await
                );
            }
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 2);
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// Spawns processing over a [`ReplayGatedApp`] anchored at genesis.
    async fn spawn_replay_gated(
        context: &deterministic::Context,
        prefix: &str,
        app: ReplayGatedApp,
    ) -> (
        Mailbox<deterministic::Context, ReplayGatedApp>,
        fixtures::MarshalFixture,
        Handle<()>,
    ) {
        let mut signing = context.child("signing");
        let scheme = scheme_mocks::fixture(&mut signing, prefix.as_bytes(), 1).schemes[0].clone();
        let marshal = fixtures::marshal_fixture_with_finalized_block(
            context.child("marshal"),
            prefix,
            scheme,
            &TestBlock::new(0, 0),
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
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let publication_context = context.child("publication");
        let (publisher, _subscriber) = Publisher::new(&publication_context);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox.clone(),
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));
        (Mailbox::new(sender), marshal, actor)
    }

    /// An invalid execution answers `false` and caches nothing, so asking again re-executes.
    #[test]
    fn invalid_verification_answers_false_uncached() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let block = TestBlock::child(&TestBlock::new(0, 0), 1);
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::default(),
                verify_gate: Arc::default(),
                finalized_gate: Arc::default(),
                gate_height: block.height(),
                unexecutable: None,
                invalid: Some(block.height()),
                apply_calls: Arc::new(AtomicUsize::new(0)),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
            };
            let (mut mailbox, marshal, actor) =
                spawn_replay_gated(&context, "invalid-verify", app).await;

            for attempt in 1..=2 {
                assert!(
                    !mailbox
                        .verify(
                            (context.child("verify"), block.context()),
                            ancestry::from_iter([
                                Arc::new(block.clone()),
                                Arc::new(TestBlock::new(0, 0)),
                            ]),
                        )
                        .await
                );
                assert_eq!(verify_calls.load(Ordering::SeqCst), attempt);
            }
            actor.abort();
            drop(marshal.guards);
        });
    }

    /// An ancestor whose replay is invalid rejects every verification sharing that replay, with
    /// one execution and no panic.
    #[test]
    fn invalid_ancestor_replay_rejects_every_waiter() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let first = TestBlock::child(&parent, 2);
            let second = TestBlock::child(&parent, 3);
            let (gate, started, release) = application_gate();
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::from([gate]))),
                verify_gate: Arc::default(),
                finalized_gate: Arc::default(),
                gate_height: parent.height(),
                unexecutable: None,
                invalid: Some(parent.height()),
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
            };
            let (mailbox, marshal, actor) =
                spawn_replay_gated(&context, "invalid-ancestor", app).await;

            // Both verifications need the parent replayed. The first owns the replay and parks at
            // the gate, and the second waits on it.
            let mut first_verifier = mailbox.clone();
            let mut first = Box::pin(first_verifier.verify(
                (context.child("first"), first.context()),
                ancestry::from_iter([Arc::new(first.clone()), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut first).is_pending());
            started.await.expect("parent replay should start");
            let mut second_verifier = mailbox.clone();
            let mut second = Box::pin(second_verifier.verify(
                (context.child("second"), second.context()),
                ancestry::from_iter([Arc::new(second.clone()), Arc::new(parent)]),
            ));
            assert!(poll!(&mut second).is_pending());
            context.sleep(Duration::from_millis(100)).await;

            release
                .send(())
                .expect("the parent replay should be parked");
            assert!(!first.await);
            assert!(!second.await);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 0);
            actor.abort();
            drop(marshal.guards);
        });
    }

    #[test]
    fn unexecutable_parent_rejects_child() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let genesis = TestBlock::new(0, 0);
            let parent = TestBlock::child(&genesis, 1);
            let child = TestBlock::child(&parent, 2);
            let mut signing = context.child("signing");
            let scheme =
                scheme_mocks::fixture(&mut signing, b"unexecutable-parent", 1).schemes[0].clone();
            let marshal = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "unexecutable-parent",
                scheme,
                &genesis,
                NZUsize!(1),
                true,
            )
            .await;
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let verify_calls = Arc::new(AtomicUsize::new(0));
            let app = ReplayGatedApp {
                gates: Arc::default(),
                verify_gate: Arc::default(),
                finalized_gate: Arc::default(),
                gate_height: parent.height(),
                unexecutable: Some(parent.height()),
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            // A parent that cannot be executed invalidates the child's ancestry
            // before the application is asked to verify the child.
            assert!(
                !mailbox
                    .verify(
                        (context.child("verify_child"), child.context()),
                        ancestry::from_iter([Arc::new(child), Arc::new(parent)]),
                    )
                    .await
            );
            assert_eq!(apply_calls.load(Ordering::SeqCst), 1);
            assert_eq!(verify_calls.load(Ordering::SeqCst), 0);
            actor.abort();
            drop(marshal.guards);
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
                .expect("finalized block barrier should remain pending");
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

    /// A verification on a finalized-away fork answers its branch-relative verdict. The mock
    /// databases never refuse, which models a losing branch whose state matches the winner's.
    /// Real storage refuses a distinct-state branch as stale instead (see the processor test
    /// `finalized_away_fork_refuses_unless_state_matches`).
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

    /// A verification whose fork a finalization dropped still answers its branch-relative
    /// verdict, under the same mock caveat as `finalized_away_fork_verification_answers_true`.
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
    fn anchor_redelivery_keeps_running_verification() {
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
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let capture_calls = Arc::new(AtomicUsize::new(0));
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                gates: Arc::new(Mutex::new(VecDeque::new())),
                verify_gate: Arc::new(Mutex::new(Some(verify_gate))),
                finalized_gate: Arc::default(),
                gate_height: finalized.height(),
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: capture_calls.clone(),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: applied_finalizations.clone(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
            waiter
                .await
                .expect("redelivered anchor should be acknowledged");

            assert!(
                poll!(&mut verify_child).is_pending(),
                "anchor redelivery must not resolve a running verification",
            );
            verify_release
                .send(())
                .expect("child verification should remain active");
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(valid);
            assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
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
            let apply_calls = Arc::new(AtomicUsize::new(0));
            let capture_calls = Arc::new(AtomicUsize::new(0));
            let applied_finalizations: Arc<Mutex<Vec<Height>>> = Arc::default();
            let app = ReplayGatedApp {
                gates: Arc::default(),
                verify_gate: Arc::default(),
                finalized_gate: Arc::default(),
                gate_height: genesis.height(),
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: capture_calls.clone(),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: applied_finalizations.clone(),
            };
            let processor = Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let mut mailbox = Mailbox::new(sender);
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            let (acknowledgement, waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(genesis), acknowledgement));
            waiter.await.expect("genesis should be acknowledged");

            assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, vec![request], None));

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
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
                unexecutable: None,
                invalid: None,
                apply_calls: Arc::new(AtomicUsize::new(0)),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            // The candidate's verification parks inside the shared replay of its
            // unknown parent.
            let mut verifier = mailbox.clone();
            let mut verify = Box::pin(verifier.verify(
                (context.child("verify"), candidate.context()),
                ancestry::from_iter([Arc::new(candidate.clone()), Arc::new(parent.clone())]),
            ));
            assert!(poll!(&mut verify).is_pending());
            apply_started.await.expect("parent replay should start");

            // The parent and then the candidate itself finalize (each reconstructed
            // by its finalization, since the parked replay has not cached the parent).
            for block in [parent, candidate] {
                let (acknowledgement, waiter) = Exact::handle();
                let _ = mailbox.report(Update::Block(Arc::new(block), acknowledgement));
                waiter
                    .await
                    .expect("finalized block should be acknowledged");
            }

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
    /// finalization is retried against the new anchor, not answered false.
    #[test]
    fn parent_finalized_during_replay_retries_and_answers_true() {
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
                unexecutable: None,
                invalid: None,
                apply_calls: Arc::new(AtomicUsize::new(0)),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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

            // The parked replay resumes and fails against the moved anchor, so
            // the verifier retries, forks the candidate from the new anchor, and
            // answers true.
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
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
    fn consecutive_finalizations_retry_descendant_replay() {
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
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
                .expect("descendant verification should re-run after the first finalization");

            let (acknowledgement, second_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(second), acknowledgement));
            second_waiter
                .await
                .expect("second finalized block should be acknowledged");
            // Each cancellation drops the attempt holding this gate, so releasing
            // it is best-effort.
            let _ = verify_release.send(());
            let valid = verify_child.await;
            actor.abort();
            drop(marshal.guards);
            assert!(
                valid,
                "a descendant of both finalized blocks must verify, not be rejected",
            );
            assert!(
                verify_calls.load(Ordering::SeqCst) > 1,
                "the descendant should have re-run against the applied state",
            );
            assert_eq!(
                apply_calls.load(Ordering::SeqCst),
                2,
                "replay should not repeat work already cached as pending state",
            );
        });
    }

    #[test]
    fn running_verification_finishes_before_queued_finalization() {
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
                unexecutable: None,
                invalid: None,
                apply_calls: Arc::new(AtomicUsize::new(0)),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: Arc::default(),
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
                .expect("running verification should remain active");
            verify_started
                .await
                .expect("running verification should start");
            finalized_started
                .await
                .expect("first finalization hook should start");

            let valid = select! {
                valid = &mut first_attempt => {
                    valid
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("queued finalization blocked running verification");
                },
            };
            assert!(
                valid,
                "running branch-relative verification must remain valid"
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
                unexecutable: None,
                invalid: None,
                apply_calls: apply_calls.clone(),
                capture_calls: Arc::new(AtomicUsize::new(0)),
                verify_calls: verify_calls.clone(),
                applied_finalizations: Arc::default(),
            };
            let control = FlushControl::default();
            let (prune_started, prune_release) = control.gate_prune();
            let databases = Single::from(TestDb::gated(control.clone()));
            let pruning = Pruning::new(
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
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
            marshal.abort().await;
        });
    }

    /// Pruning waits for the flush that covers its target without waiting for newer state.
    #[test]
    fn prune_starts_after_target_barrier() {
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

            // Releasing block 1 makes the prune target durable. Stateful prunes before starting the
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

    /// A stop while a due prune waits on an older barrier exits within the stop deadline.
    #[test]
    fn shutdown_interrupts_prune_waiting_on_barrier() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) = spawn_processing(
                &context,
                "prune-wait-shutdown",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Block 1's flush stays parked, and block 2 makes a prune due behind it.
            let genesis = TestBlock::new(0, 0);
            let block1 = TestBlock::child(&genesis, 1);
            let block2 = TestBlock::child(&block1, 2);
            let (acknowledgement, waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
            let (acknowledgement, waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block2), acknowledgement));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            context.sleep(Duration::from_millis(50)).await;
            assert_eq!(control.flushes.lock().len(), 1);

            let stopper = context.child("stopper");
            let stop = context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, Some(Duration::from_millis(100))).await });
            assert!(
                stop.await.expect("stop task should finish").is_ok(),
                "shutdown must interrupt the prune's barrier wait",
            );
            actor.await.expect("processing actor should stop cleanly");
            assert!(control.pruned.lock().is_empty());
            assert!(waiter1.await.is_err());
            assert!(waiter2.await.is_err());
            drop(mailbox);
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
                Arc::new(TestBlock::child(&TestBlock::new(1, 1), 2)),
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
                gates: Arc::default(),
                verify_gate: Arc::default(),
                finalized_gate: Arc::new(Mutex::new(Some(finalized_gate))),
                gate_height: block1.height(),
                unexecutable: None,
                invalid: None,
                apply_calls: Arc::new(AtomicUsize::new(0)),
                capture_calls: capture_calls.clone(),
                verify_calls: Arc::new(AtomicUsize::new(0)),
                applied_finalizations: applied_finalizations.clone(),
            };
            let control = FlushControl::default();
            let processor = Processor::new(
                app,
                Single::from(TestDb::gated(control.clone())),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(2));
            let mut mailbox = Mailbox::new(sender);
            let publication_context = context.child("publication");
            let (publisher, _subscriber) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            let (acknowledgement, mut waiter1) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block1), acknowledgement));
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
            let _ = mailbox.report(Update::Block(Arc::new(block2), acknowledgement));
            while control.applied.load(Ordering::Relaxed) < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
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

            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            control
                .flushes
                .lock()
                .remove(0)
                .send(Ok(()))
                .expect("successor barrier should remain pending");
            waiter2.await.expect("block 2 should be acknowledged");

            actor.abort();
            drop(marshal.guards);
        });
    }

    /// Wait until earlier mailbox messages have been handled without accessing the databases.
    async fn processing_fence(
        context: &deterministic::Context,
        mailbox: &Mailbox<deterministic::Context, GatedApp>,
    ) {
        // Empty proposals decline before calling the application or reading databases.
        assert!(
            mailbox
                .clone()
                .propose(
                    (context.child("fence"), TestBlock::new(0, 0).context()),
                    ancestry::from_iter(std::iter::empty::<Arc<TestBlock>>()),
                    (),
                )
                .await
                .is_none(),
        );
    }

    /// A redelivered receipt for an applied height waits for the flush that covers it.
    #[rstest::rstest]
    #[case::success(true)]
    #[case::failure(false)]
    fn duplicate_reports_wait_for_durability(#[case] succeeds: bool) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, subscriber, _marshal, actor) =
                spawn_processing(&context, "duplicate-durability", None).await;

            // Apply block 1 with its flush held, then report it again.
            let first = TestBlock::child(&TestBlock::new(0, 0), 1);
            let (ack, mut original) = Exact::handle();
            mailbox.report(Update::Block(Arc::new(first.clone()), ack));
            processing_fence(&context, &mailbox).await;
            let (ack, mut duplicate) = Exact::handle();
            mailbox.report(Update::Block(Arc::new(first.clone()), ack));

            // Fence after both reports have been handled.
            processing_fence(&context, &mailbox).await;
            assert_eq!(control.applied.load(Ordering::Relaxed), 1);
            assert_eq!(subscriber.latest(), Some(1));
            assert_eq!(publications(&context), 2);
            assert!(poll!(&mut original).is_pending());
            assert!(poll!(&mut duplicate).is_pending());
            assert_eq!(control.flushes.lock().len(), 1);

            let release = control.flushes.lock().remove(0);
            if !succeeds {
                // A failed flush stops processing and cancels the duplicate receipt.
                drop(release);
                actor.await.expect("failed durability stops processing");
                assert!(original.await.is_err());
                assert!(duplicate.await.is_err());
                assert_eq!(subscriber.latest(), None);
                return;
            }

            // A successful flush releases the duplicate without applying block 1 again.
            release.send(Ok(())).unwrap();
            original.await.unwrap();
            duplicate.await.unwrap();
            assert!(control.flushes.lock().is_empty());
            assert_eq!(control.applied.load(Ordering::Relaxed), 1);
            assert_eq!(subscriber.latest(), Some(1));
            assert_eq!(publications(&context), 2);
            actor.abort();
            let _ = actor.await;
        });
    }

    /// A redelivered receipt for a durable height acknowledges at once and starts no barrier.
    #[test]
    fn durable_duplicate_acknowledges_without_barrier() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _subscriber, _marshal, actor) =
                spawn_processing(&context, "durable-duplicate", None).await;

            let first = TestBlock::child(&TestBlock::new(0, 0), 1);
            let (ack, original) = Exact::handle();
            mailbox.report(Update::Block(Arc::new(first.clone()), ack));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            control.flushes.lock().remove(0).send(Ok(())).unwrap();
            original.await.unwrap();

            let (ack, duplicate) = Exact::handle();
            mailbox.report(Update::Block(Arc::new(first), ack));
            duplicate.await.expect("a durable duplicate acknowledges");
            processing_fence(&context, &mailbox).await;
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
            let processor = Processor::new(
                GatedApp {
                    verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                    proposal_gate: Arc::default(),
                    verify_valid: true,
                    stale_verifies: Arc::default(),
                    observed_contexts: Arc::clone(&observed_contexts),
                },
                Single::from(TestDb::gated(control.clone())),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let publication_context = context.child("publication");
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                snapshot_publisher: Publisher::new(&publication_context).0,
            };
            let actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

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
                        .verified(block.context().round, Arc::new(block.clone()))
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
                ancestry::from_iter([Arc::new(child), Arc::new(tip.clone())]),
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
            let processor = Processor::new(
                GatedApp {
                    verify_gates: Arc::default(),
                    proposal_gate: Arc::default(),
                    verify_valid: true,
                    stale_verifies: Arc::default(),
                    observed_contexts: Arc::default(),
                },
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(&context),
                None,
            );
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                snapshot_publisher: Publisher::new(&context).0,
            };
            let _actor = context
                .child("loop")
                .spawn(move |_| processing.run(processor, Vec::new(), None));

            // Genesis is the applied tip, so its startup delivery is acknowledged.
            while marshal.mailbox.get_processed().await != Some(Processed::Block(Height::zero())) {}

            // Installing the floor records the never-stored height 1 as processed, then delivers
            // the floor block.
            assert!(
                marshal
                    .mailbox
                    .verified(floor.context().round, Arc::new(floor.clone()))
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
                Arc::new(TestBlock::new(1, 1)),
                acknowledgement,
            ));
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let mut waiters = Vec::with_capacity(BLOCKS as usize - 1);
            let mut parent = TestBlock::new(1, 1);
            for height in 2..=BLOCKS {
                let block = TestBlock::child(&parent, height as u8);
                let (acknowledgement, waiter) = Exact::handle();
                let _ = mailbox.report(Update::Block(Arc::new(block.clone()), acknowledgement));
                waiters.push(waiter);
                parent = block;
            }
            while control.applied.load(Ordering::Relaxed) < BLOCKS as usize {
                context.sleep(Duration::from_millis(10)).await;
            }

            assert_eq!(
                control.flushes.lock().len(),
                1,
                "a pending barrier must coalesce later finalized state instead of starting a second barrier",
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
                .expect("first barrier should remain pending");
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
                .expect("first barrier should remain pending");
            waiter1.await.expect("first block acknowledgement");
            assert!(poll!(&mut waiter2).is_pending());

            verify_release
                .send(())
                .expect("verification should remain active");
            select! {
                result = &mut verify => assert!(result),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("successor barrier stopped polling the verification that owned its read lock");
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
                Arc::new(TestBlock::child(&TestBlock::new(1, 1), 2)),
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
                Arc::new(TestBlock::child(&TestBlock::new(1, 1), 2)),
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
                Arc::new(TestBlock::child(&TestBlock::new(1, 1), 2)),
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
                Arc::new(TestBlock::child(&TestBlock::new(1, 1), 2)),
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

            // The active barrier panics when the loop next polls it.
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    /// An application whose every execution observes fatal storage, optionally firing shutdown
    /// in the same poll first, unless it has a fixed block to propose.
    #[derive(Clone, Default)]
    struct FaultyApp {
        stop: bool,
        proposal: Option<TestBlock>,
    }

    impl FaultyApp {
        fn fail(&self, context: deterministic::Context) -> ExecutionError {
            if self.stop {
                // Polling `stop` once fires the signal.
                let _ = context.stop(0, None).now_or_never();
            }
            ExecutionError::Fatal("disk failed".into())
        }
    }

    impl Application<deterministic::Context> for FaultyApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Provider = ();
        type Input = ();
        type Captured = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            panic!("faulty application genesis is not used")
        }

        async fn propose(
            &mut self,
            context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            if let Some(block) = self.proposal.clone() {
                return Ok(Some(Proposed {
                    block,
                    merkleized: TestMerkleized,
                }));
            }
            Err(self.fail(context.0))
        }

        async fn verify(
            &mut self,
            context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            Err(self.fail(context.0))
        }

        async fn apply(
            &mut self,
            context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            Err(self.fail(context.0))
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }
    }

    /// Where a [`FaultyApp`] test drives its request.
    #[derive(Clone, Copy)]
    enum FatalSite {
        Propose,
        Verify,
        FinalizeReplay,
    }

    /// Spawns processing over `app` and sends one request that reaches `site`. Returns the actor
    /// handle, the marshal guards, and the request's pending outcome.
    async fn spawn_faulty(
        context: &deterministic::Context,
        app: FaultyApp,
        site: FatalSite,
    ) -> (Handle<()>, Box<dyn std::any::Any>, FatalOutcome) {
        let mut signing = context.child("signing");
        let scheme = scheme_mocks::fixture(&mut signing, b"fatal-app", 1).schemes[0].clone();
        let marshal = fixtures::marshal_fixture(
            context.child("marshal_fixture"),
            "fatal-app",
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
        let mut mailbox = Mailbox::new(sender);
        let publication_context = context.child("publication");
        let (publisher, _subscriber) = Publisher::new(&publication_context);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));

        let genesis = TestBlock::new(0, 0);
        let block = TestBlock::child(&genesis, 1);
        let outcome = match site {
            FatalSite::Propose => {
                FatalOutcome::Proposal(context.child("propose").spawn(move |context| async move {
                    mailbox
                        .propose(
                            (context, block.context()),
                            ancestry::from_iter([Arc::new(genesis)]),
                            (),
                        )
                        .await
                }))
            }
            FatalSite::Verify => {
                let verify = context.child("verify").spawn(move |context| async move {
                    mailbox
                        .verify(
                            (context, block.context()),
                            ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
                        )
                        .await
                });
                FatalOutcome::Verdict(verify)
            }
            FatalSite::FinalizeReplay => {
                let (acknowledgement, waiter) = Exact::handle();
                mailbox.report(Update::Block(Arc::new(block), acknowledgement));
                FatalOutcome::Acknowledgement(waiter)
            }
        };
        (actor, marshal.guards, outcome)
    }

    /// The pending result of the request a [`FaultyApp`] test sent.
    enum FatalOutcome {
        Proposal(Handle<Option<TestBlock>>),
        Verdict(Handle<bool>),
        Acknowledgement(<Exact as commonware_utils::Acknowledgement>::Waiter),
    }

    /// Drives `site` into fatal storage without shutdown, which must panic.
    fn fatal_execution_panics(site: FatalSite) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (_actor, _guards, _outcome) =
                spawn_faulty(&context, FaultyApp::default(), site).await;
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    /// Fatal storage observed during a proposal takes the actor down instead
    /// of masking a broken database behind an ordinary decline.
    #[test]
    #[should_panic(expected = "application proposal failed")]
    fn fatal_proposal_panics_processing() {
        fatal_execution_panics(FatalSite::Propose);
    }

    #[test]
    #[should_panic(expected = "application verification failed")]
    fn fatal_verification_panics_processing() {
        fatal_execution_panics(FatalSite::Verify);
    }

    #[test]
    #[should_panic(expected = "finalize replay failed")]
    fn fatal_finalize_replay_panics_processing() {
        fatal_execution_panics(FatalSite::FinalizeReplay);
    }

    /// Fatal storage observed after shutdown fired in the same poll exits the actor quietly,
    /// without a verdict, a proposal, or an acknowledgement.
    #[rstest::rstest]
    #[case::propose(FatalSite::Propose)]
    #[case::verify(FatalSite::Verify)]
    #[case::finalize_replay(FatalSite::FinalizeReplay)]
    fn fatal_execution_during_shutdown_exits_quietly(#[case] site: FatalSite) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let app = FaultyApp {
                stop: true,
                proposal: None,
            };
            let (actor, guards, outcome) = spawn_faulty(&context, app, site).await;
            actor.await.expect("the actor should exit cleanly");
            match outcome {
                FatalOutcome::Proposal(proposal) => {
                    assert_eq!(proposal.await.expect("proposal task"), None);
                }
                FatalOutcome::Verdict(mut verdict) => {
                    for _ in 0..16 {
                        assert!(poll!(&mut verdict).is_pending(), "no verdict may resolve");
                        context.sleep(Duration::from_millis(1)).await;
                    }
                }
                FatalOutcome::Acknowledgement(waiter) => {
                    assert!(waiter.await.is_err(), "the block must stay unacknowledged");
                }
            }
            drop(guards);
        });
    }

    /// Proposes `block` for a request at view 1 on genesis, which must panic.
    fn misframed_proposal_panics(block: TestBlock) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let app = FaultyApp {
                stop: false,
                proposal: Some(block),
            };
            let (_actor, _guards, _outcome) = spawn_faulty(&context, app, FatalSite::Propose).await;
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    #[test]
    #[should_panic(expected = "proposed block must extend the requested parent")]
    fn proposal_with_other_parent_panics() {
        misframed_proposal_panics(TestBlock::child(&TestBlock::new(0, 7), 1));
    }

    #[test]
    #[should_panic(expected = "proposed block must carry the requested round")]
    fn proposal_with_other_round_panics() {
        // Genesis has the empty digest, so this block extends it at view 2 instead of 1.
        misframed_proposal_panics(TestBlock::new(2, 1));
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
        type Captured = ();

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
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            if let Some(started) = self.started.lock().take() {
                let _ = started.send(());
            }
            std::future::pending().await
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: ReadersOf<Self::Databases, deterministic::Context>,
        ) {
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
        let processor = Processor::new(
            ParkedApp {
                started: Arc::new(Mutex::new(Some(started_tx))),
            },
            test_databases(),
            anchor(0, 0),
            StatefulMetrics::new(context),
            None,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let publication_context = context.child("publication");
        let (publisher, _subscriber) = Publisher::new(&publication_context);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.run(processor, Vec::new(), None));
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

    /// Ancestry that never yields a block and counts its clones (one per verification attempt).
    struct PendingAncestry(Arc<AtomicUsize>);

    impl Clone for PendingAncestry {
        fn clone(&self) -> Self {
            self.0.fetch_add(1, Ordering::SeqCst);
            Self(self.0.clone())
        }
    }

    impl Stream for PendingAncestry {
        type Item = Arc<TestBlock>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Ancestry<TestBlock> for PendingAncestry {
        fn peek(&self) -> Option<&TestBlock> {
            None
        }
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

            // Redeliver the applied tip, then fence behind any re-run verification.
            let (ack, waiter) = Exact::handle();
            mailbox.report(Update::Block(Arc::new(TestBlock::new(0, 0)), ack));
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
}
