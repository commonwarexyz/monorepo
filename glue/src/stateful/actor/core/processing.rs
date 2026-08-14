//! The post-sync processing loop of the stateful actor.
//!
//! The loop owns the database set and is the only thing that mutates it.
//! Verification jobs hold read handles instead, so they are never cancelled: a
//! job that is mid-read when a finalized block arrives finishes that read, the
//! apply runs, and the job continues against the state it installs.
//!
//! Each finalized block is applied to the databases, its flush deferred to a
//! pool, and a snapshot of the applied state staged for publication. The loop
//! publishes the snapshot and acknowledges the block to marshal only once the
//! flush is durable, so readers and marshal's floor never get ahead of disk.
//!
//! Pruning and fresh post-prune captures are maintenance, run only while the
//! mailbox is idle. A prune waits until the pruned range is durable, and leaves
//! the served snapshot stale until a post-prune capture publishes (see
//! [`Publisher`]).

use crate::stateful::{
    Application, Input,
    actor::{
        core::{
            mailbox::Message,
            verifications::{Handler as Verifications, Request as VerificationRequest},
        },
        processor::{Applied, Processor},
    },
    db::{SnapshotsOf, snapshot::Publisher},
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
use commonware_macros::select;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{Acknowledgement as _, futures::Pool};
use futures::{
    FutureExt as _,
    future::{Either, ready},
};
use rand_core::Rng;
use std::sync::mpsc::TryRecvError;
use tracing::{Instrument as _, debug, info_span};

/// A single unit of work for the processing loop: a mailbox message to handle,
/// or deferred maintenance (a prune, or a fresh post-prune capture) run while
/// the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
    Refresh,
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

    /// Publishes the latest durable capture of snapshots for serving.
    pub(super) snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and should be acknowledged only.
    pub(super) skip_finalized_until: Option<Height>,
}

impl<E, A, S, V> Processing<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock + 'static,
    A: Application<E> + 'static,
    S: Scheme + 'static,
    V: Variant<ApplicationBlock = A::Block> + 'static,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    /// Run the loop until shutdown.
    ///
    /// `deferred` holds verification requests that arrived during state sync
    /// and have not started yet.
    pub async fn start(
        mut self,
        mut processor: Processor<E, A>,
        deferred: Vec<VerificationRequest<E, A>>,
    ) {
        // Deferred finalize flushes, each releasing its block's marshal
        // acknowledgement once the flush completes (see `Barrier`).
        let mut syncs = Pool::<(Height, bool)>::default();

        // A prune becomes due at a finalization and runs once the mailbox idles.
        let mut pending_prune = None;

        // One signal for the actor's whole life. Re-creating it per iteration
        // would record an extra auditor event on the deterministic runtime each
        // time.
        let mut shutdown = self.context.stopped();

        let mut deferred_message = None;
        let mut verifications = Verifications::new(self.marshal.clone());
        for request in deferred {
            verifications.schedule(processor.verifier(), request);
        }

        loop {
            // Observe every already-completed flush (releasing its marshal
            // acknowledgement) before taking the next unit of work.
            while let Some((height, durable)) = syncs.next_completed().now_or_never() {
                if !durable {
                    return;
                }
                self.snapshot_publisher.complete(height);
            }

            // Publish completed verdicts before admitting another message, so
            // continuous mailbox traffic cannot starve them under the biased
            // `select!`.
            verifications.complete_ready();

            // A message deferred by an active proposal is the FIFO barrier
            // for subsequent mailbox work, so handle it before later arrivals.
            let message = match deferred_message.take() {
                Some(message) => Ok(message),
                None => self.mailbox.try_recv(),
            };

            // Pruning and fresh captures are non-critical work, run only when the
            // mailbox is idle. If a message is ready, it is always processed
            // immediately.
            let next = match message {
                // A message is ready: handle it now, regardless of any queued prune.
                Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                Err(TryRecvError::Empty) => match pending_prune.take() {
                    // No message, but a prune is queued: run it.
                    Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                    // The served snapshot is stale and every flush drained.
                    None if self.snapshot_publisher.needs_refresh() => {
                        Either::Left(ready(Some(Step::Refresh)))
                    }
                    // No message and nothing to prune: wait on the mailbox, driving
                    // flush completions and verification jobs while idle.
                    None => {
                        let mailbox = &mut self.mailbox;
                        let syncs = &mut syncs;
                        let snapshot_publisher = &mut self.snapshot_publisher;
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
                                    (height, durable) = syncs.next_completed() => {
                                        if !durable {
                                            return None;
                                        }
                                        snapshot_publisher.complete(height);
                                        if snapshot_publisher.needs_refresh() {
                                            break Some(Step::Refresh);
                                        }
                                    },
                                    _ = verifications.next_completed() => {
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

            let step = select! {
                _ = &mut shutdown => {
                    debug!("shutdown signal received, stopping processing");
                    return;
                },
                step = next => step,
            };
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
                    let span = info_span!(parent: &span, "stateful.actor.propose");
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
                        .instrument(span);
                    futures::pin_mut!(proposal);
                    let mut receive_messages = true;
                    loop {
                        if receive_messages {
                            select! {
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
                                        // Only verification may overtake an active
                                        // proposal. The first other message becomes a
                                        // FIFO barrier for later mailbox work.
                                        deferred_message = Some(message);
                                        receive_messages = false;
                                    }
                                    None => receive_messages = false,
                                },
                                _ = verifications.next_completed() => {},
                            }
                        } else {
                            select! {
                                _ = &mut proposal => break,
                                _ = verifications.next_completed() => {},
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
                    ..
                }) => {
                    let span = info_span!(parent: &span, "stateful.actor.finalized");
                    if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                        let notify =
                            processor.notify_finalized(self.context.as_present(), block.as_ref());
                        async {
                            verifications.drive(notify).await;
                            acknowledgement.acknowledge();
                        }
                        .instrument(span)
                        .await;
                        continue;
                    }

                    // The apply owns mutation. Live verification jobs pause at
                    // their next batch operation and resume afterward, so they
                    // keep being polled throughout.
                    let applied;
                    (processor, applied) = verifications
                        .drive(processor.finalize(self.context.as_present(), block.as_ref()))
                        .instrument(span.clone())
                        .await;

                    // Keep the publication bookkeeping under the same span.
                    let _span = span.entered();
                    let Some(Applied {
                        snapshots,
                        barrier,
                        prune,
                    }) = applied
                    else {
                        // Duplicate report: marshal redelivers a processed height
                        // only after a restart, where startup aligned the databases
                        // to durable state.
                        acknowledgement.acknowledge();
                        continue;
                    };
                    debug!(
                        height = block.height().get(),
                        "applied finalized database batch"
                    );

                    // The snapshot publishes and marshal is acknowledged only
                    // once the flush completes, so neither served state nor
                    // marshal's processed floor gets ahead of what is on disk.
                    // Marshal's ack window bounds the flush backlog, and
                    // unacknowledged blocks are redelivered on restart.
                    let height = block.height();
                    self.snapshot_publisher.stage(height, snapshots);
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
                Step::Prune(prune) => {
                    // The prune target must be durable, but later blocks remain
                    // available in marshal for replay and do not delay
                    // maintenance. Later mailbox work stays ordered behind the
                    // prune.
                    while self.snapshot_publisher.blocks_prune(prune.barrier_height) {
                        select! {
                            (height, durable) = syncs.next_completed() => {
                                if !durable {
                                    return;
                                }
                                self.snapshot_publisher.complete(height);
                            },
                            _ = verifications.next_completed() => {},
                        }
                    }

                    processor = verifications
                        .drive(processor.prune(prune, &self.marshal))
                        .await;
                    // The published snapshot predates this prune and keeps the pruned
                    // storage alive, as do snapshots staged before it.
                    self.snapshot_publisher.mark_stale();
                    if self.snapshot_publisher.needs_refresh() {
                        processor = verifications
                            .drive(processor.publish_snapshot(&mut self.snapshot_publisher))
                            .await;
                    }
                }
                Step::Refresh => {
                    // The served snapshot went stale at the last prune and no
                    // later flush replaced it. Every flush has drained, so the
                    // applied state is durable and can publish directly.
                    processor = verifications
                        .drive(processor.publish_snapshot(&mut self.snapshot_publisher))
                        .await;
                }
            }
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
        },
        db::{
            HandlesOf, Single, SnapshotsOf,
            snapshot::{Publisher, Reader},
        },
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
            _handles: HandlesOf<Self::Databases, deterministic::Context>,
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
        Reader<SnapshotsOf<TestDatabases, deterministic::Context>>,
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
        let publication_context = context.child("publication");
        let (publisher, reader) = Publisher::new(&publication_context);
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            snapshot_publisher: publisher,
            skip_finalized_until: None,
        };
        let actor = context
            .child("loop")
            .spawn(move |_| processing.start(processor, Vec::new()));
        (Mailbox::new(sender), reader, marshal.guards, actor)
    }

    async fn spawn_processing(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        FlushControl,
        Reader<u64>,
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
        Reader<u64>,
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            let (mut mailbox, control, _source, _marshal, actor) =
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
    fn pending_proposal_does_not_block_new_verification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (verify_gate, verify_started, verify_release) = application_gate();
            let (proposal_gate, proposal_started, proposal_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([verify_gate]))),
                proposal_gate: Arc::new(Mutex::new(Some(proposal_gate))),
                verify_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
    fn finalization_refuses_incompatible_verification_result() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (fork_gate, fork_started, fork_release) = application_gate();
            let (child_gate, child_started, child_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([fork_gate, child_gate]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            // pending set, so caching its result is refused and the verdict is
            // false.
            child_release
                .send(())
                .expect("the attempt should still be live after the apply");
            select! {
                valid = &mut verify_child => {
                    assert!(!valid, "verification on a finalized-away fork must fail");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("incompatible verification did not resolve");
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
            let (grandchild_gate, grandchild_started, grandchild_release) = application_gate();
            let app = GatedApp {
                verify_gates: Arc::new(Mutex::new(VecDeque::from([
                    parent_gate,
                    child_gate,
                    grandchild_gate,
                ]))),
                proposal_gate: Arc::new(Mutex::new(None)),
                verify_valid: true,
                observed_contexts: Arc::default(),
            };
            let (mut mailbox, _reader, _marshal, actor) =
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
            let publication_context = context.child("publication");
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let publication_context = context.child("publication");
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let publication_context = context.child("publication");
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox,
                snapshot_publisher: publisher,
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
            let (publisher, _reader) = Publisher::new(&publication_context);
            let processing = Processing {
                context: ContextCell::new(context.child("processing")),
                mailbox: receiver,
                provider: (),
                marshal: marshal.mailbox.clone(),
                snapshot_publisher: publisher,
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
            let (mut mailbox, control, source, _marshal, _actor) = spawn_processing_with_gates(
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
            assert_eq!(
                source.latest(),
                Some(0),
                "only the startup capture may serve before a block flush is durable",
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
            assert_eq!(
                source.latest(),
                Some(1),
                "block 1's capture must serve once durable",
            );
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
            assert!(
                source.latest().is_some_and(|served| served > 1),
                "block 2's capture must serve once durable",
            );
        });
    }

    /// A prune with no later finalization must publish a fresh capture, so serving
    /// stops pinning the pruned state.
    #[test]
    fn prune_without_later_block_publishes_a_fresh_capture() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, _actor) = spawn_processing(
                &context,
                "gated-prune-capture",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Blocks 1 and 2 fill the retention window, scheduling a prune at block 1.
            // Both captures predate the prune.
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
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![1]);

            // Block 2's snapshot was captured before the prune, so its publish must
            // not replace the stale snapshot: with no later block, the loop itself captures
            // and publishes again once every flush drains. The fresh capture
            // carries the same content as block 2's publish, so count
            // publications instead: startup, block 1, block 2, then the capture.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            while publications(&context) < 4 {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                source.latest(),
                Some(2),
                "the fresh capture must serve block 2's state"
            );
        });
    }

    /// When a block finalized after the prune publishes, its snapshot replaces
    /// the stale one. The loop must not also capture a fresh snapshot.
    #[test]
    fn post_prune_publish_replaces_the_stale_snapshot() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, _actor) = spawn_processing(
                &context,
                "gated-prune-clear",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(2),
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
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Releasing block 1 lets the prune run while block 2's pre-prune flush
            // is still pending, marking publication stale.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![1]);

            // Block 3 is finalized after the prune, so its capture is post-prune.
            let (acknowledgement, waiter3) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(3, 3)),
                acknowledgement,
            ));
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Block 2's pre-prune publish must not replace the stale snapshot. Block 3's
            // post-prune publish must, so no extra capture ever publishes.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter3.await.expect("block 3 acknowledgement");
            while source.latest() < Some(3) {
                context.sleep(Duration::from_millis(10)).await;
            }
            context.sleep(Duration::from_millis(50)).await;
            assert_eq!(
                source.latest(),
                Some(3),
                "block 3's own publish must replace the stale snapshot without a separate capture",
            );
        });
    }

    /// An aborted target flush must stop processing before pruning can discard its recovery state.
    #[test]
    fn aborted_target_flush_prevents_prune() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, actor) = spawn_processing(
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
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

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
                source.latest().is_none(),
                "an aborted capture must never serve",
            );
        });
    }

    /// A later flush completing first releases its acknowledgement, but nothing
    /// serves until every earlier flush lands. The frontier then publishes the
    /// newest capture, superseding the earlier one.
    #[test]
    fn out_of_order_flush_publishes_at_the_frontier() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, _actor) =
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
            while control.flushes.lock().len() < 2 {
                context.sleep(Duration::from_millis(10)).await;
            }

            // Block 2's flush lands first: its acknowledgement releases, but
            // serving stays behind block 1's pending flush.
            let release = control.flushes.lock().remove(1);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            assert_eq!(
                source.latest(),
                Some(0),
                "nothing may serve past a pending earlier flush",
            );
            assert!(poll!(&mut waiter1).is_pending());

            // Block 1 lands: the frontier jumps to block 2's capture.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            while source.latest() != Some(2) {
                context.sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// While the loop is idle, a completed flush must release its acknowledgement without
    /// displacing a simultaneously reported block, while an incomplete flush must cancel its
    /// acknowledgement when processing stops.
    #[test]
    fn idle_acks_follow_flush_outcome() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, actor) =
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
            assert_eq!(
                source.latest(),
                Some(1),
                "the durable capture must serve while the loop idles",
            );
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
                source.latest().is_none(),
                "sources must decline after the loop stops",
            );
        });
    }

    #[test]
    fn ready_aborted_flush_stops_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _source, _marshal, actor) =
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
            drop(control.flushes.lock().remove(0));

            actor.await.expect("processing actor should stop");
            assert_eq!(control.flushes.lock().len(), 1);
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
            let (mut mailbox, control, source, _marshal, actor) =
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
                source.latest().is_none(),
                "a capture whose flush never completed must never serve",
            );
        });
    }

    /// A flush failure must panic the processing loop with the database identified and leave the
    /// block unacknowledged.
    #[test]
    #[should_panic(expected = "database finalize flush failed (type")]
    fn flush_failure_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _source, _marshal, _actor) =
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
