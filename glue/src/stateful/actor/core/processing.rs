use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::Message,
        processor::{Applied, Processor},
    },
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
use commonware_utils::futures::Pool;
use futures::{
    FutureExt as _,
    future::{Either, ready},
};
use rand_core::Rng;
use std::{collections::BTreeSet, sync::mpsc::TryRecvError};
use tracing::{Instrument as _, debug, info_span};

/// A single unit of work for the processing loop: a mailbox message to handle,
/// or deferred maintenance (a prune, or a post-prune publication refresh) run
/// while the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
    Refresh,
}

/// Pending finalize flushes, plus whether a prune left publication stale.
///
/// After a prune, the published snapshot still holds pre-prune state. A durable
/// install above the stale boundary refreshes it on its own. Otherwise the loop
/// must recapture once every flush drains.
#[derive(Default)]
struct FlushTracker {
    pending: BTreeSet<Height>,
    stale_boundary: Option<Height>,
}

impl FlushTracker {
    /// Track a started flush.
    fn track(&mut self, height: Height) {
        assert!(
            self.pending.insert(height),
            "finalize flush height must be unique",
        );
    }

    /// Record a completion and return whether it was durable.
    fn complete(&mut self, (height, durable): (Height, bool)) -> bool {
        assert!(
            self.pending.remove(&height),
            "completed flush must have a pending height",
        );
        // Only an install above the boundary is a post-prune capture.
        if durable
            && self
                .stale_boundary
                .is_some_and(|boundary| height > boundary)
        {
            self.stale_boundary = None;
        }
        if !durable {
            debug!("flush incomplete at shutdown, stopping processing");
        }
        durable
    }

    /// Whether a flush at or below `barrier` is still pending, blocking a prune.
    fn blocks_prune(&self, barrier: Height) -> bool {
        self.pending
            .first()
            .is_some_and(|height| *height <= barrier)
    }

    /// Mark publication stale after a prune. Returns false when no flush is
    /// pending, so the caller must republish immediately.
    fn mark_stale(&mut self) -> bool {
        self.stale_boundary = self.pending.last().copied();
        self.stale_boundary.is_some()
    }

    /// A recapture is due once publication is stale and every flush has drained.
    fn recapture_due(&self) -> bool {
        self.stale_boundary.is_some() && self.pending.is_empty()
    }

    /// Publication was recaptured.
    const fn recaptured(&mut self) {
        self.stale_boundary = None;
    }
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
{
    pub async fn start(mut self) {
        let mut pending_prune = None;

        // Deferred finalize flushes, each releasing its block's marshal
        // acknowledgement once the flush completes (see `Barrier`).
        let mut syncs = Pool::<(Height, bool)>::default();
        let mut tracker = FlushTracker::default();
        select_loop! {
            self.context,
            on_start => {
                // Observe every already-completed flush (releasing its marshal
                // acknowledgement) before taking the next unit of work, so
                // acknowledgements keep flowing even while the mailbox is
                // never idle.
                while let Some(completion) = syncs.next_completed().now_or_never() {
                    if !tracker.complete(completion) {
                        return;
                    }
                }

                // Pruning and publication refresh are non-critical work, run only when the
                // mailbox is idle. If a message is ready, it is always processed immediately.
                let next = match self.mailbox.try_recv() {
                    // A message is ready: handle it now, regardless of any queued prune.
                    Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        // No message, but a prune is queued: run it.
                        Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                        // Publication is stale and every flush drained: recapture.
                        None if tracker.recapture_due() => {
                            Either::Left(ready(Some(Step::Refresh)))
                        }
                        // No message and nothing to prune: wait on the mailbox, driving flush
                        // completions while idle.
                        None => {
                            let mailbox = &mut self.mailbox;
                            let syncs = &mut syncs;
                            let tracker = &mut tracker;
                            Either::Right(async move {
                                loop {
                                    select! {
                                        message = mailbox.recv() => {
                                            break message.map(Step::Message);
                                        },
                                        completion = syncs.next_completed() => {
                                            if !tracker.complete(completion) {
                                                return None;
                                            }
                                            if tracker.recapture_due() {
                                                break Some(Step::Refresh);
                                            }
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
                    self.processor
                        .propose(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            input,
                            response,
                        )
                        .instrument(process)
                        .await;
                }
                Step::Message(Message::Verify {
                    span,
                    context,
                    ancestry,
                    response,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.verify");
                    self.processor
                        .verify(
                            self.context.as_present(),
                            self.marshal.clone(),
                            context,
                            ancestry,
                            response,
                        )
                        .instrument(process)
                        .await;
                }
                Step::Message(Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                }) => {
                    let process = info_span!(parent: &span, "stateful.actor.finalized");
                    if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                        self.processor
                            .notify_finalized(self.context.as_present(), block.as_ref())
                            .instrument(process)
                            .await;
                        acknowledgement.acknowledge();
                    } else {
                        let (processor, applied) = self
                            .processor
                            .finalize(self.context.as_present(), block.as_ref())
                            .instrument(process.clone())
                            .await;
                        self.processor = processor;
                        // Keep the publication bookkeeping under the same span.
                        let _process = process.entered();
                        if let Some(Applied { publication, prune }) = applied {
                            debug!(
                                height = block.height().get(),
                                "applied finalized database batch"
                            );

                            // Install the snapshot and acknowledge marshal together
                            // once the flush completes, so neither served state nor
                            // marshal's processed floor gets ahead of what is on
                            // disk. Marshal's ack window bounds the flush backlog,
                            // and unacknowledged blocks are redelivered on restart.
                            let height = block.height();
                            tracker.track(height);
                            syncs.push(async move {
                                let durable = publication.install_when_durable().await;
                                if durable {
                                    acknowledgement.acknowledge();
                                }
                                (height, durable)
                            });
                            if let Some(prune) = prune {
                                pending_prune = Some(prune);
                            }
                        } else {
                            // Duplicate report: marshal redelivers a processed
                            // height only after a restart, where startup aligned
                            // the databases to durable state.
                            acknowledgement.acknowledge();
                        }
                    }
                }
                Step::Prune(prune) => {
                    // The prune target must be durable, but later blocks remain available in
                    // marshal for replay and do not delay maintenance.
                    while tracker.blocks_prune(prune.barrier_height) {
                        let completion = syncs.next_completed().await;
                        if !tracker.complete(completion) {
                            return;
                        }
                    }
                    self.processor = self.processor.prune_databases(prune, &self.marshal).await;
                    // The published snapshot predates this prune and keeps the pruned
                    // storage alive, as do generations staged before it.
                    if !tracker.mark_stale() {
                        self.processor = self.processor.republish().await;
                    }
                }
                Step::Refresh => {
                    // Every flush drained, so applied state is durable.
                    self.processor = self.processor.republish().await;
                    tracker.recaptured();
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
    use super::{FlushTracker, Processing, skip_finalized_block};
    use crate::stateful::{
        PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
        },
        db::{Publisher, SetSource, Single},
        tests::{
            fixtures,
            mocks::{FlushControl, TestApp, TestBlock, TestDb, anchor, served_generation},
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Reporter as _, marshal::Update, simplex::mocks::scheme as scheme_mocks, types::Height,
    };
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
    };
    use futures::poll;
    use std::{sync::Arc, time::Duration};

    /// Only an install strictly above the stale boundary satisfies the refresh.
    #[test]
    fn tracker_clears_stale_only_above_boundary() {
        let mut tracker = FlushTracker::default();
        tracker.track(Height::new(1));
        tracker.track(Height::new(2));
        assert!(tracker.complete((Height::new(1), true)));
        assert!(tracker.mark_stale());
        tracker.track(Height::new(3));

        // An install at the boundary carries a pre-prune capture: still stale.
        assert!(tracker.complete((Height::new(2), true)));
        assert!(!tracker.recapture_due());

        // An install above the boundary carries a post-prune capture: refreshed.
        assert!(tracker.complete((Height::new(3), true)));
        assert!(!tracker.recapture_due());
    }

    #[test]
    fn tracker_defers_recapture_until_flushes_drain() {
        let mut tracker = FlushTracker::default();
        tracker.track(Height::new(1));
        tracker.track(Height::new(2));
        assert!(tracker.complete((Height::new(1), true)));
        assert!(tracker.mark_stale());
        assert!(!tracker.recapture_due());
        assert!(tracker.complete((Height::new(2), true)));
        assert!(tracker.recapture_due());
        tracker.recaptured();
        assert!(!tracker.recapture_due());
    }

    #[test]
    fn tracker_requests_immediate_republish_when_drained() {
        let mut tracker = FlushTracker::default();
        assert!(!tracker.mark_stale());
        assert!(!tracker.recapture_due());
    }

    /// Spawn a [`Processing`] loop over a gated [`TestDb`], returning its
    /// mailbox, flush controls, the publication source, a guard keeping the
    /// (never-started) marshal actor's mailbox open, and the processing actor
    /// handle.
    async fn spawn_processing(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, TestApp>,
        FlushControl,
        SetSource<()>,
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
        let (publisher, source) = Publisher::new(context);
        let processor = Processor::new(
            TestApp,
            databases,
            publisher,
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
            skip_finalized_until: None,
        };
        let actor = context.child("loop").spawn(move |_| processing.start());
        (Mailbox::new(sender), control, source, marshal.guards, actor)
    }

    /// Pruning waits for the flush that covers its target without waiting for newer state.
    #[test]
    fn prune_waits_only_for_target_flush() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Marshal only receives prune requests here. Its actor never runs.
            let (mut mailbox, control, source, _marshal, _actor) = spawn_processing(
                &context,
                "gated-prune",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Apply blocks 1 and 2 without releasing any flush: the loop must
            // stay live (both blocks applied) while no acknowledgement fires.
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
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must wait for pending flushes",
            );
            assert!(
                served_generation(&source).is_none(),
                "no generation may serve before its flush is durable",
            );

            // Block 2 filled the retention window, but pruning must remain blocked behind the
            // target at block 1.
            context.sleep(Duration::from_millis(50)).await;
            assert!(control.pruned.lock().is_empty());
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must keep waiting for pending flushes",
            );

            // Releasing block 1 makes the prune target durable. Block 2 remains retained in
            // marshal and must not delay pruning.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
            assert_eq!(
                served_generation(&source),
                Some(0),
                "block 1's generation must serve once durable",
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
                served_generation(&source).is_some_and(|generation| generation > 0),
                "block 2's generation must serve once durable",
            );
        });
    }

    /// A prune with no later finalization must refresh publication, so serving
    /// stops pinning the pruned state.
    #[test]
    fn prune_without_later_block_refreshes_publication() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, source, _marshal, _actor) = spawn_processing(
                &context,
                "gated-prune-refresh",
                Some(PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                }),
            )
            .await;

            // Blocks 1 and 2 fill the retention window, scheduling a prune at block 1.
            // Both generations were captured before the prune runs.
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

            // Block 2's generation was captured before the prune, so its install must
            // not satisfy the refresh: with no later block, the loop itself recaptures
            // once every flush drains.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            while served_generation(&source) < Some(2) {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(
                served_generation(&source),
                Some(2),
                "the post-prune recapture must serve",
            );
        });
    }

    /// A post-prune generation installing on its own satisfies the publication
    /// refresh: the loop must not recapture redundantly.
    #[test]
    fn post_prune_install_clears_publication_refresh() {
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

            // Block 2's pre-prune install must not satisfy the refresh. Block 3's
            // post-prune install must, so no recapture generation ever appears.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter2.await.expect("block 2 acknowledgement");
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter3.await.expect("block 3 acknowledgement");
            while served_generation(&source) < Some(2) {
                context.sleep(Duration::from_millis(10)).await;
            }
            context.sleep(Duration::from_millis(50)).await;
            assert_eq!(
                served_generation(&source),
                Some(2),
                "block 3's own install must satisfy the refresh without a recapture",
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
            assert!(
                served_generation(&source).is_none(),
                "an aborted generation must never serve",
            );
        });
    }

    /// While the loop is idle, a completed flush must release its acknowledgement without
    /// displacing a simultaneously reported block, while an incomplete flush must leave its block
    /// unacknowledged.
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
            let (acknowledgement, mut waiter2) = Exact::handle();
            let _ = mailbox.report(Update::Block(
                Arc::new(TestBlock::new(2, 2)),
                acknowledgement,
            ));
            waiter1.await.expect("block 1 acknowledgement");
            assert_eq!(
                served_generation(&source),
                Some(0),
                "the durable generation must serve while the loop idles",
            );
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
            assert!(
                served_generation(&source).is_none(),
                "sources must decline after the loop stops",
            );
        });
    }

    #[test]
    fn ready_aborted_flush_stops_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _source, _marshal, actor) =
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
            let (mut mailbox, control, source, _marshal, actor) =
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
            assert!(
                served_generation(&source).is_none(),
                "a generation whose flush never completed must never serve",
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
