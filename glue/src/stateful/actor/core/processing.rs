//! The post-sync processing loop of the stateful actor.
//!
//! Each finalized block is applied to the databases, its flush deferred to a
//! pool, and a snapshot of the applied state staged for publication. The loop
//! publishes the snapshot and acknowledges the block to marshal only once the
//! flush is durable, so readers and marshal's floor never get ahead of disk.
//!
//! Pruning and fresh post-prune captures are maintenance, run only while the
//! mailbox is idle. A prune waits until the pruned range is durable, and leaves
//! the served snapshot stale until a post-prune capture publishes (see
//! [`Publisher`].

use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::Message,
        processor::{Applied, Processor},
    },
    db::{Publisher, SnapshotsOf},
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
use std::sync::mpsc::TryRecvError;
use tracing::{Instrument as _, debug, info_span};

/// A single unit of work for the processing loop: a mailbox message to handle,
/// or deferred maintenance (a prune, or a fresh post-prune capture) run while
/// the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
    Capture,
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

    /// Publishes each durable generation of snapshots for serving.
    pub(super) snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

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
        select_loop! {
            self.context,
            on_start => {
                // Observe every already-completed flush (releasing its marshal
                // acknowledgement) before taking the next unit of work, so
                // acknowledgements keep flowing even while the mailbox is
                // never idle.
                while let Some((height, durable)) = syncs.next_completed().now_or_never() {
                    if !self.snapshot_publisher.complete(height, durable) {
                        return;
                    }
                }

                // Pruning and fresh captures are non-critical work, run only when the
                // mailbox is idle. If a message is ready, it is always processed immediately.
                let next = match self.mailbox.try_recv() {
                    // A message is ready: handle it now, regardless of any queued prune.
                    Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        // No message, but a prune is queued: run it.
                        Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                        // The served snapshot is stale and every flush drained.
                        None if self.snapshot_publisher.capture_needed() => {
                            Either::Left(ready(Some(Step::Capture)))
                        }
                        // No message and nothing to prune: wait on the mailbox, driving flush
                        // completions while idle.
                        None => {
                            let mailbox = &mut self.mailbox;
                            let syncs = &mut syncs;
                            let snapshot_publisher = &mut self.snapshot_publisher;
                            Either::Right(async move {
                                loop {
                                    select! {
                                        message = mailbox.recv() => {
                                            break message.map(Step::Message);
                                        },
                                        (height, durable) = syncs.next_completed() => {
                                            if !snapshot_publisher.complete(height, durable) {
                                                return None;
                                            }
                                            if snapshot_publisher.capture_needed() {
                                                break Some(Step::Capture);
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
                        let applied;
                        (self.processor, applied) = self
                            .processor
                            .finalize(self.context.as_present(), block.as_ref())
                            .instrument(process.clone())
                            .await;
                        // Keep the publication bookkeeping under the same span.
                        let _process = process.entered();
                        if let Some(Applied {
                            snapshots,
                            barrier,
                            prune,
                        }) = applied
                        {
                            debug!(
                                height = block.height().get(),
                                "applied finalized database batch"
                            );

                            // The snapshot publishes and marshal is acknowledged only
                            // once the flush completes, so neither served state nor
                            // marshal's processed floor gets ahead of what is on
                            // disk. Marshal's ack window bounds the flush backlog,
                            // and unacknowledged blocks are redelivered on restart.
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
                    while self.snapshot_publisher.blocks_prune(prune.barrier_height) {
                        let (height, durable) = syncs.next_completed().await;
                        if !self.snapshot_publisher.complete(height, durable) {
                            return;
                        }
                    }
                    self.processor = self.processor.prune(prune, &self.marshal).await;
                    // The published snapshot predates this prune and keeps the pruned
                    // storage alive, as do snapshots staged before it.
                    if !self.snapshot_publisher.mark_stale() {
                        let snapshots;
                        (self.processor, snapshots) = self.processor.snapshot().await;
                        self.snapshot_publisher
                            .publish_now(self.processor.processed_height(), snapshots);
                    }
                }
                Step::Capture => {
                    // The served snapshot went stale at the last prune and no later
                    // flush replaced it. Every flush has drained, so the applied
                    // state is durable and can publish directly.
                    let snapshots;
                    (self.processor, snapshots) = self.processor.snapshot().await;
                    self.snapshot_publisher
                        .publish_now(self.processor.processed_height(), snapshots);
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
    use super::{Processing, skip_finalized_block};
    use crate::stateful::{
        PruneConfig,
        actor::{
            core::mailbox::Mailbox,
            metrics::Metrics as StatefulMetrics,
            processor::{Processor, Pruning},
        },
        db::{Publisher, Reader, Single},
        tests::{
            fixtures,
            mocks::{FlushControl, TestApp, TestBlock, TestDb, anchor},
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Reporter as _, marshal::Update, simplex::mocks::scheme as scheme_mocks, types::Height,
    };
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Metrics as _, Runner as _,
        Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
    };
    use futures::poll;
    use std::{sync::Arc, time::Duration};

    async fn spawn_processing(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, TestApp>,
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
        let processor = Processor::new(
            TestApp,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            pruning,
        );
        let (mut publisher, reader) = Publisher::new(context);
        let (processor, snapshots) = processor.snapshot().await;
        publisher.publish_now(anchor(0, 0).height, snapshots);
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal: marshal.mailbox,
            processor,
            snapshot_publisher: publisher,
            skip_finalized_until: None,
        };
        let actor = context.child("loop").spawn(move |_| processing.start());
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
            assert_eq!(
                source.latest(),
                Some(0),
                "only the initial generation may serve before a block flush is durable",
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
                source.latest(),
                Some(1),
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
                source.latest().is_some_and(|generation| generation > 1),
                "block 2's generation must serve once durable",
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

    /// A post-prune generation publishing on its own satisfies the publication
    /// stale snapshot: the loop must not capture redundantly.
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
                source.latest().is_none(),
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
                source.latest(),
                Some(1),
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
                source.latest().is_none(),
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
