use crate::stateful::{
    Application, Input,
    actor::{
        core::mailbox::Message,
        processor::{Applied, Processor},
    },
    db::{DatabaseSet, Publisher},
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
use commonware_utils::{Acknowledgement, futures::Pool};
use futures::{
    future::{Either, ready},
    poll,
};
use rand_core::Rng;
use std::sync::mpsc::TryRecvError;
use tracing::{Instrument as _, debug, info_span};

/// A single unit of work for the processing loop: either a mailbox message to
/// handle or a deferred prune to run while the mailbox is idle.
enum Step<M, P> {
    Message(M),
    Prune(P),
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

    /// Installs each finalized generation's snapshot for serving once its barrier
    /// proves durable; dropping it detaches snapshot serving.
    pub(super) publisher: Publisher<<A::Databases as DatabaseSet<E>>::Snapshot>,

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
        // acknowledgement once the flush completes. Flush failures surface
        // only through these futures (panicking inside `Barrier::durable`),
        // so every one must be driven here.
        let mut syncs = Pool::<()>::default();
        select_loop! {
            self.context,
            on_start => {
                // Observe every already-completed flush (releasing its marshal
                // acknowledgement) before taking the next unit of work, so
                // acknowledgements keep flowing even while the mailbox is
                // never idle.
                while poll!(syncs.next_completed()).is_ready() {}

                // Pruning is non-critical work. We only run it when the mailbox is idle, and
                // it is never raced against the mailbox due to its internal lock acquisition.
                // If a message is ready, it is always processed immediately.
                let next = match self.mailbox.try_recv() {
                    // A message is ready: handle it now, regardless of any queued prune.
                    Ok(message) => Either::Left(ready(Some(Step::Message(message)))),
                    Err(TryRecvError::Empty) => match pending_prune.take() {
                        // No message, but a prune is queued: run it.
                        Some(prune) => Either::Left(ready(Some(Step::Prune(prune)))),
                        // No message and nothing to prune: wait on the mailbox,
                        // driving flush completions while idle.
                        None => {
                            let mailbox = &mut self.mailbox;
                            let syncs = &mut syncs;
                            Either::Right(async move {
                                loop {
                                    select! {
                                        message = mailbox.recv() => {
                                            break message.map(Step::Message);
                                        },
                                        _ = syncs.next_completed() => {},
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
                        // The processor owns the databases, so finalize consumes it and
                        // hands it back alongside the applied artifacts.
                        let (processor, applied) = self
                            .processor
                            .finalize(&self.context, block.as_ref())
                            .instrument(process)
                            .await;
                        self.processor = processor;
                        if let Some(Applied {
                            snapshot,
                            barrier,
                            prune,
                        }) = applied
                        {
                            debug!(
                                height = block.height().get(),
                                "applied finalized database batch"
                            );

                            // Acknowledge marshal only once the batch's flush
                            // completes, so marshal's processed floor never runs
                            // ahead of flushed database state (the startup rewind
                            // contract), without blocking the loop on the flush.
                            // Marshal's ack window bounds the flush backlog. On
                            // runtime teardown the acknowledgement is dropped
                            // instead: marshal redelivers the block after restart.
                            let staged = self.publisher.stage(snapshot);
                            syncs.push(async move {
                                if barrier.durable().await {
                                    staged.install();
                                    acknowledgement.acknowledge();
                                }
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
                    // Flushes may still be pending: database pruning waits on
                    // them only when the prune target is not yet durably
                    // justified (see `DatabaseSet::prune`), and marshal
                    // pruning follows it.
                    self.processor = self
                        .processor
                        .prune_databases(prune, &self.marshal)
                        .await;
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
        Application, Input, Proposed, PruneConfig,
        actor::{
            core::mailbox::Mailbox, metrics::Metrics as StatefulMetrics, processor::Processor,
        },
        db::{DatabaseSet, ManagedDb},
        tests::mocks::{
            TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant, anchor,
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Heightable as _, Reporter as _,
        marshal::{self, Update, ancestry::Ancestry, core::Actor as MarshalActor},
        simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
        types::{FixedEpocher, Height, ViewDelta},
    };
    use commonware_cryptography::{
        certificate::ConstantProvider, ed25519, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        NZU16, NZU64, NZUsize,
        acknowledgement::{Acknowledgement as _, Exact},
        channel::oneshot,
        sync::Mutex,
    };
    use futures::poll;
    use std::{convert::Infallible, sync::Arc, time::Duration};

    /// Completes one parked flush when released by the test.
    type FlushRelease = oneshot::Sender<Result<(), RuntimeError>>;

    /// Shared observer for [`GatedFlushDb`]: parked flush releases and
    /// recorded prune targets.
    #[derive(Clone, Default)]
    struct FlushControl {
        flushes: Arc<Mutex<Vec<FlushRelease>>>,
        pruned: Arc<Mutex<Vec<u64>>>,
    }

    /// Database whose finalize flush completes only when the test releases it.
    ///
    /// Its `prune` records immediately, eliding the impl-side barrier real
    /// databases provide (pruning waits for pending flushes, pinned in
    /// `stateful::db::any` tests), so the actor's own scheduling is exposed.
    struct GatedFlushDb {
        control: FlushControl,
    }

    impl<E: Send> ManagedDb<E> for GatedFlushDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = ();
        type SyncTarget = u64;
        type Snapshot = ();

        async fn snapshot(self) -> Result<(Self, Self::Snapshot), Self::Error> {
            Ok((self, ()))
        }

        fn initial_sync_target() -> Self::SyncTarget {
            unreachable!("GatedFlushDb is constructed directly in tests")
        }

        async fn init(_context: E, _config: Self::Config) -> Result<Self, Self::Error> {
            unreachable!("GatedFlushDb is constructed directly in tests")
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(
            self,
            _batch: Self::Merkleized,
        ) -> Result<(Self, Self::Snapshot, Handle<()>), Self::Error> {
            let (release, released) = oneshot::channel();
            self.control.flushes.lock().push(release);
            Ok((self, (), Handle::from_receiver(released)))
        }

        async fn prune(self, target: &Self::SyncTarget) -> Result<Self, Self::Error> {
            self.control.pruned.lock().push(*target);
            Ok(self)
        }

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(self, _target: Self::SyncTarget) -> Result<Self, Self::Error> {
            Ok(self)
        }
    }

    #[derive(Clone)]
    struct GatedApp;

    impl Application<deterministic::Context> for GatedApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = (GatedFlushDb,);
        type Provider = ();
        type Input = ();

        fn sync_targets(
            block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
            (block.height().get(),)
        }

        async fn genesis(&mut self) -> Self::Block {
            TestBlock::new(0, 0)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            None
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _databases: &Self::Databases,
            _batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            (TestMerkleized,)
        }
    }

    fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
        immutable::Config {
            metadata_partition: format!("{partition}-metadata"),
            freezer_table_partition: format!("{partition}-freezer-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-freezer-value"),
            freezer_value_target_size: 128,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition}-ordinal"),
            items_per_section: NZU64!(4),
            codec_config: (),
            replay_buffer: NZUsize!(64),
            freezer_key_write_buffer: NZUsize!(64),
            freezer_value_write_buffer: NZUsize!(64),
            ordinal_write_buffer: NZUsize!(64),
        }
    }

    /// Spawn a [`Processing`] loop over a [`GatedFlushDb`], returning its
    /// mailbox, the flush controls, and a guard keeping the (never-started)
    /// marshal actor's mailbox open.
    async fn spawn_processing(
        context: &deterministic::Context,
        prefix: &str,
        prune_config: Option<PruneConfig>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        FlushControl,
        Box<dyn std::any::Any>,
    ) {
        let mut signing = context.child("signing");
        let fixture = scheme_mocks::fixture(&mut signing, b"gated", 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), &format!("{prefix}-finalizations")),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), &format!("{prefix}-blocks")),
        )
        .await
        .expect("failed to initialize blocks archive");
        let (marshal_actor, marshal, _height) =
            MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                    start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                    partition_prefix: format!("{prefix}-marshal"),
                    mailbox_size: NZUsize!(8),
                    view_retention: ViewDelta::new(1),
                    prunable_items_per_section: NZU64!(4),
                    page_cache,
                    replay_buffer: NZUsize!(64),
                    key_write_buffer: NZUsize!(64),
                    value_write_buffer: NZUsize!(64),
                    block_codec_config: (),
                    max_repair: NZUsize!(1),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;

        let control = FlushControl::default();
        let databases = (GatedFlushDb {
            control: control.clone(),
        },);
        let processor = Processor::new(
            GatedApp,
            databases,
            anchor(0, 0),
            StatefulMetrics::new(context),
            prune_config,
        );
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let processing = Processing {
            context: ContextCell::new(context.child("processing")),
            mailbox: receiver,
            provider: (),
            marshal,
            processor,
            publisher: crate::stateful::db::Publisher::new(context).0,
            skip_finalized_until: None,
        };
        context.child("loop").spawn(move |_| processing.start());
        (Mailbox::new(sender), control, Box::new(marshal_actor))
    }

    /// The loop keeps applying finalized blocks while earlier flushes are
    /// still pending, acknowledges each block only once its flush completes
    /// (so marshal's floor never runs ahead of flushed state), and runs a
    /// deferred prune without waiting on pending flushes (database pruning
    /// itself provides that barrier).
    #[test]
    fn acks_wait_for_flushes_while_prune_runs() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // Marshal only receives prune requests here. Its actor never runs.
            let (mut mailbox, control, _marshal) = spawn_processing(
                &context,
                "gated-prune",
                Some(PruneConfig {
                    max_pending_acks: NZUsize!(1),
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

            // Block 2 filled the retention window: the deferred prune runs
            // once the mailbox idles, without waiting on the parked flushes,
            // and targets the oldest retained sync target.
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().clone(), vec![1]);
            assert!(
                poll!(&mut waiter1).is_pending() && poll!(&mut waiter2).is_pending(),
                "acknowledgements must keep waiting for pending flushes",
            );

            // Releasing block 1's flush releases only its acknowledgement.
            let release = control.flushes.lock().remove(0);
            let _ = release.send(Ok(()));
            waiter1.await.expect("block 1 acknowledgement");
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

    /// While parked idle with a flush pending, a released flush must fire its
    /// acknowledgement, a simultaneously reported block must not be lost to
    /// the completion (the historical lost-message shape), and a flush that
    /// never completes must leave its block unacknowledged.
    #[test]
    fn idle_acks_follow_flush_outcome() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal) =
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

            // Dropping block 2's release resolves its flush as shutdown. The
            // acknowledgement must be withheld so marshal's floor cannot pass
            // unflushed state.
            drop(control.flushes.lock().remove(0));
            assert!(
                waiter2.await.is_err(),
                "unflushed block must not be acknowledged",
            );
        });
    }

    /// A flush failure must panic the processing loop with the database
    /// identified (the fatal policy), rather than acknowledging the block.
    #[test]
    #[should_panic(expected = "database finalize flush failed (index 0, type")]
    fn flush_failure_panics_processing() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (mut mailbox, control, _marshal) =
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
