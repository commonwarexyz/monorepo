use crate::stateful::{
    actor::{
        core::mailbox::Message,
        metrics::Metrics as StatefulMetrics,
        processor::{Commit, FinalizeStatus, Processor},
    },
    db::DatabaseSet,
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
    CertifiableBlock, Heightable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, mpsc},
    Acknowledgement,
};
use rand_core::Rng;
use tracing::{debug, info_span, Instrument as _};

/// Digest of an application block.
type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

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

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal mailbox used for lazy block lookup.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// The processing state of the actor.
    pub(super) processor: Processor<E, A>,

    /// Finalized marshal blocks at or below this height were already reflected
    /// in the selected database anchor and should be acknowledged only.
    pub(super) skip_finalized_until: Option<Height>,
}

/// Applies staged commits durably, in finalization order, off the actor loop.
///
/// Owning clones of the application and database set lets the committer run
/// [`DatabaseSet::finalize`] (write lock + durable sync) and the application's
/// finalized hook without blocking the actor's propose/verify lane. Marshal
/// acknowledgements are released here, strictly after durability, preserving
/// the contract that acknowledged blocks are recoverable from disk.
struct Committer<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Application handle used for post-commit finalized hooks.
    app: A,

    /// The committed database set.
    databases: A::Databases,

    /// Marshal mailbox used for deferred pruning.
    marshal: MarshalMailbox<S, V>,

    /// Actor metrics (records durable commit durations).
    metrics: StatefulMetrics,

    /// Staged commits from the processing loop, in finalization order.
    commits: mpsc::UnboundedReceiver<(Commit<E, A>, Exact)>,

    /// Committed digests reported back to the processing loop so it can drop
    /// the retained pending entries.
    completions: mpsc::UnboundedSender<BlockDigest<A, E>>,
}

impl<E, A, S, V> Committer<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Apply staged commits until the processing loop drops the channel.
    ///
    /// Failures are fatal by design: [`DatabaseSet::finalize`] and
    /// [`DatabaseSet::prune`] panic internally on error, and the runtime
    /// treats a task panic as fatal to the process.
    async fn run(mut self, context: E) {
        while let Some((commit, acknowledgement)) = self.commits.recv().await {
            let Commit {
                block,
                batch,
                prune,
            } = commit;
            let timer = self.metrics.finalize_duration.timer(&context);
            self.databases.finalize(batch).await;
            self.app
                .finalized(
                    (context.child("finalized"), block.context()),
                    &block,
                    &self.databases,
                )
                .await;
            // The batch is durable: release the marshal acknowledgement.
            acknowledgement.acknowledge();
            timer.observe(&context);
            debug!(
                height = block.height().get(),
                "persisted finalized database batch"
            );
            // Let the actor drop the pending entry retained for this commit.
            if self.completions.send(block.digest()).is_err() {
                debug!("processing loop stopped, stopping committer");
                return;
            }
            if let Some(prune) = prune {
                prune.run(&mut self.databases, &self.marshal).await;
            }
        }
    }
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
        // Stage-and-commit pipeline: the actor stages each finalized block in
        // memory and hands the durable commit (database write lock + sync) to
        // a single FIFO committer task, so propose/verify are never queued
        // behind an in-flight commit.
        //
        // In-flight commits are bounded by marshal's pending-ack window: every
        // queued commit holds an unreleased acknowledgement, so marshal stops
        // delivering finalized blocks long before these channels could grow
        // without bound.
        let (commit_tx, commit_rx) = mpsc::unbounded_channel();
        let (completion_tx, mut completion_rx) = mpsc::unbounded_channel();
        let committer = Committer {
            app: self.processor.application(),
            databases: self.processor.databases().clone(),
            marshal: self.marshal.clone(),
            metrics: self.processor.metrics().clone(),
            commits: commit_rx,
            completions: completion_tx,
        };
        // Spawned from the actor's long-lived context so the committer lives
        // exactly as long as the processing loop.
        let _committer = self
            .context
            .as_present()
            .child("committer")
            .spawn(|context| committer.run(context));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received, stopping processing");
            },
            // Biased before the mailbox: completions are cheap map removals
            // that stop the pending map from retaining committed entries.
            completion = completion_rx.recv() => {
                let Some(digest) = completion else {
                    panic!("committer terminated unexpectedly");
                };
                self.processor.commit_complete(&digest);
            },
            message = self.mailbox.recv() => {
                let Some(message) = message else {
                    debug!("mailbox closed, stopping processing");
                    break;
                };
                match message {
                    Message::Propose {
                        span,
                        context,
                        ancestry,
                        response,
                    } => {
                        let process = info_span!(parent: &span, "stateful.actor.propose");
                        self.processor
                            .propose(
                                self.context.as_present(),
                                self.marshal.clone(),
                                context,
                                ancestry,
                                &mut self.input_provider,
                                response,
                            )
                            .instrument(process)
                            .await;
                    }
                    Message::Verify {
                        span,
                        context,
                        ancestry,
                        response,
                    } => {
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
                    Message::Finalized {
                        span,
                        block,
                        acknowledgement,
                    } => {
                        let process = info_span!(parent: &span, "stateful.actor.finalized");
                        async {
                            if skip_finalized_block(&mut self.skip_finalized_until, block.height()) {
                                self.processor
                                    .notify_finalized(self.context.as_present(), &block)
                                    .await;
                                acknowledgement.acknowledge();
                                return;
                            }
                            let (status, commit) =
                                self.processor.finalize(&self.context, block).await;
                            if let FinalizeStatus::Staged { height } = status {
                                debug!(
                                    height = height.get(),
                                    "staged finalized database batch for commit"
                                );
                            }
                            match commit {
                                // The committer releases the acknowledgement
                                // only after the batch is durably committed.
                                Some(commit) => {
                                    if commit_tx.send((commit, acknowledgement)).is_err() {
                                        panic!("committer terminated unexpectedly");
                                    }
                                }
                                None => acknowledgement.acknowledge(),
                            }
                        }
                        .instrument(process)
                        .await;
                    }
                    Message::SubscribeDatabases { response } => {
                        response.send_lossy(self.processor.databases().clone());
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
    use super::{skip_finalized_block, Processing};
    use crate::stateful::{
        actor::{metrics::Metrics as StatefulMetrics, processor::Processor},
        db::{Anchor, DatabaseSet, ManagedDb, Merkleized, Shared, Unmerkleized},
        tests::mocks::{TestBlock, TestScheme, TestVariant},
        Application, Mailbox, Proposed,
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        marshal::{self, ancestry, core::Actor as MarshalActor, Update},
        types::{FixedEpocher, Height, ViewDelta},
        Application as ConsensusApplication, CertifiableBlock, Heightable as _, Reporter as _,
    };
    use commonware_cryptography::{certificate::ConstantProvider, Digestible as _};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock as _, ContextCell, Runner as _, Spawner as _,
        Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        acknowledgement::{Acknowledgement as _, Exact},
        sync::Mutex,
        NZUsize, NZU16, NZU64,
    };
    use futures::{FutureExt as _, Stream, StreamExt as _};
    use std::{convert::Infallible, sync::Arc, time::Duration};

    /// Simulated latency of one durable database commit (the fsync).
    const COMMIT_LATENCY: Duration = Duration::from_millis(100);

    /// Where an unmerkleized batch was forked from.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ForkOrigin {
        /// Forked from committed database state via [`ManagedDb::new_batch`].
        Committed,
        /// Forked from a retained pending overlay via [`Merkleized::new_batch`].
        Overlay,
    }

    #[derive(Clone, Copy)]
    struct PacedUnmerkleized {
        origin: ForkOrigin,
    }

    #[derive(Clone, Copy)]
    struct PacedMerkleized;

    impl Unmerkleized for PacedUnmerkleized {
        type Merkleized = PacedMerkleized;
        type Error = Infallible;

        async fn merkleize(self) -> Result<Self::Merkleized, Self::Error> {
            Ok(PacedMerkleized)
        }
    }

    impl Merkleized for PacedMerkleized {
        type Digest = commonware_cryptography::sha256::Digest;
        type Unmerkleized = PacedUnmerkleized;

        fn root(&self) -> Self::Digest {
            commonware_cryptography::sha256::Digest::from([0; 32])
        }

        fn new_batch(&self) -> Self::Unmerkleized {
            PacedUnmerkleized {
                origin: ForkOrigin::Overlay,
            }
        }
    }

    /// A database whose durable commit sleeps for [`COMMIT_LATENCY`] while
    /// holding the write lock, modeling an fsync under the DB write lock.
    struct PacedDb {
        context: deterministic::Context,
        commits: Arc<Mutex<Vec<std::time::SystemTime>>>,
    }

    impl ManagedDb<deterministic::Context> for PacedDb {
        type Unmerkleized = PacedUnmerkleized;
        type Merkleized = PacedMerkleized;
        type Error = Infallible;
        type Config = Arc<Mutex<Vec<std::time::SystemTime>>>;
        type SyncTarget = ();

        async fn init(
            context: deterministic::Context,
            commits: Self::Config,
        ) -> Result<Self, Self::Error> {
            Ok(Self { context, commits })
        }

        async fn new_batch(db: &Shared<Self>) -> Self::Unmerkleized {
            // Forking committed state reads through the database, so it must
            // wait out any in-flight commit's write lock.
            let _guard = db.read().await;
            PacedUnmerkleized {
                origin: ForkOrigin::Committed,
            }
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<(), Self::Error> {
            // Model the durable commit fsync while the write lock is held.
            self.context.sleep(COMMIT_LATENCY).await;
            self.commits.lock().push(self.context.current());
            Ok(())
        }

        fn sync_target(&self) -> Self::SyncTarget {}

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Application over [`PacedDb`] that records where its propose batches
    /// were forked from.
    #[derive(Clone)]
    struct PacedApp {
        last_propose_origin: Arc<Mutex<Option<ForkOrigin>>>,
    }

    impl Application<deterministic::Context> for PacedApp {
        type SigningScheme = TestScheme;
        type Context = <TestBlock as CertifiableBlock>::Context;
        type Block = TestBlock;
        type Databases = Shared<PacedDb>;
        type InputProvider = ();

        fn sync_targets(
            _block: &Self::Block,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::SyncTargets {
        }

        async fn genesis(&mut self) -> Self::Block {
            TestBlock::new(0, 0)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Stream<Item = Self::Block> + Send,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            let mut ancestry = Box::pin(ancestry);
            let parent = ancestry.next().await?;
            self.last_propose_origin.lock().replace(batches.origin);
            let height = parent.height().get() + 1;
            let block = TestBlock::new(height, u8::try_from(height).expect("test height fits u8"));
            let merkleized = batches.merkleize().await.expect("merkleize is infallible");
            Some(Proposed { block, merkleized })
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Stream<Item = Self::Block> + Send,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> Option<<Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized> {
            let mut ancestry = Box::pin(ancestry);
            let _block = ancestry.next().await?;
            Some(batches.merkleize().await.expect("merkleize is infallible"))
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            batches: <Self::Databases as DatabaseSet<deterministic::Context>>::Unmerkleized,
        ) -> <Self::Databases as DatabaseSet<deterministic::Context>>::Merkleized {
            batches.merkleize().await.expect("merkleize is infallible")
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

    /// Benchmark and regression test for pipelined finalization.
    ///
    /// A finalized block's durable commit costs [`COMMIT_LATENCY`] under the
    /// database write lock. A propose request that arrives 1ms later must not
    /// queue behind that commit: it forks the retained pending overlay of the
    /// finalizing parent and resolves in ~0 simulated milliseconds. The marshal
    /// acknowledgement, by contrast, must not fire until the commit is durable,
    /// and commits must stay in finalization order.
    #[test]
    fn finalized_commit_does_not_block_propose() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            // A marshal mailbox is required to construct the processing loop,
            // but this scenario never performs a marshal lookup: all parents
            // are either pending or the processed anchor.
            let mut signing_context = context.child("signing");
            let fixture = commonware_consensus::simplex::mocks::scheme::fixture(
                &mut signing_context,
                b"pipelined-commit",
                1,
            );
            let provider = ConstantProvider::new(fixture.schemes[0].clone());
            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
            let finalizations_by_height = immutable::Archive::init(
                context.child("finalizations_by_height"),
                archive_config(page_cache.clone(), "pipelined-commit-finalizations"),
            )
            .await
            .expect("failed to initialize finalizations archive");
            let finalized_blocks = immutable::Archive::init(
                context.child("finalized_blocks"),
                archive_config(page_cache.clone(), "pipelined-commit-blocks"),
            )
            .await
            .expect("failed to initialize blocks archive");
            let (_marshal_actor, marshal, _height) =
                MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider,
                        epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                        start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                        partition_prefix: "pipelined-commit-marshal".to_string(),
                        mailbox_size: NZUsize!(8),
                        view_retention_timeout: ViewDelta::new(1),
                        prunable_items_per_section: NZU64!(4),
                        page_cache,
                        replay_buffer: NZUsize!(64),
                        key_write_buffer: NZUsize!(64),
                        value_write_buffer: NZUsize!(64),
                        block_codec_config: (),
                        max_repair: NZUsize!(1),
                        max_pending_acks: NZUsize!(4),
                        strategy: Sequential,
                    },
                )
                .await;

            // Assemble the processing loop directly at the genesis anchor.
            let commits = Arc::new(Mutex::new(Vec::new()));
            let databases = <Shared<PacedDb> as DatabaseSet<deterministic::Context>>::init(
                context.child("db_set"),
                commits.clone(),
            )
            .await;
            let app = PacedApp {
                last_propose_origin: Arc::new(Mutex::new(None)),
            };
            let genesis = TestBlock::new(0, 0);
            let processor = Processor::new(
                app.clone(),
                databases,
                Anchor {
                    height: Height::zero(),
                    round: genesis.context().round,
                    digest: genesis.digest(),
                },
                StatefulMetrics::new(&context),
                None,
            );
            let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
            let mut mailbox = Mailbox::new(sender);
            let processing = Processing {
                context: ContextCell::new(context.child("stateful")),
                mailbox: receiver,
                input_provider: (),
                marshal,
                processor,
                skip_finalized_until: None,
            };
            let _processing = context
                .child("processing")
                .spawn(move |_| processing.start());

            // Cache pending state for block1 on top of genesis.
            let block1 = TestBlock::new(1, 1);
            assert!(
                mailbox
                    .verify(
                        (context.child("verify"), block1.context()),
                        ancestry::from_iter([block1.clone(), genesis.clone()]),
                    )
                    .await,
                "block1 must verify against the genesis anchor",
            );

            // Report block1 finalized; its durable commit incurs the paced fsync.
            let start = context.current();
            let (ack1, mut waiter1) = Exact::handle();
            mailbox.report(Update::Block(block1.clone(), ack1));

            // One millisecond later, ask the actor to propose on top of block1
            // while the commit is still in flight.
            context.sleep(Duration::from_millis(1)).await;
            let propose_started = context.current();
            let block2 = mailbox
                .propose(
                    (context.child("propose"), TestBlock::new(2, 2).context()),
                    ancestry::from_iter([block1.clone(), genesis.clone()]),
                )
                .await
                .expect("propose on the finalizing tip must succeed");
            let propose_latency = context
                .current()
                .duration_since(propose_started)
                .expect("time is monotonic");
            println!("propose latency behind in-flight commit: {propose_latency:?}");
            assert!(
                propose_latency < Duration::from_millis(5),
                "propose must not queue behind the durable commit: {propose_latency:?}",
            );
            assert_eq!(
                *app.last_propose_origin.lock(),
                Some(ForkOrigin::Overlay),
                "propose must fork the retained overlay of the committing parent",
            );

            // The acknowledgement must not fire before the fsync completes.
            assert!(
                (&mut waiter1).now_or_never().is_none(),
                "acknowledgement fired before the durable commit completed",
            );
            assert!(
                commits.lock().is_empty(),
                "no batch can be durable before the paced fsync elapses",
            );

            // Finalize the freshly proposed block while block1 is still
            // committing; commits and acknowledgements must stay in order.
            let (ack2, mut waiter2) = Exact::handle();
            mailbox.report(Update::Block(block2, ack2));

            waiter1.await.expect("block1 acknowledgement must fire");
            let ack1_latency = context
                .current()
                .duration_since(start)
                .expect("time is monotonic");
            println!("block1 acknowledgement latency: {ack1_latency:?}");
            assert!(
                ack1_latency >= COMMIT_LATENCY,
                "acknowledgement must wait for the durable commit: {ack1_latency:?}",
            );
            assert!(
                (&mut waiter2).now_or_never().is_none(),
                "block2 acknowledged before its own durable commit",
            );

            waiter2.await.expect("block2 acknowledgement must fire");
            let ack2_latency = context
                .current()
                .duration_since(start)
                .expect("time is monotonic");
            println!("block2 acknowledgement latency: {ack2_latency:?}");
            assert!(
                ack2_latency >= ack1_latency + COMMIT_LATENCY,
                "commits must be applied in finalization order: {ack2_latency:?}",
            );
            assert_eq!(commits.lock().len(), 2, "both batches must be durable");
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
