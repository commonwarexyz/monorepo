//! The two-slot commit pipeline.
//!
//! A commit makes its finalized archives durable, then publishes the checkpoint that names them.
//! A second commit may sync its archives while the first publishes, but publishes only after the
//! first has.

use super::{
    actor::{Catalog, DurabilityCompletion, Fatal, outcome},
    admission::join_syncs,
    handoff,
    mailbox::Error,
    metrics::Metrics,
    validate,
};
use crate::multimmit::{
    actors::util::Completion,
    marshal::{
        actors::delivery::{self, DeliveryOutput},
        storage::{
            Error as StorageError,
            catalog::{CatalogStore, CommitPublication},
            catalog_state::{Checkpoint, CommitCleanup},
            commit::Commit,
        },
        types::Reply,
    },
    types::Body,
};
use commonware_actor::Feedback;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Clock, Metrics as RuntimeMetrics, Spawner};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
};
use tracing::{Instrument as _, Span, info_span};

/// Bounds pending archive growth without putting cleanup on every publication.
const MAX_COMMITS_BEFORE_CLEANUP: usize = 8;

/// One accepted commit awaiting durability.
pub(super) struct PendingCommit<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    publication: CommitPublication<H::Digest>,
    completion: oneshot::Sender<Result<(), Error>>,
    /// Outputs handed to delivery once the checkpoint is published.
    delivery: Option<delivery::DurableBatch<H, B>>,
    /// Hot-body bytes `delivery` charges to the shared budget.
    delivery_bytes: u64,
    outputs: usize,
    span: Span,
}

/// The commit pipeline's slots.
///
/// ```text
///           accept            archives synced         checkpoint published
///   Idle -----------> Archiving ---------------> Publishing ----------------> Idle
///                        |                           |
///                        | accept                    | accept
///                        v                           v
///               ArchivingBuffered --archives--> PublishingArchiving --archives--> PublishingArchived
///                                                     |                               |
///                                         published: next is Archiving    published: next is Publishing
/// ```
///
/// In the two-commit states the first commit is the older one.
#[derive(Default)]
pub(super) enum CommitState<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// No commit is in flight.
    #[default]
    Idle,
    /// One commit's archives are syncing.
    Archiving(PendingCommit<H, B>),
    /// The first commit's archives are syncing; the second waits to start its own.
    ArchivingBuffered(PendingCommit<H, B>, PendingCommit<H, B>),
    /// One commit's checkpoint is publishing.
    Publishing(PendingCommit<H, B>),
    /// The first commit's checkpoint is publishing while the second's archives sync.
    PublishingArchiving(PendingCommit<H, B>, PendingCommit<H, B>),
    /// The first commit's checkpoint is publishing; the second's archives are durable.
    PublishingArchived(PendingCommit<H, B>, PendingCommit<H, B>),
}

impl<H, B> CommitState<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    const fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }

    const fn is_full(&self) -> bool {
        matches!(
            self,
            Self::ArchivingBuffered(_, _)
                | Self::PublishingArchiving(_, _)
                | Self::PublishingArchived(_, _)
        )
    }
}

/// Accepted and published checkpoints, the commits between them, and the cleanup they owe.
pub(super) struct CommitPipeline<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    state: CommitState<H, B>,
    /// Checkpoint of the newest accepted commit.
    accepted: Checkpoint<H::Digest>,
    /// Newest published checkpoint.
    durable: Checkpoint<H::Digest>,
    /// Hot-body bytes charged to commits not yet handed to delivery.
    pending_delivery_bytes: u64,
    /// Pending-archive cleanup owed by published commits.
    cleanup: Option<CommitCleanup>,
    commits_since_cleanup: usize,
}

impl<H, B> CommitPipeline<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) fn new(checkpoint: Checkpoint<H::Digest>) -> Self {
        Self {
            state: CommitState::Idle,
            accepted: checkpoint.clone(),
            durable: checkpoint,
            pending_delivery_bytes: 0,
            cleanup: None,
            commits_since_cleanup: 0,
        }
    }

    /// Returns whether no commit is in flight.
    pub(super) const fn is_idle(&self) -> bool {
        self.state.is_idle()
    }

    /// Returns the newest published checkpoint.
    pub(super) const fn durable(&self) -> &Checkpoint<H::Digest> {
        &self.durable
    }

    /// Replaces both checkpoints after a floor installation.
    pub(super) fn installed(&mut self, checkpoint: Checkpoint<H::Digest>) {
        self.accepted = checkpoint.clone();
        self.durable = checkpoint;
    }
}

impl<H, B> PendingCommit<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Starts syncing the finalized archives this commit wrote.
    async fn start_archives<T, E, V>(
        &self,
        stores: &mut CatalogStore<T, E, H, V, B>,
        durability: &mut Pool<'static, DurabilityCompletion<H::Digest>>,
        metrics: &Metrics,
        clock: &impl Clock,
    ) -> Result<(), StorageError>
    where
        T: Translator,
        E: Context,
        V: Variant,
        B::Cfg: Clone,
    {
        let timer = metrics.archive_durability_timer(clock);
        let span = info_span!(
            parent: &self.span,
            "multimmit.marshal.catalog.sync_finalized_archives"
        );
        let handles = stores
            .start_finalized_sync(&self.publication)
            .instrument(span.clone())
            .await?;
        durability.push(
            async move { DurabilityCompletion::CommitArchives(timer, join_syncs(handles).await) }
                .instrument(span),
        );
        Ok(())
    }

    /// Starts publishing this commit's checkpoint once its archives are durable.
    async fn start_checkpoint<T, E, V>(
        &self,
        stores: &mut CatalogStore<T, E, H, V, B>,
        durability: &mut Pool<'static, DurabilityCompletion<H::Digest>>,
        metrics: &Metrics,
        clock: &impl Clock,
    ) -> Result<(), StorageError>
    where
        T: Translator,
        E: Context,
        V: Variant,
        B::Cfg: Clone,
    {
        let timer = metrics.publication_timer(clock);
        let span = info_span!(
            parent: &self.span,
            "multimmit.marshal.catalog.publish_checkpoint"
        );
        let sync = stores
            .start_sync_publication(&self.publication)
            .instrument(span.clone())
            .await?;
        durability.push(
            async move {
                DurabilityCompletion::CommitCheckpoint(
                    timer,
                    sync.await.map_err(StorageError::from),
                )
            }
            .instrument(span),
        );
        Ok(())
    }
}

impl<R, T, E, H, V, B> Catalog<R, T, E, H, V, B>
where
    R: Clock + Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Accepts a commit into the pipeline, or rejects it.
    pub(super) async fn accept_commit(
        &mut self,
        batch: Commit<H, V>,
        handoff: Vec<delivery::HotOutput<H, B>>,
        reply: Reply<Completion<Error>, Error>,
    ) -> Result<(), Fatal> {
        if self.commits.durable == batch.checkpoint {
            let (completion, token) = Completion::channel(|| Error::Closed);
            completion.send_lossy(Ok(()));
            reply.send_lossy(Ok(token));
            return Ok(());
        }
        if self.commits.state.is_full() {
            reply.send_lossy(Err(Error::CommitWindowFull));
            return Ok(());
        }
        let chains = self.stores.pending().chain_count();
        if let Err(error) = validate::commit(&self.commits.accepted, chains, &self.bounds, &batch) {
            reply.send_lossy(Err(error));
            return Ok(());
        }
        let plan = match handoff::plan(
            &batch.outputs,
            batch.checkpoint.floor_generation(),
            handoff,
            [self.reads.live(), self.reads.materialized()],
            handoff::Budget {
                max_bytes: self.reads.live().max_bytes().get(),
                pending: self.commits.pending_delivery_bytes,
            },
        ) {
            Ok(plan) => plan,
            Err(error) => {
                reply.send_lossy(Err(error));
                return Ok(());
            }
        };
        let outputs = batch.outputs.len();
        let publication = match outcome(self.stores.buffer_commit(batch).await)? {
            Ok(publication) => publication,
            Err(error) => {
                reply.send_lossy(Err(error));
                return Ok(());
            }
        };
        self.commits.accepted = publication.checkpoint.clone();
        self.commits.pending_delivery_bytes = plan.pending_bytes;
        let (completion, token) = Completion::channel(|| Error::Closed);
        let pending = PendingCommit {
            publication,
            completion,
            delivery: plan.batch,
            delivery_bytes: plan.bytes,
            outputs,
            span: Span::current(),
        };
        reply.send_lossy(Ok(token));
        self.commits.state = match std::mem::take(&mut self.commits.state) {
            CommitState::Idle => {
                pending
                    .start_archives(
                        &mut self.stores,
                        &mut self.durability,
                        &self.metrics,
                        &*self.context,
                    )
                    .await?;
                CommitState::Archiving(pending)
            }
            CommitState::Archiving(current) => CommitState::ArchivingBuffered(current, pending),
            CommitState::Publishing(current) => {
                pending
                    .start_archives(
                        &mut self.stores,
                        &mut self.durability,
                        &self.metrics,
                        &*self.context,
                    )
                    .await?;
                CommitState::PublishingArchiving(current, pending)
            }
            _ => unreachable!("a non-full commit pipeline has a free slot"),
        };
        Ok(())
    }

    /// Advances the pipeline once a commit's finalized archives are durable.
    pub(super) async fn archives_synced(
        &mut self,
        result: Result<(), StorageError>,
    ) -> Result<(), Fatal> {
        result?;
        self.commits.state = match std::mem::take(&mut self.commits.state) {
            CommitState::Archiving(current) => {
                current
                    .start_checkpoint(
                        &mut self.stores,
                        &mut self.durability,
                        &self.metrics,
                        &*self.context,
                    )
                    .await?;
                CommitState::Publishing(current)
            }
            CommitState::ArchivingBuffered(current, next) => {
                current
                    .start_checkpoint(
                        &mut self.stores,
                        &mut self.durability,
                        &self.metrics,
                        &*self.context,
                    )
                    .await?;
                next.start_archives(
                    &mut self.stores,
                    &mut self.durability,
                    &self.metrics,
                    &*self.context,
                )
                .await?;
                CommitState::PublishingArchiving(current, next)
            }
            CommitState::PublishingArchiving(current, next) => {
                CommitState::PublishingArchived(current, next)
            }
            _ => unreachable!("archive completion requires an archiving commit"),
        };
        Ok(())
    }

    /// Finishes the oldest commit once its checkpoint is published, then runs owed cleanup.
    pub(super) async fn checkpoint_published(
        &mut self,
        result: Result<(), StorageError>,
    ) -> Result<(), Fatal> {
        result?;
        self.commits.state = match std::mem::take(&mut self.commits.state) {
            CommitState::Publishing(current) => {
                self.finish_commit(current)?;
                CommitState::Idle
            }
            CommitState::PublishingArchiving(current, next) => {
                self.finish_commit(current)?;
                CommitState::Archiving(next)
            }
            CommitState::PublishingArchived(current, next) => {
                self.finish_commit(current)?;
                next.start_checkpoint(
                    &mut self.stores,
                    &mut self.durability,
                    &self.metrics,
                    &*self.context,
                )
                .await?;
                CommitState::Publishing(next)
            }
            _ => unreachable!("checkpoint completion requires a publishing commit"),
        };
        if self.commits.commits_since_cleanup >= MAX_COMMITS_BEFORE_CLEANUP {
            self.cleanup().await?;
        }
        Ok(())
    }

    /// Records a published commit and hands its outputs to delivery and the promoter.
    fn finish_commit(&mut self, pending: PendingCommit<H, B>) -> Result<(), Fatal> {
        let PendingCommit {
            publication,
            completion,
            delivery,
            delivery_bytes,
            outputs,
            ..
        } = pending;
        self.commits.durable = publication.checkpoint.clone();
        match &mut self.commits.cleanup {
            Some(cleanup) => cleanup.coalesce(publication.cleanup),
            None => self.commits.cleanup = Some(publication.cleanup),
        }
        self.commits.commits_since_cleanup = self.commits.commits_since_cleanup.saturating_add(1);
        self.metrics.committed(outputs);
        self.update_progress_metrics();
        let promoter_closed = self.promoter.as_ref().is_some_and(|promoter| {
            let Some(committed) = publication.checkpoint.committed() else {
                return false;
            };
            let hot = delivery
                .as_ref()
                .into_iter()
                .flat_map(|batch| &batch.outputs)
                .filter_map(|output| match output {
                    DeliveryOutput::Hot(output) => Some(output.clone()),
                    DeliveryOutput::Descriptor(_) => None,
                })
                .collect();
            promoter.published(committed, hot) == Feedback::Closed
        });
        let delivery_closed =
            delivery.is_some_and(|batch| self.delivery.committed(batch) == Feedback::Closed);
        self.commits.pending_delivery_bytes = self
            .commits
            .pending_delivery_bytes
            .checked_sub(delivery_bytes)
            .expect("pending commits own their delivery-cache charge");
        completion.send_lossy(Ok(()));
        if delivery_closed {
            return Err(Fatal::DeliveryClosed);
        }
        if promoter_closed {
            return Err(Fatal::PromoterClosed);
        }
        Ok(())
    }

    /// Prunes the pending archives that published commits made obsolete.
    pub(super) async fn cleanup(&mut self) -> Result<(), Fatal> {
        let Some(cleanup) = self.commits.cleanup.take() else {
            return Ok(());
        };
        self.stores.cleanup_pending(cleanup).await?;
        self.commits.commits_since_cleanup = 0;
        Ok(())
    }
}
