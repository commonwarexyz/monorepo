//! The synchronization actor: recovers the durable cut, then serves synchronization, finality
//! hints and floor installations one pass at a time.

use super::{
    finality::FinalityHints,
    inbox::{Absorbed, DeferredSync, Idle, Inbox},
    mailbox::{Error, FinalityBatch, Mailbox, Message},
    ports::{CatalogPort, Fetcher},
};
use crate::{
    Viewable as _,
    multimmit::{
        marshal::{
            actors::metrics,
            config::Retention,
            protocol::{order::HistoryState, paths::PathCache},
            storage::scratch::{BlockStack, HistoryStack},
            types::{LqcVerifier, OutputIndex},
            wire::max_block_segment_items,
        },
        types::{BlockRef, Body, CertificateId, CodecConfig, TransactionBlockHeader},
    },
    types::{Epoch, View},
};
use commonware_actor::mailbox;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    cache::Cache,
    channel::fallible::OneshotExt as _,
    futures::{OptionFuture, Pool},
};
use std::{collections::BTreeMap, future::ready, marker::PhantomData, num::NonZeroUsize};
use tracing::{Instrument as _, Span, debug, debug_span, info_span};

/// Configuration for the synchronization actor.
pub(crate) struct Config<C, F, S, K, Q> {
    /// Catalog that holds the durable cut and receives commits.
    pub catalog: C,
    /// Fetches of history, headers and blocks missing from the catalog.
    pub fetcher: F,
    /// Scratch stack of tip-history records staged for one pass.
    pub history_stack: S,
    /// Scratch stack of producer references staged for one walk.
    pub block_stack: K,
    /// Verifier for floor anchors.
    pub verifier: Q,
    /// Decode bounds for the epoch.
    pub codec: CodecConfig,
    /// Capacity of the actor's mailbox.
    pub mailbox_size: NonZeroUsize,
    /// Maximum number of cached producer headers and forward paths.
    pub header_cache_capacity: NonZeroUsize,
    /// Maximum number of concurrent peer fetches.
    pub backfill_concurrency: NonZeroUsize,
    /// Maximum number of outputs, history openings or selected proofs in one commit.
    pub max_commit_outputs: NonZeroUsize,
    /// Encoded block bytes after which a commit starts.
    pub max_commit_block_bytes: NonZeroUsize,
    /// Maximum encoded size of one block.
    pub max_block_bytes: NonZeroUsize,
    /// Maximum size of one resolver value.
    pub max_value_bytes: NonZeroUsize,
}

/// Work and memory bounds derived from the configuration.
pub(super) struct SyncBounds {
    /// Maximum number of concurrent peer fetches.
    pub backfill_concurrency: usize,
    /// Maximum number of outputs, history openings or selected proofs in one commit.
    pub max_commit_outputs: usize,
    /// Encoded block bytes after which a commit starts.
    pub max_commit_block_bytes: u64,
    /// Maximum number of outputs in one catalog custody lookup.
    pub custody_batch_outputs: usize,
    /// Maximum number of blocks in one peer block fetch.
    pub max_fetch_blocks: usize,
    /// Maximum number of outputs in one custody window.
    pub custody_window_outputs: usize,
}

impl SyncBounds {
    fn new<C, F, S, K, Q>(config: &Config<C, F, S, K, Q>) -> Result<Self, Error> {
        let backfill_concurrency = config.backfill_concurrency.get();
        let max_commit_outputs = config.max_commit_outputs.get();
        let max_block_bytes = config.max_block_bytes.get();
        let max_fetch_blocks =
            max_block_segment_items(max_block_bytes, config.max_value_bytes.get());
        let custody_window_outputs = backfill_concurrency
            .checked_mul(max_fetch_blocks)
            .ok_or(Error::Invalid("custody window capacity overflow"))?;
        let custody_batch_outputs = max_commit_outputs
            .min((config.max_commit_block_bytes.get() / max_block_bytes).max(1))
            .min(custody_window_outputs);
        Ok(Self {
            backfill_concurrency,
            max_commit_outputs,
            max_commit_block_bytes: u64::try_from(config.max_commit_block_bytes.get())
                .unwrap_or(u64::MAX),
            custody_batch_outputs,
            max_fetch_blocks,
            custody_window_outputs,
        })
    }
}

/// Synchronization state of the running actor, which takes in its mailbox.
pub(super) type RunningCore<C, F, S, K, Q, H, V, B> =
    Core<Inbox<V, <H as Hasher>::Digest>, C, F, S, K, Q, H, V, B>;

/// Synchronization state, with the input `I` a pass takes in while it waits.
///
/// Recovery takes nothing in ([`Idle`]); the running actor takes in its mailbox ([`Inbox`]).
///
/// The durable cut is the catalog checkpoint. `floor`, `history_index`, `committed` and `state`
/// run ahead of it while a pass plans outputs, and each started commit carries them as its
/// checkpoint.
pub(super) struct Core<I, C, F, S, K, Q, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Input taken in while a pass waits.
    pub(super) inbox: I,
    pub(super) catalog: C,
    pub(super) fetcher: F,
    /// Tip-history records of the current pass, fetched newest first and opened oldest first.
    pub(super) history_stack: S,
    /// Producer references staged by the current walk for its custody window.
    pub(super) block_stack: K,
    /// Verifier for floor anchors.
    pub(super) verifier: Q,
    /// Authenticated producer headers, used as ancestry hints.
    pub(super) headers: Cache<BlockRef<H::Digest>, TransactionBlockHeader<H::Digest>>,
    /// Authenticated forward producer paths, used as ancestry hints.
    pub(super) commitments: PathCache<H::Digest>,
    /// Direct-pool finality facts waiting for their final sweep.
    pub(super) finality: FinalityHints<H::Digest>,
    pub(super) codec: CodecConfig,
    pub(super) bounds: SyncBounds,
    pub(super) epoch: Epoch,
    /// Generation of the installed floor; each floor installation increments it.
    pub(super) floor_generation: u64,
    pub(super) archive_layout: Retention,
    /// Identifier of the floor proof: the last selected or installed L-QC.
    pub(super) floor: CertificateId<H::Digest>,
    /// View of the floor proof. Finality at or below it is already synchronized.
    pub(super) floor_view: View,
    /// Index of the newest opened tip-history record, if any.
    pub(super) history_index: Option<u64>,
    /// Index of the newest planned output, if any.
    pub(super) committed: Option<OutputIndex>,
    /// Ordered and emitted frontiers with the active tip history.
    pub(super) state: HistoryState<H::Digest>,
    /// Durability of the started commits, in start order.
    pub(super) pending_commits: Pool<'static, Result<(), Error>>,
    pub(super) metrics: metrics::Synchronizer,
    _types: PhantomData<(V, B)>,
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) fn insert_header(&mut self, header: TransactionBlockHeader<H::Digest>) {
        self.headers.put(header.block_ref::<H>(), header);
    }

    /// Applies a hint taken in during a pass, returning the reference of a received header.
    pub(super) fn apply(&mut self, absorbed: Absorbed<H::Digest>) -> Option<BlockRef<H::Digest>> {
        match absorbed {
            Absorbed::Header(header) => {
                let reference = header.block_ref::<H>();
                self.headers.put(reference, header);
                Some(reference)
            }
            Absorbed::Commitments(commitments) => {
                self.commitments.insert(&commitments);
                None
            }
            Absorbed::Finality(fact) => {
                self.finality.retain(fact, self.floor_view);
                None
            }
        }
    }

    /// Replaces the input a pass takes in.
    fn with_inbox<J>(self, inbox: J) -> Core<J, C, F, S, K, Q, H, V, B> {
        let Self {
            inbox: _,
            catalog,
            fetcher,
            history_stack,
            block_stack,
            verifier,
            headers,
            commitments,
            finality,
            codec,
            bounds,
            epoch,
            floor_generation,
            archive_layout,
            floor,
            floor_view,
            history_index,
            committed,
            state,
            pending_commits,
            metrics,
            _types,
        } = self;
        Core {
            inbox,
            catalog,
            fetcher,
            history_stack,
            block_stack,
            verifier,
            headers,
            commitments,
            finality,
            codec,
            bounds,
            epoch,
            floor_generation,
            archive_layout,
            floor,
            floor_view,
            history_index,
            committed,
            state,
            pending_commits,
            metrics,
            _types,
        }
    }
}

impl<C, F, S, K, Q, H, V, B> Core<Idle, C, F, S, K, Q, H, V, B>
where
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Restores the durable cut and finishes synchronizing to the latest retained L-QC.
    pub(super) async fn recover(
        config: Config<C, F, S, K, Q>,
        metrics: metrics::Synchronizer,
    ) -> Result<Self, Error> {
        let bounds = SyncBounds::new(&config)?;
        let Config {
            mut catalog,
            fetcher,
            history_stack,
            block_stack,
            verifier,
            codec,
            header_cache_capacity,
            ..
        } = config;
        let checkpoint = catalog.checkpoint().await?;
        let state = HistoryState::new(
            checkpoint.history(),
            checkpoint.ordered().to_vec(),
            checkpoint.emitted().to_vec(),
        )?;
        let floor_view = catalog
            .lqc(checkpoint.floor())
            .await?
            .map_or_else(View::zero, |proof| proof.view());
        let mut this = Self {
            inbox: Idle,
            catalog,
            fetcher,
            history_stack,
            block_stack,
            verifier,
            headers: Cache::new(header_cache_capacity),
            commitments: PathCache::new(
                checkpoint.epoch(),
                codec.chains(),
                header_cache_capacity.get(),
            ),
            finality: FinalityHints::new(checkpoint.epoch(), codec),
            codec,
            bounds,
            epoch: checkpoint.epoch(),
            floor_generation: checkpoint.floor_generation(),
            archive_layout: checkpoint.archive_layout(),
            floor: checkpoint.floor(),
            floor_view,
            history_index: checkpoint.history_index(),
            committed: checkpoint.committed(),
            state,
            pending_commits: Pool::default(),
            metrics,
            _types: PhantomData,
        };
        if let Some(proof) = this.catalog.latest_lqc().await? {
            let id = proof.id::<H>();
            if id != this.floor {
                this.synchronize_proofs(BTreeMap::from([(id, proof)]))
                    .await?;
            }
        }
        this.finish_commits().await?;
        Ok(this)
    }

    /// Starts taking in `receiver`.
    pub(super) fn into_running(
        self,
        receiver: mailbox::Receiver<Message<V, H::Digest>>,
    ) -> RunningCore<C, F, S, K, Q, H, V, B> {
        self.with_inbox(Inbox::new(receiver))
    }
}

impl<C, F, S, K, Q, H, V, B> RunningCore<C, F, S, K, Q, H, V, B>
where
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Serves commands until the mailbox closes or `context` stops.
    ///
    /// Commands deferred behind a pass run before the mailbox is read again.
    pub(super) async fn run(mut self, context: &impl Spawner) -> Result<(), Error> {
        select_loop! {
            context,
            on_start => {
                if self.inbox.is_done() {
                    self.finish_commits().await?;
                    break;
                }
                let deferred = OptionFuture::from(self.inbox.next_deferred().map(ready));
            },
            on_stopped => {
                debug!("synchronizer stopped");
            },
            message = deferred => {
                self.handle(message).await?;
            },
            completion = self.pending_commits.next_completed() => {
                completion?;
            },
            Some(message) = self.inbox.recv() else continue => {
                self.handle(message).await?;
            },
        }
        Ok(())
    }

    async fn handle(&mut self, message: Message<V, H::Digest>) -> Result<(), Error> {
        match message {
            Message::Commitments { commitments } => self.commitments.insert(&commitments),
            Message::Header { span, header } => {
                let process = debug_span!(
                    parent: &span,
                    "multimmit.marshal.synchronizer.header",
                    chain = header.chain().get(),
                    height = header.height().get(),
                );
                process.in_scope(|| self.insert_header(header));
            }
            Message::Synchronize { span, batch } => self.synchronize(span, batch).await?,
            Message::Finality { span, fact } => {
                let process = info_span!(
                    parent: &span,
                    "multimmit.marshal.synchronizer.pool_finality",
                    view = fact.round().view().get(),
                    votes = fact.votes(),
                );
                self.finality.retain(fact, self.floor_view);
                self.synchronize_pending_finality()
                    .instrument(process)
                    .await?;
            }
            Message::InstallFloor {
                span,
                checkpoint,
                reply,
            } => {
                self.finality
                    .prepare(checkpoint.anchor.view(), self.floor_view);
                let process = info_span!(
                    parent: &span,
                    "multimmit.marshal.synchronizer.install_floor",
                );
                let result = self.install_floor(checkpoint).instrument(process).await;
                self.finality.finish(self.floor_view);
                let installed = result.is_ok();
                reply.send_lossy(result);
                if installed {
                    self.synchronize_pending_finality().await?;
                }
            }
        }
        Ok(())
    }

    /// Runs one synchronization pass to `batch`, merged with the targets already queued behind
    /// it up to the first queued floor install.
    async fn synchronize(
        &mut self,
        span: Span,
        batch: FinalityBatch<V, H::Digest>,
    ) -> Result<(), Error> {
        let mut sync = DeferredSync { span, batch };
        // Classify each drained hint against the pass view, which a merged target can raise, so a
        // fact for a view the pass covers lands in `pending` rather than being overwritten in
        // `future` by a later one.
        self.finality.prepare(sync.batch.view, self.floor_view);
        while let Some(hint) = self.inbox.drain(&mut sync)? {
            self.finality.prepare(sync.batch.view, self.floor_view);
            self.apply(hint);
        }
        let DeferredSync { span, batch } = sync;
        self.finality.prepare(batch.view, self.floor_view);
        let process = info_span!(
            parent: &span,
            "multimmit.marshal.synchronizer.finalize",
            view = batch.view.get(),
            proofs = batch.proofs.len(),
        );
        let result = self
            .synchronize_proofs(batch.proofs)
            .instrument(process)
            .await;
        self.finality.finish(self.floor_view);
        result?;
        self.synchronize_pending_finality().await
    }
}

/// Synchronizes finalized Multimmit targets into a durable, dense output prefix.
///
/// See the [module documentation](super) for the synchronization model.
pub(crate) struct Actor<E, C, F, S, K, Q, H, V, B>
where
    H: Hasher,
    V: Variant,
{
    context: ContextCell<E>,
    config: Config<C, F, S, K, Q>,
    receiver: mailbox::Receiver<Message<V, H::Digest>>,
    metrics: metrics::Synchronizer,
    _body: PhantomData<B>,
}

impl<E, C, F, S, K, Q, H, V, B> Actor<E, C, F, S, K, Q, H, V, B>
where
    E: Spawner + Metrics,
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Creates the actor and its mailbox.
    ///
    /// `context` is marshal's: the actor registers its metrics under `synchronizer`.
    pub(crate) fn new(context: &E, config: Config<C, F, S, K, Q>) -> (Self, Mailbox<V, H::Digest>) {
        let context = context.child("synchronizer");
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let metrics = metrics::Synchronizer::new(&context);
        // A pass keeps at most one same-view proof per mailbox slot.
        let max_proofs = config.mailbox_size.get();
        let mailbox = Mailbox::new(sender, max_proofs);
        let actor = Self {
            context: ContextCell::new(context),
            config,
            receiver,
            metrics,
            _body: PhantomData,
        };
        (actor, mailbox)
    }

    /// Starts the actor: recovers the durable cut, then serves the mailbox.
    pub(crate) fn start(mut self) -> Handle<Result<(), Error>> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) -> Result<(), Error> {
        Core::recover(self.config, self.metrics)
            .await?
            .into_running(self.receiver)
            .run(self.context.as_present())
            .await
    }
}
