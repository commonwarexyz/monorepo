//! Bounded synchronization actor for finalized Multimmit targets.
//!
//! The synchronizer turns authenticated leader finality into producer-chain walks and a dense
//! output stream. It batches local catalog lookups, walks missing producer ancestry concurrently,
//! and retains bodyless output plans until bounded checkpoint-last publication. Two publications
//! may be pipelined. Resolver requests are issued only for gaps established by local catalog
//! lookup.
//!
//! Custody work runs in a sliding byte-derived window shared by adjacent history openings. Local
//! lookup pages and exact fetches may finish out of order, but only the contiguous ready prefix of
//! the authenticated order advances ordering state. Lookahead is disposable: recovery
//! reconstructs it from the last durable catalog checkpoint.

use super::{
    catalog::{self, CatalogClient},
    metrics::{self, FetchReason},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::CodecConfig,
        marshal::{
            mailbox::FloorCheckpoint,
            protocol::{
                ancestry::{self, Ancestry},
                order::{self, HistoryState, Horizontal, OrderedSlots, Reconciliation},
            },
            storage::checkpoint::{ArchiveLayout, Checkpoint},
            types::OutputIndex,
            wire::MAX_SEGMENT_ITEMS,
        },
        types::{
            BlockRef, CertificateId, Lqc, TipRecord, TransactionBlockHeader,
        },
    },
    types::{Epoch, Height, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{cache::Clock, channel::oneshot, futures::Pool};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Display,
    future::Future,
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{Instrument as _, Span, info_span};

type CustodyValues<H> = Vec<Option<catalog::CustodyRef<<H as Hasher>::Digest>>>;

type MaybeLqc<V, D> = Option<Arc<Lqc<V, D>>>;
type SelectedLqcs<V, D> = Vec<(CertificateId<D>, Arc<Lqc<V, D>>)>;
type FinalityProofs<V, D> = BTreeMap<CertificateId<D>, Arc<Lqc<V, D>>>;
/// Coalesced exact history links shared across resolver subscribers.
pub(in crate::multimmit::marshal) type HistorySegment<D> = Arc<Vec<Arc<TipRecord<D>>>>;
/// Coalesced exact producer headers shared across resolver subscribers.
pub(in crate::multimmit::marshal) type HeaderSegment<D> = Arc<Vec<TransactionBlockHeader<D>>>;
type HeaderSegments<D> = Vec<Vec<TransactionBlockHeader<D>>>;
type ProducerFetch<H> = (
    usize,
    BlockRef<<H as Hasher>::Digest>,
    Result<HeaderSegment<<H as Hasher>::Digest>, Arc<str>>,
);
type CustodyLookup<H> = (usize, usize, Result<CustodyValues<H>, Arc<str>>);
type CustodyFetch<H> = (
    usize,
    BlockRef<<H as Hasher>::Digest>,
    Result<catalog::CustodyRef<<H as Hasher>::Digest>, Arc<str>>,
);
const COMMIT_WINDOW: usize = 2;
pub(in crate::multimmit::marshal) const CUSTODY_WINDOW_PAGES: usize = COMMIT_WINDOW;

/// A synchronization operation failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("synchronizer mailbox is closed")]
    Closed,
    #[error("catalog access failed: {0}")]
    Catalog(Arc<str>),
    #[error("exact fetch failed: {0}")]
    Fetch(Arc<str>),
    #[error("history scratch archive failed: {0}")]
    Stack(Arc<str>),
    #[error("LQC verification failed: {0}")]
    Verify(Arc<str>),
    #[error("invalid synchronization input: {0}")]
    Invalid(&'static str),
    #[error("dense output coordinate is exhausted")]
    OutputExhausted,
    #[error("floor generation is exhausted")]
    GenerationExhausted,
    #[error(transparent)]
    Order(#[from] order::Error),
    #[error(transparent)]
    Ancestry(#[from] ancestry::Error),
}

fn message(error: impl Display) -> Arc<str> {
    Arc::from(error.to_string())
}

/// Exact resolver operations used by synchronization.
///
/// Implementations validate the exact requested identity before resolving. Keeping this port
/// separate prevents resolver policy and dynamic dispatch from entering the ordering mechanism.
pub(in crate::multimmit::marshal) trait Fetcher<H, V, B>:
    Clone + Send + 'static
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Error: Display + Send + Sync + 'static;

    fn lqc(
        &mut self,
        reason: FetchReason,
        id: CertificateId<H::Digest>,
    ) -> impl Future<Output = Result<Arc<Lqc<V, H::Digest>>, Self::Error>> + Send;

    fn history(
        &mut self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> impl Future<Output = Result<HistorySegment<H::Digest>, Self::Error>> + Send;

    fn headers(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> impl Future<Output = Result<HeaderSegment<H::Digest>, Self::Error>> + Send;

    fn block(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> impl Future<Output = Result<catalog::CustodyRef<H::Digest>, Self::Error>> + Send;
}

/// One authenticated history link retained in scratch storage.
pub(in crate::multimmit::marshal) struct HistoryLink<H: Hasher> {
    pub commitment: H::Digest,
    pub record: Arc<TipRecord<H::Digest>>,
}

impl<H: Hasher> Clone for HistoryLink<H> {
    fn clone(&self) -> Self {
        Self {
            commitment: self.commitment,
            record: Arc::clone(&self.record),
        }
    }
}

/// Disk-backed scratch storage for an unbounded history walk.
///
/// After `reset`, pushes arrive newest-first. `read_reverse` returns them oldest-first and then
/// returns `None`. Implementations may discard read entries.
pub(in crate::multimmit::marshal) trait HistoryStack<H: Hasher>:
    Send + 'static
{
    type Error: Display + Send + Sync + 'static;

    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn push(
        &mut self,
        link: HistoryLink<H>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn read_reverse(
        &mut self,
    ) -> impl Future<Output = Result<Option<HistoryLink<H>>, Self::Error>> + Send;
}

/// Bounded scratch storage for unbounded producer-chain traversals.
///
/// Blocks are pushed in reverse canonical order and read oldest-first. Scratch contents are
/// non-authoritative ordering plans derived from authenticated ancestry and are discarded during
/// recovery.
pub(in crate::multimmit::marshal) trait BlockStack<D: Digest>:
    Send + 'static
{
    type Error: Display + Send + Sync + 'static;

    fn reset(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn push(&mut self, block: BlockRef<D>) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn read_oldest(
        &mut self,
        chain: usize,
    ) -> impl Future<Output = Result<Option<BlockRef<D>>, Self::Error>> + Send;
}

/// Cryptographic verification for peer-resolved L-QCs and externally supplied floor anchors.
pub trait LqcVerifier<H: Hasher, V: Variant>: Send + 'static {
    /// Verification failure returned for an invalid proof or unavailable verifier.
    type Error: Display + Send + Sync + 'static;

    /// Authenticates one externally resolved L-QC before marshal admits it.
    fn verify(
        &mut self,
        proof: &Lqc<V, H::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

trait CatalogPort<H, V, B>: Send + 'static
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Error: Display + Send + Sync + 'static;
    type CommitToken: Send + 'static;
    type Custody: CustodyPort<H>;

    fn custody(&self) -> Self::Custody;

    fn checkpoint(
        &mut self,
    ) -> impl Future<Output = Result<Checkpoint<H::Digest>, Self::Error>> + Send;
    fn latest_lqc(
        &mut self,
    ) -> impl Future<Output = Result<MaybeLqc<V, H::Digest>, Self::Error>> + Send;
    fn lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> impl Future<Output = Result<MaybeLqc<V, H::Digest>, Self::Error>> + Send;
    fn final_lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
    fn header_segments(
        &mut self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
    ) -> impl Future<Output = Result<HeaderSegments<H::Digest>, Self::Error>> + Send;
    fn start_commit(
        &mut self,
        batch: catalog::Commit<H, V>,
    ) -> impl Future<Output = Result<Self::CommitToken, Self::Error>> + Send;
    fn wait_commit(
        token: Self::CommitToken,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        prune: catalog::Prune,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Cloneable catalog capability used by concurrent custody lookups.
trait CustodyPort<H: Hasher>: Clone + Send + 'static {
    type Error: Display + Send + Sync + 'static;

    fn wait_for_custody(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> impl Future<Output = Result<CustodyValues<H>, Self::Error>> + Send;
}

impl<H, V, B> CustodyPort<H> for CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Error = catalog::Error;

    async fn wait_for_custody(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<CustodyValues<H>, Self::Error> {
        Self::wait_for_custody(self, references).await
    }
}

impl<H, V, B> CatalogPort<H, V, B> for CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Error = catalog::Error;
    type CommitToken = catalog::CommitToken;
    type Custody = Self;

    fn custody(&self) -> Self::Custody {
        self.clone()
    }

    async fn checkpoint(&mut self) -> Result<Checkpoint<H::Digest>, Self::Error> {
        Self::checkpoint(self).await
    }

    async fn latest_lqc(&mut self) -> Result<MaybeLqc<V, H::Digest>, Self::Error> {
        Self::latest_lqc(self).await
    }

    async fn lqc(
        &mut self,
        id: CertificateId<H::Digest>,
    ) -> Result<MaybeLqc<V, H::Digest>, Self::Error> {
        Self::lqc(self, id).await
    }

    async fn final_lqc(&mut self, id: CertificateId<H::Digest>) -> Result<bool, Self::Error> {
        Self::final_lqc(self, id).await
    }

    async fn header_segments(
        &mut self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
    ) -> Result<Vec<Vec<TransactionBlockHeader<H::Digest>>>, Self::Error> {
        Self::header_segments(self, requests, max_bytes).await
    }

    async fn start_commit(
        &mut self,
        batch: catalog::Commit<H, V>,
    ) -> Result<Self::CommitToken, Self::Error> {
        Self::start_commit(self, batch).await
    }

    async fn wait_commit(token: Self::CommitToken) -> Result<(), Self::Error> {
        token.wait().await
    }

    async fn install(
        &mut self,
        checkpoint: Checkpoint<H::Digest>,
        prune: catalog::Prune,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Self::Error> {
        Self::install(self, checkpoint, prune, proof, history).await
    }
}

type Reply = oneshot::Sender<Result<(), Error>>;

struct FinalityBatch<V: Variant, D: Digest> {
    view: View,
    proofs: FinalityProofs<V, D>,
    max_proofs: usize,
}

struct DeferredInput<V: Variant, D: Digest> {
    synchronize: Option<(Span, FinalityBatch<V, D>)>,
    floor: Option<(Span, FloorCheckpoint<V, D>, Reply)>,
    closed: bool,
}

impl<V: Variant, D: Digest> Default for DeferredInput<V, D> {
    fn default() -> Self {
        Self {
            synchronize: None,
            floor: None,
            closed: false,
        }
    }
}

impl<V: Variant, D: Digest> FinalityBatch<V, D> {
    fn new(id: CertificateId<D>, proof: Arc<Lqc<V, D>>, max_proofs: usize) -> Self {
        debug_assert!(max_proofs > 0);
        let view = proof.view();
        let mut proofs = BTreeMap::new();
        proofs.insert(id, proof);
        Self {
            view,
            proofs,
            max_proofs,
        }
    }

    fn merge(&mut self, next: Self) {
        match next.view.cmp(&self.view) {
            std::cmp::Ordering::Greater => {
                self.view = next.view;
                self.proofs = next.proofs;
            }
            std::cmp::Ordering::Equal => {
                for (id, proof) in next.proofs {
                    // Valid same-view LQCs are equivalent under the protocol fault assumption.
                    // Bound representations of impossible equivocation received as optional hints.
                    if self.proofs.len() == self.max_proofs && !self.proofs.contains_key(&id) {
                        break;
                    }
                    self.proofs.insert(id, proof);
                }
            }
            std::cmp::Ordering::Less => {}
        }
    }
}

enum Command<V: Variant, D: Digest> {
    Header(Span, TransactionBlockHeader<D>),
    Synchronize(Span, FinalityBatch<V, D>),
    InstallFloor(Span, FloorCheckpoint<V, D>, Reply),
}

impl<V: Variant, D: Digest> Policy for Command<V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) {
        overflow.retain(
            |command| !matches!(command, Self::InstallFloor(_, _, reply) if reply.is_closed()),
        );
        match command {
            // Header hints are optional acceleration. Dropping them under mailbox pressure
            // preserves space for finality and floor obligations, which have exact fallback.
            Self::Header(_, _) => {}
            Self::Synchronize(span, batch) => match overflow.back_mut() {
                Some(Self::Synchronize(_, pending)) => pending.merge(batch),
                _ => overflow.push_back(Self::Synchronize(span, batch)),
            },
            Self::InstallFloor(span, checkpoint, reply) => {
                if !reply.is_closed() {
                    overflow.push_back(Self::InstallFloor(span, checkpoint, reply));
                }
            }
        }
    }
}

/// Bounded command port for the synchronization actor.
pub(in crate::multimmit::marshal) struct Client<V: Variant, D: Digest> {
    commands: mailbox::Sender<Command<V, D>>,
    max_proofs: usize,
}

impl<V: Variant, D: Digest> Clone for Client<V, D> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            max_proofs: self.max_proofs,
        }
    }
}

impl<V: Variant, D: Digest> Client<V, D> {
    async fn request(&self, command: impl FnOnce(Reply) -> Command<V, D>) -> Result<(), Error> {
        let (reply, receiver) = oneshot::channel();
        if self.commands.enqueue(command(reply)) == Feedback::Closed {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    /// Enqueues a finalized target without waiting for resolution or durable publication.
    pub(in crate::multimmit::marshal) fn trigger(
        &self,
        id: CertificateId<D>,
        proof: Arc<Lqc<V, D>>,
    ) -> Result<(), Error> {
        match self
            .commands
            .enqueue(Command::Synchronize(Span::current(), FinalityBatch::new(
                id,
                proof,
                self.max_proofs,
            ))) {
            Feedback::Closed => Err(Error::Closed),
            Feedback::Ok | Feedback::Backoff => Ok(()),
        }
    }

    /// Offers one authenticated producer header as a non-authoritative ancestry hint.
    pub(in crate::multimmit::marshal) fn header(
        &self,
        header: TransactionBlockHeader<D>,
    ) -> Result<(), Error> {
        match self.commands.enqueue(Command::Header(Span::current(), header)) {
            Feedback::Closed => Err(Error::Closed),
            Feedback::Ok | Feedback::Backoff => Ok(()),
        }
    }

    pub(in crate::multimmit::marshal) async fn install_floor(
        &self,
        checkpoint: FloorCheckpoint<V, D>,
    ) -> Result<(), Error> {
        self.request(|reply| Command::InstallFloor(Span::current(), checkpoint, reply))
            .await
    }
}

struct VerifiedFloor<H: Hasher, V: Variant> {
    checkpoint: Checkpoint<H::Digest>,
    prune: catalog::Prune,
    proof: Arc<Lqc<V, H::Digest>>,
    history: Arc<TipRecord<H::Digest>>,
}

struct ProducerWalk<D: Digest> {
    ancestry: Ancestry<D>,
    stage_max: Option<Height>,
    emitted: Height,
    boundaries: Vec<BlockRef<D>>,
}

impl<D: Digest> ProducerWalk<D> {
    fn stages(&self, reference: BlockRef<D>) -> bool {
        self.stage_max
            .is_some_and(|maximum| reference.height() <= maximum)
            && reference.height() > self.emitted
    }
}

/// Dense output metadata accumulated across history openings before publication.
struct PlannedOutput<D: Digest> {
    index: OutputIndex,
    custody: catalog::CustodyRef<D>,
}

struct StagedOutput<D: Digest> {
    sequence: usize,
    slot: order::Slot<D>,
    reference: BlockRef<D>,
    custody: Option<catalog::CustodyRef<D>>,
}

/// Exact canonical order across a bounded oldest-first run of history openings.
struct HistoryOrder<D: Digest> {
    slots: VecDeque<order::Slot<D>>,
}

impl<D: Digest> HistoryOrder<D> {
    fn new<H: Hasher<Digest = D>>(
        base: &[BlockRef<D>],
        links: &[HistoryLink<H>],
    ) -> Result<Self, Error> {
        let mut base = base.to_vec();
        let mut slots = VecDeque::new();
        for link in links {
            slots.extend(Horizontal::new(&base, link.record.tips())?);
            base = link.record.tips().to_vec();
        }
        Ok(Self { slots })
    }
}

impl<D: Digest> Iterator for HistoryOrder<D> {
    type Item = order::Slot<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.slots.pop_front()
    }
}

impl<D: Digest> OrderedSlots<D> for HistoryOrder<D> {
    fn newest_first(&self) -> impl Iterator<Item = order::Slot<D>> + '_ {
        self.slots.iter().rev().copied()
    }
}

/// One bounded checkpoint-last publication assembled from compact ordering metadata.
struct PublicationBatch<H, V>
where
    H: Hasher,
    V: Variant,
{
    selected: SelectedLqcs<V, H::Digest>,
    history: Vec<catalog::HistoryOpening<H>>,
    outputs: Vec<PlannedOutput<H::Digest>>,
    output_bytes: u64,
}

impl<H, V> PublicationBatch<H, V>
where
    H: Hasher,
    V: Variant,
{
    fn new(max_outputs: usize, selected: usize) -> Self {
        Self {
            selected: Vec::with_capacity(selected.min(max_outputs)),
            history: Vec::with_capacity(max_outputs),
            outputs: Vec::with_capacity(max_outputs),
            output_bytes: 0,
        }
    }

    const fn is_empty(&self) -> bool {
        self.selected.is_empty() && self.history.is_empty() && self.outputs.is_empty()
    }
}

struct Synchronizer<C, F, S, K, Q, H, V, B>
where
    C: CatalogPort<H, V, B>,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    catalog: C,
    fetcher: F,
    history_stack: S,
    block_stack: K,
    headers: Clock<BlockRef<H::Digest>, TransactionBlockHeader<H::Digest>>,
    verifier: Q,
    codec: CodecConfig,
    backfill_concurrency: usize,
    max_commit_outputs: usize,
    max_commit_block_bytes: u64,
    custody_batch_outputs: usize,
    custody_window_outputs: usize,
    epoch: Epoch,
    generation: u64,
    archive_layout: ArchiveLayout,
    floor: CertificateId<H::Digest>,
    floor_view: View,
    history_index: Option<u64>,
    committed: Option<OutputIndex>,
    state: HistoryState<H::Digest>,
    commands: Option<mailbox::Receiver<Command<V, H::Digest>>>,
    deferred: DeferredInput<V, H::Digest>,
    pending_commits: Pool<Result<(), Error>>,
    metrics: Option<metrics::Synchronizer>,
    _types: PhantomData<(V, B)>,
}

impl<C, F, S, K, Q, H, V, B> Synchronizer<C, F, S, K, Q, H, V, B>
where
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    #[allow(clippy::too_many_arguments)]
    async fn recover(
        mut catalog: C,
        fetcher: F,
        history_stack: S,
        block_stack: K,
        header_cache_capacity: NonZeroUsize,
        verifier: Q,
        codec: CodecConfig,
        backfill_concurrency: usize,
        max_commit_outputs: usize,
        max_commit_block_bytes: NonZeroUsize,
        max_resolved_block_bytes: NonZeroUsize,
        metrics: Option<metrics::Synchronizer>,
    ) -> Result<Self, Error> {
        let checkpoint = catalog
            .checkpoint()
            .await
            .map_err(|error| Error::Catalog(message(error)))?;
        let state = HistoryState::new(
            checkpoint.history(),
            checkpoint.ordered().to_vec(),
            checkpoint.emitted().to_vec(),
        )?;
        let floor_view = catalog
            .lqc(checkpoint.floor())
            .await
            .map_err(|error| Error::Catalog(message(error)))?
            .map_or_else(View::zero, |proof| proof.view());
        let custody_batch_outputs = max_commit_outputs.min(
            (max_commit_block_bytes.get() / max_resolved_block_bytes.get()).max(1),
        );
        let mut this = Self {
            catalog,
            fetcher,
            history_stack,
            block_stack,
            headers: Clock::new(header_cache_capacity),
            verifier,
            codec,
            backfill_concurrency,
            max_commit_outputs,
            max_commit_block_bytes: u64::try_from(max_commit_block_bytes.get()).unwrap_or(u64::MAX),
            custody_batch_outputs,
            custody_window_outputs: max_commit_outputs.min(
                custody_batch_outputs.saturating_mul(COMMIT_WINDOW),
            ),
            epoch: checkpoint.epoch(),
            generation: checkpoint.generation(),
            archive_layout: checkpoint.archive_layout(),
            floor: checkpoint.floor(),
            floor_view,
            history_index: checkpoint.history_index(),
            committed: checkpoint.committed(),
            state,
            commands: None,
            deferred: DeferredInput::default(),
            pending_commits: Pool::default(),
            metrics,
            _types: PhantomData,
        };
        if let Some(proof) = this
            .catalog
            .latest_lqc()
            .await
            .map_err(|error| Error::Catalog(message(error)))?
        {
            let id = proof.id::<H>();
            this.synchronize(id).await?;
        }
        this.finish_commits().await?;
        Ok(this)
    }

    async fn run(
        mut self,
        commands: mailbox::Receiver<Command<V, H::Digest>>,
    ) -> Result<(), Error> {
        self.commands = Some(commands);
        loop {
            let command = if let Some((span, batch)) = self.deferred.synchronize.take() {
                Command::Synchronize(span, batch)
            } else if let Some((span, checkpoint, reply)) = self.deferred.floor.take() {
                Command::InstallFloor(span, checkpoint, reply)
            } else if self.deferred.closed {
                self.finish_commits().await?;
                return Ok(());
            } else {
                let Some(command) = self.next_command().await? else {
                    self.finish_commits().await?;
                    return Ok(());
                };
                command
            };
            match command {
                Command::Header(span, header) => {
                    let process = info_span!(
                        parent: &span,
                        "multimmit.marshal.synchronizer.header",
                        chain = header.chain().get(),
                        height = header.height().get(),
                    );
                    process.in_scope(|| self.insert_header(header));
                }
                Command::Synchronize(span, mut batch) => {
                    while let Ok(command) = self
                        .commands
                        .as_mut()
                        .expect("a running synchronizer owns its mailbox")
                        .try_recv()
                    {
                        match command {
                            Command::Header(_, header) => self.insert_header(header),
                            Command::Synchronize(next_span, next) => {
                                if let Some(id) = next_span.id() {
                                    span.follows_from(id);
                                }
                                batch.merge(next);
                            }
                            Command::InstallFloor(floor_span, checkpoint, reply) => {
                                self.deferred.floor = Some((floor_span, checkpoint, reply));
                                break;
                            }
                        }
                    }
                    let process = info_span!(
                        parent: &span,
                        "multimmit.marshal.synchronizer.finalize",
                        view = batch.view.get(),
                        proofs = batch.proofs.len(),
                    );
                    self.synchronize_proofs(batch.proofs)
                        .instrument(process)
                        .await?;
                }
                Command::InstallFloor(span, checkpoint, reply) => {
                    let process = info_span!(
                        parent: &span,
                        "multimmit.marshal.synchronizer.install_floor",
                    );
                    let result = self.install_floor(checkpoint).instrument(process).await;
                    drop(reply.send(result));
                }
            }
        }
    }

    async fn next_command(&mut self) -> Result<Option<Command<V, H::Digest>>, Error> {
        loop {
            if self.pending_commits.is_empty() {
                return Ok(self
                    .commands
                    .as_mut()
                    .expect("a running synchronizer owns its mailbox")
                    .recv()
                    .await);
            }
            let commands = self
                .commands
                .as_mut()
                .expect("a running synchronizer owns its mailbox");
            commonware_macros::select! {
                completion = self.pending_commits.next_completed() => {
                    completion?;
                },
                command = commands.recv() => return Ok(command),
            }
        }
    }

    fn defer_command(&mut self, command: Command<V, H::Digest>) -> Result<(), Error> {
        match command {
            Command::Header(_, header) => self.insert_header(header),
            Command::Synchronize(span, batch) => match &mut self.deferred.synchronize {
                Some((pending_span, pending)) => {
                    if let Some(id) = span.id() {
                        pending_span.follows_from(id);
                    }
                    pending.merge(batch);
                }
                None => self.deferred.synchronize = Some((span, batch)),
            },
            Command::InstallFloor(span, checkpoint, reply) => {
                if self
                    .deferred
                    .floor
                    .replace((span, checkpoint, reply))
                    .is_some()
                {
                    return Err(Error::Invalid("multiple floor barriers were deferred"));
                }
            }
        }
        Ok(())
    }

    async fn wait_for_commit_slot(&mut self) -> Result<(), Error> {
        while self.pending_commits.len() >= COMMIT_WINDOW {
            if self.commands.is_none() || self.deferred.floor.is_some() || self.deferred.closed {
                self.finish_commit().await?;
                continue;
            }
            let commands = self
                .commands
                .as_mut()
                .expect("a running synchronizer owns its mailbox");
            commonware_macros::select! {
                completion = self.pending_commits.next_completed() => {
                    completion?;
                },
                command = commands.recv() => match command {
                    Some(command) => self.defer_command(command)?,
                    None => self.deferred.closed = true,
                },
            }
        }
        Ok(())
    }

    fn insert_header(&mut self, header: TransactionBlockHeader<H::Digest>) {
        self.headers.put(header.block_ref::<H>(), header);
    }

    async fn synchronize(&mut self, id: CertificateId<H::Digest>) -> Result<(), Error> {
        if id == self.floor {
            return Ok(());
        }
        let proof = self
            .fetcher
            .lqc(FetchReason::Finality, id)
            .await
            .map_err(|error| Error::Fetch(message(error)))?;
        self.synchronize_proofs(BTreeMap::from([(id, proof)])).await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.resolve_finality",
        level = "info",
        skip_all,
        fields(proofs = proofs.len())
    )]
    async fn synchronize_proofs(
        &mut self,
        proofs: FinalityProofs<V, H::Digest>,
    ) -> Result<(), Error> {
        let Some(view) = proofs.values().next().map(|proof| proof.view()) else {
            return Ok(());
        };
        if proofs.iter().any(|(id, proof)| {
            proof.id::<H>() != *id || proof.epoch() != self.epoch || proof.view() != view
        }) {
            return Err(Error::Invalid("LQC identity, epoch, or view mismatch"));
        }
        if view < self.floor_view {
            return Ok(());
        }
        let mut proofs = proofs.into_iter().collect::<Vec<_>>();
        if view == self.floor_view {
            let mut retained = Vec::with_capacity(proofs.len());
            for (id, proof) in proofs {
                if id != self.floor
                    && !self
                        .catalog
                        .final_lqc(id)
                        .await
                        .map_err(|error| Error::Catalog(message(error)))?
                {
                    retained.push((id, proof));
                }
            }
            proofs = retained;
        }
        let Some(history_commitment) = proofs.first().map(|(_, proof)| proof.leader().history())
        else {
            return Ok(());
        };
        if proofs
            .iter()
            .any(|(_, proof)| proof.leader().history() != history_commitment)
        {
            return Err(Error::Invalid(
                "same-view LQCs do not commit to one history",
            ));
        }
        self.history_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))?;
        let mut cursor = history_commitment;
        while cursor != self.state.history() {
            let records = self
                .fetcher
                .history(FetchReason::Finality, view, cursor)
                .await
                .map_err(|error| Error::Fetch(message(error)))?;
            if records.is_empty() {
                return Err(Error::Invalid("history response is empty"));
            }
            for record in records.iter() {
                if cursor == self.state.history() {
                    break;
                }
                if record.commitment::<H>() != cursor {
                    return Err(Error::Invalid("history response does not match commitment"));
                }
                self.history_stack
                    .push(HistoryLink {
                        commitment: cursor,
                        record: Arc::clone(record),
                    })
                    .await
                    .map_err(|error| Error::Stack(message(error)))?;
                cursor = record.parent();
            }
        }
        let mut batch = PublicationBatch::<H, V>::new(self.max_commit_outputs, proofs.len());
        let mut next = self
            .history_stack
            .read_reverse()
            .await
            .map_err(|error| Error::Stack(message(error)))?;
        while let Some(first) = next.take() {
            let (links, pending) = self.read_history_window(first).await?;
            next = pending;
            if links.len() > 1 {
                self.process_history_window(links, &mut batch).await?;
            } else {
                for link in links {
                    self.process_opening(link, &mut batch).await?;
                }
            }
        }
        self.history_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))?;

        for (id, proof) in proofs {
            let preview = HistoryState::new(
                self.state.history(),
                self.state.ordered().to_vec(),
                self.state.ordered().to_vec(),
            )?;
            let mut preview_sweep =
                preview.final_sweep::<H, V>(&proof, self.codec, self.state.ordered())?;
            let target = preview_sweep.target().to_vec();
            let emitted = self.state.emitted().to_vec();
            let common = self.stage(&preview_sweep, &target, &emitted).await?;
            self.state.validate_reconciliation(&target, &common)?;
            self.drive_staged(&mut preview_sweep, &emitted, &mut batch)
                .await?;
            batch.selected.push((id, proof));
            if batch.selected.len() == self.max_commit_outputs {
                self.commit_pending(&mut batch).await?;
            }
        }
        self.commit_pending(&mut batch).await?;
        self.block_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))?;
        Ok(())
    }

    /// Collects the largest oldest-first prefix whose custody metadata fits in one memory window.
    /// An individual oversized opening remains valid but bypasses speculative lookahead.
    async fn read_history_window(
        &mut self,
        first: HistoryLink<H>,
    ) -> Result<(Vec<HistoryLink<H>>, Option<HistoryLink<H>>), Error> {
        let output_limit = u64::try_from(self.custody_window_outputs).unwrap_or(u64::MAX);
        let mut history = self.state.history();
        let mut ordered = self.state.ordered().to_vec();
        let mut outputs = 0u64;
        let mut links = Vec::with_capacity(self.max_commit_outputs);
        let mut current = Some(first);

        while let Some(link) = current.take() {
            if link.record.parent() != history || link.record.commitment::<H>() != link.commitment {
                return Err(Error::Invalid(
                    "tip-history opening does not extend its recovery window",
                ));
            }
            let opening_outputs = Self::opening_output_count(&ordered, link.record.tips())?;
            let window_outputs = outputs
                .checked_add(opening_outputs)
                .ok_or(Error::OutputExhausted)?;
            if !links.is_empty() && window_outputs > output_limit {
                return Ok((links, Some(link)));
            }

            history = link.commitment;
            ordered = link.record.tips().to_vec();
            outputs = window_outputs;
            links.push(link);
            if outputs > output_limit || links.len() == self.max_commit_outputs {
                let pending = self
                    .history_stack
                    .read_reverse()
                    .await
                    .map_err(|error| Error::Stack(message(error)))?;
                return Ok((links, pending));
            }
            current = self
                .history_stack
                .read_reverse()
                .await
                .map_err(|error| Error::Stack(message(error)))?;
        }
        Ok((links, None))
    }

    fn opening_output_count(
        base: &[BlockRef<H::Digest>],
        target: &[BlockRef<H::Digest>],
    ) -> Result<u64, Error> {
        drop(Horizontal::new(base, target)?);
        base.iter().zip(target).try_fold(0u64, |total, (base, target)| {
            total
                .checked_add(target.height().get() - base.height().get())
                .ok_or(Error::OutputExhausted)
        })
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.open_history_window",
        level = "info",
        skip_all,
        fields(openings = links.len())
    )]
    async fn process_history_window(
        &mut self,
        links: Vec<HistoryLink<H>>,
        batch: &mut PublicationBatch<H, V>,
    ) -> Result<(), Error> {
        let emitted = self.state.emitted().to_vec();
        let mut stream = HistoryOrder::new(self.state.ordered(), &links)?;
        let future_emitted = self.stage_history_window(&links, &emitted).await?;

        // Validate every opening before the first output mutates ordering state. The single
        // ancestry walk proves each opening tip lies on the future emitted frontier.
        let mut preview = HistoryState::new(
            self.state.history(),
            self.state.ordered().to_vec(),
            future_emitted,
        )?;
        for link in &links {
            preview.validate_opening::<H>(
                link.commitment,
                &link.record,
                link.record.tips(),
            )?;
            preview.finish_opening::<H>(link.commitment, &link.record)?;
        }

        self.drive_staged(&mut stream, &emitted, batch).await?;
        for link in links {
            self.record_opening(link, batch).await?;
        }
        self.block_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))
    }

    /// Authenticates all producer frontiers in a bounded history window with one ancestry walk.
    async fn stage_history_window(
        &mut self,
        links: &[HistoryLink<H>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let targets = links
            .last()
            .ok_or(Error::Invalid("history window is empty"))?
            .record
            .tips();
        let first = links
            .first()
            .expect("a history window with a last link has a first link")
            .record
            .tips();
        let ordered = self.state.ordered().to_vec();
        if targets.len() != emitted.len()
            || targets.len() != ordered.len()
            || targets.len() != first.len()
        {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        self.block_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))?;

        let mut future_emitted = Vec::with_capacity(targets.len());
        let mut walks = Vec::with_capacity(targets.len());
        let mut expected_common = Vec::with_capacity(targets.len());
        for (chain, (((target, first), emitted), ordered)) in targets
            .iter()
            .zip(first)
            .zip(emitted)
            .zip(&ordered)
            .enumerate()
        {
            let high = match target.height().cmp(&emitted.height()) {
                std::cmp::Ordering::Greater => *target,
                std::cmp::Ordering::Less => *emitted,
                std::cmp::Ordering::Equal if target == emitted => *target,
                std::cmp::Ordering::Equal => {
                    return Err(Error::Invalid(
                        "history target conflicts with the emitted frontier",
                    ));
                }
            };
            let low = match first.height().cmp(&emitted.height()) {
                std::cmp::Ordering::Less => *first,
                std::cmp::Ordering::Greater => *emitted,
                std::cmp::Ordering::Equal if first == emitted => *first,
                std::cmp::Ordering::Equal => {
                    return Err(Error::Invalid(
                        "first history target conflicts with the emitted frontier",
                    ));
                }
            };
            if low.height() < ordered.height() {
                return Err(Error::Invalid(
                    "history window precedes the ordering frontier",
                ));
            }
            let ancestry = Ancestry::common(high, low)?;
            let mut boundaries = Vec::with_capacity(links.len() + 1);
            for reference in links
                .iter()
                .map(|link| link.record.tips()[chain])
                .chain(std::iter::once(*emitted))
            {
                if reference == low {
                    continue;
                }
                if reference.height() <= low.height() {
                    return Err(Error::Invalid(
                        "history boundary precedes the recovery interval",
                    ));
                }
                boundaries.push(reference);
            }
            boundaries.sort_unstable_by_key(|reference| reference.height());
            if boundaries.windows(2).any(|pair| {
                pair[0].height() == pair[1].height() && pair[0] != pair[1]
            }) {
                return Err(Error::Invalid(
                    "history boundaries conflict at one producer height",
                ));
            }
            boundaries.dedup_by_key(|reference| reference.height());
            future_emitted.push(high);
            expected_common.push(low);
            walks.push(ProducerWalk {
                ancestry,
                stage_max: (target.height() > emitted.height()).then_some(target.height()),
                emitted: emitted.height(),
                boundaries,
            });
        }
        let common = self.walk_producers(walks, FetchReason::Finality).await?;
        if common != expected_common {
            return Err(Error::Invalid(
                "history window does not descend to its recovery frontier",
            ));
        }
        Ok(future_emitted)
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.open_history",
        level = "info",
        skip_all,
        fields(tips = link.record.tips().len())
    )]
    async fn process_opening(
        &mut self,
        link: HistoryLink<H>,
        batch: &mut PublicationBatch<H, V>,
    ) -> Result<(), Error> {
        let emitted = self.state.emitted().to_vec();
        let mut stream = Horizontal::new(self.state.ordered(), link.record.tips())?;
        let common = self.stage(&stream, link.record.tips(), &emitted).await?;
        self.state
            .validate_opening::<H>(link.commitment, &link.record, &common)?;
        self.drive_staged(&mut stream, &emitted, batch).await?;
        self.record_opening(link, batch).await?;
        self.block_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))
    }

    /// Advances the authenticated history frontier and queues its durable catalog row.
    async fn record_opening(
        &mut self,
        link: HistoryLink<H>,
        batch: &mut PublicationBatch<H, V>,
    ) -> Result<(), Error> {
        self.state
            .finish_opening::<H>(link.commitment, &link.record)?;
        self.history_index = Some(match self.history_index {
            Some(index) => index.checked_add(1).ok_or(Error::GenerationExhausted)?,
            None => 0,
        });
        batch.history.push(catalog::HistoryOpening {
            commitment: link.commitment,
            record: link.record,
        });
        if batch.history.len() == self.max_commit_outputs {
            self.commit_pending(batch).await?;
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.stage_ancestry",
        level = "info",
        skip_all,
        fields(chains = targets.len())
    )]
    async fn stage<I>(
        &mut self,
        stream: &I,
        targets: &[BlockRef<H::Digest>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<Vec<BlockRef<H::Digest>>, Error>
    where
        I: OrderedSlots<H::Digest>,
    {
        if targets.len() != emitted.len() {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        self.block_stack
            .reset()
            .await
            .map_err(|error| Error::Stack(message(error)))?;
        let mut stage_max = vec![None; targets.len()];
        for slot in stream.newest_first() {
            let chain = slot.tip().chain().get() as usize;
            let target = targets
                .get(chain)
                .ok_or(Error::Invalid("slot chain is outside the frontier"))?;
            let frontier = emitted
                .get(chain)
                .ok_or(Error::Invalid("slot chain is outside the frontier"))?;
            if slot.tip().chain() != target.chain() || slot.height() > target.height() {
                return Err(Error::Invalid("ordering slot is outside resolved ancestry"));
            }
            if slot.height() <= frontier.height() {
                continue;
            }
            stage_max[chain] = Some(
                stage_max[chain].map_or(slot.height(), |height: Height| height.max(slot.height())),
            );
        }
        let walks = targets
            .iter()
            .zip(emitted)
            .enumerate()
            .map(|(chain, (target, emitted))| {
                Ancestry::common(*target, *emitted).map(|ancestry| ProducerWalk {
                    ancestry,
                    stage_max: stage_max[chain],
                    emitted: emitted.height(),
                    boundaries: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, ancestry::Error>>()?;
        self.walk_producers(walks, FetchReason::Finality).await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.walk_producers",
        level = "info",
        skip_all,
        fields(chains = walks.len(), reason = ?reason)
    )]
    async fn walk_producers(
        &mut self,
        mut walks: Vec<ProducerWalk<H::Digest>>,
        reason: FetchReason,
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let mut ready = walks
            .iter()
            .enumerate()
            .filter_map(|(chain, walk)| walk.ancestry.next().map(|_| chain))
            .collect::<VecDeque<_>>();
        let mut fetches: Pool<ProducerFetch<H>> = Pool::default();
        let mut completed_fetches = Vec::with_capacity(self.backfill_concurrency);
        while !ready.is_empty() || !fetches.is_empty() {
            let available = self.backfill_concurrency.saturating_sub(fetches.len());
            if available > 0 && !ready.is_empty() {
                let mut scheduled = Vec::with_capacity(available.min(ready.len()));
                while scheduled.len() < available {
                    let Some(chain) = ready.pop_front() else {
                        break;
                    };
                    let request = walks[chain]
                        .ancestry
                        .next()
                        .ok_or(Error::Invalid("scheduled producer walk is complete"))?;
                    if let Some(header) = self.headers.get(&request).cloned() {
                        self.accept_producer_header(&mut walks, chain, request, &header)
                            .await?;
                        if walks[chain].ancestry.next().is_some() {
                            ready.push_back(chain);
                        }
                        continue;
                    }
                    scheduled.push((
                        chain,
                        request,
                        walks[chain].ancestry.remaining().min(MAX_SEGMENT_ITEMS),
                    ));
                }
                if scheduled.is_empty() {
                    continue;
                }
                let local = {
                    let mut local = Box::pin(
                        self.catalog.header_segments(
                            scheduled
                                .iter()
                                .map(|(_, request, max_items)| (*request, *max_items))
                                .collect(),
                            usize::MAX,
                        ),
                    );
                    loop {
                        if fetches.is_empty() {
                            break local.await;
                        }
                        commonware_macros::select! {
                            fetched = fetches.next_completed() => completed_fetches.push(fetched),
                            result = &mut local => break result,
                        };
                    }
                };
                let local = local.map_err(|error| Error::Catalog(message(error)))?;
                for (chain, request, result) in completed_fetches.drain(..) {
                    self.accept_producer_headers(
                        &mut walks,
                        &mut ready,
                        chain,
                        request,
                        result.map_err(Error::Fetch)?.as_slice(),
                    )
                    .await?;
                }
                if local.len() != scheduled.len() {
                    return Err(Error::Invalid("catalog header batch cardinality mismatch"));
                }
                for ((chain, request, _), headers) in scheduled.into_iter().zip(local) {
                    if !headers.is_empty() {
                        self.accept_producer_headers(
                            &mut walks, &mut ready, chain, request, &headers,
                        )
                        .await?;
                        continue;
                    }
                    let mut fetcher = self.fetcher.clone();
                    fetches.push(async move {
                        let result = fetcher.headers(reason, request).await.map_err(message);
                        (chain, request, result)
                    });
                }
                continue;
            }

            let (chain, request, result) = fetches.next_completed().await;
            self.accept_producer_headers(
                &mut walks,
                &mut ready,
                chain,
                request,
                result.map_err(Error::Fetch)?.as_slice(),
            )
            .await?;
        }

        walks
            .into_iter()
            .map(|walk| {
                if !walk.boundaries.is_empty() {
                    return Err(Error::Invalid(
                        "producer ancestry did not reach every history boundary",
                    ));
                }
                walk.ancestry
                    .finish()
                    .ok_or(Error::Invalid("common-frontier walk did not finish"))
            })
            .collect()
    }

    async fn accept_producer_headers(
        &mut self,
        walks: &mut [ProducerWalk<H::Digest>],
        ready: &mut VecDeque<usize>,
        chain: usize,
        request: BlockRef<H::Digest>,
        headers: &[TransactionBlockHeader<H::Digest>],
    ) -> Result<(), Error> {
        if headers.is_empty() {
            return Err(Error::Invalid("resolved producer header segment is empty"));
        }
        let mut expected = request;
        for header in headers {
            if walks[chain].ancestry.next().is_none() {
                break;
            }
            self.accept_producer_header(walks, chain, expected, header)
                .await?;
            expected = BlockRef::new(
                expected.chain(),
                Height::new(expected.height().get().saturating_sub(1)),
                header.parent(),
            );
            self.insert_header(header.clone());
        }
        if walks[chain].ancestry.next().is_some() {
            ready.push_back(chain);
        }
        Ok(())
    }

    async fn accept_producer_header(
        &mut self,
        walks: &mut [ProducerWalk<H::Digest>],
        chain: usize,
        request: BlockRef<H::Digest>,
        header: &TransactionBlockHeader<H::Digest>,
    ) -> Result<(), Error> {
        let walk = walks.get_mut(chain).ok_or(Error::Invalid(
            "completed producer chain is outside the frontier",
        ))?;
        if walk
            .boundaries
            .last()
            .is_some_and(|boundary| boundary.height() == request.height())
        {
            let boundary = walk
                .boundaries
                .pop()
                .expect("a matching history boundary is present");
            if boundary != request {
                return Err(Error::Invalid(
                    "producer ancestry conflicts with a history boundary",
                ));
            }
        }
        walk.ancestry.accept::<H>(self.epoch, header)?;
        if walk.stages(request) {
            self.block_stack
                .push(request)
                .await
                .map_err(|error| Error::Stack(message(error)))?;
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.resolve_custody",
        level = "info",
        skip_all,
        fields(window = self.custody_window_outputs, batch = self.custody_batch_outputs)
    )]
    async fn drive_staged<I>(
        &mut self,
        stream: &mut I,
        initially_emitted: &[BlockRef<H::Digest>],
        batch: &mut PublicationBatch<H, V>,
    ) -> Result<(), Error>
    where
        I: OrderedSlots<H::Digest>,
    {
        let mut staged = VecDeque::with_capacity(self.custody_window_outputs);
        let mut lookups = Pool::default();
        let mut missing = VecDeque::new();
        let mut fetches = Pool::default();
        let mut next_sequence = 0usize;
        let mut unscheduled = 0usize;
        let mut stream_finished = false;
        let mut ready = 0usize;
        let mut blocked = false;
        if let Some(metrics) = &self.metrics {
            metrics.windows.inc();
        }

        loop {
            let mut planned = 0usize;
            while staged.len() < self.custody_window_outputs && !stream_finished {
                let Some((slot, reference)) = self
                    .next_staged(stream, initially_emitted)
                    .await?
                else {
                    stream_finished = true;
                    break;
                };
                staged.push_back(StagedOutput {
                    sequence: next_sequence,
                    slot,
                    reference,
                    custody: None,
                });
                next_sequence = next_sequence.checked_add(1).ok_or(Error::OutputExhausted)?;
                unscheduled += 1;
                planned += 1;
            }
            if let Some(metrics) = &self.metrics {
                metrics
                    .planned_outputs
                    .inc_by(u64::try_from(planned).unwrap_or(u64::MAX));
            }

            while unscheduled >= self.custody_batch_outputs || (stream_finished && unscheduled > 0)
            {
                let count = unscheduled.min(self.custody_batch_outputs);
                let start = next_sequence - unscheduled;
                let references = self.staged_references(&staged, start, count)?;
                let catalog = self.catalog.custody();
                lookups.push(async move {
                    let result = catalog.wait_for_custody(references).await.map_err(message);
                    (start, count, result)
                });
                unscheduled -= count;
            }

            while fetches.len() < self.backfill_concurrency {
                let Some((sequence, reference)) = missing.pop_front() else {
                    break;
                };
                let mut fetcher = self.fetcher.clone();
                fetches.push(async move {
                    let result = fetcher
                        .block(FetchReason::FinalizedBody, reference)
                        .await
                        .map_err(message);
                    (sequence, reference, result)
                });
            }

            let mut emitted = false;
            while staged
                .front()
                .is_some_and(|output| output.custody.is_some())
            {
                let output = staged
                    .pop_front()
                    .expect("a ready staged output is available");
                let custody = output
                    .custody
                    .expect("a ready staged output owns exact custody");
                let slot = output.slot;
                self.emit_output(slot, custody, batch).await?;
                ready -= 1;
                emitted = true;
            }
            if emitted {
                blocked = false;
                continue;
            }
            if stream_finished && staged.is_empty() {
                break;
            }
            if lookups.is_empty() && fetches.is_empty() && missing.is_empty() && unscheduled == 0 {
                return Err(Error::Invalid("planned output custody is missing"));
            }
            if ready > 0 && !blocked {
                if let Some(metrics) = &self.metrics {
                    metrics.blocked_prefixes.inc();
                }
                blocked = true;
            }
            if let Some(metrics) = &self.metrics {
                metrics.pressure(lookups.len(), fetches.len(), ready);
            }

            commonware_macros::select! {
                lookup = lookups.next_completed() => {
                    let local = self.apply_custody_lookup(
                        lookup,
                        &mut staged,
                        &mut missing,
                    )?;
                    ready += local;
                    if let Some(metrics) = &self.metrics {
                        metrics
                            .local_outputs
                            .inc_by(u64::try_from(local).unwrap_or(u64::MAX));
                    }
                },
                fetch = fetches.next_completed() => {
                    let (sequence, reference, result): CustodyFetch<H> = fetch;
                    let custody = result.map_err(Error::Fetch)?;
                    if self.validate_custody(&custody)? != reference {
                        return Err(Error::Invalid(
                            "resolved output custody does not match its request",
                        ));
                    }
                    self.staged_mut(&mut staged, sequence)?.custody = Some(custody);
                    ready += 1;
                    if let Some(metrics) = &self.metrics {
                        metrics.fetched_outputs.inc();
                    }
                },
            }
        }
        if let Some(metrics) = &self.metrics {
            metrics.pressure(0, 0, 0);
        }
        for chain in 0..initially_emitted.len() {
            if self
                .block_stack
                .read_oldest(chain)
                .await
                .map_err(|error| Error::Stack(message(error)))?
                .is_some()
            {
                return Err(Error::Invalid(
                    "staged producer block is outside the ordering stream",
                ));
            }
        }
        Ok(())
    }

    async fn next_staged<I>(
        &mut self,
        stream: &mut I,
        initially_emitted: &[BlockRef<H::Digest>],
    ) -> Result<Option<(order::Slot<H::Digest>, BlockRef<H::Digest>)>, Error>
    where
        I: OrderedSlots<H::Digest>,
    {
        for slot in stream {
            let chain = slot.tip().chain().get() as usize;
            let frontier = initially_emitted.get(chain).ok_or(Error::Invalid(
                "ordering slot chain is outside the frontier",
            ))?;
            if slot.height() <= frontier.height() {
                continue;
            }
            let reference = self
                .block_stack
                .read_oldest(chain)
                .await
                .map_err(|error| Error::Stack(message(error)))?
                .ok_or(Error::Invalid("ordering slot is missing its staged block"))?;
            return Ok(Some((slot, reference)));
        }
        Ok(None)
    }

    fn staged_references(
        &self,
        staged: &VecDeque<StagedOutput<H::Digest>>,
        start: usize,
        count: usize,
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        let first = staged
            .front()
            .ok_or(Error::Invalid("custody window is empty"))?
            .sequence;
        let offset = start
            .checked_sub(first)
            .ok_or(Error::Invalid("custody lookup precedes its window"))?;
        let references = staged
            .iter()
            .skip(offset)
            .take(count)
            .map(|output| output.reference)
            .collect::<Vec<_>>();
        (references.len() == count)
            .then_some(references)
            .ok_or(Error::Invalid("custody lookup exceeds its window"))
    }

    fn staged_mut<'a>(
        &self,
        staged: &'a mut VecDeque<StagedOutput<H::Digest>>,
        sequence: usize,
    ) -> Result<&'a mut StagedOutput<H::Digest>, Error> {
        let first = staged
            .front()
            .ok_or(Error::Invalid("custody window is empty"))?
            .sequence;
        staged
            .get_mut(
                sequence
                    .checked_sub(first)
                    .ok_or(Error::Invalid("custody completion precedes its window"))?,
            )
            .ok_or(Error::Invalid("custody completion exceeds its window"))
    }

    async fn emit_output(
        &mut self,
        slot: order::Slot<H::Digest>,
        custody: catalog::CustodyRef<H::Digest>,
        batch: &mut PublicationBatch<H, V>,
    ) -> Result<(), Error> {
        let reference = custody.reference();
        let encoded_len = custody.meta().encoded_len();
        if !batch.outputs.is_empty()
            && batch
                .output_bytes
                .checked_add(encoded_len)
                .is_none_or(|total| total > self.max_commit_block_bytes)
        {
            self.commit_pending(batch).await?;
        }
        if self.state.reconcile(slot, reference)? != Reconciliation::Emit {
            return Err(Error::Invalid(
                "staged ordering slot reconciled as a duplicate",
            ));
        }
        let index = match self.committed {
            Some(index) => index.next().ok_or(Error::OutputExhausted)?,
            None => OutputIndex::ZERO,
        };
        self.committed = Some(index);
        batch.output_bytes = batch.output_bytes.saturating_add(encoded_len);
        batch.outputs.push(PlannedOutput { index, custody });
        if batch.outputs.len() == self.max_commit_outputs
            || batch.output_bytes >= self.max_commit_block_bytes
        {
            self.commit_pending(batch).await?;
        }
        Ok(())
    }

    fn apply_custody_lookup(
        &self,
        lookup: CustodyLookup<H>,
        staged: &mut VecDeque<StagedOutput<H::Digest>>,
        missing: &mut VecDeque<(usize, BlockRef<H::Digest>)>,
    ) -> Result<usize, Error> {
        let (start, expected, result) = lookup;
        let custody = result.map_err(Error::Catalog)?;
        if custody.len() != expected {
            return Err(Error::Invalid("catalog block batch cardinality mismatch"));
        }
        let mut local = 0usize;
        for (offset, custody) in custody.into_iter().enumerate() {
            let sequence = start.checked_add(offset).ok_or(Error::OutputExhausted)?;
            let output = self.staged_mut(staged, sequence)?;
            let reference = output.reference;
            if let Some(custody) = custody {
                if self.validate_custody(&custody)? != reference {
                    return Err(Error::Invalid(
                        "planned output custody does not match its exact reference",
                    ));
                }
                output.custody = Some(custody);
                local += 1;
            } else {
                missing.push_back((sequence, reference));
            }
        }
        Ok(local)
    }

    fn validate_custody(
        &self,
        custody: &catalog::CustodyRef<H::Digest>,
    ) -> Result<BlockRef<H::Digest>, Error> {
        let reference = custody.reference();
        if custody.meta().header().epoch() != self.epoch
            || custody.meta().header().block_ref::<H>() != reference
        {
            return Err(Error::Invalid(
                "planned output custody does not match its exact reference",
            ));
        }
        Ok(reference)
    }

    async fn common_frontiers(
        &mut self,
        targets: &[BlockRef<H::Digest>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<Vec<BlockRef<H::Digest>>, Error> {
        if targets.len() != emitted.len() {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        let walks = targets
            .iter()
            .zip(emitted)
            .map(|(target, emitted)| {
                Ancestry::common(*target, *emitted).map(|ancestry| ProducerWalk {
                    ancestry,
                    stage_max: None,
                    emitted: emitted.height(),
                    boundaries: Vec::new(),
                })
            })
            .collect::<Result<Vec<_>, ancestry::Error>>()?;
        self.walk_producers(walks, FetchReason::StateSync).await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.publish",
        level = "info",
        skip_all,
        fields(
            selected = batch.selected.len(),
            history = batch.history.len(),
            outputs = batch.outputs.len(),
            bytes = batch.output_bytes,
        )
    )]
    async fn commit(&mut self, batch: PublicationBatch<H, V>) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        let PublicationBatch {
            selected,
            history,
            outputs,
            ..
        } = batch;
        self.wait_for_commit_slot().await?;
        let outputs = outputs
            .into_iter()
            .map(|output| catalog::OutputRow::new(output.index, output.custody))
            .collect();
        let checkpoint = self.checkpoint()?;
        let selected = selected
            .into_iter()
            .map(|(id, proof)| catalog::SelectedLqc {
                view: proof.view(),
                id,
                proof,
            })
            .collect();
        let commit = catalog::Commit {
            selected,
            history,
            outputs,
            checkpoint,
        };
        let token = self
            .catalog
            .start_commit(commit)
            .await
            .map_err(|error| Error::Catalog(message(error)))?;
        self.pending_commits.push(async move {
            C::wait_commit(token)
                .await
                .map_err(|error| Error::Catalog(message(error)))
        });
        Ok(())
    }

    async fn finish_commit(&mut self) -> Result<(), Error> {
        self.pending_commits.next_completed().await
    }

    async fn finish_commits(&mut self) -> Result<(), Error> {
        while !self.pending_commits.is_empty() {
            self.finish_commit().await?;
        }
        Ok(())
    }

    async fn commit_pending(&mut self, batch: &mut PublicationBatch<H, V>) -> Result<(), Error> {
        if batch.is_empty() {
            return Ok(());
        }
        if let Some((id, proof)) = batch.selected.last() {
            self.floor = *id;
            self.floor_view = proof.view();
        }
        let advances_frontier = !batch.outputs.is_empty();
        let pending = PublicationBatch {
            selected: std::mem::take(&mut batch.selected),
            history: std::mem::take(&mut batch.history),
            outputs: std::mem::take(&mut batch.outputs),
            output_bytes: std::mem::take(&mut batch.output_bytes),
        };
        self.commit(pending).await?;
        if advances_frontier {
            let emitted = self.state.emitted();
            self.headers.retain(|reference, _| {
                emitted
                    .get(reference.chain().get() as usize)
                    .is_some_and(|frontier| reference.height() > frontier.height())
            });
        }
        Ok(())
    }

    fn checkpoint(&self) -> Result<Checkpoint<H::Digest>, Error> {
        Checkpoint::new(
            self.epoch,
            self.generation,
            self.archive_layout,
            self.floor,
            self.state.history(),
            self.history_index,
            self.state.ordered().to_vec(),
            self.state.emitted().to_vec(),
            self.committed,
            None,
        )
        .ok_or(Error::Invalid(
            "synchronizer produced a non-canonical checkpoint",
        ))
    }

    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.apply_floor",
        level = "info",
        skip_all
    )]
    async fn install_floor(
        &mut self,
        candidate: FloorCheckpoint<V, H::Digest>,
    ) -> Result<(), Error> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let verified = self.verify_floor(generation, candidate).await?;
        self.install_verified(verified).await
    }

    async fn verify_floor(
        &mut self,
        generation: u64,
        candidate: FloorCheckpoint<V, H::Digest>,
    ) -> Result<VerifiedFloor<H, V>, Error> {
        if candidate.anchor.id::<H>() != candidate.anchor_id
            || candidate.anchor.epoch() != self.epoch
            || candidate.anchor.view() <= self.floor_view
        {
            return Err(Error::Invalid(
                "floor anchor is stale or has an identity/epoch mismatch",
            ));
        }
        self.verifier
            .verify(&candidate.anchor)
            .await
            .map_err(|error| Error::Verify(message(error)))?;
        let commitment = candidate.history.commitment::<H>();
        if candidate.anchor.leader().history() != commitment {
            return Err(Error::Invalid(
                "floor history does not establish its ordered frontier",
            ));
        }
        let ordered = candidate.history.tips().to_vec();

        if !frontier_advances(self.state.ordered(), &ordered) {
            return Err(Error::Invalid("floor ordered frontier regresses"));
        }
        if !frontier_advances(self.state.emitted(), &candidate.emitted) {
            return Err(Error::Invalid("floor emitted frontier regresses"));
        }

        let base = HistoryState::new(commitment, ordered.clone(), ordered.clone())?;
        let mut sweep = base.final_sweep::<H, V>(&candidate.anchor, self.codec, &ordered)?;
        let target = sweep.target().to_vec();
        let mut expected = ordered.clone();
        for slot in sweep.by_ref() {
            expected[slot.tip().chain().get() as usize] =
                BlockRef::new(slot.tip().chain(), slot.height(), slot.tip().digest());
        }
        for (((ordered, target), expected), emitted) in ordered
            .iter()
            .zip(&target)
            .zip(&expected)
            .zip(&candidate.emitted)
        {
            if expected.height() != emitted.height()
                || (emitted.height() == ordered.height() && emitted != ordered)
                || (emitted.height() == target.height() && emitted != target)
            {
                return Err(Error::Invalid(
                    "floor emitted frontier is not the anchor's final sweep",
                ));
            }
        }
        let common = self.common_frontiers(&target, &candidate.emitted).await?;
        HistoryState::new(commitment, ordered.clone(), candidate.emitted.clone())?
            .validate_reconciliation(&target, &common)?;

        let history_index = Some(match self.history_index {
            Some(index) => index
                .checked_add(1)
                .ok_or(Error::Invalid("history index overflow"))?,
            None => 0,
        });
        let checkpoint = Checkpoint::new(
            self.epoch,
            generation,
            self.archive_layout,
            candidate.anchor_id,
            commitment,
            history_index,
            ordered,
            candidate.emitted.clone(),
            self.committed,
            self.committed,
        )
        .ok_or(Error::Invalid("floor checkpoint is not canonical"))?;
        let prune = catalog::Prune {
            pending_lqc: View::new(candidate.anchor.view().get().saturating_add(1)),
            pending_history: View::new(candidate.anchor.view().get().saturating_add(1)),
            pending_blocks: candidate
                .emitted
                .iter()
                .map(|reference| reference.height())
                .collect(),
        };
        Ok(VerifiedFloor {
            checkpoint,
            prune,
            proof: candidate.anchor,
            history: candidate.history,
        })
    }

    async fn install_verified(&mut self, verified: VerifiedFloor<H, V>) -> Result<(), Error> {
        self.finish_commits().await?;
        let view = verified.proof.view();
        self.catalog
            .install(
                verified.checkpoint.clone(),
                verified.prune,
                verified.proof,
                verified.history,
            )
            .await
            .map_err(|error| Error::Catalog(message(error)))?;
        let checkpoint = self
            .catalog
            .checkpoint()
            .await
            .map_err(|error| Error::Catalog(message(error)))?;
        self.generation = checkpoint.generation();
        self.floor = checkpoint.floor();
        self.floor_view = view;
        self.history_index = checkpoint.history_index();
        self.committed = checkpoint.committed();
        self.state = HistoryState::new(
            checkpoint.history(),
            checkpoint.ordered().to_vec(),
            checkpoint.emitted().to_vec(),
        )?;
        self.headers.clear();
        Ok(())
    }
}

fn frontier_advances<D: Digest>(current: &[BlockRef<D>], next: &[BlockRef<D>]) -> bool {
    current.len() == next.len()
        && current.iter().zip(next).all(|(current, next)| {
            next.height() > current.height()
                || (next.height() == current.height() && next == current)
        })
}

/// Starts a bounded synchronization actor and recovers its durable cut before serving commands.
#[allow(clippy::too_many_arguments)]
pub(in crate::multimmit::marshal) fn spawn<R, H, V, B, F, S, K, Q>(
    context: R,
    capacity: NonZeroUsize,
    catalog: CatalogClient<H, V, B>,
    fetcher: F,
    history_stack: S,
    block_stack: K,
    header_cache_capacity: NonZeroUsize,
    verifier: Q,
    codec: CodecConfig,
    backfill_concurrency: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_commit_block_bytes: NonZeroUsize,
    max_resolved_block_bytes: NonZeroUsize,
) -> SpawnedSynchronizer<H, V>
where
    R: Spawner + RuntimeMetrics,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
{
    let (commands, receiver) = mailbox::new(context.child("mailbox"), capacity);
    let metrics = metrics::Synchronizer::new(&context);
    let client = Client {
        commands,
        max_proofs: capacity.get(),
    };
    let handle = context.shared(false).spawn(move |_| async move {
        Synchronizer::recover(
            catalog,
            fetcher,
            history_stack,
            block_stack,
            header_cache_capacity,
            verifier,
            codec,
            backfill_concurrency.get(),
            max_commit_outputs.get(),
            max_commit_block_bytes,
            max_resolved_block_bytes,
            Some(metrics),
        )
        .await?
        .run(receiver)
        .await
    });
    (client, handle)
}

type SpawnedSynchronizer<H, V> = (Client<V, <H as Hasher>::Digest>, Handle<Result<(), Error>>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            mocks::{Committee, sign_vote},
            types::{
                Anchor, ChainId, ChainProposal, Extension, LeaderBlock, Position,
                TransactionBlock, TransactionBlockHeader, VoteBody, genesis_history,
            },
        },
        types::{Height, Participant, Round},
    };
    use commonware_codec::EncodeSize as _;
    use commonware_cryptography::{
        Digestible, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::sync::Mutex;
    use futures::executor::block_on;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type TestBody = EmptyBlock<Sha256>;
    type TestBlock = TransactionBlock<Sha256, TestBody>;
    type CommitWaiters = Arc<Mutex<VecDeque<oneshot::Sender<Result<(), MockError>>>>>;

    #[derive(Clone, Copy, Debug, thiserror::Error)]
    #[error("mock port failure")]
    struct MockError;

    #[derive(Default)]
    struct MockStack {
        links: Vec<HistoryLink<Sha256>>,
        cursor: Option<usize>,
        high_water: usize,
        writes_since_reset: usize,
        retired_segments: usize,
    }

    impl HistoryStack<Sha256> for MockStack {
        type Error = MockError;

        async fn reset(&mut self) -> Result<(), Self::Error> {
            self.retired_segments += usize::from(self.writes_since_reset > 0);
            self.writes_since_reset = 0;
            self.links.clear();
            self.cursor = None;
            Ok(())
        }

        async fn push(&mut self, link: HistoryLink<Sha256>) -> Result<(), Self::Error> {
            self.links.push(link);
            self.writes_since_reset += 1;
            self.high_water = self.high_water.max(self.links.len());
            Ok(())
        }

        async fn read_reverse(&mut self) -> Result<Option<HistoryLink<Sha256>>, Self::Error> {
            let cursor = self.cursor.get_or_insert(self.links.len());
            if *cursor == 0 {
                return Ok(None);
            }
            *cursor -= 1;
            Ok(Some(self.links[*cursor].clone()))
        }
    }

    #[derive(Default)]
    struct MockBlockStack {
        blocks: Vec<Vec<BlockRef<Sha256Digest>>>,
        writes_since_reset: usize,
        retired_segments: usize,
    }

    impl BlockStack<Sha256Digest> for MockBlockStack {
        type Error = MockError;

        async fn reset(&mut self) -> Result<(), Self::Error> {
            self.retired_segments += usize::from(self.writes_since_reset > 0);
            self.writes_since_reset = 0;
            self.blocks.clear();
            Ok(())
        }

        async fn push(&mut self, block: BlockRef<Sha256Digest>) -> Result<(), Self::Error> {
            let chain = block.chain().get() as usize;
            if self.blocks.len() <= chain {
                self.blocks.resize_with(chain + 1, Vec::new);
            }
            self.blocks[chain].push(block);
            self.writes_since_reset += 1;
            Ok(())
        }

        async fn read_oldest(
            &mut self,
            chain: usize,
        ) -> Result<Option<BlockRef<Sha256Digest>>, Self::Error> {
            Ok(self.blocks.get_mut(chain).and_then(Vec::pop))
        }
    }

    type MockLqcEntry = (CertificateId<Sha256Digest>, Arc<Lqc<MinPk, Sha256Digest>>);
    type MockBlocks = Arc<Mutex<BTreeMap<BlockRef<Sha256Digest>, Arc<TestBlock>>>>;

    #[derive(Clone, Default)]
    struct MockFetcher {
        lqcs: Vec<MockLqcEntry>,
        histories: Vec<(Sha256Digest, Arc<TipRecord<Sha256Digest>>)>,
        blocks: Arc<Vec<Vec<Arc<TestBlock>>>>,
        catalog_blocks: MockBlocks,
        block_reasons: Arc<Mutex<Vec<FetchReason>>>,
        lqc_calls: Arc<AtomicUsize>,
        history_calls: Arc<AtomicUsize>,
        block_calls: Arc<AtomicUsize>,
        catalog_block_calls: Option<Arc<AtomicUsize>>,
        fetch_batch_starts: Arc<Mutex<Vec<usize>>>,
        block_active: Arc<AtomicUsize>,
        block_peak: Arc<AtomicUsize>,
        yield_block_fetches: bool,
        fetch_delay_by_height: bool,
        gates: Option<Arc<FetchGates>>,
        fetch_requires: Option<(BlockRef<Sha256Digest>, usize)>,
    }

    impl Fetcher<Sha256, MinPk, TestBody> for MockFetcher {
        type Error = MockError;

        async fn lqc(
            &mut self,
            _reason: FetchReason,
            id: CertificateId<Sha256Digest>,
        ) -> Result<Arc<Lqc<MinPk, Sha256Digest>>, Self::Error> {
            self.lqc_calls.fetch_add(1, Ordering::Relaxed);
            self.lqcs
                .iter()
                .find(|(candidate, _)| *candidate == id)
                .map(|(_, proof)| proof.clone())
                .ok_or(MockError)
        }

        async fn history(
            &mut self,
            _reason: FetchReason,
            _view: View,
            mut commitment: Sha256Digest,
        ) -> Result<HistorySegment<Sha256Digest>, Self::Error> {
            self.history_calls.fetch_add(1, Ordering::Relaxed);
            let mut records = Vec::new();
            while let Some(record) = self
                .histories
                .iter()
                .find(|(candidate, _)| *candidate == commitment)
                .map(|(_, record)| Arc::clone(record))
            {
                commitment = record.parent();
                records.push(record);
            }
            (!records.is_empty())
                .then(|| Arc::new(records))
                .ok_or(MockError)
        }

        async fn headers(
            &mut self,
            _reason: FetchReason,
            mut reference: BlockRef<Sha256Digest>,
        ) -> Result<HeaderSegment<Sha256Digest>, Self::Error> {
            let chain = self
                .blocks
                .get(reference.chain().get() as usize)
                .ok_or(MockError)?;
            let mut headers = Vec::new();
            while let Some(block) = chain.iter().find(|block| block.reference() == reference) {
                let header = block.header().clone();
                reference = BlockRef::new(
                    reference.chain(),
                    Height::new(reference.height().get().saturating_sub(1)),
                    header.parent(),
                );
                headers.push(header);
            }
            (!headers.is_empty())
                .then(|| Arc::new(headers))
                .ok_or(MockError)
        }

        async fn block(
            &mut self,
            reason: FetchReason,
            reference: BlockRef<Sha256Digest>,
        ) -> Result<catalog::CustodyRef<Sha256Digest>, Self::Error> {
            self.block_reasons.lock().push(reason);
            self.block_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(calls) = &self.catalog_block_calls {
                self.fetch_batch_starts
                    .lock()
                    .push(calls.load(Ordering::Relaxed));
            }
            let block = self
                .blocks
                .get(reference.chain().get() as usize)
                .and_then(|blocks| blocks.iter().find(|block| block.reference() == reference))
                .cloned()
                .ok_or(MockError)?;
            if let Some((gated, required)) = self.fetch_requires
                && reference == gated
            {
                commonware_runtime::utils::reschedule().await;
                if self.block_calls.load(Ordering::Relaxed) < required {
                    return Err(MockError);
                }
            }
            if self.yield_block_fetches {
                let active = self.block_active.fetch_add(1, Ordering::Relaxed) + 1;
                self.block_peak.fetch_max(active, Ordering::Relaxed);
                commonware_runtime::utils::reschedule().await;
                self.block_active.fetch_sub(1, Ordering::Relaxed);
            }
            if self.fetch_delay_by_height {
                for _ in 0..reference.height().get() {
                    commonware_runtime::utils::reschedule().await;
                }
            }
            if let Some(gates) = &self.gates {
                gates.fetch(reference.chain().get() as usize).await?;
            }
            self.catalog_blocks
                .lock()
                .insert(reference, Arc::clone(&block));
            Ok(catalog::CustodyRef::for_test(&block))
        }
    }

    struct FetchGateState {
        active: usize,
        peak: usize,
        active_by_chain: [usize; 3],
        peak_by_chain: [usize; 3],
        starts: Vec<usize>,
        receivers: [Option<oneshot::Receiver<()>>; 3],
        release_initial_fast: Option<oneshot::Sender<()>>,
        release_straggler: Option<oneshot::Sender<()>>,
        progressed_around_straggler: bool,
    }

    struct FetchGates(Mutex<FetchGateState>);

    impl FetchGates {
        fn new() -> Self {
            let (release_straggler, straggler) = oneshot::channel();
            let (release_initial_fast, initial_fast) = oneshot::channel();
            Self(Mutex::new(FetchGateState {
                active: 0,
                peak: 0,
                active_by_chain: [0; 3],
                peak_by_chain: [0; 3],
                starts: Vec::new(),
                receivers: [Some(straggler), Some(initial_fast), None],
                release_initial_fast: Some(release_initial_fast),
                release_straggler: Some(release_straggler),
                progressed_around_straggler: false,
            }))
        }

        async fn fetch(&self, chain: usize) -> Result<(), MockError> {
            let (receiver, release) = {
                let mut state = self.0.lock();
                assert_eq!(state.active_by_chain[chain], 0);
                state.active += 1;
                state.peak = state.peak.max(state.active);
                state.active_by_chain[chain] = 1;
                state.peak_by_chain[chain] = state.peak_by_chain[chain].max(1);
                state.starts.push(chain);
                let receiver = state.receivers[chain].take();
                let release = if state.active_by_chain[0] == 1 && state.active_by_chain[1] == 1 {
                    state.release_initial_fast.take()
                } else if chain == 2 && state.release_straggler.is_some() {
                    assert_eq!(state.active_by_chain[0], 1);
                    state.progressed_around_straggler = true;
                    state.release_straggler.take()
                } else {
                    None
                };
                (receiver, release)
            };
            if let Some(release) = release {
                release.send(()).map_err(|_| MockError)?;
            }
            if let Some(receiver) = receiver {
                receiver.await.map_err(|_| MockError)?;
            }
            let mut state = self.0.lock();
            state.active -= 1;
            state.active_by_chain[chain] = 0;
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockVerifier(bool);

    impl LqcVerifier<Sha256, MinPk> for MockVerifier {
        type Error = MockError;

        async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
            self.0.then_some(()).ok_or(MockError)
        }
    }

    struct MockCatalog {
        checkpoint: Checkpoint<Sha256Digest>,
        latest: Option<Arc<Lqc<MinPk, Sha256Digest>>>,
        blocks: MockBlocks,
        block_batches: Arc<Mutex<Vec<Vec<BlockRef<Sha256Digest>>>>>,
        block_calls: Arc<AtomicUsize>,
        header_limits: Arc<Mutex<Vec<Vec<usize>>>>,
        outputs: Vec<BlockRef<Sha256Digest>>,
        batches: Vec<usize>,
        history_commits: usize,
        selected: Vec<CertificateId<Sha256Digest>>,
        selected_calls: Arc<Mutex<Vec<CertificateId<Sha256Digest>>>>,
        commit_calls: Arc<AtomicUsize>,
        commit_waiters: Option<CommitWaiters>,
        commit_start_gate: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
        installed: usize,
    }

    #[derive(Clone)]
    struct MockCustody {
        blocks: MockBlocks,
        batches: Arc<Mutex<Vec<Vec<BlockRef<Sha256Digest>>>>>,
        calls: Arc<AtomicUsize>,
    }

    impl CustodyPort<Sha256> for MockCustody {
        type Error = MockError;

        async fn wait_for_custody(
            &self,
            references: Vec<BlockRef<Sha256Digest>>,
        ) -> Result<Vec<Option<catalog::CustodyRef<Sha256Digest>>>, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.batches.lock().push(references.clone());
            Ok(references
                .into_iter()
                .map(|reference| {
                    self.blocks.lock().get(&reference).cloned().map(|block| {
                        assert_eq!(block.reference(), reference);
                        catalog::CustodyRef::for_test(&block)
                    })
                })
                .collect())
        }
    }

    impl CatalogPort<Sha256, MinPk, TestBody> for MockCatalog {
        type Error = MockError;
        type CommitToken = oneshot::Receiver<Result<(), MockError>>;
        type Custody = MockCustody;

        fn custody(&self) -> Self::Custody {
            MockCustody {
                blocks: Arc::clone(&self.blocks),
                batches: Arc::clone(&self.block_batches),
                calls: Arc::clone(&self.block_calls),
            }
        }

        async fn checkpoint(&mut self) -> Result<Checkpoint<Sha256Digest>, Self::Error> {
            Ok(self.checkpoint.clone())
        }

        async fn latest_lqc(
            &mut self,
        ) -> Result<Option<Arc<Lqc<MinPk, Sha256Digest>>>, Self::Error> {
            Ok(self.latest.take())
        }

        async fn lqc(
            &mut self,
            _: CertificateId<Sha256Digest>,
        ) -> Result<Option<Arc<Lqc<MinPk, Sha256Digest>>>, Self::Error> {
            Ok(None)
        }

        async fn final_lqc(
            &mut self,
            id: CertificateId<Sha256Digest>,
        ) -> Result<bool, Self::Error> {
            Ok(self.selected.contains(&id))
        }

        async fn header_segments(
            &mut self,
            requests: Vec<(BlockRef<Sha256Digest>, usize)>,
            _max_bytes: usize,
        ) -> Result<Vec<Vec<TransactionBlockHeader<Sha256Digest>>>, Self::Error> {
            self.header_limits
                .lock()
                .push(requests.iter().map(|(_, max_items)| *max_items).collect());
            Ok(requests
                .into_iter()
                .map(|(mut reference, max_items)| {
                    let mut headers = Vec::new();
                    while headers.len() < max_items {
                        let Some(block) = self.blocks.lock().get(&reference).cloned() else {
                            break;
                        };
                        let header = block.header().clone();
                        reference = BlockRef::new(
                            reference.chain(),
                            Height::new(reference.height().get().saturating_sub(1)),
                            header.parent(),
                        );
                        headers.push(header);
                    }
                    headers
                })
                .collect())
        }

        async fn start_commit(
            &mut self,
            batch: catalog::Commit<Sha256, MinPk>,
        ) -> Result<Self::CommitToken, Self::Error> {
            self.commit_calls.fetch_add(1, Ordering::Relaxed);
            self.batches.push(batch.outputs.len());
            self.outputs
                .extend(batch.outputs.iter().map(catalog::OutputRow::reference));
            self.history_commits += batch.history.len();
            for selected in batch.selected {
                self.selected.push(selected.id);
                self.selected_calls.lock().push(selected.id);
            }
            self.checkpoint = batch.checkpoint;
            let (completion, token) = oneshot::channel();
            if let Some(waiters) = &self.commit_waiters {
                waiters.lock().push_back(completion);
            } else {
                let _ = completion.send(Ok(()));
            }
            if let Some((started, release)) = self.commit_start_gate.take() {
                let _ = started.send(());
                release.await.map_err(|_| MockError)?;
            }
            Ok(token)
        }

        async fn wait_commit(token: Self::CommitToken) -> Result<(), Self::Error> {
            token.await.unwrap_or(Err(MockError))
        }

        async fn install(
            &mut self,
            checkpoint: Checkpoint<Sha256Digest>,
            _: catalog::Prune,
            _: Arc<Lqc<MinPk, Sha256Digest>>,
            _: Arc<TipRecord<Sha256Digest>>,
        ) -> Result<(), Self::Error> {
            self.checkpoint = checkpoint;
            self.installed += 1;
            Ok(())
        }
    }

    type TestSynchronizer = Synchronizer<
        MockCatalog,
        MockFetcher,
        MockStack,
        MockBlockStack,
        MockVerifier,
        Sha256,
        MinPk,
        TestBody,
    >;

    fn digest(label: &[u8], value: u64) -> Sha256Digest {
        Sha256::hash(&[label, &value.to_be_bytes()])
    }

    fn committee(seed: u64, chains: u32, limits: Limits) -> Committee<MinPk> {
        Committee::new_with_namespace_and_producers(
            seed,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_SYNCHRONIZER",
            6,
            (0..chains).map(Participant::new).collect(),
            limits,
        )
    }

    fn genesis_record(committee: &Committee<MinPk>) -> Arc<TipRecord<Sha256Digest>> {
        let genesis = committee.config.genesis();
        Arc::new(
            TipRecord::new(genesis_history::<Sha256>(genesis), genesis.tips().to_vec()).unwrap(),
        )
    }

    fn lqc(
        committee: &Committee<MinPk>,
        view: u64,
        signers: impl IntoIterator<Item = usize>,
    ) -> Arc<Lqc<MinPk, Sha256Digest>> {
        let leader = committee.leader_block(view);
        let votes = signers
            .into_iter()
            .map(|signer| committee.vote(signer, &leader))
            .collect::<Vec<_>>();
        Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                .unwrap(),
        )
    }

    fn lqc_with_history(
        committee: &Committee<MinPk>,
        view: u64,
        history: Sha256Digest,
        tip: BlockRef<Sha256Digest>,
    ) -> Arc<Lqc<MinPk, Sha256Digest>> {
        let leader = LeaderBlock::new(
            Round::new(committee.config.epoch(), View::new(view)),
            committee.config.genesis().vqc(),
            history,
            vec![
                ChainProposal::new(
                    ChainId::new(0),
                    Anchor::Tip(tip),
                    Vec::new(),
                    committee.codec().pipeline_depth(),
                )
                .unwrap(),
            ],
            committee.codec(),
        )
        .unwrap();
        let vote = VoteBody::for_leader::<Sha256, MinPk>(
            &leader,
            vec![Position::new(0)],
            vec![Extension::empty()],
            committee.codec(),
        )
        .unwrap();
        let votes = (0..committee.codec().view_quorum())
            .map(|signer| sign_vote(&committee.signers[signer], vote.clone()).unwrap())
            .collect::<Vec<_>>();
        Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
                .unwrap(),
        )
    }

    fn base(chain: u32, height: u64) -> BlockRef<Sha256Digest> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            digest(b"base", (u64::from(chain) << 32) | height),
        )
    }

    fn chain(epoch: Epoch, base: BlockRef<Sha256Digest>, count: usize) -> Vec<Arc<TestBlock>> {
        let mut parent = base.digest();
        (1..=count)
            .map(|offset| {
                let height = base.height().get() + offset as u64;
                let body =
                    EmptyBlock::new(digest(b"body parent", height), Height::new(height), height);
                let header = TransactionBlockHeader::new(
                    epoch,
                    base.chain(),
                    Height::new(height),
                    parent,
                    body.digest(),
                )
                .unwrap();
                let block = Arc::new(TransactionBlock::new(header, body).unwrap());
                parent = block.reference().digest();
                block
            })
            .collect()
    }

    fn tip(blocks: &[Arc<TestBlock>]) -> BlockRef<Sha256Digest> {
        blocks.last().unwrap().reference()
    }

    fn checkpoint(
        epoch: Epoch,
        history: Sha256Digest,
        ordered: Vec<BlockRef<Sha256Digest>>,
        emitted: Vec<BlockRef<Sha256Digest>>,
    ) -> Checkpoint<Sha256Digest> {
        Checkpoint::new(
            epoch,
            0,
            ArchiveLayout::new(false, false, false),
            CertificateId::new(digest(b"floor", epoch.get())),
            history,
            None,
            ordered,
            emitted,
            None,
            None,
        )
        .unwrap()
    }

    async fn actor(
        checkpoint: Checkpoint<Sha256Digest>,
        blocks: Vec<Vec<Arc<TestBlock>>>,
        codec: CodecConfig,
        max: usize,
    ) -> TestSynchronizer {
        let catalog_blocks = MockBlocks::default();
        Synchronizer::recover(
            MockCatalog {
                checkpoint,
                latest: None,
                blocks: Arc::clone(&catalog_blocks),
                block_batches: Arc::default(),
                block_calls: Arc::new(AtomicUsize::new(0)),
                header_limits: Arc::default(),
                outputs: Vec::new(),
                batches: Vec::new(),
                history_commits: 0,
                selected: Vec::new(),
                selected_calls: Arc::default(),
                commit_calls: Arc::new(AtomicUsize::new(0)),
                commit_waiters: None,
                commit_start_gate: None,
                installed: 0,
            },
            MockFetcher {
                blocks: Arc::new(blocks),
                catalog_blocks,
                ..MockFetcher::default()
            },
            MockStack::default(),
            MockBlockStack::default(),
            NonZeroUsize::new(16 * 1024).unwrap(),
            MockVerifier(true),
            codec,
            32,
            max,
            NonZeroUsize::new(64 * 1024 * 1024).unwrap(),
            NonZeroUsize::new(4 * 1024 * 1024).unwrap(),
            None,
        )
        .await
        .unwrap()
    }

    async fn commit_opening(actor: &mut TestSynchronizer, link: HistoryLink<Sha256>) {
        let mut batch = PublicationBatch::new(actor.max_commit_outputs, 0);
        actor.process_opening(link, &mut batch).await.unwrap();
        actor.commit(batch).await.unwrap();
    }

    fn planned(index: u64, block: &Arc<TestBlock>) -> PlannedOutput<Sha256Digest> {
        PlannedOutput {
            index: OutputIndex::new(index),
            custody: catalog::CustodyRef::for_test(block),
        }
    }

    fn publication(outputs: Vec<PlannedOutput<Sha256Digest>>) -> PublicationBatch<Sha256, MinPk> {
        let output_bytes = outputs
            .iter()
            .map(|output| output.custody.meta().encoded_len())
            .sum();
        PublicationBatch {
            selected: Vec::new(),
            history: Vec::new(),
            outputs,
            output_bytes,
        }
    }

    #[test]
    fn full_commit_window_consumes_header_input_before_durability() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(6, 1, Limits::new(1, 0).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = chain(epoch, base, 1);
            let history = digest(b"pipeline history", 0);
            let mut actor = actor(
                checkpoint(epoch, history, vec![base], vec![base]),
                vec![blocks.clone()],
                committee.codec(),
                8,
            )
            .await;
            actor
                .catalog
                .blocks
                .lock()
                .insert(blocks[0].reference(), Arc::clone(&blocks[0]));
            let waiters = Arc::new(Mutex::new(VecDeque::new()));
            actor.catalog.commit_waiters = Some(Arc::clone(&waiters));

            actor
                .commit(publication(vec![planned(0, &blocks[0])]))
                .await
                .unwrap();
            assert_eq!(waiters.lock().len(), 1);
            actor
                .commit(publication(vec![planned(1, &blocks[0])]))
                .await
                .unwrap();
            assert_eq!(waiters.lock().len(), 2);

            let record = Arc::new(TipRecord::new(history, vec![tip(&blocks)]).unwrap());
            let commitment = record.commitment::<Sha256>();
            let mut batch = PublicationBatch::new(actor.max_commit_outputs, 0);
            let mut opening =
                Box::pin(actor.process_opening(HistoryLink { commitment, record }, &mut batch));
            commonware_macros::select! {
                result = &mut opening => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {
                    panic!("full commit window blocked bounded output planning")
                },
            }
            drop(opening);
            assert_eq!(batch.outputs.len(), 1);
            assert_eq!(actor.pending_commits.len(), COMMIT_WINDOW);

            let (commands, receiver) = mailbox::new(context, NonZeroUsize::new(1).unwrap());
            actor.commands = Some(receiver);
            let reference = blocks[0].reference();
            assert_eq!(
                commands.enqueue(Command::Header(Span::none(), blocks[0].header().clone())),
                Feedback::Ok
            );
            let mut third = Box::pin(actor.commit(publication(vec![planned(2, &blocks[0])])));
            assert_eq!(waiters.lock().len(), COMMIT_WINDOW);
            let release = async {
                commonware_runtime::utils::reschedule().await;
                let first = waiters.lock().pop_front().unwrap();
                first.send(Ok(())).unwrap();
            };
            let (result, ()) = futures::join!(&mut third, release);
            result.unwrap();
            drop(third);
            assert!(actor.headers.get(&reference).is_some());
            assert_eq!(waiters.lock().len(), 2);

            let second = waiters.lock().pop_front().unwrap();
            let _ = second.send(Ok(()));
            let third = waiters.lock().pop_front().unwrap();
            let _ = third.send(Ok(()));
            actor.finish_commits().await.unwrap();
            assert!(actor.pending_commits.is_empty());
        });
    }

    #[test]
    fn paper_order_is_offset_major_across_producers() {
        block_on(async {
            let committee = committee(7, 3, Limits::new(3, 1).unwrap());
            let epoch = committee.config.epoch();
            let bases = vec![base(0, 0), base(1, 0), base(2, 0)];
            let blocks = vec![
                chain(epoch, bases[0], 2),
                chain(epoch, bases[1], 2),
                chain(epoch, bases[2], 2),
            ];
            let tips = blocks.iter().map(|blocks| tip(blocks)).collect();
            let history = digest(b"history", 0);
            let record = Arc::new(TipRecord::new(history, tips).unwrap());
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, history, bases.clone(), bases),
                blocks,
                committee.codec(),
                8,
            )
            .await;
            let gates = Arc::new(FetchGates::new());
            actor.fetcher.gates = Some(Arc::clone(&gates));
            actor.backfill_concurrency = 2;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;
            let coordinates = actor
                .catalog
                .outputs
                .iter()
                .map(|reference| (reference.chain().get(), reference.height().get()))
                .collect::<Vec<_>>();
            assert_eq!(
                coordinates,
                vec![(0, 1), (1, 1), (2, 1), (0, 2), (1, 2), (2, 2)]
            );
            let state = gates.0.lock();
            assert_eq!(state.peak, 2);
            assert_eq!(state.peak_by_chain, [1, 1, 1]);
            assert_eq!(&state.starts[..2], &[0, 1]);
            assert!(state.progressed_around_straggler);
        });
    }

    #[test]
    fn producer_walk_uses_local_headers_before_resolving_missing_body() {
        block_on(async {
            let committee = committee(18, 3, Limits::new(3, 1).unwrap());
            let epoch = committee.config.epoch();
            let bases = vec![base(0, 0), base(1, 0), base(2, 0)];
            let blocks = vec![
                chain(epoch, bases[0], 3),
                chain(epoch, bases[1], 3),
                chain(epoch, bases[2], 3),
            ];
            let record = Arc::new(
                TipRecord::new(
                    digest(b"local batch history", 0),
                    blocks.iter().map(|blocks| tip(blocks)).collect(),
                )
                .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(
                    epoch,
                    digest(b"local batch history", 0),
                    bases.clone(),
                    bases,
                ),
                blocks.clone(),
                committee.codec(),
                8,
            )
            .await;
            actor.catalog.blocks.lock().extend(
                blocks[0]
                    .iter()
                    .chain(&blocks[1][..2])
                    .chain(&blocks[2])
                    .map(|block| (block.reference(), Arc::clone(block))),
            );
            actor.fetcher.catalog_block_calls = Some(Arc::clone(&actor.catalog.block_calls));
            actor.backfill_concurrency = 3;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(&*actor.catalog.header_limits.lock(), &[vec![3, 3, 3]]);
            assert!(
                actor
                    .catalog
                    .block_batches
                    .lock()
                    .iter()
                    .all(|batch| batch.len() <= actor.custody_batch_outputs)
            );
            for block in blocks.iter().flatten() {
                let lookups = actor
                    .catalog
                    .block_batches
                    .lock()
                    .iter()
                    .flatten()
                    .filter(|reference| **reference == block.reference())
                    .count();
                assert_eq!(lookups, 1);
            }
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 1);
            assert!(
                actor.fetcher.fetch_batch_starts.lock()[0] > 0,
                "network backfill started before its local custody lookup"
            );
            assert_eq!(
                actor
                    .catalog
                    .outputs
                    .iter()
                    .map(|reference| (reference.chain().get(), reference.height().get()))
                    .collect::<Vec<_>>(),
                vec![
                    (0, 1),
                    (1, 1),
                    (2, 1),
                    (0, 2),
                    (1, 2),
                    (2, 2),
                    (0, 3),
                    (1, 3),
                    (2, 3),
                ]
            );
        });
    }

    #[test]
    fn cached_headers_backfill_only_the_missing_body_into_custody() {
        block_on(async {
            let committee = committee(23, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 3)];
            let record = Arc::new(
                TipRecord::new(digest(b"cached history", 0), vec![tip(&blocks[0])]).unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                8,
            )
            .await;
            for (position, block) in blocks[0].iter().enumerate() {
                actor.insert_header(block.header().clone());
                if position != 1 {
                    actor
                        .catalog
                        .blocks
                        .lock()
                        .insert(block.reference(), Arc::clone(block));
                }
            }

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.catalog.block_calls.load(Ordering::Relaxed), 1);
            assert_eq!(actor.catalog.block_batches.lock().len(), 1);
            assert_eq!(
                actor
                    .catalog
                    .block_batches
                    .lock()
                    .iter()
                    .map(Vec::len)
                    .collect::<Vec<_>>(),
                vec![3]
            );
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 1);
            assert_eq!(
                &*actor.fetcher.block_reasons.lock(),
                &[FetchReason::FinalizedBody]
            );
            assert_eq!(actor.catalog.outputs.len(), 3);
        });
    }

    #[test]
    fn same_chain_bodies_use_available_backfill_concurrency() {
        block_on(async {
            let committee = committee(24, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 3)];
            let record = Arc::new(
                TipRecord::new(digest(b"parallel body history", 0), vec![tip(&blocks[0])]).unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                8,
            )
            .await;
            for block in &blocks[0] {
                actor.insert_header(block.header().clone());
            }
            actor.backfill_concurrency = 3;
            actor.fetcher.yield_block_fetches = true;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.fetcher.block_peak.load(Ordering::Relaxed), 3);
        });
    }

    #[test]
    fn custody_lookup_pages_are_bounded_by_the_resolved_artifact_limit() {
        block_on(async {
            let committee = committee(31, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 40)];
            let record = Arc::new(
                TipRecord::new(digest(b"custody page history", 0), vec![tip(&blocks[0])]).unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                64,
            )
            .await;
            for block in &blocks[0] {
                actor.insert_header(block.header().clone());
                actor
                    .catalog
                    .blocks
                    .lock()
                    .insert(block.reference(), Arc::clone(block));
            }

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.custody_batch_outputs, 16);
            assert_eq!(
                actor
                    .catalog
                    .block_batches
                    .lock()
                    .iter()
                    .map(Vec::len)
                    .collect::<Vec<_>>(),
                vec![16, 16, 8]
            );
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 0);
        });
    }

    #[test]
    fn custody_window_schedules_past_a_blocked_first_page() {
        block_on(async {
            const OUTPUTS: usize = 40;
            const PAGE: usize = 16;
            let committee = committee(33, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, OUTPUTS)];
            let record = Arc::new(
                TipRecord::new(digest(b"custody window history", 0), vec![tip(&blocks[0])])
                    .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                64,
            )
            .await;
            for block in &blocks[0] {
                actor.insert_header(block.header().clone());
            }
            actor.backfill_concurrency = 32;
            actor.fetcher.fetch_requires = Some((blocks[0][0].reference(), PAGE + 1));

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.catalog.outputs.len(), OUTPUTS);
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), OUTPUTS);
        });
    }

    #[test]
    fn custody_window_refills_past_a_blocked_trailing_page() {
        block_on(async {
            const OUTPUTS: usize = 64;
            const PAGE: usize = 16;
            const WINDOW: usize = PAGE * COMMIT_WINDOW;
            let committee = committee(34, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, OUTPUTS)];
            let record = Arc::new(
                TipRecord::new(digest(b"sliding custody history", 0), vec![tip(&blocks[0])])
                    .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                OUTPUTS,
            )
            .await;
            for block in &blocks[0] {
                actor.insert_header(block.header().clone());
            }
            actor.backfill_concurrency = WINDOW;
            actor.fetcher.fetch_requires = Some((blocks[0][WINDOW - 1].reference(), WINDOW + 1));

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.catalog.outputs.len(), OUTPUTS);
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), OUTPUTS);
        });
    }

    #[test]
    fn custody_window_refills_keep_page_batches() {
        block_on(async {
            const OUTPUTS: usize = 64;
            const PAGE: usize = 16;
            let committee = committee(35, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, OUTPUTS)];
            let record = Arc::new(
                TipRecord::new(
                    digest(b"batched custody refill history", 0),
                    vec![tip(&blocks[0])],
                )
                .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                OUTPUTS,
            )
            .await;
            for block in &blocks[0] {
                actor.insert_header(block.header().clone());
            }
            actor.backfill_concurrency = PAGE * COMMIT_WINDOW;
            actor.fetcher.fetch_delay_by_height = true;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(
                actor
                    .catalog
                    .block_batches
                    .lock()
                    .iter()
                    .map(Vec::len)
                    .collect::<Vec<_>>(),
                vec![PAGE; OUTPUTS / PAGE]
            );
        });
    }

    #[test]
    fn adjacent_history_openings_share_bounded_commits() {
        block_on(async {
            const OPENINGS: usize = 5;
            const BATCH: usize = 2;
            let committee = committee(15, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                BATCH,
            )
            .await;
            let mut parent = genesis_history::<Sha256>(genesis);
            let mut batch = PublicationBatch::new(BATCH, 0);
            for _ in 0..OPENINGS {
                let record = Arc::new(TipRecord::new(parent, genesis.tips().to_vec()).unwrap());
                let commitment = record.commitment::<Sha256>();
                actor
                    .process_opening(HistoryLink { commitment, record }, &mut batch)
                    .await
                    .unwrap();
                parent = commitment;
            }
            actor.commit(batch).await.unwrap();

            assert_eq!(actor.catalog.history_commits, OPENINGS);
            assert_eq!(actor.catalog.batches, vec![0, 0, 0]);
        });
    }

    #[test]
    fn adjacent_history_openings_share_backfill_concurrency() {
        block_on(async {
            let committee = committee(34, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 2)];
            let history = digest(b"cross-opening history", 0);
            let first = Arc::new(
                TipRecord::new(history, vec![blocks[0][0].reference()]).unwrap(),
            );
            let first_id = first.commitment::<Sha256>();
            let second = Arc::new(
                TipRecord::new(first_id, vec![blocks[0][1].reference()]).unwrap(),
            );
            let second_id = second.commitment::<Sha256>();
            let proof = lqc_with_history(&committee, 1, second_id, blocks[0][1].reference());
            let id = proof.id::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, history, vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                8,
            )
            .await;
            actor.fetcher.histories = vec![(first_id, first), (second_id, second)];
            actor.fetcher.fetch_requires = Some((blocks[0][0].reference(), 2));
            actor.backfill_concurrency = 2;

            actor
                .synchronize_proofs(BTreeMap::from([(id, proof)]))
                .await
                .unwrap();

            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 2);
            assert_eq!(&*actor.catalog.header_limits.lock(), &[vec![2]]);
            assert_eq!(
                actor.catalog.outputs,
                vec![blocks[0][0].reference(), blocks[0][1].reference()]
            );
        });
    }

    #[test]
    fn history_window_authenticates_intermediate_tips() {
        block_on(async {
            let committee = committee(36, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 2)];
            let history = digest(b"boundary history", 0);
            let fork = BlockRef::new(ChainId::new(0), Height::new(1), digest(b"fork", 1));
            let first = Arc::new(TipRecord::new(history, vec![fork]).unwrap());
            let first_id = first.commitment::<Sha256>();
            let second = Arc::new(
                TipRecord::new(first_id, vec![blocks[0][1].reference()]).unwrap(),
            );
            let second_id = second.commitment::<Sha256>();
            let proof = lqc_with_history(&committee, 1, second_id, blocks[0][1].reference());
            let id = proof.id::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, history, vec![base], vec![base]),
                blocks,
                committee.codec(),
                8,
            )
            .await;
            actor.fetcher.histories = vec![(first_id, first), (second_id, second)];

            assert!(matches!(
                actor
                    .synchronize_proofs(BTreeMap::from([(id, proof)]))
                    .await,
                Err(Error::Invalid(
                    "producer ancestry conflicts with a history boundary"
                ))
            ));
            assert!(actor.catalog.outputs.is_empty());
        });
    }

    #[test]
    fn finalized_publication_does_not_reload_custodied_bodies() {
        block_on(async {
            const OPENINGS: usize = 5;
            const BATCH: usize = 8;
            let committee = committee(32, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = chain(epoch, base, OPENINGS);
            let history = digest(b"materialization history", 0);
            let mut actor = actor(
                checkpoint(epoch, history, vec![base], vec![base]),
                vec![blocks.clone()],
                committee.codec(),
                BATCH,
            )
            .await;
            let mut parent = history;
            let mut batch = PublicationBatch::new(BATCH, 0);
            for block in &blocks {
                let record = Arc::new(TipRecord::new(parent, vec![block.reference()]).unwrap());
                let commitment = record.commitment::<Sha256>();
                actor
                    .process_opening(HistoryLink { commitment, record }, &mut batch)
                    .await
                    .unwrap();
                parent = commitment;
            }
            actor.commit(batch).await.unwrap();

            assert_eq!(actor.catalog.outputs.len(), OPENINGS);
        });
    }

    #[test]
    fn long_gap_uses_capped_dense_batches() {
        block_on(async {
            const GAP: usize = 512;
            const BATCH: usize = 17;
            let committee = committee(8, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 10_000);
            let blocks = vec![chain(epoch, base, GAP)];
            let record = Arc::new(
                TipRecord::new(digest(b"long history", 0), vec![tip(&blocks[0])]).unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks,
                committee.codec(),
                BATCH,
            )
            .await;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;
            assert_eq!(actor.catalog.outputs.len(), GAP);
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), GAP);
            assert!(
                actor
                    .fetcher
                    .block_reasons
                    .lock()
                    .iter()
                    .all(|reason| *reason == FetchReason::FinalizedBody),
                "producer discovery must not fetch complete bodies"
            );
            assert!(actor.catalog.batches.iter().all(|size| *size <= BATCH));
            assert_eq!(actor.catalog.batches.iter().sum::<usize>(), GAP);
            assert_eq!(
                actor.catalog.checkpoint.committed(),
                Some(OutputIndex::new(511))
            );
            assert_eq!(actor.block_stack.retired_segments, 1);
        });
    }

    #[test]
    fn publication_batches_respect_the_block_byte_bound() {
        block_on(async {
            let committee = committee(29, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 5)];
            let record = Arc::new(
                TipRecord::new(digest(b"byte bound history", 0), vec![tip(&blocks[0])]).unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, record.parent(), vec![base], vec![base]),
                blocks.clone(),
                committee.codec(),
                8,
            )
            .await;
            let block_bytes = u64::try_from(blocks[0][0].encode_size()).unwrap();
            actor.max_commit_block_bytes = block_bytes * 2;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;

            assert_eq!(actor.catalog.batches, vec![2, 2, 1]);
            assert_eq!(actor.catalog.outputs.len(), 5);
        });
    }

    #[test]
    fn completed_synchronization_retires_consumed_history_scratch() {
        block_on(async {
            let committee = committee(14, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let parent = genesis_history::<Sha256>(genesis);
            let record = Arc::new(TipRecord::new(parent, genesis.tips().to_vec()).unwrap());
            let commitment = record.commitment::<Sha256>();
            let proof = Arc::new(committee.lqc(1));
            assert_eq!(proof.leader().history(), commitment);
            let id = proof.id::<Sha256>();
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    parent,
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor.fetcher.histories.push((commitment, record));

            actor
                .synchronize_proofs(BTreeMap::from([(id, proof)]))
                .await
                .unwrap();

            assert_eq!(actor.history_stack.retired_segments, 1);
            assert!(actor.history_stack.links.is_empty());
        });
    }

    #[test]
    fn restart_reconciles_authenticated_duplicates_without_outputs() {
        block_on(async {
            let committee = committee(9, 1, Limits::new(1, 1).unwrap());
            let epoch = committee.config.epoch();
            let base = base(0, 0);
            let blocks = vec![chain(epoch, base, 4)];
            let emitted = tip(&blocks[0]);
            let history = digest(b"restart history", 0);
            let record = Arc::new(TipRecord::new(history, vec![emitted]).unwrap());
            let commitment = record.commitment::<Sha256>();
            let mut actor = actor(
                checkpoint(epoch, history, vec![base], vec![emitted]),
                blocks,
                committee.codec(),
                2,
            )
            .await;

            commit_opening(&mut actor, HistoryLink { commitment, record }).await;
            assert!(actor.catalog.outputs.is_empty());
            assert_eq!(actor.catalog.history_commits, 1);
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 0);
        });
    }

    fn floor_fixture(
        committee: &Committee<MinPk>,
    ) -> (
        Checkpoint<Sha256Digest>,
        FloorCheckpoint<MinPk, Sha256Digest>,
    ) {
        let genesis = committee.config.genesis();
        let parent = genesis_history::<Sha256>(genesis);
        let history = Arc::new(TipRecord::new(parent, genesis.tips().to_vec()).unwrap());
        let anchor = Arc::new(committee.lqc(1));
        let current = checkpoint(
            genesis.epoch(),
            parent,
            genesis.tips().to_vec(),
            genesis.tips().to_vec(),
        );
        let floor = FloorCheckpoint::new(
            anchor.id::<Sha256>(),
            anchor,
            history,
            genesis.tips().to_vec(),
        );
        (current, floor)
    }

    #[test]
    fn incompatible_floor_resumes_without_installing() {
        block_on(async {
            let committee = committee(11, 2, Limits::new(2, 1).unwrap());
            let (current, floor) = floor_fixture(&committee);
            let mut emitted = floor.emitted.clone();
            emitted[0] = BlockRef::new(emitted[0].chain(), emitted[0].height(), digest(b"fork", 0));
            let incompatible =
                FloorCheckpoint::new(floor.anchor_id, floor.anchor, floor.history, emitted);
            let mut actor =
                actor(current, vec![Vec::new(), Vec::new()], committee.codec(), 4).await;

            assert!(matches!(
                actor.install_floor(incompatible).await,
                Err(Error::Invalid(_))
            ));
            assert_eq!(actor.catalog.installed, 0);
        });
    }

    #[test]
    fn finalized_proofs_at_or_below_the_floor_are_idempotent() {
        block_on(async {
            let committee = committee(12, 2, Limits::new(2, 1).unwrap());
            let (current, _) = floor_fixture(&committee);
            let proof = Arc::new(committee.lqc(1));
            let id = proof.id::<Sha256>();
            let mut actor =
                actor(current, vec![Vec::new(), Vec::new()], committee.codec(), 4).await;
            actor.floor = id;
            actor.floor_view = proof.view();

            actor
                .synchronize_proofs(BTreeMap::from([(id, proof)]))
                .await
                .unwrap();

            assert_eq!(actor.history_stack.high_water, 0);
            assert!(actor.catalog.selected.is_empty());
        });
    }

    #[test]
    fn run_coalesces_queued_synchronization_hints() {
        deterministic::Runner::default().start(|context| async move {
            const HINTS: usize = 64;
            let committee = committee(17, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let proof = Arc::new(committee.lqc(1));
            let id = proof.id::<Sha256>();
            let history = genesis_record(&committee);
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor
                .fetcher
                .histories
                .push((history.commitment::<Sha256>(), Arc::clone(&history)));
            let commit_calls = Arc::clone(&actor.catalog.commit_calls);
            let (commands, receiver) = mailbox::new(
                context,
                NonZeroUsize::new(HINTS).expect("the hint count is non-zero"),
            );
            for _ in 0..HINTS {
                assert_eq!(
                    commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                        id,
                        Arc::clone(&proof),
                        HINTS,
                    ))),
                    Feedback::Ok
                );
            }
            drop(commands);

            actor.run(receiver).await.unwrap();

            assert_eq!(commit_calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn run_batches_distinct_queued_synchronization_hints() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(18, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let first = Arc::new(committee.lqc(1));
            let second = Arc::new(committee.lqc(2));
            let first_id = first.id::<Sha256>();
            let second_id = second.id::<Sha256>();
            let history = genesis_record(&committee);
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor
                .fetcher
                .histories
                .push((history.commitment::<Sha256>(), Arc::clone(&history)));
            let commit_calls = Arc::clone(&actor.catalog.commit_calls);
            let history_calls = Arc::clone(&actor.fetcher.history_calls);
            let (commands, receiver) = mailbox::new(context, NonZeroUsize::new(2).unwrap());
            assert_eq!(
                commands.enqueue(Command::Synchronize(Span::none(),
                    FinalityBatch::new(first_id, first, 2,)
                )),
                Feedback::Ok
            );
            assert_eq!(
                commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                    second_id, second, 2
                ))),
                Feedback::Ok
            );
            drop(commands);

            actor.run(receiver).await.unwrap();

            assert_eq!(commit_calls.load(Ordering::Relaxed), 1);
            assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn run_coalesces_finality_before_fetching_history() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(23, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let lower = Arc::new(committee.lqc(1));
            let parent = committee.vqc(2);
            let leader = committee.leader_block_with_parent(3, &parent);
            let votes = (0..committee.codec().view_quorum())
                .map(|signer| committee.vote(signer, &leader))
                .collect::<Vec<_>>();
            let higher = Arc::new(
                committee
                    .verifier
                    .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                    .unwrap(),
            );
            let genesis_record = genesis_record(&committee);
            let parent_record = Arc::new(
                TipRecord::new(parent.leader().history(), genesis.tips().to_vec()).unwrap(),
            );
            assert_eq!(
                parent_record.commitment::<Sha256>(),
                higher.leader().history()
            );
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor.fetcher.histories = vec![
                (genesis_record.commitment::<Sha256>(), genesis_record),
                (parent_record.commitment::<Sha256>(), parent_record),
            ];
            let selected = Arc::clone(&actor.catalog.selected_calls);
            let history_calls = Arc::clone(&actor.fetcher.history_calls);
            let higher_id = higher.id::<Sha256>();
            let (commands, receiver) = mailbox::new(context, NonZeroUsize::new(2).unwrap());
            assert_eq!(
                commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                    lower.id::<Sha256>(),
                    lower,
                    2,
                ))),
                Feedback::Ok
            );
            assert_eq!(
                commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                    higher_id, higher, 2
                ))),
                Feedback::Ok
            );
            drop(commands);

            actor.run(receiver).await.unwrap();

            assert_eq!(*selected.lock(), vec![higher_id]);
            assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        });
    }

    #[test]
    fn run_pipelines_commit_across_live_synchronization_passes() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(22, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let first = Arc::new(committee.lqc(1));
            let second = Arc::new(committee.lqc(2));
            let history = genesis_record(&committee);
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor
                .fetcher
                .histories
                .push((history.commitment::<Sha256>(), Arc::clone(&history)));
            let waiters = Arc::new(Mutex::new(VecDeque::new()));
            actor.catalog.commit_waiters = Some(Arc::clone(&waiters));
            let commit_calls = Arc::clone(&actor.catalog.commit_calls);
            let (started, first_started) = oneshot::channel();
            let (release_first, release) = oneshot::channel();
            actor.catalog.commit_start_gate = Some((started, release));
            let (commands, receiver) =
                mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());

            let driver = async move {
                assert_eq!(
                    commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                        first.id::<Sha256>(),
                        first,
                        2,
                    ))),
                    Feedback::Ok
                );
                first_started.await.unwrap();
                assert_eq!(
                    commands.enqueue(Command::Synchronize(Span::none(), FinalityBatch::new(
                        second.id::<Sha256>(),
                        second,
                        2,
                    ))),
                    Feedback::Ok
                );
                release_first.send(()).unwrap();

                futures::future::poll_fn(|cx| {
                    if commit_calls.load(Ordering::Relaxed) == 2 {
                        std::task::Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                })
                .await;
                assert_eq!(commit_calls.load(Ordering::Relaxed), 2);
                assert_eq!(waiters.lock().len(), 2);

                let first = waiters.lock().pop_front().unwrap();
                first.send(Ok(())).unwrap();
                let second = waiters.lock().pop_front().unwrap();
                second.send(Ok(())).unwrap();
                drop(commands);
            };

            let (result, ()) = futures::join!(actor.run(receiver), driver);
            result.unwrap();
        });
    }

    #[test]
    fn run_preserves_distinct_same_view_finality() {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(21, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let first = lqc(&committee, 1, 0..5);
            let second = lqc(&committee, 1, 1..6);
            let first_id = first.id::<Sha256>();
            let second_id = second.id::<Sha256>();
            assert_ne!(first_id, second_id);
            let history = genesis_record(&committee);
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            actor
                .fetcher
                .histories
                .push((history.commitment::<Sha256>(), Arc::clone(&history)));
            let selected = Arc::clone(&actor.catalog.selected_calls);
            let (commands, receiver) = mailbox::new(context, NonZeroUsize::new(2).unwrap());
            for (id, proof) in [(first_id, first), (second_id, second)] {
                assert_eq!(
                    commands.enqueue(Command::Synchronize(
                        Span::none(),
                        FinalityBatch::new(id, proof, 2),
                    )),
                    Feedback::Ok
                );
            }
            drop(commands);

            actor.run(receiver).await.unwrap();

            assert_eq!(*selected.lock(), vec![first_id, second_id]);
        });
    }

    #[test]
    fn live_synchronization_uses_the_reported_proof_without_refetching_it() {
        block_on(async {
            let committee = committee(19, 2, Limits::new(2, 1).unwrap());
            let genesis = committee.config.genesis();
            let proof = Arc::new(committee.lqc(1));
            let id = proof.id::<Sha256>();
            let history = genesis_record(&committee);
            assert_eq!(history.commitment::<Sha256>(), proof.leader().history());
            let mut actor = actor(
                checkpoint(
                    committee.config.epoch(),
                    genesis_history::<Sha256>(genesis),
                    genesis.tips().to_vec(),
                    genesis.tips().to_vec(),
                ),
                vec![Vec::new(), Vec::new()],
                committee.codec(),
                4,
            )
            .await;
            let lqc_calls = Arc::clone(&actor.fetcher.lqc_calls);
            let history_calls = Arc::clone(&actor.fetcher.history_calls);
            actor
                .fetcher
                .histories
                .push((history.commitment::<Sha256>(), history));

            actor
                .synchronize_proofs(BTreeMap::from([(id, proof)]))
                .await
                .unwrap();

            assert_eq!(lqc_calls.load(Ordering::Relaxed), 0);
            assert_eq!(history_calls.load(Ordering::Relaxed), 1);
            assert_eq!(actor.catalog.selected, vec![id]);
        });
    }

    #[test]
    fn synchronization_overflow_coalesces_to_the_highest_view() {
        let committee = committee(20, 2, Limits::new(2, 1).unwrap());
        let proof = Arc::new(committee.lqc(1));
        let mut overflow = VecDeque::new();
        for value in (0..1_000).rev() {
            let id = CertificateId::new(digest(b"overflow target", value));
            let mut batch = FinalityBatch::new(id, Arc::clone(&proof), 1);
            batch.view = View::new(value);
            Command::<MinPk, Sha256Digest>::handle(
                &mut overflow,
                Command::Synchronize(Span::none(), batch),
            );
        }

        assert_eq!(overflow.len(), 1);
        let Some(Command::Synchronize(_, batch)) = overflow.pop_front() else {
            panic!("coalesced synchronization target missing");
        };
        assert_eq!(batch.view, View::new(999));
        assert!(
            batch
                .proofs
                .contains_key(&CertificateId::new(digest(b"overflow target", 999)))
        );
    }

    #[test]
    fn synchronization_overflow_bounds_adversarial_same_view_proofs() {
        let committee = committee(24, 2, Limits::new(2, 1).unwrap());
        let proof = Arc::new(committee.lqc(1));
        let mut overflow = VecDeque::new();
        for value in 0..1_000 {
            Command::<MinPk, Sha256Digest>::handle(
                &mut overflow,
                Command::Synchronize(Span::none(), FinalityBatch::new(
                    CertificateId::new(digest(b"same-view target", value)),
                    Arc::clone(&proof),
                    2,
                )),
            );
        }

        let Some(Command::Synchronize(_, batch)) = overflow.pop_front() else {
            panic!("coalesced synchronization target missing");
        };
        assert_eq!(batch.proofs.len(), 2);
        assert!(overflow.is_empty());
    }

    #[test]
    fn synchronization_overflow_discards_canceled_floor_installations() {
        let committee = committee(16, 2, Limits::new(2, 1).unwrap());
        let (_, first_floor) = floor_fixture(&committee);
        let (first_reply, first_receiver) = oneshot::channel();
        let mut overflow = VecDeque::new();
        Command::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Command::InstallFloor(Span::none(), first_floor, first_reply),
        );
        assert_eq!(overflow.len(), 1);
        drop(first_receiver);

        let (_, second_floor) = floor_fixture(&committee);
        let (second_reply, second_receiver) = oneshot::channel();
        drop(second_receiver);
        Command::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Command::InstallFloor(Span::none(), second_floor, second_reply),
        );

        assert!(overflow.is_empty());
    }

    #[test]
    fn floor_installation_rejects_a_valid_frontier_rewind() {
        block_on(async {
            let committee = committee(13, 2, Limits::new(2, 1).unwrap());
            let epoch = committee.config.epoch();
            let genesis = committee.config.genesis();
            let blocks = vec![
                chain(epoch, genesis.tips()[0], 1),
                chain(epoch, genesis.tips()[1], 1),
            ];
            let advanced = blocks.iter().map(|chain| tip(chain)).collect::<Vec<_>>();
            let current = checkpoint(
                epoch,
                genesis_history::<Sha256>(genesis),
                advanced.clone(),
                advanced,
            );
            let (_, floor) = floor_fixture(&committee);
            let mut actor = actor(current, blocks, committee.codec(), 4).await;

            assert!(matches!(
                actor.install_floor(floor).await,
                Err(Error::Invalid("floor ordered frontier regresses"))
            ));
            assert_eq!(actor.catalog.installed, 0);
        });
    }
}
