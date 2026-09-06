//! Bounded single-owner catalog actor for Multimmit marshal.
//!
//! The catalog serializes logical storage transitions while their independent archive syncs run in
//! bounded background slots. Finalized checkpoints are published last, making recovery depend on
//! one authoritative cut. Its block cache is advisory: every cache miss is answered from durable
//! custody without changing observable behavior.
//! Committed body reads can proceed while admission owns its mutable journals; ordinary requests
//! retain mailbox ordering, and destructive transitions wait for journal ownership to return.

use super::{
    delivery::{self, DeliveryClient},
    materializer::{CompletedRequest, Materializer},
    metrics, promoter,
};
pub(in crate::multimmit::marshal) use crate::multimmit::marshal::storage::{
    archive::Shared, checkpoint::Prune,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            storage::{
                archive::ReadOutcome as FinalizedReadOutcome,
                blocks::{BlockMeta, FinalBlock},
                checkpoint::{CatalogState, Checkpoint},
                pending::{BODY_READ_CONCURRENCY, BodyReadGroup, PendingBlocks},
                state::{
                    self as storage, Admission, AdmissionFootprint, FinalHistory, FinalLqc,
                    PendingHistory, PendingLqc, StoredRef, Stores,
                },
            },
            types::OutputIndex,
        },
        types::{
            BlockRef, CertificateId, ChainId, Lqc, TipRecord, TransactionBlock,
            TransactionBlockHeader,
        },
    },
    types::{Height, View},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::{Codec, EncodeSize, FixedSize as _, Read, ReadExt as _, Write};
use commonware_cryptography::{
    Digest, Digestible, Hasher, bls12381::primitives::variant::Variant, crc32,
};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Handle, Metrics as RuntimeMetrics, Spawner,
    telemetry::metrics::{HistogramExt as _, histogram},
};
use commonware_storage::{Context, metadata::Metadata, translator::Translator};
use commonware_utils::{channel::oneshot, futures::Pool, sequence::Unit};
use futures::{
    FutureExt as _,
    future::{pending, try_join_all},
};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::{Arc, mpsc::TryRecvError},
    time::SystemTime,
};
use tracing::{Instrument as _, Span, info_span};

/// Bounds temporary archive growth without putting cleanup on every publication.
const MAX_COMMITS_BEFORE_CLEANUP: usize = 8;

/// Admission-cut size above which a reply-free cut counts as naturally full.
///
/// Purely observational: [`metrics::Catalog::cut_trigger`] labels each smaller reply-free cut
/// `eager`, measuring how many cuts a batching policy could hold back and how large their
/// batches would grow. Cut starts are not gated on it.
const ADMISSION_CUT_MIN_ITEMS: usize = 16;

/// Returns the complete single-row metadata blob size for a catalog state.
pub(in crate::multimmit::marshal) fn metadata_blob_size<D: Digest>(
    state: &CatalogState<D>,
) -> Option<usize> {
    u64::SIZE
        .checked_add(Unit::SIZE)?
        .checked_add(state.encode_size())?
        .checked_add(crc32::Digest::SIZE)
}
/// A catalog request failed.
#[derive(Clone, Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("catalog mailbox is closed")]
    Closed,
    #[error("delivery mailbox is closed")]
    DeliveryClosed,
    #[error("immutable promoter mailbox is closed")]
    PromoterClosed,
    #[error("invalid catalog request: {0}")]
    Invalid(&'static str),
    #[error("catalog storage failed: {0}")]
    Storage(Arc<str>),
}
impl Error {
    pub(in crate::multimmit::marshal) fn storage(error: impl std::fmt::Display) -> Self {
        Self::Storage(Arc::from(error.to_string()))
    }

    const fn fatal(&self) -> bool {
        matches!(
            self,
            Self::DeliveryClosed | Self::PromoterClosed | Self::Storage(_)
        )
    }
}

/// The selected finality proof in a commit.
pub(in crate::multimmit::marshal) struct SelectedLqc<V: Variant, H: Hasher> {
    pub view: View,
    pub id: CertificateId<H::Digest>,
    pub proof: Arc<Lqc<V, H::Digest>>,
}

/// One authenticated tip-history opening, ordered oldest first.
pub(in crate::multimmit::marshal) struct HistoryOpening<H: Hasher> {
    pub commitment: H::Digest,
    pub record: Arc<TipRecord<H::Digest>>,
}

/// Catalog-proven durable custody needed to order a block without reading its body.
pub(in crate::multimmit::marshal) struct CustodyRef<D: Digest> {
    reference: BlockRef<D>,
    meta: BlockMeta<D>,
}

impl<D: Digest> CustodyRef<D> {
    const fn new(reference: BlockRef<D>, meta: BlockMeta<D>) -> Self {
        Self { reference, meta }
    }

    pub(in crate::multimmit::marshal) const fn reference(&self) -> BlockRef<D> {
        self.reference
    }

    pub(in crate::multimmit::marshal) const fn meta(&self) -> &BlockMeta<D> {
        &self.meta
    }

    pub(in crate::multimmit::marshal) const fn into_parts(self) -> (BlockRef<D>, BlockMeta<D>) {
        (self.reference, self.meta)
    }
}

impl<D: Digest> Read for CustodyRef<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self::new(BlockRef::read(buf)?, BlockMeta::read(buf)?))
    }
}

impl<D: Digest> Write for CustodyRef<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.reference.write(buf);
        self.meta.write(buf);
    }
}

impl<D: Digest> EncodeSize for CustodyRef<D> {
    fn encode_size(&self) -> usize {
        self.reference.encode_size() + self.meta.encode_size()
    }
}

#[cfg(test)]
impl<D: Digest> CustodyRef<D> {
    pub(in crate::multimmit::marshal) fn for_test<H, B>(block: &Arc<TransactionBlock<H, B>>) -> Self
    where
        H: Hasher<Digest = D>,
        B: Codec + Digestible<Digest = H::Digest>,
    {
        Self::new(
            block.reference(),
            BlockMeta::new(
                block.header().clone(),
                u64::try_from(block.encode_size()).unwrap(),
            ),
        )
    }
}

/// Dense publication coordinate paired with catalog-proven body custody.
pub(in crate::multimmit::marshal) struct OutputRow<D: Digest> {
    pub index: OutputIndex,
    custody: CustodyRef<D>,
}

impl<D: Digest> OutputRow<D> {
    pub(in crate::multimmit::marshal) const fn new(
        index: OutputIndex,
        custody: CustodyRef<D>,
    ) -> Self {
        Self { index, custody }
    }

    pub(in crate::multimmit::marshal) const fn reference(&self) -> BlockRef<D> {
        self.custody.reference()
    }

    pub(in crate::multimmit::marshal) const fn meta(&self) -> &BlockMeta<D> {
        self.custody.meta()
    }

    pub(in crate::multimmit::marshal) const fn into_parts(
        self,
    ) -> (OutputIndex, BlockRef<D>, BlockMeta<D>) {
        let (reference, block) = self.custody.into_parts();
        (self.index, reference, block)
    }
}

/// A complete checkpoint-last commit.
pub(in crate::multimmit::marshal) struct Commit<H, V>
where
    H: Hasher,
    V: Variant,
{
    pub selected: Vec<SelectedLqc<V, H>>,
    pub history: Vec<HistoryOpening<H>>,
    pub outputs: Vec<OutputRow<H::Digest>>,
    pub checkpoint: Checkpoint<H::Digest>,
}

/// A non-authoritative byte-bounded cache of validated producer blocks.
struct CachedBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    encoded_len: usize,
    block: Arc<TransactionBlock<H, B>>,
}

struct BlockCache<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    max_bytes: usize,
    encoded_bytes: usize,
    order: VecDeque<BlockRef<H::Digest>>,
    blocks: HashMap<BlockRef<H::Digest>, CachedBlock<H, B>>,
    by_digest: HashMap<(ChainId, H::Digest), BlockRef<H::Digest>>,
}

impl<H, B> BlockCache<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            max_bytes: max_bytes.get(),
            encoded_bytes: 0,
            order: VecDeque::new(),
            blocks: HashMap::new(),
            by_digest: HashMap::new(),
        }
    }

    /// Retains unique references in insertion order. Oversized blocks are skipped.
    fn insert(
        &mut self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> u64 {
        if self.blocks.contains_key(&reference) {
            return 0;
        }
        let encoded_len = block.encode_size();
        if encoded_len > self.max_bytes {
            return 0;
        }
        let mut evictions = 0u64;
        while self
            .encoded_bytes
            .checked_add(encoded_len)
            .is_none_or(|total| total > self.max_bytes)
        {
            let evicted_reference = self
                .order
                .pop_front()
                .expect("a non-empty cache exceeds its byte bound");
            let block = self
                .blocks
                .remove(&evicted_reference)
                .expect("cache order names a retained block");
            self.by_digest
                .remove(&(evicted_reference.chain(), evicted_reference.digest()));
            self.encoded_bytes -= block.encoded_len;
            evictions = evictions.saturating_add(1);
        }
        self.encoded_bytes += encoded_len;
        self.order.push_back(reference);
        self.by_digest
            .insert((reference.chain(), reference.digest()), reference);
        self.blocks
            .insert(reference, CachedBlock { encoded_len, block });
        evictions
    }

    fn get(&self, reference: &BlockRef<H::Digest>) -> Option<Arc<TransactionBlock<H, B>>> {
        self.blocks
            .get(reference)
            .map(|entry| Arc::clone(&entry.block))
    }

    fn custody(&self, reference: BlockRef<H::Digest>) -> Option<CustodyRef<H::Digest>> {
        let entry = self.blocks.get(&reference)?;
        let encoded_len = u64::try_from(entry.encoded_len).ok()?;
        Some(CustodyRef::new(
            reference,
            BlockMeta::new(entry.block.header().clone(), encoded_len),
        ))
    }

    fn get_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.by_digest
            .get(&(chain, digest))
            .and_then(|reference| self.get(reference))
    }

    fn clear(&mut self) {
        self.encoded_bytes = 0;
        self.order.clear();
        self.blocks.clear();
        self.by_digest.clear();
    }

    fn prune(&mut self, frontiers: &[BlockRef<H::Digest>]) {
        let mut retained = VecDeque::with_capacity(self.order.len());
        while let Some(reference) = self.order.pop_front() {
            if frontiers
                .get(reference.chain().get() as usize)
                .is_some_and(|frontier| reference.height() <= frontier.height())
            {
                let block = self
                    .blocks
                    .remove(&reference)
                    .expect("cache order names a retained block");
                self.by_digest
                    .remove(&(reference.chain(), reference.digest()));
                self.encoded_bytes -= block.encoded_len;
            } else {
                retained.push_back(reference);
            }
        }
        self.order = retained;
    }
}

/// Compact durable progress reported by the catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct Progress<D: Digest> {
    pub generation: u64,
    pub floor: CertificateId<D>,
    pub committed: Option<OutputIndex>,
    pub acknowledged: Option<OutputIndex>,
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;

enum AdmissionMode {
    Buffered,
    Durable,
    Staged(Reply<()>),
}

impl AdmissionMode {
    const fn sync_metadata(&self) -> bool {
        matches!(self, Self::Durable)
    }

    fn fail(self, error: Error) {
        if let Self::Staged(completion) = self {
            drop(completion.send(Err(error)));
        }
    }
}

struct AdmissionCompletion<D: Digest> {
    replies: Vec<Reply<()>>,
    blocks: Vec<BlockRef<D>>,
    timer: histogram::Timer,
    result: Result<(), Error>,
    span: Span,
}

/// One bounded temporary-storage cut not yet handed to the durability pool.
struct PendingAdmission<D: Digest> {
    footprint: AdmissionFootprint,
    replies: Vec<Reply<()>>,
    blocks: Vec<BlockRef<D>>,
    items: usize,
    span: Span,
}

/// Completion token for one accepted ordering commit.
///
/// Tokens resolve in acceptance order after checkpoint-last publication.
pub(in crate::multimmit::marshal) struct CommitToken(oneshot::Receiver<Result<(), Error>>);

impl CommitToken {
    pub(in crate::multimmit::marshal) async fn wait(self) -> Result<(), Error> {
        self.0.await.unwrap_or(Err(Error::Closed))
    }
}

/// Completion of one accepted producer-block custody cut.
#[must_use = "custody is not established until the token completes"]
pub(in crate::multimmit::marshal) struct AdmissionToken(oneshot::Receiver<Result<(), Error>>);

impl AdmissionToken {
    pub(in crate::multimmit::marshal) async fn wait(self) -> Result<(), Error> {
        self.0.await.unwrap_or(Err(Error::Closed))
    }
}

struct PendingCommit<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    publication: storage::CommitPublication<H::Digest>,
    completion: oneshot::Sender<Result<(), Error>>,
    delivery: Option<delivery::DurableBatch<H, B>>,
    delivery_bytes: u64,
    outputs: u64,
    span: Span,
}

impl<H, B> PendingCommit<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn fail(self, error: Error) {
        drop(self.completion.send(Err(error)));
    }
}

/// The fixed two-cut durability pipeline.
///
/// A second cut archives alongside the first cut's checkpoint, but cannot publish its own
/// checkpoint until the first cut has published.
enum CommitState<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Idle,
    Archiving(PendingCommit<H, B>),
    ArchivingBuffered(PendingCommit<H, B>, PendingCommit<H, B>),
    Publishing(PendingCommit<H, B>),
    PublishingArchiving(PendingCommit<H, B>, PendingCommit<H, B>),
    PublishingArchived(PendingCommit<H, B>, PendingCommit<H, B>),
}

impl<H, B> CommitState<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
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

    fn fail(self, error: Error) {
        match self {
            Self::Idle => {}
            Self::Archiving(pending) | Self::Publishing(pending) => pending.fail(error),
            Self::ArchivingBuffered(first, second)
            | Self::PublishingArchiving(first, second)
            | Self::PublishingArchived(first, second) => {
                first.fail(error.clone());
                second.fail(error);
            }
        }
    }
}

enum DurabilityCompletion<D: Digest> {
    Admission(AdmissionCompletion<D>),
    CommitArchives(histogram::Timer, Result<(), Error>),
    CommitCheckpoint(histogram::Timer, Result<(), Error>),
}
type MaybeLqc<V, D> = Option<Arc<Lqc<V, D>>>;
type CustodyValues<H> = Vec<Option<CustodyRef<<H as Hasher>::Digest>>>;

struct CustodyLookup<H: Hasher> {
    values: CustodyValues<H>,
    cache_hits: u64,
    storage_hits: u64,
    misses: u64,
}
type BodyValues<H, B> = Vec<Option<Arc<TransactionBlock<H, B>>>>;
type AvailableBodies<H, B> = HashMap<BlockRef<<H as Hasher>::Digest>, Arc<TransactionBlock<H, B>>>;
/// A bounded request waiting for scheduler capacity or an identical read.
///
/// Planned groups retain exact locators and pin their segments, so logical pruning cannot erase
/// the request's source before it enters the materializer.
struct BodyWaiter<E, H, B>
where
    E: Context,
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    references: Vec<BlockRef<H::Digest>>,
    values: BodyValues<H, B>,
    groups: Vec<BodyReadGroup<E, H, B>>,
    reply: Reply<BodyValues<H, B>>,
}
type BodyCandidate<H, B> = (
    BlockRef<<H as Hasher>::Digest>,
    Option<Arc<TransactionBlock<H, B>>>,
);
type HistorySegment<H> = Vec<Arc<TipRecord<<H as Hasher>::Digest>>>;
type HeaderSegment<H> = Vec<TransactionBlockHeader<<H as Hasher>::Digest>>;
type HeaderSegments<H> = Vec<HeaderSegment<H>>;
type OutputRefs<H> = Vec<StoredRef<<H as Hasher>::Digest>>;
type OutputReadResult<H> = Result<storage::FinalBlockReadOutcome<H>, Error>;
type OutputReads<H> = Pool<(u64, OutputReadResult<H>)>;
type CustodyWaiter<H> = (
    Vec<BlockRef<<H as Hasher>::Digest>>,
    Reply<CustodyValues<H>>,
);
type AdmissionCommand<H, V, B> = (Vec<Admission<H, V, B>>, AdmissionMode, Reply<()>);

struct HistorySegmentState<H: Hasher> {
    commitment: H::Digest,
    max_items: usize,
    max_bytes: usize,
    item_bytes: usize,
    records: HistorySegment<H>,
}

struct HeaderBranch<H: Hasher> {
    reference: Option<BlockRef<H::Digest>>,
    max_items: usize,
    item_bytes: usize,
    headers: HeaderSegment<H>,
}

struct HeaderSegmentsState<H: Hasher> {
    max_bytes: usize,
    branches: Vec<HeaderBranch<H>>,
}

struct OutputRefsState<H: Hasher> {
    next: u64,
    remaining: usize,
    max_bytes: u64,
    encoded_bytes: u64,
    outputs: OutputRefs<H>,
    // Ready suffixes retain metadata credits until the contiguous prefix is resolved.
    reads: VecDeque<Option<OutputReadResult<H>>>,
}

impl<H: Hasher> OutputRefsState<H> {
    /// Whether the contiguous results determine a response or require archive continuation.
    fn prefix_ready(&self) -> bool {
        let mut encoded_bytes = self.encoded_bytes;
        let mut nonempty = !self.outputs.is_empty();
        for result in &self.reads {
            match result {
                None => return false,
                Some(Ok(FinalizedReadOutcome::Done(Some((_, meta))))) => {
                    let next = encoded_bytes.checked_add(meta.block().encoded_len());
                    if nonempty && next.is_none_or(|total| total > self.max_bytes) {
                        return true;
                    }
                    encoded_bytes = next.unwrap_or(u64::MAX);
                    nonempty = true;
                }
                Some(_) => return true,
            }
        }
        true
    }
}

enum MetadataJob<E: Context, H: Hasher> {
    History {
        state: HistorySegmentState<H>,
        reply: Reply<HistorySegment<H>>,
        step: storage::HistoryRead<E, H>,
    },
    Headers {
        state: HeaderSegmentsState<H>,
        reply: Reply<HeaderSegments<H>>,
        steps: Pool<(usize, Result<storage::FinalBlockReadOutcome<H>, Error>)>,
    },
    Outputs {
        state: OutputRefsState<H>,
        reply: Reply<OutputRefs<H>>,
        steps: OutputReads<H>,
    },
}

enum MetadataCompletion<E: Context, H: Hasher> {
    Canceled(usize),
    History {
        state: HistorySegmentState<H>,
        reply: Reply<HistorySegment<H>>,
        result: Result<storage::HistoryReadOutcome<E, H>, Error>,
    },
    Headers {
        state: HeaderSegmentsState<H>,
        reply: Reply<HeaderSegments<H>>,
        steps: Pool<(usize, Result<storage::FinalBlockReadOutcome<H>, Error>)>,
        index: usize,
        result: Result<storage::FinalBlockReadOutcome<H>, Error>,
    },
    Outputs {
        state: OutputRefsState<H>,
        reply: Reply<OutputRefs<H>>,
        steps: OutputReads<H>,
    },
}

impl<E: Context, H: Hasher> MetadataCompletion<E, H> {
    fn steps(&self) -> usize {
        match self {
            Self::Canceled(steps) => *steps,
            Self::History { .. } => 1,
            Self::Headers { steps, .. } => 1 + steps.len(),
            Self::Outputs { state, .. } => state.reads.len(),
        }
    }
}

impl<E: Context, H: Hasher> MetadataJob<E, H> {
    fn steps(&self) -> usize {
        match self {
            Self::History { .. } => 1,
            Self::Headers { steps, .. } => steps.len(),
            Self::Outputs { state, .. } => state.reads.len(),
        }
    }

    async fn execute(self) -> MetadataCompletion<E, H> {
        match self {
            Self::History {
                state,
                mut reply,
                step,
            } => {
                let result = select! {
                    _ = reply.closed() => return MetadataCompletion::Canceled(1),
                    result = step.execute() => result,
                };
                MetadataCompletion::History {
                    state,
                    reply,
                    result,
                }
            }
            Self::Headers {
                state,
                mut reply,
                mut steps,
            } => {
                let count = steps.len();
                let (index, result) = select! {
                    _ = reply.closed() => return MetadataCompletion::Canceled(count),
                    completion = steps.next_completed() => completion,
                };
                MetadataCompletion::Headers {
                    state,
                    reply,
                    steps,
                    index,
                    result,
                }
            }
            Self::Outputs {
                mut state,
                mut reply,
                mut steps,
            } => {
                let count = state.reads.len();
                while !state.prefix_ready() {
                    let completed = select! {
                        _ = reply.closed() => return MetadataCompletion::Canceled(count),
                        completed = steps.next_completed() => completed,
                    };
                    let mut completed = Some(completed);
                    while let Some((index, result)) = completed {
                        let offset = usize::try_from(index - state.next)
                            .expect("the read belongs to the active output window");
                        state.reads[offset] = Some(result);
                        completed = steps.next_completed().now_or_never();
                    }
                }
                MetadataCompletion::Outputs {
                    state,
                    reply,
                    steps,
                }
            }
        }
    }
}

struct DeliveryCursorControl {
    generation: u64,
    acknowledged: Option<OutputIndex>,
    reply: Option<Reply<()>>,
}

impl DeliveryCursorControl {
    fn fail(self, error: Error) {
        if let Some(reply) = self.reply {
            drop(reply.send(Err(error)));
        }
    }
}

impl Policy for DeliveryCursorControl {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, control: Self) {
        if control.reply.is_none()
            && let Some(last) = overflow.back_mut()
            && last.reply.is_none()
            && last.generation == control.generation
        {
            last.acknowledged = last.acknowledged.max(control.acknowledged);
            return;
        }
        overflow.push_back(control);
    }
}

enum CatalogEvent<D, A, R, M, S, C, Q> {
    Durability(D),
    DeliveryCursor(A),
    Metadata(R),
    Materialization(M),
    Seal(S),
    Command(C),
    Read(Q),
}

#[allow(clippy::too_many_arguments)]
async fn next_catalog_event<D, A, R, M, S, C, Q>(
    durability: D,
    acknowledgement: A,
    metadata: R,
    materialization: M,
    seal: S,
    command: C,
    read: Q,
    accept_acknowledgements: bool,
    accept_commands: bool,
) -> CatalogEvent<D::Output, A::Output, R::Output, M::Output, S::Output, C::Output, Q::Output>
where
    D: Future,
    A: Future,
    R: Future,
    M: Future,
    S: Future,
    C: Future,
    Q: Future,
{
    let acknowledgement = async move {
        if accept_acknowledgements {
            acknowledgement.await
        } else {
            pending().await
        }
    };
    let command = async move {
        if accept_commands {
            command.await
        } else {
            pending().await
        }
    };
    select! {
        completion = durability => CatalogEvent::Durability(completion),
        acknowledgement = acknowledgement => CatalogEvent::DeliveryCursor(acknowledgement),
        completion = metadata => CatalogEvent::Metadata(completion),
        completion = materialization => CatalogEvent::Materialization(completion),
        completion = seal => CatalogEvent::Seal(completion),
        command = command => CatalogEvent::Command(command),
        read = read => CatalogEvent::Read(read),
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum InstallCut {
    Intent,
    Archived,
    Published,
}

macro_rules! request_methods {
    ($($name:ident($($argument:ident: $ty:ty),*) -> $output:ty => $make:expr;)+) => {$(
        #[tracing::instrument(
            name = "multimmit.marshal.catalog.request",
            level = "debug",
            skip_all,
            fields(operation = stringify!($name))
        )]
        pub async fn $name(&self, $($argument: $ty),*) -> Result<$output, Error> {
            self.request($make).await
        }
    )+};
}

enum Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Admit(Vec<Admission<H, V, B>>, AdmissionMode, Reply<()>),
    Lqc(CertificateId<H::Digest>, Reply<MaybeLqc<V, H::Digest>>),
    FinalLqc(CertificateId<H::Digest>, Reply<bool>),
    LatestLqc(Reply<MaybeLqc<V, H::Digest>>),
    History(H::Digest, Reply<Option<Arc<TipRecord<H::Digest>>>>),
    HistorySegment(H::Digest, usize, usize, Reply<HistorySegment<H>>),
    HeaderSegments(
        Vec<(BlockRef<H::Digest>, usize)>,
        usize,
        Reply<HeaderSegments<H>>,
    ),
    WaitForCustody(Vec<BlockRef<H::Digest>>, Reply<CustodyValues<H>>),
    Bodies(Vec<BlockRef<H::Digest>>, Reply<BodyValues<H, B>>),
    BodyCandidateByDigest(ChainId, H::Digest, Reply<Option<BodyCandidate<H, B>>>),
    OutputRefs(OutputIndex, usize, NonZeroUsize, Reply<OutputRefs<H>>),
    Commit(
        Commit<H, V>,
        Vec<delivery::DurableOutput<H, B>>,
        Reply<CommitToken>,
    ),
    #[cfg(test)]
    CommitThroughCheckpoint(Commit<H, V>, Reply<()>),
    #[cfg(test)]
    Pause(oneshot::Receiver<()>, oneshot::Sender<()>, Reply<()>),
    Install(
        Checkpoint<H::Digest>,
        Prune,
        Arc<Lqc<V, H::Digest>>,
        Arc<TipRecord<H::Digest>>,
        Reply<delivery::ResetWaiter>,
    ),
    #[cfg(test)]
    InstallThrough(
        Checkpoint<H::Digest>,
        Prune,
        Arc<Lqc<V, H::Digest>>,
        Arc<TipRecord<H::Digest>>,
        InstallCut,
        Reply<()>,
    ),
    Prune(u64, Reply<()>),
    Promoted(Vec<BlockRef<H::Digest>>, Reply<()>),
    Checkpoint(Reply<Checkpoint<H::Digest>>),
    Progress(Reply<Progress<H::Digest>>),
}

struct TracedCommand<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    command: Command<H, V, B>,
    span: Span,
    /// Client-side enqueue time; present only on commands stamped at the mailbox boundary.
    enqueued: Option<SystemTime>,
}

impl<H, V, B> TracedCommand<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn new(command: Command<H, V, B>) -> Self {
        Self {
            command,
            span: Span::current(),
            enqueued: None,
        }
    }

    fn stamped(command: Command<H, V, B>, enqueued: SystemTime) -> Self {
        Self {
            command,
            span: Span::current(),
            enqueued: Some(enqueued),
        }
    }

    const fn with_span(command: Command<H, V, B>, span: Span) -> Self {
        Self {
            command,
            span,
            enqueued: None,
        }
    }

    fn fail(self, error: Error) {
        self.command.fail(error);
    }
}

impl<H, V, B> Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    const fn kind(&self) -> &'static str {
        match self {
            Self::Admit(_, _, _) => "admit",
            Self::Lqc(_, _) => "lqc",
            Self::FinalLqc(_, _) => "final_lqc",
            Self::LatestLqc(_) => "latest_lqc",
            Self::History(_, _) => "history",
            Self::HistorySegment(_, _, _, _) => "history_segment",
            Self::HeaderSegments(_, _, _) => "header_segments",
            Self::WaitForCustody(_, _) => "wait_for_custody",
            Self::Bodies(_, _) => "bodies",
            Self::BodyCandidateByDigest(_, _, _) => "body_candidate_by_digest",
            Self::OutputRefs(_, _, _, _) => "output_refs",
            Self::Commit(_, _, _) => "commit",
            #[cfg(test)]
            Self::CommitThroughCheckpoint(_, _) => "commit_through_checkpoint",
            #[cfg(test)]
            Self::Pause(_, _, _) => "pause",
            Self::Install(_, _, _, _, _) => "install",
            #[cfg(test)]
            Self::InstallThrough(_, _, _, _, _, _) => "install_through",
            Self::Prune(_, _) => "prune",
            Self::Promoted(_, _) => "promoted",
            Self::Checkpoint(_) => "checkpoint",
            Self::Progress(_) => "progress",
        }
    }

    const fn commit_barrier(&self) -> bool {
        match self {
            Self::Install(_, _, _, _, _) | Self::Prune(_, _) => true,
            #[cfg(test)]
            Self::InstallThrough(_, _, _, _, _, _) => true,
            _ => false,
        }
    }

    const fn body_barrier(&self) -> bool {
        match self {
            Self::Install(_, _, _, _, _) => true,
            #[cfg(test)]
            Self::InstallThrough(_, _, _, _, _, _) => true,
            _ => false,
        }
    }

    fn read_canceled(&self) -> bool {
        match self {
            Self::Bodies(_, reply) => reply.is_closed(),
            Self::BodyCandidateByDigest(_, _, reply) => reply.is_closed(),
            Self::HeaderSegments(_, _, reply) => reply.is_closed(),
            Self::OutputRefs(_, _, _, reply) => reply.is_closed(),
            _ => unreachable!("only independent reads use the read lane"),
        }
    }

    async fn read_closed(&mut self) {
        match self {
            Self::Bodies(_, reply) => reply.closed().await,
            Self::BodyCandidateByDigest(_, _, reply) => reply.closed().await,
            Self::HeaderSegments(_, _, reply) => reply.closed().await,
            Self::OutputRefs(_, _, _, reply) => reply.closed().await,
            _ => unreachable!("only independent reads use the read lane"),
        }
    }

    fn fail(self, error: Error) {
        match self {
            #[cfg(test)]
            Self::InstallThrough(_, _, _, _, _, reply) => drop(reply.send(Err(error))),
            Self::Commit(_, _, reply) => drop(reply.send(Err(error))),
            Self::Install(_, _, _, _, reply) => drop(reply.send(Err(error))),
            Self::Admit(_, mode, reply) => {
                mode.fail(error.clone());
                drop(reply.send(Err(error)));
            }
            Self::Prune(_, reply) | Self::Promoted(_, reply) => drop(reply.send(Err(error))),
            #[cfg(test)]
            Self::CommitThroughCheckpoint(_, reply) => drop(reply.send(Err(error))),
            #[cfg(test)]
            Self::Pause(_, _, reply) => drop(reply.send(Err(error))),
            Self::Lqc(_, reply) => drop(reply.send(Err(error))),
            Self::FinalLqc(_, reply) => drop(reply.send(Err(error))),
            Self::LatestLqc(reply) => drop(reply.send(Err(error))),
            Self::History(_, reply) => drop(reply.send(Err(error))),
            Self::HistorySegment(_, _, _, reply) => drop(reply.send(Err(error))),
            Self::HeaderSegments(_, _, reply) => drop(reply.send(Err(error))),
            Self::WaitForCustody(_, reply) => drop(reply.send(Err(error))),
            Self::Bodies(_, reply) => drop(reply.send(Err(error))),
            Self::BodyCandidateByDigest(_, _, reply) => drop(reply.send(Err(error))),
            Self::OutputRefs(_, _, _, reply) => drop(reply.send(Err(error))),
            Self::Checkpoint(reply) => drop(reply.send(Err(error))),
            Self::Progress(reply) => drop(reply.send(Err(error))),
        }
    }
}

/// Leaves a capacity-blocked read at the mailbox head until it can start or is canceled.
async fn next_read<H, V, B>(
    reads: &mut mailbox::Receiver<TracedCommand<H, V, B>>,
    deferred: &mut Option<TracedCommand<H, V, B>>,
    accept: bool,
    ready: bool,
) -> Option<TracedCommand<H, V, B>>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    if !accept {
        return pending().await;
    }
    if let Some(read) = deferred {
        if !ready {
            read.command.read_closed().await;
        }
        return deferred.take();
    }
    reads.recv().await
}

impl<H, V, B> Policy for TracedCommand<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) {
        overflow.push_back(command);
    }
}

/// Cloneable client for the bounded catalog mailbox.
pub(in crate::multimmit::marshal) struct CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    commands: mailbox::Sender<TracedCommand<H, V, B>>,
    delivery_cursors: mailbox::Sender<DeliveryCursorControl>,
    independent_reads: mailbox::Sender<TracedCommand<H, V, B>>,
    admission_capacity: usize,
    /// Reads the runtime clock at enqueue so the actor can measure mailbox dwell.
    now: EnqueueClock,
}

/// Runtime-clock accessor shared with catalog clients.
///
/// Clients stay generic only over protocol types, so the runtime clock crosses this boundary
/// as an erased closure; the call runs once per command, off every hot path.
type EnqueueClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

impl<H, V, B> Clone for CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            delivery_cursors: self.delivery_cursors.clone(),
            independent_reads: self.independent_reads.clone(),
            admission_capacity: self.admission_capacity,
            now: self.now.clone(),
        }
    }
}

impl<H, V, B> CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    async fn request<T>(
        &self,
        make: impl FnOnce(Reply<T>) -> Command<H, V, B>,
    ) -> Result<T, Error> {
        let (reply, receiver) = oneshot::channel();
        let command = TracedCommand::stamped(make(reply), (self.now)());
        // These lookups may overtake queued admissions and observe an earlier miss. They
        // establish neither custody nor an admission barrier; custody checks stay FIFO.
        let mailbox = match &command.command {
            Command::BodyCandidateByDigest(..)
            | Command::HeaderSegments(..)
            | Command::OutputRefs(..) => &self.independent_reads,
            _ => &self.commands,
        };
        if mailbox.enqueue(command) == Feedback::Closed {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    request_methods! {
        admit_lqc(view: View, id: CertificateId<H::Digest>, proof: Arc<Lqc<V, H::Digest>>) -> ()
            => |reply| Command::Admit(vec![Admission::Lqc(view, id, proof)], AdmissionMode::Durable, reply);
        stage_lqc(view: View, id: CertificateId<H::Digest>, proof: Arc<Lqc<V, H::Digest>>) -> ()
            => |reply| Command::Admit(vec![Admission::Lqc(view, id, proof)], AdmissionMode::Buffered, reply);
        stage_history(view: View, commitment: H::Digest, record: Arc<TipRecord<H::Digest>>) -> ()
            => |reply| Command::Admit(vec![Admission::History(view, commitment, record)], AdmissionMode::Buffered, reply);
        admit_block(reference: BlockRef<H::Digest>, block: Arc<TransactionBlock<H, B>>) -> ()
            => |reply| Command::Admit(vec![Admission::Block(reference, block)], AdmissionMode::Durable, reply);
        lqc(id: CertificateId<H::Digest>) -> Option<Arc<Lqc<V, H::Digest>>>
            => |reply| Command::Lqc(id, reply);
        final_lqc(id: CertificateId<H::Digest>) -> bool
            => |reply| Command::FinalLqc(id, reply);
        latest_lqc() -> Option<Arc<Lqc<V, H::Digest>>> => Command::LatestLqc;
        history(commitment: H::Digest) -> Option<Arc<TipRecord<H::Digest>>>
            => |reply| Command::History(commitment, reply);
        history_segment(commitment: H::Digest, max_items: usize, max_bytes: usize) -> HistorySegment<H>
            => |reply| Command::HistorySegment(commitment, max_items, max_bytes, reply);
        header_segments(requests: Vec<(BlockRef<H::Digest>, usize)>, max_bytes: usize) -> HeaderSegments<H>
            => |reply| Command::HeaderSegments(requests, max_bytes, reply);
        wait_for_custody(references: Vec<BlockRef<H::Digest>>) -> CustodyValues<H>
            => |reply| Command::WaitForCustody(references, reply);
        bodies(references: Vec<BlockRef<H::Digest>>) -> BodyValues<H, B>
            => |reply| Command::Bodies(references, reply);
        prune(generation: u64) -> () => |reply| Command::Prune(generation, reply);
        promoted(frontiers: Vec<BlockRef<H::Digest>>) -> ()
            => |reply| Command::Promoted(frontiers, reply);
        progress() -> Progress<H::Digest> => Command::Progress;
        checkpoint() -> Checkpoint<H::Digest> => Command::Checkpoint;
    }

    /// Reads already-committed custody independently of queued admissions. Callers must have
    /// obtained these exact references from a published checkpoint before issuing the request.
    pub(in crate::multimmit::marshal) async fn committed_bodies(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        let (reply, receiver) = oneshot::channel();
        let command = TracedCommand::stamped(Command::Bodies(references, reply), (self.now)());
        if self.independent_reads.enqueue(command) == Feedback::Closed {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    /// Publishes an already durable delivery cursor to catalog's progress and pruning mirror.
    pub(in crate::multimmit::marshal) fn delivery_cursor(
        &self,
        generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Feedback {
        self.delivery_cursors.enqueue(DeliveryCursorControl {
            generation,
            acknowledged,
            reply: None,
        })
    }

    /// Publishes a durable generation reset before completing floor installation.
    pub(in crate::multimmit::marshal) async fn reset_delivery_cursor(
        &self,
        generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Result<(), Error> {
        let (reply, receiver) = oneshot::channel();
        if self.delivery_cursors.enqueue(DeliveryCursorControl {
            generation,
            acknowledged,
            reply: Some(reply),
        }) == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    /// Returns an exact pending block without exposing catalog storage ownership.
    #[tracing::instrument(name = "multimmit.marshal.catalog.block", level = "debug", skip_all)]
    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        Ok(self.bodies(vec![reference]).await?.pop().flatten())
    }

    /// Returns a pending block by its chain and authenticated header digest.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.block_by_digest",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn block_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        let Some((reference, block)) = self
            .request(|reply| Command::BodyCandidateByDigest(chain, digest, reply))
            .await?
        else {
            return Ok(None);
        };
        match block {
            Some(block) => Ok(Some(block)),
            None => self.block(reference).await,
        }
    }

    /// Queues a slice of validated producer blocks together for catalog admission.
    ///
    /// This preserves the admission bound while making ready blocks available for coalescing.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.stage_blocks",
        level = "debug",
        skip_all,
        fields(blocks = blocks.len())
    )]
    pub(in crate::multimmit::marshal) async fn stage_blocks(
        &self,
        blocks: &[Arc<TransactionBlock<H, B>>],
    ) -> Result<(), Error> {
        if blocks.is_empty() {
            return Ok(());
        }
        try_join_all(blocks.chunks(self.admission_capacity).map(|blocks| {
            self.request(|reply| {
                Command::Admit(
                    blocks
                        .iter()
                        .map(|block| Admission::Block(block.reference(), Arc::clone(block)))
                        .collect(),
                    AdmissionMode::Buffered,
                    reply,
                )
            })
        }))
        .await
        .map(|_| ())
    }

    /// Stages one producer block and returns its exact custody completion.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.stage_block",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn stage_block(
        &self,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<AdmissionToken, Error> {
        let (completion, receiver) = oneshot::channel();
        self.request(|reply| {
            Command::Admit(
                vec![Admission::Block(block.reference(), block)],
                AdmissionMode::Staged(completion),
                reply,
            )
        })
        .await?;
        Ok(AdmissionToken(receiver))
    }

    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn admit_history(
        &self,
        view: View,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| {
            Command::Admit(
                vec![Admission::History(view, commitment, record)],
                AdmissionMode::Durable,
                reply,
            )
        })
        .await
    }

    /// Installs a durable floor and waits until delivery has crossed its generation reset.
    #[tracing::instrument(name = "multimmit.marshal.catalog.install", level = "info", skip_all)]
    pub(in crate::multimmit::marshal) async fn install(
        &self,
        checkpoint: Checkpoint<H::Digest>,
        prune: Prune,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let reset = self
            .request(|reply| Command::Install(checkpoint, prune, proof, history, reply))
            .await?;
        reset
            .wait()
            .await
            .then_some(())
            .ok_or(Error::DeliveryClosed)
    }

    /// Reads a dense committed prefix as compact references.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.output_refs",
        level = "info",
        skip_all,
        fields(start = start.get(), max_items = max_items.get(), max_bytes = max_bytes.get())
    )]
    pub(in crate::multimmit::marshal) async fn output_refs(
        &self,
        start: OutputIndex,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
    ) -> Result<OutputRefs<H>, Error> {
        self.request(|reply| Command::OutputRefs(start, max_items.get(), max_bytes, reply))
            .await
    }

    /// Accepts one bounded commit with recovered bodies retained by its caller.
    ///
    /// Handoff bodies are ordered like their output rows and remain advisory: publication depends
    /// only on durable custody, and delivery materializes any body omitted by the shared hot-byte
    /// bound.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.commit",
        level = "info",
        skip_all,
        fields(
            selected = batch.selected.len(),
            history = batch.history.len(),
            outputs = batch.outputs.len(),
            handoff = handoff.len(),
        )
    )]
    pub(in crate::multimmit::marshal) async fn start_commit(
        &self,
        batch: Commit<H, V>,
        handoff: Vec<delivery::DurableOutput<H, B>>,
    ) -> Result<CommitToken, Error> {
        self.request(|reply| Command::Commit(batch, handoff, reply))
            .await
    }

    /// Commits one bounded ordering batch durably.
    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn commit(
        &self,
        batch: Commit<H, V>,
    ) -> Result<(), Error> {
        self.start_commit(batch, Vec::new()).await?.wait().await
    }

    #[cfg(test)]
    async fn admit_finality(
        &self,
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| {
            Command::Admit(
                vec![Admission::Finality {
                    view,
                    id,
                    proof,
                    history,
                }],
                AdmissionMode::Durable,
                reply,
            )
        })
        .await
    }

    #[cfg(test)]
    async fn commit_through_checkpoint(&self, batch: Commit<H, V>) -> Result<(), Error> {
        self.request(|reply| Command::CommitThroughCheckpoint(batch, reply))
            .await
    }

    #[cfg(test)]
    async fn install_through(
        &self,
        checkpoint: Checkpoint<H::Digest>,
        prune: Prune,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
        phase: InstallCut,
    ) -> Result<(), Error> {
        self.request(|reply| {
            Command::InstallThrough(checkpoint, prune, proof, history, phase, reply)
        })
        .await
    }
}

struct Catalog<R, T, E, H, V, B>
where
    R: Clock + Spawner,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    clock: R,
    stores: Stores<T, E, H, V, B>,
    materializer: Materializer<R, E, H, B>,
    body_waiters: VecDeque<BodyWaiter<E, H, B>>,
    body_waiter_capacity: usize,
    /// Newly admitted blocks protected from historical read churn.
    block_cache: BlockCache<H, B>,
    /// Storage reads retained for request reuse and sparse delivery handoff.
    materialized_cache: BlockCache<H, B>,
    max_commit_outputs: usize,
    max_commit_block_bytes: usize,
    max_block_bytes: usize,
    delivery: DeliveryClient<H, B>,
    promoter: Option<promoter::Client<H, B>>,
    max_hot_block_bytes: u64,
    max_materialized_block_bytes: u64,
    pending_delivery_bytes: u64,
    commands: mailbox::Receiver<TracedCommand<H, V, B>>,
    delivery_cursors: mailbox::Receiver<DeliveryCursorControl>,
    independent_reads: mailbox::Receiver<TracedCommand<H, V, B>>,
    independent_reads_open: bool,
    deferred_read: Option<TracedCommand<H, V, B>>,
    deferred: Option<TracedCommand<H, V, B>>,
    durability: Pool<DurabilityCompletion<H::Digest>>,
    // Block metadata remains catalog-owned during admissions. History continuations can need
    // the pending-history journal, so they run only after the admission returns ownership.
    block_reads: Pool<MetadataCompletion<E, H>>,
    history_reads: Pool<MetadataCompletion<E, H>>,
    metadata_steps: usize,
    metadata_step_capacity: usize,
    /// In-flight sealed-segment proofs; optimization-only writes that never gate barriers.
    seals: Pool<(Vec<u64>, Result<(), Error>)>,
    durability_capacity: usize,
    // Every ready resolver request may await the admission cut that establishes local custody.
    custody_waiter_capacity: usize,
    // Delivery owns the durable cursor. Catalog retains only its current-generation mirror for
    // public progress and finalized pruning.
    durable_acknowledged: Option<OutputIndex>,
    durable_checkpoint: Checkpoint<H::Digest>,
    accepted_checkpoint: Checkpoint<H::Digest>,
    commit_state: CommitState<H, B>,
    admission_active: bool,
    pending_admission: Option<PendingAdmission<H::Digest>>,
    // A body can be read as soon as it is buffered, but it cannot establish custody until the
    // first admission cut containing it completes.
    volatile_blocks: HashSet<BlockRef<H::Digest>>,
    custody_waiters: VecDeque<CustodyWaiter<H>>,
    cleanup_due: Option<storage::PendingCleanup>,
    commits_since_cleanup: usize,
    metrics: metrics::Catalog,
}

impl<R, T, E, H, V, B> Catalog<R, T, E, H, V, B>
where
    R: Clock + Spawner,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    fn barrier_ready(&self) -> bool {
        self.commit_state.is_idle()
            && !self.admission_active
            && self.pending_admission.is_none()
            && self.durability.is_empty()
    }

    fn command_ready(&self, command: &Command<H, V, B>) -> bool {
        match command {
            Command::Promoted(_, _) => !self.admission_active && self.pending_admission.is_none(),
            Command::Admit(admissions, _, _)
                if !admissions.is_empty() && admissions.len() <= self.durability_capacity =>
            {
                let pending = self.pending_admission.as_ref().map_or(0, |cut| cut.items);
                admissions.len() <= self.durability_capacity - pending
            }
            Command::Bodies(_, _) => self.body_waiters.len() < self.body_waiter_capacity,
            Command::HistorySegment(_, max_items, max_bytes, _)
                if *max_items != 0 && *max_bytes != 0 =>
            {
                self.metadata_has_capacity(1)
            }
            Command::HeaderSegments(requests, max_bytes, _)
                if *max_bytes != 0
                    && requests.len() <= self.metadata_step_capacity
                    && requests.iter().all(|(_, max_items)| *max_items != 0) =>
            {
                self.metadata_has_capacity(requests.len())
            }
            Command::OutputRefs(_, _, _, _) => self.metadata_has_capacity(1),
            command => {
                !command.commit_barrier()
                    || (self.barrier_ready()
                        && (!command.body_barrier()
                            || (self.materializer.is_idle() && self.metadata_steps == 0)))
            }
        }
    }

    async fn run(mut self) -> Result<(), Error> {
        let result = self.run_loop().await;
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }

    async fn run_loop(&mut self) -> Result<(), Error> {
        let mut commands_open = true;
        let mut delivery_cursors_open = true;
        loop {
            let started = self.clock.current();
            let admission = self.start_admission_sync().await;
            if !matches!(admission, Ok(false)) {
                self.metrics
                    .work("internal", "admission_start", started, self.clock.current());
            }
            if admission? {
                continue;
            }

            if delivery_cursors_open {
                match self.delivery_cursors.try_recv() {
                    Ok(control) => {
                        let started = self.clock.current();
                        let result = self.process_delivery_cursor(control);
                        self.metrics.work(
                            "completion",
                            "delivery_cursor",
                            started,
                            self.clock.current(),
                        );
                        result?;
                        continue;
                    }
                    Err(TryRecvError::Disconnected) => delivery_cursors_open = false,
                    Err(TryRecvError::Empty) => {}
                }
            }

            // Service at most one independent read before returning to mutable work. A floor
            // installation closes intake while its existing readers drain.
            let accept_reads = self.accept_independent_reads();
            let read_ready = self.deferred_read_ready();
            if let Some(read) = next_read(
                &mut self.independent_reads,
                &mut self.deferred_read,
                accept_reads,
                read_ready,
            )
            .now_or_never()
            {
                match read {
                    Some(read) => self.process_read(read)?,
                    None => self.independent_reads_open = false,
                }
            }

            if let Some(command) = self.deferred.take() {
                if self.command_ready(&command.command) {
                    self.process_command(command).await?;
                    continue;
                }
                self.deferred = Some(command);
            // The biased select below services ready internal completions before more intake.
            // Direct draining is safe only when no completion can become ready.
            } else if commands_open
                && self.durability.is_empty()
                && self.metadata_steps == 0
                && self.seals.is_empty()
                && self.materializer.is_idle()
            {
                match self.commands.try_recv() {
                    Ok(mut command) => {
                        self.note_intake(&mut command);
                        self.process_command(command).await?;
                        continue;
                    }
                    Err(TryRecvError::Disconnected) => commands_open = false,
                    Err(TryRecvError::Empty) => {}
                }
            }

            if !commands_open
                && !delivery_cursors_open
                && !self.independent_reads_open
                && self.deferred_read.is_none()
                && self.deferred.is_none()
                && self.pending_admission.is_none()
                && !self.admission_active
                && self.durability.is_empty()
                && self.metadata_steps == 0
                && self.seals.is_empty()
                && self.materializer.is_idle()
                && self.body_waiters.is_empty()
            {
                return Ok(());
            }

            let waiting_for = self
                .deferred
                .as_ref()
                .map_or("event", |command| command.command.kind());
            let started = self.clock.current();
            let accept_independent_reads = self.accept_independent_reads();
            let read_ready = self.deferred_read_ready();
            let event = next_catalog_event(
                self.durability.next_completed(),
                self.delivery_cursors.recv(),
                async {
                    select! {
                        completion = self.history_reads.next_completed() => completion,
                        completion = self.block_reads.next_completed() => completion,
                    }
                },
                self.materializer.complete_next(),
                self.seals.next_completed(),
                self.commands.recv(),
                next_read(
                    &mut self.independent_reads,
                    &mut self.deferred_read,
                    accept_independent_reads,
                    read_ready,
                ),
                delivery_cursors_open,
                commands_open && self.deferred.is_none(),
            )
            .await;
            self.metrics
                .work("wait", waiting_for, started, self.clock.current());
            let operation = match &event {
                CatalogEvent::Durability(DurabilityCompletion::Admission(_)) => Some("admission"),
                CatalogEvent::Durability(DurabilityCompletion::CommitArchives(_, _)) => {
                    Some("commit_archives")
                }
                CatalogEvent::Durability(DurabilityCompletion::CommitCheckpoint(_, _)) => {
                    Some("checkpoint")
                }
                CatalogEvent::DeliveryCursor(Some(_)) => Some("delivery_cursor"),
                CatalogEvent::Metadata(_) => Some("metadata"),
                CatalogEvent::Seal(_) => Some("seal"),
                CatalogEvent::Materialization(_) => Some("materialization"),
                CatalogEvent::Command(_)
                | CatalogEvent::Read(_)
                | CatalogEvent::DeliveryCursor(None) => None,
            };
            let started = self.clock.current();
            let result = async {
                match event {
                    CatalogEvent::Durability(completion) => {
                        self.complete_durability(completion).await?;
                    }
                    CatalogEvent::DeliveryCursor(Some(control)) => {
                        self.process_delivery_cursor(control)?;
                    }
                    CatalogEvent::DeliveryCursor(None) => delivery_cursors_open = false,
                    CatalogEvent::Metadata(completion) => {
                        self.complete_metadata(completion)?;
                    }
                    CatalogEvent::Seal((sealed, result)) => {
                        result?;
                        let pinned = self.pinned_body_segments();
                        let reclaimed = self.stores.finish_pending_seals(sealed, &pinned).await?;
                        self.materializer.release_readers(reclaimed);
                    }
                    CatalogEvent::Materialization(completion) => {
                        self.finish_materialization(completion)?;
                    }
                    CatalogEvent::Command(Some(mut command)) => {
                        self.note_intake(&mut command);
                        self.process_command(command).await?;
                    }
                    CatalogEvent::Command(None) => commands_open = false,
                    CatalogEvent::Read(Some(read)) => self.process_read(read)?,
                    CatalogEvent::Read(None) => self.independent_reads_open = false,
                }
                Ok::<_, Error>(())
            }
            .await;
            if let Some(operation) = operation {
                self.metrics
                    .work("completion", operation, started, self.clock.current());
            }
            result?;
        }
    }

    fn accept_independent_reads(&self) -> bool {
        self.independent_reads_open
            && self
                .deferred
                .as_ref()
                .is_none_or(|command| !command.command.body_barrier())
    }

    fn deferred_read_ready(&self) -> bool {
        self.deferred_read
            .as_ref()
            .is_none_or(|read| self.command_ready(&read.command))
    }

    fn process_read(&mut self, read: TracedCommand<H, V, B>) -> Result<(), Error> {
        if read.command.read_canceled() {
            return Ok(());
        }
        if !self.command_ready(&read.command) {
            assert!(self.deferred_read.is_none());
            self.deferred_read = Some(read);
            return Ok(());
        }
        let operation = read.command.kind();
        let span = info_span!(parent: &read.span, "multimmit.marshal.catalog.process",
            command = operation, handler_ns = tracing::field::Empty);
        let started = self.clock.current();
        let result = {
            let _guard = span.enter();
            self.process_lookup(read.command)
        };
        let finished = self.clock.current();
        self.metrics.work("command", operation, started, finished);
        span.record(
            "handler_ns",
            u64::try_from(
                finished
                    .duration_since(started)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(u64::MAX),
        );
        result
    }

    fn process_lookup(&mut self, command: Command<H, V, B>) -> Result<(), Error> {
        match command {
            Command::Bodies(references, reply) => self.process_bodies(references, reply),
            Command::BodyCandidateByDigest(chain, digest, reply) => {
                let candidate = match self.cached_block_by_digest(chain, digest) {
                    Some(block) => Some((block.reference(), Some(block))),
                    None => self
                        .stores
                        .pending_reference_by_digest(chain, digest)
                        .map(|reference| (reference, None)),
                };
                respond(reply, Ok(candidate))
            }
            Command::HeaderSegments(requests, max_bytes, reply) => {
                self.start_header_segments(requests, max_bytes, reply)
            }
            Command::OutputRefs(start, max_items, max_bytes, reply) => {
                self.start_output_refs(start, max_items, max_bytes, reply)
            }
            _ => unreachable!("only independent reads use the read lane"),
        }
    }

    /// Drives immutable reads while one admission exclusively owns its mutable journals.
    /// No durability completion, prune, installation, or other mutation runs in this interval.
    async fn write_admission(&mut self, write: Admission<H, V, B>) -> Result<(), Error> {
        let write = self.stores.start_admission(write)?;
        let mut write = std::pin::pin!(write);
        loop {
            let accept_reads = self.accept_independent_reads();
            let read_ready = self.deferred_read_ready();
            let read = next_read(
                &mut self.independent_reads,
                &mut self.deferred_read,
                accept_reads,
                read_ready,
            );
            select! {
                result = &mut write => return self.stores.finish_admission(result?),
                completion = self.block_reads.next_completed() => {
                    self.complete_metadata(completion).map_err(Error::storage)?;
                },
                completion = self.materializer.complete_next() => {
                    self.finish_materialization(completion).map_err(Error::storage)?;
                },
                read = read => {
                    let Some(read) = read else {
                        self.independent_reads_open = false;
                        continue;
                    };
                    self.process_read(read).map_err(Error::storage)?;
                },
            }
        }
    }

    fn finish_materialization(
        &mut self,
        completion: Result<Option<CompletedRequest<H, B>>, Error>,
    ) -> Result<(), Error> {
        let completed = completion?;
        self.update_materialization_metrics();
        if let Some(completed) = completed {
            let available = self.complete_materialization(completed)?;
            self.retry_body_waiters(&available)?;
        }
        Ok(())
    }

    /// Records mailbox dwell for a stamped command at its first intake.
    ///
    /// The stamp is consumed so deferred retries and internal requeues are never re-observed.
    fn note_intake(&mut self, command: &mut TracedCommand<H, V, B>) {
        let Some(enqueued) = command.enqueued.take() else {
            return;
        };
        if matches!(command.command, Command::Admit(_, _, _)) {
            self.metrics
                .admission_command_dwell
                .observe_between(enqueued, self.clock.current());
        }
    }

    async fn process_command(&mut self, command: TracedCommand<H, V, B>) -> Result<(), Error> {
        let operation = command.command.kind();
        let span = info_span!(
            parent: &command.span,
            "multimmit.marshal.catalog.process",
            command = operation,
            handler_ns = tracing::field::Empty,
        );
        let started = self.clock.current();
        let result = async {
            let TracedCommand { command, span, .. } = command;
            match command {
                Command::Admit(write, sync, reply) => {
                    self.admit_batch(write, sync, reply, span).await
                }
                command => self.process(command).await,
            }
        }
        .instrument(span.clone())
        .await;
        let finished = self.clock.current();
        self.metrics.work("command", operation, started, finished);
        span.record(
            "handler_ns",
            u64::try_from(
                finished
                    .duration_since(started)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(u64::MAX),
        );
        result
    }

    fn process_delivery_cursor(&mut self, control: DeliveryCursorControl) -> Result<(), Error> {
        let DeliveryCursorControl {
            generation,
            acknowledged,
            reply,
        } = control;
        let checkpoint = &self.durable_checkpoint;
        let result = if generation < checkpoint.generation() {
            Ok(())
        } else if generation > checkpoint.generation() {
            Err(Error::Invalid(
                "delivery cursor generation exceeds the catalog generation",
            ))
        } else if acknowledged > checkpoint.committed() {
            Err(Error::Invalid(
                "delivery cursor exceeds the committed output",
            ))
        } else {
            if acknowledged > self.durable_acknowledged {
                self.durable_acknowledged = acknowledged;
            }
            Ok(())
        };
        if result.is_ok() {
            self.update_progress_metrics();
        }
        match reply {
            Some(reply) => respond(reply, result),
            None => result,
        }
    }

    fn complete_materialization(
        &mut self,
        completed: CompletedRequest<H, B>,
    ) -> Result<AvailableBodies<H, B>, Error> {
        self.metrics
            .materialized_bodies
            .inc_by(u64::try_from(completed.materialized).unwrap_or(u64::MAX));
        let available = completed
            .values
            .iter()
            .flatten()
            .map(|block| (block.reference(), Arc::clone(block)))
            .collect::<HashMap<_, _>>();
        let mut evictions = 0u64;
        for block in completed.values.iter().flatten() {
            evictions = evictions.saturating_add(
                self.materialized_cache
                    .insert(block.reference(), Arc::clone(block)),
            );
        }
        self.metrics.materialized_cache_evictions.inc_by(evictions);
        self.update_cache_metrics();
        respond(completed.reply, Ok(completed.values))?;
        Ok(available)
    }

    fn retry_body_waiters(&mut self, available: &AvailableBodies<H, B>) -> Result<(), Error> {
        let waiting = self.body_waiters.len();
        for _ in 0..waiting {
            let mut waiter = self
                .body_waiters
                .pop_front()
                .expect("the body waiter count was captured");
            for (reference, value) in waiter.references.iter().zip(&mut waiter.values) {
                if value.is_none()
                    && let Some(block) = available.get(reference)
                {
                    *value = Some(Arc::clone(block));
                }
            }
            let missing = self.fill_cached_bodies(&waiter.references, &mut waiter.values);
            let missing = missing
                .into_iter()
                .map(|(_, reference)| reference)
                .collect::<BTreeSet<_>>();
            let mut retained = Vec::with_capacity(waiter.groups.len());
            for mut group in std::mem::take(&mut waiter.groups) {
                if group.retain_references(&missing).map_err(Error::storage)? {
                    retained.push(group);
                }
            }
            waiter.groups = retained;
            self.submit_body_waiter(waiter)?;
        }
        self.update_materialization_metrics();
        Ok(())
    }

    fn fill_cached_bodies(
        &mut self,
        references: &[BlockRef<H::Digest>],
        values: &mut BodyValues<H, B>,
    ) -> Vec<(usize, BlockRef<H::Digest>)> {
        let mut missing = Vec::new();
        let mut cache_hits = 0u64;
        for (output, reference) in references.iter().copied().enumerate() {
            if values[output].is_some() {
                continue;
            }
            if let Some(block) = self.cached_block(&reference) {
                values[output] = Some(block);
                cache_hits = cache_hits.saturating_add(1);
            } else {
                missing.push((output, reference));
            }
        }
        self.metrics.body_cache_hits.inc_by(cache_hits);
        missing
    }

    fn process_bodies(
        &mut self,
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<BodyValues<H, B>>,
    ) -> Result<(), Error> {
        let mut values = vec![None; references.len()];
        let missing = self.fill_cached_bodies(&references, &mut values);
        let groups = self.stores.body_read_groups(
            missing,
            self.max_materialized_block_bytes,
            BODY_READ_CONCURRENCY,
        )?;
        self.submit_body_waiter(BodyWaiter {
            references,
            values,
            groups,
            reply,
        })
    }

    fn submit_body_waiter(&mut self, waiter: BodyWaiter<E, H, B>) -> Result<(), Error> {
        if !waiter.groups.is_empty()
            && (!self.materializer.has_capacity()
                || self
                    .materializer
                    .overlaps(waiter.groups.iter().flat_map(BodyReadGroup::references)))
        {
            if self.body_waiters.len() < self.body_waiter_capacity {
                self.body_waiters.push_back(waiter);
            } else {
                self.deferred = Some(TracedCommand::new(Command::Bodies(
                    waiter.references,
                    waiter.reply,
                )));
            }
            self.update_materialization_metrics();
            return Ok(());
        }
        self.metrics
            .materialization_groups
            .inc_by(u64::try_from(waiter.groups.len()).unwrap_or(u64::MAX));
        if let Some(completed) =
            self.materializer
                .enqueue(waiter.values, waiter.groups, waiter.reply)?
        {
            self.complete_materialization(completed)?;
        }
        self.update_materialization_metrics();
        Ok(())
    }

    fn pinned_body_segments(&self) -> BTreeSet<u64> {
        let mut pinned = self.materializer.pinned_segments();
        pinned.extend(
            self.body_waiters
                .iter()
                .flat_map(|waiter| waiter.groups.iter().map(BodyReadGroup::segment)),
        );
        pinned
    }

    fn update_materialization_metrics(&self) {
        let (active_jobs, active_bytes, queued_groups) = self.materializer.stats();
        self.metrics.materialization(
            active_jobs,
            active_bytes,
            queued_groups,
            self.body_waiters.len(),
        );
    }

    fn update_cache_metrics(&self) {
        self.metrics.caches(
            self.block_cache.blocks.len(),
            self.block_cache.encoded_bytes,
            self.materialized_cache.blocks.len(),
            self.materialized_cache.encoded_bytes,
        );
    }

    fn cached_block(&self, reference: &BlockRef<H::Digest>) -> Option<Arc<TransactionBlock<H, B>>> {
        self.block_cache
            .get(reference)
            .or_else(|| self.materialized_cache.get(reference))
    }

    fn cached_block_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.block_cache
            .get_by_digest(chain, digest)
            .or_else(|| self.materialized_cache.get_by_digest(chain, digest))
    }

    fn fail(&mut self, error: Error) {
        self.materializer.fail(error.clone());
        self.block_reads.cancel_all();
        self.history_reads.cancel_all();
        self.metadata_steps = 0;
        self.seals.cancel_all();
        if let Some(read) = self.deferred_read.take() {
            read.fail(error.clone());
        }
        if let Some(command) = self.deferred.take() {
            command.fail(error.clone());
        }
        if let Some(cut) = self.pending_admission.take() {
            for reply in cut.replies {
                drop(reply.send(Err(error.clone())));
            }
        }
        for (_, reply) in self.custody_waiters.drain(..) {
            drop(reply.send(Err(error.clone())));
        }
        for waiter in self.body_waiters.drain(..) {
            drop(waiter.reply.send(Err(error.clone())));
        }
        while let Ok(command) = self.commands.try_recv() {
            command.fail(error.clone());
        }
        while let Ok(control) = self.delivery_cursors.try_recv() {
            control.fail(error.clone());
        }
        while let Ok(read) = self.independent_reads.try_recv() {
            read.fail(error.clone());
        }
        std::mem::replace(&mut self.commit_state, CommitState::Idle).fail(error);
    }

    async fn complete_durability(
        &mut self,
        completion: DurabilityCompletion<H::Digest>,
    ) -> Result<(), Error> {
        match completion {
            DurabilityCompletion::Admission(AdmissionCompletion {
                replies,
                blocks,
                timer,
                result,
                span,
            }) => {
                timer.observe(&self.clock);
                self.admission_active = false;
                if result.is_ok() {
                    self.materializer
                        .retain_readers(self.stores.sealed_body_readers());
                    for reference in blocks {
                        self.volatile_blocks.remove(&reference);
                    }
                }
                for reply in replies {
                    drop(reply.send(result.clone()));
                }
                result?;
                // The completed cut proved every full segment durable; persist their seal
                // proofs so later readers open them from index metadata alone. Seals are an
                // optimization with no ordering needs, so they never gate commit barriers; the
                // store keeps sealing segments readable and unreclaimed until the proof lands.
                let (sealed, handles) = self.stores.start_pending_seals().await?;
                if !handles.is_empty() {
                    let span = info_span!(
                        parent: &span,
                        "multimmit.marshal.catalog.seal_pending",
                        segments = sealed.len(),
                    );
                    self.seals
                        .push(async move { (sealed, drain(handles).await) }.instrument(span));
                }
                self.complete_custody_waiters().await?;
                self.start_admission_sync().await.map(|_| ())
            }
            DurabilityCompletion::CommitArchives(timer, result) => {
                timer.observe(&self.clock);
                self.complete_commit_archives(result).await
            }
            DurabilityCompletion::CommitCheckpoint(timer, result) => {
                timer.observe(&self.clock);
                self.complete_commit_checkpoint(result).await
            }
        }
    }

    async fn start_admission_sync(&mut self) -> Result<bool, Error> {
        if self.admission_active {
            return Ok(false);
        }
        let Some(cut) = self.pending_admission.take() else {
            return Ok(false);
        };
        let trigger = if !cut.replies.is_empty() {
            "reply"
        } else if cut.items >= ADMISSION_CUT_MIN_ITEMS {
            "items"
        } else {
            "eager"
        };
        self.metrics.cut_trigger(trigger);
        self.metrics
            .admission_cut_scheduled_items
            .inc_by(u64::try_from(cut.items).unwrap_or(u64::MAX));
        let span = info_span!(
            parent: &cut.span,
            "multimmit.marshal.catalog.admission_cut",
            items = cut.items,
            blocks = cut.blocks.len(),
        );
        let completion_span = span.clone();
        let timer = self.metrics.admission_durability.timer(&self.clock);
        let handles = match self.stores.start_admission_sync(cut.footprint).await {
            Ok(handles) => handles,
            Err(error) => {
                for reply in cut.replies {
                    drop(reply.send(Err(error.clone())));
                }
                return Err(error);
            }
        };
        self.admission_active = true;
        self.durability.push(
            async move {
                DurabilityCompletion::Admission(AdmissionCompletion {
                    replies: cut.replies,
                    blocks: cut.blocks,
                    timer,
                    result: drain(handles).await,
                    span: completion_span,
                })
            }
            .instrument(span),
        );
        Ok(true)
    }

    async fn custody_values(
        stores: &Stores<T, E, H, V, B>,
        cache: &BlockCache<H, B>,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<CustodyLookup<H>, Error> {
        let values = try_join_all(references.into_iter().map(|reference| async move {
            if let Some(custody) = cache.custody(reference) {
                return Ok((Some(custody), true));
            }
            stores
                .block_meta(reference)
                .await
                .map(|meta| (meta.map(|meta| CustodyRef::new(reference, meta)), false))
        }))
        .await?;
        let mut cache_hits = 0u64;
        let mut storage_hits = 0u64;
        let mut misses = 0u64;
        let values = values
            .into_iter()
            .map(|(value, cached)| {
                if cached {
                    cache_hits = cache_hits.saturating_add(1);
                } else if value.is_some() {
                    storage_hits = storage_hits.saturating_add(1);
                } else {
                    misses = misses.saturating_add(1);
                }
                value
            })
            .collect();
        Ok(CustodyLookup {
            values,
            cache_hits,
            storage_hits,
            misses,
        })
    }

    fn record_custody_lookup(&self, lookup: CustodyLookup<H>) -> CustodyValues<H> {
        self.metrics.custody_cache_hits.inc_by(lookup.cache_hits);
        self.metrics
            .custody_storage_hits
            .inc_by(lookup.storage_hits);
        self.metrics.custody_misses.inc_by(lookup.misses);
        lookup.values
    }

    async fn complete_custody_waiters(&mut self) -> Result<(), Error> {
        let mut waiting = std::mem::take(&mut self.custody_waiters);
        while let Some((references, reply)) = waiting.pop_front() {
            if references
                .iter()
                .any(|reference| self.volatile_blocks.contains(reference))
            {
                self.custody_waiters.push_back((references, reply));
                continue;
            }
            let result = Self::custody_values(&self.stores, &self.block_cache, references)
                .await
                .map(|lookup| self.record_custody_lookup(lookup));
            respond(reply, result)?;
        }
        Ok(())
    }

    async fn start_commit_archives(&mut self, pending: &PendingCommit<H, B>) -> Result<(), Error> {
        let timer = self.metrics.finalized_archive_durability.timer(&self.clock);
        let handles = self
            .stores
            .start_finalized_sync(&pending.publication)
            .await?;
        let span = info_span!(
            parent: &pending.span,
            "multimmit.marshal.catalog.sync_finalized_archives"
        );
        self.durability.push(
            async move { DurabilityCompletion::CommitArchives(timer, drain(handles).await) }
                .instrument(span),
        );
        Ok(())
    }

    async fn start_commit_checkpoint(
        &mut self,
        pending: &mut PendingCommit<H, B>,
    ) -> Result<(), Error> {
        let timer = self.metrics.checkpoint_publication.timer(&self.clock);
        let sync = self
            .stores
            .start_sync_publication(&mut pending.publication)
            .await?;
        let span = info_span!(
            parent: &pending.span,
            "multimmit.marshal.catalog.publish_checkpoint"
        );
        self.durability.push(
            async move {
                DurabilityCompletion::CommitCheckpoint(timer, sync.await.map_err(Error::storage))
            }
            .instrument(span),
        );
        Ok(())
    }

    async fn complete_commit_archives(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        let state = std::mem::replace(&mut self.commit_state, CommitState::Idle);
        if let Err(error) = result {
            state.fail(error.clone());
            return Err(error);
        }
        match state {
            CommitState::Archiving(mut current) => {
                if let Err(error) = self.start_commit_checkpoint(&mut current).await {
                    current.fail(error.clone());
                    return Err(error);
                }
                self.commit_state = CommitState::Publishing(current);
            }
            CommitState::ArchivingBuffered(mut current, next) => {
                if let Err(error) = self.start_commit_checkpoint(&mut current).await {
                    CommitState::ArchivingBuffered(current, next).fail(error.clone());
                    return Err(error);
                }
                if let Err(error) = self.start_commit_archives(&next).await {
                    CommitState::PublishingArchiving(current, next).fail(error.clone());
                    return Err(error);
                }
                self.commit_state = CommitState::PublishingArchiving(current, next);
            }
            CommitState::PublishingArchiving(current, next) => {
                self.commit_state = CommitState::PublishingArchived(current, next);
            }
            _ => unreachable!("archive completion requires an archiving commit state"),
        }
        Ok(())
    }

    async fn complete_commit_checkpoint(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        let state = std::mem::replace(&mut self.commit_state, CommitState::Idle);
        if let Err(error) = result {
            state.fail(error.clone());
            return Err(error);
        }
        match state {
            CommitState::Publishing(current) => {
                self.finish_commit(current)?;
            }
            CommitState::PublishingArchiving(current, next) => {
                if let Err(error) = self.finish_commit(current) {
                    next.fail(error.clone());
                    return Err(error);
                }
                self.commit_state = CommitState::Archiving(next);
            }
            CommitState::PublishingArchived(current, mut next) => {
                if let Err(error) = self.finish_commit(current) {
                    next.fail(error.clone());
                    return Err(error);
                }
                if let Err(error) = self.start_commit_checkpoint(&mut next).await {
                    next.fail(error.clone());
                    return Err(error);
                }
                self.commit_state = CommitState::Publishing(next);
            }
            _ => unreachable!("checkpoint completion requires a publishing commit state"),
        }

        if self.commits_since_cleanup >= MAX_COMMITS_BEFORE_CLEANUP
            && let Err(error) = self.cleanup().await
        {
            std::mem::replace(&mut self.commit_state, CommitState::Idle).fail(error.clone());
            return Err(error);
        }
        Ok(())
    }

    fn finish_commit(&mut self, pending: PendingCommit<H, B>) -> Result<(), Error> {
        self.durable_checkpoint = pending.publication.checkpoint.clone();
        if let Some(cleanup) = &mut self.cleanup_due {
            cleanup.coalesce(pending.publication.cleanup.clone());
        } else {
            self.cleanup_due = Some(pending.publication.cleanup.clone());
        }
        self.commits_since_cleanup = self.commits_since_cleanup.saturating_add(1);
        self.metrics.commits.inc();
        self.metrics.committed_outputs.inc_by(pending.outputs);
        self.update_progress_metrics();
        let delivery = pending.delivery;
        let promoter_closed = self.promoter.as_ref().is_some_and(|promoter| {
            let Some(committed) = pending.publication.checkpoint.committed() else {
                return false;
            };
            let hot = delivery
                .as_ref()
                .into_iter()
                .flat_map(|batch| &batch.outputs)
                .filter_map(|output| {
                    output.block.as_ref().map(|block| promoter::HotBody {
                        index: output.stored.index,
                        block: Arc::clone(block),
                        encoded_len: output.stored.encoded_len,
                    })
                })
                .collect();
            promoter.published(committed, hot) == Feedback::Closed
        });
        let delivery_closed =
            delivery.is_some_and(|batch| self.delivery.committed(batch) == Feedback::Closed);
        self.pending_delivery_bytes = self
            .pending_delivery_bytes
            .checked_sub(pending.delivery_bytes)
            .expect("pending commits own their delivery-cache charge");
        drop(pending.completion.send(Ok(())));
        if delivery_closed {
            return Err(Error::DeliveryClosed);
        }
        if promoter_closed {
            return Err(Error::PromoterClosed);
        }
        Ok(())
    }

    async fn cleanup(&mut self) -> Result<(), Error> {
        let Some(cleanup) = self.cleanup_due.take() else {
            return Ok(());
        };
        self.stores.cleanup_pending(cleanup).await?;
        self.commits_since_cleanup = 0;
        Ok(())
    }

    fn validate_admission(&self, write: &Admission<H, V, B>) -> Result<(), Error> {
        let epoch = self.stores.checkpoint().map(Checkpoint::epoch);
        match write {
            Admission::Lqc(view, id, proof)
                if proof.view() != *view
                    || proof.id::<H>() != *id
                    || epoch.is_some_and(|value| proof.epoch() != value) =>
            {
                Err(Error::Invalid("LQC identity or epoch mismatch"))
            }
            Admission::History(_, commitment, record)
                if record.commitment::<H>() != *commitment =>
            {
                Err(Error::Invalid("history commitment mismatch"))
            }
            #[cfg(test)]
            Admission::Finality {
                view,
                id,
                proof,
                history,
            } if proof.view() != *view
                || proof.id::<H>() != *id
                || epoch.is_some_and(|value| proof.epoch() != value)
                || history.commitment::<H>() != proof.leader().history() =>
            {
                Err(Error::Invalid("finality proof and history mismatch"))
            }
            Admission::Block(_, block) if block.encode_size() > self.max_block_bytes => {
                Err(Error::Invalid("producer block exceeds encoded-byte bound"))
            }
            Admission::Block(reference, block)
                if block.reference() != *reference
                    || reference.chain().get() as usize >= self.stores.chain_count()
                    || epoch.is_some_and(|value| block.header().epoch() != value) =>
            {
                Err(Error::Invalid("producer-block identity or epoch mismatch"))
            }
            _ => Ok(()),
        }
    }

    async fn admit_batch(
        &mut self,
        first: Vec<Admission<H, V, B>>,
        first_mode: AdmissionMode,
        reply: Reply<()>,
        first_span: Span,
    ) -> Result<(), Error> {
        let processing_span = Span::current();
        let mut next = Some((first, first_mode, reply, first_span));
        while let Some((admissions, mode, reply, command_span)) = next.take() {
            if admissions.is_empty() {
                drop(reply.send(Ok(())));
            } else if admissions.len() > self.durability_capacity {
                mode.fail(Error::Invalid("admission batch exceeds catalog capacity"));
                drop(reply.send(Err(Error::Invalid(
                    "admission batch exceeds catalog capacity",
                ))));
            } else {
                let pending_items = self.pending_admission.as_ref().map_or(0, |cut| cut.items);
                let remaining = self
                    .durability_capacity
                    .checked_sub(pending_items)
                    .expect("the pending admission cut is bounded");
                if admissions.len() > remaining {
                    self.deferred = Some(TracedCommand::with_span(
                        Command::Admit(admissions, mode, reply),
                        command_span,
                    ));
                    break;
                }
                let mut items = admissions.len();
                let mut commands = vec![(admissions, mode, reply)];
                while items < remaining {
                    let Ok(mut traced) = self.commands.try_recv() else {
                        break;
                    };
                    self.note_intake(&mut traced);
                    match traced {
                        TracedCommand {
                            command: Command::Admit(admissions, mode, reply),
                            span,
                            ..
                        } if admissions.len() <= remaining - items => {
                            processing_span.follows_from(span.id());
                            items += admissions.len();
                            commands.push((admissions, mode, reply));
                        }
                        command => {
                            self.deferred = Some(command);
                            break;
                        }
                    }
                }
                self.buffer_admission_commands(commands).await?;
            }

            if self.deferred.is_some()
                || self
                    .pending_admission
                    .as_ref()
                    .is_some_and(|cut| cut.items >= self.durability_capacity)
            {
                break;
            }
            let Ok(mut traced) = self.commands.try_recv() else {
                break;
            };
            self.note_intake(&mut traced);
            match traced {
                TracedCommand {
                    command: Command::Admit(admissions, mode, reply),
                    span,
                    ..
                } => {
                    processing_span.follows_from(span.id());
                    next = Some((admissions, mode, reply, span));
                }
                command => {
                    self.deferred = Some(command);
                    break;
                }
            }
        }
        Ok(())
    }

    async fn buffer_admission_commands(
        &mut self,
        commands: Vec<AdmissionCommand<H, V, B>>,
    ) -> Result<(), Error> {
        let capacity = commands.iter().map(|(writes, _, _)| writes.len()).sum();
        let mut writes = Vec::with_capacity(capacity);
        let mut cache = Vec::new();
        let mut durable = Vec::with_capacity(commands.len());
        let mut buffered = Vec::with_capacity(commands.len());
        for (admissions, mode, reply) in commands {
            match admissions
                .iter()
                .try_for_each(|write| self.validate_admission(write))
            {
                Ok(()) => {
                    let sync_metadata = mode.sync_metadata();
                    for write in admissions {
                        if let Admission::Block(reference, block) = &write {
                            cache.push((*reference, Arc::clone(block)));
                        }
                        writes.push((write, sync_metadata));
                    }
                    match mode {
                        AdmissionMode::Buffered => buffered.push(reply),
                        AdmissionMode::Durable => durable.push(reply),
                        AdmissionMode::Staged(completion) => {
                            buffered.push(reply);
                            durable.push(completion);
                        }
                    }
                }
                Err(error) => {
                    mode.fail(error.clone());
                    drop(reply.send(Err(error)));
                }
            }
        }
        if writes.is_empty() {
            return Ok(());
        }
        let admitted = writes.len();
        let footprint = match async {
            let footprint = self.stores.admission_footprint(&writes)?;
            for (write, _) in writes {
                self.write_admission(write).await?;
            }
            Ok::<_, Error>(footprint)
        }
        .await
        {
            Ok(footprint) => footprint,
            Err(error) => {
                for reply in durable.into_iter().chain(buffered) {
                    drop(reply.send(Err(error.clone())));
                }
                return error.fatal().then_some(error).map_or(Ok(()), Err);
            }
        };
        let block_refs = cache
            .iter()
            .map(|(reference, _)| *reference)
            .collect::<Vec<_>>();
        self.volatile_blocks.extend(block_refs.iter().copied());
        let mut evictions = 0u64;
        for (reference, block) in cache {
            evictions = evictions.saturating_add(self.block_cache.insert(reference, block));
        }
        self.metrics.block_cache_evictions.inc_by(evictions);
        self.update_cache_metrics();
        self.metrics
            .admissions
            .inc_by(u64::try_from(admitted).unwrap_or(u64::MAX));
        for reply in buffered {
            drop(reply.send(Ok(())));
        }
        if let Some(footprint) = footprint {
            if let Some(cut) = &mut self.pending_admission {
                let span = Span::current();
                if cut.span.id() != span.id() {
                    cut.span.follows_from(span.id());
                }
                cut.footprint.merge(footprint);
                cut.replies.extend(durable);
                cut.blocks.extend(block_refs);
                cut.items += admitted;
            } else {
                self.pending_admission = Some(PendingAdmission {
                    footprint,
                    replies: durable,
                    blocks: block_refs,
                    items: admitted,
                    span: Span::current(),
                });
            }
        } else if let Some(cut) = &mut self.pending_admission {
            cut.items += admitted;
        }
        Ok(())
    }

    fn validate_commit(&self, batch: &Commit<H, V>) -> Result<(), Error> {
        let current = &self.accepted_checkpoint;
        let next = &batch.checkpoint;
        if next.epoch() != current.epoch()
            || next.generation() != current.generation()
            || next.archive_layout() != current.archive_layout()
            || next.ordered().len() != self.stores.chain_count()
            || batch.selected.len() > self.max_commit_outputs
            || batch.outputs.len() > self.max_commit_outputs
        {
            return Err(Error::Invalid("checkpoint context mismatch"));
        }
        let mut output_bytes = 0usize;
        for (position, output) in batch.outputs.iter().enumerate() {
            let encoded_len = usize::try_from(output.meta().encoded_len()).unwrap_or(usize::MAX);
            if position > 0
                && output_bytes
                    .checked_add(encoded_len)
                    .is_none_or(|total| total > self.max_commit_block_bytes)
            {
                return Err(Error::Invalid("commit block bytes exceed bound"));
            }
            output_bytes = output_bytes.saturating_add(encoded_len);
        }
        if batch.selected.iter().any(|selected| {
            selected.proof.view() != selected.view
                || selected.proof.epoch() != current.epoch()
                || selected.proof.id::<H>() != selected.id
                || selected.proof.leader().history() != next.history()
        }) || batch
            .selected
            .windows(2)
            .any(|pair| pair[0].view > pair[1].view)
        {
            return Err(Error::Invalid("selected LQC does not establish checkpoint"));
        }
        match batch.selected.last() {
            Some(selected) if next.floor() != selected.id => {
                return Err(Error::Invalid("selected LQC does not establish checkpoint"));
            }
            None if next.floor() != current.floor() => {
                return Err(Error::Invalid("intermediate commit changed the LQC floor"));
            }
            _ => {}
        }
        if !frontier_advances(current.ordered(), next.ordered())
            || !frontier_advances(current.emitted(), next.emitted())
        {
            return Err(Error::Invalid(
                "checkpoint frontier regressed or conflicted",
            ));
        }
        let mut history = current.history();
        for opening in &batch.history {
            if opening.record.parent() != history
                || opening.record.commitment::<H>() != opening.commitment
            {
                return Err(Error::Invalid("history openings are not contiguous"));
            }
            history = opening.commitment;
        }
        if history != next.history() {
            return Err(Error::Invalid("history does not reach checkpoint"));
        }
        let history_index = match (current.history_index(), batch.history.len()) {
            (index, 0) => index,
            (Some(index), count) => Some(
                index
                    .checked_add(
                        u64::try_from(count)
                            .map_err(|_| Error::Invalid("history index overflow"))?,
                    )
                    .ok_or(Error::Invalid("history index overflow"))?,
            ),
            (None, count) => Some(
                u64::try_from(count - 1).map_err(|_| Error::Invalid("history index overflow"))?,
            ),
        };
        if next.history_index() != history_index {
            return Err(Error::Invalid("checkpoint history index is not contiguous"));
        }
        let ordered = batch
            .history
            .last()
            .map_or(current.ordered(), |opening| opening.record.tips());
        if next.ordered() != ordered {
            return Err(Error::Invalid("checkpoint ordering does not match history"));
        }
        let first = match current.committed() {
            Some(index) => index
                .next()
                .ok_or(Error::Invalid("output index overflow"))?,
            None => OutputIndex::ZERO,
        };
        for (offset, output) in batch.outputs.iter().enumerate() {
            let offset =
                u64::try_from(offset).map_err(|_| Error::Invalid("output batch too large"))?;
            let expected = first
                .get()
                .checked_add(offset)
                .map(OutputIndex::new)
                .ok_or(Error::Invalid("output index overflow"))?;
            let reference = output.reference();
            if output.index != expected
                || reference.chain().get() as usize >= self.stores.chain_count()
                || output.meta().header().block_ref::<H>() != reference
                || output.meta().header().epoch() != current.epoch()
            {
                return Err(Error::Invalid("output rows are not dense or exact"));
            }
        }
        let committed = batch
            .outputs
            .last()
            .map_or(current.committed(), |row| Some(row.index));
        if next.committed() != committed {
            return Err(Error::Invalid("checkpoint does not cover output batch"));
        }
        let mut emitted = current.emitted().to_vec();
        for output in &batch.outputs {
            let reference = output.reference();
            let frontier = &mut emitted[reference.chain().get() as usize];
            if reference.height().get()
                != frontier
                    .height()
                    .get()
                    .checked_add(1)
                    .ok_or(Error::Invalid("output frontier overflow"))?
            {
                return Err(Error::Invalid(
                    "output rows do not advance exact chain frontiers",
                ));
            }
            *frontier = reference;
        }
        if emitted != next.emitted() {
            return Err(Error::Invalid(
                "checkpoint emission does not match output rows",
            ));
        }
        Ok(())
    }

    fn prepare_delivery(
        &self,
        batch: &Commit<H, V>,
        handoff: Vec<delivery::DurableOutput<H, B>>,
    ) -> Result<(Option<delivery::DurableBatch<H, B>>, u64), Error> {
        const HANDOFF_PRIORITY: u8 = 0;
        const LIVE_CACHE_PRIORITY: u8 = 1;
        const MATERIALIZED_CACHE_PRIORITY: u8 = 2;

        let Some(committed) = batch.outputs.last().map(|output| output.index) else {
            if !handoff.is_empty() {
                return Err(Error::Invalid("delivery handoff has no output row"));
            }
            return Ok((None, 0));
        };
        let available = self
            .max_hot_block_bytes
            .saturating_sub(self.pending_delivery_bytes);
        let descriptor_bytes = delivery::descriptor_bytes::<H::Digest>();
        let descriptor_count = batch
            .outputs
            .len()
            .min(usize::try_from(available / descriptor_bytes).unwrap_or(usize::MAX));
        let mut delivery_bytes =
            descriptor_bytes.saturating_mul(u64::try_from(descriptor_count).unwrap_or(u64::MAX));
        // Preserve the widest output coverage first. Remaining bytes upgrade descriptors by body
        // source priority without narrowing that coverage.
        let mut retained = (0..batch.outputs.len())
            .map(|position| position < descriptor_count)
            .collect::<Vec<_>>();
        let mut hot = vec![false; batch.outputs.len()];
        let mut bodies = (0..batch.outputs.len())
            .map(|_| None)
            .collect::<Vec<Option<(u8, delivery::DurableOutput<H, B>)>>>();
        let mut handoff = handoff.into_iter().peekable();
        for (slot, output) in bodies.iter_mut().zip(&batch.outputs) {
            let Some(retained) = handoff.next_if(|retained| retained.index <= output.index) else {
                continue;
            };
            if retained.index != output.index {
                return Err(Error::Invalid(
                    "delivery handoff is not ordered with its output rows",
                ));
            }
            let encoded_len = output.meta().encoded_len();
            if retained.block.reference() != output.reference()
                || retained.block.header() != output.meta().header()
                || u64::try_from(retained.block.encode_size()).ok() != Some(encoded_len)
                || retained.encoded_len != encoded_len
            {
                return Err(Error::Invalid(
                    "delivery handoff does not match its output row",
                ));
            }
            *slot = Some((HANDOFF_PRIORITY, retained));
        }
        if handoff.next().is_some() {
            return Err(Error::Invalid(
                "delivery handoff contains an unknown output row",
            ));
        }
        for (priority, cache) in [
            (LIVE_CACHE_PRIORITY, &self.block_cache),
            (MATERIALIZED_CACHE_PRIORITY, &self.materialized_cache),
        ] {
            for (slot, output) in bodies.iter_mut().zip(&batch.outputs) {
                if slot.is_some() {
                    continue;
                }
                let Some(block) = cache.get(&output.reference()) else {
                    continue;
                };
                let encoded_len = output.meta().encoded_len();
                if block.reference() != output.reference()
                    || block.header() != output.meta().header()
                    || u64::try_from(block.encode_size()).ok() != Some(encoded_len)
                {
                    continue;
                }
                *slot = Some((
                    priority,
                    delivery::DurableOutput {
                        index: output.index,
                        block,
                        encoded_len,
                    },
                ));
            }
        }
        let mut candidates = bodies
            .iter()
            .enumerate()
            .filter_map(|(position, body)| body.as_ref().map(|(priority, _)| (*priority, position)))
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        for (priority, position) in candidates {
            let encoded_len = bodies[position]
                .as_ref()
                .expect("candidate body exists")
                .1
                .encoded_len;
            let body_bytes = delivery::body_bytes::<H::Digest>(encoded_len);
            if retained[position] {
                let additional = body_bytes.saturating_sub(descriptor_bytes);
                if delivery_bytes
                    .checked_add(additional)
                    .is_some_and(|total| total <= available)
                {
                    delivery_bytes += additional;
                    hot[position] = true;
                }
                continue;
            }

            let remaining = available.saturating_sub(delivery_bytes);
            let additional = body_bytes.saturating_sub(descriptor_bytes);
            if additional > remaining {
                continue;
            }
            let replacement = (0..batch.outputs.len())
                .filter(|candidate| retained[*candidate] && !hot[*candidate])
                .filter(|candidate| {
                    bodies[*candidate]
                        .as_ref()
                        .map_or(u8::MAX, |(candidate_priority, _)| *candidate_priority)
                        > priority
                })
                .max_by_key(|candidate| {
                    (
                        bodies[*candidate]
                            .as_ref()
                            .map_or(u8::MAX, |(candidate_priority, _)| *candidate_priority),
                        *candidate,
                    )
                });
            let Some(replacement) = replacement else {
                continue;
            };
            delivery_bytes += additional;
            retained[replacement] = false;
            retained[position] = true;
            hot[position] = true;
        }
        self.pending_delivery_bytes
            .checked_add(delivery_bytes)
            .ok_or(Error::Invalid("pending delivery-cache bytes overflow"))?;
        let generation = batch.checkpoint.generation();
        let outputs = batch
            .outputs
            .iter()
            .enumerate()
            .filter(|(position, _)| retained[*position])
            .map(|(position, output)| delivery::DeliveryOutput {
                stored: StoredRef {
                    index: output.index,
                    reference: output.reference(),
                    encoded_len: output.meta().encoded_len(),
                    generation,
                },
                block: hot[position].then(|| {
                    bodies[position]
                        .as_ref()
                        .expect("hot body exists")
                        .1
                        .block
                        .clone()
                }),
            })
            .collect();
        Ok((
            Some(delivery::DurableBatch::new(
                generation,
                committed,
                outputs,
                delivery_bytes,
                self.max_hot_block_bytes,
            )),
            delivery_bytes,
        ))
    }

    fn validate_install(
        &self,
        checkpoint: &Checkpoint<H::Digest>,
        prune: &Prune,
        proof: &Arc<Lqc<V, H::Digest>>,
        history: &Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let current = self.stores.checkpoint();
        let history_index = current
            .and_then(Checkpoint::history_index)
            .map_or(Some(0), |index| index.checked_add(1))
            .ok_or(Error::Invalid("history index overflow"))?;
        let chains = self.stores.chain_count();
        if checkpoint.ordered().len() != chains
            || prune.pending_blocks.len() != chains
            || checkpoint.history_index() != Some(history_index)
            || current.is_some_and(|current| {
                checkpoint.epoch() != current.epoch()
                    || checkpoint.generation() <= current.generation()
                    || checkpoint.archive_layout() != current.archive_layout()
                    || checkpoint.committed() != current.committed()
                    || !frontier_advances(current.ordered(), checkpoint.ordered())
                    || !frontier_advances(current.emitted(), checkpoint.emitted())
            })
        {
            return Err(Error::Invalid(
                "floor installation is not a newer compatible generation",
            ));
        }
        if proof.id::<H>() != checkpoint.floor()
            || proof.epoch() != checkpoint.epoch()
            || proof.leader().history() != checkpoint.history()
            || history.commitment::<H>() != checkpoint.history()
        {
            return Err(Error::Invalid(
                "floor artifacts do not establish checkpoint",
            ));
        }
        Ok(())
    }

    fn push_metadata(&mut self, job: MetadataJob<E, H>) {
        let steps = job.steps();
        self.metadata_steps = self
            .metadata_steps
            .checked_add(steps)
            .expect("metadata step count does not overflow");
        assert!(self.metadata_steps <= self.metadata_step_capacity);
        match job {
            MetadataJob::History { .. } => self.history_reads.push(job.execute()),
            MetadataJob::Headers { .. } | MetadataJob::Outputs { .. } => {
                self.block_reads.push(job.execute());
            }
        }
    }

    const fn release_metadata_steps(&mut self, steps: usize) {
        self.metadata_steps = self
            .metadata_steps
            .checked_sub(steps)
            .expect("metadata completion owns its active steps");
    }

    fn metadata_has_capacity(&self, steps: usize) -> bool {
        self.metadata_steps
            .checked_add(steps)
            .is_some_and(|total| total <= self.metadata_step_capacity)
    }

    fn start_history_segment(
        &mut self,
        commitment: H::Digest,
        max_items: usize,
        max_bytes: usize,
        reply: Reply<HistorySegment<H>>,
    ) -> Result<(), Error> {
        if max_items == 0 || max_bytes == 0 {
            return respond(
                reply,
                Err(Error::Invalid("history segment bounds are zero")),
            );
        }
        if reply.is_closed() {
            return Ok(());
        }
        if !self.metadata_has_capacity(1) {
            return respond(
                reply,
                Err(Error::Invalid(
                    "catalog metadata read capacity is exhausted",
                )),
            );
        }
        let step = match self.stores.history_read(commitment) {
            Ok(step) => step,
            Err(error) => return respond(reply, Err(error)),
        };
        self.push_metadata(MetadataJob::History {
            state: HistorySegmentState {
                commitment,
                max_items,
                max_bytes,
                item_bytes: 0,
                records: Vec::new(),
            },
            reply,
            step,
        });
        Ok(())
    }

    fn advance_header_branch(
        &self,
        branch: &mut HeaderBranch<H>,
        outcome: Option<storage::FinalBlockReadOutcome<H>>,
        max_bytes: usize,
    ) -> Result<Option<storage::FinalBlockReadStep<E, H>>, Error> {
        let mut outcome = outcome;
        loop {
            let Some(reference) = branch.reference else {
                return Ok(None);
            };
            let header = match outcome.take() {
                Some(FinalizedReadOutcome::Continue(request)) => {
                    return self.stores.continue_final_block_read(request).map(Some);
                }
                Some(FinalizedReadOutcome::Done(value)) => {
                    self.stores.finalized_block_header(reference, value)?
                }
                None => match self.stores.pending_block_header(reference) {
                    Some(header) => Some(header),
                    None => {
                        return self
                            .stores
                            .final_block_by_key_read(reference.digest())
                            .map(Some);
                    }
                },
            };
            let Some(header) = header else {
                branch.reference = None;
                return Ok(None);
            };
            let next_item_bytes = branch.item_bytes.saturating_add(header.encode_size());
            let encoded_bytes = branch
                .headers
                .len()
                .saturating_add(1)
                .encode_size()
                .saturating_add(next_item_bytes);
            if encoded_bytes > max_bytes {
                branch.reference = None;
                return Ok(None);
            }
            let height = reference.height().get();
            branch.item_bytes = next_item_bytes;
            branch.headers.push(header.clone());
            if branch.headers.len() == branch.max_items || height == 1 {
                branch.reference = None;
                return Ok(None);
            }
            branch.reference = Some(BlockRef::new(
                reference.chain(),
                Height::new(height - 1),
                header.parent(),
            ));
        }
    }

    fn start_header_segments(
        &mut self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
        reply: Reply<HeaderSegments<H>>,
    ) -> Result<(), Error> {
        if max_bytes == 0 || requests.iter().any(|(_, max_items)| *max_items == 0) {
            return respond(reply, Err(Error::Invalid("header segment bounds are zero")));
        }
        if requests.len() > self.metadata_step_capacity {
            return respond(
                reply,
                Err(Error::Invalid(
                    "header segment request vector exceeds capacity",
                )),
            );
        }
        if reply.is_closed() {
            return Ok(());
        }
        if !self.metadata_has_capacity(requests.len()) {
            return respond(
                reply,
                Err(Error::Invalid(
                    "catalog metadata read capacity is exhausted",
                )),
            );
        }
        let mut state = HeaderSegmentsState {
            max_bytes,
            branches: requests
                .into_iter()
                .map(|(reference, max_items)| HeaderBranch {
                    reference: Some(reference),
                    max_items,
                    item_bytes: 0,
                    headers: Vec::new(),
                })
                .collect(),
        };
        let mut steps = Pool::default();
        for (index, branch) in state.branches.iter_mut().enumerate() {
            match self.advance_header_branch(branch, None, max_bytes) {
                Ok(Some(step)) => {
                    steps.push(async move { (index, step.execute().await.map_err(Error::storage)) })
                }
                Ok(None) => {}
                Err(error) => return respond(reply, Err(error)),
            }
        }
        if steps.is_empty() {
            return respond(
                reply,
                Ok(state
                    .branches
                    .into_iter()
                    .map(|branch| branch.headers)
                    .collect()),
            );
        }
        self.push_metadata(MetadataJob::Headers {
            state,
            reply,
            steps,
        });
        Ok(())
    }

    fn start_output_refs(
        &mut self,
        start: OutputIndex,
        max_items: usize,
        max_bytes: NonZeroUsize,
        reply: Reply<OutputRefs<H>>,
    ) -> Result<(), Error> {
        let Some(committed) = self.durable_checkpoint.committed() else {
            return respond(
                reply,
                Err(Error::Invalid(
                    "output range does not begin at a committed row",
                )),
            );
        };
        if start > committed {
            return respond(
                reply,
                Err(Error::Invalid(
                    "output range does not begin at a committed row",
                )),
            );
        }
        if reply.is_closed() {
            return Ok(());
        }
        if !self.metadata_has_capacity(1) {
            return respond(
                reply,
                Err(Error::Invalid(
                    "catalog metadata read capacity is exhausted",
                )),
            );
        }
        let available = committed
            .get()
            .checked_sub(start.get())
            .and_then(|distance| distance.checked_add(1))
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(usize::MAX);
        self.start_output_window(
            OutputRefsState {
                next: start.get(),
                remaining: max_items.min(available),
                max_bytes: u64::try_from(max_bytes.get()).unwrap_or(u64::MAX),
                encoded_bytes: 0,
                outputs: Vec::new(),
                reads: VecDeque::new(),
            },
            reply,
        );
        Ok(())
    }

    fn start_output_window(&mut self, mut state: OutputRefsState<H>, reply: Reply<OutputRefs<H>>) {
        let count = state
            .remaining
            .min(self.metadata_step_capacity - self.metadata_steps);
        assert!(count > 0 && state.reads.is_empty());
        state.reads.resize_with(count, || None);
        let mut steps = Pool::default();
        for offset in 0..count {
            let index = state
                .next
                .checked_add(offset as u64)
                .expect("the output window is bounded by its committed frontier");
            let step = self.stores.final_block_at_read(index);
            steps.push(async move {
                let result = match step {
                    Ok(step) => step.execute().await.map_err(Error::storage),
                    Err(error) => Err(error),
                };
                (index, result)
            });
        }
        self.push_metadata(MetadataJob::Outputs {
            state,
            reply,
            steps,
        });
    }

    fn complete_metadata(&mut self, completion: MetadataCompletion<E, H>) -> Result<(), Error> {
        self.release_metadata_steps(completion.steps());
        match completion {
            MetadataCompletion::Canceled(_) => Ok(()),
            MetadataCompletion::History {
                mut state,
                reply,
                result,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                match result {
                    Err(error) => respond(reply, Err(error)),
                    Ok(storage::HistoryReadOutcome::Continue(continuation)) => {
                        let step = match self.stores.continue_history_read(continuation) {
                            Ok(step) => step,
                            Err(error) => return respond(reply, Err(error)),
                        };
                        self.push_metadata(MetadataJob::History { state, reply, step });
                        Ok(())
                    }
                    Ok(storage::HistoryReadOutcome::Done(None)) => {
                        respond(reply, Ok(state.records))
                    }
                    Ok(storage::HistoryReadOutcome::Done(Some(record))) => {
                        let next_item_bytes = state.item_bytes.saturating_add(record.encode_size());
                        let encoded_bytes = state
                            .records
                            .len()
                            .saturating_add(1)
                            .encode_size()
                            .saturating_add(next_item_bytes);
                        if encoded_bytes > state.max_bytes {
                            return respond(reply, Ok(state.records));
                        }
                        state.commitment = record.parent();
                        state.item_bytes = next_item_bytes;
                        state.records.push(record);
                        if state.records.len() == state.max_items {
                            return respond(reply, Ok(state.records));
                        }
                        let step = match self.stores.history_read(state.commitment) {
                            Ok(step) => step,
                            Err(error) => return respond(reply, Err(error)),
                        };
                        self.push_metadata(MetadataJob::History { state, reply, step });
                        Ok(())
                    }
                }
            }
            MetadataCompletion::Headers {
                mut state,
                reply,
                mut steps,
                index,
                result,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                let outcome = match result {
                    Ok(outcome) => outcome,
                    Err(error) => return respond(reply, Err(error)),
                };
                match self.advance_header_branch(
                    &mut state.branches[index],
                    Some(outcome),
                    state.max_bytes,
                ) {
                    Ok(Some(step)) => {
                        steps.push(
                            async move { (index, step.execute().await.map_err(Error::storage)) },
                        );
                    }
                    Ok(None) => {}
                    Err(error) => return respond(reply, Err(error)),
                }
                if steps.is_empty() {
                    return respond(
                        reply,
                        Ok(state
                            .branches
                            .into_iter()
                            .map(|branch| branch.headers)
                            .collect()),
                    );
                }
                self.push_metadata(MetadataJob::Headers {
                    state,
                    reply,
                    steps,
                });
                Ok(())
            }
            MetadataCompletion::Outputs {
                mut state,
                reply,
                mut steps,
            } => {
                if reply.is_closed() {
                    return Ok(());
                }
                while let Some(result) = state.reads.front_mut().and_then(Option::take) {
                    let value = match result {
                        Ok(FinalizedReadOutcome::Done(value)) => value,
                        Ok(FinalizedReadOutcome::Continue(request)) => {
                            *state.reads.front_mut().expect("the prefix exists") =
                                Some(Ok(FinalizedReadOutcome::Continue(request)));
                            break;
                        }
                        Err(error) => return respond(reply, Err(error)),
                    };
                    state.reads.pop_front();
                    let output = match self.stores.stored_ref(state.next, value) {
                        Ok(output) => output,
                        Err(error) => return respond(reply, Err(error)),
                    };
                    if !state.outputs.is_empty()
                        && state
                            .encoded_bytes
                            .checked_add(output.encoded_len)
                            .is_none_or(|total| total > state.max_bytes)
                    {
                        return respond(reply, Ok(state.outputs));
                    }
                    state.encoded_bytes = state.encoded_bytes.saturating_add(output.encoded_len);
                    state.outputs.push(output);
                    state.remaining -= 1;
                    if state.remaining == 0 {
                        return respond(reply, Ok(state.outputs));
                    }
                    state.next = match state.next.checked_add(1) {
                        Some(next) => next,
                        None => {
                            return respond(reply, Err(Error::Invalid("output index overflow")));
                        }
                    };
                }
                if state.reads.is_empty() {
                    self.start_output_window(state, reply);
                } else {
                    for (offset, slot) in state.reads.iter_mut().enumerate() {
                        let Some(result) = slot.take() else {
                            continue;
                        };
                        let request = match result {
                            Ok(FinalizedReadOutcome::Continue(request)) => request,
                            result => {
                                *slot = Some(result);
                                continue;
                            }
                        };
                        let index = state
                            .next
                            .checked_add(offset as u64)
                            .expect("the output window is bounded by its committed frontier");
                        let step = self.stores.continue_final_block_read(request);
                        steps.push(async move {
                            let result = match step {
                                Ok(step) => step.execute().await.map_err(Error::storage),
                                Err(error) => Err(error),
                            };
                            (index, result)
                        });
                    }
                    self.push_metadata(MetadataJob::Outputs {
                        state,
                        reply,
                        steps,
                    });
                }
                Ok(())
            }
        }
    }

    async fn process(&mut self, command: Command<H, V, B>) -> Result<(), Error> {
        match command {
            command @ (Command::HistorySegment(_, _, _, _)
            | Command::HeaderSegments(_, _, _)
            | Command::OutputRefs(_, _, _, _)
            | Command::Install(_, _, _, _, _)
            | Command::Prune(_, _)
            | Command::Promoted(_, _))
                if !self.command_ready(&command) =>
            {
                self.deferred = Some(TracedCommand::new(command));
                Ok(())
            }
            #[cfg(test)]
            command @ Command::InstallThrough(_, _, _, _, _, _)
                if !self.command_ready(&command) =>
            {
                self.deferred = Some(TracedCommand::new(command));
                Ok(())
            }
            Command::Lqc(id, reply) => respond(reply, self.stores.lqc(id).await),
            Command::FinalLqc(id, reply) => respond(reply, self.stores.final_lqc(id).await),
            Command::LatestLqc(reply) => respond(reply, self.stores.latest_lqc().await),
            Command::History(key, reply) => respond(reply, self.stores.history(key).await),
            Command::HistorySegment(key, max_items, max_bytes, reply) => {
                self.start_history_segment(key, max_items, max_bytes, reply)
            }
            Command::WaitForCustody(references, reply) => {
                if references
                    .iter()
                    .any(|reference| self.volatile_blocks.contains(reference))
                {
                    if self.custody_waiters.len() >= self.custody_waiter_capacity {
                        return respond(
                            reply,
                            Err(Error::Invalid("catalog custody waiter bound is exhausted")),
                        );
                    }
                    self.custody_waiters.push_back((references, reply));
                    Ok(())
                } else {
                    let result = Self::custody_values(&self.stores, &self.block_cache, references)
                        .await
                        .map(|lookup| self.record_custody_lookup(lookup));
                    respond(reply, result)
                }
            }
            command @ (Command::Bodies(..)
            | Command::BodyCandidateByDigest(..)
            | Command::HeaderSegments(..)
            | Command::OutputRefs(..)) => self.process_lookup(command),
            Command::Commit(batch, handoff, reply) => {
                if self.durable_checkpoint == batch.checkpoint {
                    let (completion, receipt) = oneshot::channel();
                    drop(completion.send(Ok(())));
                    return respond(reply, Ok(CommitToken(receipt)));
                }
                if self.commit_state.is_full() {
                    return respond(
                        reply,
                        Err(Error::Invalid("commit publication window is full")),
                    );
                }
                if let Err(error) = self.validate_commit(&batch) {
                    return respond(reply, Err(error));
                }
                let (delivery, delivery_bytes) = match self.prepare_delivery(&batch, handoff) {
                    Ok(delivery) => delivery,
                    Err(error) => return respond(reply, Err(error)),
                };
                let outputs = u64::try_from(batch.outputs.len()).unwrap_or(u64::MAX);
                let publication = match self.stores.buffer_commit(batch).await {
                    Ok(publication) => publication,
                    Err(error) => return respond(reply, Err(error)),
                };
                self.accepted_checkpoint = publication.checkpoint.clone();
                let (completion, receipt) = oneshot::channel();
                let pending = PendingCommit {
                    publication,
                    completion,
                    delivery,
                    delivery_bytes,
                    outputs,
                    span: Span::current(),
                };
                self.pending_delivery_bytes = self
                    .pending_delivery_bytes
                    .checked_add(delivery_bytes)
                    .expect("prepared delivery fits the pending delivery-cache budget");
                drop(reply.send(Ok(CommitToken(receipt))));
                let state = std::mem::replace(&mut self.commit_state, CommitState::Idle);
                match state {
                    CommitState::Idle => {
                        if let Err(error) = self.start_commit_archives(&pending).await {
                            pending.fail(error.clone());
                            return Err(error);
                        }
                        self.commit_state = CommitState::Archiving(pending);
                    }
                    CommitState::Archiving(current) => {
                        self.commit_state = CommitState::ArchivingBuffered(current, pending);
                    }
                    CommitState::Publishing(current) => {
                        if let Err(error) = self.start_commit_archives(&pending).await {
                            CommitState::Publishing(current).fail(error.clone());
                            pending.fail(error.clone());
                            return Err(error);
                        }
                        self.commit_state = CommitState::PublishingArchiving(current, pending);
                    }
                    _ => {
                        unreachable!("a non-full commit state has capacity for one additional cut")
                    }
                }
                Ok(())
            }
            #[cfg(test)]
            Command::CommitThroughCheckpoint(batch, reply) => {
                let result = match self.validate_commit(&batch) {
                    Ok(()) => self.stores.publish_commit(batch).await.map(|_| ()),
                    Err(error) => Err(error),
                };
                respond(reply, result)
            }
            #[cfg(test)]
            Command::Pause(release, started, reply) => {
                let _ = started.send(());
                respond(reply, release.await.map_err(|_| Error::Closed))
            }
            Command::Install(checkpoint, prune, proof, history, reply) => {
                self.cleanup().await?;
                let installed = checkpoint.clone();
                let result = match self.validate_install(&checkpoint, &prune, &proof, &history) {
                    Ok(()) => {
                        self.materializer.clear_reader_cache();
                        self.stores.install(checkpoint, prune, proof, history).await
                    }
                    Err(error) => Err(error),
                };
                let result = match result {
                    Ok(()) => {
                        self.block_cache.clear();
                        self.materialized_cache.clear();
                        self.update_cache_metrics();
                        self.durable_checkpoint = installed.clone();
                        self.accepted_checkpoint = installed.clone();
                        self.durable_acknowledged = None;
                        self.metrics.floor_installations.inc();
                        self.update_progress_metrics();
                        if self.promoter.as_ref().is_some_and(|promoter| {
                            promoter.installed(
                                installed.generation(),
                                installed.committed(),
                                installed.emitted().to_vec(),
                            ) == Feedback::Closed
                        }) {
                            Err(Error::PromoterClosed)
                        } else {
                            self.delivery
                                .reset(installed.generation(), installed.committed())
                                .ok_or(Error::DeliveryClosed)
                        }
                    }
                    Err(error) => Err(error),
                };
                respond(reply, result)
            }
            #[cfg(test)]
            Command::InstallThrough(checkpoint, prune, proof, history, phase, reply) => {
                self.cleanup().await?;
                let result = match self.validate_install(&checkpoint, &prune, &proof, &history) {
                    Ok(()) => {
                        self.materializer.clear_reader_cache();
                        self.stores
                            .begin_install(
                                checkpoint.clone(),
                                proof.view(),
                                prune,
                                commonware_codec::Encode::encode(proof.as_ref()),
                                commonware_codec::Encode::encode(history.as_ref()),
                            )
                            .await?;
                        if matches!(phase, InstallCut::Intent) {
                            Ok(())
                        } else {
                            self.stores
                                .archive_install(&checkpoint, proof, history)
                                .await?;
                            if matches!(phase, InstallCut::Archived) {
                                Ok(())
                            } else {
                                self.stores.finish_install().await
                            }
                        }
                    }
                    Err(error) => Err(error),
                };
                respond(reply, result)
            }
            Command::Prune(generation, reply) => {
                let pinned = self.pinned_body_segments();
                let acknowledged = (self.durable_checkpoint.generation() == generation)
                    .then_some(self.durable_acknowledged)
                    .flatten();
                let result = self
                    .stores
                    .prune_finalized(generation, acknowledged, &pinned)
                    .await;
                let result = result.map(|reclaimed| {
                    self.materializer.release_readers(reclaimed);
                    self.block_cache.clear();
                    self.materialized_cache.clear();
                    self.update_cache_metrics();
                });
                respond(reply, result)
            }
            Command::Promoted(frontiers, reply) => {
                let pinned = self.pinned_body_segments();
                let result = self.stores.promoted(frontiers.clone(), &pinned).await;
                let result = result.map(|reclaimed| {
                    self.materializer.release_readers(reclaimed);
                    self.block_cache.prune(&frontiers);
                    self.materialized_cache.prune(&frontiers);
                    self.update_cache_metrics();
                });
                respond(reply, result)
            }
            Command::Checkpoint(reply) => respond(reply, Ok(self.durable_checkpoint.clone())),
            Command::Progress(reply) => {
                let checkpoint = &self.durable_checkpoint;
                let progress = Progress {
                    generation: checkpoint.generation(),
                    floor: checkpoint.floor(),
                    committed: checkpoint.committed(),
                    acknowledged: self.durable_acknowledged,
                };
                respond(reply, Ok(progress))
            }
            Command::Admit(_, _, _) => unreachable!("admissions are batched by the owner"),
        }
    }

    fn update_progress_metrics(&self) {
        let checkpoint = &self.durable_checkpoint;
        self.metrics.progress(checkpoint.committed());
    }
}

fn frontier_advances<D: Digest>(current: &[BlockRef<D>], next: &[BlockRef<D>]) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .zip(next)
            .all(|(current, next)| next.height() > current.height() || next == current)
}

/// Awaits every handle in one durability wave.
async fn drain(handles: Vec<Handle<()>>) -> Result<(), Error> {
    try_join_all(handles)
        .await
        .map(|_| ())
        .map_err(Error::storage)
}

fn respond<T>(reply: Reply<T>, result: Result<T, Error>) -> Result<(), Error> {
    let fatal = result.as_ref().err().filter(|error| error.fatal()).cloned();
    drop(reply.send(result));
    fatal.map_or(Ok(()), Err)
}

/// Starts a catalog actor with exclusive ownership of every mutable store.
#[allow(clippy::too_many_arguments)]
pub(in crate::multimmit::marshal) async fn spawn<R, T, E, H, V, B>(
    context: R,
    capacity: NonZeroUsize,
    admission_cut_capacity: NonZeroUsize,
    metadata_step_capacity: NonZeroUsize,
    custody_waiter_capacity: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_commit_block_bytes: NonZeroUsize,
    max_block_bytes: NonZeroUsize,
    delivery: DeliveryClient<H, B>,
    delivery_generation: u64,
    durable_acknowledged: Option<OutputIndex>,
    promoter: Option<promoter::Client<H, B>>,
    max_hot_block_bytes: NonZeroUsize,
    max_materialized_block_bytes: NonZeroUsize,
    finalized_lqc: FinalLqc<T, E, H, V>,
    finalized_history: FinalHistory<T, E, H>,
    finalized_blocks: FinalBlock<T, E, H>,
    pending_lqc: PendingLqc<T, E, H, V>,
    pending_history: PendingHistory<T, E, H>,
    pending_blocks: PendingBlocks<T, E, H, B>,
    metadata: Metadata<E, Unit, CatalogState<H::Digest>>,
    codec_config: crate::multimmit::config::CodecConfig,
    max_metadata_blob_size: NonZeroUsize,
) -> Result<SpawnedCatalog<H, V, B>, Error>
where
    R: Clock + Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    let mut stores = Stores::new(
        finalized_lqc,
        finalized_history,
        finalized_blocks,
        pending_lqc,
        pending_history,
        pending_blocks,
        metadata,
        codec_config,
        max_metadata_blob_size.get(),
    )?;
    stores.recover_install().await?;
    stores.recover_commit().await?;
    let metrics = metrics::Catalog::new(&context);
    let checkpoint = stores
        .checkpoint()
        .expect("catalog is opened with a durable checkpoint")
        .clone();
    if delivery_generation != checkpoint.generation()
        || durable_acknowledged > checkpoint.committed()
    {
        return Err(Error::Invalid(
            "delivery cursor does not match the recovered catalog checkpoint",
        ));
    }
    metrics.progress(checkpoint.committed());
    let (commands, receiver) = mailbox::new(context.child("mailbox"), capacity);
    let (delivery_cursors, delivery_cursor_receiver) =
        mailbox::new(context.child("delivery_cursor_mailbox"), NonZeroUsize::MIN);
    let (independent_reads, read_receiver) = mailbox::new(context.child("read_mailbox"), capacity);
    let enqueue_clock = context.child("enqueue_clock");
    let client = CatalogClient {
        commands,
        delivery_cursors,
        independent_reads,
        admission_capacity: admission_cut_capacity.get(),
        now: Arc::new(move || enqueue_clock.current()),
    };
    let mut materializer = Materializer::new(
        context.child("materializer"),
        BODY_READ_CONCURRENCY,
        u64::try_from(max_materialized_block_bytes.get()).unwrap_or(u64::MAX),
        capacity.get(),
        metrics.reader_acquisitions.clone(),
        metrics.materialized_body_bytes.clone(),
    );
    materializer.retain_readers(stores.sealed_body_readers());
    let clock = context.child("clock");
    let handle = context.shared(false).spawn(move |_| {
        Catalog {
            clock,
            stores,
            materializer,
            body_waiters: VecDeque::new(),
            body_waiter_capacity: capacity.get(),
            block_cache: BlockCache::new(max_hot_block_bytes),
            materialized_cache: BlockCache::new(max_materialized_block_bytes),
            max_commit_outputs: max_commit_outputs.get(),
            max_commit_block_bytes: max_commit_block_bytes.get(),
            max_block_bytes: max_block_bytes.get(),
            delivery,
            promoter,
            max_hot_block_bytes: u64::try_from(max_hot_block_bytes.get()).unwrap_or(u64::MAX),
            max_materialized_block_bytes: u64::try_from(max_materialized_block_bytes.get())
                .unwrap_or(u64::MAX),
            pending_delivery_bytes: 0,
            commands: receiver,
            delivery_cursors: delivery_cursor_receiver,
            independent_reads: read_receiver,
            independent_reads_open: true,
            deferred_read: None,
            deferred: None,
            durability: Pool::default(),
            block_reads: Pool::default(),
            history_reads: Pool::default(),
            metadata_steps: 0,
            metadata_step_capacity: metadata_step_capacity.get(),
            seals: Pool::default(),
            durability_capacity: admission_cut_capacity.get(),
            custody_waiter_capacity: custody_waiter_capacity.get(),
            durable_acknowledged,
            durable_checkpoint: checkpoint.clone(),
            accepted_checkpoint: checkpoint,
            commit_state: CommitState::Idle,
            admission_active: false,
            pending_admission: None,
            volatile_blocks: HashSet::new(),
            custody_waiters: VecDeque::new(),
            cleanup_due: None,
            commits_since_cleanup: 0,
            metrics,
        }
        .run()
    });
    Ok((client, handle))
}

type SpawnedCatalog<H, V, B> = (CatalogClient<H, V, B>, Handle<Result<(), Error>>);

#[cfg(test)]
mod tests {
    use super::{super::materializer::BODY_READER_RESIDENCY, *};
    use crate::{
        Reporter,
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            marshal::{
                config::{ArchiveConfig, ArchiveMode, Config, Start},
                storage::checkpoint::ArchiveLayout,
                types::Update,
            },
            mocks::Committee,
            types::{ChainId, TransactionBlockHeader, genesis_history},
        },
        types::{Epoch, Height, Participant},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context as DeterministicContext},
        mocks::{
            DelayedReadContext, DelayedSyncContext, PendingReads, PendingSyncs,
            drive_pending_syncs, release_next_pending_syncs,
        },
    };
    use commonware_storage::translator::TwoCap;
    use commonware_utils::{
        Acknowledgement as _, NZU16, NZU32, NZU64, NZUsize, acknowledgement::Exact, sync::Mutex,
    };
    use std::num::NonZeroU64;

    type TestBody = EmptyBlock<Sha256>;
    type Client = CatalogClient<Sha256, MinPk, TestBody>;
    type DeliveryReceiver = delivery::DeliveryReceiver<Sha256, TestBody>;

    #[derive(Clone, Default)]
    struct TestReporter {
        pending: Arc<Mutex<VecDeque<(OutputIndex, Exact)>>>,
    }

    impl TestReporter {
        fn contains(&self, index: OutputIndex) -> bool {
            self.pending
                .lock()
                .iter()
                .any(|(pending_index, _)| *pending_index == index)
        }

        fn acknowledge(&self, index: OutputIndex) -> bool {
            let mut pending = self.pending.lock();
            let Some(position) = pending
                .iter()
                .position(|(pending_index, _)| *pending_index == index)
            else {
                return false;
            };
            let (_, acknowledgement) = pending
                .remove(position)
                .expect("the located acknowledgement exists");
            drop(pending);
            acknowledgement.acknowledge();
            true
        }
    }

    async fn wait_for_report(
        context: &DeterministicContext,
        reporter: &TestReporter,
        index: OutputIndex,
    ) {
        for _ in 0..100 {
            if reporter.contains(index) {
                return;
            }
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("delivery did not report output {index}");
    }

    impl Reporter for TestReporter {
        type Activity = Update<TransactionBlock<Sha256, TestBody>>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            let Update::Block {
                index,
                acknowledgement,
                ..
            } = activity;
            self.pending.lock().push_back((index, acknowledgement));
            Feedback::Ok
        }
    }

    /// Sums samples whose metric name ends with `suffix`, optionally restricted to samples
    /// carrying `label` in their label set.
    fn metric_sum(metrics: &str, suffix: &str, label: Option<&str>) -> u64 {
        metrics
            .lines()
            .filter_map(|line| {
                if line.starts_with('#') {
                    return None;
                }
                let (sample, value) = line.rsplit_once(' ')?;
                let (name, labels) = sample
                    .split_once('{')
                    .map_or((sample, ""), |(name, labels)| (name, labels));
                (name.ends_with(suffix) && label.is_none_or(|label| labels.contains(label)))
                    .then(|| value.parse::<u64>().expect("counter is numeric"))
            })
            .sum()
    }

    fn metric_total(metrics: &str, suffix: &str) -> u64 {
        metric_sum(metrics, suffix, None)
    }

    /// Couples the mailbox, admission-cut, and pending-segment capacities, mirroring the
    /// pre-split single knob these tests shape storage geometry with.
    fn set_capacity(config: &mut Config<TwoCap, MinPk, TestBody>, capacity: usize) {
        config.catalog_mailbox_size = NonZeroUsize::new(capacity).expect("capacity is non-zero");
        config.admission_cut_capacity = config.catalog_mailbox_size;
        config.pending_segment_items =
            NonZeroU64::new(capacity as u64).expect("capacity is non-zero");
    }

    fn config(
        context: &DeterministicContext,
        committee: &Committee<MinPk>,
    ) -> Config<TwoCap, MinPk, TestBody> {
        let mut archive = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        );
        archive.items_per_section = NZU64!(1);
        let mut config = Config::new(
            committee.config.epoch(),
            NZU32!(4),
            Start::Genesis(committee.config.genesis().clone()),
            "catalog_integration".into(),
            committee.codec(),
            (),
            archive,
        )
        .unwrap();
        set_capacity(&mut config, 16);
        config.max_commit_outputs = NZUsize!(1);
        config.finalized_lqc = ArchiveMode::Prunable;
        config.finalized_history = ArchiveMode::Immutable;
        config.finalized_blocks = ArchiveMode::Prunable;
        config
    }

    async fn spawn_catalog<E>(
        config: Config<TwoCap, MinPk, TestBody>,
        context: E,
    ) -> (Client, Handle<Result<(), Error>>, DeliveryReceiver)
    where
        E: Context + Spawner + RuntimeMetrics,
    {
        let (delivery, receiver) = delivery::channel(context.child("delivery_mailbox"));
        let (client, handle, _, _, _) = config.spawn::<_, Sha256>(context, delivery).await.unwrap();
        (client, handle, receiver)
    }

    async fn open(
        context: &DeterministicContext,
        label: &'static str,
        committee: &Committee<MinPk>,
    ) -> (Client, Handle<Result<(), Error>>, DeliveryReceiver) {
        spawn_catalog(config(context, committee), context.child(label)).await
    }

    #[test]
    fn backfill_command_kinds_are_stable() {
        fn reply<T>() -> Reply<T> {
            oneshot::channel().0
        }

        let commands = [
            (
                Command::<Sha256, MinPk, TestBody>::Admit(
                    Vec::new(),
                    AdmissionMode::Buffered,
                    reply(),
                ),
                "admit",
            ),
            (
                Command::WaitForCustody(Vec::new(), reply()),
                "wait_for_custody",
            ),
            (Command::Bodies(Vec::new(), reply()), "bodies"),
        ];

        for (command, expected) in commands {
            assert_eq!(command.kind(), expected);
        }
    }

    #[test]
    fn delivery_cursor_overflow_coalesces_between_reset_barriers() {
        let mut overflow = VecDeque::new();
        DeliveryCursorControl::handle(
            &mut overflow,
            DeliveryCursorControl {
                generation: 3,
                acknowledged: Some(OutputIndex::new(1)),
                reply: None,
            },
        );
        DeliveryCursorControl::handle(
            &mut overflow,
            DeliveryCursorControl {
                generation: 3,
                acknowledged: Some(OutputIndex::new(4)),
                reply: None,
            },
        );
        assert_eq!(overflow.len(), 1);
        assert_eq!(overflow[0].acknowledged, Some(OutputIndex::new(4)));

        let (reply, _receiver) = oneshot::channel();
        DeliveryCursorControl::handle(
            &mut overflow,
            DeliveryCursorControl {
                generation: 4,
                acknowledged: None,
                reply: Some(reply),
            },
        );
        DeliveryCursorControl::handle(
            &mut overflow,
            DeliveryCursorControl {
                generation: 4,
                acknowledged: Some(OutputIndex::new(2)),
                reply: None,
            },
        );
        DeliveryCursorControl::handle(
            &mut overflow,
            DeliveryCursorControl {
                generation: 4,
                acknowledged: Some(OutputIndex::new(7)),
                reply: None,
            },
        );
        assert_eq!(overflow.len(), 3);
        assert!(overflow[1].reply.is_some());
        assert_eq!(overflow[2].acknowledged, Some(OutputIndex::new(7)));
    }

    fn producer_block(
        committee: &Committee<MinPk>,
        chain: u32,
        timestamp: u64,
    ) -> Arc<TransactionBlock<Sha256, TestBody>> {
        let body = TestBody::new(
            Sha256::hash(&[b"application parent"]),
            Height::new(9),
            timestamp,
        );
        let header = committee.transaction_header(chain, body.digest());
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    fn output_row(
        index: OutputIndex,
        block: &Arc<TransactionBlock<Sha256, TestBody>>,
    ) -> OutputRow<Sha256Digest> {
        OutputRow::new(index, CustodyRef::for_test(block))
    }

    #[test]
    fn block_cache_is_byte_bounded_and_idempotent() {
        let committee = Committee::<MinPk>::new_with_namespace_and_producers(
            7,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BLOCK_CACHE",
            6,
            (0..4).map(Participant::new).collect(),
            Limits::new(2, 2).unwrap(),
        );
        let first = producer_block(&committee, 0, 10);
        let second = producer_block(&committee, 0, 11);
        let third = producer_block(&committee, 0, 12);
        let block_len = first.encode_size();
        assert_eq!(second.encode_size(), block_len);
        assert_eq!(third.encode_size(), block_len);

        let mut cache = BlockCache::new(NonZeroUsize::new(block_len * 2).unwrap());
        cache.insert(first.reference(), Arc::clone(&first));
        cache.insert(first.reference(), Arc::clone(&first));
        assert_eq!(cache.encoded_bytes, block_len);
        assert_eq!(cache.order.len(), 1);

        cache.insert(second.reference(), Arc::clone(&second));
        assert_eq!(
            cache
                .get_by_digest(second.reference().chain(), second.reference().digest())
                .as_deref(),
            Some(second.as_ref())
        );
        cache.insert(third.reference(), Arc::clone(&third));
        assert!(cache.get(&first.reference()).is_none());
        assert_eq!(
            cache.get(&second.reference()).as_deref(),
            Some(second.as_ref())
        );
        assert_eq!(
            cache.get(&third.reference()).as_deref(),
            Some(third.as_ref())
        );
        assert_eq!(cache.encoded_bytes, block_len * 2);

        let mut oversized = BlockCache::new(NonZeroUsize::new(block_len - 1).unwrap());
        oversized.insert(first.reference(), first);
        assert!(oversized.blocks.is_empty());
    }

    #[test]
    fn hot_custody_does_not_read_storage() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                39,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HOT_CUSTODY",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), context.child("catalog")).await;
            let block = producer_block(&committee, 0, 39);
            let reference = block.reference();
            client.admit_block(reference, block).await.unwrap();

            let before = metric_total(&context.encode(), "runtime_storage_reads_total");
            let custody = client.wait_for_custody(vec![reference]).await.unwrap();
            let after = metric_total(&context.encode(), "runtime_storage_reads_total");
            assert!(custody[0].is_some());
            assert_eq!(after, before);

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn pending_metadata_bypasses_finalized_archive_reads() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                52,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_PENDING_METADATA",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..4)
                .map(|chain| producer_block(&committee, chain, 52 + u64::from(chain)))
                .collect::<Vec<_>>();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                config.max_commit_outputs = NZUsize!(4);
                config.archive.page_cache = CacheRef::from_pooler(context, NZU16!(1), NZUsize!(1));
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &blocks {
                emitted[block.reference().chain().get() as usize] = block.reference();
            }
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(3)),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                        .collect(),
                    checkpoint,
                })
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;
            let reference = blocks[0].reference();
            let gate = reads.arm();
            let mut pending = Box::pin(async {
                let (custody, headers) = futures::try_join!(
                    client.wait_for_custody(vec![reference]),
                    client.header_segments(vec![(reference, 1)], usize::MAX),
                )?;
                Ok::<_, Error>((custody, headers))
            });
            let (custody, headers) = commonware_macros::select! {
                result = &mut pending => result.unwrap(),
                result = gate.blocked => {
                    result.unwrap();
                    panic!("pending metadata lookup reached finalized storage")
                },
            };
            assert!(custody[0].is_some());
            assert_eq!(headers[0], vec![blocks[0].header().clone()]);

            drop(pending);
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn header_completion_owns_all_branch_credits_on_error_or_cancellation() {
        deterministic::Runner::default().start(|_| async move {
            for canceled in [false, true] {
                for count in 1..=4 {
                    let mut steps = Pool::default();
                    steps.push(async { (0, Err(Error::Invalid("header read failed"))) });
                    for _ in 1..count {
                        steps.push(std::future::pending());
                    }
                    let (reply, receiver) = oneshot::channel();
                    let _receiver = (!canceled).then_some(receiver);
                    let completion = MetadataJob::<DeterministicContext, Sha256>::Headers {
                        state: HeaderSegmentsState {
                            max_bytes: usize::MAX,
                            branches: Vec::new(),
                        },
                        reply,
                        steps,
                    }
                    .execute()
                    .await;
                    assert_eq!(completion.steps(), count);
                    if canceled {
                        assert!(matches!(completion, MetadataCompletion::Canceled(_)));
                    } else {
                        assert!(matches!(
                            completion,
                            MetadataCompletion::Headers { result: Err(_), .. }
                        ));
                    }
                }
            }
        });
    }

    #[test]
    fn header_batch_capacity_is_independent_of_admission_cut() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                57,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HEADER_CAPACITY",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..4)
                .map(|chain| producer_block(&committee, chain, 57 + u64::from(chain)))
                .collect::<Vec<_>>();
            let mut config = config(&context, &committee);
            set_capacity(&mut config, 1);
            let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }

            let headers = client
                .header_segments(
                    blocks.iter().map(|block| (block.reference(), 1)).collect(),
                    usize::MAX,
                )
                .await
                .unwrap();
            assert_eq!(headers.len(), blocks.len());
            for (headers, block) in headers.iter().zip(&blocks) {
                assert_eq!(headers, std::slice::from_ref(block.header()));
            }

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn header_branches_advance_independently() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                58,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_HEADER_BRANCHES",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let parents = (0..2)
                .map(|chain| producer_block(&committee, chain, 58 + u64::from(chain)))
                .collect::<Vec<_>>();
            let children = parents
                .iter()
                .enumerate()
                .map(|(chain, parent)| {
                    let body = TestBody::new(
                        Sha256::hash(&[b"application parent"]),
                        Height::new(10),
                        60 + chain as u64,
                    );
                    let header = TransactionBlockHeader::new(
                        committee.config.epoch(),
                        ChainId::new(chain as u32),
                        Height::new(2),
                        parent.reference().digest(),
                        body.digest(),
                    )
                    .unwrap();
                    Arc::new(TransactionBlock::new(header, body).unwrap())
                })
                .collect::<Vec<_>>();
            let blocks = parents.iter().chain(&children).cloned().collect::<Vec<_>>();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                config.max_commit_outputs = NZUsize!(4);
                config.finalized_blocks = ArchiveMode::Immutable;
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &children {
                emitted[block.reference().chain().get() as usize] = block.reference();
            }
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                        .collect(),
                    checkpoint: Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        current.floor(),
                        current.history(),
                        current.history_index(),
                        current.ordered().to_vec(),
                        emitted.clone(),
                        Some(OutputIndex::new(3)),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            client.promoted(emitted).await.unwrap();
            drop(client);
            handle.abort();
            let _ = handle.await;

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;
            let slow_gate = reads.arm();
            let fast_gate = reads.arm();
            let mut request = Box::pin(client.header_segments(
                children
                    .iter()
                    .map(|block| (block.reference(), 2))
                    .collect(),
                usize::MAX,
            ));
            let mut first_steps = Box::pin(try_join_all([slow_gate.blocked, fast_gate.blocked]));
            commonware_macros::select! {
                result = &mut first_steps => { result.unwrap(); },
                result = &mut request => panic!("header request completed before both branches blocked: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("both header branches did not reach independent storage reads")
                },
            }
            drop(first_steps);

            let continuation_gate = reads.arm();
            fast_gate.release.send(()).unwrap();
            commonware_macros::select! {
                result = continuation_gate.blocked => result.unwrap(),
                result = &mut request => panic!("header request completed while one branch remained blocked: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("an unblocked header branch did not advance independently")
                },
            }
            continuation_gate.release.send(()).unwrap();
            slow_gate.release.send(()).unwrap();
            let headers = request.await.unwrap();
            for ((headers, child), parent) in headers.iter().zip(&children).zip(&parents) {
                assert_eq!(headers, &[child.header().clone(), parent.header().clone()]);
            }

            drop(client);
            handle.abort();
            let _ = handle.await;
        });
    }

    #[test]
    fn historical_body_reads_do_not_displace_live_custody() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                40,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_CACHE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 40);
            let second = producer_block(&committee, 0, 41);
            let absent = producer_block(&committee, 0, 42);
            let mut config = config(&context, &committee);
            config.max_hot_block_bytes =
                NonZeroUsize::new(first.encode_size()).expect("the block is non-empty");
            let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
            client
                .admit_block(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            client
                .admit_block(second.reference(), Arc::clone(&second))
                .await
                .unwrap();

            let materialized_before = metric_total(&context.encode(), "materialized_bodies_total");
            assert_eq!(
                client.bodies(vec![first.reference()]).await.unwrap()[0].as_deref(),
                Some(first.as_ref())
            );
            let materialized_after = metric_total(&context.encode(), "materialized_bodies_total");
            assert!(materialized_after > materialized_before);

            assert_eq!(
                client.bodies(vec![first.reference()]).await.unwrap()[0].as_deref(),
                Some(first.as_ref())
            );
            assert_eq!(
                metric_total(&context.encode(), "materialized_bodies_total"),
                materialized_after
            );

            let custody = client
                .wait_for_custody(vec![
                    second.reference(),
                    first.reference(),
                    absent.reference(),
                ])
                .await
                .unwrap();
            assert!(custody[0].is_some());
            assert!(custody[1].is_some());
            assert!(custody[2].is_none());
            let metrics = context.encode();
            assert_eq!(metric_total(&metrics, "custody_cache_hits_total"), 1);
            assert_eq!(metric_total(&metrics, "custody_storage_hits_total"), 1);
            assert_eq!(metric_total(&metrics, "custody_misses_total"), 1);
            assert_eq!(metric_total(&metrics, "block_cache_evictions_total"), 1);
            assert_eq!(metric_total(&metrics, "block_cache_items"), 1);
            assert_eq!(
                metric_total(&metrics, "block_cache_bytes"),
                u64::try_from(second.encode_size()).unwrap()
            );
            assert_eq!(metric_total(&metrics, "materialized_cache_items"), 1);
            assert_eq!(
                metric_total(&metrics, "materialized_cache_bytes"),
                u64::try_from(first.encode_size()).unwrap()
            );

            assert_eq!(
                client.bodies(vec![second.reference()]).await.unwrap()[0].as_deref(),
                Some(second.as_ref())
            );
            let materialized_live = metric_total(&context.encode(), "materialized_bodies_total");
            assert_eq!(materialized_live, materialized_after);

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[derive(Clone, Copy)]
    enum IndependentReadCase {
        Body,
        Candidate,
        Headers,
        Outputs,
    }

    #[rstest::rstest]
    #[case::body(false, IndependentReadCase::Body)]
    #[case::sealed_body(true, IndependentReadCase::Body)]
    #[case::candidate(false, IndependentReadCase::Candidate)]
    #[case::headers(false, IndependentReadCase::Headers)]
    #[case::outputs(false, IndependentReadCase::Outputs)]
    fn independent_read_completes_during_segment_open(
        #[case] sealed: bool,
        #[case] read_case: IndependentReadCase,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                81,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_DURING_APPEND",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let configure = || {
                let mut config = config(&context, &committee);
                set_capacity(&mut config, 1);
                config
            };
            let first = producer_block(&committee, 0, 81);
            let next = producer_block(&committee, 1, 82);
            let (client, handle, _delivery) =
                spawn_catalog(configure(), context.child("initial")).await;
            client
                .admit_block(first.reference(), first.clone())
                .await
                .unwrap();
            if sealed {
                let tail = producer_block(&committee, 2, 83);
                client.admit_block(tail.reference(), tail).await.unwrap();
            }
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = first.reference();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &first)],
                    checkpoint: Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        current.floor(),
                        current.history(),
                        current.history_index(),
                        current.ordered().to_vec(),
                        emitted,
                        Some(OutputIndex::ZERO),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            let refs = client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024))
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) = drive_pending_syncs(
                &syncs,
                spawn_catalog(configure(), delayed.child("reopened")),
            )
            .await;
            syncs.arm();
            let mut admission = Box::pin(client.stage_block(next));
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                select! {
                    _ = &mut admission => panic!("append completed before opening its segment"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert!(syncs.calls() > 0, "new segment did not reach storage");
            let mut ordinary = Box::pin(client.block(first.reference()));
            select! {
                _ = &mut ordinary => panic!("ordinary read overtook the admission"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            let bodies = promoter::Bodies::new(client.clone(), None);
            let mut read = Box::pin(async {
                match read_case {
                    IndependentReadCase::Body => {
                        assert_eq!(
                            bodies.materialize(&refs).await.unwrap()[0].as_ref(),
                            first.as_ref()
                        );
                    }
                    IndependentReadCase::Candidate => {
                        let candidate = client
                            .request(|reply| {
                                Command::BodyCandidateByDigest(
                                    first.reference().chain(),
                                    first.reference().digest(),
                                    reply,
                                )
                            })
                            .await
                            .unwrap()
                            .expect("the stored block has a candidate");
                        assert_eq!(candidate.0, first.reference());
                    }
                    IndependentReadCase::Headers => {
                        let headers = client
                            .header_segments(vec![(first.reference(), 1)], 1024)
                            .await
                            .unwrap();
                        assert_eq!(headers, vec![vec![first.header().clone()]]);
                    }
                    IndependentReadCase::Outputs => {
                        let outputs = client
                            .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024))
                            .await
                            .unwrap();
                        assert_eq!(outputs[0].reference, first.reference());
                    }
                }
            });
            select! {
                _ = &mut read => {},
                _ = context.sleep(std::time::Duration::from_millis(10)) => {
                    panic!("independent catalog read waited for unrelated segment-open I/O");
                },
            }
            assert_eq!(
                metric_total(&context.encode(), "materialized_bodies_total"),
                u64::from(matches!(read_case, IndependentReadCase::Body))
            );
            syncs.unblock();
            admission.await.unwrap().wait().await.unwrap();
            assert_eq!(ordinary.await.unwrap().as_deref(), Some(first.as_ref()));
            drop(read);
            drop(bodies);
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn body_reads_wait_for_materialization_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                44,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_BACKPRESSURE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 44);
            let second = producer_block(&committee, 1, 45);
            let evictor = producer_block(&committee, 2, 46);
            let mut initial = config(&context, &committee);
            set_capacity(&mut initial, 1);
            initial.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
            let (client, handle, _delivery) =
                spawn_catalog(initial, context.child("initial")).await;
            for block in [&first, &second, &evictor] {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let mut reopened = config(&context, &committee);
            set_capacity(&mut reopened, 1);
            reopened.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
            let (client, handle, _delivery) =
                spawn_catalog(reopened, delayed.child("catalog")).await;

            let gate = reads.arm();
            let mut first_read = Box::pin(client.block(first.reference()));
            let mut blocked = Box::pin(gate.blocked);
            commonware_macros::select! {
                result = &mut blocked => result.unwrap(),
                result = &mut first_read => panic!("cold body read completed before reaching storage: {result:?}"),
            }
            let mut second_read = Box::pin(client.block(second.reference()));
            commonware_macros::select! {
                result = &mut second_read => panic!("body request bypassed materialization backpressure: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            let headers = select! {
                result = client.header_segments(vec![(evictor.reference(), 1)], 1024) => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(10)) => {
                    panic!("body backpressure blocked an independent header lookup");
                },
            };
            assert_eq!(headers, vec![vec![evictor.header().clone()]]);

            gate.release.send(()).unwrap();
            assert_eq!(first_read.await.unwrap().as_deref(), Some(first.as_ref()));
            assert_eq!(second_read.await.unwrap().as_deref(), Some(second.as_ref()));
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn body_read_groups_respect_materialized_cache_budget() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                54,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_MATERIALIZED_GROUP_BOUND",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (64..97)
                .map(|timestamp| producer_block(&committee, 0, timestamp))
                .collect::<Vec<_>>();
            let block_bytes = blocks[0].encode_size();
            assert!(blocks.iter().all(|block| block.encode_size() == block_bytes));

            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, 64);
                config.max_hot_block_bytes = NonZeroUsize::new(block_bytes * 64).unwrap();
                config.max_materialized_block_bytes = NonZeroUsize::new(block_bytes).unwrap();
                config
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("catalog")).await;
            let gate = reads.arm();
            let mut request = Box::pin(client.bodies(
                blocks.iter().map(|block| block.reference()).collect(),
            ));
            let mut blocked = Box::pin(gate.blocked);
            commonware_macros::select! {
                result = &mut blocked => result.unwrap(),
                result = &mut request => panic!("cold body request completed before reaching storage: {result:?}"),
            }
            assert_eq!(
                metric_total(&context.encode(), "materialization_active_bytes"),
                u64::try_from(block_bytes).unwrap(),
            );

            gate.release.send(()).unwrap();
            assert_eq!(request.await.unwrap().len(), blocks.len());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn concurrent_body_reads_share_cold_materialization() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                45,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_COALESCE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let cold = producer_block(&committee, 0, 45);
            let mut initial = config(&context, &committee);
            initial.max_hot_block_bytes = NonZeroUsize::new(cold.encode_size()).unwrap();
            let (client, handle, _delivery) =
                spawn_catalog(initial, context.child("initial")).await;
            client
                .admit_block(cold.reference(), Arc::clone(&cold))
                .await
                .unwrap();
            for timestamp in 46..63 {
                let evictor = producer_block(&committee, 1, timestamp);
                client
                    .admit_block(evictor.reference(), evictor)
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let mut reopened = config(&context, &committee);
            reopened.max_hot_block_bytes = NonZeroUsize::new(cold.encode_size()).unwrap();
            let (client, handle, _delivery) =
                spawn_catalog(reopened, delayed.child("catalog")).await;

            let gate = reads.arm();
            let mut first = Box::pin(client.block(cold.reference()));
            let mut blocked = Box::pin(gate.blocked);
            commonware_macros::select! {
                result = &mut blocked => result.unwrap(),
                result = &mut first => panic!("cold body read completed before reaching storage: {result:?}"),
            }
            let groups_before = metric_total(&context.encode(), "materialization_groups_total");
            let mut second = Box::pin(client.block(cold.reference()));
            let mut progress = Box::pin(client.progress());
            commonware_macros::select! {
                result = &mut progress => { result.unwrap(); },
                result = &mut second => panic!("duplicate body read completed independently: {result:?}"),
            }
            drop(progress);
            let groups_after = metric_total(&context.encode(), "materialization_groups_total");
            assert_eq!(groups_after, groups_before);

            gate.release.send(()).unwrap();
            assert_eq!(first.await.unwrap().as_deref(), Some(cold.as_ref()));
            assert_eq!(second.await.unwrap().as_deref(), Some(cold.as_ref()));
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn sequential_body_reads_reuse_resident_sealed_readers() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                50,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RETAINED_SEGMENT_READER",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            // Two blocks per segment: segments 0..=RESIDENCY exercise the residency bound and
            // the final full segment stays current. Heights start at 128 so every block encodes
            // to the same size and the one-block hot cache always holds only the latest read.
            let blocks = (0..2 * (BODY_READER_RESIDENCY as u32 + 2))
                .map(|offset| producer_block(&committee, offset % 4, 128 + u64::from(offset)))
                .collect::<Vec<_>>();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, 2);
                config.max_hot_block_bytes = NonZeroUsize::new(blocks[0].encode_size()).unwrap();
                config.max_materialized_block_bytes = config.max_hot_block_bytes;
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            // Reopen: the current sealed segment's reader is offered at spawn, so one resident
            // slot is already occupied.
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("reopened")).await;
            let acquisitions = || metric_total(&context.encode(), "reader_acquisitions_total");
            let recoveries = || {
                metric_sum(
                    &context.encode(),
                    "reader_acquisitions_total",
                    Some("Recovered"),
                )
            };
            let read = |index: usize| {
                let client = &client;
                let blocks = &blocks;
                async move {
                    assert_eq!(
                        client
                            .block(blocks[index].reference())
                            .await
                            .unwrap()
                            .as_deref(),
                        Some(blocks[index].as_ref())
                    );
                }
            };

            read(0).await;
            assert_eq!(
                acquisitions(),
                1,
                "the first cold segment reader was not acquired"
            );
            read(1).await;
            assert_eq!(
                acquisitions(),
                1,
                "sequential reads from one sealed segment reopened its journal"
            );

            // Fill the remaining resident slots with distinct sealed segments.
            let filling = BODY_READER_RESIDENCY - 2;
            for segment in 1..=filling {
                read(2 * segment).await;
            }
            assert_eq!(acquisitions(), 1 + filling as u64);
            read(0).await;
            assert_eq!(
                acquisitions(),
                1 + filling as u64,
                "reader was evicted before the materializer reached residency"
            );

            // The next two distinct segments evict the offered current reader, then the oldest
            // opened reader (segment 0). Revisiting segment 0 must reacquire it through its
            // sealed proof, never through recovery.
            read(2 * (filling + 1)).await;
            assert_eq!(
                acquisitions(),
                2 + filling as u64,
                "next segment past residency"
            );
            read(2 * (filling + 2)).await;
            assert_eq!(
                acquisitions(),
                3 + filling as u64,
                "second segment past residency"
            );
            read(0).await;
            assert_eq!(
                acquisitions(),
                4 + filling as u64,
                "reader retention exceeded the materializer's bounded residency"
            );
            assert_eq!(
                recoveries(),
                0,
                "a sealed segment reader was reacquired through mutable recovery"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn sealed_admission_reader_avoids_a_cold_acquisition() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                51,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SEALED_READER_HANDOFF",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 51);
            let second = producer_block(&committee, 1, 52);
            let mut config = config(&context, &committee);
            set_capacity(&mut config, 1);
            config.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
            let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;

            client
                .admit_block(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            client
                .admit_block(second.reference(), Arc::clone(&second))
                .await
                .unwrap();
            assert_eq!(
                metric_total(&context.encode(), "reader_acquisitions_total"),
                0
            );
            assert_eq!(
                client.block(first.reference()).await.unwrap().as_deref(),
                Some(first.as_ref())
            );
            assert_eq!(
                metric_total(&context.encode(), "reader_acquisitions_total"),
                0,
                "a live-sealed segment was reopened before its first materialization"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn recovered_sealed_reader_survives_segment_rollover() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                52,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RECOVERED_READER_HANDOFF",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 52);
            let second = producer_block(&committee, 1, 53);
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, 1);
                config.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            client
                .admit_block(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("reopened")).await;
            client
                .admit_block(second.reference(), Arc::clone(&second))
                .await
                .unwrap();
            assert_eq!(
                client.block(first.reference()).await.unwrap().as_deref(),
                Some(first.as_ref())
            );
            assert_eq!(
                metric_total(&context.encode(), "reader_acquisitions_total"),
                0,
                "a recovered sealed segment was reopened after rollover"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn body_reads_refresh_current_segment_snapshot() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                49,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_SNAPSHOT_REFRESH",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..6)
                .map(|offset| producer_block(&committee, offset % 4, 49 + u64::from(offset)))
                .collect::<Vec<_>>();
            let mut initial = config(&context, &committee);
            initial.max_hot_block_bytes =
                NonZeroUsize::new(blocks[0].encode_size() * 2).expect("the blocks are non-empty");
            initial.archive.page_cache =
                CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(1));
            let (client, handle, _delivery) =
                spawn_catalog(initial, context.child("initial")).await;
            for block in &blocks[..3] {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let mut reopened = config(&context, &committee);
            reopened.max_hot_block_bytes =
                NonZeroUsize::new(blocks[0].encode_size() * 2).expect("the blocks are non-empty");
            reopened.archive.page_cache =
                CacheRef::from_pooler(&context, NZU16!(1), NZUsize!(1));
            let (client, handle, _delivery) =
                spawn_catalog(reopened, delayed.child("reopened")).await;

            let gate = reads.arm();
            let mut first = Box::pin(client.block(blocks[0].reference()));
            commonware_macros::select! {
                result = &mut first => panic!("body read completed before reaching storage: {result:?}"),
                result = gate.blocked => result.unwrap(),
            }

            for block in &blocks[3..] {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let latest = commonware_macros::select! {
                result = client.block(blocks[3].reference()) => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("newer ready snapshot was not scheduled independently")
                },
            };
            assert_eq!(latest.as_deref(), Some(blocks[3].as_ref()));

            gate.release.send(()).unwrap();
            assert_eq!(first.await.unwrap().as_deref(), Some(blocks[0].as_ref()));
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn cold_segment_acquisition_is_shared_without_blocking_other_segments() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                48,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SEGMENT_READERS",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..9)
                .map(|offset| producer_block(&committee, offset % 4, 48 + u64::from(offset)))
                .collect::<Vec<_>>();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, 4);
                config.max_hot_block_bytes =
                    NonZeroUsize::new(blocks[0].encode_size() * 4).unwrap();
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("catalog")).await;

            let gate = reads.arm();
            let mut first = Box::pin(client.block(blocks[0].reference()));
            commonware_macros::select! {
                result = &mut first => panic!("cold body read completed before reaching storage: {result:?}"),
                result = gate.blocked => result.unwrap(),
            }

            let mut same_segment = Box::pin(client.block(blocks[1].reference()));
            commonware_macros::select! {
                result = &mut same_segment => panic!("same-segment request opened a second reader: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {},
            }

            let independent = client.block(blocks[4].reference());
            let independent = commonware_macros::select! {
                result = independent => result,
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("blocked segment stalled an independent segment")
                },
            };
            assert_eq!(independent.unwrap().as_deref(), Some(blocks[4].as_ref()));

            gate.release.send(()).unwrap();
            assert_eq!(first.await.unwrap().as_deref(), Some(blocks[0].as_ref()));
            assert_eq!(
                same_segment.await.unwrap().as_deref(),
                Some(blocks[1].as_ref())
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn producer_admission_progresses_while_cold_body_read_is_blocked() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                42,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_ADMISSION",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let cold = producer_block(&committee, 0, 42);
            let staged = producer_block(&committee, 1, 44);
            let mut initial = config(&context, &committee);
            initial.max_hot_block_bytes =
                NonZeroUsize::new(cold.encode_size()).expect("the block is non-empty");
            let (client, handle, _delivery) =
                spawn_catalog(initial, context.child("catalog")).await;
            client
                .admit_block(cold.reference(), Arc::clone(&cold))
                .await
                .unwrap();
            for timestamp in 43..59 {
                let evictor = producer_block(&committee, 0, timestamp);
                client
                    .admit_block(evictor.reference(), evictor)
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let mut config = config(&context, &committee);
            config.max_hot_block_bytes =
                NonZeroUsize::new(cold.encode_size()).expect("the block is non-empty");
            let (client, handle, _delivery) =
                spawn_catalog(config, delayed.child("catalog")).await;

            let gate = reads.arm();
            let mut blocked = Box::pin(gate.blocked);
            let mut body_read = Box::pin(client.bodies(vec![cold.reference()]));
            commonware_macros::select! {
                result = &mut blocked => result.expect("read gate closed before the body read arrived"),
                result = &mut body_read => panic!("cold body read completed before reaching storage: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("cold body read did not reach storage")
                },
            }

            let mut admission =
                Box::pin(client.admit_block(staged.reference(), Arc::clone(&staged)));
            commonware_macros::select! {
                result = &mut admission => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("durable producer admission was blocked behind a cold body read")
                },
            }
            drop(admission);

            gate.release.send(()).expect("blocked read was dropped");
            assert_eq!(
                body_read.await.unwrap()[0].as_deref(),
                Some(cold.as_ref())
            );
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn producer_admission_progresses_while_cold_metadata_read_is_blocked() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                56,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_METADATA_READ_ADMISSION",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let cold = producer_block(&committee, 0, 56);
            let staged = producer_block(&committee, 1, 57);

            let configure = |context: &DeterministicContext| config(context, &committee);
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            client
                .admit_block(cold.reference(), Arc::clone(&cold))
                .await
                .unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = cold.reference();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &cold)],
                    checkpoint: Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        current.floor(),
                        current.history(),
                        current.history_index(),
                        current.ordered().to_vec(),
                        emitted,
                        Some(OutputIndex::ZERO),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;

            let gate = reads.arm();
            let mut blocked = Box::pin(gate.blocked);
            let mut metadata_read =
                Box::pin(client.output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024)));
            commonware_macros::select! {
                result = &mut blocked => result.expect("read gate closed before metadata I/O"),
                _ = &mut metadata_read => {
                    panic!("cold metadata read completed before reaching storage")
                },
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("cold metadata read did not reach storage")
                },
            }

            let mut prune = Box::pin(client.prune(0));
            commonware_macros::select! {
                result = &mut prune => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("pruning was blocked behind an exact cold metadata read")
                },
            }
            drop(prune);

            let mut admission =
                Box::pin(client.admit_block(staged.reference(), Arc::clone(&staged)));
            commonware_macros::select! {
                result = &mut admission => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("durable producer admission was blocked behind a cold metadata read")
                },
            }
            drop(admission);

            gate.release.send(()).expect("blocked read was dropped");
            assert_eq!(metadata_read.await.unwrap()[0].reference, cold.reference());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[derive(Clone, Copy)]
    enum DescriptorReadCase {
        Concurrent,
        SpeculativeTail,
        Limited,
        Canceled,
    }

    #[rstest::rstest]
    #[case::prunable(ArchiveMode::Prunable, DescriptorReadCase::Concurrent)]
    #[case::immutable(ArchiveMode::Immutable, DescriptorReadCase::Concurrent)]
    #[case::prunable_speculative_tail(ArchiveMode::Prunable, DescriptorReadCase::SpeculativeTail)]
    #[case::immutable_speculative_tail(ArchiveMode::Immutable, DescriptorReadCase::SpeculativeTail)]
    #[case::prunable_limited(ArchiveMode::Prunable, DescriptorReadCase::Limited)]
    #[case::immutable_limited(ArchiveMode::Immutable, DescriptorReadCase::Limited)]
    #[case::prunable_canceled(ArchiveMode::Prunable, DescriptorReadCase::Canceled)]
    #[case::immutable_canceled(ArchiveMode::Immutable, DescriptorReadCase::Canceled)]
    fn committed_output_descriptors_read_concurrently(
        #[case] archive: ArchiveMode,
        #[case] scenario: DescriptorReadCase,
    ) {
        deterministic::Runner::timed(std::time::Duration::from_secs(10)).start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                62,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_OUTPUT_DESCRIPTOR_READS",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let speculative_tail = matches!(scenario, DescriptorReadCase::SpeculativeTail);
            let limited = matches!(scenario, DescriptorReadCase::Limited);
            let canceled = matches!(scenario, DescriptorReadCase::Canceled);
            let count = if speculative_tail || limited { 3 } else { 2 };
            let blocks = (0..count)
                .map(|chain| producer_block(&committee, chain, 62 + u64::from(chain)))
                .collect::<Vec<_>>();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                config.max_commit_outputs = NonZeroUsize::new(blocks.len()).unwrap();
                config.finalized_blocks = archive;
                if limited || canceled {
                    config.backfill_concurrency = NZUsize!(2);
                }
                config
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &blocks {
                emitted[block.reference().chain().get() as usize] = block.reference();
            }
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                        .collect(),
                    checkpoint: Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        current.floor(),
                        current.history(),
                        current.history_index(),
                        current.ordered().to_vec(),
                        emitted,
                        Some(OutputIndex::new(u64::from(count - 1))),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            drop(client);
            handle.abort();
            let _ = handle.await;

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (delivery, _delivery) = delivery::channel(delayed.child("delivery_mailbox"));
            let (client, handle, _, promoter_handle, _) = configure(&context)
                .spawn::<_, Sha256>(delayed.child("reopened"), delivery)
                .await
                .unwrap();
            // This fixture owns every metadata request so its read gates and credits are exact.
            if let Some(promoter_handle) = promoter_handle {
                promoter_handle.abort();
                let _ = promoter_handle.await;
            }
            let first = reads.arm();
            let second = reads.arm();
            let tail = (speculative_tail || limited).then(|| reads.arm());
            let mut request = Box::pin(client.output_refs(
                OutputIndex::ZERO,
                NonZeroUsize::new(blocks.len()).unwrap(),
                if speculative_tail {
                    NonZeroUsize::MIN
                } else {
                    NZUsize!(1024 * 1024)
                },
            ));
            commonware_macros::select! {
                result = first.blocked => result.expect("first descriptor read gate closed"),
                _ = &mut request => panic!("descriptor request completed before its first read"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("first committed output descriptor did not reach storage");
                },
            }
            commonware_macros::select! {
                result = second.blocked => result.expect("second descriptor read gate closed"),
                _ = &mut request => panic!("descriptor request completed while its first read was blocked"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("second committed output descriptor waited for the first metadata read");
                },
            }

            if canceled {
                let mut deferred = Box::pin(client.header_segments(
                    vec![(blocks[0].reference(), 1)], 1024,
                ));
                select! {
                    _ = &mut deferred => panic!("header request exceeded metadata credits"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
                let progress = select! {
                    result = client.progress() => result.unwrap(),
                    _ = context.sleep(std::time::Duration::from_millis(10)) => {
                        panic!("read backpressure blocked the command lane");
                    },
                };
                assert_eq!(progress.committed, Some(OutputIndex::new(u64::from(count - 1))));
                drop(deferred);
                let candidate = select! {
                    result = client.request(|reply| Command::BodyCandidateByDigest(
                        blocks[0].reference().chain(), Sha256::hash(&[b"missing candidate"]), reply,
                    )) => result.unwrap(),
                    _ = context.sleep(std::time::Duration::from_millis(10)) => {
                        panic!("canceled read blocked the independent lane behind occupied credits");
                    },
                };
                assert!(candidate.is_none());
                drop(request);
                let replacement = client.output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1024 * 1024));
                let outputs = commonware_macros::select! {
                    result = replacement => result.unwrap(),
                    _ = context.sleep(std::time::Duration::from_millis(100)) => {
                        panic!("canceled descriptor window did not release its credits");
                    },
                };
                assert_eq!(outputs.len(), blocks.len());
                assert!(first.release.is_closed() && second.release.is_closed());
                drop(client);
                handle.abort();
                let _ = handle.await;
                return;
            }
            let mut prefix_releases = Some([first.release, second.release]);
            let tail_release = if let Some(tail) = tail {
                let mut blocked = Box::pin(tail.blocked);
                if limited {
                    commonware_macros::select! {
                        _ = &mut blocked => panic!("descriptor reads exceeded metadata credits"),
                        _ = &mut request => panic!("descriptor request skipped its blocked prefix"),
                        _ = context.sleep(std::time::Duration::from_millis(10)) => {},
                    }
                    for release in prefix_releases.take().unwrap() {
                        release.send(()).unwrap();
                    }
                }
                commonware_macros::select! {
                    result = &mut blocked => result.expect("trailing descriptor read gate closed"),
                    _ = &mut request => panic!("descriptor request completed while its prefix was blocked"),
                    _ = context.sleep(std::time::Duration::from_millis(100)) => {
                        panic!("speculative output descriptor did not reach storage");
                    },
                }
                if limited {
                    tail.release.send(()).unwrap();
                    None
                } else {
                    Some(tail.release)
                }
            } else {
                None
            };
            if let Some(releases) = prefix_releases {
                for release in releases.into_iter().rev() {
                    release.send(()).unwrap();
                }
            }
            let outputs = commonware_macros::select! {
                result = &mut request => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("ready descriptor prefix waited for speculative tail I/O");
                },
            };
            drop(request);
            if let Some(tail_release) = tail_release {
                assert!(tail_release.is_closed(), "unused descriptor read was not canceled");
            }
            assert_eq!(outputs.len(), if speculative_tail { 1 } else { blocks.len() });
            for (index, (output, block)) in outputs.iter().zip(&blocks).enumerate() {
                assert_eq!(output.index, OutputIndex::new(index as u64));
                assert_eq!(output.reference, block.reference());
            }
            drop(client);
            handle.abort();
            let _ = handle.await;
        });
    }

    #[test]
    fn application_prune_preserves_queued_cold_materialization() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                43,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_PINNED_PRUNE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let candidates = (0..=BODY_READ_CONCURRENCY)
                .map(|offset| producer_block(&committee, 0, 100 + offset as u64))
                .collect::<Vec<_>>();
            let current = producer_block(&committee, 1, 200);
            let block_bytes = candidates[0].encode_size();
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, 1);
                config.max_hot_block_bytes =
                    NonZeroUsize::new(block_bytes * BODY_READ_CONCURRENCY).unwrap();
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("first")).await;
            for block in candidates.iter().chain(std::iter::once(&current)) {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let checkpoint = client.checkpoint().await.unwrap();
            let finalized = candidates.last().unwrap();
            let mut emitted = checkpoint.emitted().to_vec();
            emitted[0] = finalized.reference();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, finalized)],
                    checkpoint: Checkpoint::new(
                        checkpoint.epoch(),
                        checkpoint.generation(),
                        checkpoint.archive_layout(),
                        checkpoint.floor(),
                        checkpoint.history(),
                        checkpoint.history_index(),
                        checkpoint.ordered().to_vec(),
                        emitted,
                        Some(OutputIndex::ZERO),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;
            assert_eq!(
                client.delivery_cursor(0, Some(OutputIndex::ZERO)),
                Feedback::Ok
            );
            while client.progress().await.unwrap().acknowledged != Some(OutputIndex::ZERO) {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            let (releases, blocked): (Vec<_>, Vec<_>) = (0..BODY_READ_CONCURRENCY)
                .map(|_| {
                    let gate = reads.arm();
                    (gate.release, gate.blocked)
                })
                .unzip();
            let expected = candidates
                .iter()
                .map(|block| block.reference())
                .collect::<Vec<_>>();
            let mut body_read = Box::pin(client.bodies(expected.clone()));
            let mut blocked = Box::pin(try_join_all(blocked));
            commonware_macros::select! {
                result = &mut blocked => { result.unwrap(); },
                result = &mut body_read => panic!("cold materialization completed before all active reads were gated: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("cold materialization did not fill its read window")
                },
            }

            client.prune(0).await.unwrap();
            for release in releases {
                release.send(()).expect("blocked read was dropped");
            }
            let materialized = body_read.await.unwrap();
            assert_eq!(
                materialized
                    .iter()
                    .map(|block| block.as_ref().unwrap().reference())
                    .collect::<Vec<_>>(),
                expected
            );
            client.prune(0).await.unwrap();

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn body_materialization_balances_request_across_read_jobs() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                54,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_BODY_READ_CONCURRENCY",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..BODY_READ_CONCURRENCY)
                .map(|offset| producer_block(&committee, offset as u32 % 4, 300 + offset as u64))
                .collect::<Vec<_>>();
            let block_bytes = blocks[0].encode_size();
            assert!(blocks.iter().all(|block| block.encode_size() == block_bytes));
            let materialized_bytes = block_bytes * BODY_READ_CONCURRENCY * 3;
            let request_bytes = block_bytes * 2;
            assert!(request_bytes < materialized_bytes / BODY_READ_CONCURRENCY);
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, BODY_READ_CONCURRENCY);
                config.max_materialized_block_bytes =
                    NonZeroUsize::new(materialized_bytes).unwrap();
                config
            };

            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), context.child("initial")).await;
            for block in &blocks {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;
            let gate = reads.arm();
            let references = blocks
                .iter()
                .take(2)
                .rev()
                .map(|block| block.reference())
                .collect::<Vec<_>>();
            let mut body_read = Box::pin(client.bodies(references.clone()));
            let mut blocked = Box::pin(gate.blocked);
            commonware_macros::select! {
                result = &mut blocked => { result.unwrap(); },
                result = &mut body_read => panic!("body materialization completed before reaching storage: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("body materialization did not expose the available read jobs")
                },
            }
            assert_eq!(
                metric_total(&context.encode(), "materialization_groups_total"),
                references.len() as u64,
                "one bounded body request did not expose the available read jobs"
            );
            assert_eq!(
                metric_total(&context.encode(), "materialization_active_jobs"),
                references.len() as u64,
            );
            assert_eq!(
                metric_total(&context.encode(), "materialization_active_bytes"),
                u64::try_from(request_bytes).unwrap(),
            );

            gate.release.send(()).expect("blocked read was dropped");
            let materialized = body_read.await.unwrap();
            assert_eq!(
                materialized
                    .iter()
                    .map(|block| block.as_ref().unwrap().reference())
                    .collect::<Vec<_>>(),
                references
            );
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn warmed_commit_retains_every_requested_hot_body() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                41,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_HANDOFF",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 41);
            let filler = producer_block(&committee, 0, 42);
            let second = producer_block(&committee, 1, 43);
            let mut first_config = config(&context, &committee);
            first_config.max_hot_block_bytes = NonZeroUsize::new(first.encode_size() * 2).unwrap();
            first_config.max_commit_outputs = NZUsize!(2);
            let (client, handle, _delivery) =
                spawn_catalog(first_config, context.child("first")).await;
            for block in [&first, &filler, &second] {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(client);
            assert!(handle.await.is_ok());

            let mut reopened_config = config(&context, &committee);
            reopened_config.max_hot_block_bytes =
                NonZeroUsize::new(first.encode_size() * 2).unwrap();
            reopened_config.max_commit_outputs = NZUsize!(2);
            let (client, handle, mut delivery) =
                spawn_catalog(reopened_config, context.child("reopened")).await;
            for references in [
                vec![first.reference(), filler.reference()],
                vec![first.reference(), second.reference()],
            ] {
                assert!(
                    client
                        .bodies(references)
                        .await
                        .unwrap()
                        .into_iter()
                        .all(|block| block.is_some())
                );
            }

            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = first.reference();
            emitted[1] = second.reference();
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![
                        output_row(OutputIndex::ZERO, &first),
                        output_row(OutputIndex::new(1), &second),
                    ],
                    checkpoint,
                })
                .await
                .unwrap();
            assert_eq!(delivery.next_batch().await.outputs.len(), 2);

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn live_handoff_takes_priority_over_materialized_history() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                47,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SPARSE_HANDOFF",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let first = producer_block(&committee, 0, 47);
            let second = producer_block(&committee, 1, 48);
            let mut initial = config(&context, &committee);
            initial.max_hot_block_bytes = NonZeroUsize::new(second.encode_size()).unwrap();
            initial.max_commit_outputs = NZUsize!(2);
            let (client, handle, _delivery) = spawn_catalog(initial, context.child("first")).await;
            client
                .admit_block(first.reference(), Arc::clone(&first))
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let mut reopened = config(&context, &committee);
            reopened.max_hot_block_bytes = NonZeroUsize::new(second.encode_size()).unwrap();
            reopened.max_materialized_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
            reopened.max_commit_outputs = NZUsize!(2);
            let (client, handle, mut delivery) =
                spawn_catalog(reopened, context.child("reopened")).await;
            assert!(client.bodies(vec![first.reference()]).await.unwrap()[0].is_some());
            client
                .admit_block(second.reference(), Arc::clone(&second))
                .await
                .unwrap();

            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = first.reference();
            emitted[1] = second.reference();
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![
                        output_row(OutputIndex::ZERO, &first),
                        output_row(OutputIndex::new(1), &second),
                    ],
                    checkpoint,
                })
                .await
                .unwrap();

            let batch = delivery.next_batch().await;
            assert_eq!(batch.outputs.len(), 1);
            assert_eq!(batch.outputs[0].stored.index, OutputIndex::new(1));
            assert_eq!(batch.outputs[0].block.as_deref(), Some(second.as_ref()));

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn recovered_handoff_survives_live_cache_eviction() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                49,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_RECOVERED_HANDOFF",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let recovered = producer_block(&committee, 0, 49);
            let filler = producer_block(&committee, 1, 50);
            let encoded_len = u64::try_from(recovered.encode_size()).unwrap();
            let mut catalog_config = config(&context, &committee);
            catalog_config.max_hot_block_bytes =
                NonZeroUsize::new(recovered.encode_size()).unwrap();
            let (client, handle, mut delivery) =
                spawn_catalog(catalog_config, context.child("catalog")).await;
            for block in [&recovered, &filler] {
                client
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }

            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = recovered.reference();
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::ZERO),
            )
            .unwrap();
            client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::ZERO, &recovered)],
                        checkpoint,
                    },
                    vec![delivery::DurableOutput {
                        index: OutputIndex::ZERO,
                        block: Arc::clone(&recovered),
                        encoded_len,
                    }],
                )
                .await
                .unwrap()
                .wait()
                .await
                .unwrap();

            let batch = delivery.next_batch().await;
            assert_eq!(batch.outputs.len(), 1);
            assert_eq!(batch.outputs[0].stored.index, OutputIndex::ZERO);
            assert_eq!(batch.outputs[0].block.as_deref(), Some(recovered.as_ref()));

            drop(client);
            assert!(handle.await.is_ok());
        });
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

    #[test]
    fn custody_sync_does_not_block_catalog_reads() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                7,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ASYNC_CUSTODY",
                6,
                producers,
                limits,
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let catalog_config = config(&context, &committee);
            let (client, handle, _delivery) = drive_pending_syncs(
                &syncs,
                spawn_catalog(catalog_config, delayed.child("catalog")),
            )
            .await;
            let warm = producer_block(&committee, 0, 9);
            drive_pending_syncs(
                &syncs,
                client.admit_block(warm.reference(), warm),
            )
            .await
            .unwrap();
            let block = producer_block(&committee, 0, 10);
            let reference = block.reference();

            syncs.arm();
            let mut admission = Box::pin(client.admit_block(reference, Arc::clone(&block)));
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                commonware_macros::select! {
                    result = &mut admission => panic!("custody completed before its sync: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert!(syncs.calls() > 0, "custody did not start a durability operation");

            let mut read = Box::pin(client.block(reference));
            let mut stored = None;
            for _ in 0..100 {
                commonware_macros::select! {
                    result = &mut read => {
                        stored = Some(result.expect("catalog read succeeds"));
                        break;
                    },
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            let stored = stored.expect("custody sync blocked an independent catalog read");
            drop(read);
            assert_eq!(stored.as_deref(), Some(block.as_ref()));
            commonware_macros::select! {
                result = &mut admission => panic!("custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            syncs.unblock();
            admission.await.unwrap();
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn custody_waiter_does_not_block_unrelated_commands() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                43,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_WAITER",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let block = producer_block(&committee, 0, 43);
            let reference = block.reference();

            syncs.arm();
            let mut admission = Box::pin(client.admit_block(reference, block));
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                commonware_macros::select! {
                    result = &mut admission => panic!("custody completed before durability: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert!(syncs.calls() > 0, "custody cut did not start");

            let mut custody = Box::pin(client.wait_for_custody(vec![reference]));
            commonware_macros::select! {
                _ = &mut custody => panic!("custody completed before durability"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            let mut progress = Box::pin(client.progress());
            commonware_macros::select! {
                result = &mut progress => { result.unwrap(); },
                _ = context.sleep(std::time::Duration::from_millis(1)) => {
                    panic!("custody waiter blocked unrelated catalog work")
                },
            }

            syncs.unblock();
            admission.await.unwrap();
            assert!(custody.await.unwrap()[0].is_some());
            drop(progress);
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn custody_waiters_cover_resolver_and_synchronizer_fanout() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                45,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_FANOUT",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let mut storage_config = config(&context, &committee);
            set_capacity(&mut storage_config, 1);
            storage_config.resolver_mailbox_size = NZUsize!(1);
            storage_config.backfill_concurrency = NZUsize!(1);
            let (client, handle, _delivery) =
                spawn_catalog(storage_config, delayed.child("catalog")).await;
            let block = producer_block(&committee, 0, 45);
            let reference = block.reference();

            syncs.arm();
            client
                .stage_blocks(std::slice::from_ref(&block))
                .await
                .unwrap();
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(syncs.calls() > 0, "custody cut did not start");

            let mut first = Box::pin(client.wait_for_custody(vec![reference]));
            commonware_macros::select! {
                _ = &mut first => panic!("first waiter completed before durability"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            client.progress().await.unwrap();
            let mut second = Box::pin(client.wait_for_custody(vec![reference]));
            commonware_macros::select! {
                _ = &mut second => panic!("first synchronizer lookup exceeded the custody bound"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            client.progress().await.unwrap();
            let mut third = Box::pin(client.wait_for_custody(vec![reference]));
            commonware_macros::select! {
                _ = &mut third => panic!("synchronizer lookups exceeded the custody bound"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            client.progress().await.unwrap();

            syncs.unblock();
            assert!(first.await.unwrap()[0].is_some());
            assert!(second.await.unwrap()[0].is_some());
            assert!(third.await.unwrap()[0].is_some());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn custody_is_invisible_until_admission_is_durable() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                35,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_DURABLE_CUSTODY",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let block = producer_block(&committee, 0, 35);
            let reference = block.reference();

            syncs.arm();
            client
                .stage_blocks(std::slice::from_ref(&block))
                .await
                .unwrap();
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(
                syncs.calls() > 0,
                "custody did not start a durability operation"
            );
            assert!(client.block(reference).await.unwrap().is_some());

            let mut custody = Box::pin(client.wait_for_custody(vec![reference]));
            commonware_macros::select! {
                _ = &mut custody => panic!("custody completed before durability"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            syncs.unblock();
            assert!(custody.await.unwrap()[0].is_some());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn admission_cut_triggers_label_reply_and_eager_cuts() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                27,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUT_TRIGGERS",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;

            // Hold a reply-bearing staged cut in flight.
            syncs.arm();
            let first = client
                .stage_block(producer_block(&committee, 0, 10))
                .await
                .unwrap();
            client.progress().await.unwrap();
            assert!(syncs.calls() > 0, "staged cut did not start");

            // Reply-free buffered blocks accumulate behind the in-flight cut and start as
            // their own small cut once it completes.
            let buffered = [
                producer_block(&committee, 1, 11),
                producer_block(&committee, 2, 12),
            ];
            client.stage_blocks(&buffered).await.unwrap();

            syncs.unblock();
            first.wait().await.unwrap();
            client.prune(0).await.unwrap();
            let metrics = context.encode();
            assert_eq!(
                metric_total(&metrics, "admission_durability_duration_count"),
                2,
                "the staged cut and the buffered cut both completed"
            );
            assert_eq!(
                metric_total(&metrics, "admission_cut_scheduled_items_total"),
                3,
                "every admission was scheduled"
            );
            assert_eq!(
                metric_sum(
                    &metrics,
                    "admission_cut_triggers_total",
                    Some("trigger=\"reply\"")
                ),
                1,
                "the staged cut is labeled by its waiting reply"
            );
            assert_eq!(
                metric_sum(
                    &metrics,
                    "admission_cut_triggers_total",
                    Some("trigger=\"eager\"")
                ),
                1,
                "the small reply-free cut is labeled as batchable"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn deferred_barrier_commands_hold_intake_and_admissions_record_dwell() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                26,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INTAKE_INSTRUMENTATION",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let blocks = [
                producer_block(&committee, 0, 10),
                producer_block(&committee, 1, 11),
            ];

            // Block the first admission cut so a second cut queues behind it.
            syncs.arm();
            let first = client.stage_block(blocks[0].clone()).await.unwrap();
            client.progress().await.unwrap();
            assert!(syncs.calls() > 0, "first admission cut did not start");
            let second = client.stage_block(blocks[1].clone()).await.unwrap();

            // A commit-barrier command defers until admission quiescence, and the occupied
            // deferred slot holds back every later command.
            let mut prune = Box::pin(client.prune(0));
            commonware_macros::select! {
                result = &mut prune => panic!("prune completed before quiescence: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            let mut blocked = Box::pin(client.progress());
            commonware_macros::select! {
                result = &mut blocked => panic!("intake proceeded past a deferred barrier: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            syncs.unblock();
            first.wait().await.unwrap();
            second.wait().await.unwrap();
            prune.await.unwrap();
            blocked.await.unwrap();

            let metrics = context.encode();
            assert!(
                metric_total(&metrics, "admission_command_dwell_duration_count") >= 2,
                "both stage commands record admission dwell"
            );
            assert!(
                metric_sum(
                    &metrics,
                    "work_nanoseconds_total",
                    Some("source=\"wait\",operation=\"prune\"")
                ) >= 1_000_000,
                "the deferred prune wait is separate from command execution"
            );
            assert!(
                metric_sum(
                    &metrics,
                    "work_calls_total",
                    Some("source=\"command\",operation=\"admit\"")
                ) >= 2,
                "admission handlers are counted independently of background durability"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn oversized_block_is_rejected_before_custody() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                32,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_BLOCK_BOUND",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let mut config = config(&context, &committee);
            config.max_block_bytes = NZUsize!(1);
            let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
            let block = producer_block(&committee, 0, 32);
            let reference = block.reference();

            assert!(matches!(
                client.stage_blocks(std::slice::from_ref(&block)).await,
                Err(Error::Invalid(_))
            ));
            assert!(client.block(reference).await.unwrap().is_none());

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn durable_admission_starts_before_deferred_reads() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                24,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_DURABILITY_FAIRNESS",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let block = producer_block(&committee, 0, 10);
            let reference = block.reference();
            let (admission_reply, mut admission) = oneshot::channel();
            let (read_reply, read) = oneshot::channel();

            syncs.arm();
            assert!(
                client
                    .commands
                    .enqueue(TracedCommand::new(Command::Admit(
                        vec![Admission::Block(reference, block.clone())],
                        AdmissionMode::Durable,
                        admission_reply,
                    )))
                    .accepted()
            );
            assert!(
                client
                    .commands
                    .enqueue(TracedCommand::new(Command::Bodies(
                        vec![reference],
                        read_reply,
                    )))
                    .accepted()
            );

            assert_eq!(
                read.await.unwrap().unwrap()[0].as_deref(),
                Some(block.as_ref())
            );
            assert!(
                syncs.calls() > 0,
                "deferred reads overtook the pending durability cut"
            );
            assert!(matches!(
                admission.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            syncs.unblock();
            admission.await.unwrap().unwrap();
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn staged_admissions_coalesce_one_trailing_cut_and_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                23,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_CUSTODY_PIPELINE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let mut storage_config = config(&context, &committee);
            storage_config.archive.items_per_section = NZU64!(1024);
            let (client, handle, _delivery) =
                spawn_catalog(storage_config, delayed.child("catalog")).await;
            let blocks = [
                producer_block(&committee, 0, 10),
                producer_block(&committee, 1, 11),
                producer_block(&committee, 2, 12),
            ];

            syncs.arm();
            let first = client.stage_block(blocks[0].clone()).await.unwrap();
            client.progress().await.unwrap();
            let first_cut_syncs = syncs.calls();
            assert!(first_cut_syncs > 0, "first custody cut did not start");
            let mut first = Box::pin(first.wait());
            commonware_macros::select! {
                result = &mut first => panic!("first custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            let second = client.stage_block(blocks[1].clone()).await.unwrap();
            let mut second = Box::pin(second.wait());
            commonware_macros::select! {
                result = &mut second => panic!("second custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            assert_eq!(
                client.block(blocks[1].reference()).await.unwrap().as_deref(),
                Some(blocks[1].as_ref())
            );

            let third = client.stage_block(blocks[2].clone()).await.unwrap();
            drop(third);
            assert_eq!(
                client.block(blocks[2].reference()).await.unwrap().as_deref(),
                Some(blocks[2].as_ref())
            );
            assert_eq!(
                syncs.calls(),
                first_cut_syncs,
                "trailing admissions started separate sync cuts"
            );

            release_next_pending_syncs(&syncs, first_cut_syncs);
            first.await.unwrap();
            for _ in 0..100 {
                if syncs.calls() > first_cut_syncs {
                    break;
                }
                commonware_macros::select! {
                    result = &mut second => panic!("second custody escaped the first cut: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            let trailing_cut_syncs = syncs.calls() - first_cut_syncs;
            assert!(trailing_cut_syncs > 0, "trailing custody cut did not start");
            commonware_macros::select! {
                result = &mut second => panic!("second custody completed before its cut: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            release_next_pending_syncs(&syncs, trailing_cut_syncs);
            second.await.unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let mut storage_config = config(&context, &committee);
            storage_config.archive.items_per_section = NZU64!(1024);
            let (client, handle, _delivery) =
                spawn_catalog(storage_config, context.child("reopen")).await;
            for block in blocks {
                assert_eq!(
                    client.block(block.reference()).await.unwrap().as_deref(),
                    Some(block.as_ref())
                );
            }
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn bounded_admission_batch_moves_to_the_next_trailing_cut() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                44,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ADMISSION_BOUNDARY",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let mut storage_config = config(&context, &committee);
            set_capacity(&mut storage_config, 2);
            storage_config.archive.items_per_section = NZU64!(1024);
            let (client, handle, _delivery) =
                spawn_catalog(storage_config, delayed.child("catalog")).await;
            let blocks = [
                producer_block(&committee, 0, 40),
                producer_block(&committee, 1, 41),
                producer_block(&committee, 2, 42),
                producer_block(&committee, 3, 43),
            ];

            syncs.arm();
            let mut first = Box::pin(client.admit_block(blocks[0].reference(), blocks[0].clone()));
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                commonware_macros::select! {
                    result = &mut first => panic!("first custody completed before durability: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            client.progress().await.unwrap();
            let first_cut_syncs = syncs.calls();
            assert!(first_cut_syncs > 0, "first custody cut did not start");

            let mut trailing = Box::pin(client.admit_block(
                blocks[1].reference(),
                blocks[1].clone(),
            ));
            commonware_macros::select! {
                result = &mut trailing => panic!("trailing custody completed before durability: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            let mut batch = Box::pin(client.stage_blocks(&blocks[2..]));
            commonware_macros::select! {
                result = &mut batch => panic!("batch crossed a full trailing-cut boundary: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            release_next_pending_syncs(&syncs, first_cut_syncs);
            first.await.unwrap();
            let mut admitted = false;
            for _ in 0..100 {
                commonware_macros::select! {
                    result = &mut batch => {
                        result.unwrap();
                        admitted = true;
                        break;
                    },
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert!(admitted, "bounded batch did not enter the next trailing cut");
            drop(batch);

            syncs.unblock();
            trailing.await.unwrap();
            let custody = client
                .wait_for_custody(vec![blocks[2].reference(), blocks[3].reference()])
                .await
                .unwrap();
            assert!(custody.into_iter().all(|value| value.is_some()));
            assert!(client.block(blocks[2].reference()).await.unwrap().is_some());
            assert!(client.block(blocks[3].reference()).await.unwrap().is_some());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn staged_lqc_buffers_without_durability() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                9,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_STAGED_LQC",
                6,
                producers,
                limits,
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let proof = Arc::new(committee.lqc(1));
            let id = proof.id::<Sha256>();

            syncs.arm();
            client
                .stage_lqc(proof.view(), id, Arc::clone(&proof))
                .await
                .unwrap();
            assert_eq!(syncs.calls(), 0);
            assert_eq!(
                client.lqc(id).await.unwrap().as_deref(),
                Some(proof.as_ref())
            );

            syncs.unblock();
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn distinct_same_view_lqcs_reopen_and_prune_by_ordinal() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                9,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SAME_VIEW",
                6,
                producers,
                limits,
            );
            let first = lqc(&committee, 1, 0..5);
            let second = lqc(&committee, 1, 1..6);
            let first_id = first.id::<Sha256>();
            let second_id = second.id::<Sha256>();
            assert_ne!(first_id, second_id);
            assert_eq!(first.view(), second.view());
            assert_eq!(first.leader().history(), second.leader().history());

            let mut first_config = config(&context, &committee);
            first_config.max_commit_outputs = NZUsize!(2);
            let (client, handle, _delivery) =
                spawn_catalog(first_config, context.child("first_open")).await;
            let current = client.checkpoint().await.unwrap();
            let record = Arc::new(
                TipRecord::at_tips(
                    current.history(),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let history = record.commitment::<Sha256>();
            assert_eq!(first.leader().history(), history);
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                second_id,
                history,
                Some(0),
                current.ordered().to_vec(),
                current.emitted().to_vec(),
                current.committed(),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: vec![
                        SelectedLqc {
                            view: first.view(),
                            id: first_id,
                            proof: first.clone(),
                        },
                        SelectedLqc {
                            view: second.view(),
                            id: second_id,
                            proof: second.clone(),
                        },
                    ],
                    history: vec![HistoryOpening {
                        commitment: history,
                        record,
                    }],
                    outputs: Vec::new(),
                    checkpoint,
                })
                .await
                .unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let mut reopen_config = config(&context, &committee);
            reopen_config.max_commit_outputs = NZUsize!(2);
            let (client, handle, _delivery) =
                spawn_catalog(reopen_config, context.child("reopen")).await;
            assert!(client.final_lqc(first_id).await.unwrap());
            assert!(client.final_lqc(second_id).await.unwrap());
            client.prune(0).await.unwrap();
            assert!(!client.final_lqc(first_id).await.unwrap());
            assert!(client.final_lqc(second_id).await.unwrap());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn commits_buffer_a_second_cut_before_the_first_is_durable() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                18,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_COMMIT_PIPELINE",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let current = client.checkpoint().await.unwrap();
            let first = producer_block(&committee, 0, 20);
            let second = producer_block(&committee, 1, 21);
            drive_pending_syncs(
                &syncs,
                client.admit_block(first.reference(), Arc::clone(&first)),
            )
            .await
            .unwrap();
            drive_pending_syncs(
                &syncs,
                client.admit_block(second.reference(), Arc::clone(&second)),
            )
            .await
            .unwrap();

            let mut first_emitted = current.emitted().to_vec();
            first_emitted[0] = first.reference();
            let first_checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                first_emitted.clone(),
                Some(OutputIndex::ZERO),
            )
            .unwrap();
            let mut second_emitted = first_emitted;
            second_emitted[1] = second.reference();
            let second_checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                second_emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();

            let completed_before_pipeline = syncs.completions();
            syncs.arm();
            let first_token = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::ZERO, &first)],
                        checkpoint: first_checkpoint,
                    },
                    Vec::new(),
                )
                .await
                .unwrap();
            let second_token = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::new(1), &second)],
                        checkpoint: second_checkpoint,
                    },
                    Vec::new(),
                )
                .await
                .unwrap();

            let first_archive_syncs = syncs.calls();
            assert!(first_archive_syncs > 0, "first archive cut did not start");
            assert_eq!(client.progress().await.unwrap().committed, None);
            assert!(matches!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await,
                Err(Error::Invalid(_))
            ));

            let mut first_wait = Box::pin(first_token.wait());
            release_next_pending_syncs(&syncs, first_archive_syncs);
            for _ in 0..100 {
                if syncs.calls() >= first_archive_syncs + 2 {
                    break;
                }
                commonware_macros::select! {
                    result = &mut first_wait => panic!("first cut published before its checkpoint sync: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            let overlap_syncs = syncs.calls() - first_archive_syncs;
            assert!(
                overlap_syncs >= 2,
                "checkpoint publication did not overlap the next archive cut"
            );
            assert_eq!(client.progress().await.unwrap().committed, None);

            let second_archives = {
                let mut pending = syncs.lock();
                assert_eq!(pending.len(), overlap_syncs);
                pending.drain(1..).collect::<Vec<_>>()
            };
            let second_archive_syncs = second_archives.len();
            for sync in second_archives {
                let _ = sync.release.send(Ok(()));
            }
            let completed_through_second_archives = completed_before_pipeline
                + first_archive_syncs
                + second_archive_syncs;
            for _ in 0..100 {
                if syncs.completions() >= completed_through_second_archives {
                    break;
                }
                commonware_macros::select! {
                    result = &mut first_wait => panic!("second archives bypassed the first checkpoint: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert_eq!(
                syncs.completions(),
                completed_through_second_archives,
                "second archive cut did not finish ahead of the first checkpoint"
            );

            let mut second_wait = Box::pin(second_token.wait());
            release_next_pending_syncs(&syncs, 1);
            first_wait.await.unwrap();
            assert_eq!(
                client.progress().await.unwrap().committed,
                Some(OutputIndex::ZERO)
            );
            assert_eq!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await
                    .unwrap()[0]
                    .reference,
                first.reference()
            );
            assert!(matches!(
                client
                    .output_refs(OutputIndex::new(1), NZUsize!(1), NZUsize!(1024 * 1024))
                    .await,
                Err(Error::Invalid(_))
            ));
            commonware_macros::select! {
                result = &mut second_wait => panic!("second cut published with the first checkpoint: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            release_next_pending_syncs(&syncs, 1);
            second_wait.await.unwrap();
            assert_eq!(
                client.progress().await.unwrap().committed,
                Some(OutputIndex::new(1))
            );
            assert_eq!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1024 * 1024))
                    .await
                    .unwrap()
                    .len(),
                2
            );
            let singleton = client
                .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1))
                .await
                .unwrap();
            assert_eq!(singleton.len(), 1);
            assert_eq!(singleton[0].reference, first.reference());
            let batch = client
                .output_refs(OutputIndex::ZERO, NZUsize!(2), NZUsize!(1024 * 1024))
                .await
                .unwrap();
            assert_eq!(batch.len(), 2);
            assert_eq!(batch[1].reference, second.reference());

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn ready_checkpoint_completion_precedes_buffered_progress() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                46,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COMPLETION_FAIRNESS",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            let block = producer_block(&committee, 0, 46);
            drive_pending_syncs(
                &syncs,
                client.admit_block(block.reference(), Arc::clone(&block)),
            )
            .await
            .unwrap();

            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = block.reference();
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::ZERO),
            )
            .unwrap();

            syncs.arm();
            let token = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::ZERO, &block)],
                        checkpoint,
                    },
                    Vec::new(),
                )
                .await
                .unwrap();
            let archive_syncs = syncs.calls();
            release_next_pending_syncs(&syncs, archive_syncs);
            for _ in 0..100 {
                if syncs.calls() > archive_syncs {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(syncs.calls(), archive_syncs + 1);

            let (release_pause, pause) = oneshot::channel();
            let (started, pause_started) = oneshot::channel();
            let mut pause = Box::pin(client.request(|reply| Command::Pause(pause, started, reply)));
            let mut pause_started = Box::pin(pause_started);
            commonware_macros::select! {
                result = &mut pause_started => result.unwrap(),
                result = &mut pause => panic!("catalog pause completed before release: {result:?}"),
            }

            let mut progress = Vec::new();
            for _ in 0..8 {
                let (reply, receiver) = oneshot::channel();
                let _ = client
                    .commands
                    .enqueue(TracedCommand::new(Command::Progress(reply)));
                progress.push(receiver);
            }
            release_next_pending_syncs(&syncs, 1);
            release_pause.send(()).unwrap();
            pause.await.unwrap();
            for receiver in progress {
                assert_eq!(
                    receiver.await.unwrap().unwrap().committed,
                    Some(OutputIndex::ZERO)
                );
            }
            token.wait().await.unwrap();

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn acknowledgement_durability_is_independent_of_commit_publication() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                62,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_INDEPENDENT_ACK",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let config = config(&context, &committee);
            let delivery_bounds = delivery::Bounds {
                pending_acks: config.max_pending_acks,
                delivery_bytes: config.max_delivery_bytes,
                hot_block_bytes: config.max_hot_block_bytes,
            };
            let (delivery_client, delivery_commands) =
                delivery::channel(delayed.child("delivery_mailbox"));
            let (client, catalog_handle, promoter, promoter_handle, delivery_store) = config
                .spawn::<_, Sha256>(delayed.child("catalog"), delivery_client)
                .await
                .unwrap();
            assert!(promoter.is_none());
            assert!(promoter_handle.is_none());
            let reporter = TestReporter::default();
            let delivery_handle = delivery::spawn(
                delayed.child("delivery"),
                delivery_store,
                client.clone(),
                promoter::Bodies::new(client.clone(), None),
                reporter.clone(),
                delivery_commands,
                delivery_bounds,
            );

            let current = client.checkpoint().await.unwrap();
            let first = producer_block(&committee, 0, 62);
            client
                .stage_blocks(std::slice::from_ref(&first))
                .await
                .unwrap();
            let mut first_emitted = current.emitted().to_vec();
            first_emitted[0] = first.reference();
            let first_checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                first_emitted.clone(),
                Some(OutputIndex::ZERO),
            )
            .unwrap();
            drive_pending_syncs(
                &syncs,
                client.commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &first)],
                    checkpoint: first_checkpoint,
                }),
            )
            .await
            .unwrap();
            for _ in 0..100 {
                if reporter
                    .pending
                    .lock()
                    .iter()
                    .any(|(index, _)| *index == OutputIndex::ZERO)
                {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }

            let second = producer_block(&committee, 1, 63);
            drive_pending_syncs(
                &syncs,
                client.admit_block(second.reference(), Arc::clone(&second)),
            )
            .await
            .unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut second_emitted = first_emitted;
            second_emitted[1] = second.reference();
            let second_checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                second_emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();

            syncs.arm();
            let commit = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::new(1), &second)],
                        checkpoint: second_checkpoint,
                    },
                    Vec::new(),
                )
                .await
                .unwrap();
            let mut commit_syncs = 0;
            for _ in 0..100 {
                context.sleep(std::time::Duration::from_millis(1)).await;
                let calls = syncs.calls();
                if calls == commit_syncs && calls > 0 {
                    break;
                }
                commit_syncs = calls;
            }
            assert!(commit_syncs > 0, "commit durability did not start");
            assert!(reporter.acknowledge(OutputIndex::ZERO));
            for _ in 0..100 {
                if syncs.calls() > commit_syncs {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(syncs.calls(), commit_syncs + 1);

            let acknowledgement_sync = syncs.lock().pop().unwrap();
            let _ = acknowledgement_sync.release.send(Ok(()));
            for _ in 0..100 {
                if client.progress().await.unwrap().acknowledged == Some(OutputIndex::ZERO) {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(
                client.progress().await.unwrap().acknowledged,
                Some(OutputIndex::ZERO)
            );

            let mut publication = Box::pin(commit.wait());
            commonware_macros::select! {
                result = &mut publication => {
                    panic!("commit completed before its durability was released: {result:?}")
                },
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            drive_pending_syncs(&syncs, publication).await.unwrap();
            delivery_handle.abort();
            let _ = delivery_handle.await;
            drop(client);
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn application_ready_acknowledgements_refill_while_cursor_sync_is_active() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                63,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_ACK_COALESCING",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let mut config = config(&context, &committee);
            config.max_commit_outputs = NZUsize!(4);
            config.max_pending_acks = NZUsize!(1);
            let delivery_bounds = delivery::Bounds {
                pending_acks: config.max_pending_acks,
                delivery_bytes: config.max_delivery_bytes,
                hot_block_bytes: config.max_hot_block_bytes,
            };
            let (delivery_client, delivery_commands) =
                delivery::channel(delayed.child("delivery_mailbox"));
            let (client, catalog_handle, promoter, promoter_handle, delivery_store) = config
                .spawn::<_, Sha256>(delayed.child("catalog"), delivery_client)
                .await
                .unwrap();
            assert!(promoter.is_none());
            assert!(promoter_handle.is_none());
            let reporter = TestReporter::default();
            let delivery_handle = delivery::spawn(
                delayed.child("delivery"),
                delivery_store,
                client.clone(),
                promoter::Bodies::new(client.clone(), None),
                reporter.clone(),
                delivery_commands,
                delivery_bounds,
            );

            let blocks = (0..4)
                .map(|chain| producer_block(&committee, chain, 63 + u64::from(chain)))
                .collect::<Vec<_>>();
            client.stage_blocks(&blocks).await.unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &blocks {
                emitted[block.reference().chain().get() as usize] = block.reference();
            }
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(3)),
            )
            .unwrap();
            drive_pending_syncs(
                &syncs,
                client.commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                        .collect(),
                    checkpoint,
                }),
            )
            .await
            .unwrap();

            wait_for_report(&context, &reporter, OutputIndex::ZERO).await;
            syncs.arm();
            let syncs_before = syncs.calls();
            assert!(reporter.acknowledge(OutputIndex::ZERO));
            for _ in 0..100 {
                if syncs.calls() > syncs_before {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(syncs.calls(), syncs_before + 1);

            for index in 1..4 {
                let index = OutputIndex::new(index);
                wait_for_report(&context, &reporter, index).await;
                assert!(reporter.acknowledge(index));
            }
            for _ in 0..100 {
                if metric_total(&context.encode(), "delivery_pending_durability") == 4 {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(syncs.calls(), syncs_before + 1);
            assert_eq!(client.progress().await.unwrap().acknowledged, None);
            let metrics = context.encode();
            assert_eq!(metric_total(&metrics, "delivery_pending_durability"), 4);
            assert_eq!(metric_total(&metrics, "delivery_in_flight"), 0);

            let acknowledgement_sync = syncs.lock().pop().unwrap();
            acknowledgement_sync.release.send(Ok(())).unwrap();
            for _ in 0..100 {
                if syncs.calls() == syncs_before + 2 {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(syncs.calls(), syncs_before + 2);
            let acknowledgement_sync = syncs.lock().pop().unwrap();
            acknowledgement_sync.release.send(Ok(())).unwrap();
            for _ in 0..100 {
                if client.progress().await.unwrap().acknowledged == Some(OutputIndex::new(3)) {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(
                client.progress().await.unwrap().acknowledged,
                Some(OutputIndex::new(3))
            );
            let metrics = context.encode();
            assert_eq!(metric_total(&metrics, "delivery_pending_durability"), 0);
            assert_eq!(
                metric_total(&metrics, "delivery_acknowledgement_starts_total_total",),
                2
            );
            assert_eq!(
                metric_total(&metrics, "delivery_acknowledgements_total_total",),
                4
            );

            delivery_handle.abort();
            let _ = delivery_handle.await;
            drop(client);
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn delivery_reset_preempts_cold_materialization() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                84,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_COLD_RESET",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let mut config = config(&context, &committee);
            config.max_hot_block_bytes =
                NonZeroUsize::new(delivery::descriptor_bytes::<Sha256Digest>() as usize).unwrap();
            let bounds = delivery::Bounds {
                pending_acks: config.max_pending_acks,
                delivery_bytes: config.max_delivery_bytes,
                hot_block_bytes: config.max_hot_block_bytes,
            };
            let (delivery_client, commands) = delivery::channel(delayed.child("delivery_mailbox"));
            let control = delivery_client.clone();
            let (client, catalog_handle, _, _, store) = config
                .spawn::<_, Sha256>(delayed.child("catalog"), delivery_client)
                .await
                .unwrap();
            let block = producer_block(&committee, 0, 84);
            client
                .admit_block(block.reference(), block.clone())
                .await
                .unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = block.reference();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &block)],
                    checkpoint: Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        current.floor(),
                        current.history(),
                        current.history_index(),
                        current.ordered().to_vec(),
                        emitted,
                        Some(OutputIndex::ZERO),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            let gate = reads.arm();
            let reporter = TestReporter::default();
            let delivery_handle = delivery::spawn(
                delayed.child("delivery"),
                store,
                client.clone(),
                promoter::Bodies::new(client.clone(), None),
                reporter.clone(),
                commands,
                bounds,
            );
            gate.blocked.await.unwrap();
            let reset = control
                .reset(current.generation(), Some(OutputIndex::ZERO))
                .unwrap();
            select! {
                applied = reset.wait() => assert!(!applied),
                _ = context.sleep(std::time::Duration::from_millis(10)) => {
                    panic!("delivery reset waited for a superseded cold read");
                },
            }
            gate.release.send(()).unwrap();
            for _ in 0..10 {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(!reporter.contains(OutputIndex::ZERO));
            assert_eq!(client.progress().await.unwrap().acknowledged, None);
            assert!(delivery_handle.await.unwrap().is_err());
            drop(control);
            drop(client);
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn floor_install_supersedes_queued_committed_body_read() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                85, b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_READ_INSTALL",
                6, (0..4).map(Participant::new).collect(), Limits::new(2, 2).unwrap(),
            );
            let blocks = (0..2).map(|chain| producer_block(&committee, chain, 85 + u64::from(chain))).collect::<Vec<_>>();
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext { inner: context.child("delayed"), pending: syncs.clone() };
            let mut config = config(&context, &committee);
            config.max_commit_outputs = NZUsize!(2);
            config.max_pending_acks = NZUsize!(1);
            config.max_hot_block_bytes = NonZeroUsize::new(
                blocks[0].encode_size() + delivery::descriptor_bytes::<Sha256Digest>() as usize,
            ).unwrap();
            let bounds = delivery::Bounds {
                pending_acks: config.max_pending_acks, delivery_bytes: config.max_delivery_bytes,
                hot_block_bytes: config.max_hot_block_bytes,
            };
            let (delivery_client, commands) = delivery::channel(delayed.child("delivery_mailbox"));
            let (client, catalog_handle, _, _, store) = drive_pending_syncs(&syncs,
                config.spawn::<_, Sha256>(delayed.child("catalog"), delivery_client),
            ).await.unwrap();
            let reporter = TestReporter::default();
            let delivery_handle = delivery::spawn(delayed.child("delivery"), store, client.clone(),
                promoter::Bodies::new(client.clone(), None), reporter.clone(), commands, bounds);
            drive_pending_syncs(&syncs, client.stage_blocks(&blocks)).await.unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &blocks { emitted[block.reference().chain().get() as usize] = block.reference(); }
            let token = drive_pending_syncs(&syncs, client.start_commit(Commit {
                selected: Vec::new(), history: Vec::new(),
                outputs: blocks.iter().enumerate().map(|(i, block)| output_row(OutputIndex::new(i as u64), block)).collect(),
                checkpoint: Checkpoint::new(current.epoch(), current.generation(), current.archive_layout(),
                    current.floor(), current.history(), current.history_index(), current.ordered().to_vec(),
                    emitted.clone(), Some(OutputIndex::new(1))).unwrap(),
            }, vec![delivery::DurableOutput { index: OutputIndex::ZERO, block: blocks[0].clone(),
                encoded_len: blocks[0].encode_size() as u64 }])).await.unwrap();
            drive_pending_syncs(&syncs, token.wait()).await.unwrap();
            wait_for_report(&context, &reporter, OutputIndex::ZERO).await;

            let genesis = committee.config.genesis();
            let base = TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec()).unwrap();
            let record = Arc::new(TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap());
            let leader = committee.leader_block_with_parent(5, &committee.vqc(3));
            let votes = (0..committee.codec().view_quorum()).map(|signer| committee.vote(signer, &leader)).collect::<Vec<_>>();
            let proof = Arc::new(committee.verifier.assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential).unwrap());
            let target = checkpoint(&committee, 1, proof.id::<Sha256>(), record.commitment::<Sha256>(),
                0, emitted, Some(OutputIndex::new(1)));

            syncs.arm();
            let staged = client.stage_block(producer_block(&committee, 2, 87)).await.unwrap();
            client.progress().await.unwrap();
            assert!(syncs.calls() > 0);
            let mut install = Box::pin(client.install(target, install_prune(proof.view()), proof, record));
            select! {
                _ = &mut install => panic!("installation overtook admission durability"),
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }
            assert!(reporter.acknowledge(OutputIndex::ZERO));
            context.sleep(std::time::Duration::from_millis(1)).await;
            assert!(!reporter.contains(OutputIndex::new(1)));
            syncs.unblock();
            select! {
                result = &mut install => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_secs(1)) => panic!("installation did not reset the pending cold read"),
            }
            staged.wait().await.unwrap();
            let progress = client.progress().await.unwrap();
            assert_eq!(progress.generation, 1);
            assert_eq!(progress.acknowledged, Some(OutputIndex::new(1)));
            assert!(!reporter.contains(OutputIndex::new(1)));
            delivery_handle.abort();
            let _ = delivery_handle.await;
            drop(install);
            drop(client);
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn queued_generation_reset_preempts_acknowledgement_refill() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                64,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_DELIVERY_RESET_PREEMPTION",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let mut config = config(&context, &committee);
            config.max_commit_outputs = NZUsize!(2);
            config.max_pending_acks = NZUsize!(1);
            let delivery_bounds = delivery::Bounds {
                pending_acks: config.max_pending_acks,
                delivery_bytes: config.max_delivery_bytes,
                hot_block_bytes: config.max_hot_block_bytes,
            };
            let (delivery_client, delivery_commands) =
                delivery::channel(context.child("delivery_mailbox"));
            let delivery_control = delivery_client.clone();
            let (client, catalog_handle, promoter, promoter_handle, delivery_store) = config
                .spawn::<_, Sha256>(context.child("catalog"), delivery_client)
                .await
                .unwrap();
            assert!(promoter.is_none());
            assert!(promoter_handle.is_none());
            let reporter = TestReporter::default();
            let delivery_handle = delivery::spawn(
                context.child("delivery"),
                delivery_store,
                client.clone(),
                promoter::Bodies::new(client.clone(), None),
                reporter.clone(),
                delivery_commands,
                delivery_bounds,
            );

            let blocks = (0..2)
                .map(|chain| producer_block(&committee, chain, 64 + u64::from(chain)))
                .collect::<Vec<_>>();
            client.stage_blocks(&blocks).await.unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            for block in &blocks {
                emitted[block.reference().chain().get() as usize] = block.reference();
            }
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| output_row(OutputIndex::new(index as u64), block))
                        .collect(),
                    checkpoint,
                })
                .await
                .unwrap();

            wait_for_report(&context, &reporter, OutputIndex::ZERO).await;
            let reset = delivery_control.reset(1, None).unwrap();
            assert!(reporter.acknowledge(OutputIndex::ZERO));
            let mut reset = Box::pin(reset.wait());
            let mut next_report =
                Box::pin(wait_for_report(&context, &reporter, OutputIndex::new(1)));
            commonware_macros::select! {
                applied = &mut reset => assert!(!applied),
                _ = &mut next_report => {
                    panic!("delivery refilled before applying a queued generation reset")
                },
            }
            assert!(!reporter.contains(OutputIndex::new(1)));

            let _ = delivery_handle.await;
            drop(delivery_control);
            drop(client);
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn archive_durable_checkpoint_volatile_commit_replays_exactly() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                44,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_CHECKPOINT_CRASH",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let block = producer_block(&committee, 0, 44);
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
            drive_pending_syncs(
                &syncs,
                client.admit_block(block.reference(), Arc::clone(&block)),
            )
            .await
            .unwrap();
            let current = client.checkpoint().await.unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = block.reference();
            let checkpoint = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::ZERO),
            )
            .unwrap();

            syncs.arm();
            let token = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::ZERO, &block)],
                        checkpoint: checkpoint.clone(),
                    },
                    Vec::new(),
                )
                .await
                .unwrap();
            let archive_syncs = syncs.calls();
            assert!(archive_syncs > 0, "finalized archive cut did not start");
            let mut publication = Box::pin(token.wait());
            release_next_pending_syncs(&syncs, archive_syncs);
            for _ in 0..100 {
                if syncs.calls() > archive_syncs {
                    break;
                }
                commonware_macros::select! {
                    result = &mut publication => panic!("commit published before its checkpoint cut: {result:?}"),
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert_eq!(
                syncs.calls(),
                archive_syncs + 1,
                "checkpoint cut did not start after finalized archives became durable"
            );
            drop(publication);
            handle.abort();
            drop(client);
            let _ = handle.await;

            let (client, handle, _delivery) =
                open(&context, "reopened_checkpoint_crash", &committee).await;
            assert_eq!(client.progress().await.unwrap().committed, None);
            assert!(matches!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await,
                Err(Error::Invalid(_))
            ));
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &block)],
                    checkpoint,
                })
                .await
                .unwrap();
            assert_eq!(
                client.progress().await.unwrap().committed,
                Some(OutputIndex::ZERO)
            );
            assert_eq!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await
                    .unwrap()[0]
                    .reference,
                block.reference()
            );
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn archive_ahead_lqc_ordinal_is_skipped_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                68,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_LQC_ORDINAL_CRASH",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );

            for (mode, label, delayed_label, reopen_label) in [
                (
                    ArchiveMode::Prunable,
                    "prunable",
                    "prunable_delayed",
                    "prunable_reopen",
                ),
                (
                    ArchiveMode::Immutable,
                    "immutable",
                    "immutable_delayed",
                    "immutable_reopen",
                ),
            ] {
                let configure = || {
                    let mut config = config(&context, &committee);
                    config.partition_prefix = format!("catalog_lqc_ordinal_crash_{label}");
                    config.finalized_lqc = mode;
                    config
                };
                let first = Arc::new(lqc(&committee, 1, 0..5));
                let second = Arc::new(lqc(&committee, 1, 1..6));
                let first_id = first.id::<Sha256>();
                let second_id = second.id::<Sha256>();
                assert_ne!(first_id, second_id);

                let syncs = PendingSyncs::default();
                let delayed = DelayedSyncContext {
                    inner: context.child(delayed_label),
                    pending: syncs.clone(),
                };
                let (client, handle, _delivery) =
                    spawn_catalog(configure(), delayed.child("catalog")).await;
                let current = client.checkpoint().await.unwrap();
                let record = Arc::new(
                    TipRecord::at_tips(
                        current.history(),
                        committee.config.genesis().tips().to_vec(),
                    )
                    .unwrap(),
                );
                let history = record.commitment::<Sha256>();
                assert_eq!(first.leader().history(), history);
                let checkpoint = |floor| {
                    Checkpoint::new(
                        current.epoch(),
                        current.generation(),
                        current.archive_layout(),
                        floor,
                        history,
                        Some(0),
                        current.ordered().to_vec(),
                        current.emitted().to_vec(),
                        current.committed(),
                    )
                    .unwrap()
                };

                syncs.arm();
                let token = client
                    .start_commit(
                        Commit {
                            selected: vec![SelectedLqc {
                                view: first.view(),
                                id: first_id,
                                proof: Arc::clone(&first),
                            }],
                            history: vec![HistoryOpening {
                                commitment: history,
                                record: Arc::clone(&record),
                            }],
                            outputs: Vec::new(),
                            checkpoint: checkpoint(first_id),
                        },
                        Vec::new(),
                    )
                    .await
                    .unwrap();
                let archive_syncs = syncs.calls();
                assert!(archive_syncs > 0);
                let mut publication = Box::pin(token.wait());
                release_next_pending_syncs(&syncs, archive_syncs);
                for _ in 0..100 {
                    if syncs.calls() > archive_syncs {
                        break;
                    }
                    commonware_macros::select! {
                        result = &mut publication => {
                            panic!("commit published before checkpoint sync: {result:?}")
                        },
                        _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                    }
                }
                assert!(
                    syncs.calls() > archive_syncs,
                    "checkpoint durability did not start after the archive cut"
                );
                drop(publication);
                handle.abort();
                drop(client);
                let _ = handle.await;

                let (client, handle, _delivery) =
                    spawn_catalog(configure(), context.child(reopen_label)).await;
                assert_eq!(client.progress().await.unwrap().floor, current.floor());
                client
                    .commit(Commit {
                        selected: vec![SelectedLqc {
                            view: second.view(),
                            id: second_id,
                            proof: Arc::clone(&second),
                        }],
                        history: vec![HistoryOpening {
                            commitment: history,
                            record: Arc::clone(&record),
                        }],
                        outputs: Vec::new(),
                        checkpoint: checkpoint(second_id),
                    })
                    .await
                    .unwrap();
                assert!(client.final_lqc(first_id).await.unwrap());
                assert!(client.final_lqc(second_id).await.unwrap());
                client.prune(0).await.unwrap();
                assert_eq!(
                    client.final_lqc(first_id).await.unwrap(),
                    mode == ArchiveMode::Immutable
                );
                assert!(client.final_lqc(second_id).await.unwrap());
                drop(client);
                assert!(handle.await.is_ok());
            }
        });
    }

    #[test]
    fn commit_block_byte_bound_rejects_multi_block_overshoot_but_allows_a_single_block() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                30,
                b"_COMMONWARE_CONSENSUS_MULTIMIT_CATALOG_COMMIT_BYTES",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let mut config = config(&context, &committee);
            config.max_commit_outputs = NZUsize!(2);
            config.max_commit_block_bytes = NZUsize!(1);
            let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
            let current = client.checkpoint().await.unwrap();
            let first = producer_block(&committee, 0, 30);
            let second = producer_block(&committee, 1, 31);
            client
                .stage_blocks(std::slice::from_ref(&first))
                .await
                .unwrap();
            client
                .stage_blocks(std::slice::from_ref(&second))
                .await
                .unwrap();

            let mut emitted = current.emitted().to_vec();
            emitted[0] = first.reference();
            emitted[1] = second.reference();
            let oversized = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::new(1)),
            )
            .unwrap();
            let result = client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![
                            output_row(OutputIndex::ZERO, &first),
                            output_row(OutputIndex::new(1), &second),
                        ],
                        checkpoint: oversized,
                    },
                    Vec::new(),
                )
                .await;
            assert!(matches!(result, Err(Error::Invalid(_))));

            let mut emitted = current.emitted().to_vec();
            emitted[0] = first.reference();
            let singleton = Checkpoint::new(
                current.epoch(),
                current.generation(),
                current.archive_layout(),
                current.floor(),
                current.history(),
                current.history_index(),
                current.ordered().to_vec(),
                emitted,
                Some(OutputIndex::ZERO),
            )
            .unwrap();
            client
                .start_commit(
                    Commit {
                        selected: Vec::new(),
                        history: Vec::new(),
                        outputs: vec![output_row(OutputIndex::ZERO, &first)],
                        checkpoint: singleton,
                    },
                    Vec::new(),
                )
                .await
                .unwrap()
                .wait()
                .await
                .unwrap();

            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn checkpoint(
        committee: &Committee<MinPk>,
        generation: u64,
        floor: CertificateId<Sha256Digest>,
        history: Sha256Digest,
        history_index: u64,
        emitted: Vec<BlockRef<Sha256Digest>>,
        committed: Option<OutputIndex>,
    ) -> Checkpoint<Sha256Digest> {
        Checkpoint::new(
            committee.config.epoch(),
            generation,
            crate::multimmit::marshal::storage::checkpoint::ArchiveLayout::new(true, false, true),
            floor,
            history,
            Some(history_index),
            committee.config.genesis().tips().to_vec(),
            emitted,
            committed,
        )
        .unwrap()
    }

    fn selected_commit(
        proof: Arc<Lqc<MinPk, Sha256Digest>>,
        checkpoint: Checkpoint<Sha256Digest>,
    ) -> Commit<Sha256, MinPk> {
        Commit {
            selected: vec![SelectedLqc {
                view: proof.view(),
                id: proof.id::<Sha256>(),
                proof,
            }],
            history: Vec::new(),
            outputs: Vec::new(),
            checkpoint,
        }
    }

    fn install_prune(view: View) -> Prune {
        Prune {
            pending_lqc: View::new(view.get() + 1),
            pending_history: View::new(view.get() + 1),
            pending_blocks: vec![Height::new(2); 4],
        }
    }

    fn exercise_install_crash_cut(phase: InstallCut) {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                7,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INSTALL_RECOVERY",
                6,
                producers,
                limits,
            );
            let genesis = committee.config.genesis();
            let base = Arc::new(
                TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap(),
            );
            let record = Arc::new(
                TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
            );
            let history = record.commitment::<Sha256>();
            let parent = committee.vqc(3);
            let leader = committee.leader_block_with_parent(5, &parent);
            let votes = (0..committee.codec().view_quorum())
                .map(|signer| committee.vote(signer, &leader))
                .collect::<Vec<_>>();
            let proof = Arc::new(
                committee
                    .verifier
                    .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                    .unwrap(),
            );
            assert_eq!(proof.leader().history(), history);
            let id = proof.id::<Sha256>();
            let target = checkpoint(&committee, 1, id, history, 0, genesis.tips().to_vec(), None);
            let prune = Prune {
                pending_lqc: View::new(proof.view().get() + 1),
                pending_history: View::new(proof.view().get() + 1),
                pending_blocks: vec![Height::new(1); 4],
            };

            let (client, handle, _delivery) = open(&context, "install_cut", &committee).await;
            client
                .install_through(target.clone(), prune, proof.clone(), record.clone(), phase)
                .await
                .unwrap();
            handle.abort();
            drop(client);
            let _ = handle.await;

            let (client, handle, _delivery) = open(&context, "recovered", &committee).await;
            assert_eq!(
                client.progress().await.unwrap(),
                Progress {
                    generation: 1,
                    floor: id,
                    committed: None,
                    acknowledged: None,
                }
            );
            assert_eq!(
                client.lqc(id).await.unwrap().as_deref(),
                Some(proof.as_ref())
            );
            assert_eq!(
                client.history(history).await.unwrap().as_deref(),
                Some(record.as_ref())
            );
            assert!(client.latest_lqc().await.unwrap().is_none());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn interrupted_install_recovers_before_catalog_service() {
        for phase in [
            InstallCut::Intent,
            InstallCut::Archived,
            InstallCut::Published,
        ] {
            exercise_install_crash_cut(phase);
        }
    }

    #[test]
    fn oversized_install_intent_is_rejected_before_archive_mutation() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                7,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_INSTALL_BOUND",
                6,
                producers,
                limits,
            );
            let genesis = committee.config.genesis();
            let base =
                TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap();
            let record = Arc::new(
                TipRecord::at_tips(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
            );
            let history = record.commitment::<Sha256>();
            let parent = committee.vqc(3);
            let leader = committee.leader_block_with_parent(5, &parent);
            let votes = (0..committee.codec().view_quorum())
                .map(|signer| committee.vote(signer, &leader))
                .collect::<Vec<_>>();
            let proof = Arc::new(
                committee
                    .verifier
                    .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                    .unwrap(),
            );
            assert_eq!(proof.leader().history(), history);
            let id = proof.id::<Sha256>();
            let target = checkpoint(&committee, 1, id, history, 0, genesis.tips().to_vec(), None);
            let prune = Prune {
                pending_lqc: View::new(proof.view().get() + 1),
                pending_history: View::new(proof.view().get() + 1),
                pending_blocks: vec![Height::new(1); 4],
            };
            let current = Checkpoint::new(
                committee.config.epoch(),
                0,
                crate::multimmit::marshal::storage::checkpoint::ArchiveLayout::new(
                    true, false, true,
                ),
                genesis.lqc(),
                genesis_history::<Sha256>(genesis),
                None,
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
                None,
            )
            .unwrap();
            let ready = CatalogState::ready(current, None);
            let intent = ready
                .begin(
                    target.clone(),
                    proof.view(),
                    None,
                    prune.clone(),
                    commonware_codec::Encode::encode(proof.as_ref()),
                    commonware_codec::Encode::encode(record.as_ref()),
                )
                .unwrap();
            let ready_size = metadata_blob_size(&ready).unwrap();
            let intent_size = metadata_blob_size(&intent).unwrap();
            assert!(ready_size < intent_size);
            let bound = NonZeroUsize::new(intent_size - 1).unwrap();
            assert!(ready_size <= bound.get());

            let mut bounded = config(&context, &committee);
            bounded.max_checkpoint_bytes = bound;
            let (client, handle, _delivery) =
                spawn_catalog(bounded, context.child("bounded")).await;
            assert!(matches!(
                client.install(target, prune, proof, record).await,
                Err(Error::Invalid(
                    "catalog state exceeds configured metadata bound"
                ))
            ));
            assert_eq!(client.progress().await.unwrap().generation, 0);
            assert!(client.lqc(id).await.unwrap().is_none());
            assert!(client.history(history).await.unwrap().is_none());
            drop(client);
            assert!(handle.await.is_ok());

            let mut bounded = config(&context, &committee);
            bounded.max_checkpoint_bytes = bound;
            let (client, handle, _delivery) = spawn_catalog(bounded, context.child("reopen")).await;
            assert_eq!(client.progress().await.unwrap().generation, 0);
            assert!(client.lqc(id).await.unwrap().is_none());
            assert!(client.history(history).await.unwrap().is_none());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn immutable_commit_recovers_canonical_body_and_reclaims_losing_candidates() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                31,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_IMMUTABLE_CLEANUP",
                6,
                (0..4).map(Participant::new).collect(),
                Limits::new(2, 2).unwrap(),
            );
            let genesis = committee.config.genesis();
            let record = Arc::new(
                TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap(),
            );
            let history = record.commitment::<Sha256>();
            let canonical = producer_block(&committee, 0, 10);
            let losing = producer_block(&committee, 0, 11);
            let reference = canonical.reference();
            let losing_reference = losing.reference();

            let mut first = config(&context, &committee);
            first.finalized_blocks = ArchiveMode::Immutable;
            let (delivery, _delivery_receiver) =
                delivery::channel(context.child("immutable_first_delivery"));
            let (client, handle, _, promoter_handle, _) = first
                .spawn::<_, Sha256>(context.child("immutable_first"), delivery)
                .await
                .unwrap();
            client
                .admit_block(reference, Arc::clone(&canonical))
                .await
                .unwrap();
            client.admit_block(losing_reference, losing).await.unwrap();
            let mut emitted = genesis.tips().to_vec();
            emitted[0] = reference;
            client
                .commit_through_checkpoint(Commit {
                    selected: Vec::new(),
                    history: vec![HistoryOpening {
                        commitment: history,
                        record,
                    }],
                    outputs: vec![output_row(OutputIndex::ZERO, &canonical)],
                    checkpoint: Checkpoint::new(
                        committee.config.epoch(),
                        0,
                        ArchiveLayout::new(true, false, false),
                        genesis.lqc(),
                        history,
                        Some(0),
                        genesis.tips().to_vec(),
                        emitted,
                        Some(OutputIndex::ZERO),
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            handle.abort();
            promoter_handle.unwrap().abort();
            drop(client);
            let _ = handle.await;

            let mut reopened = config(&context, &committee);
            reopened.finalized_blocks = ArchiveMode::Immutable;
            let (delivery, _delivery_receiver) =
                delivery::channel(context.child("immutable_reopen_delivery"));
            let (client, handle, promoter, promoter_handle, _) = reopened
                .spawn::<_, Sha256>(context.child("immutable_reopen"), delivery)
                .await
                .unwrap();
            let bodies = promoter::Bodies::new(client.clone(), promoter);
            for _ in 0..100 {
                if client.block(losing_reference).await.unwrap().is_none() {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert_eq!(
                bodies.block(reference).await.unwrap().as_deref(),
                Some(canonical.as_ref())
            );
            assert!(client.block(losing_reference).await.unwrap().is_none());
            let outputs = client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await
                .unwrap();
            assert_eq!(outputs[0].reference, reference);
            assert_eq!(
                bodies.materialize(&outputs).await.unwrap()[0].as_ref(),
                canonical.as_ref()
            );
            promoter_handle.unwrap().abort();
            drop(client);
            handle.abort();
            let _ = handle.await;
        });
    }

    #[test]
    fn admissions_chunked_commit_delivery_reopen_and_install() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                7,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG",
                6,
                producers.clone(),
                limits,
            );
            let alternate = Committee::<MinPk>::new_with_namespace_and_producers(
                7,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ALTERNATE",
                6,
                producers,
                limits,
            );
            let genesis = committee.config.genesis();
            let initial_history = genesis_history::<Sha256>(genesis);
            let record =
                Arc::new(TipRecord::at_tips(initial_history, genesis.tips().to_vec()).unwrap());
            let history = record.commitment::<Sha256>();
            let proof = Arc::new(committee.lqc(3));
            let alternate_proof = Arc::new(alternate.lqc(3));
            let proof_id = proof.id::<Sha256>();
            let alternate_id = alternate_proof.id::<Sha256>();
            assert_ne!(proof_id, alternate_id);

            let block = producer_block(&committee, 0, 10);
            let conflicting = producer_block(&committee, 0, 11);
            let other_chain = producer_block(&committee, 1, 12);
            let reference = block.reference();
            let conflicting_reference = conflicting.reference();
            let other_reference = other_chain.reference();
            let (client, handle, _delivery) = open(&context, "first_open", &committee).await;

            let admissions = futures::join!(
                client.admit_finality(proof.view(), proof_id, proof.clone(), record.clone()),
                client.admit_lqc(
                    alternate_proof.view(),
                    alternate_id,
                    alternate_proof.clone()
                ),
                client.admit_block(reference, block.clone()),
                client.admit_block(conflicting_reference, conflicting.clone()),
                client.admit_block(other_reference, other_chain.clone()),
            );
            for result in [
                admissions.0,
                admissions.1,
                admissions.2,
                admissions.3,
                admissions.4,
            ] {
                result.unwrap();
            }

            assert_eq!(
                client.lqc(proof_id).await.unwrap().as_deref(),
                Some(proof.as_ref())
            );
            assert_eq!(
                client.lqc(alternate_id).await.unwrap().as_deref(),
                Some(alternate_proof.as_ref())
            );
            assert_eq!(
                client.latest_lqc().await.unwrap().unwrap().view(),
                View::new(3)
            );
            assert_eq!(
                client
                    .block_by_digest(reference.chain(), reference.digest())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(block.as_ref())
            );

            let bad_id = CertificateId::new(Sha256::hash(&[b"wrong LQC identity"]));
            assert!(matches!(
                client.admit_lqc(proof.view(), bad_id, proof.clone()).await,
                Err(Error::Invalid(_))
            ));
            assert!(matches!(
                client
                    .admit_finality(
                        proof.view(),
                        proof_id,
                        proof.clone(),
                        Arc::new(
                            TipRecord::at_tips(
                                Sha256::hash(&[b"wrong history parent"]),
                                genesis.tips().to_vec(),
                            )
                            .unwrap(),
                        ),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let bad_reference = BlockRef::new(
                ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"wrong block identity"]),
            );
            assert!(matches!(
                client.admit_block(bad_reference, block.clone()).await,
                Err(Error::Invalid(_))
            ));

            let mut two_emitted = genesis.tips().to_vec();
            two_emitted[0] = reference;
            two_emitted[1] = other_reference;
            let oversized = Commit {
                selected: Vec::new(),
                history: vec![HistoryOpening {
                    commitment: history,
                    record: record.clone(),
                }],
                outputs: vec![
                    output_row(OutputIndex::ZERO, &block),
                    output_row(OutputIndex::new(1), &other_chain),
                ],
                checkpoint: checkpoint(
                    &committee,
                    0,
                    genesis.lqc(),
                    history,
                    0,
                    two_emitted,
                    Some(OutputIndex::new(1)),
                ),
            };
            assert!(matches!(
                client.commit(oversized).await,
                Err(Error::Invalid(_))
            ));
            assert_eq!(client.progress().await.unwrap().committed, None);
            assert!(matches!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await,
                Err(Error::Invalid(_))
            ));

            let mut emitted = genesis.tips().to_vec();
            emitted[0] = reference;
            let intermediate = checkpoint(
                &committee,
                0,
                genesis.lqc(),
                history,
                0,
                emitted.clone(),
                Some(OutputIndex::ZERO),
            );
            let stale_record = Arc::new(
                TipRecord::at_tips(
                    Sha256::hash(&[b"stale pending history"]),
                    genesis.tips().to_vec(),
                )
                .unwrap(),
            );
            let stale_history = stale_record.commitment::<Sha256>();
            client
                .admit_history(View::new(2), stale_history, stale_record)
                .await
                .unwrap();
            client
                .commit_through_checkpoint(Commit {
                    selected: Vec::new(),
                    history: vec![HistoryOpening {
                        commitment: history,
                        record: record.clone(),
                    }],
                    outputs: vec![output_row(OutputIndex::ZERO, &block)],
                    checkpoint: intermediate,
                })
                .await
                .unwrap();
            handle.abort();
            drop(client);
            let _ = handle.await;

            let (client, handle, _delivery) =
                open(&context, "block_cleanup_recovery", &committee).await;

            assert_eq!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await
                    .unwrap()[0]
                    .reference,
                reference
            );
            let wrong_context =
                BlockRef::new(ChainId::new(1), reference.height(), reference.digest());
            assert!(client.block(wrong_context).await.unwrap().is_none());
            assert_eq!(
                client.history(history).await.unwrap().as_deref(),
                Some(record.as_ref())
            );
            assert!(client.block(conflicting_reference).await.unwrap().is_some());
            assert!(client.block(other_reference).await.unwrap().is_some());
            assert!(client.lqc(alternate_id).await.unwrap().is_some());
            assert!(client.history(stale_history).await.unwrap().is_some());

            let finalized = checkpoint(
                &committee,
                0,
                proof_id,
                history,
                0,
                emitted.clone(),
                Some(OutputIndex::ZERO),
            );
            client
                .admit_block(conflicting_reference, conflicting.clone())
                .await
                .unwrap();
            client
                .commit_through_checkpoint(selected_commit(proof.clone(), finalized.clone()))
                .await
                .unwrap();
            handle.abort();
            drop(client);
            let _ = handle.await;

            let (client, handle, _delivery) =
                open(&context, "commit_cleanup_recovery", &committee).await;
            assert_eq!(client.progress().await.unwrap().floor, proof_id);
            assert!(client.lqc(alternate_id).await.unwrap().is_none());
            assert!(client.history(stale_history).await.unwrap().is_none());
            assert!(client.block(conflicting_reference).await.unwrap().is_some());
            handle.abort();
            drop(client);
            let _ = handle.await;

            let reopen_context = context.child("commit_cleanup_replay");
            let (delivery_client, _delivery) =
                delivery::channel(reopen_context.child("delivery_mailbox"));
            let (client, handle, _, _, mut delivery_store) = config(&context, &committee)
                .spawn::<_, Sha256>(reopen_context, delivery_client)
                .await
                .unwrap();
            assert!(client.lqc(alternate_id).await.unwrap().is_none());
            assert!(client.history(stale_history).await.unwrap().is_none());
            assert!(client.block(conflicting_reference).await.unwrap().is_some());
            client
                .commit(selected_commit(proof.clone(), finalized.clone()))
                .await
                .unwrap();
            assert!(
                client
                    .block_by_digest(ChainId::new(1), reference.digest())
                    .await
                    .unwrap()
                    .is_none(),
                "a finalized digest is served only for its producer chain"
            );
            assert_eq!(
                client.lqc(proof_id).await.unwrap().as_deref(),
                Some(proof.as_ref())
            );
            assert!(client.lqc(alternate_id).await.unwrap().is_none());
            assert!(client.latest_lqc().await.unwrap().is_none());

            assert!(matches!(
                client
                    .reset_delivery_cursor(0, Some(OutputIndex::new(1)))
                    .await,
                Err(Error::Invalid(_))
            ));
            delivery_store
                .start_acknowledgement(0, OutputIndex::ZERO)
                .await
                .unwrap()
                .await
                .unwrap();
            assert_eq!(
                client.delivery_cursor(0, Some(OutputIndex::ZERO)),
                Feedback::Ok
            );
            while client.progress().await.unwrap().acknowledged != Some(OutputIndex::ZERO) {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            assert!(matches!(
                delivery_store
                    .start_acknowledgement(0, OutputIndex::ZERO)
                    .await,
                Err(crate::multimmit::marshal::storage::delivery::Error::Invalid(_))
            ));
            drop(delivery_store);
            drop(client);
            assert!(handle.await.is_ok());

            let (client, handle, mut delivery) = open(&context, "reopen", &committee).await;
            assert_eq!(
                client.progress().await.unwrap(),
                Progress {
                    generation: 0,
                    floor: proof_id,
                    committed: Some(OutputIndex::ZERO),
                    acknowledged: Some(OutputIndex::ZERO),
                }
            );
            let reopened_reference = client
                .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                .await
                .unwrap()[0]
                .reference;
            let reopened_block = client.block(reopened_reference).await.unwrap().unwrap();
            assert_eq!(reopened_reference, reference);
            assert_eq!(reopened_block.as_ref(), block.as_ref());

            let parent = committee.vqc(3);
            let leader = committee.leader_block_with_parent(5, &parent);
            let votes = (0..committee.codec().view_quorum())
                .map(|signer| committee.vote(signer, &leader))
                .collect::<Vec<_>>();
            let floor_proof = Arc::new(
                committee
                    .verifier
                    .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                    .unwrap(),
            );
            let floor_id = floor_proof.id::<Sha256>();
            let floor_record = Arc::new(
                TipRecord::at_tips(history, committee.config.genesis().tips().to_vec()).unwrap(),
            );
            let floor_history = floor_record.commitment::<Sha256>();
            assert_eq!(floor_proof.leader().history(), floor_history);
            let installed = checkpoint(
                &committee,
                1,
                floor_id,
                floor_history,
                1,
                emitted,
                Some(OutputIndex::ZERO),
            );
            let stale_history_index = checkpoint(
                &committee,
                1,
                floor_id,
                floor_history,
                0,
                installed.emitted().to_vec(),
                Some(OutputIndex::ZERO),
            );
            assert!(matches!(
                client
                    .install(
                        stale_history_index,
                        install_prune(floor_proof.view()),
                        floor_proof.clone(),
                        floor_record.clone(),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let phantom_output = checkpoint(
                &committee,
                1,
                floor_id,
                floor_history,
                1,
                installed.emitted().to_vec(),
                Some(OutputIndex::new(1)),
            );
            assert!(matches!(
                client
                    .install(
                        phantom_output,
                        install_prune(floor_proof.view()),
                        floor_proof.clone(),
                        floor_record.clone(),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            let mut installation = Box::pin(client.install(
                installed.clone(),
                install_prune(floor_proof.view()),
                floor_proof.clone(),
                floor_record.clone(),
            ));
            let reset = commonware_macros::select! {
                result = &mut installation => {
                    panic!("floor installation returned before delivery reset: {result:?}")
                },
                reset = delivery.next_reset() => reset,
            };
            let (generation, acknowledged, reset) = reset;
            assert_eq!(generation, 1);
            assert_eq!(acknowledged, Some(OutputIndex::ZERO));
            assert_eq!(reset.len(), 1);
            client
                .reset_delivery_cursor(generation, acknowledged)
                .await
                .unwrap();
            for acknowledgement in reset {
                let _ = acknowledgement.send(());
            }
            installation.await.unwrap();
            assert_eq!(
                client.progress().await.unwrap(),
                Progress {
                    generation: 1,
                    floor: floor_id,
                    committed: Some(OutputIndex::ZERO),
                    acknowledged: Some(OutputIndex::ZERO),
                }
            );
            assert_eq!(
                client.lqc(floor_id).await.unwrap().as_deref(),
                Some(floor_proof.as_ref())
            );
            assert!(client.latest_lqc().await.unwrap().is_none());
            assert!(client.lqc(proof_id).await.unwrap().is_some());
            assert_eq!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await
                    .unwrap()[0]
                    .reference,
                reference
            );
            assert_eq!(
                client.history(floor_history).await.unwrap().as_deref(),
                Some(floor_record.as_ref())
            );
            assert!(matches!(
                client
                    .install(
                        installed,
                        install_prune(floor_proof.view()),
                        floor_proof.clone(),
                        floor_record.clone(),
                    )
                    .await,
                Err(Error::Invalid(_))
            ));
            assert!(matches!(client.prune(0).await, Err(Error::Invalid(_))));
            client.prune(1).await.unwrap();
            client.prune(1).await.unwrap();
            assert!(client.lqc(proof_id).await.unwrap().is_none());
            assert!(client.block(reference).await.unwrap().is_none());
            assert!(client.block(other_reference).await.unwrap().is_none());
            assert!(matches!(
                client
                    .output_refs(OutputIndex::ZERO, NZUsize!(1), NZUsize!(1024 * 1024))
                    .await,
                Err(Error::Storage(_))
            ));
            handle.abort();
            drop(client);

            let (client, handle, _delivery) = open(&context, "installed_reopen", &committee).await;
            assert_eq!(client.progress().await.unwrap().floor, floor_id);
            assert_eq!(
                client.lqc(floor_id).await.unwrap().as_deref(),
                Some(floor_proof.as_ref())
            );
            assert_eq!(
                client.history(floor_history).await.unwrap().as_deref(),
                Some(floor_record.as_ref())
            );
            assert!(client.latest_lqc().await.unwrap().is_none());
            drop(client);
            assert!(handle.await.is_ok());
        });
    }

    #[test]
    fn shared_codec_round_trip_does_not_require_inner_clone() {
        let body = TestBody::new(Sha256::hash(&[b"parent"]), Height::new(1), 1);
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"producer parent"]),
            body.digest(),
        )
        .unwrap();
        let shared = Shared::new(Arc::new(
            TransactionBlock::<Sha256, _>::new(header, body).unwrap(),
        ));
        let encoded = commonware_codec::Encode::encode(&shared);
        let decoded =
            <Shared<TransactionBlock<Sha256, TestBody>> as commonware_codec::Decode>::decode_cfg(
                encoded,
                &(),
            )
            .unwrap();
        assert_eq!(decoded.into_inner().as_ref(), shared.into_inner().as_ref());
    }
}
