//! Bounded single-owner catalog actor for Multimmit marshal.
//!
//! The catalog serializes logical storage transitions while their independent archive syncs run in
//! bounded background slots. Finalized checkpoints are published last, making recovery depend on
//! one authoritative cut. Its block cache is advisory: every cache miss is answered from durable
//! custody without changing observable behavior.

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
    types::View,
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
    Clock, Handle, Metrics as RuntimeMetrics, Spawner, telemetry::metrics::histogram,
};
use commonware_storage::{Context, metadata::Metadata, translator::Translator};
use commonware_utils::{channel::oneshot, futures::Pool, sequence::Unit};
use futures::future::{pending, try_join_all};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::{Arc, mpsc::TryRecvError},
};
use tracing::{Instrument as _, Span, info_span};

/// Bounds temporary archive growth without putting cleanup on every publication.
const MAX_COMMITS_BEFORE_CLEANUP: usize = 8;

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
            self.by_digest.remove(&(
                evicted_reference.chain(),
                evicted_reference.digest(),
            ));
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
pub(in crate::multimmit::marshal) struct AdmissionToken(
    oneshot::Receiver<Result<(), Error>>,
);

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
    acknowledgements: Vec<(OutputIndex, u64, Reply<()>)>,
    delivery: Option<delivery::DurableBatch<H, B>>,
    hot_bytes: u64,
    outputs: u64,
    span: Span,
}

impl<H, B> PendingCommit<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn fail(self, error: Error) {
        drop(self.completion.send(Err(error.clone())));
        for (_, _, reply) in self.acknowledgements {
            drop(reply.send(Err(error.clone())));
        }
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
    Acknowledgement {
        index: OutputIndex,
        advances: u64,
        reply: Reply<()>,
        result: Result<(), Error>,
    },
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
type CustodyWaiter<H> = (
    Vec<BlockRef<<H as Hasher>::Digest>>,
    Reply<CustodyValues<H>>,
);
type AdmissionCommand<H, V, B> = (Vec<Admission<H, V, B>>, AdmissionMode, Reply<()>);

enum CatalogEvent<D, M, S, C> {
    Durability(D),
    Materialization(M),
    Seal(S),
    Command(C),
}

async fn next_catalog_event<D, M, S, C>(
    durability: D,
    materialization: M,
    seal: S,
    command: C,
    accept_commands: bool,
) -> CatalogEvent<D::Output, M::Output, S::Output, C::Output>
where
    D: Future,
    M: Future,
    S: Future,
    C: Future,
{
    let command = async move {
        if accept_commands {
            command.await
        } else {
            pending().await
        }
    };
    select! {
        completion = durability => CatalogEvent::Durability(completion),
        completion = materialization => CatalogEvent::Materialization(completion),
        completion = seal => CatalogEvent::Seal(completion),
        command = command => CatalogEvent::Command(command),
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
    Commit(Commit<H, V>, Reply<CommitToken>),
    #[cfg(test)]
    CommitThroughCheckpoint(Commit<H, V>, Reply<()>),
    #[cfg(test)]
    Pause(oneshot::Receiver<()>, oneshot::Sender<()>, Reply<()>),
    AcknowledgeThrough(OutputIndex, Reply<()>),
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
        }
    }

    const fn with_span(command: Command<H, V, B>, span: Span) -> Self {
        Self { command, span }
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
    const fn commit_barrier(&self) -> bool {
        match self {
            Self::Install(_, _, _, _, _) | Self::Prune(_, _) | Self::Promoted(_, _) => true,
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

    fn fail(self, error: Error) {
        match self {
            #[cfg(test)]
            Self::InstallThrough(_, _, _, _, _, reply) => drop(reply.send(Err(error))),
            Self::Commit(_, reply) => drop(reply.send(Err(error))),
            Self::Install(_, _, _, _, reply) => drop(reply.send(Err(error))),
            Self::Admit(_, mode, reply) => {
                mode.fail(error.clone());
                drop(reply.send(Err(error)));
            }
            Self::AcknowledgeThrough(_, reply)
            | Self::Prune(_, reply)
            | Self::Promoted(_, reply) => drop(reply.send(Err(error))),
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
    admission_capacity: usize,
}

impl<H, V, B> Clone for CatalogClient<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            admission_capacity: self.admission_capacity,
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
        if self.commands.enqueue(TracedCommand::new(make(reply))) == Feedback::Closed {
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
        acknowledge_through(index: OutputIndex) -> ()
            => |reply| Command::AcknowledgeThrough(index, reply);
        prune(generation: u64) -> () => |reply| Command::Prune(generation, reply);
        promoted(frontiers: Vec<BlockRef<H::Digest>>) -> ()
            => |reply| Command::Promoted(frontiers, reply);
        progress() -> Progress<H::Digest> => Command::Progress;
        checkpoint() -> Checkpoint<H::Digest> => Command::Checkpoint;
    }

    /// Returns an exact pending block without exposing catalog storage ownership.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.block",
        level = "debug",
        skip_all
    )]
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
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.install",
        level = "info",
        skip_all
    )]
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
        level = "debug",
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

    /// Accepts one bounded commit and returns a token for its durable publication.
    ///
    /// Producer bodies are already durable in temporary custody. Any bodies still resident in the
    /// catalog's advisory cache are handed to delivery after publication; cache misses never delay
    /// the authoritative ordering checkpoint.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.commit",
        level = "info",
        skip_all,
        fields(
            selected = batch.selected.len(),
            history = batch.history.len(),
            outputs = batch.outputs.len(),
        )
    )]
    pub(in crate::multimmit::marshal) async fn start_commit(
        &self,
        batch: Commit<H, V>,
    ) -> Result<CommitToken, Error> {
        self.request(|reply| Command::Commit(batch, reply)).await
    }

    /// Commits one bounded ordering batch durably.
    #[cfg(test)]
    pub(in crate::multimmit::marshal) async fn commit(
        &self,
        batch: Commit<H, V>,
    ) -> Result<(), Error> {
        self.start_commit(batch).await?.wait().await
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
    pending_hot_bytes: u64,
    commands: mailbox::Receiver<TracedCommand<H, V, B>>,
    deferred: Option<TracedCommand<H, V, B>>,
    durability: Pool<DurabilityCompletion<H::Digest>>,
    /// In-flight sealed-segment proofs; optimization-only writes that never gate barriers.
    seals: Pool<(Vec<u64>, Result<(), Error>)>,
    durability_capacity: usize,
    // Every ready resolver request may await the admission cut that establishes local custody.
    custody_waiter_capacity: usize,
    // Metadata exposes a started sync's cursor before it is durable. External progress and
    // finalized pruning advance only after the completion is observed.
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
    pending_acknowledgement: Option<(OutputIndex, u64, Reply<()>, Span)>,
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
            Command::Admit(admissions, _, _)
                if !admissions.is_empty() && admissions.len() <= self.durability_capacity =>
            {
                let pending = self.pending_admission.as_ref().map_or(0, |cut| cut.items);
                admissions.len() <= self.durability_capacity - pending
            }
            Command::Bodies(_, _) => self.body_waiters.len() < self.body_waiter_capacity,
            command => {
                !command.commit_barrier()
                    || (self.barrier_ready()
                        && (!command.body_barrier() || self.materializer.is_idle()))
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
        loop {
            if self.start_admission_sync().await? {
                continue;
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
                && self.seals.is_empty()
                && self.materializer.is_idle()
            {
                match self.commands.try_recv() {
                    Ok(command) => {
                        self.process_command(command).await?;
                        continue;
                    }
                    Err(TryRecvError::Disconnected) => commands_open = false,
                    Err(TryRecvError::Empty) => {}
                }
            }

            if !commands_open
                && self.deferred.is_none()
                && self.pending_admission.is_none()
                && !self.admission_active
                && self.durability.is_empty()
                && self.seals.is_empty()
                && self.materializer.is_idle()
                && self.body_waiters.is_empty()
            {
                return Ok(());
            }

            match next_catalog_event(
                self.durability.next_completed(),
                self.materializer.complete_next(),
                self.seals.next_completed(),
                self.commands.recv(),
                commands_open && self.deferred.is_none(),
            )
            .await
            {
                CatalogEvent::Durability(completion) => {
                    self.complete_durability(completion).await?;
                }
                CatalogEvent::Seal((sealed, result)) => {
                    result?;
                    let pinned = self.pinned_body_segments();
                    let reclaimed = self.stores.finish_pending_seals(sealed, &pinned).await?;
                    self.materializer.release_readers(reclaimed);
                }
                CatalogEvent::Materialization(completion) => {
                    let completed = completion?;
                    self.update_materialization_metrics();
                    if let Some(completed) = completed {
                        let available = self.complete_materialization(completed)?;
                        self.retry_body_waiters(&available)?;
                    }
                }
                CatalogEvent::Command(Some(command)) => {
                    self.process_command(command).await?;
                }
                CatalogEvent::Command(None) => commands_open = false,
            }
        }
    }

    async fn process_command(&mut self, command: TracedCommand<H, V, B>) -> Result<(), Error> {
        let span = info_span!(
            parent: &command.span,
            "multimmit.marshal.catalog.process",
        );
        async {
            let TracedCommand { command, span } = command;
            match command {
                Command::Admit(write, sync, reply) => {
                    self.admit_batch(write, sync, reply, span).await
                }
                command => self.process(command).await,
            }
        }
        .instrument(span)
        .await
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
        self.metrics
            .materialized_cache_evictions
            .inc_by(evictions);
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
        let concurrency = u64::try_from(BODY_READ_CONCURRENCY).unwrap_or(u64::MAX);
        let max_group_bytes = self
            .max_materialized_block_bytes
            .checked_div(concurrency)
            .unwrap_or(0)
            .max(1);
        let groups = self.stores.body_read_groups(
            missing,
            max_group_bytes,
            NonZeroUsize::new(BODY_READ_CONCURRENCY)
                .expect("body read concurrency is non-zero"),
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

    fn cached_block(
        &self,
        reference: &BlockRef<H::Digest>,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
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
        self.seals.cancel_all();
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
        std::mem::replace(&mut self.commit_state, CommitState::Idle).fail(error.clone());
        if let Some((_, _, reply, _)) = self.pending_acknowledgement.take() {
            drop(reply.send(Err(error)));
        }
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
                    self.seals.push(
                        async move { (sealed, drain(handles).await) }.instrument(span),
                    );
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
            DurabilityCompletion::Acknowledgement {
                index,
                advances,
                reply,
                result,
            } => {
                if result.is_ok() {
                    self.durable_acknowledged = self.durable_acknowledged.max(Some(index));
                    self.metrics.acknowledgements.inc_by(advances);
                    self.update_progress_metrics();
                }
                respond(reply, result)
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

    fn attach_pending_acknowledgement(
        &mut self,
        pending: &mut PendingCommit<H, B>,
    ) -> Result<(), Error> {
        let Some((index, advances, reply, span)) = self.pending_acknowledgement.take() else {
            return Ok(());
        };
        if !pending
            .publication
            .checkpoint
            .preserve_acknowledged(Some(index))
        {
            drop(reply.send(Err(Error::Invalid(
                "acknowledgement exceeds commit publication",
            ))));
            return Err(Error::Invalid("acknowledgement exceeds commit publication"));
        }
        pending.span.follows_from(span.id());
        pending.acknowledgements.push((index, advances, reply));
        Ok(())
    }

    async fn start_commit_archives(&mut self, pending: &PendingCommit<H, B>) -> Result<(), Error> {
        let timer = self
            .metrics
            .finalized_archive_durability
            .timer(&self.clock);
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
        self.attach_pending_acknowledgement(pending)?;
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

        if self.commit_state.is_idle()
            && let Some((index, advances, reply, span)) = self.pending_acknowledgement.take()
        {
            let process = info_span!(
                parent: &span,
                "multimmit.marshal.catalog.process",
            );
            self.start_acknowledgement(index, advances, reply)
                .instrument(process)
                .await?;
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
        self.durable_acknowledged = self.durable_checkpoint.acknowledged();
        if let Some(cleanup) = &mut self.cleanup_due {
            cleanup.coalesce(pending.publication.cleanup.clone());
        } else {
            self.cleanup_due = Some(pending.publication.cleanup.clone());
        }
        self.commits_since_cleanup = self.commits_since_cleanup.saturating_add(1);
        self.metrics.commits.inc();
        self.metrics.committed_outputs.inc_by(pending.outputs);
        for (index, advances, reply) in pending.acknowledgements {
            self.durable_acknowledged = self.durable_acknowledged.max(Some(index));
            self.metrics.acknowledgements.inc_by(advances);
            drop(reply.send(Ok(())));
        }
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
                .map(|output| promoter::HotBody {
                    index: output.index,
                    block: Arc::clone(&output.block),
                    encoded_len: output.encoded_len,
                })
                .collect();
            promoter.published(committed, hot) == Feedback::Closed
        });
        let delivery_closed =
            delivery.is_some_and(|batch| self.delivery.committed(batch) == Feedback::Closed);
        self.pending_hot_bytes = self
            .pending_hot_bytes
            .checked_sub(pending.hot_bytes)
            .expect("pending commits own their hot-byte charge");
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
                    match self.commands.try_recv() {
                        Ok(TracedCommand {
                            command: Command::Admit(admissions, mode, reply),
                            span,
                        })
                            if admissions.len() <= remaining - items =>
                        {
                            processing_span.follows_from(span.id());
                            items += admissions.len();
                            commands.push((admissions, mode, reply));
                        }
                        Ok(command) => {
                            self.deferred = Some(command);
                            break;
                        }
                        Err(_) => break,
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
            match self.commands.try_recv() {
                Ok(TracedCommand {
                    command: Command::Admit(admissions, mode, reply),
                    span,
                }) => {
                    processing_span.follows_from(span.id());
                    next = Some((admissions, mode, reply, span));
                }
                Ok(command) => {
                    self.deferred = Some(command);
                    break;
                }
                Err(_) => break,
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
        let footprint = match self.stores.buffer_admissions(writes).await {
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
    ) -> Result<(Option<delivery::DurableBatch<H, B>>, u64), Error> {
        let Some(committed) = batch.outputs.last().map(|output| output.index) else {
            return Ok((None, 0));
        };
        let available = self
            .max_hot_block_bytes
            .saturating_sub(self.pending_hot_bytes);
        let mut hot_bytes = 0u64;
        let mut outputs = (0..batch.outputs.len()).map(|_| None).collect::<Vec<_>>();
        for cache in [&self.block_cache, &self.materialized_cache] {
            for (slot, output) in outputs.iter_mut().zip(&batch.outputs) {
                if slot.is_some() {
                    continue;
                }
                let Some(block) = cache.get(&output.reference()) else {
                    continue;
                };
                let encoded_len = output.meta().encoded_len();
                let Some(total) = hot_bytes.checked_add(encoded_len) else {
                    continue;
                };
                if block.reference() != output.reference()
                    || block.header() != output.meta().header()
                    || u64::try_from(block.encode_size()).ok() != Some(encoded_len)
                    || total > available
                {
                    continue;
                }
                hot_bytes = total;
                *slot = Some(delivery::DurableOutput {
                    index: output.index,
                    block,
                    encoded_len,
                });
            }
        }
        self.pending_hot_bytes
            .checked_add(hot_bytes)
            .ok_or(Error::Invalid("pending hot delivery bytes overflow"))?;
        Ok((
            Some(delivery::DurableBatch::new(
                batch.checkpoint.generation(),
                committed,
                outputs.into_iter().flatten().collect(),
                hot_bytes,
                self.max_hot_block_bytes,
            )),
            hot_bytes,
        ))
    }

    fn acknowledgement_advances(&self, index: OutputIndex) -> Result<u64, Error> {
        let current = &self.accepted_checkpoint;
        if current
            .acknowledged()
            .is_some_and(|acknowledged| index <= acknowledged)
        {
            return Ok(0);
        }
        if current
            .committed()
            .is_none_or(|committed| index > committed)
        {
            return Err(Error::Invalid(
                "acknowledgement does not advance a committed output prefix",
            ));
        }
        Ok(current.acknowledged().map_or_else(
            || index.get().saturating_add(1),
            |acknowledged| index.get().saturating_sub(acknowledged.get()),
        ))
    }

    async fn start_acknowledgement(
        &mut self,
        index: OutputIndex,
        advances: u64,
        reply: Reply<()>,
    ) -> Result<(), Error> {
        let mut next = self.accepted_checkpoint.clone();
        if !next.preserve_acknowledged(Some(index)) {
            return respond(
                reply,
                Err(Error::Invalid("acknowledgement exceeds committed output")),
            );
        }
        self.accepted_checkpoint = next.clone();
        let sync = self.stores.start_sync_checkpoint(next).await?;
        let span = info_span!(
            "multimmit.marshal.catalog.acknowledge",
            index = index.get(),
            advances = advances,
        );
        self.durability.push(
            async move {
                DurabilityCompletion::Acknowledgement {
                    index,
                    advances,
                    reply,
                    result: sync.await.map_err(Error::storage),
                }
            }
            .instrument(span),
        );
        Ok(())
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
            || checkpoint.acknowledged() != checkpoint.committed()
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

    async fn process(&mut self, command: Command<H, V, B>) -> Result<(), Error> {
        match command {
            command @ (Command::Install(_, _, _, _, _)
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
            Command::HistorySegment(key, max_items, max_bytes, reply) => respond(
                reply,
                self.stores.history_segment(key, max_items, max_bytes).await,
            ),
            Command::HeaderSegments(requests, max_bytes, reply) => {
                let stores = &self.stores;
                respond(
                    reply,
                    try_join_all(requests.into_iter().map(|(reference, max_items)| {
                        stores.header_segment(reference, max_items, max_bytes)
                    }))
                    .await,
                )
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
            Command::OutputRefs(start, max_items, max_bytes, reply) => {
                let result = match self.durable_checkpoint.committed() {
                    Some(committed) if start <= committed => {
                        let available = committed
                            .get()
                            .checked_sub(start.get())
                            .and_then(|distance| distance.checked_add(1))
                            .and_then(|count| usize::try_from(count).ok())
                            .unwrap_or(usize::MAX);
                        self.stores
                            .output_refs(start, max_items.min(available), max_bytes.get())
                            .await
                    }
                    _ => Err(Error::Invalid(
                        "output range does not begin at a committed row",
                    )),
                };
                respond(reply, result)
            }
            Command::Commit(mut batch, reply) => {
                if self.durable_checkpoint == batch.checkpoint {
                    let (completion, receipt) = oneshot::channel();
                    drop(completion.send(Ok(())));
                    return respond(reply, Ok(CommitToken(receipt)));
                }
                let acknowledged = self.accepted_checkpoint.acknowledged();
                if !batch.checkpoint.preserve_acknowledged(acknowledged) {
                    return respond(
                        reply,
                        Err(Error::Invalid(
                            "ordering commit regressed below acknowledged delivery",
                        )),
                    );
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
                let (delivery, hot_bytes) = match self.prepare_delivery(&batch) {
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
                    acknowledgements: Vec::new(),
                    delivery,
                    hot_bytes,
                    outputs,
                    span: Span::current(),
                };
                self.pending_hot_bytes = self
                    .pending_hot_bytes
                    .checked_add(hot_bytes)
                    .expect("prepared delivery fits the pending hot-byte budget");
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
            Command::CommitThroughCheckpoint(mut batch, reply) => {
                let acknowledged = self.stores.checkpoint().and_then(Checkpoint::acknowledged);
                let result = if batch.checkpoint.preserve_acknowledged(acknowledged) {
                    match self.validate_commit(&batch) {
                        Ok(()) => self.stores.publish_commit(batch).await.map(|_| ()),
                        Err(error) => Err(error),
                    }
                } else {
                    Err(Error::Invalid(
                        "ordering commit regressed below acknowledged delivery",
                    ))
                };
                respond(reply, result)
            }
            #[cfg(test)]
            Command::Pause(release, started, reply) => {
                let _ = started.send(());
                respond(reply, release.await.map_err(|_| Error::Closed))
            }
            Command::AcknowledgeThrough(index, reply) => {
                let advances = match self.acknowledgement_advances(index) {
                    Ok(advances) => advances,
                    Err(error) => return respond(reply, Err(error)),
                };
                if advances == 0 {
                    return respond(reply, Ok(()));
                }
                if self.pending_acknowledgement.is_some() {
                    return respond(
                        reply,
                        Err(Error::Invalid(
                            "acknowledgement publication is already pending",
                        )),
                    );
                }
                if !self.commit_state.is_idle() {
                    self.accepted_checkpoint.preserve_acknowledged(Some(index));
                    self.pending_acknowledgement =
                        Some((index, advances, reply, Span::current()));
                } else {
                    self.start_acknowledgement(index, advances, reply).await?;
                }
                Ok(())
            }
            Command::Install(checkpoint, prune, proof, history, reply) => {
                self.cleanup().await?;
                let acknowledged = checkpoint.acknowledged();
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
                        self.durable_acknowledged = acknowledged;
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
                            self.delivery.reset().ok_or(Error::DeliveryClosed)
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
                let result = self
                    .stores
                    .prune_finalized(generation, self.durable_acknowledged, &pinned)
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
            Command::Checkpoint(reply) => {
                let mut checkpoint = self.durable_checkpoint.clone();
                let result = checkpoint
                    .preserve_acknowledged(self.durable_acknowledged)
                    .then_some(checkpoint)
                    .ok_or(Error::Invalid("durable acknowledgement exceeds commit"));
                respond(reply, result)
            }
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
        self.metrics
            .progress(checkpoint.committed(), self.durable_acknowledged);
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
    try_join_all(handles).await.map(|_| ()).map_err(Error::storage)
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
    custody_waiter_capacity: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_commit_block_bytes: NonZeroUsize,
    max_block_bytes: NonZeroUsize,
    delivery: DeliveryClient<H, B>,
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
    let durable_acknowledged = checkpoint.acknowledged();
    metrics.progress(checkpoint.committed(), checkpoint.acknowledged());
    let (commands, receiver) = mailbox::new(context.child("mailbox"), capacity);
    let client = CatalogClient {
        commands,
        admission_capacity: admission_cut_capacity.get(),
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
            pending_hot_bytes: 0,
            commands: receiver,
            deferred: None,
            durability: Pool::default(),
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
            pending_acknowledgement: None,
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
    use super::*;
    use super::super::materializer::BODY_READER_RESIDENCY;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            marshal::{
                config::{ArchiveConfig, ArchiveMode, Config, Start},
                storage::checkpoint::ArchiveLayout,
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
    use commonware_utils::{NZU16, NZU32, NZU64, NZUsize};
    use std::num::NonZeroU64;

    type TestBody = EmptyBlock<Sha256>;
    type Client = CatalogClient<Sha256, MinPk, TestBody>;
    type DeliveryReceiver = delivery::DeliveryReceiver<Sha256, TestBody>;

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
        let (client, handle, _, _) = config.spawn::<_, Sha256>(context, delivery).await.unwrap();
        (client, handle, receiver)
    }

    async fn open(
        context: &DeterministicContext,
        label: &'static str,
        committee: &Committee<MinPk>,
    ) -> (Client, Handle<Result<(), Error>>, DeliveryReceiver) {
        spawn_catalog(config(context, committee), context.child(label)).await
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
                config.archive.page_cache =
                    CacheRef::from_pooler(context, NZU16!(1), NZUsize!(1));
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
                current.acknowledged(),
            )
            .unwrap();
            client
                .commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: blocks
                        .iter()
                        .enumerate()
                        .map(|(index, block)| {
                            output_row(OutputIndex::new(index as u64), block)
                        })
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

            let materialized_before =
                metric_total(&context.encode(), "materialized_bodies_total");
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
                config.max_hot_block_bytes =
                    NonZeroUsize::new(blocks[0].encode_size()).unwrap();
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
            let acquisitions =
                || metric_total(&context.encode(), "reader_acquisitions_total");
            let recoveries = || {
                metric_sum(&context.encode(), "reader_acquisitions_total", Some("Recovered"))
            };
            let read = |index: usize| {
                let client = &client;
                let blocks = &blocks;
                async move {
                    assert_eq!(
                        client.block(blocks[index].reference()).await.unwrap().as_deref(),
                        Some(blocks[index].as_ref())
                    );
                }
            };

            read(0).await;
            assert_eq!(acquisitions(), 1, "the first cold segment reader was not acquired");
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
            assert_eq!(acquisitions(), 2 + filling as u64, "next segment past residency");
            read(2 * (filling + 2)).await;
            assert_eq!(acquisitions(), 3 + filling as u64, "second segment past residency");
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
                        None,
                    )
                    .unwrap(),
                })
                .await
                .unwrap();
            client.acknowledge_through(OutputIndex::ZERO).await.unwrap();
            drop(client);
            assert!(handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("delayed"),
                pending: reads.clone(),
            };
            let (client, handle, _delivery) =
                spawn_catalog(configure(&context), delayed.child("reopened")).await;
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
            let configure = |context: &DeterministicContext| {
                let mut config = config(context, &committee);
                set_capacity(&mut config, BODY_READ_CONCURRENCY);
                config.max_hot_block_bytes = NonZeroUsize::new(
                    block_bytes * BODY_READ_CONCURRENCY * BODY_READ_CONCURRENCY,
                )
                .unwrap();
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
            let references = blocks.iter().map(|block| block.reference()).collect();
            let mut body_read = Box::pin(client.bodies(references));
            let mut blocked = Box::pin(gate.blocked);
            commonware_macros::select! {
                result = &mut blocked => { result.unwrap(); },
                result = &mut body_read => panic!("body materialization completed before reaching storage: {result:?}"),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("body materialization did not reach storage")
                },
            }
            assert_eq!(
                metric_total(&context.encode(), "materialization_groups_total"),
                BODY_READ_CONCURRENCY as u64,
                "one bounded body request did not expose the available read jobs"
            );

            gate.release.send(()).expect("blocked read was dropped");
            let materialized = body_read.await.unwrap();
            assert_eq!(
                materialized
                    .iter()
                    .map(|block| block.as_ref().unwrap().reference())
                    .collect::<Vec<_>>(),
                blocks
                    .iter()
                    .map(|block| block.reference())
                    .collect::<Vec<_>>()
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
                current.acknowledged(),
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
            reopened.max_materialized_block_bytes =
                NonZeroUsize::new(first.encode_size()).unwrap();
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
                current.acknowledged(),
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
            assert_eq!(batch.outputs[0].index, OutputIndex::new(1));
            assert_eq!(batch.outputs[0].block.as_ref(), second.as_ref());

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
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), delayed.child("catalog")).await;
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
            config.resolver_max_value_bytes = NZUsize!(1);
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
                TipRecord::new(
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
                current.acknowledged(),
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
    fn acknowledgement_sync_does_not_block_catalog_reads() {
        deterministic::Runner::default().start(|context| async move {
            let limits = Limits::new(2, 2).unwrap();
            let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
            let committee = Committee::<MinPk>::new_with_namespace_and_producers(
                8,
                b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ASYNC_ACK",
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
            let current = client.checkpoint().await.unwrap();
            let block = producer_block(&committee, 0, 11);
            let reference = block.reference();
            client
                .stage_blocks(std::slice::from_ref(&block))
                .await
                .unwrap();
            let mut emitted = current.emitted().to_vec();
            emitted[0] = reference;
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
                None,
            )
            .unwrap();
            drive_pending_syncs(
                &syncs,
                client.commit(Commit {
                    selected: Vec::new(),
                    history: Vec::new(),
                    outputs: vec![output_row(OutputIndex::ZERO, &block)],
                    checkpoint,
                }),
            )
            .await
            .unwrap();

            syncs.arm();
            let mut acknowledgement = Box::pin(client.acknowledge_through(OutputIndex::ZERO));
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                commonware_macros::select! {
                    result = &mut acknowledgement => {
                        panic!("acknowledgement completed before its sync: {result:?}")
                    },
                    _ = context.sleep(std::time::Duration::from_millis(1)) => {},
                }
            }
            assert!(
                syncs.calls() > 0,
                "acknowledgement did not start a durability operation"
            );

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
            let stored = stored
                .expect("acknowledgement sync blocked an independent catalog read")
                .expect("committed output remains readable");
            drop(read);
            assert_eq!(stored.as_ref(), block.as_ref());
            commonware_macros::select! {
                result = &mut acknowledgement => {
                    panic!("acknowledgement completed before durability: {result:?}")
                },
                _ = context.sleep(std::time::Duration::from_millis(1)) => {},
            }

            syncs.unblock();
            acknowledgement.await.unwrap();
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
                None,
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
                None,
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
                current.acknowledged(),
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
                None,
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
                None,
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
                None,
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
        acknowledged: Option<OutputIndex>,
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
            acknowledged,
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
                TipRecord::new(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                    .unwrap(),
            );
            let record = Arc::new(
                TipRecord::new(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
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
            let target = checkpoint(
                &committee,
                1,
                id,
                history,
                0,
                genesis.tips().to_vec(),
                None,
                None,
            );
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
            let base = TipRecord::new(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap();
            let record = Arc::new(
                TipRecord::new(base.commitment::<Sha256>(), genesis.tips().to_vec()).unwrap(),
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
            let target = checkpoint(
                &committee,
                1,
                id,
                history,
                0,
                genesis.tips().to_vec(),
                None,
                None,
            );
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
                None,
            )
            .unwrap();
            let ready = CatalogState::ready(current, None);
            let intent = ready
                .begin(
                    target.clone(),
                    proof.view(),
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
                TipRecord::new(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
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
            let (client, handle, _, promoter_handle) = first
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
                        None,
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
            let (client, handle, promoter, promoter_handle) = reopened
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
    fn admissions_chunked_commit_ack_reopen_and_install() {
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
                Arc::new(TipRecord::new(initial_history, genesis.tips().to_vec()).unwrap());
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
                            TipRecord::new(
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
                    None,
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
                None,
            );
            let stale_record = Arc::new(
                TipRecord::new(
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
                None,
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

            let (client, handle, _delivery) =
                open(&context, "commit_cleanup_replay", &committee).await;
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
                client.acknowledge_through(OutputIndex::new(1)).await,
                Err(Error::Invalid(_))
            ));
            client.acknowledge_through(OutputIndex::ZERO).await.unwrap();
            client.acknowledge_through(OutputIndex::ZERO).await.unwrap();
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
                TipRecord::new(history, committee.config.genesis().tips().to_vec()).unwrap(),
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
                None,
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
                None,
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
            assert_eq!(reset.len(), 1);
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
