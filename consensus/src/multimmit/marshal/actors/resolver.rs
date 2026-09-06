//! Bounded resolver actor with exact, durable completion.

use super::{
    catalog::{self, CatalogClient},
    metrics::{self, FetchReason},
    producer, promoter,
    synchronizer::{FetchedBlock, Fetcher, HeaderSegment, HistorySegment, LqcVerifier},
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        config::CodecConfig,
        marshal::wire::{Key, MAX_SEGMENT_ITEMS},
        types::{
            BlockRef, CertificateId, Lqc, TipRecord, TransactionBlock, TransactionBlockHeader,
        },
    },
    types::{Epoch, Height, View},
};
use bytes::Bytes;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::{Codec, Decode as _, EncodeSize as _, RangeCfg};
use commonware_cryptography::{Digest, Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_resolver::{Consumer, Delivery, Fetch, Outcome, Resolver, p2p::Producer};
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{
    channel::oneshot,
    futures::{AbortablePool, Aborter, Pool},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    fmt::Display,
    future::pending,
    num::{NonZeroU16, NonZeroUsize},
    slice,
    sync::{Arc, mpsc::TryRecvError},
};
use tracing::{Instrument as _, Span, info_span};

/// An exact fetch could not complete.
#[derive(Clone, Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    #[error("resolver adapter is closed")]
    Closed,
    #[error("resolver has stopped accepting fetches")]
    ResolverClosed,
    #[error("resolver pending bound is exhausted")]
    PendingFull,
    #[error("resolver request coordinate is exhausted")]
    RequestExhausted,
    #[error("invalid resolver request: {0}")]
    Invalid(&'static str),
    #[error("catalog access failed: {0}")]
    Catalog(Arc<str>),
    #[error("resolver child actor failed: {0}")]
    Child(Arc<str>),
}

fn catalog_error(error: impl Display) -> Error {
    Error::Catalog(Arc::from(error.to_string()))
}

fn response_process_span(parent: &Span, received: usize) -> Span {
    info_span!(
        parent: parent,
        "multimmit.marshal.resolver.fetch.response.process",
        received = received,
    )
}

fn response_stage_span(process: &Span, blocks: usize, bytes: u64) -> Span {
    info_span!(
        parent: process,
        "multimmit.marshal.resolver.fetch.response.stage",
        blocks = blocks,
        bytes = bytes,
    )
}

type BlockSegment<H, B> = Arc<Vec<Arc<TransactionBlock<H, B>>>>;

fn validate_history_segment<H: Hasher>(
    mut expected: H::Digest,
    records: Vec<TipRecord<H::Digest>>,
) -> Option<HistorySegment<H::Digest>> {
    let mut segment = Vec::with_capacity(records.len());
    for record in records {
        if record.commitment::<H>() != expected {
            return None;
        }
        expected = record.parent();
        segment.push(Arc::new(record));
    }
    Some(Arc::new(segment))
}

fn validate_header_segment<H: Hasher>(
    epoch: Epoch,
    mut expected: BlockRef<H::Digest>,
    headers: Vec<TransactionBlockHeader<H::Digest>>,
) -> Option<HeaderSegment<H::Digest>> {
    for (position, header) in headers.iter().enumerate() {
        if header.epoch() != epoch
            || header.block_ref::<H>() != expected
            || (expected.height().get() == 1 && position + 1 != headers.len())
        {
            return None;
        }
        expected = BlockRef::new(
            expected.chain(),
            crate::types::Height::new(expected.height().get().saturating_sub(1)),
            header.parent(),
        );
    }
    Some(Arc::new(headers))
}

fn validate_block_segment<H, B>(
    epoch: Epoch,
    mut expected: BlockRef<H::Digest>,
    blocks: Vec<TransactionBlock<H, B>>,
) -> Option<BlockSegment<H, B>>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let count = blocks.len();
    let mut segment = Vec::with_capacity(count);
    for (position, block) in blocks.into_iter().enumerate() {
        if block.header().epoch() != epoch
            || block.reference() != expected
            || (expected.height().get() == 1 && position + 1 != count)
        {
            return None;
        }
        expected = BlockRef::new(
            expected.chain(),
            Height::new(expected.height().get().saturating_sub(1)),
            block.header().parent(),
        );
        segment.push(Arc::new(block));
    }
    Some(Arc::new(segment))
}

/// Immutable decoding and resource limits for one adapter actor.
pub(in crate::multimmit::marshal) struct Config<C> {
    epoch: Epoch,
    codec: CodecConfig,
    body: C,
    max_block_bytes: NonZeroUsize,
    max_value_bytes: NonZeroUsize,
}

impl<C> Config<C> {
    pub(in crate::multimmit::marshal) const fn new(
        epoch: Epoch,
        codec: CodecConfig,
        body: C,
        max_block_bytes: NonZeroUsize,
        max_value_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            epoch,
            codec,
            body,
            max_block_bytes,
            max_value_bytes,
        }
    }
}

#[derive(Clone)]
struct Generation(Arc<()>);

impl PartialEq for Generation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Generation {}

impl PartialOrd for Generation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Generation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        Arc::as_ptr(&self.0).cmp(&Arc::as_ptr(&other.0))
    }
}

/// Local identity retained by `commonware-resolver` for one exact waiter.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Subscriber {
    generation: Generation,
    request: u64,
}

type LqcReply<V, D> = oneshot::Sender<Result<Arc<Lqc<V, D>>, Error>>;
type HistoryReply<D> = oneshot::Sender<Result<HistorySegment<D>, Error>>;
type HeaderReply<D> = oneshot::Sender<Result<HeaderSegment<D>, Error>>;
type BlockReply<H, B> = oneshot::Sender<Result<Arc<TransactionBlock<H, B>>, Error>>;
type BlocksReply<H, B> = oneshot::Sender<Result<BlockSegment<H, B>, Error>>;

fn track_reply<T: Send + 'static>(
    request: u64,
    mut reply: oneshot::Sender<T>,
    cancellations: &mut Pool<'static, u64>,
) -> oneshot::Sender<T> {
    let (relay, receiver) = oneshot::channel();
    cancellations.push(async move {
        select! {
            result = receiver => {
                if let Ok(result) = result {
                    drop(reply.send(result));
                }
            },
            _ = reply.closed() => {},
        }
        request
    });
    relay
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockMode {
    /// Wait for local ingress without starting a resolver request.
    Wait,
    /// Fetch for a caller that requires temporary catalog custody.
    Fetch,
    /// Fetch for a subscription whose service reply establishes durable custody.
    Subscribe,
}

enum Pending<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Lqc(CertificateId<H::Digest>, LqcReply<V, H::Digest>),
    History(H::Digest, HistoryReply<H::Digest>),
    Headers(BlockRef<H::Digest>, HeaderReply<H::Digest>),
    Block(BlockRef<H::Digest>, BlockMode, BlockReply<H, B>),
    Blocks(Arc<Vec<BlockRef<H::Digest>>>, BlocksReply<H, B>),
    CertifiedBlock(BlockRef<H::Digest>),
}

struct Request<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    span: Span,
    pending: Pending<H, V, B>,
    reason: FetchReason,
    fetching: bool,
}

impl<H, V, B> Request<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    const fn fetch_reason(&self) -> Option<FetchReason> {
        if self.fetching || !self.pending.fetches() {
            return None;
        }
        Some(match &self.pending {
            Pending::Block(_, BlockMode::Subscribe, _) => FetchReason::CertifiedSubscription,
            _ => self.reason,
        })
    }
}

enum Artifact<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Lqc(CertificateId<H::Digest>, Arc<Lqc<V, H::Digest>>),
    History(H::Digest, HistorySegment<H::Digest>),
    Headers(BlockRef<H::Digest>, HeaderSegment<H::Digest>),
    Block(BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>),
    Blocks(Key<H::Digest>, BlockSegment<H, B>),
}

impl<H, V, B> Pending<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn closed(&self) -> bool {
        match self {
            Self::Lqc(_, reply) => reply.is_closed(),
            Self::History(_, reply) => reply.is_closed(),
            Self::Headers(_, reply) => reply.is_closed(),
            Self::Block(_, _, reply) => reply.is_closed(),
            Self::Blocks(_, reply) => reply.is_closed(),
            Self::CertifiedBlock(_) => false,
        }
    }

    fn fail(self, error: Error) {
        match self {
            Self::Lqc(_, reply) => drop(reply.send(Err(error))),
            Self::History(_, reply) => drop(reply.send(Err(error))),
            Self::Headers(_, reply) => drop(reply.send(Err(error))),
            Self::Block(_, _, reply) => drop(reply.send(Err(error))),
            Self::Blocks(_, reply) => drop(reply.send(Err(error))),
            Self::CertifiedBlock(_) => {}
        }
    }

    fn track(self, request: u64, cancellations: &mut Pool<'static, u64>) -> Self {
        match self {
            Self::Lqc(id, reply) => Self::Lqc(id, track_reply(request, reply, cancellations)),
            Self::History(commitment, reply) => {
                Self::History(commitment, track_reply(request, reply, cancellations))
            }
            Self::Headers(reference, reply) => {
                Self::Headers(reference, track_reply(request, reply, cancellations))
            }
            Self::Block(reference, mode, reply) => {
                Self::Block(reference, mode, track_reply(request, reply, cancellations))
            }
            Self::Blocks(references, reply) => {
                Self::Blocks(references, track_reply(request, reply, cancellations))
            }
            Self::CertifiedBlock(reference) => Self::CertifiedBlock(reference),
        }
    }

    fn key(&self) -> Key<H::Digest> {
        match self {
            Self::Lqc(id, _) => Key::lqc_by_id(*id),
            Self::History(commitment, _) => Key::tip_record(*commitment),
            Self::Headers(reference, _) => Key::producer_headers(*reference),
            Self::Block(reference, _, _) | Self::CertifiedBlock(reference) => {
                Key::producer_block(reference.chain(), reference.digest())
            }
            Self::Blocks(references, _) => Key::producer_blocks(
                references[0],
                NonZeroU16::new(
                    u16::try_from(references.len()).expect("bounded range length fits in u16"),
                )
                .expect("body ranges are non-empty"),
            ),
        }
    }

    const fn fetches(&self) -> bool {
        matches!(
            self,
            Self::Lqc(_, _)
                | Self::History(_, _)
                | Self::Headers(_, _)
                | Self::Block(_, BlockMode::Fetch | BlockMode::Subscribe, _)
                | Self::Blocks(_, _)
        )
    }

    fn accepts(&self, artifact: &Artifact<H, V, B>) -> bool {
        match (self, artifact) {
            (Self::Lqc(expected, _), Artifact::Lqc(actual, _)) => expected.get() == actual.get(),
            (Self::History(expected, _), Artifact::History(actual, _)) => expected == actual,
            (Self::Headers(expected, _), Artifact::Headers(actual, _)) => expected == actual,
            (Self::Block(expected, _, _), Artifact::Block(actual, _)) => expected == actual,
            (Self::Blocks(expected, _), Artifact::Blocks(_, actual)) => {
                !actual.is_empty()
                    && actual.len() <= expected.len()
                    && expected
                        .iter()
                        .zip(actual.iter())
                        .all(|(expected, actual)| *expected == actual.reference())
            }
            (Self::CertifiedBlock(expected), Artifact::Block(actual, _)) => expected == actual,
            _ => false,
        }
    }

    fn succeed(self, artifact: &Artifact<H, V, B>) {
        match (self, artifact) {
            (Self::Lqc(_, reply), Artifact::Lqc(_, value)) => {
                drop(reply.send(Ok(Arc::clone(value))))
            }
            (Self::History(_, reply), Artifact::History(_, value)) => {
                drop(reply.send(Ok(Arc::clone(value))))
            }
            (Self::Headers(_, reply), Artifact::Headers(_, value)) => {
                drop(reply.send(Ok(Arc::clone(value))))
            }
            (Self::Block(_, _, reply), Artifact::Block(_, value)) => {
                drop(reply.send(Ok(Arc::clone(value))))
            }
            (Self::Blocks(_, reply), Artifact::Blocks(_, value)) => {
                drop(reply.send(Ok(Arc::clone(value))))
            }
            (Self::CertifiedBlock(_), Artifact::Block(_, _)) => {}
            _ => unreachable!("matching artifact has matching request type"),
        }
    }
}

impl<H, V, B> Artifact<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    const fn key(&self) -> Key<H::Digest> {
        match self {
            Self::Lqc(id, _) => Key::lqc_by_id(*id),
            Self::History(commitment, _) => Key::tip_record(*commitment),
            Self::Headers(reference, _) => Key::producer_headers(*reference),
            Self::Block(reference, _) => Key::producer_block(reference.chain(), reference.digest()),
            Self::Blocks(key, _) => *key,
        }
    }
}

async fn local_artifact<H, V, B>(
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    key: Key<H::Digest>,
    range_references: Option<Arc<Vec<BlockRef<H::Digest>>>>,
    max_value_bytes: usize,
) -> Result<Option<Artifact<H, V, B>>, Error>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Clone,
{
    match key {
        Key::LqcById { id } => catalog
            .lqc(id)
            .await
            .map_err(catalog_error)
            .map(|proof| proof.map(|proof| Artifact::Lqc(id, proof))),
        Key::TipRecord { commitment } => catalog
            .history(commitment)
            .await
            .map_err(catalog_error)
            .map(|record| {
                record.map(|record| Artifact::History(commitment, Arc::new(vec![record])))
            }),
        Key::ProducerBlock { chain, digest } => bodies
            .block_by_digest(chain, digest)
            .await
            .map_err(catalog_error)
            .map(|block| block.map(|block| Artifact::Block(block.reference(), block))),
        Key::ProducerBlocks { .. } => {
            let Some(references) = range_references else {
                return Err(Error::Invalid("range recheck is missing exact references"));
            };
            let values = bodies
                .blocks(references.as_ref().clone())
                .await
                .map_err(catalog_error)?;
            if values.len() != references.len() {
                return Err(Error::Catalog(Arc::from(
                    "local producer body range has invalid cardinality",
                )));
            }
            let mut blocks = Vec::new();
            for (reference, block) in references.iter().zip(values) {
                let Some(block) = block else {
                    break;
                };
                if block.reference() != *reference {
                    return Err(Error::Catalog(Arc::from(
                        "local producer body does not match its range coordinate",
                    )));
                }
                blocks.push(block);
            }
            Ok((!blocks.is_empty()).then(|| Artifact::Blocks(key, Arc::new(blocks))))
        }
        Key::ProducerHeaders { head } => {
            let headers = catalog
                .header_segments(vec![(head, MAX_SEGMENT_ITEMS)], max_value_bytes)
                .await
                .map_err(catalog_error)?
                .pop()
                .unwrap_or_default();
            Ok((!headers.is_empty()).then(|| Artifact::Headers(head, Arc::new(headers))))
        }
    }
}

enum Command<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> {
    #[cfg(test)]
    Barrier(oneshot::Sender<()>),
    Deliver(
        Span,
        Delivery<Key<H::Digest>, Subscriber>,
        Bytes,
        DeliveryReply,
    ),
    Fetch(Span, Pending<H, V, B>, FetchReason),
    CertifiedBlock(BlockRef<H::Digest>),
    RetireCertified(Vec<BlockRef<H::Digest>>, oneshot::Sender<Result<(), Error>>),
    AdmittedBlock(
        BlockRef<H::Digest>,
        Arc<TransactionBlock<H, B>>,
        oneshot::Sender<Result<(), Error>>,
    ),
    AdmittedHistory(
        H::Digest,
        Arc<TipRecord<H::Digest>>,
        oneshot::Sender<Result<(), Error>>,
    ),
}

struct DeliveryReply(Option<oneshot::Sender<Outcome>>);

struct BlockDelivery<D: Digest> {
    delivery: Delivery<Key<D>, Subscriber>,
    value: Bytes,
    response: DeliveryReply,
}

struct ReadyBlock<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    delivery: Delivery<Key<H::Digest>, Subscriber>,
    reference: BlockRef<H::Digest>,
    block: Arc<TransactionBlock<H, B>>,
    response: DeliveryReply,
}

struct ReadyRange<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    delivery: Delivery<Key<H::Digest>, Subscriber>,
    blocks: BlockSegment<H, B>,
    response: DeliveryReply,
}

struct StagingJob<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    ready: Vec<ReadyBlock<H, B>>,
    ready_ranges: Vec<ReadyRange<H, B>>,
    staged: Vec<Arc<TransactionBlock<H, B>>>,
    keys: BTreeSet<Key<H::Digest>>,
    bytes: u64,
    span: Span,
}

struct StagingCompletion<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    ready: Vec<ReadyBlock<H, B>>,
    ready_ranges: Vec<ReadyRange<H, B>>,
    keys: BTreeSet<Key<H::Digest>>,
    bytes: u64,
    timer: commonware_runtime::telemetry::metrics::histogram::Timer,
    result: Result<(), Error>,
}

struct RecheckCompletion<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    key: Key<H::Digest>,
    result: Result<Option<Artifact<H, V, B>>, Error>,
}

enum Event<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Recheck(Option<RecheckCompletion<H, V, B>>),
    Staging(StagingCompletion<H, B>),
    Canceled(u64),
    Command(Option<Command<H, V, B>>),
}

impl DeliveryReply {
    const fn new(reply: oneshot::Sender<Outcome>) -> Self {
        Self(Some(reply))
    }

    fn send(mut self, outcome: Outcome) {
        if let Some(reply) = self.0.take() {
            let _ = reply.send(outcome);
        }
    }
}

impl Drop for DeliveryReply {
    fn drop(&mut self) {
        if let Some(reply) = self.0.take() {
            let _ = reply.send(Outcome::Ignored);
        }
    }
}

impl<H, V, B> Policy for Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) {
        let retain = |command: &Self| match command {
            Self::Fetch(_, pending, _) => !pending.closed(),
            Self::AdmittedBlock(_, _, reply)
            | Self::AdmittedHistory(_, _, reply)
            | Self::RetireCertified(_, reply) => !reply.is_closed(),
            #[cfg(test)]
            Self::Barrier(reply) => !reply.is_closed(),
            _ => true,
        };
        overflow.retain(retain);
        match command {
            Self::Deliver(_, _, _, reply) => reply.send(Outcome::Ambiguous),
            Self::CertifiedBlock(_) => {}
            command => {
                if retain(&command) {
                    overflow.push_back(command);
                }
            }
        }
    }
}

/// Resolver-facing producer and consumer.
pub struct Bridge<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> {
    commands: mailbox::Sender<Command<H, V, B>>,
    producer: producer::Mailbox<H::Digest>,
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Clone for Bridge<H, V, B> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            producer: self.producer.clone(),
        }
    }
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Producer
    for Bridge<H, V, B>
{
    type Key = Key<H::Digest>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        self.producer.produce(key)
    }

    fn try_produce(&mut self, key: Self::Key) -> Option<oneshot::Receiver<Bytes>> {
        self.producer.try_produce(key)
    }
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Consumer
    for Bridge<H, V, B>
{
    type Key = Key<H::Digest>;
    type Value = Bytes;
    type Subscriber = Subscriber;
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (response, receiver) = oneshot::channel();
        let span = info_span!(
            parent: &delivery.subscribers.first().1,
            "multimmit.marshal.resolver.fetch.response",
        );
        for (_, cause) in delivery.subscribers.iter().skip(1) {
            span.follows_from(cause.id());
        }
        let _ = self.commands.enqueue(Command::Deliver(
            span,
            delivery,
            value,
            DeliveryReply::new(response),
        ));
        receiver
    }
}

/// Unopened actor endpoint paired with a [`Bridge`].
pub(in crate::multimmit::marshal) struct Endpoint<
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
> {
    commands: mailbox::Sender<Command<H, V, B>>,
    receiver: mailbox::Receiver<Command<H, V, B>>,
    producer_guard: producer::Mailbox<H::Digest>,
    producer: producer::Receiver<H::Digest>,
    generation: Generation,
}

/// Allocates the bounded resolver-facing channel before the resolver is constructed.
pub(in crate::multimmit::marshal) fn channel<
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
>(
    metrics: impl RuntimeMetrics,
    producer_metrics: impl RuntimeMetrics,
    capacity: NonZeroUsize,
) -> (Bridge<H, V, B>, Endpoint<H, V, B>) {
    let generation = Generation(Arc::new(()));
    let (commands, receiver) = mailbox::new(metrics, capacity);
    let (producer, producer_receiver) = producer::channel(producer_metrics, capacity);
    (
        Bridge {
            commands: commands.clone(),
            producer: producer.clone(),
        },
        Endpoint {
            commands,
            receiver,
            producer_guard: producer,
            producer: producer_receiver,
            generation,
        },
    )
}

/// Exact fetch client consumed by the synchronizer.
pub(in crate::multimmit::marshal) struct Client<
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
> {
    commands: mailbox::Sender<Command<H, V, B>>,
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Clone for Client<H, V, B> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Client<H, V, B> {
    #[cfg(test)]
    async fn barrier(&self) {
        let (reply, receiver) = oneshot::channel();
        assert!(self.commands.enqueue(Command::Barrier(reply)).accepted());
        receiver.await.unwrap();
    }

    async fn request<T>(
        &self,
        reason: FetchReason,
        make: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Pending<H, V, B>,
    ) -> Result<T, Error> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .enqueue(Command::Fetch(Span::current(), make(reply), reason))
            == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.lqc",
        level = "info",
        skip_all,
        fields(reason = ?reason)
    )]
    pub(in crate::multimmit::marshal) async fn lqc(
        &self,
        reason: FetchReason,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<V, H::Digest>>, Error> {
        self.request(reason, |reply| Pending::Lqc(id, reply)).await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.history",
        level = "info",
        skip_all,
        fields(reason = ?reason, view = view.get())
    )]
    async fn history(
        &self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> Result<HistorySegment<H::Digest>, Error> {
        self.request(reason, |reply| Pending::History(commitment, reply))
            .await
    }

    async fn headers(
        &self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<HeaderSegment<H::Digest>, Error> {
        self.request(reason, |reply| Pending::Headers(reference, reply))
            .await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.block",
        level = "info",
        skip_all,
        fields(
            reason = ?reason,
            chain = reference.chain().get(),
            height = reference.height().get(),
        )
    )]
    pub(in crate::multimmit::marshal) async fn block(
        &self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        self.request(reason, |reply| {
            Pending::Block(reference, BlockMode::Fetch, reply)
        })
        .await
    }

    async fn blocks(
        &self,
        reason: FetchReason,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BlockSegment<H, B>, Error> {
        if references.is_empty() || references.len() > MAX_SEGMENT_ITEMS {
            return Err(Error::Invalid("producer body range length is invalid"));
        }
        if references.windows(2).any(|pair| {
            pair[0].chain() != pair[1].chain()
                || pair[1].height().get().checked_add(1) != Some(pair[0].height().get())
        }) {
            return Err(Error::Invalid(
                "producer body range coordinates are not consecutive",
            ));
        }
        self.request(reason, |reply| Pending::Blocks(Arc::new(references), reply))
            .await
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.subscribe_block",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn subscribe_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        self.request(FetchReason::CertifiedSubscription, |reply| {
            Pending::Block(reference, BlockMode::Wait, reply)
        })
        .await
    }

    pub(in crate::multimmit::marshal) fn certified_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Feedback {
        self.commands.enqueue(Command::CertifiedBlock(reference))
    }

    pub(in crate::multimmit::marshal) async fn retire_certified(
        &self,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Result<(), Error> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .enqueue(Command::RetireCertified(frontiers, reply))
            == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.admit_block",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn admitted_block(
        &self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .enqueue(Command::AdmittedBlock(reference, block, reply))
            == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    #[tracing::instrument(
        name = "multimmit.marshal.resolver.admit_history",
        level = "debug",
        skip_all
    )]
    pub(in crate::multimmit::marshal) async fn admitted_history(
        &self,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let (reply, receiver) = oneshot::channel();
        if self
            .commands
            .enqueue(Command::AdmittedHistory(commitment, record, reply))
            == Feedback::Closed
        {
            return Err(Error::Closed);
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }
}

/// Exact resolver client that returns only catalog-proven producer-block custody.
pub(in crate::multimmit::marshal) struct CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    resolver: Client<H, V, B>,
    catalog: CatalogClient<H, V, B>,
}

impl<H, V, B> CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) const fn new(
        resolver: Client<H, V, B>,
        catalog: CatalogClient<H, V, B>,
    ) -> Self {
        Self { resolver, catalog }
    }

    async fn confirm_custody(
        &self,
        references: &[BlockRef<H::Digest>],
    ) -> Result<Vec<catalog::CustodyRef<H::Digest>>, Error> {
        let values = self
            .catalog
            .wait_for_custody(references.to_vec())
            .await
            .map_err(catalog_error)?;
        if values.len() != references.len() {
            return Err(Error::Catalog(Arc::from(
                "catalog custody response has invalid cardinality",
            )));
        }
        references
            .iter()
            .zip(values)
            .map(|(reference, custody)| {
                custody
                    .filter(|custody| custody.reference() == *reference)
                    .ok_or_else(|| {
                        Error::Catalog(Arc::from("resolved producer block lacks exact custody"))
                    })
            })
            .collect()
    }
}

impl<H, V, B> Clone for CustodyFetcher<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self::new(self.resolver.clone(), self.catalog.clone())
    }
}

impl<H: Hasher, V: Variant, B: Codec + Digestible<Digest = H::Digest>> Fetcher<H, V, B>
    for CustodyFetcher<H, V, B>
{
    type Error = Error;

    async fn lqc(
        &mut self,
        reason: FetchReason,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<V, H::Digest>>, Self::Error> {
        self.resolver.lqc(reason, id).await
    }

    async fn history(
        &mut self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> Result<HistorySegment<H::Digest>, Self::Error> {
        self.resolver.history(reason, view, commitment).await
    }

    async fn headers(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<HeaderSegment<H::Digest>, Self::Error> {
        self.resolver.headers(reason, reference).await
    }

    async fn block(
        &mut self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<FetchedBlock<H, B>, Self::Error> {
        let block = self.resolver.block(reason, reference).await?;
        if block.reference() != reference {
            return Err(Error::Catalog(Arc::from(
                "resolved producer block identity mismatch",
            )));
        }
        let span = info_span!(
            "multimmit.marshal.resolver.confirm_custody",
            reason = ?reason,
            chain = reference.chain().get(),
            height = reference.height().get(),
        );
        async {
            let custody = self
                .confirm_custody(&[reference])
                .await?
                .pop()
                .ok_or(Error::Invalid("custody response is empty"))?;
            Ok(FetchedBlock { custody, block })
        }
        .instrument(span)
        .await
    }

    async fn blocks(
        &mut self,
        reason: FetchReason,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<Vec<FetchedBlock<H, B>>, Self::Error> {
        let blocks = self.resolver.blocks(reason, references.clone()).await?;
        let returned = blocks
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        if returned.is_empty()
            || returned.len() > references.len()
            || !references
                .iter()
                .zip(&returned)
                .all(|(expected, actual)| expected == actual)
        {
            return Err(Error::Invalid(
                "resolved producer body range is not an exact prefix",
            ));
        }
        let custody = self.confirm_custody(&returned).await?;
        Ok(custody
            .into_iter()
            .zip(blocks.iter().cloned())
            .map(|(custody, block)| FetchedBlock { custody, block })
            .collect())
    }
}

struct Actor<
    E: Clock,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    R: Resolver<Key = Key<H::Digest>, Subscriber = Subscriber>,
    Q: LqcVerifier<H, V>,
> {
    clock: E,
    resolver: R,
    verifier: Q,
    config: Config<B::Cfg>,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    receiver: mailbox::Receiver<Command<H, V, B>>,
    _producer_guard: producer::Mailbox<H::Digest>,
    generation: Generation,
    pending: BTreeMap<u64, Request<H, V, B>>,
    /// Exact artifact identity to every bounded waiter for that artifact.
    pending_by_key: BTreeMap<Key<H::Digest>, BTreeSet<u64>>,
    /// Queued keys have no aborter; active reads belong to their remaining exact-key waiters.
    rechecking: BTreeMap<Key<H::Digest>, Option<Aborter>>,
    queued_rechecks: VecDeque<Key<H::Digest>>,
    rechecks: AbortablePool<'static, RecheckCompletion<H, V, B>>,
    admitting: BTreeSet<Key<H::Digest>>,
    queued_staging: VecDeque<StagingJob<H, B>>,
    queued_staging_bytes: u64,
    staging: Pool<'static, StagingCompletion<H, B>>,
    active_staging_bytes: u64,
    cancellations: Pool<'static, u64>,
    next_request: u64,
    max_pending: usize,
    max_rechecks: usize,
    max_staging: usize,
    #[cfg(test)]
    barriers: Vec<oneshot::Sender<()>>,
    metrics: metrics::Resolver,
}

impl<E, H, V, B, R, Q> Actor<E, H, V, B, R, Q>
where
    E: Clock,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    R: Resolver<Key = Key<H::Digest>, Subscriber = Subscriber>,
    Q: LqcVerifier<H, V>,
    B::Cfg: Send + 'static,
{
    fn retain_removed(&mut self, removed: BTreeSet<u64>) {
        if removed.is_empty() {
            return;
        }
        let generation = self.generation.clone();
        let _ = self.resolver.retain(move |_, subscriber| {
            subscriber.generation != generation || !removed.contains(&subscriber.request)
        });
    }

    fn prune_closed(&mut self) {
        let closed = self
            .pending
            .iter()
            .filter_map(|(request, pending)| pending.pending.closed().then_some(*request))
            .collect::<BTreeSet<_>>();
        for request in &closed {
            self.remove(*request);
        }
        self.retain_removed(closed);
    }

    fn remove(&mut self, request: u64) -> Option<Request<H, V, B>> {
        let pending = self.pending.remove(&request)?;
        let key = pending.pending.key();
        let requests = self
            .pending_by_key
            .get_mut(&key)
            .expect("every pending request is indexed");
        requests.remove(&request);
        if requests.is_empty() {
            self.pending_by_key.remove(&key);
            if let Some(None) = self.rechecking.remove(&key) {
                self.queued_rechecks.retain(|queued| *queued != key);
            }
        }
        Some(pending)
    }

    fn evict_certified(&mut self) -> bool {
        let Some(request) = self.pending.iter().find_map(|(request, pending)| {
            matches!(pending.pending, Pending::CertifiedBlock(_)).then_some(*request)
        }) else {
            return false;
        };
        self.remove(request).expect("request is active");
        self.retain_removed(BTreeSet::from([request]));
        true
    }

    fn active(&self, delivery: &Delivery<Key<H::Digest>, Subscriber>) -> bool {
        delivery.subscribers.iter().any(|(subscriber, _)| {
            subscriber.generation == self.generation
                && self
                    .pending
                    .get(&subscriber.request)
                    .is_some_and(|pending| pending.pending.key() == delivery.key)
        })
    }

    fn start_fetch(&mut self, request: u64) {
        let Some((key, reason, span)) = self.pending.get_mut(&request).and_then(|pending| {
            let reason = pending.fetch_reason()?;
            pending.fetching = true;
            Some((pending.pending.key(), reason, pending.span.clone()))
        }) else {
            return;
        };
        self.metrics.request(reason);
        if let Key::ProducerBlocks { max_items, .. } = key {
            self.metrics.range_requested(usize::from(max_items.get()));
        }
        tracing::debug!(?key, ?reason, request, "starting exact marshal fetch");
        let submit = info_span!(
            parent: &span,
            "multimmit.marshal.resolver.fetch.submit",
            reason = ?reason,
        );
        let feedback = submit.in_scope(|| {
            self.resolver.fetch(Fetch {
                key,
                subscriber: Subscriber {
                    generation: self.generation.clone(),
                    request,
                },
                span,
            })
        });
        if feedback != Feedback::Closed {
            return;
        }
        self.remove(request)
            .expect("registered request exists")
            .pending
            .fail(Error::ResolverClosed);
        self.retain_removed(BTreeSet::from([request]));
    }

    fn register(&mut self, span: Span, pending: Pending<H, V, B>, reason: FetchReason) {
        if pending.closed() {
            return;
        }
        let invalid_chain = match &pending {
            Pending::Block(reference, _, _)
            | Pending::Headers(reference, _)
            | Pending::CertifiedBlock(reference) => {
                reference.chain().get() as usize >= self.config.codec.chains()
            }
            Pending::Blocks(references, _) => references
                .iter()
                .any(|reference| reference.chain().get() as usize >= self.config.codec.chains()),
            Pending::Lqc(_, _) | Pending::History(_, _) => false,
        };
        if invalid_chain {
            pending.fail(Error::Invalid("producer chain is outside the epoch"));
            return;
        }
        if let Pending::Block(reference, _, _) = &pending {
            let key = pending.key();
            let certified = self.pending_by_key.get(&key).and_then(|requests| {
                requests.iter().copied().find(|request| {
                    matches!(self.pending.get(request), Some(Request { pending: Pending::CertifiedBlock(expected), .. }) if expected == reference)
                })
            });
            if let Some(request) = certified {
                let Pending::Block(reference, mode, reply) = pending else {
                    unreachable!("matched pending block")
                };
                let mode = match mode {
                    BlockMode::Wait => BlockMode::Subscribe,
                    BlockMode::Fetch | BlockMode::Subscribe => BlockMode::Fetch,
                };
                let pending =
                    Pending::Block(reference, mode, reply).track(request, &mut self.cancellations);
                self.pending.insert(
                    request,
                    Request {
                        span,
                        pending,
                        reason,
                        fetching: false,
                    },
                );
                if !self.rechecking.contains_key(&key) {
                    self.start_fetch(request);
                }
                return;
            }
        }
        if self.pending.len() >= self.max_pending {
            self.prune_closed();
            if self.pending.len() >= self.max_pending
                && !matches!(&pending, Pending::CertifiedBlock(_))
            {
                self.evict_certified();
            }
            if self.pending.len() >= self.max_pending
                && matches!(
                    reason,
                    FetchReason::Finality | FetchReason::FinalizedBody | FetchReason::StateSync
                )
            {
                // Synchronization concurrency is bounded by this registry. Preserve those durable
                // progress obligations by returning pressure to an independent request instead.
                let request = *self
                    .pending
                    .keys()
                    .next()
                    .expect("a saturated registry contains a request");
                self.remove(request)
                    .expect("selected request is active")
                    .pending
                    .fail(Error::PendingFull);
                self.retain_removed(BTreeSet::from([request]));
            }
            if self.pending.len() >= self.max_pending {
                pending.fail(Error::PendingFull);
                return;
            }
        }
        let request = self.next_request;
        let Some(next) = request.checked_add(1) else {
            pending.fail(Error::RequestExhausted);
            return;
        };
        self.next_request = next;
        let key = pending.key();
        let pending = pending.track(request, &mut self.cancellations);
        self.pending.insert(
            request,
            Request {
                span,
                pending,
                reason,
                fetching: false,
            },
        );
        self.pending_by_key.entry(key).or_default().insert(request);
        if let Entry::Vacant(entry) = self.rechecking.entry(key) {
            entry.insert(None);
            self.queued_rechecks.push_back(key);
        } else {
            self.metrics.local_recheck_coalesced.inc();
        }
    }

    fn certified_block(&mut self, reference: BlockRef<H::Digest>) {
        if reference.chain().get() as usize >= self.config.codec.chains() {
            return;
        }
        let key = Key::producer_block(reference.chain(), reference.digest());
        let requests = self
            .pending_by_key
            .get(&key)
            .into_iter()
            .flat_map(|requests| requests.iter())
            .copied()
            .collect::<Vec<_>>();
        let mut active = false;
        let mut promote = Vec::new();
        for request in requests {
            match self
                .pending
                .get_mut(&request)
                .map(|request| &mut request.pending)
            {
                Some(Pending::Block(expected, mode, _)) if *expected == reference => {
                    active = true;
                    if *mode == BlockMode::Wait {
                        *mode = BlockMode::Subscribe;
                        if !self.rechecking.contains_key(&key) {
                            promote.push(request);
                        }
                    }
                }
                Some(Pending::CertifiedBlock(expected)) if *expected == reference => {
                    active = true;
                }
                _ => {}
            }
        }
        for request in promote {
            self.start_fetch(request);
        }
        if !active && self.pending.len() < self.max_pending {
            self.register(
                Span::none(),
                Pending::CertifiedBlock(reference),
                FetchReason::Finality,
            );
        }
    }

    fn retire_certified(&mut self, frontiers: &[BlockRef<H::Digest>]) {
        let requests = self
            .pending
            .iter()
            .filter_map(|(request, pending)| match &pending.pending {
                Pending::CertifiedBlock(reference)
                    if frontiers.iter().any(|frontier| {
                        frontier.chain() == reference.chain()
                            && frontier.height() >= reference.height()
                    }) =>
                {
                    Some(*request)
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        for request in &requests {
            self.remove(*request).expect("request is active");
        }
        self.retain_removed(requests);
    }

    fn schedule_rechecks(&mut self) {
        while self.rechecks.len() < self.max_rechecks {
            let Some(key) = self.queued_rechecks.pop_front() else {
                break;
            };
            let mut requests = self
                .pending_by_key
                .get(&key)
                .expect("an active recheck has pending requests")
                .iter()
                .map(|request| {
                    self.pending
                        .get(request)
                        .expect("every indexed request is pending")
                });
            let first = requests
                .next()
                .expect("a pending request index is non-empty");
            let range_references = match &first.pending {
                Pending::Blocks(references, _) => Some(Arc::clone(references)),
                _ => None,
            };
            let recheck = info_span!(
                parent: &first.span,
                "multimmit.marshal.resolver.fetch.local_recheck",
                reason = ?first.reason,
            );
            for request in requests {
                recheck.follows_from(request.span.id());
            }
            let catalog = self.catalog.clone();
            let bodies = self.bodies.clone();
            let max_value_bytes = self.config.max_value_bytes.get();
            self.metrics.local_rechecks.inc();
            let aborter = self.rechecks.push(
                async move {
                    RecheckCompletion {
                        key,
                        result: local_artifact(
                            catalog,
                            bodies,
                            key,
                            range_references,
                            max_value_bytes,
                        )
                        .await,
                    }
                }
                .instrument(recheck),
            );
            *self.rechecking.get_mut(&key).expect("recheck is queued") = Some(aborter);
        }
    }

    fn complete_recheck(&mut self, completion: RecheckCompletion<H, V, B>) -> Result<(), Error> {
        if self.rechecking.remove(&completion.key).is_none() {
            return Err(Error::Invalid("completed local recheck is not active"));
        }
        if let Some(artifact) = completion.result? {
            self.complete(None, artifact);
            return Ok(());
        }
        self.metrics.local_misses.inc();
        let requests = self
            .pending_by_key
            .get(&completion.key)
            .into_iter()
            .flat_map(|requests| requests.iter())
            .copied()
            .collect::<Vec<_>>();
        for request in requests {
            self.start_fetch(request);
        }
        Ok(())
    }

    fn complete(
        &mut self,
        delivery: Option<&Delivery<Key<H::Digest>, Subscriber>>,
        artifact: Artifact<H, V, B>,
    ) -> bool {
        // An authenticated body also proves its header. Ancestry waiters need no additional
        // network response or durability fence to use that proof.
        let blocks = match &artifact {
            Artifact::Block(_, block) => slice::from_ref(block),
            Artifact::Blocks(_, blocks) => blocks.as_slice(),
            _ => &[],
        };
        for block in blocks {
            let reference = block.reference();
            if self
                .pending_by_key
                .contains_key(&Key::producer_headers(reference))
            {
                self.complete(
                    None,
                    Artifact::Headers(reference, Arc::new(vec![block.header().clone()])),
                );
            }
        }
        let key = artifact.key();
        let complete = delivery.is_none_or(|delivery| {
            delivery
                .subscribers
                .iter()
                .filter(|(subscriber, _)| subscriber.generation == self.generation)
                .all(|(subscriber, _)| {
                    self.pending
                        .get(&subscriber.request)
                        .is_none_or(|pending| pending.pending.accepts(&artifact))
                })
        });
        let requests = self
            .pending_by_key
            .get(&key)
            .into_iter()
            .flat_map(|requests| requests.iter())
            .copied()
            .filter(|request| self.pending[request].pending.accepts(&artifact))
            .collect::<BTreeSet<_>>();
        for request in &requests {
            self.remove(*request)
                .expect("request is active")
                .pending
                .succeed(&artifact);
        }
        self.retain_removed(requests);
        complete
    }

    fn complete_admitted_block(
        &mut self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) {
        self.complete(None, Artifact::Block(reference, Arc::clone(&block)));
        let ranges = self
            .pending_by_key
            .keys()
            .filter(|key| matches!(key, Key::ProducerBlocks { head, .. } if *head == reference))
            .copied()
            .collect::<Vec<_>>();
        let blocks = Arc::new(vec![block]);
        for key in ranges {
            self.complete(None, Artifact::Blocks(key, Arc::clone(&blocks)));
        }
    }

    async fn deliver(
        &mut self,
        delivery: Delivery<Key<H::Digest>, Subscriber>,
        value: Bytes,
    ) -> Result<Outcome, Error> {
        if !self.active(&delivery) {
            return Ok(Outcome::Ignored);
        }
        if value.len() > self.config.max_value_bytes.get() {
            return Ok(Outcome::Invalid);
        }
        let outcome = match delivery.key {
            Key::LqcById { id } => {
                let Ok(proof) = Lqc::<V, H::Digest>::decode_cfg(value, &self.config.codec) else {
                    return Ok(Outcome::Invalid);
                };
                if proof.epoch() != self.config.epoch
                    || proof.id::<H>() != id
                    || self.verifier.verify(&proof).await.is_err()
                {
                    return Ok(Outcome::Invalid);
                }
                let id = proof.id::<H>();
                let proof = Arc::new(proof);
                self.catalog
                    .admit_lqc(proof.view(), id, Arc::clone(&proof))
                    .await
                    .map_err(catalog_error)?;
                self.complete(Some(&delivery), Artifact::Lqc(id, proof))
            }
            Key::TipRecord { commitment } => {
                let Ok(records) = Vec::<TipRecord<H::Digest>>::decode_cfg(
                    value,
                    &(
                        RangeCfg::from(1..=MAX_SEGMENT_ITEMS),
                        self.config.codec.chains(),
                    ),
                ) else {
                    return Ok(Outcome::Invalid);
                };
                let Some(segment) = validate_history_segment::<H>(commitment, records) else {
                    return Ok(Outcome::Invalid);
                };
                self.complete(Some(&delivery), Artifact::History(commitment, segment))
            }
            Key::ProducerBlock { .. } => unreachable!("producer blocks are delivered in slices"),
            Key::ProducerBlocks { .. } => return Ok(Outcome::Invalid),
            Key::ProducerHeaders { head } => {
                let Ok(headers) = Vec::<TransactionBlockHeader<H::Digest>>::decode_cfg(
                    value,
                    &(RangeCfg::from(1..=MAX_SEGMENT_ITEMS), ()),
                ) else {
                    return Ok(Outcome::Invalid);
                };
                let Some(headers) = validate_header_segment::<H>(self.config.epoch, head, headers)
                else {
                    return Ok(Outcome::Invalid);
                };
                self.complete(Some(&delivery), Artifact::Headers(head, headers))
            }
        };
        Ok(if outcome {
            Outcome::Complete
        } else {
            Outcome::Ambiguous
        })
    }

    /// Validates ready block deliveries before queuing required bodies for catalog admission.
    fn deliver_blocks(&mut self, deliveries: Vec<BlockDelivery<H::Digest>>, process: Span) {
        let validate = info_span!(
            parent: &process,
            "multimmit.marshal.resolver.fetch.response.validate",
            received = deliveries.len(),
            valid = tracing::field::Empty,
            staged = tracing::field::Empty,
        );
        let validate_guard = validate.enter();
        let mut ready = Vec::with_capacity(deliveries.len());
        let mut staged = Vec::with_capacity(deliveries.len());
        let mut staged_keys = BTreeSet::new();
        let mut staged_bytes = 0u64;
        let mut valid = 0usize;
        for BlockDelivery {
            delivery,
            value,
            response,
        } in deliveries
        {
            if !self.active(&delivery) {
                self.respond(response, Outcome::Ignored);
                continue;
            }
            if value.len() > self.config.max_value_bytes.get() {
                self.respond(response, Outcome::Invalid);
                continue;
            }
            let encoded_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
            let Key::ProducerBlock { chain, digest } = delivery.key else {
                unreachable!("block delivery slice contains only producer blocks");
            };
            let Ok(block) = TransactionBlock::<H, B>::decode_cfg(value, &self.config.body) else {
                self.respond(response, Outcome::Invalid);
                continue;
            };
            let reference = block.reference();
            if block.encode_size() > self.config.max_block_bytes.get()
                || block.header().epoch() != self.config.epoch
                || reference.chain() != chain
                || reference.digest() != digest
            {
                self.respond(response, Outcome::Invalid);
                continue;
            }
            let block = Arc::new(block);
            let needs_temporary_custody = self
                .pending_by_key
                .get(&delivery.key)
                .into_iter()
                .flat_map(|requests| requests.iter())
                .any(
                    |request| match self.pending.get(request).map(|request| &request.pending) {
                        Some(Pending::Block(expected, BlockMode::Fetch, _))
                        | Some(Pending::CertifiedBlock(expected)) => *expected == reference,
                        _ => false,
                    },
                );
            if needs_temporary_custody {
                if self.admitting.contains(&delivery.key) {
                    self.respond(response, Outcome::Ignored);
                    continue;
                }
                if self.admitting.len() >= self.max_pending {
                    self.respond(response, Outcome::Ambiguous);
                    continue;
                }
                self.admitting.insert(delivery.key);
                staged_keys.insert(delivery.key);
                staged_bytes = staged_bytes.saturating_add(encoded_len);
                staged.push(Arc::clone(&block));
                ready.push(ReadyBlock {
                    delivery,
                    reference,
                    block,
                    response,
                });
            } else {
                self.complete_blocks(vec![ReadyBlock {
                    delivery,
                    reference,
                    block,
                    response,
                }]);
            }
            valid += 1;
        }
        validate.record("valid", valid);
        validate.record("staged", staged.len());
        drop(validate_guard);

        if staged.is_empty() {
            return;
        }
        let stage = response_stage_span(&process, staged.len(), staged_bytes);
        self.queue_staging(StagingJob {
            ready,
            ready_ranges: Vec::new(),
            staged,
            keys: staged_keys,
            bytes: staged_bytes,
            span: stage,
        });
    }

    fn deliver_range(
        &mut self,
        delivery: Delivery<Key<H::Digest>, Subscriber>,
        value: Bytes,
        response: DeliveryReply,
        process: Span,
    ) {
        if !self.active(&delivery) {
            self.respond(response, Outcome::Ignored);
            return;
        }
        if value.len() > self.config.max_value_bytes.get() {
            self.respond(response, Outcome::Invalid);
            return;
        }
        let key = delivery.key;
        let Key::ProducerBlocks { head, max_items } = key else {
            unreachable!("range delivery owns a producer-block range key");
        };
        let bytes = u64::try_from(value.len()).unwrap_or(u64::MAX);
        let Ok(blocks) = Vec::<TransactionBlock<H, B>>::decode_cfg(
            value,
            &(
                RangeCfg::from(1..=usize::from(max_items.get())),
                self.config.body.clone(),
            ),
        ) else {
            self.respond(response, Outcome::Invalid);
            return;
        };
        let Some(blocks) = validate_block_segment::<H, B>(self.config.epoch, head, blocks) else {
            self.respond(response, Outcome::Invalid);
            return;
        };
        if blocks
            .iter()
            .any(|block| block.encode_size() > self.config.max_block_bytes.get())
        {
            self.respond(response, Outcome::Invalid);
            return;
        }
        let artifact = Artifact::Blocks(key, Arc::clone(&blocks));
        let accepted = self
            .pending_by_key
            .get(&key)
            .into_iter()
            .flat_map(|requests| requests.iter())
            .any(|request| self.pending[request].pending.accepts(&artifact));
        if !accepted {
            self.respond(response, Outcome::Invalid);
            return;
        }
        if self.admitting.contains(&key) {
            self.respond(response, Outcome::Ignored);
            return;
        }
        if self.admitting.len() >= self.max_pending {
            self.respond(response, Outcome::Ambiguous);
            return;
        }
        self.metrics
            .range_received(usize::from(max_items.get()), blocks.len());
        self.admitting.insert(key);
        let staged = blocks.iter().cloned().collect::<Vec<_>>();
        let stage = response_stage_span(&process, staged.len(), bytes);
        self.queue_staging(StagingJob {
            ready: Vec::new(),
            ready_ranges: vec![ReadyRange {
                delivery,
                blocks,
                response,
            }],
            staged,
            keys: BTreeSet::from([key]),
            bytes,
            span: stage,
        });
    }

    fn queue_staging(&mut self, job: StagingJob<H, B>) {
        self.queued_staging_bytes = self.queued_staging_bytes.saturating_add(job.bytes);
        self.queued_staging.push_back(job);
    }

    fn complete_blocks(&mut self, ready: Vec<ReadyBlock<H, B>>) {
        for ReadyBlock {
            delivery,
            reference,
            block,
            response,
        } in ready
        {
            let outcome = if self.complete(Some(&delivery), Artifact::Block(reference, block)) {
                Outcome::Complete
            } else {
                Outcome::Ambiguous
            };
            self.respond(response, outcome);
        }
    }

    fn complete_ranges(&mut self, ready: Vec<ReadyRange<H, B>>) {
        for ReadyRange {
            delivery,
            blocks,
            response,
        } in ready
        {
            let key = delivery.key;
            let outcome = if self.complete(Some(&delivery), Artifact::Blocks(key, blocks)) {
                Outcome::Complete
            } else {
                Outcome::Ambiguous
            };
            self.respond(response, outcome);
        }
    }

    fn schedule_staging(&mut self) {
        while self.staging.len() < self.max_staging {
            let Some(job) = self.queued_staging.pop_front() else {
                break;
            };
            self.queued_staging_bytes = self
                .queued_staging_bytes
                .checked_sub(job.bytes)
                .expect("queued staging byte accounting underflow");
            self.active_staging_bytes = self.active_staging_bytes.saturating_add(job.bytes);
            let catalog = self.catalog.clone();
            let timer = self.metrics.staging_latency.timer(&self.clock);
            self.staging.push(
                async move {
                    let result = catalog
                        .stage_blocks(&job.staged)
                        .await
                        .map_err(catalog_error);
                    StagingCompletion {
                        ready: job.ready,
                        ready_ranges: job.ready_ranges,
                        keys: job.keys,
                        bytes: job.bytes,
                        timer,
                        result,
                    }
                }
                .instrument(job.span),
            );
        }
    }

    fn complete_staging(&mut self, completion: StagingCompletion<H, B>) -> Result<(), Error> {
        completion.timer.observe(&self.clock);
        self.active_staging_bytes = self
            .active_staging_bytes
            .checked_sub(completion.bytes)
            .ok_or(Error::Invalid("staging byte accounting underflow"))?;
        for key in completion.keys {
            if !self.admitting.remove(&key) {
                return Err(Error::Invalid("completed staging key is not active"));
            }
        }
        completion.result?;
        self.complete_blocks(completion.ready);
        self.complete_ranges(completion.ready_ranges);
        Ok(())
    }

    fn respond(&mut self, response: DeliveryReply, outcome: Outcome) {
        self.metrics.outcome(outcome);
        response.send(outcome);
    }

    #[cfg(test)]
    fn complete_barriers(&mut self) {
        if self.rechecking.is_empty() {
            for barrier in self.barriers.drain(..) {
                let _ = barrier.send(());
            }
        }
    }

    async fn run(mut self) -> Result<(), Error> {
        self.metrics.pending(0);
        let mut deferred = None;
        let mut commands_open = true;
        loop {
            self.schedule_rechecks();
            self.schedule_staging();
            self.metrics
                .rechecks(self.rechecks.len(), self.queued_rechecks.len());
            self.metrics.staging(
                self.staging.len(),
                self.active_staging_bytes,
                self.queued_staging.len(),
                self.queued_staging_bytes,
            );
            if !commands_open && self.queued_staging.is_empty() && self.staging.is_empty() {
                break;
            }
            let event = match deferred.take() {
                Some(command) => Event::Command(Some(command)),
                None => {
                    let command = async {
                        if commands_open {
                            self.receiver.recv().await
                        } else {
                            pending::<Option<Command<H, V, B>>>().await
                        }
                    };
                    select! {
                        completion = self.rechecks.next_completed() => Event::Recheck(completion.ok()),
                        completion = self.staging.next_completed() => Event::Staging(completion),
                        request = self.cancellations.next_completed() => Event::Canceled(request),
                        command = command => Event::Command(command),
                    }
                }
            };
            let command = match event {
                Event::Recheck(completion) => {
                    if let Some(completion) = completion {
                        self.complete_recheck(completion)?;
                    }
                    #[cfg(test)]
                    self.complete_barriers();
                    self.metrics.pending(self.pending.len());
                    continue;
                }
                Event::Staging(completion) => {
                    self.complete_staging(completion)?;
                    self.metrics.pending(self.pending.len());
                    continue;
                }
                Event::Canceled(request) => {
                    if let Some(pending) = self.remove(request)
                        && pending.fetching
                    {
                        self.retain_removed(BTreeSet::from([request]));
                    }
                    self.metrics.pending(self.pending.len());
                    continue;
                }
                Event::Command(Some(command)) => command,
                Event::Command(None) => {
                    commands_open = false;
                    continue;
                }
            };
            match command {
                #[cfg(test)]
                Command::Barrier(reply) => {
                    if self.rechecking.is_empty() {
                        let _ = reply.send(());
                    } else {
                        self.barriers.push(reply);
                    }
                }
                Command::Deliver(span, delivery, value, response)
                    if matches!(&delivery.key, Key::ProducerBlock { .. }) =>
                {
                    let mut deliveries = vec![(
                        span,
                        BlockDelivery {
                            delivery,
                            value,
                            response,
                        },
                    )];
                    while deliveries.len() < self.max_pending {
                        match self.receiver.try_recv() {
                            Ok(Command::Deliver(span, delivery, value, response))
                                if matches!(&delivery.key, Key::ProducerBlock { .. }) =>
                            {
                                deliveries.push((
                                    span,
                                    BlockDelivery {
                                        delivery,
                                        value,
                                        response,
                                    },
                                ));
                            }
                            Ok(command) => {
                                deferred = Some(command);
                                break;
                            }
                            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
                        }
                    }
                    let process = response_process_span(&deliveries[0].0, deliveries.len());
                    for (cause, _) in deliveries.iter().skip(1) {
                        process.follows_from(cause.id());
                    }
                    let deliveries = deliveries
                        .into_iter()
                        .map(|(_, delivery)| delivery)
                        .collect();
                    self.deliver_blocks(deliveries, process);
                }
                Command::Deliver(span, delivery, value, response)
                    if matches!(&delivery.key, Key::ProducerBlocks { .. }) =>
                {
                    let process = response_process_span(&span, 1);
                    drop(span);
                    self.deliver_range(delivery, value, response, process);
                }
                Command::Deliver(span, delivery, value, response) => {
                    let process = response_process_span(&span, 1);
                    drop(span);
                    let outcome = self.deliver(delivery, value).instrument(process).await?;
                    self.respond(response, outcome);
                }
                Command::Fetch(span, pending, reason) => {
                    let process = info_span!(
                        parent: &span,
                        "multimmit.marshal.resolver.process",
                        reason = ?reason,
                    );
                    let fetch = info_span!(
                        parent: &process,
                        "multimmit.marshal.resolver.fetch",
                        reason = ?reason,
                    );
                    process.in_scope(|| self.register(fetch, pending, reason));
                }
                Command::CertifiedBlock(reference) => {
                    self.certified_block(reference);
                }
                Command::RetireCertified(frontiers, reply) => {
                    self.retire_certified(&frontiers);
                    drop(reply.send(Ok(())));
                }
                Command::AdmittedBlock(reference, block, response) => {
                    if block.reference() != reference || block.header().epoch() != self.config.epoch
                    {
                        drop(response.send(Err(Error::Catalog(Arc::from(
                            "admitted block identity mismatch",
                        )))));
                    } else {
                        self.complete_admitted_block(reference, block);
                        drop(response.send(Ok(())));
                    }
                }
                Command::AdmittedHistory(commitment, record, response) => {
                    if record.commitment::<H>() != commitment {
                        drop(response.send(Err(Error::Catalog(Arc::from(
                            "admitted history identity mismatch",
                        )))));
                    } else {
                        self.complete(None, Artifact::History(commitment, Arc::new(vec![record])));
                        drop(response.send(Ok(())));
                    }
                }
            }
            self.metrics.pending(self.pending.len());
        }
        Ok(())
    }
}

/// Opens an endpoint and starts exact fetch completion.
#[allow(clippy::too_many_arguments)]
pub(in crate::multimmit::marshal) fn spawn<E, R, Q, H, V, B>(
    context: E,
    endpoint: Endpoint<H, V, B>,
    resolver: R,
    verifier: Q,
    config: Config<B::Cfg>,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    max_pending: NonZeroUsize,
    max_active_serves: NonZeroUsize,
) -> (Client<H, V, B>, Handle<Result<(), Error>>)
where
    E: Clock + Spawner + RuntimeMetrics,
    R: Resolver<Key = Key<H::Digest>, Subscriber = Subscriber>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    B::Cfg: Send + 'static,
{
    let client = Client {
        commands: endpoint.commands,
    };
    let producer_handle = producer::spawn(
        context.child("producer"),
        endpoint.producer,
        catalog.clone(),
        bodies.clone(),
        config.max_block_bytes,
        config.max_value_bytes,
        max_pending,
        max_active_serves,
    );
    let metrics = metrics::Resolver::new(&context);
    let actor = Actor {
        clock: context.child("adapter"),
        resolver,
        verifier,
        config,
        catalog,
        bodies,
        receiver: endpoint.receiver,
        _producer_guard: endpoint.producer_guard,
        generation: endpoint.generation,
        pending: BTreeMap::new(),
        pending_by_key: BTreeMap::new(),
        rechecking: BTreeMap::new(),
        queued_rechecks: VecDeque::new(),
        rechecks: AbortablePool::default(),
        admitting: BTreeSet::new(),
        queued_staging: VecDeque::new(),
        queued_staging_bytes: 0,
        staging: Pool::default(),
        active_staging_bytes: 0,
        cancellations: Pool::default(),
        next_request: 0,
        max_pending: max_pending.get(),
        max_rechecks: max_active_serves.get(),
        max_staging: max_active_serves.get(),
        #[cfg(test)]
        barriers: Vec::new(),
        metrics,
    };
    let mut actor_handle = context
        .child("adapter")
        .shared(false)
        .spawn(move |_| actor.run());
    let mut producer_handle = producer_handle;
    let handle = context
        .child("supervisor")
        .shared(false)
        .spawn(move |_| async move {
            select! {
                result = &mut actor_handle => {
                    let result = result
                        .map_err(|error| Error::Child(Arc::from(error.to_string())))
                        .and_then(|result| result);
                    if result.is_err() {
                        producer_handle.abort();
                        return result;
                    }
                    (&mut producer_handle)
                        .await
                        .map_err(|error| Error::Child(Arc::from(error.to_string())))
                        .and_then(|result| {
                            result.map_err(|error| Error::Child(Arc::from(error.to_string())))
                        })
                },
                result = &mut producer_handle => {
                    let result = result
                        .map_err(|error| Error::Child(Arc::from(error.to_string())))
                        .and_then(|result| {
                            result.map_err(|error| Error::Child(Arc::from(error.to_string())))
                        });
                    if result.is_err() {
                        actor_handle.abort();
                        return result;
                    }
                    (&mut actor_handle)
                        .await
                        .map_err(|error| Error::Child(Arc::from(error.to_string())))
                        .and_then(|result| result)
                },
            }
        });
    (client, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::{
            config::Limits,
            marshal::{
                actors::{catalog, delivery, promoter},
                config::{ArchiveConfig, ArchiveMode, Config as MarshalConfig, Start},
            },
            mocks::Committee,
            types::{ChainId, TipRecord, genesis_history},
        },
        types::Height,
    };
    use bytes::BytesMut;
    use commonware_codec::Encode;
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{
            DelayedReadContext, DelayedSyncContext, PendingReads, PendingSyncs,
            release_next_pending_syncs,
        },
    };
    use commonware_storage::{Context as StorageContext, translator::TwoCap};
    use commonware_utils::{NZU16, NZUsize, sync::Mutex, vec::NonEmptyVec};
    use futures::future::Either;
    use rstest::rstest;
    use std::{
        num::{NonZeroU32, NonZeroU64},
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tracing::{Subscriber as TracingSubscriber, span};
    use tracing_subscriber::{
        Layer, filter::filter_fn, layer::Context as LayerContext, prelude::*, registry::LookupSpan,
    };

    type TestBody = EmptyBlock<Sha256>;

    #[derive(Default)]
    struct RecordedTrace {
        spans: Vec<(&'static str, Option<&'static str>)>,
        ambient_links: usize,
    }

    #[derive(Clone, Default)]
    struct Traces(Arc<Mutex<RecordedTrace>>);

    impl<S: TracingSubscriber + for<'a> LookupSpan<'a>> Layer<S> for Traces {
        fn on_new_span(
            &self,
            attrs: &span::Attributes<'_>,
            id: &span::Id,
            ctx: LayerContext<'_, S>,
        ) {
            let parent = ctx
                .span(id)
                .unwrap()
                .parent()
                .map(|parent| parent.metadata().name());
            self.0.lock().spans.push((attrs.metadata().name(), parent));
        }

        fn on_follows_from(&self, id: &span::Id, _: &span::Id, ctx: LayerContext<'_, S>) {
            if ctx.span(id).unwrap().metadata().name() == "filter_ambient" {
                self.0.lock().ambient_links += 1;
            }
        }
    }

    #[rstest]
    #[case(true, true)]
    #[case(false, true)]
    #[case(true, false)]
    #[case(false, false)]
    fn filtered_response_spans_do_not_capture_ambient(#[case] process: bool, #[case] stage: bool) {
        const PROCESS: &str = "multimmit.marshal.resolver.fetch.response.process";
        const STAGE: &str = "multimmit.marshal.resolver.fetch.response.stage";
        const ADMIT: &str = "multimmit.marshal.catalog.stage_blocks";
        let traces = Traces::default();
        let subscriber = tracing_subscriber::registry()
            .with(traces.clone())
            .with(filter_fn(move |metadata| {
                (process || metadata.name() != PROCESS) && (stage || metadata.name() != STAGE)
            }));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("filter_ambient")
                .in_scope(fetched_block_deliveries_share_one_catalog_admission_cut);
        });
        let recorded = traces.0.lock();
        assert_eq!(
            recorded.ambient_links, 0,
            "disabled processing must not link the ambient span"
        );
        let stages = recorded
            .spans
            .iter()
            .filter(|(name, _)| *name == STAGE)
            .collect::<Vec<_>>();
        assert_eq!(stages.len(), usize::from(stage));
        if stage {
            assert_eq!(stages[0].1, process.then_some(PROCESS));
        }
        let admissions = recorded
            .spans
            .iter()
            .filter(|(name, _)| *name == ADMIT)
            .collect::<Vec<_>>();
        assert_eq!(admissions.len(), 1);
        assert_eq!(
            admissions[0].1,
            Some(if stage { STAGE } else { "filter_ambient" }),
            "catalog admission must not retain a disabled staging span's ambient context"
        );
    }
    type TestActor = (
        Bridge<Sha256, MinPk, TestBody>,
        Client<Sha256, MinPk, TestBody>,
        CatalogClient<Sha256, MinPk, TestBody>,
        Generation,
        delivery::DeliveryReceiver<Sha256, TestBody>,
        Handle<Result<(), Error>>,
        Handle<Result<(), catalog::Error>>,
    );

    #[derive(Clone, Copy)]
    struct NoopResolver;

    impl Resolver for NoopResolver {
        type Key = Key<Sha256Digest>;
        type Subscriber = Subscriber;

        fn fetch<F>(&mut self, _: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct CountingResolver {
        fetches: Arc<AtomicUsize>,
        feedback: Feedback,
    }

    impl Resolver for CountingResolver {
        type Key = Key<Sha256Digest>;
        type Subscriber = Subscriber;

        fn fetch<F>(&mut self, _: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.fetches.fetch_add(1, Ordering::Relaxed);
            self.feedback
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.fetches.fetch_add(fetches.len(), Ordering::Relaxed);
            self.feedback
        }

        fn retain(
            &mut self,
            _: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    struct AcceptVerifier;

    impl LqcVerifier<Sha256, MinPk> for AcceptVerifier {
        type Error = &'static str;

        async fn verify(&mut self, _: &Lqc<MinPk, Sha256Digest>) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn subscriber(generation: &Generation, request: u64) -> Subscriber {
        Subscriber {
            generation: generation.clone(),
            request,
        }
    }

    fn keyed_delivery(
        key: Key<Sha256Digest>,
        subscriber: Subscriber,
    ) -> Delivery<Key<Sha256Digest>, Subscriber> {
        Delivery {
            key,
            subscribers: NonEmptyVec::new((subscriber, tracing::Span::none())),
        }
    }

    fn delivery(subscriber: Subscriber) -> Delivery<Key<Sha256Digest>, Subscriber> {
        keyed_delivery(Key::tip_record(Sha256::hash(&[b"history"])), subscriber)
    }

    fn producer_chain(
        committee: &Committee<MinPk>,
        count: usize,
    ) -> Vec<Arc<TransactionBlock<Sha256, TestBody>>> {
        let mut parent = committee.config.genesis().tips()[0].digest();
        (1..=count)
            .map(|height| {
                let height = Height::new(height as u64);
                let body = TestBody::new(
                    Sha256::hash(&[b"range application parent"]),
                    height,
                    height.get(),
                );
                let header = TransactionBlockHeader::new(
                    committee.config.epoch(),
                    ChainId::new(0),
                    height,
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

    async fn open_test_actor<R>(
        context: &deterministic::Context,
        committee: &Committee<MinPk>,
        partition: &str,
        label: &'static str,
        max_value_bytes: NonZeroUsize,
        resolver: R,
        max_pending: NonZeroUsize,
    ) -> TestActor
    where
        R: Resolver<Key = Key<Sha256Digest>, Subscriber = Subscriber>,
    {
        open_test_actor_with_catalog(
            context,
            context.child("catalog"),
            committee,
            partition,
            label,
            max_value_bytes,
            resolver,
            max_pending,
            max_pending,
            NonZeroUsize::MAX,
            NZUsize!(1024),
        )
        .await
    }

    fn catalog_config(
        context: &deterministic::Context,
        committee: &Committee<MinPk>,
        partition: &str,
    ) -> MarshalConfig<TwoCap, MinPk, TestBody> {
        let archive = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        );
        let mut catalog_config = MarshalConfig::new(
            committee.config.epoch(),
            NonZeroU32::new(committee.codec().chains() as u32).unwrap(),
            Start::Genesis(committee.config.genesis().clone()),
            partition.into(),
            committee.codec(),
            (),
            archive,
        )
        .unwrap();
        catalog_config.finalized_blocks = ArchiveMode::Prunable;
        catalog_config
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_test_actor_with_catalog<R, E>(
        context: &deterministic::Context,
        catalog_context: E,
        committee: &Committee<MinPk>,
        partition: &str,
        label: &'static str,
        max_value_bytes: NonZeroUsize,
        resolver: R,
        max_pending: NonZeroUsize,
        max_active_serves: NonZeroUsize,
        max_hot_block_bytes: NonZeroUsize,
        catalog_mailbox_size: NonZeroUsize,
    ) -> TestActor
    where
        R: Resolver<Key = Key<Sha256Digest>, Subscriber = Subscriber>,
        E: StorageContext + Spawner,
    {
        let mut catalog_config = catalog_config(context, committee, partition);
        catalog_config.max_hot_block_bytes = max_hot_block_bytes;
        catalog_config.catalog_mailbox_size = catalog_mailbox_size;
        catalog_config.admission_cut_capacity = catalog_mailbox_size;
        catalog_config.pending_segment_items =
            NonZeroU64::new(catalog_mailbox_size.get() as u64).unwrap();
        let (delivery, delivery_commands) = delivery::channel(context.child("delivery"));
        let (catalog, catalog_handle, promoter, _, _) = catalog_config
            .spawn::<_, Sha256>(catalog_context, delivery)
            .await
            .unwrap();
        let bodies = promoter::Bodies::new(catalog.clone(), promoter);
        let (bridge, endpoint) = channel::<Sha256, MinPk, TestBody>(
            context.child("resolver_mailbox"),
            context.child("producer_mailbox"),
            NZUsize!(16),
        );
        let generation = endpoint.generation.clone();
        let (client, resolver_handle) = spawn(
            context.child(label),
            endpoint,
            resolver,
            AcceptVerifier,
            Config::new(
                committee.config.epoch(),
                committee.codec(),
                (),
                NZUsize!(112),
                max_value_bytes,
            ),
            catalog.clone(),
            bodies,
            max_pending,
            max_active_serves,
        );
        (
            bridge,
            client,
            catalog,
            generation,
            delivery_commands,
            resolver_handle,
            catalog_handle,
        )
    }

    #[test]
    fn compact_segments_require_exact_linked_ancestry() {
        let committee = Committee::<MinPk>::new(41, 6, Limits::new(1, 0).unwrap());
        let tips = committee.config.genesis().tips().to_vec();
        let oldest = TipRecord::at_tips(Sha256::hash(&[b"history floor"]), tips.clone()).unwrap();
        let newest = TipRecord::at_tips(oldest.commitment::<Sha256>(), tips).unwrap();
        let head = newest.commitment::<Sha256>();
        assert!(validate_history_segment::<Sha256>(head, vec![newest.clone(), oldest]).is_some());
        assert!(validate_history_segment::<Sha256>(head, vec![newest.clone(), newest]).is_none());

        let epoch = committee.config.epoch();
        let first = TransactionBlockHeader::new(
            epoch,
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"block floor"]),
            Sha256::hash(&[b"body 1"]),
        )
        .unwrap();
        let second = TransactionBlockHeader::new(
            epoch,
            ChainId::new(0),
            Height::new(2),
            first.digest::<Sha256>(),
            Sha256::hash(&[b"body 2"]),
        )
        .unwrap();
        let head = second.block_ref::<Sha256>();
        assert!(
            validate_header_segment::<Sha256>(epoch, head, vec![second.clone(), first]).is_some()
        );
        assert!(
            validate_header_segment::<Sha256>(epoch, head, vec![second.clone(), second]).is_none()
        );
    }

    #[test]
    fn producer_caps_consecutive_body_ranges_to_response_budget() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(52, 6, Limits::new(2, 1).unwrap());
            let blocks = producer_chain(&committee, 4);
            assert!(blocks.iter().all(|block| block.encode_size() <= 112));
            let (mut bridge, client, catalog, _, _, resolver_handle, catalog_handle) =
                open_test_actor(
                    &context,
                    &committee,
                    "producer_body_range_test",
                    "resolver",
                    NonZeroUsize::new(3 * 112 + 3usize.encode_size()).unwrap(),
                    NoopResolver,
                    NZUsize!(16),
                )
                .await;
            for block in &blocks {
                catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            let head = blocks.last().unwrap().reference();
            let value = bridge
                .produce(Key::producer_blocks(head, NonZeroU16::new(4).unwrap()))
                .await
                .unwrap();
            let decoded = Vec::<TransactionBlock<Sha256, TestBody>>::decode_cfg(
                value,
                &(RangeCfg::from(1..=4), ()),
            )
            .unwrap();
            assert_eq!(
                decoded
                    .iter()
                    .map(TransactionBlock::reference)
                    .collect::<Vec<_>>(),
                blocks
                    .iter()
                    .rev()
                    .take(3)
                    .map(|block| block.reference())
                    .collect::<Vec<_>>()
            );

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn oversized_peer_blocks_are_invalid_without_stopping_the_actor() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(55, 6, Limits::new(2, 1).unwrap());
            let height = Height::new(u64::MAX);
            let body = TestBody::new(
                Sha256::hash(&[b"oversized application parent"]),
                height,
                u64::MAX,
            );
            let header = TransactionBlockHeader::new(
                committee.config.epoch(),
                ChainId::new(0),
                height,
                committee.config.genesis().tips()[0].digest(),
                body.digest(),
            )
            .unwrap();
            let block = Arc::new(TransactionBlock::<Sha256, _>::new(header, body).unwrap());
            assert!(block.encode_size() > 112);
            let (mut bridge, client, catalog, generation, _, resolver_handle, catalog_handle) =
                open_test_actor(
                    &context,
                    &committee,
                    "oversized_peer_block_test",
                    "resolver",
                    NZUsize!(1024 * 1024),
                    NoopResolver,
                    NZUsize!(16),
                )
                .await;

            let reference = block.reference();
            let (reply, scalar) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(reference, BlockMode::Fetch, reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_block(reference.chain(), reference.digest()),
                            subscriber(&generation, 0),
                        ),
                        block.encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Invalid
            );

            let (reply, range) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::new(vec![reference]), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_blocks(reference, NonZeroU16::new(1).unwrap()),
                            subscriber(&generation, 1),
                        ),
                        vec![block].encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Invalid
            );
            client.retire_certified(Vec::new()).await.unwrap();

            drop(scalar);
            drop(range);
            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn body_range_rechecks_local_custody_and_accepts_late_admission() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(56, 6, Limits::new(2, 1).unwrap());
            let blocks = producer_chain(&committee, 2);
            let (_, client, catalog, _, _, resolver_handle, catalog_handle) = open_test_actor(
                &context,
                &committee,
                "local_body_range_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
            )
            .await;

            catalog
                .admit_block(blocks[1].reference(), Arc::clone(&blocks[1]))
                .await
                .unwrap();
            let (reply, local) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(
                            Arc::new(vec![blocks[1].reference(), blocks[0].reference()]),
                            reply,
                        ),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            let local = local.await.unwrap().unwrap();
            assert_eq!(local.len(), 1);
            assert_eq!(local[0].reference(), blocks[1].reference());

            let (reply, late) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::new(vec![blocks[0].reference()]), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            client.barrier().await;
            catalog
                .admit_block(blocks[0].reference(), Arc::clone(&blocks[0]))
                .await
                .unwrap();
            client
                .admitted_block(blocks[0].reference(), Arc::clone(&blocks[0]))
                .await
                .unwrap();
            let late = late.await.unwrap().unwrap();
            assert_eq!(late.len(), 1);
            assert_eq!(late[0].reference(), blocks[0].reference());

            drop(client);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn header_fetch_accepts_late_durable_body_admission() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = Committee::<MinPk>::new(57, 6, Limits::new(2, 1).unwrap());
            let blocks = producer_chain(&committee, 2);
            let head = blocks[1].reference();
            let fetches = Arc::new(AtomicUsize::new(0));
            let (_, client, catalog, _, _, resolver_handle, catalog_handle) = open_test_actor(
                &context,
                &committee,
                "late_header_body_admission_test",
                "resolver",
                NZUsize!(1024 * 1024),
                CountingResolver {
                    fetches: Arc::clone(&fetches),
                    feedback: Feedback::Ok,
                },
                NZUsize!(16),
            )
            .await;
            catalog
                .admit_block(blocks[0].reference(), Arc::clone(&blocks[0]))
                .await
                .unwrap();

            let (reply, headers) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Headers(head, reply),
                        FetchReason::Finality,
                    ))
                    .accepted()
            );
            client.barrier().await;
            assert_eq!(fetches.load(Ordering::Relaxed), 1);

            catalog
                .admit_block(head, Arc::clone(&blocks[1]))
                .await
                .unwrap();
            let custody = catalog.wait_for_custody(vec![head]).await.unwrap();
            assert_eq!(custody[0].as_ref().unwrap().reference(), head);
            client
                .admitted_block(head, Arc::clone(&blocks[1]))
                .await
                .unwrap();

            let headers = select! {
                result = headers => result.unwrap().unwrap(),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("locally durable body did not complete its pending header fetch")
                },
            };
            assert_eq!(headers.first(), Some(blocks[1].header()));
            assert!(
                validate_header_segment::<Sha256>(
                    committee.config.epoch(),
                    head,
                    headers.as_ref().clone(),
                )
                .is_some()
            );
            assert_eq!(fetches.load(Ordering::Relaxed), 1);

            drop(client);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn peer_bodies_complete_only_exact_header_fetches() {
        for range in [false, true] {
            deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
                let committee = Committee::<MinPk>::new(58, 6, Limits::new(2, 1).unwrap());
                let blocks = producer_chain(&committee, 3);
                let expected = blocks
                    .iter()
                    .rev()
                    .take(if range { 2 } else { 1 })
                    .cloned()
                    .collect::<Vec<_>>();
                let references = expected
                    .iter()
                    .map(|block| block.reference())
                    .collect::<Vec<_>>();
                let head = references[0];
                let other = BlockRef::new(
                    head.chain(),
                    head.height(),
                    Sha256::hash(&[b"different producer header"]),
                );
                let fetches = Arc::new(AtomicUsize::new(0));
                let (mut bridge, client, catalog, generation, _, resolver_handle, catalog_handle) =
                    open_test_actor(
                        &context,
                        &committee,
                        "peer_body_header_completion_test",
                        "resolver",
                        NZUsize!(1024 * 1024),
                        CountingResolver {
                            fetches: Arc::clone(&fetches),
                            feedback: Feedback::Ok,
                        },
                        NZUsize!(16),
                    )
                    .await;

                let mut headers = Vec::new();
                for reference in references.iter().copied().chain([other]) {
                    let (reply, receiver) = oneshot::channel();
                    assert!(
                        client
                            .commands
                            .enqueue(Command::Fetch(
                                Span::none(),
                                Pending::Headers(reference, reply),
                                FetchReason::Finality,
                            ))
                            .accepted()
                    );
                    headers.push(receiver);
                }
                let body_request = headers.len() as u64;
                let (pending, response, key, value) = if range {
                    let (reply, receiver) = oneshot::channel();
                    (
                        Pending::Blocks(Arc::new(references.clone()), reply),
                        Either::Left(receiver),
                        Key::producer_blocks(head, NonZeroU16::new(2).unwrap()),
                        expected.encode(),
                    )
                } else {
                    let (reply, receiver) = oneshot::channel();
                    (
                        Pending::Block(head, BlockMode::Fetch, reply),
                        Either::Right(receiver),
                        Key::producer_block(head.chain(), head.digest()),
                        expected[0].encode(),
                    )
                };
                assert!(
                    client
                        .commands
                        .enqueue(Command::Fetch(Span::none(), pending, FetchReason::FinalizedBody))
                        .accepted()
                );
                client.barrier().await;
                assert_eq!(fetches.load(Ordering::Relaxed), headers.len() + 1);
                assert_eq!(
                    bridge
                        .deliver(keyed_delivery(key, subscriber(&generation, body_request)), value)
                        .await
                        .unwrap(),
                    Outcome::Complete
                );
                let received = match response {
                    Either::Left(response) => response.await.unwrap().unwrap().as_ref().clone(),
                    Either::Right(response) => vec![response.await.unwrap().unwrap()],
                };
                assert_eq!(received, expected);

                let mut unmatched = headers.pop().unwrap();
                for (receiver, block) in headers.into_iter().zip(&expected) {
                    let headers = select! {
                        result = receiver => result.unwrap().unwrap(),
                        _ = context.sleep(Duration::from_millis(100)) => {
                            panic!("peer body did not complete its pending header fetch (range={range})")
                        },
                    };
                    assert_eq!(headers.first(), Some(block.header()));
                    assert!(
                        validate_header_segment::<Sha256>(
                            committee.config.epoch(),
                            block.reference(),
                            headers.as_ref().clone(),
                        )
                        .is_some()
                    );
                }
                select! {
                    result = &mut unmatched => {
                        panic!("peer body completed a different header head: {result:?}")
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {},
                }
                drop(unmatched);
                drop(client);
                drop(bridge);
                drop(catalog);
                assert!(resolver_handle.await.is_ok());
                assert!(catalog_handle.await.is_ok());
            });
        }
    }

    #[test]
    fn body_range_delivery_requires_an_exact_prefix_and_stages_once() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(53, 6, Limits::new(2, 1).unwrap());
            let blocks = producer_chain(&committee, 3);
            let references = blocks
                .iter()
                .rev()
                .map(|block| block.reference())
                .collect::<Vec<_>>();
            let key = Key::producer_blocks(references[0], NonZeroU16::new(3).unwrap());
            let (mut bridge, client, catalog, generation, _, resolver_handle, catalog_handle) =
                open_test_actor(
                    &context,
                    &committee,
                    "consumer_body_range_test",
                    "resolver",
                    NZUsize!(1024 * 1024),
                    NoopResolver,
                    NZUsize!(16),
                )
                .await;
            let (reply, receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::new(references.clone()), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            client.barrier().await;

            let malformed = vec![Arc::clone(&blocks[1]), Arc::clone(&blocks[0])].encode();
            assert_eq!(
                bridge
                    .deliver(keyed_delivery(key, subscriber(&generation, 0)), malformed,)
                    .await
                    .unwrap(),
                Outcome::Invalid
            );

            let prefix = vec![Arc::clone(&blocks[2]), Arc::clone(&blocks[1])];
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(key, subscriber(&generation, 0)),
                        prefix.encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            let resolved = receiver.await.unwrap().unwrap();
            assert_eq!(resolved.len(), 2);
            assert_eq!(resolved[0].reference(), references[0]);
            assert_eq!(resolved[1].reference(), references[1]);
            assert!(
                catalog
                    .wait_for_custody(references[..2].to_vec())
                    .await
                    .unwrap()
                    .into_iter()
                    .all(|custody| custody.is_some())
            );
            let metrics = context.encode();
            assert!(metrics.contains("range_requests_total 1"));
            assert!(metrics.contains("range_requested_blocks_total 3"));
            assert!(metrics.contains("range_received_blocks_total 2"));
            assert!(metrics.contains("range_short_responses_total 1"));

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn blocked_range_staging_does_not_stall_resolver_commands() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(54, 6, Limits::new(2, 1).unwrap());
            let blocks = producer_chain(&committee, 5);
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                delayed.child("catalog"),
                &committee,
                "blocked_range_staging_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(2),
                NZUsize!(1),
                NonZeroUsize::MAX,
                NZUsize!(1),
            )
            .await;

            syncs.arm();
            let first = catalog.stage_block(Arc::clone(&blocks[0])).await.unwrap();
            catalog.progress().await.unwrap();
            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            let first_cut_syncs = syncs.calls();
            assert!(first_cut_syncs > 0, "first custody cut did not start");
            let second = catalog.stage_block(Arc::clone(&blocks[1])).await.unwrap();

            let reference = blocks[2].reference();
            let references = Arc::new(vec![reference]);
            let (reply, receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::clone(&references), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            client.barrier().await;
            let key = Key::producer_blocks(reference, NonZeroU16::new(1).unwrap());
            let mut delivery = Box::pin(bridge.deliver(
                keyed_delivery(key, subscriber(&generation, 0)),
                vec![Arc::clone(&blocks[2])].encode(),
            ));
            commonware_macros::select! {
                result = &mut delivery => panic!("range staging crossed a full trailing cut: {result:?}"),
                _ = context.sleep(Duration::from_millis(1)) => {},
            }

            commonware_macros::select! {
                result = client.retire_certified(Vec::new()) => result.unwrap(),
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("blocked range staging stalled an independent resolver command")
                },
            }

            let next = blocks[3].reference();
            let (reply, next_receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::new(vec![next]), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            client.retire_certified(Vec::new()).await.unwrap();
            let next_bytes = vec![Arc::clone(&blocks[3])].encode();
            let mut next_delivery = Box::pin(bridge.deliver(
                keyed_delivery(
                    Key::producer_blocks(next, NonZeroU16::new(1).unwrap()),
                    subscriber(&generation, 1),
                ),
                next_bytes.clone(),
            ));
            client.retire_certified(Vec::new()).await.unwrap();
            commonware_macros::select! {
                result = &mut next_delivery => panic!("queued range staging completed early: {result:?}"),
                _ = context.sleep(Duration::from_millis(1)) => {},
            }
            let metrics = context.encode();
            assert!(metrics.contains("staging_active 1"), "{metrics}");
            assert!(metrics.contains("staging_queued 1"), "{metrics}");
            assert!(
                metrics.contains(&format!("staging_queued_bytes {}", next_bytes.len())),
                "{metrics}"
            );
            drop(receiver);
            drop(next_receiver);

            let overflow = blocks[4].reference();
            let (reply, overflow_receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Blocks(Arc::new(vec![overflow]), reply),
                        FetchReason::FinalizedBody,
                    ))
                    .accepted()
            );
            client.retire_certified(Vec::new()).await.unwrap();
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_blocks(overflow, NonZeroU16::new(1).unwrap()),
                            subscriber(&generation, 2),
                        ),
                        vec![Arc::clone(&blocks[4])].encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Ambiguous
            );
            drop(overflow_receiver);

            drop(client);
            drop(bridge);
            commonware_macros::select! {
                result = &mut delivery => {
                    panic!("producer shutdown aborted accepted range staging: {result:?}")
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }
            release_next_pending_syncs(&syncs, first_cut_syncs);
            assert_eq!(delivery.await.unwrap(), Outcome::Complete);
            syncs.unblock();
            assert_eq!(next_delivery.await.unwrap(), Outcome::Complete);
            first.wait().await.unwrap();
            second.wait().await.unwrap();

            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn consumer_overflow_is_ambiguous_and_closure_is_ignored() {
        deterministic::Runner::default().start(|context| async move {
            let (mut bridge, endpoint) = channel::<Sha256, MinPk, TestBody>(
                context.child("resolver_mailbox"),
                context.child("producer_mailbox"),
                NZUsize!(1),
            );
            let generation = endpoint.generation.clone();
            assert!(
                bridge
                    .commands
                    .enqueue(Command::CertifiedBlock(BlockRef::new(
                        ChainId::new(0),
                        Height::new(1),
                        Sha256::hash(&[b"occupied"]),
                    )))
                    .accepted()
            );
            let outcome = bridge.deliver(delivery(subscriber(&generation, 0)), Bytes::new());
            assert_eq!(outcome.await.unwrap(), Outcome::Ambiguous);

            drop(endpoint);
            let outcome = bridge.deliver(delivery(subscriber(&generation, 1)), Bytes::new());
            assert_eq!(outcome.await.unwrap(), Outcome::Ignored);
        });
    }

    #[test]
    fn overflow_discards_canceled_exact_fetches() {
        let (first_reply, first_receiver) = oneshot::channel();
        let first: Command<Sha256, MinPk, TestBody> = Command::Fetch(
            Span::none(),
            Pending::Lqc(
                CertificateId::new(Sha256::hash(&[b"canceled overflow fetch"])),
                first_reply,
            ),
            FetchReason::Explicit,
        );
        let mut overflow = VecDeque::new();
        <Command<Sha256, MinPk, TestBody> as Policy>::handle(&mut overflow, first);
        assert_eq!(overflow.len(), 1);
        drop(first_receiver);

        let (second_reply, second_receiver) = oneshot::channel();
        let second: Command<Sha256, MinPk, TestBody> = Command::Fetch(
            Span::none(),
            Pending::Lqc(
                CertificateId::new(Sha256::hash(&[b"already canceled overflow fetch"])),
                second_reply,
            ),
            FetchReason::Explicit,
        );
        drop(second_receiver);
        <Command<Sha256, MinPk, TestBody> as Policy>::handle(&mut overflow, second);

        assert!(overflow.is_empty());
    }

    #[test]
    fn generation_identity_is_not_reused() {
        deterministic::Runner::default().start(|context| async move {
            let (_, first) = channel::<Sha256, MinPk, TestBody>(
                context.child("first"),
                context.child("first_producer"),
                NZUsize!(1),
            );
            let (_, second) = channel::<Sha256, MinPk, TestBody>(
                context.child("second"),
                context.child("second_producer"),
                NZUsize!(1),
            );
            assert!(first.generation != second.generation);
        });
    }

    #[test]
    fn canceled_waiters_are_reclaimed_at_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let catalog_config = catalog_config(&context, &committee, "resolver_capacity_test");
            let (delivery, _delivery_commands) = delivery::channel(context.child("delivery"));
            let (catalog, catalog_handle, promoter, _, _) = catalog_config
                .spawn::<_, Sha256>(context.child("catalog"), delivery)
                .await
                .unwrap();
            let bodies = promoter::Bodies::new(catalog.clone(), promoter);

            let (_bridge, endpoint) = channel::<Sha256, MinPk, TestBody>(
                context.child("resolver_mailbox"),
                context.child("producer_mailbox"),
                NZUsize!(8),
            );
            let (client, resolver_handle) = spawn(
                context.child("resolver"),
                endpoint,
                NoopResolver,
                AcceptVerifier,
                Config::new(
                    committee.config.epoch(),
                    committee.codec(),
                    (),
                    NZUsize!(1024),
                    NZUsize!(1024),
                ),
                catalog,
                bodies,
                NZUsize!(2),
                NZUsize!(2),
            );

            let mut canceled = Vec::new();
            for commitment in [
                Sha256::hash(&[b"canceled 0"]),
                Sha256::hash(&[b"canceled 1"]),
            ] {
                let (reply, receiver) = oneshot::channel();
                assert!(
                    client
                        .commands
                        .enqueue(Command::Fetch(
                            Span::none(),
                            Pending::History(commitment, reply),
                            FetchReason::Finality,
                        ))
                        .accepted()
                );
                canceled.push(receiver);
            }
            client.barrier().await;
            drop(canceled);

            let commitment = Sha256::hash(&[b"active"]);
            let (reply, mut active) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::History(commitment, reply),
                        FetchReason::Finality,
                    ))
                    .accepted()
            );
            client.barrier().await;

            assert!(matches!(
                active.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            resolver_handle.abort();
            catalog_handle.abort();
            let _ = resolver_handle.await;
            let _ = catalog_handle.await;
        });
    }

    #[test]
    fn finality_fetch_has_capacity_under_explicit_pressure() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let (_bridge, client, _, _, _, resolver_handle, catalog_handle) = open_test_actor(
                &context,
                &committee,
                "resolver_finality_capacity_test",
                "resolver",
                NZUsize!(1024),
                NoopResolver,
                NZUsize!(1),
            )
            .await;

            let (explicit_reply, _explicit) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::History(Sha256::hash(&[b"explicit pressure"]), explicit_reply,),
                        FetchReason::Explicit,
                    ))
                    .accepted()
            );
            client.barrier().await;

            let (finality_reply, mut finality) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::History(Sha256::hash(&[b"finality"]), finality_reply,),
                        FetchReason::Finality,
                    ))
                    .accepted()
            );
            client.barrier().await;
            assert!(matches!(
                finality.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            resolver_handle.abort();
            catalog_handle.abort();
            let _ = resolver_handle.await;
            let _ = catalog_handle.await;
        });
    }

    #[test]
    fn local_custody_completes_before_peer_fetch() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let catalog_config = catalog_config(&context, &committee, "resolver_local_first_test");
            let (delivery, _delivery_commands) = delivery::channel(context.child("delivery"));
            let (catalog, catalog_handle, promoter, _, _) = catalog_config
                .spawn::<_, Sha256>(context.child("catalog"), delivery)
                .await
                .unwrap();
            let bodies = promoter::Bodies::new(catalog.clone(), promoter);
            let parent = Arc::new(
                TipRecord::at_tips(
                    genesis_history::<Sha256>(committee.config.genesis()),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let record = Arc::new(
                TipRecord::at_tips(
                    parent.commitment::<Sha256>(),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            catalog
                .admit_history(
                    View::new(1),
                    parent.commitment::<Sha256>(),
                    Arc::clone(&parent),
                )
                .await
                .unwrap();
            catalog
                .admit_history(View::new(2), commitment, record.clone())
                .await
                .unwrap();

            let fetches = Arc::new(AtomicUsize::new(0));
            let (bridge, endpoint) = channel::<Sha256, MinPk, TestBody>(
                context.child("resolver_mailbox"),
                context.child("producer_mailbox"),
                NZUsize!(8),
            );
            let (client, resolver_handle) = spawn(
                context.child("resolver"),
                endpoint,
                CountingResolver {
                    fetches: fetches.clone(),
                    feedback: Feedback::Closed,
                },
                AcceptVerifier,
                Config::new(
                    committee.config.epoch(),
                    committee.codec(),
                    (),
                    NZUsize!(1024),
                    NZUsize!(1024),
                ),
                catalog,
                bodies,
                NZUsize!(8),
                NZUsize!(8),
            );

            let segment = client
                .history(FetchReason::Finality, View::new(1), commitment)
                .await
                .unwrap();
            assert_eq!(segment.as_slice(), &[record]);
            assert_eq!(fetches.load(Ordering::Relaxed), 0);

            let invalid = BlockRef::new(
                ChainId::new(committee.codec().chains() as u32),
                Height::new(1),
                Sha256::hash(&[b"invalid producer chain"]),
            );
            assert!(matches!(
                client.block(FetchReason::Explicit, invalid).await,
                Err(Error::Invalid("producer chain is outside the epoch"))
            ));
            assert_eq!(fetches.load(Ordering::Relaxed), 0);

            drop(client);
            drop(bridge);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn certified_blocks_fetch_only_for_live_authorized_waiters() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let fetches = Arc::new(AtomicUsize::new(0));
            let (bridge, client, catalog, _, _delivery_commands, resolver_handle, catalog_handle) =
                open_test_actor(
                    &context,
                    &committee,
                    "resolver_certified_floor_test",
                    "resolver",
                    NZUsize!(1024),
                    CountingResolver {
                        fetches: fetches.clone(),
                        feedback: Feedback::Ok,
                    },
                    NZUsize!(4),
                )
                .await;
            let first = BlockRef::new(
                ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"first certified block"]),
            );
            let second = BlockRef::new(
                ChainId::new(0),
                Height::new(2),
                Sha256::hash(&[b"second certified block"]),
            );

            assert!(client.certified_block(first).accepted());
            assert!(client.certified_block(second).accepted());
            client.barrier().await;
            assert_eq!(fetches.load(Ordering::Relaxed), 0);

            client.retire_certified(vec![first]).await.unwrap();
            let (retired_reply, mut retired_receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(first, BlockMode::Wait, retired_reply),
                        FetchReason::CertifiedSubscription,
                    ))
                    .accepted()
            );
            let (authorized_reply, mut authorized_receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(second, BlockMode::Wait, authorized_reply),
                        FetchReason::CertifiedSubscription,
                    ))
                    .accepted()
            );
            client.barrier().await;
            assert!(matches!(
                retired_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                authorized_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(fetches.load(Ordering::Relaxed), 1);
            assert!(
                context
                    .encode()
                    .contains("requests_started_total{reason=\"CertifiedSubscription\"} 1")
            );

            let explicit = BlockRef::new(
                ChainId::new(1),
                Height::new(3),
                Sha256::hash(&[b"explicit certified block"]),
            );
            assert!(client.certified_block(explicit).accepted());
            client.barrier().await;
            let (explicit_reply, explicit_receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(explicit, BlockMode::Fetch, explicit_reply,),
                        FetchReason::Explicit,
                    ))
                    .accepted()
            );
            client.barrier().await;
            assert_eq!(fetches.load(Ordering::Relaxed), 2);
            assert!(
                context
                    .encode()
                    .contains("requests_started_total{reason=\"Explicit\"} 1")
            );

            drop(retired_receiver);
            drop(authorized_receiver);
            drop(explicit_receiver);
            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn deliver_enforces_the_exact_value_byte_bound() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let record = Arc::new(
                TipRecord::at_tips(
                    genesis_history::<Sha256>(committee.config.genesis()),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let commitment = record.commitment::<Sha256>();
            let encoded = vec![record.as_ref().clone()].encode();
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor(
                &context,
                &committee,
                "resolver_value_bound_test",
                "resolver",
                NonZeroUsize::new(encoded.len()).unwrap(),
                NoopResolver,
                NZUsize!(16),
            )
            .await;
            let (reply, mut receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::History(commitment, reply),
                        FetchReason::Finality,
                    ))
                    .accepted()
            );
            client.barrier().await;

            let mut oversized = BytesMut::from(encoded.as_ref());
            oversized.extend_from_slice(&[0]);
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(Key::tip_record(commitment), subscriber(&generation, 0),),
                        oversized.freeze(),
                    )
                    .await
                    .unwrap(),
                Outcome::Invalid
            );
            assert!(matches!(
                receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(catalog.history(commitment).await.unwrap().is_none());

            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(Key::tip_record(commitment), subscriber(&generation, 0),),
                        encoded,
                    )
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(receiver.await.unwrap().unwrap().as_slice(), &[record]);
            assert!(catalog.history(commitment).await.unwrap().is_none());

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn deliver_rejects_malformed_and_wrong_identity_values() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
            let proof = Arc::new(committee.lqc(3));
            let wrong_proof = committee.lqc(4);
            let id = proof.id::<Sha256>();
            let record = Arc::new(
                TipRecord::at_tips(
                    genesis_history::<Sha256>(committee.config.genesis()),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let wrong_record = TipRecord::at_tips(
                Sha256::hash(&[b"wrong history parent"]),
                committee.config.genesis().tips().to_vec(),
            )
            .unwrap();
            let commitment = record.commitment::<Sha256>();
            let body = TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), 10);
            let block = Arc::new(
                TransactionBlock::<Sha256, _>::new(
                    committee.transaction_header(0, body.digest()),
                    body,
                )
                .unwrap(),
            );
            let reference = block.reference();
            let wrong_height = BlockRef::new(
                reference.chain(),
                reference.height().next(),
                reference.digest(),
            );
            let wrong_body =
                TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), 11);
            let wrong_block = TransactionBlock::<Sha256, _>::new(
                committee.transaction_header(0, wrong_body.digest()),
                wrong_body,
            )
            .unwrap();
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor(
                &context,
                &committee,
                "resolver_adversarial_delivery_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
            )
            .await;
            let (lqc_reply, mut lqc_receiver) = oneshot::channel();
            let (history_reply, mut history_receiver) = oneshot::channel();
            let (block_reply, mut block_receiver) = oneshot::channel();
            let (wrong_height_reply, mut wrong_height_receiver) = oneshot::channel();
            for pending in [
                Pending::Lqc(id, lqc_reply),
                Pending::History(commitment, history_reply),
                Pending::Block(reference, BlockMode::Fetch, block_reply),
            ] {
                assert!(
                    client
                        .commands
                        .enqueue(Command::Fetch(Span::none(), pending, FetchReason::Explicit,))
                        .accepted()
                );
            }
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(wrong_height, BlockMode::Fetch, wrong_height_reply,),
                        FetchReason::Explicit,
                    ))
                    .accepted()
            );
            client.barrier().await;

            let values = [
                proof.encode(),
                vec![record.as_ref().clone()].encode(),
                block.encode(),
            ];
            let keys = [
                Key::lqc_by_id(id),
                Key::tip_record(commitment),
                Key::producer_block(reference.chain(), reference.digest()),
            ];
            for (request, (key, value)) in keys.into_iter().zip(values).enumerate() {
                let truncated = value.slice(..value.len() - 1);
                let mut trailing = BytesMut::from(value.as_ref());
                trailing.extend_from_slice(&[0]);
                for malformed in [truncated, trailing.freeze()] {
                    assert_eq!(
                        bridge
                            .deliver(
                                keyed_delivery(key, subscriber(&generation, request as u64),),
                                malformed,
                            )
                            .await
                            .unwrap(),
                        Outcome::Invalid
                    );
                }
            }

            for (request, (key, value)) in [
                (Key::lqc_by_id(id), wrong_proof.encode()),
                (
                    Key::tip_record(commitment),
                    vec![wrong_record.clone()].encode(),
                ),
                (
                    Key::producer_block(reference.chain(), reference.digest()),
                    wrong_block.encode(),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    bridge
                        .deliver(
                            keyed_delivery(key, subscriber(&generation, request as u64)),
                            value,
                        )
                        .await
                        .unwrap(),
                    Outcome::Invalid
                );
            }
            assert!(matches!(
                lqc_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                history_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                block_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(catalog.lqc(id).await.unwrap().is_none());
            assert!(catalog.history(commitment).await.unwrap().is_none());
            assert!(catalog.block(reference).await.unwrap().is_none());
            assert!(
                catalog
                    .lqc(wrong_proof.id::<Sha256>())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                catalog
                    .history(wrong_record.commitment::<Sha256>())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                catalog
                    .block(wrong_block.reference())
                    .await
                    .unwrap()
                    .is_none()
            );

            for (request, (key, value)) in [
                (Key::lqc_by_id(id), proof.encode()),
                (
                    Key::tip_record(commitment),
                    vec![record.as_ref().clone()].encode(),
                ),
                (
                    Key::producer_block(reference.chain(), reference.digest()),
                    block.encode(),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(
                    bridge
                        .deliver(
                            keyed_delivery(key, subscriber(&generation, request as u64)),
                            value,
                        )
                        .await
                        .unwrap(),
                    Outcome::Complete
                );
            }
            assert_eq!(lqc_receiver.await.unwrap().unwrap(), proof);
            assert_eq!(
                history_receiver.await.unwrap().unwrap().as_slice(),
                &[record]
            );
            assert_eq!(block_receiver.await.unwrap().unwrap(), block);
            assert!(matches!(
                wrong_height_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_block(reference.chain(), reference.digest()),
                            subscriber(&generation, 3),
                        ),
                        block.encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Ambiguous
            );
            assert!(matches!(
                wrong_height_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(catalog.block(wrong_height).await.unwrap().is_none());

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn subscribed_fetch_defers_custody_to_the_service() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(9, 6, Limits::new(2, 1).unwrap());
            let body = TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), 12);
            let block = Arc::new(
                TransactionBlock::<Sha256, _>::new(
                    committee.transaction_header(0, body.digest()),
                    body,
                )
                .unwrap(),
            );
            let reference = block.reference();
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor(
                &context,
                &committee,
                "resolver_subscription_custody_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
            )
            .await;
            let (reply, receiver) = oneshot::channel();
            assert!(
                client
                    .commands
                    .enqueue(Command::Fetch(
                        Span::none(),
                        Pending::Block(reference, BlockMode::Wait, reply),
                        FetchReason::CertifiedSubscription,
                    ))
                    .accepted()
            );
            assert!(client.certified_block(reference).accepted());
            client.barrier().await;
            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_block(reference.chain(), reference.digest()),
                            subscriber(&generation, 0),
                        ),
                        block.encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(receiver.await.unwrap().unwrap(), block);
            assert!(catalog.block(reference).await.unwrap().is_none());

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn blocked_producer_key_does_not_stall_independent_serves() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(47, 6, Limits::new(2, 1).unwrap());
            let blocks: [Arc<TransactionBlock<Sha256, TestBody>>; 3] =
                std::array::from_fn(|index| {
                let chain = [0, 1, 0][index];
                let body = TestBody::new(
                    Sha256::hash(&[b"application parent"]),
                    Height::new(1),
                    47 + index as u64,
                );
                Arc::new(
                    TransactionBlock::<Sha256, _>::new(
                        committee.transaction_header(chain, body.digest()),
                        body,
                    )
                    .unwrap(),
                )
            });
            let history_parent = genesis_history::<Sha256>(committee.config.genesis());
            let history = Arc::new(
                TipRecord::at_tips(history_parent, committee.config.genesis().tips().to_vec()).unwrap(),
            );
            let history_commitment = history.commitment::<Sha256>();
            let partition = "resolver_concurrent_produce_test";
            let (
                initial_bridge,
                initial_client,
                initial_catalog,
                _generation,
                _delivery_commands,
                initial_resolver_handle,
                initial_catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                context.child("initial_catalog"),
                &committee,
                partition,
                "initial_resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
                NZUsize!(16),
                NZUsize!(1),
                NZUsize!(2),
            )
            .await;
            for block in &blocks {
                initial_catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            initial_catalog
                .admit_history(View::new(1), history_commitment, Arc::clone(&history))
                .await
                .unwrap();
            drop(initial_client);
            drop(initial_bridge);
            drop(initial_catalog);
            assert!(initial_resolver_handle.await.is_ok());
            assert!(initial_catalog_handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("reopened_catalog"),
                pending: reads.clone(),
            };
            let (
                mut bridge,
                client,
                catalog,
                _generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                delayed,
                &committee,
                partition,
                "reopened_resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
                NZUsize!(16),
                NZUsize!(1),
                NZUsize!(2),
            )
            .await;

            let gate = reads.arm();
            let mut first = Box::pin(bridge.produce(Key::producer_block(
                blocks[0].reference().chain(),
                blocks[0].reference().digest(),
            )));
            commonware_macros::select! {
                result = &mut first => panic!("first producer read completed before its gate: {result:?}"),
                blocked = gate.blocked => blocked.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first producer read never reached storage"),
            }
            let duplicate = bridge.produce(Key::producer_block(
                blocks[0].reference().chain(),
                blocks[0].reference().digest(),
            ));
            let second = bridge.produce(Key::tip_record(history_commitment));
            let second = commonware_macros::select! {
                result = second => result,
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("a blocked producer key stalled an independent serve")
                },
            };
            assert_eq!(second.unwrap(), vec![history.as_ref().clone()].encode());

            drop(client);
            drop(bridge);
            let mut resolver_handle = Box::pin(resolver_handle);
            commonware_macros::select! {
                result = &mut resolver_handle => {
                    panic!("clean shutdown aborted an accepted producer read: {result:?}")
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }
            let _ = gate.release.send(());
            assert_eq!(first.await.unwrap(), blocks[0].encode());
            let duplicate = commonware_macros::select! {
                result = duplicate => result,
                _ = context.sleep(Duration::from_secs(1)) => {
                    panic!("an exact duplicate started a second storage read")
                },
            };
            assert_eq!(duplicate.unwrap(), blocks[0].encode());

            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn admitted_producer_request_waits_for_actor_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(51, 6, Limits::new(2, 1).unwrap());
            let blocks: [Arc<TransactionBlock<Sha256, TestBody>>; 3] =
                std::array::from_fn(|index| {
                    let body = TestBody::new(
                        Sha256::hash(&[b"application parent"]),
                        Height::new(1),
                        51 + index as u64,
                    );
                    Arc::new(
                        TransactionBlock::<Sha256, _>::new(
                            committee.transaction_header(index as u32, body.digest()),
                            body,
                        )
                        .unwrap(),
                    )
                });
            let block = &blocks[0];
            let history = Arc::new(
                TipRecord::at_tips(
                    genesis_history::<Sha256>(committee.config.genesis()),
                    committee.config.genesis().tips().to_vec(),
                )
                .unwrap(),
            );
            let history_commitment = history.commitment::<Sha256>();
            let partition = "resolver_producer_admission_test";
            let (
                initial_bridge,
                initial_client,
                initial_catalog,
                _,
                _,
                initial_resolver_handle,
                initial_catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                context.child("initial_catalog"),
                &committee,
                partition,
                "initial_resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(1),
                NZUsize!(1),
                NZUsize!(1),
                NZUsize!(2),
            )
            .await;
            for block in &blocks {
                initial_catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            initial_catalog
                .admit_history(View::new(1), history_commitment, Arc::clone(&history))
                .await
                .unwrap();
            drop(initial_client);
            drop(initial_bridge);
            drop(initial_catalog);
            assert!(initial_resolver_handle.await.is_ok());
            assert!(initial_catalog_handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("reopened_catalog"),
                pending: reads.clone(),
            };
            let (
                mut bridge,
                client,
                catalog,
                _,
                _,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                delayed,
                &committee,
                partition,
                "reopened_resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(1),
                NZUsize!(1),
                NZUsize!(1),
                NZUsize!(2),
            )
            .await;

            let gate = reads.arm();
            let mut first = Box::pin(
                bridge
                    .try_produce(Key::producer_block(
                        block.reference().chain(),
                        block.reference().digest(),
                    ))
                    .expect("the first request fits the producer mailbox"),
            );
            commonware_macros::select! {
                result = &mut first => panic!("first producer read completed before its gate: {result:?}"),
                result = gate.blocked => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("first producer read never reached storage"),
            }

            let mut second = Box::pin(
                bridge
                    .try_produce(Key::tip_record(history_commitment))
                    .expect("the second request fits the producer mailbox"),
            );
            commonware_macros::select! {
                result = &mut second => panic!("admitted producer request was rejected internally: {result:?}"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }

            gate.release.send(()).unwrap();
            assert_eq!(first.await.unwrap(), block.encode());
            assert_eq!(second.await.unwrap(), vec![history.as_ref().clone()].encode());

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[rstest]
    #[case::spare_slot(false, false)]
    #[case::completed_locally(true, false)]
    #[case::canceled(false, true)]
    fn blocked_local_recheck_does_not_stall_independent_fetch(
        #[case] complete_locally: bool,
        #[case] cancel_locally: bool,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(49, 6, Limits::new(2, 1).unwrap());
            let blocks: [Arc<TransactionBlock<Sha256, TestBody>>; 3] =
                std::array::from_fn(|index| {
                    let body = TestBody::new(
                        Sha256::hash(&[b"application parent"]),
                        Height::new(1),
                        49 + index as u64,
                    );
                    Arc::new(
                        TransactionBlock::<Sha256, _>::new(
                            committee.transaction_header(index as u32, body.digest()),
                            body,
                        )
                        .unwrap(),
                    )
                });
            let partition = "resolver_concurrent_recheck_test";
            let (
                initial_bridge,
                initial_client,
                initial_catalog,
                _,
                _,
                initial_resolver_handle,
                initial_catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                context.child("initial_catalog"),
                &committee,
                partition,
                "initial_resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
                NZUsize!(16),
                NZUsize!(1),
                NZUsize!(2),
            )
            .await;
            for block in &blocks {
                initial_catalog
                    .admit_block(block.reference(), Arc::clone(block))
                    .await
                    .unwrap();
            }
            drop(initial_client);
            drop(initial_bridge);
            drop(initial_catalog);
            assert!(initial_resolver_handle.await.is_ok());
            assert!(initial_catalog_handle.await.is_ok());

            let reads = PendingReads::default();
            let delayed = DelayedReadContext {
                inner: context.child("reopened_catalog"),
                pending: reads.clone(),
            };
            let fetches = Arc::new(AtomicUsize::new(0));
            let (bridge, client, catalog, _, _, resolver_handle, catalog_handle) =
                open_test_actor_with_catalog(
                    &context,
                    delayed,
                    &committee,
                    partition,
                    "reopened_resolver",
                    NZUsize!(1024 * 1024),
                    CountingResolver {
                        fetches: Arc::clone(&fetches),
                        feedback: Feedback::Closed,
                    },
                    NZUsize!(16),
                    NonZeroUsize::new(if complete_locally || cancel_locally { 1 } else { 16 })
                        .unwrap(),
                    NZUsize!(1),
                    NZUsize!(2),
                )
                .await;

            let gate = reads.arm();
            let mut local = Box::pin(client.block(FetchReason::Explicit, blocks[0].reference()));
            commonware_macros::select! {
                result = &mut local => panic!("local block completed before its storage gate: {result:?}"),
                blocked = gate.blocked => blocked.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("local recheck never reached storage"),
            }

            let mut shared = Box::pin(client.block(FetchReason::Explicit, blocks[0].reference()));
            commonware_macros::select! {
                result = &mut shared => panic!("shared recheck completed before its storage gate: {result:?}"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }
            drop(shared);
            commonware_macros::select! {
                result = &mut local => panic!("canceling one caller completed another: {result:?}"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }

            let missing = BlockRef::new(
                ChainId::new(1),
                Height::new(1),
                Sha256::hash(&[b"independent missing block"]),
            );
            if complete_locally || cancel_locally {
                let mut queued = Box::pin(client.block(FetchReason::Explicit, missing));
                commonware_macros::select! {
                    result = &mut queued => panic!("queued recheck bypassed the occupied slot: {result:?}"),
                    _ = context.sleep(Duration::from_millis(10)) => {},
                }
                let metrics = context.encode();
                assert!(metrics.contains("reopened_resolver_local_rechecks_queued 1"), "{metrics}");
                drop(queued);
                context.sleep(Duration::from_millis(10)).await;
                let metrics = context.encode();
                assert!(metrics.contains("reopened_resolver_local_rechecks_queued 0"), "{metrics}");
            }

            if complete_locally {
                client
                    .admitted_block(blocks[0].reference(), Arc::clone(&blocks[0]))
                    .await
                    .unwrap();
                assert_eq!((&mut local).await.unwrap(), blocks[0]);
            }
            let mut local = if cancel_locally {
                drop(local);
                None
            } else {
                Some(local)
            };

            let independent = commonware_macros::select! {
                result = client.block(FetchReason::Explicit, missing) => result,
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("a blocked local recheck stalled an independent fetch")
                },
            };
            assert!(matches!(independent, Err(Error::ResolverClosed)));
            assert_eq!(fetches.load(Ordering::Relaxed), 1);

            let _ = gate.release.send(());
            if !complete_locally && let Some(local) = local.as_mut() {
                assert_eq!(local.await.unwrap(), blocks[0]);
            }
            drop(local);
            assert_eq!(fetches.load(Ordering::Relaxed), 1);

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn late_custody_waiter_stages_shared_delivery() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(10, 6, Limits::new(2, 1).unwrap());
            let body = TestBody::new(Sha256::hash(&[b"application parent"]), Height::new(1), 13);
            let block = Arc::new(
                TransactionBlock::<Sha256, _>::new(
                    committee.transaction_header(0, body.digest()),
                    body,
                )
                .unwrap(),
            );
            let reference = block.reference();
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor(
                &context,
                &committee,
                "resolver_late_custody_waiter_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
            )
            .await;
            let (subscription_reply, subscription) = oneshot::channel();
            let (fetch_reply, fetch) = oneshot::channel();
            for pending in [
                Pending::Block(reference, BlockMode::Subscribe, subscription_reply),
                Pending::Block(reference, BlockMode::Fetch, fetch_reply),
            ] {
                assert!(
                    client
                        .commands
                        .enqueue(Command::Fetch(Span::none(), pending, FetchReason::Explicit,))
                        .accepted()
                );
            }
            client.barrier().await;

            assert_eq!(
                bridge
                    .deliver(
                        keyed_delivery(
                            Key::producer_block(reference.chain(), reference.digest()),
                            subscriber(&generation, 0),
                        ),
                        block.encode(),
                    )
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(subscription.await.unwrap().unwrap(), block);
            assert_eq!(fetch.await.unwrap().unwrap(), block);
            assert_eq!(
                catalog.block(reference).await.unwrap().as_deref(),
                Some(block.as_ref())
            );

            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn fetched_block_deliveries_share_one_catalog_admission_cut() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::new(43, 6, Limits::new(2, 1).unwrap());
            let blocks = [0, 1].map(|chain| {
                let body = TestBody::new(
                    Sha256::hash(&[b"application parent"]),
                    Height::new(1),
                    u64::from(chain),
                );
                Arc::new(
                    TransactionBlock::<Sha256, _>::new(
                        committee.transaction_header(chain, body.digest()),
                        body,
                    )
                    .unwrap(),
                )
            });
            let syncs = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: syncs.clone(),
            };
            let (
                mut bridge,
                client,
                catalog,
                generation,
                _delivery_commands,
                resolver_handle,
                catalog_handle,
            ) = open_test_actor_with_catalog(
                &context,
                delayed.child("catalog"),
                &committee,
                "resolver_block_slice_test",
                "resolver",
                NZUsize!(1024 * 1024),
                NoopResolver,
                NZUsize!(16),
                NZUsize!(16),
                NonZeroUsize::MAX,
                NZUsize!(1024),
            )
            .await;
            let mut _block_receivers = Vec::new();
            for block in &blocks {
                let (reply, receiver) = oneshot::channel();
                assert!(
                    client
                        .commands
                        .enqueue(Command::Fetch(
                            Span::none(),
                            Pending::Block(block.reference(), BlockMode::Fetch, reply,),
                            FetchReason::FinalizedBody,
                        ))
                        .accepted()
                );
                _block_receivers.push(receiver);
            }
            client.barrier().await;

            syncs.arm();
            let first = bridge.deliver(
                keyed_delivery(
                    Key::producer_block(
                        blocks[0].reference().chain(),
                        blocks[0].reference().digest(),
                    ),
                    subscriber(&generation, 0),
                ),
                blocks[0].encode(),
            );
            let second = bridge.deliver(
                keyed_delivery(
                    Key::producer_block(
                        blocks[1].reference().chain(),
                        blocks[1].reference().digest(),
                    ),
                    subscriber(&generation, 1),
                ),
                blocks[1].encode(),
            );
            let (first, second) = futures::join!(first, second);
            assert_eq!(first.unwrap(), Outcome::Complete);
            assert_eq!(second.unwrap(), Outcome::Complete);

            for _ in 0..100 {
                if syncs.calls() > 0 {
                    break;
                }
                context.sleep(std::time::Duration::from_millis(1)).await;
            }
            let cut_syncs = syncs.calls();
            assert!(cut_syncs > 0, "block slice did not start durability");
            release_next_pending_syncs(&syncs, cut_syncs);

            let references = blocks.iter().map(|block| block.reference()).collect();
            let durable = commonware_macros::select! {
                result = catalog.wait_for_custody(references) => result.unwrap(),
                _ = context.sleep(std::time::Duration::from_millis(100)) => {
                    panic!("block slice did not become durable after one admission cut")
                },
            };
            assert_eq!(
                syncs.calls(),
                cut_syncs,
                "fetched blocks were split across durability cuts"
            );
            assert!(durable.into_iter().all(|value| value.is_some()));

            syncs.unblock();
            drop(client);
            drop(bridge);
            drop(catalog);
            assert!(resolver_handle.await.is_ok());
            assert!(catalog_handle.await.is_ok());
        });
    }

    #[test]
    fn exact_identity_and_ambiguity_are_distinct() {
        let committee = Committee::<MinPk>::new(7, 6, Limits::new(2, 1).unwrap());
        let proof = committee.lqc(3);
        let received = proof.id::<Sha256>();
        let other = committee.lqc(4).id::<Sha256>();
        assert_ne!(received, other);
        assert_eq!(proof.epoch(), committee.config.epoch());
        assert_eq!(
            Lqc::<MinPk, Sha256Digest>::decode_cfg(proof.encode(), &committee.codec())
                .unwrap()
                .id::<Sha256>(),
            received
        );
    }
}
