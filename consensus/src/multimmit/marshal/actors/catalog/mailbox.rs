//! Catalog requests, their lanes, and the client that sends them.
//!
//! Requests travel on three lanes. Commands keep mailbox order, so a lookup observes every
//! admission queued before it. Independent reads ([`Read`]) may overtake queued admissions and
//! must not be used to establish custody. Cursor updates mirror delivery's durable cursor.

use super::metrics::Operation;
use crate::{
    multimmit::{
        actors::util::{Completion, ask, reliable_policy},
        marshal::{
            MarshalProgress,
            actors::delivery,
            storage::{
                catalog::{Admission, InstallRequest, StoredRef},
                catalog_state::Checkpoint,
                commit::Commit,
            },
            types::{BodyValues, CustodyValues, MaybeLqc, OutputIndex, Reply},
        },
        types::{
            BlockRef, Body, CertificateId, ChainId, Lqc, TipRecord, TransactionBlock,
            TransactionBlockHeader,
        },
    },
    types::View,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::channel::fallible::OneshotExt as _;
use futures::future::try_join_all;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc, time::SystemTime};
use tracing::Span;

/// A catalog request was not served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// The catalog stopped before replying.
    #[error("catalog mailbox is closed")]
    Closed,
    /// Delivery stopped before acknowledging a floor installation.
    #[error("delivery mailbox is closed")]
    DeliveryClosed,
    /// The request is malformed or inconsistent with catalog state.
    #[error("invalid catalog request: {0}")]
    Invalid(&'static str),
    /// Both commit slots are waiting for durability.
    #[error("commit publication window is full")]
    CommitWindowFull,
    /// Too many custody requests are waiting for admission cuts.
    #[error("catalog custody waiter bound is exhausted")]
    CustodyWaitersFull,
}

impl Error {
    /// Returns whether the catalog rejected the request and remains usable.
    pub(crate) const fn is_rejected(&self) -> bool {
        matches!(
            self,
            Self::Invalid(_) | Self::CommitWindowFull | Self::CustodyWaitersFull
        )
    }
}

pub(super) type HistorySegment<H> = Vec<Arc<TipRecord<<H as Hasher>::Digest>>>;
pub(super) type HeaderSegments<H> = Vec<Vec<TransactionBlockHeader<<H as Hasher>::Digest>>>;
pub(super) type OutputRefs<H> = Vec<StoredRef<<H as Hasher>::Digest>>;

/// A pending block located by digest, with its body when a cache holds it.
pub(super) type BodyCandidate<H, B> = (
    BlockRef<<H as Hasher>::Digest>,
    Option<Arc<TransactionBlock<H, B>>>,
);

/// When an admission's caller hears back.
pub(super) enum AdmissionReply {
    /// Replies once the admissions are buffered and readable.
    Buffered(Reply<(), Error>),
    /// Replies once the admissions are durable custody.
    Durable(Reply<(), Error>),
    /// Replies to `accepted` once buffered and to `durable` once durable custody.
    Staged {
        accepted: Reply<(), Error>,
        durable: Reply<(), Error>,
    },
}

impl AdmissionReply {
    /// Returns whether the admissions must join the next durability cut.
    pub(super) const fn is_durable(&self) -> bool {
        matches!(self, Self::Durable(_))
    }

    /// Answers a request that admits nothing: the caller's first reply succeeds at once.
    ///
    /// A staged request's durable reply is dropped, so its completion resolves as closed.
    pub(super) fn empty(self) {
        let reply = match self {
            Self::Buffered(reply) | Self::Durable(reply) => reply,
            Self::Staged { accepted, .. } => accepted,
        };
        reply.send_lossy(Ok(()));
    }

    /// Sends `error` to every reply.
    pub(super) fn fail(self, error: Error) {
        match self {
            Self::Buffered(reply) | Self::Durable(reply) => {
                reply.send_lossy(Err(error));
            }
            Self::Staged { accepted, durable } => {
                accepted.send_lossy(Err(error));
                durable.send_lossy(Err(error));
            }
        }
    }
}

/// A request on the command lane, which keeps mailbox order.
pub(super) enum Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Buffers pending artifacts and replies as `reply` specifies.
    Admit {
        admissions: Vec<Admission<H, V, B>>,
        reply: AdmissionReply,
    },
    /// Any other ordered request.
    Command(Command<H, V, B>),
}

impl<H, V, B> Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Returns the stable metric and span label of this request.
    pub(super) const fn kind(&self) -> Operation {
        match self {
            Self::Admit { .. } => Operation::Admit,
            Self::Command(command) => command.kind(),
        }
    }
}

/// An ordered request other than an admission.
pub(super) enum Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Returns the L-QC with `id`, finalized or pending.
    Lqc {
        id: CertificateId<H::Digest>,
        reply: Reply<MaybeLqc<V, H::Digest>, Error>,
    },
    /// Returns whether the L-QC with `id` is finalized.
    FinalLqc {
        id: CertificateId<H::Digest>,
        reply: Reply<bool, Error>,
    },
    /// Returns the first pending L-QC at the highest pending view.
    LatestLqc {
        reply: Reply<MaybeLqc<V, H::Digest>, Error>,
    },
    /// Returns the history opening with `commitment`, finalized or pending.
    History {
        commitment: H::Digest,
        reply: Reply<Option<Arc<TipRecord<H::Digest>>>, Error>,
    },
    /// Walks history openings back from `commitment` within the item and byte bounds.
    HistorySegment {
        commitment: H::Digest,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
        reply: Reply<HistorySegment<H>, Error>,
    },
    /// Returns durable custody for `references`, waiting for buffered blocks' admission cut.
    WaitForCustody {
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<CustodyValues<H::Digest>, Error>,
    },
    /// Returns the bodies of `references`, observing every earlier admission.
    Bodies {
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<BodyValues<H, B>, Error>,
    },
    /// Accepts one bounded commit with the bodies its caller holds.
    Commit {
        batch: Commit<H, V>,
        handoff: Vec<delivery::HotOutput<H, B>>,
        reply: Reply<Completion<Error>, Error>,
    },
    /// Installs a verified state-sync floor.
    Install {
        request: InstallRequest<V, H::Digest>,
        reply: Reply<delivery::ResetWaiter, Error>,
    },
    /// Prunes finalized storage for the delivery cursor of `floor_generation`.
    Prune {
        floor_generation: u64,
        reply: Reply<(), Error>,
    },
    /// Reclaims pending bodies the promoter copied through `frontiers`.
    Promoted {
        frontiers: Vec<BlockRef<H::Digest>>,
        reply: Reply<(), Error>,
    },
    /// Returns the published checkpoint.
    Checkpoint {
        reply: Reply<Checkpoint<H::Digest>, Error>,
    },
    /// Returns durable progress.
    Progress {
        reply: Reply<MarshalProgress<H::Digest>, Error>,
    },
}

impl<H, V, B> Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Returns the stable metric and span label of this request.
    pub(super) const fn kind(&self) -> Operation {
        match self {
            Self::Lqc { .. } => Operation::Lqc,
            Self::FinalLqc { .. } => Operation::FinalLqc,
            Self::LatestLqc { .. } => Operation::LatestLqc,
            Self::History { .. } => Operation::History,
            Self::HistorySegment { .. } => Operation::HistorySegment,
            Self::WaitForCustody { .. } => Operation::WaitForCustody,
            Self::Bodies { .. } => Operation::Bodies,
            Self::Commit { .. } => Operation::Commit,
            Self::Install { .. } => Operation::Install,
            Self::Prune { .. } => Operation::Prune,
            Self::Promoted { .. } => Operation::Promoted,
            Self::Checkpoint { .. } => Operation::Checkpoint,
            Self::Progress { .. } => Operation::Progress,
        }
    }
}

/// A read of already-committed or advisory state that may overtake queued admissions.
pub(super) enum Read<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Returns the bodies of committed `references`.
    Bodies {
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<BodyValues<H, B>, Error>,
    },
    /// Locates a pending block of `chain` by header digest.
    BodyCandidate {
        chain: ChainId,
        digest: H::Digest,
        reply: Reply<Option<BodyCandidate<H, B>>, Error>,
    },
    /// Walks header ancestry back from each start within the item and byte bounds.
    HeaderSegments {
        requests: Vec<(BlockRef<H::Digest>, NonZeroUsize)>,
        max_bytes: NonZeroUsize,
        reply: Reply<HeaderSegments<H>, Error>,
    },
    /// Returns committed output rows from `start` within the item and byte bounds.
    OutputRefs {
        start: OutputIndex,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
        reply: Reply<OutputRefs<H>, Error>,
    },
}

impl<H, B> Read<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Returns the stable metric and span label of this read.
    pub(super) const fn kind(&self) -> Operation {
        match self {
            Self::Bodies { .. } => Operation::Bodies,
            Self::BodyCandidate { .. } => Operation::BodyCandidate,
            Self::HeaderSegments { .. } => Operation::HeaderSegments,
            Self::OutputRefs { .. } => Operation::OutputRefs,
        }
    }

    /// Returns whether the caller stopped waiting for the reply.
    pub(super) fn is_canceled(&self) -> bool {
        match self {
            Self::Bodies { reply, .. } => reply.is_closed(),
            Self::BodyCandidate { reply, .. } => reply.is_closed(),
            Self::HeaderSegments { reply, .. } => reply.is_closed(),
            Self::OutputRefs { reply, .. } => reply.is_closed(),
        }
    }

    /// Resolves once the caller stops waiting for the reply.
    pub(super) async fn canceled(&mut self) {
        match self {
            Self::Bodies { reply, .. } => reply.closed().await,
            Self::BodyCandidate { reply, .. } => reply.closed().await,
            Self::HeaderSegments { reply, .. } => reply.closed().await,
            Self::OutputRefs { reply, .. } => reply.closed().await,
        }
    }
}

/// A request with the caller's span and, until first intake, its enqueue time.
pub(super) struct Traced<M> {
    pub(super) message: M,
    pub(super) span: Span,
    /// Client-side enqueue time, consumed when the catalog first takes the request.
    pub(super) enqueued: Option<SystemTime>,
}

reliable_policy!(impl<M> for Traced<M>);

/// A delivery-cursor change mirrored into catalog progress and pruning.
pub(super) enum CursorMessage {
    /// Delivery durably acknowledged through `acknowledged`.
    Update {
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
    },
    /// Delivery durably reset its cursor for a new floor generation.
    Reset {
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
        reply: Reply<(), Error>,
    },
}

impl Policy for CursorMessage {
    type Overflow = VecDeque<Self>;

    /// Coalesces an update into a trailing update of the same generation; resets stay barriers.
    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if let Self::Update {
            floor_generation,
            acknowledged,
        } = &message
            && let Some(Self::Update {
                floor_generation: last_generation,
                acknowledged: last_acknowledged,
            }) = overflow.back_mut()
            && last_generation == floor_generation
        {
            *last_acknowledged = (*last_acknowledged).max(*acknowledged);
            return;
        }
        overflow.push_back(message);
    }
}

/// Runtime-clock accessor shared with catalog clients.
///
/// Clients stay generic only over protocol types, so the runtime clock crosses this boundary as
/// an erased closure. Every request calls it once at enqueue.
pub(super) type EnqueueClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// Cloneable client for the catalog's lanes.
pub(crate) struct Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) commands: mailbox::Sender<Traced<Message<H, V, B>>>,
    pub(super) cursors: mailbox::Sender<CursorMessage>,
    pub(super) reads: mailbox::Sender<Traced<Read<H, B>>>,
    /// Most admissions one request may carry.
    pub(super) admission_cut_capacity: usize,
    /// Reads the runtime clock at enqueue so the actor can measure mailbox dwell.
    pub(super) now: EnqueueClock,
}

impl<H, V, B> Clone for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            cursors: self.cursors.clone(),
            reads: self.reads.clone(),
            admission_cut_capacity: self.admission_cut_capacity,
            now: self.now.clone(),
        }
    }
}

impl<H, V, B> Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Sends an ordered request and awaits its reply.
    pub(super) async fn request<T>(
        &self,
        make: impl FnOnce(Reply<T, Error>) -> Message<H, V, B>,
    ) -> Result<T, Error> {
        ask(
            |message| {
                self.commands.enqueue(Traced {
                    message,
                    span: Span::current(),
                    enqueued: Some((self.now)()),
                })
            },
            make,
            Error::Closed,
        )
        .await
    }

    /// Sends an ordered request other than an admission and awaits its reply.
    async fn command<T>(
        &self,
        make: impl FnOnce(Reply<T, Error>) -> Command<H, V, B>,
    ) -> Result<T, Error> {
        self.request(|reply| Message::Command(make(reply))).await
    }

    /// Sends an independent read and awaits its reply.
    pub(super) async fn read<T>(
        &self,
        make: impl FnOnce(Reply<T, Error>) -> Read<H, B>,
    ) -> Result<T, Error> {
        ask(
            |message| {
                self.reads.enqueue(Traced {
                    message,
                    span: Span::current(),
                    enqueued: Some((self.now)()),
                })
            },
            make,
            Error::Closed,
        )
        .await
    }

    /// Admits an L-QC and waits until it is durable.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "admit_lqc")
    )]
    pub(crate) async fn admit_lqc(
        &self,
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::Admit {
            admissions: vec![Admission::Lqc(view, id, proof)],
            reply: AdmissionReply::Durable(reply),
        })
        .await
    }

    /// Buffers an L-QC without waiting for durability.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "stage_lqc")
    )]
    pub(crate) async fn stage_lqc(
        &self,
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::Admit {
            admissions: vec![Admission::Lqc(view, id, proof)],
            reply: AdmissionReply::Buffered(reply),
        })
        .await
    }

    /// Buffers a history opening without waiting for durability.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "stage_history")
    )]
    pub(crate) async fn stage_history(
        &self,
        view: View,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::Admit {
            admissions: vec![Admission::History(view, commitment, record)],
            reply: AdmissionReply::Buffered(reply),
        })
        .await
    }

    /// Admits a producer block and waits until it is durable custody.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "admit_block")
    )]
    pub(crate) async fn admit_block(
        &self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::Admit {
            admissions: vec![Admission::Block(reference, block)],
            reply: AdmissionReply::Durable(reply),
        })
        .await
    }

    /// Returns the L-QC with `id`, finalized or pending.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "lqc")
    )]
    pub(crate) async fn lqc(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<MaybeLqc<V, H::Digest>, Error> {
        self.command(|reply| Command::Lqc { id, reply }).await
    }

    /// Returns whether the L-QC with `id` is finalized.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "final_lqc")
    )]
    pub(crate) async fn final_lqc(&self, id: CertificateId<H::Digest>) -> Result<bool, Error> {
        self.command(|reply| Command::FinalLqc { id, reply }).await
    }

    /// Returns the first pending L-QC at the highest pending view.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "latest_lqc")
    )]
    pub(crate) async fn latest_lqc(&self) -> Result<MaybeLqc<V, H::Digest>, Error> {
        self.command(|reply| Command::LatestLqc { reply }).await
    }

    /// Returns the history opening with `commitment`, finalized or pending.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "history")
    )]
    pub(crate) async fn history(
        &self,
        commitment: H::Digest,
    ) -> Result<Option<Arc<TipRecord<H::Digest>>>, Error> {
        self.command(|reply| Command::History { commitment, reply })
            .await
    }

    /// Walks up to `max_items` history openings back from `commitment`, encoding within
    /// `max_bytes`.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "history_segment")
    )]
    pub(crate) async fn history_segment(
        &self,
        commitment: H::Digest,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<HistorySegment<H>, Error> {
        let (Some(max_items), Some(max_bytes)) =
            (NonZeroUsize::new(max_items), NonZeroUsize::new(max_bytes))
        else {
            return Err(Error::Invalid("history segment bounds are zero"));
        };
        self.command(|reply| Command::HistorySegment {
            commitment,
            max_items,
            max_bytes,
            reply,
        })
        .await
    }

    /// Walks header ancestry back from each `(start, max_items)` request, encoding each segment
    /// within `max_bytes`.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "header_segments")
    )]
    pub(crate) async fn header_segments(
        &self,
        requests: Vec<(BlockRef<H::Digest>, usize)>,
        max_bytes: usize,
    ) -> Result<HeaderSegments<H>, Error> {
        let bounded = requests
            .into_iter()
            .map(|(start, max_items)| NonZeroUsize::new(max_items).map(|max| (start, max)))
            .collect::<Option<Vec<_>>>();
        let (Some(requests), Some(max_bytes)) = (bounded, NonZeroUsize::new(max_bytes)) else {
            return Err(Error::Invalid("header segment bounds are zero"));
        };
        self.read(|reply| Read::HeaderSegments {
            requests,
            max_bytes,
            reply,
        })
        .await
    }

    /// Returns durable custody for `references`, waiting while any is buffered but not yet
    /// durable.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "wait_for_custody")
    )]
    pub(crate) async fn wait_for_custody(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<CustodyValues<H::Digest>, Error> {
        self.command(|reply| Command::WaitForCustody { references, reply })
            .await
    }

    /// Returns the bodies of `references`, observing every admission sent before it.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "bodies")
    )]
    pub(crate) async fn bodies(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        self.command(|reply| Command::Bodies { references, reply })
            .await
    }

    /// Prunes finalized storage up to delivery's cursor for `floor_generation`.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "prune")
    )]
    pub(crate) async fn prune(&self, floor_generation: u64) -> Result<(), Error> {
        self.command(|reply| Command::Prune {
            floor_generation,
            reply,
        })
        .await
    }

    /// Reclaims pending bodies the promoter durably copied through `frontiers`.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "promoted")
    )]
    pub(crate) async fn promoted(&self, frontiers: Vec<BlockRef<H::Digest>>) -> Result<(), Error> {
        self.command(|reply| Command::Promoted { frontiers, reply })
            .await
    }

    /// Returns durable progress.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "progress")
    )]
    pub(crate) async fn progress(&self) -> Result<MarshalProgress<H::Digest>, Error> {
        self.command(|reply| Command::Progress { reply }).await
    }

    /// Returns the published checkpoint.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.request",
        level = "debug",
        skip_all,
        fields(operation = "checkpoint")
    )]
    pub(crate) async fn checkpoint(&self) -> Result<Checkpoint<H::Digest>, Error> {
        self.command(|reply| Command::Checkpoint { reply }).await
    }

    /// Reads committed bodies independently of queued admissions.
    ///
    /// Callers must have taken these references from a published checkpoint.
    pub(crate) async fn committed_bodies(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        self.read(|reply| Read::Bodies { references, reply }).await
    }

    /// Mirrors delivery's durable cursor into catalog progress and pruning.
    pub(crate) fn delivery_cursor(
        &self,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Feedback {
        self.cursors.enqueue(CursorMessage::Update {
            floor_generation,
            acknowledged,
        })
    }

    /// Mirrors delivery's durable generation reset and waits until the catalog applied it.
    pub(crate) async fn reset_delivery_cursor(
        &self,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Result<(), Error> {
        ask(
            |message| self.cursors.enqueue(message),
            |reply| CursorMessage::Reset {
                floor_generation,
                acknowledged,
                reply,
            },
            Error::Closed,
        )
        .await
    }

    /// Returns a pending or committed block by reference.
    #[tracing::instrument(name = "multimmit.marshal.catalog.block", level = "debug", skip_all)]
    pub(crate) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        Ok(self.bodies(vec![reference]).await?.pop().flatten())
    }

    /// Returns a pending block by its chain and header digest.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.block_by_digest",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn block_by_digest(
        &self,
        chain: ChainId,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        let Some((reference, block)) = self
            .read(|reply| Read::BodyCandidate {
                chain,
                digest,
                reply,
            })
            .await?
        else {
            return Ok(None);
        };
        match block {
            Some(block) => Ok(Some(block)),
            None => self.block(reference).await,
        }
    }

    /// Buffers validated producer blocks, in requests of at most one admission cut each.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.stage_blocks",
        level = "debug",
        skip_all,
        fields(blocks = blocks.len())
    )]
    pub(crate) async fn stage_blocks(
        &self,
        blocks: &[Arc<TransactionBlock<H, B>>],
    ) -> Result<(), Error> {
        if blocks.is_empty() {
            return Ok(());
        }
        try_join_all(blocks.chunks(self.admission_cut_capacity).map(|blocks| {
            self.request(|reply| Message::Admit {
                admissions: blocks
                    .iter()
                    .map(|block| Admission::Block(block.reference(), Arc::clone(block)))
                    .collect(),
                reply: AdmissionReply::Buffered(reply),
            })
        }))
        .await
        .map(|_| ())
    }

    /// Buffers one producer block and returns the completion of its durable custody.
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.stage_block",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn stage_block(
        &self,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<Completion<Error>, Error> {
        let (durable, custody) = Completion::channel(|| Error::Closed);
        self.request(|accepted| Message::Admit {
            admissions: vec![Admission::Block(block.reference(), block)],
            reply: AdmissionReply::Staged { accepted, durable },
        })
        .await?;
        Ok(custody)
    }

    /// Installs a verified floor and waits until delivery has crossed its generation reset.
    #[tracing::instrument(name = "multimmit.marshal.catalog.install", level = "info", skip_all)]
    pub(crate) async fn install(&self, request: InstallRequest<V, H::Digest>) -> Result<(), Error> {
        let reset = self
            .command(|reply| Command::Install { request, reply })
            .await?;
        reset.wait().await
    }

    /// Returns committed output rows from `start`, up to `max_items` rows encoding within
    /// `max_bytes` (one larger row is returned alone).
    #[tracing::instrument(
        name = "multimmit.marshal.catalog.output_refs",
        level = "info",
        skip_all,
        fields(start = start.get(), max_items = max_items.get(), max_bytes = max_bytes.get())
    )]
    pub(crate) async fn output_refs(
        &self,
        start: OutputIndex,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
    ) -> Result<OutputRefs<H>, Error> {
        self.read(|reply| Read::OutputRefs {
            start,
            max_items,
            max_bytes,
            reply,
        })
        .await
    }

    /// Accepts one bounded commit and returns the completion of its publication.
    ///
    /// `handoff` may carry bodies the caller already holds, ordered like the batch's output rows;
    /// delivery reads any body the handoff omits. Completions resolve in acceptance order.
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
    pub(crate) async fn start_commit(
        &self,
        batch: Commit<H, V>,
        handoff: Vec<delivery::HotOutput<H, B>>,
    ) -> Result<Completion<Error>, Error> {
        self.command(|reply| Command::Commit {
            batch,
            handoff,
            reply,
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::testing::TestBody;
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_utils::channel::oneshot;

    fn reply<T>() -> Reply<T, Error> {
        oneshot::channel().0
    }

    #[test]
    fn request_kind_labels_are_stable() {
        let requests = [
            (
                Message::<Sha256, MinPk, TestBody>::Admit {
                    admissions: Vec::new(),
                    reply: AdmissionReply::Buffered(reply()),
                },
                "admit",
            ),
            (
                Message::Command(Command::WaitForCustody {
                    references: Vec::new(),
                    reply: reply(),
                }),
                "wait_for_custody",
            ),
            (
                Message::Command(Command::Bodies {
                    references: Vec::new(),
                    reply: reply(),
                }),
                "bodies",
            ),
        ];
        for (request, expected) in requests {
            assert_eq!(request.kind().as_str(), expected);
        }
        let read = Read::<Sha256, TestBody>::Bodies {
            references: Vec::new(),
            reply: reply(),
        };
        assert_eq!(read.kind().as_str(), "bodies");
    }

    fn update(floor_generation: u64, acknowledged: Option<u64>) -> CursorMessage {
        CursorMessage::Update {
            floor_generation,
            acknowledged: acknowledged.map(OutputIndex::new),
        }
    }

    fn acknowledged(message: &CursorMessage) -> Option<OutputIndex> {
        match message {
            CursorMessage::Update { acknowledged, .. }
            | CursorMessage::Reset { acknowledged, .. } => *acknowledged,
        }
    }

    #[test]
    fn cursor_overflow_coalesces_updates_between_resets() {
        let mut overflow = VecDeque::new();
        CursorMessage::handle(&mut overflow, update(3, Some(1)));
        CursorMessage::handle(&mut overflow, update(3, Some(4)));
        assert_eq!(overflow.len(), 1);
        assert_eq!(acknowledged(&overflow[0]), Some(OutputIndex::new(4)));

        CursorMessage::handle(
            &mut overflow,
            CursorMessage::Reset {
                floor_generation: 4,
                acknowledged: None,
                reply: reply(),
            },
        );
        CursorMessage::handle(&mut overflow, update(4, Some(2)));
        CursorMessage::handle(&mut overflow, update(4, Some(7)));
        assert_eq!(overflow.len(), 3);
        assert!(matches!(overflow[1], CursorMessage::Reset { .. }));
        assert_eq!(acknowledged(&overflow[2]), Some(OutputIndex::new(7)));
    }
}
