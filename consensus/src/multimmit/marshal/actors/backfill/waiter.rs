//! Backfill waiters: what each caller waits for, and how the actor answers it.

use super::{
    Error,
    validate::{SharedBlocks, SharedHeaders, SharedHistory},
};
use crate::multimmit::{
    marshal::{actors::metrics::FetchReason, storage::commit::CustodyRef, wire::BackfillKey},
    types::{BlockRef, Body, CertificateId, Lqc, TransactionBlock},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
};
use std::{num::NonZeroU16, slice, sync::Arc};
use tracing::Span;

/// Identity of one backfill waiter's fetch in the network resolver.
///
/// `commonware-resolver` removes only the delivered subscribers when a response completes. A
/// distinct identity per waiter lets a waiter that starts fetching while another waiter's response
/// is being validated keep its subscription, so the resolver redelivers that response to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BackfillSubscriber(u64);

impl BackfillSubscriber {
    /// Returns the identity allocated after this one.
    ///
    /// Identities wrap after `u64::MAX` registrations; they only need to be distinct among the
    /// bounded set of live waiters.
    pub(super) const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// A non-empty prefix of requested consecutive producer blocks, newest first.
///
/// Block `i` is the requested reference `i`. Only a waiter that accepted the blocks for its own
/// request constructs one.
pub(crate) struct ExactPrefix<H: Hasher, B: Body<H>>(SharedBlocks<H, B>);

impl<H: Hasher, B: Body<H>> ExactPrefix<H, B> {
    /// Returns the blocks, newest first.
    pub(crate) fn blocks(&self) -> &[Arc<TransactionBlock<H, B>>] {
        &self.0
    }
}

/// A fetched block paired with the durable catalog custody that describes it.
///
/// The custody row has the block's header and encoded length. The body is retained until
/// its custody row reaches delivery preparation.
pub(crate) struct CustodiedBlock<H: Hasher, B: Body<H>> {
    custody: CustodyRef<H::Digest>,
    block: Arc<TransactionBlock<H, B>>,
}

impl<H: Hasher, B: Body<H>> CustodiedBlock<H, B> {
    /// Pairs `block` with `custody`, or returns `None` if the custody row describes another block.
    pub(crate) fn new(
        custody: CustodyRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Option<Self> {
        let meta = custody.meta();
        (meta.header() == block.header()
            && u64::try_from(block.encode_size()).ok() == Some(meta.encoded_len()))
        .then_some(Self { custody, block })
    }

    /// Returns the block's reference.
    pub(crate) const fn reference(&self) -> BlockRef<H::Digest> {
        self.custody.reference()
    }

    /// Returns the custody row and the block.
    pub(crate) fn into_parts(self) -> (CustodyRef<H::Digest>, Arc<TransactionBlock<H, B>>) {
        (self.custody, self.block)
    }
}

/// How a block waiter obtains its block and who establishes custody of a peer response.
///
/// | Mode | Fetches from peers | Peer response staged in temporary custody |
/// |---|---|---|
/// | `Wait` | no | not applicable |
/// | `Subscribe` | yes | no: the caller admits the block |
/// | `Fetch` | yes | yes |
/// | `Certified` | no | yes, when another waiter's fetch resolves the block |
///
/// `Certified` is a marker without a caller, recorded when a block has a DA certificate and
/// nothing waits for it. Transitions:
///
/// - A DA certificate turns `Wait` into `Subscribe` ([`Self::on_certified`]).
/// - A waiter that registers while a marker holds its block replaces the marker: `Wait` becomes
///   `Subscribe`, and `Fetch` or `Subscribe` becomes `Fetch` ([`Self::merge_certified`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockMode {
    /// Wait for local admission without fetching.
    Wait,
    /// Fetch for a caller that requires temporary catalog custody.
    Fetch,
    /// Fetch for a caller that admits the block itself.
    Subscribe,
    /// DA-certificate marker without a caller.
    Certified,
}

impl BlockMode {
    /// Returns the mode after the block is reported DA-certified.
    pub(super) const fn on_certified(self) -> Self {
        match self {
            Self::Wait => Self::Subscribe,
            mode => mode,
        }
    }

    /// Returns the mode of a waiter that replaces a DA-certificate marker.
    pub(super) const fn merge_certified(self) -> Self {
        match self {
            Self::Wait => Self::Subscribe,
            Self::Fetch | Self::Subscribe => Self::Fetch,
            Self::Certified => Self::Certified,
        }
    }

    /// Returns whether a waiter in this mode fetches from peers.
    pub(super) const fn fetches(self) -> bool {
        matches!(self, Self::Fetch | Self::Subscribe)
    }

    /// Returns whether a peer response for a waiter in this mode is staged in temporary custody.
    pub(super) const fn stages(self) -> bool {
        matches!(self, Self::Fetch | Self::Certified)
    }
}

/// Returns whether `reference` names a producer chain of the epoch.
pub(super) fn in_epoch<D: Digest>(reference: &BlockRef<D>, chains: usize) -> bool {
    usize::try_from(reference.chain().get()).is_ok_and(|chain| chain < chains)
}

/// What a waiter waits for.
pub(super) enum Target<D: Digest> {
    /// The L-QC with this identifier.
    Lqc(CertificateId<D>),
    /// A linked tip-history segment starting at this commitment.
    History(D),
    /// A linked producer-header segment starting at this reference.
    Headers(BlockRef<D>),
    /// One producer block.
    Block {
        /// The block.
        reference: BlockRef<D>,
        /// How the waiter obtains the block.
        mode: BlockMode,
    },
    /// A prefix of these consecutive producer blocks, newest first.
    Blocks(Arc<Vec<BlockRef<D>>>),
}

impl<D: Digest> Target<D> {
    /// Returns the peer-visible key of the target.
    pub(super) fn key(&self) -> BackfillKey<D> {
        match self {
            Self::Lqc(id) => BackfillKey::lqc_by_id(*id),
            Self::History(commitment) => BackfillKey::tip_record(*commitment),
            Self::Headers(reference) => BackfillKey::producer_headers(*reference),
            Self::Block { reference, .. } => {
                BackfillKey::producer_block(reference.chain(), reference.digest())
            }
            Self::Blocks(references) => BackfillKey::producer_blocks(
                references[0],
                NonZeroU16::new(
                    u16::try_from(references.len()).expect("bounded range length fits in u16"),
                )
                .expect("body ranges are non-empty"),
            ),
        }
    }

    /// Returns whether every producer chain the target names belongs to the epoch.
    pub(super) fn in_epoch(&self, chains: usize) -> bool {
        match self {
            Self::Lqc(_) | Self::History(_) => true,
            Self::Headers(reference) | Self::Block { reference, .. } => in_epoch(reference, chains),
            Self::Blocks(references) => references
                .iter()
                .all(|reference| in_epoch(reference, chains)),
        }
    }

    /// Returns whether the target is a DA-certificate marker.
    pub(super) const fn is_marker(&self) -> bool {
        matches!(
            self,
            Self::Block {
                mode: BlockMode::Certified,
                ..
            }
        )
    }

    /// Returns whether a waiter for this target fetches from peers.
    const fn fetches(&self) -> bool {
        match self {
            Self::Lqc(_) | Self::History(_) | Self::Headers(_) | Self::Blocks(_) => true,
            Self::Block { mode, .. } => mode.fetches(),
        }
    }

    /// Returns whether `resolved` satisfies this target.
    pub(super) fn accepts<H, V, B>(&self, resolved: &Resolved<H, V, B>) -> bool
    where
        H: Hasher<Digest = D>,
        V: Variant,
        B: Body<H>,
    {
        match (self, resolved) {
            (Self::Lqc(expected), Resolved::Lqc(actual, _)) => expected == actual,
            (Self::History(expected), Resolved::History(actual, _)) => expected == actual,
            (Self::Headers(expected), Resolved::Headers(actual, _)) => expected == actual,
            (Self::Block { reference, .. }, Resolved::Block(actual, _)) => reference == actual,
            (Self::Blocks(expected), Resolved::Blocks(_, actual)) => {
                !actual.is_empty()
                    && actual.len() <= expected.len()
                    && expected
                        .iter()
                        .zip(actual.iter())
                        .all(|(expected, actual)| *expected == actual.reference())
            }
            _ => false,
        }
    }
}

type LqcReply<V, D> = oneshot::Sender<Result<Arc<Lqc<V, D>>, Error>>;
type HistoryReply<D> = oneshot::Sender<Result<SharedHistory<D>, Error>>;
type HeaderReply<D> = oneshot::Sender<Result<SharedHeaders<D>, Error>>;
type BlockReply<H, B> = oneshot::Sender<Result<Arc<TransactionBlock<H, B>>, Error>>;
type BlocksReply<H, B> = oneshot::Sender<Result<ExactPrefix<H, B>, Error>>;

/// The channel a waiter's result goes to, typed by its target.
pub(super) enum Reply<H: Hasher, V: Variant, B: Body<H>> {
    /// Answers a [`Target::Lqc`] waiter.
    Lqc(LqcReply<V, H::Digest>),
    /// Answers a [`Target::History`] waiter.
    History(HistoryReply<H::Digest>),
    /// Answers a [`Target::Headers`] waiter.
    Headers(HeaderReply<H::Digest>),
    /// Answers a [`Target::Block`] waiter.
    Block(BlockReply<H, B>),
    /// Answers a [`Target::Blocks`] waiter.
    Blocks(BlocksReply<H, B>),
}

/// Relays `result` to `reply`, or finishes early when the caller drops its receiver.
async fn relay<T: Send>(receiver: oneshot::Receiver<T>, mut reply: oneshot::Sender<T>) {
    select! {
        result = receiver => {
            if let Ok(result) = result {
                reply.send_lossy(result);
            }
        },
        _ = reply.closed() => {},
    }
}

/// Wraps `reply` in a relay whose completion `cancellations` tracks.
///
/// The waiter stores the returned sender in place of the caller's reply. The relay future forwards
/// the waiter's result to the caller, or finishes early when the caller drops its receiver. Either
/// way it yields `cancellation`, and the actor then drops the waiter if it is still registered.
fn track<T: Send + 'static, D: Digest>(
    reply: oneshot::Sender<T>,
    cancellation: Cancellation<D>,
    cancellations: &mut Pool<'static, Cancellation<D>>,
) -> oneshot::Sender<T> {
    let (sender, receiver) = oneshot::channel();
    cancellations.push(async move {
        relay(receiver, reply).await;
        cancellation
    });
    sender
}

impl<H: Hasher, V: Variant, B: Body<H>> Reply<H, V, B> {
    /// Returns whether the caller stopped waiting.
    pub(super) fn is_closed(&self) -> bool {
        match self {
            Self::Lqc(reply) => reply.is_closed(),
            Self::History(reply) => reply.is_closed(),
            Self::Headers(reply) => reply.is_closed(),
            Self::Block(reply) => reply.is_closed(),
            Self::Blocks(reply) => reply.is_closed(),
        }
    }

    /// Answers the caller with `error`.
    pub(super) fn fail(self, error: Error) {
        match self {
            Self::Lqc(reply) => reply.send_lossy(Err(error)),
            Self::History(reply) => reply.send_lossy(Err(error)),
            Self::Headers(reply) => reply.send_lossy(Err(error)),
            Self::Block(reply) => reply.send_lossy(Err(error)),
            Self::Blocks(reply) => reply.send_lossy(Err(error)),
        };
    }

    /// Answers the caller with `resolved`, which its waiter's target accepted.
    fn succeed(self, resolved: &Resolved<H, V, B>) {
        match (self, resolved) {
            (Self::Lqc(reply), Resolved::Lqc(_, proof)) => reply.send_lossy(Ok(Arc::clone(proof))),
            (Self::History(reply), Resolved::History(_, segment)) => {
                reply.send_lossy(Ok(Arc::clone(segment)))
            }
            (Self::Headers(reply), Resolved::Headers(_, segment)) => {
                reply.send_lossy(Ok(Arc::clone(segment)))
            }
            (Self::Block(reply), Resolved::Block(_, block)) => {
                reply.send_lossy(Ok(Arc::clone(block)))
            }
            (Self::Blocks(reply), Resolved::Blocks(_, blocks)) => {
                reply.send_lossy(Ok(ExactPrefix(Arc::clone(blocks))))
            }
            _ => unreachable!("an accepting target has the resolved value's reply type"),
        };
    }

    /// Routes the reply through a relay that reports `cancellation` once the caller is done.
    pub(super) fn track(
        self,
        cancellation: Cancellation<H::Digest>,
        cancellations: &mut Pool<'static, Cancellation<H::Digest>>,
    ) -> Self {
        match self {
            Self::Lqc(reply) => Self::Lqc(track(reply, cancellation, cancellations)),
            Self::History(reply) => Self::History(track(reply, cancellation, cancellations)),
            Self::Headers(reply) => Self::Headers(track(reply, cancellation, cancellations)),
            Self::Block(reply) => Self::Block(track(reply, cancellation, cancellations)),
            Self::Blocks(reply) => Self::Blocks(track(reply, cancellation, cancellations)),
        }
    }
}

/// Identifies a waiter whose caller is done.
pub(super) struct Cancellation<D: Digest> {
    /// Key the waiter waits on.
    pub key: BackfillKey<D>,
    /// Identity of the waiter.
    pub id: BackfillSubscriber,
}

/// Whether a waiter has a fetch registered with the network resolver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FetchState {
    /// Waiting for a local recheck, local admission, or promotion.
    Idle,
    /// Subscribed with the network resolver under the waiter's identity.
    Fetching,
}

/// One caller, or DA-certificate marker, waiting on a backfill key.
pub(super) struct Waiter<H: Hasher, V: Variant, B: Body<H>> {
    /// Identity of the waiter's fetch in the network resolver.
    pub id: BackfillSubscriber,
    /// The value the waiter needs.
    pub target: Target<H::Digest>,
    /// The caller's reply; a DA-certificate marker has none.
    pub reply: Option<Reply<H, V, B>>,
    /// Span of the request that registered the waiter.
    pub span: Span,
    /// Protocol obligation behind the request.
    pub reason: FetchReason,
    /// Whether the waiter has a network fetch registered.
    pub state: FetchState,
}

impl<H: Hasher, V: Variant, B: Body<H>> Waiter<H, V, B> {
    /// Returns whether the waiter's caller stopped waiting.
    pub(super) fn is_closed(&self) -> bool {
        self.reply.as_ref().is_some_and(Reply::is_closed)
    }

    /// Returns whether the waiter is a DA-certificate marker.
    pub(super) const fn is_marker(&self) -> bool {
        self.target.is_marker()
    }

    /// Returns the reason to report for a new network fetch, or `None` when the waiter does not
    /// fetch or already does.
    pub(super) const fn fetch_reason(&self) -> Option<FetchReason> {
        if matches!(self.state, FetchState::Fetching) || !self.target.fetches() {
            return None;
        }
        Some(match self.target {
            Target::Block {
                mode: BlockMode::Subscribe,
                ..
            } => FetchReason::CertifiedSubscription,
            _ => self.reason,
        })
    }

    /// Answers the caller with `error`.
    pub(super) fn fail(self, error: Error) {
        if let Some(reply) = self.reply {
            reply.fail(error);
        }
    }

    /// Answers the caller with `resolved`, which the waiter's target accepts.
    pub(super) fn complete(self, resolved: &Resolved<H, V, B>) {
        debug_assert!(self.target.accepts(resolved));
        if let Some(reply) = self.reply {
            reply.succeed(resolved);
        }
    }
}

/// A value that satisfies the waiters of one key.
pub(super) enum Resolved<H: Hasher, V: Variant, B: Body<H>> {
    /// The L-QC with this identifier.
    Lqc(CertificateId<H::Digest>, Arc<Lqc<V, H::Digest>>),
    /// A linked tip-history segment starting at this commitment.
    History(H::Digest, SharedHistory<H::Digest>),
    /// A linked producer-header segment starting at this reference.
    Headers(BlockRef<H::Digest>, SharedHeaders<H::Digest>),
    /// The producer block with this reference.
    Block(BlockRef<H::Digest>, Arc<TransactionBlock<H, B>>),
    /// A linked block segment for this range key.
    Blocks(BackfillKey<H::Digest>, SharedBlocks<H, B>),
}

impl<H: Hasher, V: Variant, B: Body<H>> Resolved<H, V, B> {
    /// Returns the key whose waiters the value may satisfy.
    pub(super) const fn key(&self) -> BackfillKey<H::Digest> {
        match self {
            Self::Lqc(id, _) => BackfillKey::lqc_by_id(*id),
            Self::History(commitment, _) => BackfillKey::tip_record(*commitment),
            Self::Headers(reference, _) => BackfillKey::producer_headers(*reference),
            Self::Block(reference, _) => {
                BackfillKey::producer_block(reference.chain(), reference.digest())
            }
            Self::Blocks(key, _) => *key,
        }
    }

    /// Returns the complete blocks the value carries.
    pub(super) fn blocks(&self) -> &[Arc<TransactionBlock<H, B>>] {
        match self {
            Self::Block(_, block) => slice::from_ref(block),
            Self::Blocks(_, blocks) => blocks.as_slice(),
            Self::Lqc(..) | Self::History(..) | Self::Headers(..) => &[],
        }
    }
}
