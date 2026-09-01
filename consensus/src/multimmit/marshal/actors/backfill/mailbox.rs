//! The backfill mailbox, the resolver bridge, and their messages.

use super::{
    serve,
    validate::{SharedHeaders, SharedHistory},
    waiter::{BackfillSubscriber, BlockMode, ExactPrefix, Reply, Target},
};
use crate::{
    multimmit::{
        actors::util::ask,
        marshal::{
            actors::{catalog, metrics::FetchReason},
            bodies,
            wire::{BackfillKey, MAX_SEGMENT_ITEMS},
        },
        types::{BlockRef, Body, CertificateId, Lqc, TipRecord, TransactionBlock},
    },
    types::View,
};
use bytes::Bytes;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_resolver::{Consumer, Delivery, Outcome, p2p::Producer};
use commonware_runtime::Error as RuntimeError;
use commonware_utils::channel::{fallible::OneshotExt as _, oneshot};
use std::{collections::VecDeque, sync::Arc};
use tracing::{Span, info_span};

/// A backfill fetch could not complete.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The backfill actor has stopped accepting requests.
    #[error("backfill mailbox is closed")]
    MailboxClosed,
    /// The network resolver has stopped accepting fetches.
    #[error("network resolver has stopped accepting fetches")]
    NetworkClosed,
    /// The pending-request bound is full and the request could not evict another request.
    #[error("backfill pending bound is exhausted")]
    PendingFull,
    /// A request, a local catalog response, or actor bookkeeping violated an invariant.
    #[error("invalid backfill request or state: {0}")]
    Invalid(&'static str),
    /// A catalog request failed.
    #[error("catalog request failed: {0}")]
    Catalog(#[from] catalog::Error),
    /// A body lookup across temporary and immutable custody failed.
    #[error("body lookup failed: {0}")]
    Bodies(#[from] bodies::Error),
    /// A verification task stopped before reporting.
    #[error("verification task failed: {0}")]
    Verification(#[from] RuntimeError),
}

/// Reply channel for the [`Outcome`] of one resolver delivery.
///
/// Dropping it unanswered reports [`Outcome::Ignored`], so the network resolver retires the key at
/// once instead of redelivering the response to other subscribers of an actor that will not judge
/// it (for example, after the actor exits with deliveries still queued).
pub(super) struct DeliveryReply(Option<oneshot::Sender<Outcome>>);

impl DeliveryReply {
    pub(super) const fn new(reply: oneshot::Sender<Outcome>) -> Self {
        Self(Some(reply))
    }

    /// Reports `outcome` to the network resolver.
    pub(super) fn send(mut self, outcome: Outcome) {
        if let Some(reply) = self.0.take() {
            reply.send_lossy(outcome);
        }
    }
}

impl Drop for DeliveryReply {
    /// Reports [`Outcome::Ignored`] for a delivery that was never answered.
    fn drop(&mut self) {
        if let Some(reply) = self.0.take() {
            reply.send_lossy(Outcome::Ignored);
        }
    }
}

/// A peer response for one backfill key.
pub(super) struct Incoming<D: Digest> {
    /// Span of the delivery, linked to the fetches it answers.
    pub span: Span,
    pub delivery: Delivery<BackfillKey<D>, BackfillSubscriber>,
    pub value: Bytes,
    pub response: DeliveryReply,
}

/// A command for the backfill actor.
pub(super) enum Message<H: Hasher, V: Variant, B: Body<H>> {
    /// A peer response for one backfill key.
    Deliver(Incoming<H::Digest>),
    /// A caller waiting for `target`.
    Fetch {
        span: Span,
        target: Target<H::Digest>,
        reply: Reply<H, V, B>,
        reason: FetchReason,
    },
    /// A producer block now has a DA certificate.
    CertifiedBlock { reference: BlockRef<H::Digest> },
    /// Forget recorded DA certificates at or below per-chain frontiers.
    RetireCertified {
        frontiers: Vec<BlockRef<H::Digest>>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// The catalog admitted a producer block.
    AdmittedBlock {
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    /// The catalog admitted a tip-history record.
    AdmittedHistory {
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
}

impl<H: Hasher, V: Variant, B: Body<H>> Policy for Message<H, V, B> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        let retain = |message: &Self| match message {
            Self::Fetch { reply, .. } => !reply.is_closed(),
            Self::AdmittedBlock { reply, .. }
            | Self::AdmittedHistory { reply, .. }
            | Self::RetireCertified { reply, .. } => !reply.is_closed(),
            Self::Deliver(_) | Self::CertifiedBlock { .. } => true,
        };
        overflow.retain(retain);
        match message {
            // The resolver retries an ambiguous response without penalizing its peer.
            Self::Deliver(incoming) => incoming.response.send(Outcome::Ambiguous),
            // Certificate hints are optional; a later subscription still fetches the block.
            Self::CertifiedBlock { .. } => {}
            message => {
                if retain(&message) {
                    overflow.push_back(message);
                }
            }
        }
    }
}

/// Resolver-facing producer and consumer, created with the actor before the network
/// `commonware_resolver` engine is built.
pub struct BackfillBridge<H: Hasher, V: Variant, B: Body<H>> {
    commands: mailbox::Sender<Message<H, V, B>>,
    serve: serve::Mailbox<H::Digest>,
}

impl<H: Hasher, V: Variant, B: Body<H>> BackfillBridge<H, V, B> {
    pub(super) const fn new(
        commands: mailbox::Sender<Message<H, V, B>>,
        serve: serve::Mailbox<H::Digest>,
    ) -> Self {
        Self { commands, serve }
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Clone for BackfillBridge<H, V, B> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            serve: self.serve.clone(),
        }
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Producer for BackfillBridge<H, V, B> {
    type Key = BackfillKey<H::Digest>;

    fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        self.serve.produce(key)
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Consumer for BackfillBridge<H, V, B> {
    type Key = BackfillKey<H::Digest>;
    type Value = Bytes;
    type Subscriber = BackfillSubscriber;
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
        let _ = self.commands.enqueue(Message::Deliver(Incoming {
            span,
            delivery,
            value,
            response: DeliveryReply::new(response),
        }));
        receiver
    }
}

/// Mailbox for backfill requests, used by the synchronizer and the marshal router.
///
/// Every request first rechecks local custody and fetches from peers only on a miss. Block
/// requests differ in who establishes custody of a peer response:
///
/// - Fetch ([`Self::block`], [`Self::blocks`]): the actor stages the response in temporary
///   catalog custody before returning it.
/// - Wait ([`Self::subscribe_block`]): the actor never fetches until the block is DA-certified,
///   and returns a peer response without staging it; the caller admits it to establish custody.
pub(crate) struct Mailbox<H: Hasher, V: Variant, B: Body<H>> {
    pub(super) commands: mailbox::Sender<Message<H, V, B>>,
}

impl<H: Hasher, V: Variant, B: Body<H>> Clone for Mailbox<H, V, B> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

impl<H: Hasher, V: Variant, B: Body<H>> Mailbox<H, V, B> {
    pub(super) const fn new(commands: mailbox::Sender<Message<H, V, B>>) -> Self {
        Self { commands }
    }

    /// Enqueues the message built by `make` and awaits its reply.
    async fn request<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Message<H, V, B>,
    ) -> Result<T, Error> {
        ask(
            |message| self.commands.enqueue(message),
            make,
            Error::MailboxClosed,
        )
        .await
    }

    /// Registers a waiter for `target` and awaits its result.
    async fn fetch<T>(
        &self,
        reason: FetchReason,
        target: Target<H::Digest>,
        reply: impl FnOnce(oneshot::Sender<Result<T, Error>>) -> Reply<H, V, B>,
    ) -> Result<T, Error> {
        self.request(|sender| Message::Fetch {
            span: Span::current(),
            target,
            reply: reply(sender),
            reason,
        })
        .await
    }

    /// Returns the L-QC identified by `id`.
    ///
    /// A peer response is verified and admitted to the catalog before it is returned.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.lqc",
        level = "info",
        skip_all,
        fields(reason = ?reason)
    )]
    pub(crate) async fn lqc(
        &self,
        reason: FetchReason,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<V, H::Digest>>, Error> {
        self.fetch(reason, Target::Lqc(id), Reply::Lqc).await
    }

    /// Returns a linked tip-history segment, newest first, that starts at `commitment`.
    ///
    /// `view` is recorded on the tracing span only.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.history",
        level = "info",
        skip_all,
        fields(reason = ?reason, view = view.get())
    )]
    pub(crate) async fn history(
        &self,
        reason: FetchReason,
        view: View,
        commitment: H::Digest,
    ) -> Result<SharedHistory<H::Digest>, Error> {
        self.fetch(reason, Target::History(commitment), Reply::History)
            .await
    }

    /// Returns a linked producer-header segment, newest first, that starts at `reference`.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.headers",
        level = "info",
        skip_all,
        fields(
            reason = ?reason,
            chain = reference.chain().get(),
            height = reference.height().get(),
        )
    )]
    pub(crate) async fn headers(
        &self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<SharedHeaders<H::Digest>, Error> {
        self.fetch(reason, Target::Headers(reference), Reply::Headers)
            .await
    }

    /// Returns producer block `reference` with Fetch custody.
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
    pub(crate) async fn block(
        &self,
        reason: FetchReason,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let target = Target::Block {
            reference,
            mode: BlockMode::Fetch,
        };
        self.fetch(reason, target, Reply::Block).await
    }

    /// Returns a non-empty prefix of the consecutive producer blocks `references`, newest first,
    /// with Fetch custody.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.blocks",
        level = "info",
        skip_all,
        fields(
            reason = ?reason,
            chain = references.first().map(|reference| reference.chain().get()),
            height = references.first().map(|reference| reference.height().get()),
            blocks = references.len(),
        )
    )]
    pub(crate) async fn blocks(
        &self,
        reason: FetchReason,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<ExactPrefix<H, B>, Error> {
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
        self.fetch(reason, Target::Blocks(Arc::new(references)), Reply::Blocks)
            .await
    }

    /// Returns producer block `reference` with Wait custody.
    ///
    /// Local admission ([`Self::admitted_block`]) completes the wait. Once the block is reported
    /// DA-certified ([`Self::certified_block`]), the actor also fetches it from peers.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.subscribe_block",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn subscribe_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let target = Target::Block {
            reference,
            mode: BlockMode::Wait,
        };
        self.fetch(FetchReason::CertifiedSubscription, target, Reply::Block)
            .await
    }

    /// Reports that producer block `reference` has a DA certificate.
    ///
    /// Waiting subscriptions for the block start fetching. When none waits and the pending bound
    /// has room, the actor records the certificate so a later subscription fetches at once. The
    /// hint is dropped under mailbox pressure.
    pub(crate) fn certified_block(&self, reference: BlockRef<H::Digest>) -> Feedback {
        self.commands.enqueue(Message::CertifiedBlock { reference })
    }

    /// Forgets recorded DA certificates for blocks at or below `frontiers` on their chains.
    pub(crate) async fn retire_certified(
        &self,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::RetireCertified { frontiers, reply })
            .await
    }

    /// Completes waiters for producer block `reference`, which the catalog has admitted.
    ///
    /// Range requests whose newest block is `reference` complete with that one block.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.admit_block",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn admitted_block(
        &self,
        reference: BlockRef<H::Digest>,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::AdmittedBlock {
            reference,
            block,
            reply,
        })
        .await
    }

    /// Completes waiters for tip-history record `commitment`, which the catalog has admitted.
    #[tracing::instrument(
        name = "multimmit.marshal.resolver.admit_history",
        level = "debug",
        skip_all
    )]
    pub(crate) async fn admitted_history(
        &self,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::AdmittedHistory {
            commitment,
            record,
            reply,
        })
        .await
    }
}
