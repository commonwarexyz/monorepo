use super::{Variant, durability::Durable as _};
use crate::{
    Reporter,
    marshal::Identifier,
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
};
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_p2p::Recipients;
use commonware_runtime::{Handle, telemetry::traces::TracedExt as _};
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, num::NonZeroUsize, ops::Range, sync::Arc};
use tracing::{Span, info_span};

/// Messages sent to the marshal [Actor](super::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, V: Variant> {
    /// A request to retrieve the `(height, digest)` of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The span carried with this request.
        span: Span,
        /// The identifier of the block to get the information of.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved `(height, digest)`.
        response: oneshot::Sender<Option<(Height, <V::Block as Digestible>::Digest)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by [Identifier::Digest] may return non-finalized
    /// or even unverified blocks.
    GetBlock {
        /// The span carried with this request.
        span: Span,
        /// The identifier of the block to retrieve.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The span carried with this request.
        span: Span,
        /// The height of the finalization to retrieve.
        height: Height,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, V::Commitment>>>,
    },
    /// A request to retrieve the latest processed height.
    GetProcessedHeight {
        /// The span carried with this request.
        span: Span,
        /// A channel to send the latest processed height.
        response: oneshot::Sender<Option<Height>>,
    },
    /// A request to acquire the block matching an exact commitment.
    Acquire {
        /// The span carried with this request.
        span: Span,
        /// The commitment of the block to retrieve.
        commitment: V::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<V::Block>,
    },
    /// A lease requesting forward prefetch of commitment metadata.
    Prefetch {
        /// The span carried with this request.
        span: Span,
        /// The commitments in forward order.
        commitments: Arc<[V::Commitment]>,
        /// The selected indices within the commitment sequence.
        range: Range<usize>,
        /// The sender retained while the caller owns the lease receiver.
        lease: oneshot::Sender<()>,
    },
    /// A request to wait for a finalized block at a height.
    AwaitFinalized {
        /// The span carried with this request.
        span: Span,
        /// The height of the finalized block.
        height: Height,
        /// A channel to send the finalized block.
        response: oneshot::Sender<V::Block>,
    },
    /// A request to retrieve the verified block previously persisted for `round`.
    GetVerified {
        /// The span carried with this request.
        span: Span,
        /// The round to query.
        round: Round,
        /// A channel to send the retrieved block, if any.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to forward a block to a set of recipients.
    Forward {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was proposed.
        round: Round,
        /// The commitment of the block to forward.
        commitment: V::Commitment,
        /// The recipients to forward the block to.
        recipients: Recipients<S::PublicKey>,
    },
    /// A request to broadcast a locally proposed block and persist it.
    Proposed {
        /// The span carried with this request.
        span: Span,
        /// The round in which the block was proposed.
        round: Round,
        /// The proposed block.
        block: V::Block,
        /// The recipients to broadcast the block to.
        recipients: Recipients<S::PublicKey>,
        /// A channel sent once the block sync has started.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// A notification that a block reached the verify stage. Persisting it
    /// does not imply application validity.
    Verified {
        /// The span carried with this request.
        span: Span,
        /// The round of the verify request.
        round: Round,
        /// The block.
        block: V::Block,
        /// A channel sent once the block sync has started.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// A notification that a block reached the certify stage. Persisting it
    /// does not imply application validity.
    Certified {
        /// The span carried with this request.
        span: Span,
        /// The round of the certify request.
        round: Round,
        /// The block.
        block: V::Block,
        /// A channel sent once the block and notarization syncs have started; the
        /// handle covers both.
        ack: oneshot::Sender<Handle<()>>,
    },
    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances marshal's current floor, marshal
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [Message::Prune] instead.
    SetFloor {
        /// The span carried with this request.
        span: Span,
        /// The candidate floor finalization, verified by the actor before use.
        finalization: Finalization<S, V::Commitment>,
    },
    /// Requests pruning finalized blocks and certificates below the given height.
    ///
    /// Unlike [Message::SetFloor], this does not affect the sync starting
    /// point. Requests above marshal's current floor are ignored.
    Prune {
        /// The span carried with this request.
        span: Span,
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    },
    /// A notarization from the consensus engine.
    Notarization {
        /// The span carried with this request.
        span: Span,
        /// The notarization.
        notarization: Notarization<S, V::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The span carried with this request.
        span: Span,
        /// The finalization.
        finalization: Finalization<S, V::Commitment>,
    },
    /// A certification from the consensus engine.
    Certification {
        /// The span carried with this request.
        span: Span,
        /// The certified notarization.
        notarization: Notarization<S, V::Commitment>,
    },
}

impl<S: Scheme, V: Variant> Message<S, V> {
    /// Returns the span carried with this message.
    pub(crate) const fn span(&self) -> &Span {
        match self {
            Self::GetInfo { span, .. }
            | Self::GetBlock { span, .. }
            | Self::GetFinalization { span, .. }
            | Self::GetVerified { span, .. }
            | Self::Acquire { span, .. }
            | Self::Prefetch { span, .. }
            | Self::AwaitFinalized { span, .. }
            | Self::Forward { span, .. }
            | Self::Proposed { span, .. }
            | Self::Verified { span, .. }
            | Self::Certified { span, .. }
            | Self::Notarization { span, .. }
            | Self::Finalization { span, .. }
            | Self::Certification { span, .. }
            | Self::GetProcessedHeight { span, .. }
            | Self::SetFloor { span, .. }
            | Self::Prune { span, .. } => span,
        }
    }

    /// Returns the operation name of this message.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::GetInfo { .. } => "get_info",
            Self::GetBlock { .. } => "get_block",
            Self::GetFinalization { .. } => "get_finalization",
            Self::GetProcessedHeight { .. } => "get_processed_height",
            Self::Acquire { .. } => "acquire",
            Self::Prefetch { .. } => "prefetch",
            Self::AwaitFinalized { .. } => "await_finalized",
            Self::GetVerified { .. } => "get_verified",
            Self::Forward { .. } => "forward",
            Self::Proposed { .. } => "proposed",
            Self::Verified { .. } => "verified",
            Self::Certified { .. } => "certified",
            Self::SetFloor { .. } => "set_floor",
            Self::Prune { .. } => "prune",
            Self::Notarization { .. } => "notarization",
            Self::Finalization { .. } => "finalization",
            Self::Certification { .. } => "certification",
        }
    }

    fn stale(&self, current: Option<Height>) -> bool {
        match self {
            // Height-targeted reads below the floor can never be served
            Self::GetInfo {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetBlock {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetFinalization { height, .. }
            | Self::AwaitFinalized { height, .. } => Some(*height) < current,
            // Durability acks cannot be dropped: callers depend on them
            Self::Proposed { .. } | Self::Verified { .. } | Self::Certified { .. } => false,
            // Digest and latest lookups are not bound to a specific height
            Self::GetBlock {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetInfo {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetProcessedHeight { .. } => false,
            Self::Acquire { .. }
            | Self::Prefetch { .. }
            | Self::GetVerified { .. }
            | Self::Forward { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. }
            | Self::Certification { .. } => false,
        }
    }

    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetInfo { response, .. } => response.is_closed(),
            Self::GetBlock { response, .. } | Self::GetVerified { response, .. } => {
                response.is_closed()
            }
            Self::GetFinalization { response, .. } => response.is_closed(),
            Self::GetProcessedHeight { response, .. } => response.is_closed(),
            Self::Acquire { response, .. } | Self::AwaitFinalized { response, .. } => {
                response.is_closed()
            }
            Self::Prefetch { lease, .. } => lease.is_closed(),
            Self::Forward { .. }
            | Self::Proposed { .. }
            | Self::Verified { .. }
            | Self::Certified { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. }
            | Self::Certification { .. } => false,
        }
    }
}

pub(crate) struct Pending<S: Scheme, V: Variant> {
    floor: Option<(Span, Finalization<S, V::Commitment>)>,
    prune: Option<(Span, Height)>,
    messages: VecDeque<Message<S, V>>,
}

impl<S: Scheme, V: Variant> Default for Pending<S, V> {
    fn default() -> Self {
        Self {
            floor: None,
            prune: None,
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, V: Variant> Pending<S, V> {
    // Only prune advances are usable for height staleness checks. A pending
    // floor finalization does not carry the block height until the block is decoded.
    fn height(&self) -> Option<Height> {
        self.prune.as_ref().map(|(_, height)| *height)
    }

    fn retain(&mut self) {
        let current = self.height();
        self.messages
            .retain(|message| !message.response_closed() && !message.stale(current));
    }

    fn set_floor(&mut self, span: Span, finalization: Finalization<S, V::Commitment>) {
        let round = finalization.round();
        if self
            .floor
            .as_ref()
            .is_some_and(|(_, floor)| floor.round() >= round)
        {
            return;
        }

        self.floor = Some((span, finalization));
    }

    fn prune(&mut self, span: Span, height: Height) {
        let current = self.height();
        if current >= Some(height) {
            return;
        }

        self.prune = Some((span, height));
        self.retain();
    }

    fn drain_one<F>(&mut self, message: Message<S, V>, push: &mut F) -> bool
    where
        F: FnMut(Message<S, V>) -> Option<Message<S, V>>,
    {
        // Receiver accepted; the message is consumed
        let Some(message) = push(message) else {
            return true;
        };

        // Receiver rejected; restore so the next drain retries from the same point
        match message {
            Message::SetFloor { span, finalization } => self.set_floor(span, finalization),
            Message::Prune { span, height } => self.prune(span, height),
            message => self.messages.push_front(message),
        }
        false
    }
}

impl<S: Scheme, V: Variant> Overflow<Message<S, V>> for Pending<S, V> {
    fn is_empty(&self) -> bool {
        self.floor.is_none() && self.prune.is_none() && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, V>) -> Option<Message<S, V>>,
    {
        // Drain floor and prune first so the actor advances its floor before
        // it sees the height-bounded reads that follow
        if let Some((span, finalization)) = self.floor.take()
            && !self.drain_one(Message::SetFloor { span, finalization }, &mut push)
        {
            return;
        }
        if let Some((span, height)) = self.prune.take()
            && !self.drain_one(Message::Prune { span, height }, &mut push)
        {
            return;
        }

        // Drain the remaining queued messages in FIFO order
        while let Some(message) = self.messages.pop_front() {
            if message.response_closed() {
                continue;
            }
            if !self.drain_one(message, &mut push) {
                break;
            }
        }
    }
}

/// Coalesces `SetFloor` and `Prune`. Other overflowed messages
/// retain FIFO order.
impl<S: Scheme, V: Variant> Policy for Message<S, V> {
    type Overflow = Pending<S, V>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // A closed responder cannot be served
        if message.response_closed() {
            return;
        }
        match message {
            // Floors collapse to the highest round seen; prune collapses to
            // the highest height seen.
            Self::SetFloor { span, finalization } => {
                overflow.set_floor(span, finalization);
            }
            Self::Prune { span, height } => {
                overflow.prune(span, height);
            }
            message => {
                if message.stale(overflow.height()) {
                    return;
                }
                overflow.messages.push_back(message);
            }
        }
    }
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, V: Variant> {
    sender: Sender<Message<S, V>>,
    max_pending_acks: usize,
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: Sender<Message<S, V>>, max_pending_acks: NonZeroUsize) -> Self {
        Self {
            sender,
            max_pending_acks: max_pending_acks.get(),
        }
    }

    /// Returns the maximum number of application blocks marshal can dispatch before
    /// acknowledgements advance its processed floor.
    pub const fn max_pending_acks(&self) -> usize {
        self.max_pending_acks
    }

    /// Retrieve `(height, digest)` for a finalized block by height, digest, or latest.
    pub async fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetInfo {
            span: info_span!("marshal.mailbox.get_info"),
            identifier,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<V::Block> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetBlock {
            span: info_span!("marshal.mailbox.get_block"),
            identifier,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&self, height: Height) -> Option<Finalization<S, V::Commitment>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetFinalization {
            span: info_span!("marshal.mailbox.get_finalization", height = height.traced()),
            height,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Retrieve the latest processed height.
    pub async fn get_processed_height(&self) -> Option<Height> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetProcessedHeight {
            span: info_span!("marshal.mailbox.get_processed_height"),
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Acquire the block matching `commitment`, fetching it from peers when missing locally.
    ///
    /// Callers for the same commitment share acquisition work. Drop the receiver to cancel
    /// this caller's interest. The receiver closes without delivery if marshal shuts down.
    ///
    /// Delivery does not imply application validity or durability. Consumers that need durable,
    /// height-ordered delivery should use application dispatch.
    pub fn acquire(&self, commitment: V::Commitment) -> oneshot::Receiver<V::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Acquire {
            span: info_span!("marshal.mailbox.acquire", commitment = %commitment),
            commitment,
            response,
        });
        receiver
    }

    /// Register forward prefetch demand for `range` within a sequence of commitments.
    ///
    /// The lease retains commitment metadata. Marshal bounds the combined number of active
    /// prefetches and speculative bodies awaiting consumption. Prefetch is best effort: local
    /// availability fulfills demand. Explicit acquisitions are owned by their callers and
    /// are independent of the prefetch bound. Use [Self::acquire] to obtain a body.
    ///
    /// Keep the returned receiver alive while the demand is needed; drop it to release
    /// unused demand. The receiver does not deliver a value and should not be awaited.
    /// Empty or invalid ranges return a closed receiver.
    pub fn prefetch(
        &self,
        commitments: Arc<[V::Commitment]>,
        range: Range<usize>,
    ) -> oneshot::Receiver<()> {
        let (lease, receiver) = oneshot::channel();
        if !commitments
            .get(range.clone())
            .is_some_and(|selected| !selected.is_empty())
        {
            return receiver;
        }
        let _ = self.sender.enqueue(Message::Prefetch {
            span: info_span!("marshal.mailbox.prefetch"),
            commitments,
            range,
            lease,
        });
        receiver
    }

    /// Wait for the finalized block at `height` to become available locally.
    ///
    /// This does not initiate a network request. Drop the receiver to cancel the wait.
    /// The receiver closes without delivery if marshal shuts down or prunes the height.
    pub fn finalized(&self, height: Height) -> oneshot::Receiver<V::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::AwaitFinalized {
            span: info_span!("marshal.mailbox.finalized", height = height.traced()),
            height,
            response,
        });
        receiver
    }

    /// Returns the verified block previously persisted for `round`, if any.
    ///
    /// Multiple candidates can exist for one round (an equivocating leader can
    /// land one before a crash and another after), and this returns the first
    /// stored. Callers must not assume it is the most recently verified
    /// candidate: check context/digest before reuse, or look up by digest.
    pub async fn get_verified(&self, round: Round) -> Option<V::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetVerified {
            span: info_span!("marshal.mailbox.get_verified", round = %round),
            round,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// Requests the broadcast of a locally proposed block, persisting it after
    /// the send.
    ///
    /// The actor hands the block to the network before ingesting and persisting
    /// it, so the storage write never delays propagation. `ack` receives the
    /// durable-sync handle once the write's sync has started. The propose path
    /// stages the block (and `ack`) at propose time and calls this when consensus
    /// requests the broadcast via [`crate::Relay::broadcast`], awaiting durability
    /// only at certification so the sync overlaps consensus voting.
    ///
    /// A dropped `ack` (the mailbox is closed) abandons the handshake.
    pub fn proposed(
        &self,
        round: Round,
        block: impl Into<V::Block>,
        recipients: Recipients<S::PublicKey>,
        ack: oneshot::Sender<Handle<()>>,
    ) -> Feedback {
        self.sender.enqueue(Message::Proposed {
            span: info_span!("marshal.mailbox.proposed", round = %round),
            round,
            block: block.into(),
            recipients,
            ack,
        })
    }

    /// Notifies the actor that a block should be durably persisted at `round`,
    /// delivering its durable-sync handle through `ack` without awaiting it.
    ///
    /// Takes a sender rather than returning a receiver so certification can
    /// deliver the handle into a handshake staged at propose time. A dropped
    /// `ack` (the mailbox is closed) abandons the handshake.
    pub fn verified_deferred(
        &self,
        round: Round,
        block: impl Into<V::Block>,
        ack: oneshot::Sender<Handle<()>>,
    ) {
        let _ = self.sender.enqueue(Message::Verified {
            span: info_span!("marshal.mailbox.verified", round = %round),
            round,
            block: block.into(),
            ack,
        });
    }

    /// Notifies the actor that a block reached the verify stage.
    ///
    /// Returns after the block is durably persisted. Mirrors [Self::certified]: the
    /// durable sync is awaited on the caller's task (off the actor), so the actor
    /// never blocks on fsync.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&self, round: Round, block: impl Into<V::Block>) -> bool {
        let (ack, receiver) = oneshot::channel();
        self.verified_deferred(round, block, ack);
        let Ok(handle) = receiver.await else {
            return false;
        };
        handle.durable(round, "verified").await
    }

    /// Notifies the actor that a block reached the certify stage.
    ///
    /// Returns after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&self, round: Round, block: impl Into<V::Block>) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certified {
            span: info_span!("marshal.mailbox.certified", round = %round),
            round,
            block: block.into(),
            ack,
        });
        let Ok(handle) = receiver.await else {
            return false;
        };
        handle.durable(round, "certified").await
    }

    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances marshal's current floor, marshal
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [Self::prune] instead.
    /// Use [`crate::marshal::Config::start`] to provide the startup anchor.
    pub fn set_floor(&self, finalization: Finalization<S, V::Commitment>) {
        let _ = self.sender.enqueue(Message::SetFloor {
            span: info_span!("marshal.mailbox.set_floor", round = %finalization.round()),
            finalization,
        });
    }

    /// Requests pruning finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// Requests above marshal's current floor are ignored.
    pub fn prune(&self, height: Height) {
        let _ = self.sender.enqueue(Message::Prune {
            span: info_span!("marshal.mailbox.prune", height = height.traced()),
            height,
        });
    }

    /// Forward a locally stored block to a set of recipients.
    pub fn forward(
        &self,
        round: Round,
        commitment: V::Commitment,
        recipients: Recipients<S::PublicKey>,
    ) -> Feedback {
        self.sender.enqueue(Message::Forward {
            span: info_span!("marshal.mailbox.forward", round = %round, commitment = %commitment),
            round,
            commitment,
            recipients,
        })
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization {
                span: info_span!("marshal.mailbox.notarization", round = %notarization.round()),
                notarization,
            },
            Activity::Finalization(finalization) => Message::Finalization {
                span: info_span!("marshal.mailbox.finalization", round = %finalization.round()),
                finalization,
            },
            Activity::Certification(notarization) => Message::Certification {
                span: info_span!("marshal.mailbox.certification", round = %notarization.round()),
                notarization,
            },
            _ => return Feedback::Ok,
        };
        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Heightable,
        marshal::{mocks::harness, standard::Standard},
        simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal},
        types::{Epoch, View},
    };
    use commonware_cryptography::{Digest as _, certificate::mocks::Fixture};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{NZUsize, TestRng, channel::oneshot::error::TryRecvError};

    type TestMessage = Message<harness::S, Standard<harness::B>>;
    type TestPending = Pending<harness::S, Standard<harness::B>>;

    fn round(height: u64) -> Round {
        Round::new(Epoch::zero(), View::new(height))
    }

    fn block(height: u64) -> harness::B {
        harness::make_raw_block(harness::D::EMPTY, Height::new(height), height)
    }

    fn commitment(height: u64) -> harness::D {
        block(height).digest()
    }

    fn finalization(height: u64) -> Finalization<harness::S, harness::D> {
        let mut rng = TestRng::new(height);
        let Fixture { schemes, .. } = bls12381_threshold_vrf::fixture::<harness::V, _>(
            &mut rng,
            harness::NAMESPACE,
            harness::NUM_VALIDATORS,
        );
        let proposal = Proposal::new(round(height), View::zero(), commitment(height));
        <harness::StandardHarness as harness::TestHarness>::make_finalization(
            proposal,
            &schemes,
            harness::QUORUM,
        )
    }

    fn get_info(height: u64) -> (TestMessage, oneshot::Receiver<Option<(Height, harness::D)>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetInfo {
                span: Span::none(),
                identifier: Identifier::Height(Height::new(height)),
                response,
            },
            receiver,
        )
    }

    fn proposed(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Proposed {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                recipients: Recipients::All,
                ack,
            },
            receiver,
        )
    }

    fn verified(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Verified {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                ack,
            },
            receiver,
        )
    }

    fn certified(height: u64) -> (TestMessage, oneshot::Receiver<Handle<()>>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Certified {
                span: Span::none(),
                round: round(height),
                block: block(height).into(),
                ack,
            },
            receiver,
        )
    }

    fn get_block(height: u64) -> (TestMessage, oneshot::Receiver<Option<Arc<harness::B>>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetBlock {
                span: Span::none(),
                identifier: Identifier::Height(Height::new(height)),
                response,
            },
            receiver,
        )
    }

    fn get_finalization(
        height: u64,
    ) -> (
        TestMessage,
        oneshot::Receiver<Option<Finalization<harness::S, harness::D>>>,
    ) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetFinalization {
                span: Span::none(),
                height: Height::new(height),
                response,
            },
            receiver,
        )
    }

    fn set_floor(height: u64) -> TestMessage {
        TestMessage::SetFloor {
            span: Span::none(),
            finalization: finalization(height),
        }
    }

    fn prune(height: u64) -> TestMessage {
        TestMessage::Prune {
            span: Span::none(),
            height: Height::new(height),
        }
    }

    fn pending() -> TestPending {
        TestPending::default()
    }

    fn drain(overflow: &mut TestPending) -> VecDeque<TestMessage> {
        let mut drained = VecDeque::new();
        overflow.drain(|message| {
            drained.push_back(message);
            None
        });
        drained
    }

    fn has_get_info(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetInfo {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                } if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_block(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetBlock {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                } if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_finalization(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetFinalization {
                    height: found,
                    response,
                    ..
                } if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_block_message(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,

                    TestMessage::Proposed { block, .. }
                        | TestMessage::Verified { block, .. }
                        | TestMessage::Certified { block, .. }

                    if block.height() == Height::new(height)
            )
        })
    }

    fn has_prune(overflow: &TestPending, height: u64) -> bool {
        overflow.prune.as_ref().map(|(_, height)| *height) == Some(Height::new(height))
    }

    #[test]
    fn durable_methods_report_failure_when_mailbox_closed() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (sender, receiver) =
                commonware_actor::mailbox::new::<TestMessage>(context, NZUsize!(1));
            let mailbox = Mailbox::<harness::S, Standard<harness::B>>::new(sender, NZUsize!(1));
            drop(receiver);

            let (ack, receiver) = oneshot::channel();
            let _ = mailbox.proposed(round(1), block(1), Recipients::All, ack);
            assert!(receiver.await.is_err());
            assert!(!mailbox.verified(round(2), block(2)).await);
            assert!(!mailbox.certified(round(3), block(3)).await);
        });
    }

    #[test]
    fn policy_handles_closed_responses() {
        let mut overflow = pending();

        let (pending_closed, pending_closed_rx) = get_block(1);
        drop(pending_closed_rx);
        overflow.messages.push_back(pending_closed);

        let (pending_open, mut pending_open_rx) = get_info(2);
        overflow.messages.push_back(pending_open);

        let (current_closed, current_closed_rx) = get_finalization(3);
        drop(current_closed_rx);
        <TestMessage as Policy>::handle(&mut overflow, current_closed);

        assert!(!has_get_block(&overflow, 1));
        assert!(has_get_info(&overflow, 2));
        assert!(!has_get_finalization(&overflow, 3));
        assert!(matches!(
            pending_open_rx.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }

    #[test]
    fn policy_drain_stops_after_returned_response_closes() {
        let mut overflow = pending();
        let (first, first_rx) = get_block(1);
        let (second, mut second_rx) = get_info(2);
        overflow.messages.push_back(first);
        overflow.messages.push_back(second);

        let mut first_rx = Some(first_rx);
        let mut attempts = 0;
        overflow.drain(|message| {
            attempts += 1;
            drop(first_rx.take());
            Some(message)
        });
        assert_eq!(attempts, 1);

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 1);
        assert!(matches!(
            &drained[0],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                response,
                ..
            } if *height == Height::new(2) && !response.is_closed()
        ));
        assert!(matches!(second_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_keeps_highest_floor_and_prune() {
        let mut overflow = pending();

        <TestMessage as Policy>::handle(&mut overflow, set_floor(5));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(3));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(8));
        <TestMessage as Policy>::handle(&mut overflow, prune(4));
        <TestMessage as Policy>::handle(&mut overflow, prune(2));
        <TestMessage as Policy>::handle(&mut overflow, prune(7));

        assert_eq!(
            overflow.floor.as_ref().map(|(_, floor)| floor.round()),
            Some(round(8))
        );
        assert_eq!(
            overflow.prune.as_ref().map(|(_, height)| *height),
            Some(Height::new(7))
        );
        assert!(overflow.messages.is_empty());

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_replaces_floor_and_prune_and_drops_stale_pending_on_drain() {
        let mut overflow = pending();

        overflow.floor = Some((Span::none(), finalization(5)));
        let (get_info_4, _get_info_4_rx) = get_info(4);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        let (get_block_8, _get_block_8_rx) = get_block(8);
        overflow.messages.push_back(get_info_4);
        overflow.messages.push_back(get_block_7);
        overflow.messages.push_back(get_block_8);
        <TestMessage as Policy>::handle(&mut overflow, set_floor(8));
        <TestMessage as Policy>::handle(&mut overflow, prune(8));
        assert_eq!(
            overflow.floor.as_ref().map(|(_, floor)| floor.round()),
            Some(round(8))
        );
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_info(&overflow, 4));
        assert!(!has_get_block(&overflow, 7));
        assert!(has_get_block(&overflow, 8));
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(8)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(8)
        ));

        let mut overflow = pending();
        overflow.prune = Some((Span::none(), Height::new(5)));
        let (get_finalization_4, _get_finalization_4_rx) = get_finalization(4);
        let (get_block_6, _get_block_6_rx) = get_block(6);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        overflow.messages.push_back(get_finalization_4);
        overflow.messages.push_back(get_block_6);
        overflow.messages.push_back(get_block_7);
        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(
            overflow.prune.as_ref().map(|(_, height)| *height),
            Some(Height::new(7))
        );
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_finalization(&overflow, 4));
        assert!(!has_get_block(&overflow, 6));
        assert!(has_get_block(&overflow, 7));
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_prune_drops_closed_pending() {
        let mut overflow = pending();
        let (closed_message, closed_rx) = get_block(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_block(8);

        overflow.messages.push_back(closed_message);
        overflow.messages.push_back(open_message);

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_block(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut overflow = pending();
        let (closed_message, closed_rx) = get_finalization(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_finalization(8);

        overflow.messages.push_back(closed_message);
        overflow.messages.push_back(open_message);

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_finalization(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_skips_retain_when_prune_height_does_not_increase() {
        let mut overflow = pending();
        <TestMessage as Policy>::handle(&mut overflow, prune(10));

        let (closed_message, closed_rx) = get_block(11);
        drop(closed_rx);
        overflow.messages.push_back(closed_message);

        <TestMessage as Policy>::handle(&mut overflow, set_floor(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(12));
        assert!(overflow.messages.is_empty());
    }

    #[test]
    fn policy_drops_stale_requests_against_pending_floor_and_prune() {
        let mut overflow = pending();
        let (get_info_4, _get_info_4_rx) = get_info(4);
        let (get_info_5, _get_info_5_rx) = get_info(5);
        let (get_info_6, _get_info_6_rx) = get_info(6);
        let (get_info_7, _get_info_7_rx) = get_info(7);
        let (get_block_4, _get_block_4_rx) = get_block(4);
        let (get_block_5, _get_block_5_rx) = get_block(5);
        let (get_block_6, _get_block_6_rx) = get_block(6);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        let (get_finalization_4, _get_finalization_4_rx) = get_finalization(4);
        let (get_finalization_6, _get_finalization_6_rx) = get_finalization(6);

        <TestMessage as Policy>::handle(&mut overflow, set_floor(5));
        <TestMessage as Policy>::handle(&mut overflow, get_info_4);
        <TestMessage as Policy>::handle(&mut overflow, get_info_5);
        <TestMessage as Policy>::handle(&mut overflow, get_block_4);
        <TestMessage as Policy>::handle(&mut overflow, get_block_5);
        <TestMessage as Policy>::handle(&mut overflow, get_finalization_4);

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert!(has_prune(&overflow, 7));
        <TestMessage as Policy>::handle(&mut overflow, get_info_6);
        <TestMessage as Policy>::handle(&mut overflow, get_finalization_6);
        assert!(!has_get_finalization(&overflow, 6));
        <TestMessage as Policy>::handle(&mut overflow, get_block_6);
        <TestMessage as Policy>::handle(&mut overflow, get_info_7);
        assert!(has_get_info(&overflow, 7));
        <TestMessage as Policy>::handle(&mut overflow, get_block_7);
        assert!(has_get_block(&overflow, 7));

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 4);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { finalization, .. } if finalization.round() == round(5)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height, .. } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
        assert!(matches!(
            &drained[3],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_keeps_block_messages_and_waiters() {
        let mut overflow = pending();

        let (proposed_message, mut proposed_ack) = proposed(4);
        let (verified_message, mut verified_ack) = verified(6);
        let (certified_message, mut certified_ack) = certified(8);
        overflow.messages.push_back(proposed_message);
        overflow.messages.push_back(verified_message);
        overflow.messages.push_back(certified_message);

        <TestMessage as Policy>::handle(&mut overflow, set_floor(7));
        assert!(has_block_message(&overflow, 4));
        assert!(has_block_message(&overflow, 6));
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(proposed_ack.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(verified_ack.try_recv(), Err(TryRecvError::Empty)));
        assert!(matches!(certified_ack.try_recv(), Err(TryRecvError::Empty)));

        <TestMessage as Policy>::handle(&mut overflow, prune(9));
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(certified_ack.try_recv(), Err(TryRecvError::Empty)));

        let (stale, mut stale_ack) = proposed(8);
        <TestMessage as Policy>::handle(&mut overflow, stale);
        assert!(has_block_message(&overflow, 8));
        assert!(matches!(stale_ack.try_recv(), Err(TryRecvError::Empty)));

        let (current, mut current_ack) = verified(9);
        <TestMessage as Policy>::handle(&mut overflow, current);
        assert!(has_block_message(&overflow, 9));
        assert!(matches!(current_ack.try_recv(), Err(TryRecvError::Empty)));

        let drained = drain(&mut overflow);
        assert!(matches!(drained[0], TestMessage::SetFloor { .. }));
        assert!(matches!(drained[1], TestMessage::Prune { .. }));
    }

    #[test]
    fn acquisition_fifo_survives_pruning_and_skips_canceled_callers() {
        let mut overflow = pending();
        let (first_response, mut first_receiver) = oneshot::channel();
        let (closed_response, closed_receiver) = oneshot::channel();
        let (last_response, mut last_receiver) = oneshot::channel();
        for (height, response) in [
            (1, first_response),
            (2, closed_response),
            (3, last_response),
        ] {
            <TestMessage as Policy>::handle(
                &mut overflow,
                TestMessage::Acquire {
                    span: Span::none(),
                    commitment: commitment(height),
                    response,
                },
            );
        }
        drop(closed_receiver);
        <TestMessage as Policy>::handle(&mut overflow, prune(10));
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(drained[0], TestMessage::Prune { .. }));
        assert!(
            matches!(drained[1], TestMessage::Acquire { commitment: found, .. } if found == commitment(1))
        );
        assert!(
            matches!(drained[2], TestMessage::Acquire { commitment: found, .. } if found == commitment(3))
        );
        assert!(matches!(
            first_receiver.try_recv(),
            Err(TryRecvError::Empty)
        ));
        assert!(matches!(last_receiver.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn finalized_body_waits_obey_pruning_and_cancellation() {
        let mut overflow = pending();
        let (stale_response, mut stale_receiver) = oneshot::channel();
        let (closed_response, closed_receiver) = oneshot::channel();
        let (current_response, mut current_receiver) = oneshot::channel();
        for (height, response) in [
            (4, stale_response),
            (5, closed_response),
            (5, current_response),
        ] {
            <TestMessage as Policy>::handle(
                &mut overflow,
                TestMessage::AwaitFinalized {
                    span: Span::none(),
                    height: Height::new(height),
                    response,
                },
            );
        }
        drop(closed_receiver);
        <TestMessage as Policy>::handle(&mut overflow, prune(5));
        assert!(matches!(
            stale_receiver.try_recv(),
            Err(TryRecvError::Closed)
        ));
        assert!(matches!(
            current_receiver.try_recv(),
            Err(TryRecvError::Empty)
        ));
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(
            matches!(drained[1], TestMessage::AwaitFinalized { height, .. } if height == Height::new(5))
        );
    }
}
