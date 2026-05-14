use super::Variant;
use crate::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider},
        Identifier,
    },
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
    Reporter,
};
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::{channel::oneshot, vec::NonEmptyVec};
use std::collections::{btree_map::Entry, BTreeMap, VecDeque};

/// Messages sent to the marshal [Actor](super::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme, V: Variant> {
    /// A request to retrieve the `(height, digest)` of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
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
        /// The identifier of the block to retrieve.
        identifier: Identifier<<V::Block as Digestible>::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The height of the finalization to retrieve.
        height: Height,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, V::Commitment>>>,
    },
    /// A hint that a finalized block may be available at a given height.
    ///
    /// This triggers a network fetch if the finalization is not available locally.
    /// This is fire-and-forget: the finalization will be stored in marshal and
    /// delivered via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    ///
    /// Targets are required because this is typically called when a peer claims to
    /// be ahead. If a target returns invalid data, the resolver will block them.
    /// Sending this message multiple times with different targets adds to the
    /// target set.
    HintFinalized {
        /// The height of the finalization to fetch.
        height: Height,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    },
    /// A request to subscribe to a block by its digest.
    SubscribeByDigest {
        /// The round in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The digest of the block to retrieve.
        digest: <V::Block as Digestible>::Digest,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<V::Block>,
    },
    /// A request to subscribe to a block by its commitment.
    SubscribeByCommitment {
        /// The round in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The commitment of the block to retrieve.
        commitment: V::Commitment,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<V::Block>,
    },
    /// A request to retrieve the verified block previously persisted for `round`.
    GetVerified {
        /// The round to query.
        round: Round,
        /// A channel to send the retrieved block, if any.
        response: oneshot::Sender<Option<V::Block>>,
    },
    /// A request to forward a block to a set of recipients.
    Forward {
        /// The round in which the block was proposed.
        round: Round,
        /// The commitment of the block to forward.
        commitment: V::Commitment,
        /// The recipients to forward the block to.
        recipients: Recipients<S::PublicKey>,
    },
    /// A notification that a block has been locally proposed by this node.
    Proposed {
        /// The round in which the block was proposed.
        round: Round,
        /// The proposed block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },
    /// A notification that a block has been certified by the application.
    Certified {
        /// The round in which the block was certified.
        round: Round,
        /// The certified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },
    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Message::Prune] instead.
    ///
    /// The default floor is 0.
    SetFloor {
        /// The candidate floor height.
        height: Height,
    },
    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Message::SetFloor], this does not affect the sync starting point.
    /// Callers must only prune at or below marshal's current floor
    /// (`last_processed_height`).
    Prune {
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    },
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<S, V::Commitment>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<S, V::Commitment>,
    },
}

impl<S: Scheme, V: Variant> Message<S, V> {
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
            | Self::GetFinalization { height, .. } => Some(*height) < current,
            // Hints only inform the actor about heights strictly above the floor
            Self::HintFinalized { height, .. } => Some(*height) <= current,
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
            } => false,
            Self::SubscribeByDigest { .. }
            | Self::SubscribeByCommitment { .. }
            | Self::GetVerified { .. }
            | Self::Forward { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }

    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetInfo { response, .. } => response.is_closed(),
            Self::GetBlock { response, .. } | Self::GetVerified { response, .. } => {
                response.is_closed()
            }
            Self::GetFinalization { response, .. } => response.is_closed(),
            Self::SubscribeByDigest { response, .. }
            | Self::SubscribeByCommitment { response, .. } => response.is_closed(),
            Self::HintFinalized { .. }
            | Self::Forward { .. }
            | Self::Proposed { .. }
            | Self::Verified { .. }
            | Self::Certified { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }
}

pub(crate) struct Pending<S: Scheme, V: Variant> {
    floor: Option<Height>,
    prune: Option<Height>,
    hints: BTreeMap<Height, NonEmptyVec<S::PublicKey>>,
    messages: VecDeque<PendingMessage<S, V>>,
}

enum PendingMessage<S: Scheme, V: Variant> {
    Message(Message<S, V>),
    HintFinalized(Height),
}

impl<S: Scheme, V: Variant> Default for Pending<S, V> {
    fn default() -> Self {
        Self {
            floor: None,
            prune: None,
            hints: BTreeMap::new(),
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme, V: Variant> Pending<S, V> {
    // The effective floor for staleness checks is the max of both pending advances
    fn height(&self) -> Option<Height> {
        self.floor.into_iter().chain(self.prune).max()
    }

    fn retain(&mut self) {
        let current = self.height();
        self.hints.retain(|height, _| Some(*height) > current);

        let hints = &self.hints;
        self.messages.retain(|message| match message {
            PendingMessage::Message(message) => {
                !message.response_closed() && !message.stale(current)
            }
            PendingMessage::HintFinalized(height) => hints.contains_key(height),
        });
    }

    fn set_floor(&mut self, height: Height) {
        let current = self.height();
        let floor = Some(height);
        if self.floor >= floor {
            return;
        }

        self.floor = self.floor.max(floor);
        if self.height() > current {
            self.retain();
        }
    }

    fn prune(&mut self, height: Height) {
        let current = self.height();
        let prune = Some(height);
        if self.prune >= prune {
            return;
        }

        self.prune = self.prune.max(prune);
        if self.height() > current {
            self.retain();
        }
    }

    fn extend_hint_targets(
        pending: &mut NonEmptyVec<S::PublicKey>,
        targets: NonEmptyVec<S::PublicKey>,
    ) {
        for target in targets {
            if !pending.contains(&target) {
                pending.push(target);
            }
        }
    }

    fn hint_finalized(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        // Hint is already covered by floor/prune
        let current = self.height();
        if current.is_some_and(|current| height <= current) {
            return;
        }

        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert(targets);
                self.messages
                    .push_back(PendingMessage::HintFinalized(height));
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(entry.get_mut(), targets);
            }
        }
    }

    fn restore_hint(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert(targets);
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(entry.get_mut(), targets);
            }
        }
        self.messages
            .push_front(PendingMessage::HintFinalized(height));
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
            Message::SetFloor { height } => self.set_floor(height),
            Message::Prune { height } => self.prune(height),
            Message::HintFinalized { height, targets } => self.restore_hint(height, targets),
            message => self.messages.push_front(PendingMessage::Message(message)),
        }
        false
    }
}

impl<S: Scheme, V: Variant> Overflow<Message<S, V>> for Pending<S, V> {
    fn is_empty(&self) -> bool {
        self.floor.is_none()
            && self.prune.is_none()
            && self.hints.is_empty()
            && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, V>) -> Option<Message<S, V>>,
    {
        // Drain floor and prune first so the actor advances its floor before
        // it sees the height-bounded reads that follow
        if let Some(height) = self.floor.take() {
            if !self.drain_one(Message::SetFloor { height }, &mut push) {
                return;
            }
        }
        if let Some(height) = self.prune.take() {
            if !self.drain_one(Message::Prune { height }, &mut push) {
                return;
            }
        }

        // Drain the remaining queued messages in FIFO order
        let height = self.height();
        while let Some(pending) = self.messages.pop_front() {
            match pending {
                PendingMessage::Message(message) => {
                    if message.response_closed() || message.stale(height) {
                        continue;
                    }
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
                PendingMessage::HintFinalized(hint_height) => {
                    if Some(hint_height) <= height {
                        self.hints.remove(&hint_height);
                        continue;
                    }
                    let Some(targets) = self.hints.remove(&hint_height) else {
                        continue;
                    };
                    let message = Message::HintFinalized {
                        height: hint_height,
                        targets,
                    };
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
            }
        }
    }
}

impl<S: Scheme, V: Variant> Policy for Message<S, V> {
    type Overflow = Pending<S, V>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // A closed responder cannot be served
        if message.response_closed() {
            return;
        }
        match message {
            // Coalesce hints: a single entry per height with a unioned target set
            Self::HintFinalized { height, targets } => {
                overflow.hint_finalized(height, targets);
            }
            // Floor and prune collapse to the highest height seen
            Self::SetFloor { height } => {
                overflow.set_floor(height);
            }
            Self::Prune { height } => {
                overflow.prune(height);
            }
            // Queue if the new message is still useful
            message => {
                if message.stale(overflow.height()) {
                    return;
                }
                overflow
                    .messages
                    .push_back(PendingMessage::Message(message));
            }
        }
    }
}

/// A mailbox for sending messages to the marshal [Actor](super::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme, V: Variant> {
    sender: Sender<Message<S, V>>,
}

impl<S: Scheme, V: Variant> Mailbox<S, V> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetInfo {
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
            identifier,
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&self, height: Height) -> Option<Finalization<S, V::Commitment>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetFinalization { height, response });
        receiver.await.ok().flatten()
    }

    /// Hints that a finalized block may be available at the given height.
    ///
    /// This method will request the finalization from the network via the resolver
    /// if it is not available locally.
    ///
    /// Targets are required because this is typically called when a peer claims to be
    /// ahead. By targeting only those peers, we limit who we ask. If a target returns
    /// invalid data, they will be blocked by the resolver. If targets don't respond
    /// or return "no data", they effectively rate-limit themselves.
    ///
    /// Calling this multiple times for the same height with different targets will
    /// add to the target set if there is an ongoing fetch, allowing more peers to be tried.
    ///
    /// This is fire-and-forget: the finalization will be stored in marshal and delivered
    /// via the normal finalization flow when available.
    ///
    /// The height must be covered by both the epocher and the provider. If the
    /// epocher cannot map the height to an epoch, or the provider cannot supply
    /// a scheme for that epoch, the hint is silently dropped.
    pub fn hint_finalized(&self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        let _ = self
            .sender
            .enqueue(Message::HintFinalized { height, targets });
    }

    /// Subscribe to a block by its digest.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub fn subscribe_by_digest(
        &self,
        round: Option<Round>,
        digest: <V::Block as Digestible>::Digest,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByDigest {
            round,
            digest,
            response: tx,
        });
        rx
    }

    /// Subscribe to a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub fn subscribe_by_commitment(
        &self,
        round: Option<Round>,
        commitment: V::Commitment,
    ) -> oneshot::Receiver<V::Block> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::SubscribeByCommitment {
            round,
            commitment,
            response: tx,
        });
        rx
    }

    /// Returns an [AncestorStream] over the ancestry of a given block, leading up to genesis.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry(
        &self,
        (start_round, start_digest): (Option<Round>, <V::Block as Digestible>::Digest),
    ) -> Option<AncestorStream<Self, V::ApplicationBlock>> {
        let mailbox = self.clone();
        let subscription = self.subscribe_by_digest(start_round, start_digest);
        subscription
            .await
            .ok()
            .map(|block| AncestorStream::new(mailbox, [V::into_inner(block)]))
    }

    /// Returns the verified block previously persisted for `round`, if any.
    pub async fn get_verified(&self, round: Round) -> Option<V::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetVerified { round, response });
        receiver.await.ok().flatten()
    }

    /// Notifies the actor that a block has been locally proposed.
    ///
    /// Returns after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn proposed(&self, round: Round, block: V::Block) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Proposed {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Notifies the actor that a block has been verified.
    ///
    /// Returns after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&self, round: Round, block: V::Block) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Verified {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Notifies the actor that a block has been certified.
    ///
    /// Returns after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&self, round: Round, block: V::Block) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certified {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Sets the sync starting point (advances if higher than current).
    ///
    /// Marshal will sync and deliver blocks starting at `floor + 1`. Data below
    /// the floor is pruned.
    ///
    /// To prune data without affecting the sync starting point (say at some trailing depth
    /// from tip), use [Self::prune] instead.
    ///
    /// The default floor is 0.
    pub fn set_floor(&self, height: Height) {
        let _ = self.sender.enqueue(Message::SetFloor { height });
    }

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Self::set_floor], this does not affect the sync starting point.
    /// Callers must only prune at or below marshal's current floor
    /// (`last_processed_height`).
    pub fn prune(&self, height: Height) {
        let _ = self.sender.enqueue(Message::Prune { height });
    }

    /// Forward a block to a set of recipients.
    pub fn forward(
        &self,
        round: Round,
        commitment: V::Commitment,
        recipients: Recipients<S::PublicKey>,
    ) {
        let _ = self.sender.enqueue(Message::Forward {
            round,
            commitment,
            recipients,
        });
    }
}

impl<S: Scheme, V: Variant> BlockProvider for Mailbox<S, V> {
    type Block = V::ApplicationBlock;

    async fn fetch_block(self, digest: <V::Block as Digestible>::Digest) -> Option<Self::Block> {
        self.subscribe_by_digest(None, digest)
            .await
            .ok()
            .map(V::into_inner)
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => return Feedback::Ok,
        };
        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{mocks::harness, standard::Standard},
        types::{Epoch, View},
        Heightable,
    };
    use commonware_cryptography::{ed25519::PrivateKey, Digest as _, Signer as _};
    use commonware_utils::channel::oneshot::error::TryRecvError;

    type TestMessage = Message<harness::S, Standard<harness::B>>;
    type TestPending = Pending<harness::S, Standard<harness::B>>;

    fn public_key(seed: u64) -> harness::K {
        PrivateKey::from_seed(seed).public_key()
    }

    fn round(height: u64) -> Round {
        Round::new(Epoch::zero(), View::new(height))
    }

    fn block(height: u64) -> harness::B {
        harness::make_raw_block(harness::D::EMPTY, Height::new(height), height)
    }

    fn get_info(height: u64) -> (TestMessage, oneshot::Receiver<Option<(Height, harness::D)>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetInfo {
                identifier: Identifier::Height(Height::new(height)),
                response,
            },
            receiver,
        )
    }

    fn proposed(height: u64) -> (TestMessage, oneshot::Receiver<()>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Proposed {
                round: round(height),
                block: block(height),
                ack: Some(ack),
            },
            receiver,
        )
    }

    fn verified(height: u64) -> (TestMessage, oneshot::Receiver<()>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Verified {
                round: round(height),
                block: block(height),
                ack: Some(ack),
            },
            receiver,
        )
    }

    fn certified(height: u64) -> (TestMessage, oneshot::Receiver<()>) {
        let (ack, receiver) = oneshot::channel();
        (
            TestMessage::Certified {
                round: round(height),
                block: block(height),
                ack: Some(ack),
            },
            receiver,
        )
    }

    fn get_block(height: u64) -> (TestMessage, oneshot::Receiver<Option<harness::B>>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::GetBlock {
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
                height: Height::new(height),
                response,
            },
            receiver,
        )
    }

    fn subscribe_by_digest(height: u64) -> (TestMessage, oneshot::Receiver<harness::B>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::SubscribeByDigest {
                round: Some(round(height)),
                digest: block(height).digest(),
                response,
            },
            receiver,
        )
    }

    fn subscribe_by_commitment(height: u64) -> (TestMessage, oneshot::Receiver<harness::B>) {
        let (response, receiver) = oneshot::channel();
        (
            TestMessage::SubscribeByCommitment {
                round: Some(round(height)),
                commitment: block(height).digest(),
                response,
            },
            receiver,
        )
    }

    fn hint_finalized(height: u64, target: harness::K) -> TestMessage {
        TestMessage::HintFinalized {
            height: Height::new(height),
            targets: NonEmptyVec::new(target),
        }
    }

    fn set_floor(height: u64) -> TestMessage {
        TestMessage::SetFloor {
            height: Height::new(height),
        }
    }

    fn prune(height: u64) -> TestMessage {
        TestMessage::Prune {
            height: Height::new(height),
        }
    }

    fn pending() -> TestPending {
        TestPending::default()
    }

    fn drain(overflow: &mut TestPending) -> VecDeque<TestMessage> {
        let mut drained = VecDeque::new();
        while !overflow.is_empty() {
            overflow.drain(|message| {
                drained.push_back(message);
                None
            });
        }
        drained
    }

    fn has_get_info(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetInfo {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_block(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetBlock {
                    identifier: Identifier::Height(found),
                    response,
                    ..
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn has_get_finalization(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::GetFinalization {
                    height: found,
                    response,
                }) if *found == Height::new(height) && !response.is_closed()
            )
        })
    }

    fn hint_targets(overflow: &TestPending, height: u64) -> Option<&NonEmptyVec<harness::K>> {
        overflow.hints.get(&Height::new(height))
    }

    fn has_block_message(overflow: &TestPending, height: u64) -> bool {
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(
                    TestMessage::Proposed { block, .. }
                        | TestMessage::Verified { block, .. }
                        | TestMessage::Certified { block, .. }
                )
                    if block.height() == Height::new(height)
            )
        })
    }

    fn has_prune(overflow: &TestPending, height: u64) -> bool {
        overflow.prune == Some(Height::new(height))
    }

    fn has_subscription(overflow: &TestPending, height: u64) -> bool {
        let expected = block(height).digest();
        overflow.messages.iter().any(|message| {
            matches!(
                message,
                PendingMessage::Message(TestMessage::SubscribeByDigest { digest, response, .. })
                    if *digest == expected && !response.is_closed()
            ) || matches!(
                message,
                PendingMessage::Message(TestMessage::SubscribeByCommitment {
                    commitment,
                    response,
                    ..
                }) if *commitment == expected && !response.is_closed()
            )
        })
    }

    #[test]
    fn policy_coalesces_hint_targets() {
        let mut overflow = pending();
        let first = public_key(1);
        let second = public_key(2);

        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, second.clone()));

        assert_eq!(overflow.messages.len(), 1);
        let targets = hint_targets(&overflow, 10).expect("expected hint");
        assert_eq!(targets.len().get(), 2);
        assert!(targets.contains(&first));
        assert!(targets.contains(&second));
    }

    #[test]
    fn policy_drops_closed_subscriptions() {
        let mut overflow = pending();

        let (pending_closed, pending_closed_rx) = subscribe_by_digest(1);
        drop(pending_closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_closed));

        let (pending_open, mut pending_open_rx) = subscribe_by_commitment(2);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_open));

        let (current_closed, current_closed_rx) = subscribe_by_digest(3);
        drop(current_closed_rx);
        <TestMessage as Policy>::handle(&mut overflow, current_closed);

        assert!(!has_subscription(&overflow, 1));
        assert!(has_subscription(&overflow, 2));
        assert!(!has_subscription(&overflow, 3));
        assert!(matches!(
            pending_open_rx.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }

    #[test]
    fn policy_drops_closed_responses() {
        let mut overflow = pending();

        let (pending_closed, pending_closed_rx) = get_block(1);
        drop(pending_closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_closed));

        let (pending_open, mut pending_open_rx) = get_info(2);
        overflow
            .messages
            .push_back(PendingMessage::Message(pending_open));

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
        overflow.messages.push_back(PendingMessage::Message(first));
        overflow.messages.push_back(PendingMessage::Message(second));

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
            } if *height == Height::new(2) && !response.is_closed()
        ));
        assert!(matches!(second_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_keeps_coalesced_hints_in_fifo_position() {
        let mut overflow = pending();
        let first = public_key(1);
        let second = public_key(2);
        let (get_block_9, _get_block_9_rx) = get_block(9);
        let (get_info_11, _get_info_11_rx) = get_info(11);

        <TestMessage as Policy>::handle(&mut overflow, get_block_9);
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, first.clone()));
        <TestMessage as Policy>::handle(&mut overflow, get_info_11);
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(10, second.clone()));

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 3);
        assert!(matches!(
            &drained[0],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(9)
        ));
        assert!(matches!(
            &drained[2],
            TestMessage::GetInfo {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(11)
        ));
        let TestMessage::HintFinalized { height, targets } = &drained[1] else {
            panic!("expected hint");
        };
        assert_eq!(*height, Height::new(10));
        assert_eq!(targets.len().get(), 2);
        assert!(targets.contains(&first));
        assert!(targets.contains(&second));
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

        assert_eq!(overflow.floor, Some(Height::new(8)));
        assert_eq!(overflow.prune, Some(Height::new(7)));
        assert!(overflow.messages.is_empty());

        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { height } if *height == Height::new(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_replaces_floor_and_prune_and_drops_stale_pending_on_drain() {
        let mut overflow = pending();

        overflow.floor = Some(Height::new(5));
        let (get_info_4, _get_info_4_rx) = get_info(4);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        let (get_block_8, _get_block_8_rx) = get_block(8);
        overflow
            .messages
            .push_back(PendingMessage::Message(get_info_4));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_7));
        overflow.hint_finalized(Height::new(8), NonEmptyVec::new(public_key(1)));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_8));
        <TestMessage as Policy>::handle(&mut overflow, set_floor(8));
        assert_eq!(overflow.floor, Some(Height::new(8)));
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_info(&overflow, 4));
        assert!(!has_get_block(&overflow, 7));
        assert!(has_get_block(&overflow, 8));
        assert!(hint_targets(&overflow, 8).is_none());
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::SetFloor { height } if *height == Height::new(8)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::GetBlock {
                identifier: Identifier::Height(height),
                ..
            } if *height == Height::new(8)
        ));

        let mut overflow = pending();
        overflow.prune = Some(Height::new(5));
        let (get_finalization_4, _get_finalization_4_rx) = get_finalization(4);
        let (get_block_6, _get_block_6_rx) = get_block(6);
        let (get_block_7, _get_block_7_rx) = get_block(7);
        overflow
            .messages
            .push_back(PendingMessage::Message(get_finalization_4));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_6));
        overflow.hint_finalized(Height::new(6), NonEmptyVec::new(public_key(2)));
        overflow
            .messages
            .push_back(PendingMessage::Message(get_block_7));
        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.prune, Some(Height::new(7)));
        assert_eq!(overflow.messages.len(), 1);
        assert!(!has_get_finalization(&overflow, 4));
        assert!(!has_get_block(&overflow, 6));
        assert!(has_get_block(&overflow, 7));
        assert!(hint_targets(&overflow, 6).is_none());
        let drained = drain(&mut overflow);
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            &drained[0],
            TestMessage::Prune { height } if *height == Height::new(7)
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
    fn policy_floor_and_prune_drop_closed_pending() {
        let mut overflow = pending();
        let (closed_message, closed_rx) = get_block(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_block(8);

        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(open_message));

        <TestMessage as Policy>::handle(&mut overflow, set_floor(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_block(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));

        let mut overflow = pending();
        let (closed_message, closed_rx) = get_finalization(8);
        drop(closed_rx);
        let (open_message, mut open_rx) = get_finalization(8);

        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(open_message));

        <TestMessage as Policy>::handle(&mut overflow, prune(7));
        assert_eq!(overflow.messages.len(), 1);
        assert!(has_get_finalization(&overflow, 8));
        assert!(matches!(open_rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn policy_skips_retain_when_effective_height_does_not_increase() {
        let mut overflow = pending();
        <TestMessage as Policy>::handle(&mut overflow, set_floor(10));

        let (closed_message, closed_rx) = get_block(11);
        drop(closed_rx);
        overflow
            .messages
            .push_back(PendingMessage::Message(closed_message));

        <TestMessage as Policy>::handle(&mut overflow, set_floor(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(9));
        assert_eq!(overflow.messages.len(), 1);

        <TestMessage as Policy>::handle(&mut overflow, prune(12));
        assert!(overflow.messages.is_empty());
    }

    #[test]
    fn policy_drops_stale_requests_during_drain_after_prior_floor_and_prune() {
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
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(5, public_key(1)));
        <TestMessage as Policy>::handle(&mut overflow, hint_finalized(6, public_key(2)));

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
            TestMessage::SetFloor { height } if *height == Height::new(5)
        ));
        assert!(matches!(
            &drained[1],
            TestMessage::Prune { height } if *height == Height::new(7)
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
        overflow
            .messages
            .push_back(PendingMessage::Message(proposed_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(verified_message));
        overflow
            .messages
            .push_back(PendingMessage::Message(certified_message));

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
}
