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
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::{channel::oneshot, vec::NonEmptyVec};
use std::{collections::VecDeque, future::Future};

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
        ack: oneshot::Sender<()>,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: oneshot::Sender<()>,
    },
    /// A notification that a block has been certified by the application.
    Certified {
        /// The round in which the block was certified.
        round: Round,
        /// The certified block.
        block: V::Block,
        /// A channel signaled once the block is durably stored.
        ack: oneshot::Sender<()>,
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
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
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

#[derive(Clone, Copy, Default)]
struct Cutoff {
    height: Option<Height>,
}

impl Cutoff {
    const fn new(height: Height) -> Self {
        Self {
            height: Some(height),
        }
    }

    fn update_max_height(max: &mut Option<Height>, height: Height) {
        if max.is_none_or(|current| height > current) {
            *max = Some(height);
        }
    }

    fn observe<S: Scheme, V: Variant>(&mut self, message: &Message<S, V>) {
        match message {
            Message::SetFloor { height } | Message::Prune { height } => {
                Self::update_max_height(&mut self.height, *height);
            }
            _ => {}
        }
    }

    fn drops_below(self, height: Height) -> bool {
        self.height.is_some_and(|cutoff| height < cutoff)
    }

    fn drops_at_or_below(self, height: Height) -> bool {
        self.height.is_some_and(|cutoff| height <= cutoff)
    }
}

impl<S: Scheme, V: Variant> Message<S, V> {
    fn stale(&self, cutoff: Cutoff) -> bool {
        match self {
            Self::GetInfo {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetBlock {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetFinalization { height, .. } => cutoff.drops_below(*height),
            Self::HintFinalized { height, .. } => cutoff.drops_at_or_below(*height),
            Self::GetBlock {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetInfo {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            } => false,
            _ => false,
        }
    }
}

impl<S: Scheme, V: Variant> Policy for Message<S, V> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            Self::HintFinalized { height, targets } => {
                let mut cutoff = Cutoff::default();
                let mut pending_targets = Some(targets);

                // Coalesce same-height hints into one request with all known targets.
                for message in overflow.iter_mut() {
                    cutoff.observe(message);
                    if cutoff.drops_at_or_below(height) {
                        return false;
                    }

                    if let Self::HintFinalized {
                        height: existing_height,
                        targets: existing_targets,
                    } = message
                    {
                        if *existing_height != height {
                            continue;
                        }

                        for target in pending_targets.take().expect("targets must be present") {
                            if !existing_targets.contains(&target) {
                                existing_targets.push(target);
                            }
                        }
                        return true;
                    }
                }

                let targets = pending_targets.expect("targets must be present");
                let message = Self::HintFinalized { height, targets };
                if message.stale(cutoff) {
                    return false;
                }
                overflow.push_back(message);
            }
            Self::SetFloor { height } => {
                let mut cutoff = Cutoff::new(height);
                let mut append = true;

                // Use the incoming floor to drop obsolete work before appending it.
                overflow.retain_mut(|message| {
                    let keep = match message {
                        Self::SetFloor {
                            height: existing_height,
                        } => {
                            if height > *existing_height {
                                false
                            } else {
                                append = false;
                                true
                            }
                        }
                        _ => true,
                    };
                    if !keep {
                        return false;
                    }

                    cutoff.observe(message);
                    !message.stale(cutoff)
                });

                if append {
                    overflow.push_back(Self::SetFloor { height });
                }
            }
            Self::Prune { height } => {
                let mut cutoff = Cutoff::new(height);
                let mut append = true;

                // Use the incoming prune to drop obsolete work before appending it.
                overflow.retain_mut(|message| {
                    let keep = match message {
                        Self::Prune {
                            height: existing_height,
                        } => {
                            if height > *existing_height {
                                false
                            } else {
                                append = false;
                                true
                            }
                        }
                        _ => true,
                    };
                    if !keep {
                        return false;
                    }

                    cutoff.observe(message);
                    !message.stale(cutoff)
                });

                if append {
                    overflow.push_back(Self::Prune { height });
                }
            }
            message => {
                let mut cutoff = Cutoff::default();
                if overflow.iter().any(|existing| {
                    cutoff.observe(existing);
                    message.stale(cutoff)
                }) {
                    return false;
                }

                // Preserve ordinary FIFO overflow behavior for other messages.
                overflow.push_back(message);
            }
        }

        true
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
    pub fn get_info(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> oneshot::Receiver<Option<(Height, <V::Block as Digestible>::Digest)>> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetInfo {
            identifier,
            response,
        });
        receiver
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub fn get_block(
        &self,
        identifier: impl Into<Identifier<<V::Block as Digestible>::Digest>>,
    ) -> oneshot::Receiver<Option<V::Block>> {
        let identifier = identifier.into();
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetBlock {
            identifier,
            response,
        });
        receiver
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub fn get_finalization(
        &self,
        height: Height,
    ) -> oneshot::Receiver<Option<Finalization<S, V::Commitment>>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetFinalization { height, response });
        receiver
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
    pub fn ancestry(
        &self,
        (start_round, start_digest): (Option<Round>, <V::Block as Digestible>::Digest),
    ) -> impl Future<Output = Option<AncestorStream<Self, V::ApplicationBlock>>> + '_ {
        let subscription = self.subscribe_by_digest(start_round, start_digest);
        let mailbox = self.clone();
        async move {
            subscription
                .await
                .ok()
                .map(|block| AncestorStream::new(mailbox, [V::into_inner(block)]))
        }
    }

    /// Returns the verified block previously persisted for `round`, if any.
    pub fn get_verified(&self, round: Round) -> oneshot::Receiver<Option<V::Block>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetVerified { round, response });
        receiver
    }

    /// Notifies the actor that a block has been locally proposed.
    ///
    /// The returned receiver resolves after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub fn proposed(&self, round: Round, block: V::Block) -> oneshot::Receiver<()> {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Proposed { round, block, ack });
        receiver
    }

    /// Notifies the actor that a block has been verified.
    ///
    /// The returned receiver resolves after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub fn verified(&self, round: Round, block: V::Block) -> oneshot::Receiver<()> {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Verified { round, block, ack });
        receiver
    }

    /// Notifies the actor that a block has been certified.
    ///
    /// The returned receiver resolves after the block is durably persisted.
    #[must_use = "callers must consider block durability before proceeding"]
    pub fn certified(&self, round: Round, block: V::Block) -> oneshot::Receiver<()> {
        let (ack, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::Certified { round, block, ack });
        receiver
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
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    ///
    /// A `prune` request for a height above marshal's current floor is dropped.
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

    fn fetch_block(
        self,
        digest: <V::Block as Digestible>::Digest,
    ) -> impl Future<Output = Option<Self::Block>> + Send {
        let subscription = self.subscribe_by_digest(None, digest);
        async move { subscription.await.ok().map(V::into_inner) }
    }
}

impl<S: Scheme, V: Variant> Reporter for Mailbox<S, V> {
    type Activity = Activity<S, V::Commitment>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => {
                // Ignore other activity types
                return Feedback::Ok;
            }
        };
        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{mocks::harness, standard::Standard};
    use commonware_cryptography::{ed25519::PrivateKey, Signer as _};

    type TestMessage = Message<harness::S, Standard<harness::B>>;

    fn public_key(seed: u64) -> harness::K {
        PrivateKey::from_seed(seed).public_key()
    }

    fn get_info(height: u64) -> TestMessage {
        let (response, _) = oneshot::channel();
        TestMessage::GetInfo {
            identifier: Identifier::Height(Height::new(height)),
            response,
        }
    }

    fn get_block(height: u64) -> TestMessage {
        let (response, _) = oneshot::channel();
        TestMessage::GetBlock {
            identifier: Identifier::Height(Height::new(height)),
            response,
        }
    }

    fn get_finalization(height: u64) -> TestMessage {
        let (response, _) = oneshot::channel();
        TestMessage::GetFinalization {
            height: Height::new(height),
            response,
        }
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

    fn has_get_info(overflow: &VecDeque<TestMessage>, height: u64) -> bool {
        overflow.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetInfo {
                    identifier: Identifier::Height(found),
                    ..
                } if *found == Height::new(height)
            )
        })
    }

    fn has_get_block(overflow: &VecDeque<TestMessage>, height: u64) -> bool {
        overflow.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetBlock {
                    identifier: Identifier::Height(found),
                    ..
                } if *found == Height::new(height)
            )
        })
    }

    fn has_get_finalization(overflow: &VecDeque<TestMessage>, height: u64) -> bool {
        overflow.iter().any(|message| {
            matches!(
                message,
                TestMessage::GetFinalization { height: found, .. }
                    if *found == Height::new(height)
            )
        })
    }

    fn has_hint(overflow: &VecDeque<TestMessage>, height: u64) -> bool {
        overflow.iter().any(|message| {
            matches!(
                message,
                TestMessage::HintFinalized { height: found, .. }
                    if *found == Height::new(height)
            )
        })
    }

    fn has_prune(overflow: &VecDeque<TestMessage>, height: u64) -> bool {
        overflow.iter().any(|message| {
            matches!(
                message,
                TestMessage::Prune { height: found } if *found == Height::new(height)
            )
        })
    }

    #[test]
    fn policy_coalesces_hint_targets() {
        let mut overflow = VecDeque::new();
        let first = public_key(1);
        let second = public_key(2);

        assert!(<TestMessage as Policy>::handle(
            &mut overflow,
            hint_finalized(10, first.clone())
        ));
        assert!(<TestMessage as Policy>::handle(
            &mut overflow,
            hint_finalized(10, first.clone())
        ));
        assert!(<TestMessage as Policy>::handle(
            &mut overflow,
            hint_finalized(10, second.clone())
        ));

        assert_eq!(overflow.len(), 1);
        let TestMessage::HintFinalized { height, targets } = &overflow[0] else {
            panic!("expected hint");
        };
        assert_eq!(*height, Height::new(10));
        assert_eq!(targets.len().get(), 2);
        assert!(targets.contains(&first));
        assert!(targets.contains(&second));
    }

    #[test]
    fn policy_keeps_highest_floor_and_prune() {
        let mut overflow = VecDeque::new();

        assert!(<TestMessage as Policy>::handle(&mut overflow, set_floor(5)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, set_floor(3)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, set_floor(8)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, prune(4)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, prune(2)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, prune(7)));

        assert_eq!(overflow.len(), 2);
        assert!(matches!(
            &overflow[0],
            TestMessage::SetFloor { height } if *height == Height::new(8)
        ));
        assert!(matches!(
            &overflow[1],
            TestMessage::Prune { height } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_replaces_floor_and_prune_at_back() {
        let mut overflow = VecDeque::new();

        overflow.push_back(set_floor(5));
        overflow.push_back(get_info(4));
        overflow.push_back(get_block(7));
        overflow.push_back(hint_finalized(8, public_key(1)));
        overflow.push_back(get_block(8));
        assert!(<TestMessage as Policy>::handle(&mut overflow, set_floor(8)));
        assert_eq!(overflow.len(), 2);
        assert!(!has_get_info(&overflow, 4));
        assert!(!has_get_block(&overflow, 7));
        assert!(!has_hint(&overflow, 8));
        assert!(has_get_block(&overflow, 8));
        assert!(matches!(
            &overflow[1],
            TestMessage::SetFloor { height } if *height == Height::new(8)
        ));

        overflow.clear();
        overflow.push_back(prune(5));
        overflow.push_back(get_finalization(4));
        overflow.push_back(get_block(6));
        overflow.push_back(hint_finalized(6, public_key(2)));
        overflow.push_back(get_block(7));
        assert!(<TestMessage as Policy>::handle(&mut overflow, prune(7)));
        assert_eq!(overflow.len(), 2);
        assert!(!has_get_finalization(&overflow, 4));
        assert!(!has_get_block(&overflow, 6));
        assert!(!has_hint(&overflow, 6));
        assert!(has_get_block(&overflow, 7));
        assert!(matches!(
            &overflow[1],
            TestMessage::Prune { height } if *height == Height::new(7)
        ));
    }

    #[test]
    fn policy_drops_stale_requests_after_prior_floor_and_prune() {
        let mut overflow = VecDeque::new();

        assert!(<TestMessage as Policy>::handle(&mut overflow, set_floor(5)));
        assert!(!<TestMessage as Policy>::handle(&mut overflow, get_info(4)));
        assert!(<TestMessage as Policy>::handle(&mut overflow, get_info(5)));
        assert!(!<TestMessage as Policy>::handle(
            &mut overflow,
            get_block(4)
        ));
        assert!(<TestMessage as Policy>::handle(&mut overflow, get_block(5)));
        assert!(!<TestMessage as Policy>::handle(
            &mut overflow,
            get_finalization(4)
        ));
        assert!(!<TestMessage as Policy>::handle(
            &mut overflow,
            hint_finalized(5, public_key(1))
        ));
        assert!(<TestMessage as Policy>::handle(
            &mut overflow,
            hint_finalized(6, public_key(2))
        ));

        assert!(<TestMessage as Policy>::handle(&mut overflow, prune(7)));
        assert!(!has_get_info(&overflow, 5));
        assert!(!has_get_block(&overflow, 5));
        assert!(!has_hint(&overflow, 5));
        assert!(!has_hint(&overflow, 6));
        assert!(has_prune(&overflow, 7));
        assert!(!<TestMessage as Policy>::handle(&mut overflow, get_info(6)));
        assert!(!<TestMessage as Policy>::handle(
            &mut overflow,
            get_finalization(6)
        ));
        assert!(!has_get_finalization(&overflow, 6));
        assert!(!<TestMessage as Policy>::handle(
            &mut overflow,
            get_block(6)
        ));
        assert!(<TestMessage as Policy>::handle(&mut overflow, get_info(7)));
        assert!(has_get_info(&overflow, 7));
        assert!(<TestMessage as Policy>::handle(&mut overflow, get_block(7)));
        assert!(has_get_block(&overflow, 7));
    }
}
