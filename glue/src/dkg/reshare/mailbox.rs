//! Reshare [`Actor`] ingress.
//!
//! [`Actor`]: super::Actor

use crate::dkg::{ReshareBlock, network::Directory, types::Payload};
use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender as ActorSender},
};
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{
        Update,
        ancestry::{Ancestry, BoxedAncestry},
    },
    types::Height,
};
use commonware_cryptography::{
    Digested, Digestible as _, Signer,
    bls12381::{dkg::feldman_desmedt::SignedDealerLog, primitives::variant::Variant},
};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{Acknowledgement, acknowledgement::Exact, channel::oneshot, sequence::Unit};
use std::collections::VecDeque;
use tracing::{Span, error, info_span};

/// Response to [`Mailbox::epoch_info`].
#[derive(Clone, PartialEq, Eq)]
pub enum EpochInfoResponse<V, C, D = Unit>
where
    V: Variant,
    C: Signer,
    D: Directory<C::PublicKey>,
{
    /// The payload the final block must carry.
    ///
    /// `None` means the final block must carry no payload. Continuous reshare
    /// always returns `Some`.
    Available(Option<Payload<V, C, D>>),
    /// The actor cannot derive the payload for this request.
    ///
    /// This is not evidence that a proposed payload is invalid. A later request
    /// may return [`Self::Available`].
    Pending,
    /// The actor is following the epoch without the history needed to derive
    /// the payload.
    ///
    /// This is not evidence that a proposed payload is valid or invalid.
    Following,
    /// The ancestry does not connect to the actor's finalized tip, or the actor
    /// has stopped.
    Unavailable,
}

/// A message that can be sent to the [`Actor`].
///
/// [`Actor`]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<B, V, C, A = Exact>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    /// A request for the dealer logs to include in the block being proposed at
    /// `height` (see [`Mailbox::dealer_logs`]).
    DealerLogs {
        span: Span,
        height: Height,
        response: oneshot::Sender<Vec<SignedDealerLog<V, C>>>,
    },

    /// A request for the payload of an epoch's final block (see
    /// [`Mailbox::epoch_info`]).
    EpochInfo {
        span: Span,
        ancestry: BoxedAncestry<B>,
        response: oneshot::Sender<EpochInfoResponse<V, C, B::Directory>>,
    },

    /// A finalized block reported by marshal, acknowledged through `response`
    /// once its effects are complete.
    Finalized {
        span: Span,
        block: Digested<B>,
        response: A,
    },
}

impl<B, V, C, A> Message<B, V, C, A>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    fn response_closed(&self) -> bool {
        match self {
            Self::DealerLogs { response, .. } => response.is_closed(),
            Self::EpochInfo { response, .. } => response.is_closed(),
            Self::Finalized { .. } => false,
        }
    }
}

impl<B, V, C, A> Policy for Message<B, V, C, A>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.push_back(message);
    }
}

/// Inbox for sending messages to the reshare [`Actor`].
///
/// [`Actor`]: super::Actor
#[derive(Clone)]
pub struct Mailbox<B, V, C, A = Exact>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    sender: ActorSender<Message<B, V, C, A>>,
}

impl<B, V, C, A> Mailbox<B, V, C, A>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    /// Creates a mailbox that sends to the actor behind `sender`.
    pub const fn new(sender: ActorSender<Message<B, V, C, A>>) -> Self {
        Self { sender }
    }

    /// Requests the dealer logs to include in the block being proposed at
    /// `height`.
    ///
    /// Returns every log this node holds for the epoch's inclusion window (its
    /// own and those received from other dealers) whose dealer has no log in a
    /// finalized block yet. Logs carried by unfinalized ancestors may be
    /// returned again. Returns no logs for a height outside the actor's
    /// current epoch, while the actor is not in an inclusion window, or if the
    /// actor has stopped.
    pub async fn dealer_logs(&mut self, height: Height) -> Vec<SignedDealerLog<V, C>> {
        let (response_tx, response_rx) = oneshot::channel();
        let span = info_span!("dkg.reshare.mailbox.dealer_logs", height = height.traced());
        if !self
            .sender
            .enqueue(Message::DealerLogs {
                span,
                height,
                response: response_tx,
            })
            .accepted()
        {
            error!("failed to send request for dealer logs");
            return Vec::new();
        }

        match response_rx.await {
            Ok(logs) => logs,
            Err(err) => {
                error!(?err, "failed to receive dealer logs response");
                Vec::new()
            }
        }
    }

    /// Requests the payload for an epoch's final block.
    ///
    /// `ancestry` starts at the final block (verification) or at its parent
    /// (proposal) and must extend the actor's finalized tip. Returns
    /// [`EpochInfoResponse::Unavailable`] if it does not or if the actor has
    /// stopped.
    pub async fn epoch_info(
        &mut self,
        ancestry: impl Ancestry<B>,
    ) -> EpochInfoResponse<V, C, B::Directory> {
        let (response_tx, response_rx) = oneshot::channel();
        let span = info_span!("dkg.reshare.mailbox.epoch_info");
        if !self
            .sender
            .enqueue(Message::EpochInfo {
                span,
                ancestry: BoxedAncestry::new(ancestry),
                response: response_tx,
            })
            .accepted()
        {
            error!("failed to send request for epoch info");
            return EpochInfoResponse::Unavailable;
        }

        match response_rx.await {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(?err, "failed to receive epoch info response");
                EpochInfoResponse::Unavailable
            }
        }
    }
}

impl<B, V, C, A> Reporter for Mailbox<B, V, C, A>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    type Activity = Update<B, A>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        let Update::Block(block, ack_tx) = update else {
            return Feedback::Ok;
        };
        let span = info_span!(
            "dkg.reshare.mailbox.finalized",
            height = block.height().traced(),
            digest = %block.digest()
        );
        self.sender.enqueue(Message::Finalized {
            span,
            block,
            response: ack_tx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks::{self, TestBlock, TestBlsVariant};
    use commonware_actor::mailbox;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_runtime::{Runner, deterministic};
    use commonware_utils::{NZUsize, channel::oneshot};
    use futures::{FutureExt as _, StreamExt as _};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    type TestMessage = Message<TestBlock, TestBlsVariant, PrivateKey>;

    #[derive(Clone)]
    struct DelayedAncestry {
        parent: Option<Digested<TestBlock>>,
        gate: futures::future::Shared<oneshot::Receiver<()>>,
    }

    impl futures::Stream for DelayedAncestry {
        type Item = Digested<TestBlock>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if self.gate.poll_unpin(cx).is_pending() {
                return Poll::Pending;
            }
            Poll::Ready(self.parent.take())
        }
    }

    impl Ancestry<TestBlock> for DelayedAncestry {
        fn peek(&self) -> Option<&Digested<TestBlock>> {
            None
        }
    }

    #[test]
    fn dealer_logs_returns_empty_when_actor_gone() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, receiver) = mailbox::new::<TestMessage>(context, NZUsize!(1));
            drop(receiver);

            let mut mailbox = Mailbox::<TestBlock, TestBlsVariant, PrivateKey, Exact>::new(sender);

            assert!(mailbox.dealer_logs(Height::new(1)).await.is_empty());
        });
    }

    #[test]
    fn epoch_info_forwards_delayed_parent_without_polling() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, mut receiver) = mailbox::new::<TestMessage>(context, NZUsize!(1));
            let mut mailbox = Mailbox::<TestBlock, TestBlsVariant, PrivateKey, Exact>::new(sender);
            let parent = mocks::genesis_block(PrivateKey::from_seed(0).public_key());
            let parent = Digested::precomputed(parent.clone(), parent.digest());
            let (release, gate) = oneshot::channel();
            let ancestry = DelayedAncestry {
                parent: Some(parent.clone()),
                gate: gate.shared(),
            };
            let mut request = Box::pin(mailbox.epoch_info(ancestry));

            assert!(request.as_mut().now_or_never().is_none());
            let message = receiver
                .try_recv()
                .expect("request should reach the actor without polling ancestry");
            let Message::EpochInfo {
                mut ancestry,
                response,
                ..
            } = message
            else {
                panic!("expected epoch info request");
            };
            assert!(ancestry.next().now_or_never().is_none());

            release.send(()).expect("ancestry should still be waiting");
            assert_eq!(
                ancestry
                    .next()
                    .await
                    .expect("parent should remain in ancestry")
                    .digest(),
                parent.digest()
            );
            assert!(response.send(EpochInfoResponse::Available(None)).is_ok());
            assert!(matches!(request.await, EpochInfoResponse::Available(None)));
        });
    }

    #[test]
    fn canceled_epoch_info_closes_forwarded_response_without_polling_ancestry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, mut receiver) = mailbox::new::<TestMessage>(context, NZUsize!(1));
            let mut mailbox = Mailbox::<TestBlock, TestBlsVariant, PrivateKey, Exact>::new(sender);
            let parent = mocks::genesis_block(PrivateKey::from_seed(0).public_key());
            let parent = Digested::precomputed(parent.clone(), parent.digest());
            let (release, gate) = oneshot::channel();
            let ancestry = DelayedAncestry {
                parent: Some(parent),
                gate: gate.shared(),
            };
            let mut request = Box::pin(mailbox.epoch_info(ancestry));

            assert!(request.as_mut().now_or_never().is_none());
            let Message::EpochInfo {
                ancestry, response, ..
            } = receiver
                .try_recv()
                .expect("request should reach the actor without polling ancestry")
            else {
                panic!("expected epoch info request");
            };
            drop(request);

            assert!(response.is_closed());
            assert!(release.send(()).is_ok());
            drop(ancestry);
        });
    }
}
