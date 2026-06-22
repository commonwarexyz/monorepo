//! Reshare [`Actor`] ingress.
//!
//! [`Actor`]: super::Actor

use crate::dkg::{types::Payload, ReshareBlock};
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{marshal::Update, types::Height, Reporter};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Signer};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{acknowledgement::Exact, channel::oneshot, Acknowledgement};
use futures::Stream;
use std::{collections::VecDeque, pin::Pin};
use tracing::{error, info_span, Span};

/// Type-erased block ancestry stream sent through the actor mailbox.
pub(crate) type ErasedAncestry<B> = Pin<Box<dyn Stream<Item = B> + Send>>;

/// A message that can be sent to the [`Actor`].
///
/// [`Actor`]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<B, V, C, A = Exact>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    /// A request for the next finalized dealer log to include before the final
    /// block of the epoch.
    ///
    /// `height` is the height of the block being proposed. The actor uses it to
    /// avoid re-offering a log into competing proposals while one it already
    /// served into may still finalize.
    NextLog {
        span: Span,
        height: Height,
        response: oneshot::Sender<Option<Payload<V, C>>>,
    },

    /// A request for the final block's speculative [`EpochInfo`](crate::dkg::types::EpochInfo).
    EpochInfo {
        span: Span,
        ancestry: ErasedAncestry<B>,
        response: oneshot::Sender<Option<Payload<V, C>>>,
    },

    /// A new block has been finalized.
    Finalized { span: Span, block: B, response: A },
}

impl<B, V, C, A> Policy for Message<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Inbox for sending messages to the reshare [`Actor`].
///
/// [`Actor`]: super::Actor
#[derive(Clone)]
pub struct Mailbox<B, V, C, A = Exact>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    sender: Sender<Message<B, V, C, A>>,
}

impl<B, V, C, A> Mailbox<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<B, V, C, A>>) -> Self {
        Self { sender }
    }

    /// Request a dealer log for inclusion before the final block of the epoch.
    ///
    /// `height` is the height of the block being proposed.
    pub async fn next_log(&mut self, height: Height) -> Option<Payload<V, C>> {
        let (response_tx, response_rx) = oneshot::channel();
        let span = info_span!("dkg.reshare.mailbox.next_log", height = height.traced());
        if !self
            .sender
            .enqueue(Message::NextLog {
                span,
                height,
                response: response_tx,
            })
            .accepted()
        {
            error!("failed to send request for next dealer log");
            return None;
        }

        match response_rx.await {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(?err, "failed to receive payload response");
                None
            }
        }
    }

    /// Request the final block's next-epoch artifact.
    pub async fn epoch_info(
        &mut self,
        ancestry: impl Stream<Item = B> + Send + 'static,
    ) -> Option<Payload<V, C>> {
        let (response_tx, response_rx) = oneshot::channel();
        let span = info_span!("dkg.reshare.mailbox.epoch_info");
        if !self
            .sender
            .enqueue(Message::EpochInfo {
                span,
                ancestry: Box::pin(ancestry),
                response: response_tx,
            })
            .accepted()
        {
            error!("failed to send request for epoch info");
            return None;
        }

        match response_rx.await {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(?err, "failed to receive epoch info response");
                None
            }
        }
    }
}

impl<B, V, C, A> Reporter for Mailbox<B, V, C, A>
where
    B: ReshareBlock,
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
    use crate::dkg::tests::mocks::{TestBlock, TestBlsVariant};
    use commonware_actor::mailbox;
    use commonware_cryptography::ed25519::PrivateKey;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZUsize;

    type TestMessage = Message<TestBlock, TestBlsVariant, PrivateKey>;

    #[test]
    fn next_log_returns_none_when_actor_gone() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (sender, receiver) = mailbox::new::<TestMessage>(context, NZUsize!(1));
            drop(receiver);

            let mut mailbox = Mailbox::<TestBlock, TestBlsVariant, PrivateKey>::new(sender);

            assert!(mailbox.next_log(Height::new(1)).await.is_none());
        });
    }
}
