//! Reshare [`Actor`] ingress.
//!
//! [`Actor`]: super::Actor

use crate::dkg::{ReshareBlock, types::Payload};
use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender as ActorSender},
};
use commonware_consensus::{Reporter, marshal::Update, types::Height};
use commonware_cryptography::{Signer, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{Acknowledgement, acknowledgement::Exact, channel::oneshot};
use futures::Stream;
use std::{collections::VecDeque, pin::Pin, sync::Arc};
use tracing::{Span, error, info_span};

/// Type-erased block ancestry stream sent through the actor mailbox.
pub(crate) type ErasedAncestry<B> = Pin<Box<dyn Stream<Item = Arc<B>> + Send>>;

/// Response to a final-block epoch artifact request.
#[derive(Clone, PartialEq, Eq)]
pub enum EpochInfoResponse<V, C>
where
    V: Variant,
    C: Signer,
{
    /// The actor derived a stable response.
    ///
    /// `None` is a legitimate response only for a failed one-shot DKG final
    /// block, which intentionally carries no epoch artifact.
    Available(Option<Payload<V, C>>),
    /// The actor cannot answer this request yet.
    ///
    /// This is not evidence that a proposed artifact is invalid. Verification
    /// remains pending until the request is canceled or local progress catches up.
    Pending,
    /// The actor is following the epoch without its protocol history.
    ///
    /// It cannot derive the artifact, but that absence is not evidence that a
    /// proposed artifact is invalid.
    Following,
    /// The actor was expected to derive the artifact but cannot produce it.
    Unavailable,
}

/// A dealer log reserved for one proposal attempt.
///
/// Dropping the reservation releases the log back to the reshare actor. Call
/// [`included`](Self::included) only after the wrapped application returns a
/// block for the proposal attempt that received this payload.
#[must_use = "dropping a log reservation releases it for another proposal"]
pub struct LogReservation<B, V, C, A = Exact>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    height: Height,
    payload: Option<Payload<V, C>>,
    release: Option<ActorSender<Message<B, V, C, A>>>,
}

impl<B, V, C, A> LogReservation<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    pub(crate) const fn new(
        height: Height,
        payload: Payload<V, C>,
        release: ActorSender<Message<B, V, C, A>>,
    ) -> Self {
        Self {
            height,
            payload: Some(payload),
            release: Some(release),
        }
    }

    /// Takes the reserved dealer log payload.
    ///
    /// Returns `None` if the payload was already taken.
    pub const fn take_payload(&mut self) -> Option<Payload<V, C>> {
        self.payload.take()
    }

    /// Keeps the log reserved for this height until finalization confirms
    /// whether the proposal landed on-chain.
    pub fn included(mut self) {
        self.release = None;
    }
}

impl<B, V, C, A> Drop for LogReservation<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    fn drop(&mut self) {
        let Some(release) = self.release.take() else {
            return;
        };
        let _ = release.enqueue(Message::ReleaseLog {
            height: self.height,
        });
    }
}

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
        release: ActorSender<Self>,
        response: oneshot::Sender<Option<LogReservation<B, V, C, A>>>,
    },

    /// A proposal attempt was canceled or returned no block after receiving a
    /// dealer log.
    ReleaseLog { height: Height },

    /// A request for the final block's speculative [`EpochInfo`](crate::dkg::types::EpochInfo).
    EpochInfo {
        span: Span,
        ancestry: ErasedAncestry<B>,
        response: oneshot::Sender<EpochInfoResponse<V, C>>,
    },

    /// A new block has been finalized.
    Finalized {
        span: Span,
        block: Arc<B>,
        response: A,
    },
}

impl<B, V, C, A> Message<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    fn response_closed(&self) -> bool {
        match self {
            Self::NextLog { response, .. } => response.is_closed(),
            Self::ReleaseLog { .. } => false,
            Self::EpochInfo { response, .. } => response.is_closed(),
            Self::Finalized { .. } => false,
        }
    }
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
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    sender: ActorSender<Message<B, V, C, A>>,
}

impl<B, V, C, A> Mailbox<B, V, C, A>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
    A: Acknowledgement,
{
    /// Create a new mailbox.
    pub const fn new(sender: ActorSender<Message<B, V, C, A>>) -> Self {
        Self { sender }
    }

    /// Request a dealer log for inclusion before the final block of the epoch.
    ///
    /// `height` is the height of the block being proposed.
    pub async fn next_log(&mut self, height: Height) -> Option<LogReservation<B, V, C, A>> {
        let (response_tx, response_rx) = oneshot::channel();
        let span = info_span!("dkg.reshare.mailbox.next_log", height = height.traced());
        if !self
            .sender
            .enqueue(Message::NextLog {
                span,
                height,
                release: self.sender.clone(),
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
        ancestry: impl Stream<Item = Arc<B>> + Send + 'static,
    ) -> EpochInfoResponse<V, C> {
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
    use commonware_runtime::{Runner, deterministic};
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
