//! DKG [Actor] ingress (mailbox and messages)
//!
//! [Actor]: super::Actor

use crate::application::Block;
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{marshal::Update, Reporter};
use commonware_cryptography::{
    bls12381::{dkg::SignedDealerLog, primitives::variant::Variant},
    Hasher, Signer,
};
use commonware_utils::{acknowledgement::Exact, channel::oneshot, Acknowledgement};
use std::collections::VecDeque;
use tracing::error;

/// A message that can be sent to the [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<H, C, V, A = Exact>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    A: Acknowledgement,
{
    /// A request for the [Actor]'s next [SignedDealerLog] for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    Act {
        response: oneshot::Sender<Option<SignedDealerLog<V, C>>>,
    },

    /// A new block has been finalized.
    Finalized { block: Block<H, C, V>, response: A },
}

impl<H, C, V, A> Policy for Message<H, C, V, A>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
    }
}

/// Inbox for sending messages to the DKG [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox<H, C, V, A = Exact>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    A: Acknowledgement,
{
    sender: Sender<Message<H, C, V, A>>,
}

impl<H, C, V, A> Mailbox<H, C, V, A>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    A: Acknowledgement,
{
    /// Create a new mailbox.
    pub const fn new(sender: Sender<Message<H, C, V, A>>) -> Self {
        Self { sender }
    }

    /// Request the [Actor]'s next payload for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    pub async fn act(&mut self) -> Option<SignedDealerLog<V, C>> {
        let (response_tx, response_rx) = oneshot::channel();
        let message = Message::Act {
            response: response_tx,
        };
        if !self.sender.enqueue(message).accepted() {
            error!("failed to send act message");
            return None;
        }

        match response_rx.await {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(?err, "failed to receive act response");
                None
            }
        }
    }
}

impl<H, C, V, A> Reporter for Mailbox<H, C, V, A>
where
    H: Hasher,
    C: Signer,
    V: Variant,
    A: Acknowledgement,
{
    type Activity = Update<Block<H, C, V>, A>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        // Report the finalized block to the DKG actor on a best-effort basis.
        let Update::Block(block, ack_tx) = update else {
            // We ignore any other updates sent by marshal.
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized {
            block,
            response: ack_tx,
        })
    }
}
