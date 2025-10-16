//! DKG [Actor] ingress (mailbox and messages)
//!
//! [Actor]: super::Actor

use crate::{application::Block, dkg::DealOutcome};
use commonware_consensus::Reporter;
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// A message that can be sent to the [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// A request for the [Actor]'s next [DealOutcome] for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    Act {
        response: oneshot::Sender<Option<DealOutcome<C, V>>>,
    },

    /// A new block has been finalized.
    Finalized { block: Block<H, C, V> },
}

/// Inbox for sending messages to the DKG [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    sender: mpsc::Sender<Message<H, C, V>>,
}

impl<H, C, V> Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new mailbox.
    pub fn new(sender: mpsc::Sender<Message<H, C, V>>) -> Self {
        Self { sender }
    }

    /// Request the [Actor]'s next payload for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    pub async fn act(&mut self) -> Option<DealOutcome<C, V>> {
        let (response_tx, response_rx) = oneshot::channel();
        let message = Message::Act {
            response: response_tx,
        };
        self.sender.send(message).await.expect("mailbox closed");

        response_rx.await.expect("response channel closed")
    }
}

impl<H, C, V> Reporter for Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Activity = Block<H, C, V>;

    async fn report(&mut self, block: Self::Activity) {
        self.sender
            .send(Message::Finalized { block })
            .await
            .expect("mailbox closed");
    }
}
