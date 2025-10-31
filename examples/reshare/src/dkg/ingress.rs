//! DKG [Actor] ingress (mailbox and messages)
//!
//! [Actor]: super::Actor

use crate::application::Block;
use commonware_consensus::{marshal::Update, Reporter};
use commonware_cryptography::{
    bls12381::{dkg2::SignedDealerLog, primitives::variant::Variant},
    Hasher, PrivateKey,
};
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
    C: PrivateKey,
    V: Variant,
{
    /// A request for the [Actor]'s next [SignedDealerLog] for inclusion within a block.
    ///
    /// [Actor]: super::Actor
    Act {
        response: oneshot::Sender<Option<SignedDealerLog<V, C>>>,
    },

    /// A new block has been finalized.
    Finalized {
        block: Block<H, C, V>,
        response: oneshot::Sender<()>,
    },
}

/// Inbox for sending messages to the DKG [Actor].
///
/// [Actor]: super::Actor
#[derive(Clone)]
pub struct Mailbox<H, C, V>
where
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    sender: mpsc::Sender<Message<H, C, V>>,
}

impl<H, C, V> Mailbox<H, C, V>
where
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    /// Create a new mailbox.
    pub fn new(sender: mpsc::Sender<Message<H, C, V>>) -> Self {
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
        self.sender.send(message).await.expect("mailbox closed");

        response_rx.await.expect("response channel closed")
    }
}

impl<H, C, V> Reporter for Mailbox<H, C, V>
where
    H: Hasher,
    C: PrivateKey,
    V: Variant,
{
    type Activity = Update<Block<H, C, V>>;

    async fn report(&mut self, update: Self::Activity) {
        let (sender, receiver) = oneshot::channel();

        // Report the finalized block to the DKG actor on a best-effort basis.
        let Update::Block(block) = update else {
            // We ignore any other updates sent by marshal.
            return;
        };
        let _ = self
            .sender
            .send(Message::Finalized {
                block,
                response: sender,
            })
            .await;
        let _ = receiver.await;
    }
}
