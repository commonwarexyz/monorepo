use commonware_cryptography::Ed25519; // Assuming Ed25519 for sender ID
use futures::channel::mpsc;
use futures::SinkExt; // Required for sender.send(...).await

// Define new message types for a potential broadcast actor
// D is removed as Digest is no longer central to these messages.
// If specific digest types are needed later, they can be part of the payload.
pub enum ActorMessage {
    /// Instructs the actor to broadcast a payload.
    BroadcastPayload(Vec<u8>),
    /// Relays a received message to the actor (if main.rs delegates handling).
    MessageReceived {
        sender_id: Ed25519, // Or appropriate public key type
        payload: Vec<u8>,
    },
    // Add other actor-specific commands if needed
}

/// Mailbox for the application actor.
#[derive(Clone)]
pub struct ActorMailbox {
    // Changed Message<D> to ActorMessage
    sender: mpsc::Sender<ActorMessage>,
}

impl ActorMailbox {
    pub(super) fn new(sender: mpsc::Sender<ActorMessage>) -> Self {
        Self { sender }
    }

    // Example method to send a broadcast instruction to the actor
    pub async fn request_broadcast(&mut self, payload: Vec<u8>) -> Result<(), mpsc::SendError> {
        self.sender.send(ActorMessage::BroadcastPayload(payload)).await
    }

    // Example method to inform actor about a received message
    pub async fn notify_message_received(&mut self, sender_id: Ed25519, payload: Vec<u8>) -> Result<(), mpsc::SendError> {
        self.sender.send(ActorMessage::MessageReceived { sender_id, payload }).await
    }
}

// Removed Automaton (Au) and Relay (Re) trait implementations as they are consensus-specific.
// If the actor needs to interact with network components directly in a more abstract way,
// new traits or methods would be defined here or in actor.rs.
