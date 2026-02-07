use super::{
    ingress::{ActorMailbox, ActorMessage},
    // supervisor::Supervisor, // Supervisor was consensus-specific
    Config, // Assuming Config will be simplified
};
// use commonware_cryptography::Hasher; // Hasher removed
use commonware_cryptography::Ed25519; // For sender_id in ActorMessage
use commonware_runtime::{Handle, Spawner};
// use commonware_utils::{hex, Array}; // hex and Array might not be needed
use futures::{channel::mpsc, StreamExt};
use rand::Rng; // Rng for context.fill, if actor still generates random data
// use std::marker::PhantomData; // PhantomData removed
use tracing::info;

// GENESIS constant removed

/// Application actor (simplified for broadcast).
// P, S, H generics removed as they were related to Supervisor, Hasher, and consensus participants/signatures
pub struct ApplicationActor<R: Rng + Spawner> {
    context: R,
    mailbox: mpsc::Receiver<ActorMessage>,
    // broadcaster: Option<Broadcaster<...>>, // TODO: Decide how actor interacts with actual broadcast component from main.rs
                                            // For now, actor will only log actions.
}

impl<R: Rng + Spawner> ApplicationActor<R> {
    /// Create a new application actor.
    // P, H generics removed from Config type parameters.
    // No longer returns Supervisor.
    pub fn new(
        context: R,
        // Assuming Config is simplified and mailbox_size is still relevant
        config: Config, // Config might need to be Config<H> if ActorMessage uses Digest, but it doesn't currently
    ) -> (Self, ActorMailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                mailbox,
                // broadcaster: None, // Initialize if actor should own/use a broadcaster instance
            },
            ActorMailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.next().await {
            match message {
                ActorMessage::BroadcastPayload(payload) => {
                    // In a real scenario, this actor would need access to the
                    // Broadcaster component from main.rs to send the message.
                    // For now, we just log the action.
                    info!(payload = ?payload, "Actor: would broadcast payload");

                    // Example: if actor generated its own data to broadcast:
                    let mut data_to_broadcast = vec![0u8; 16];
                    self.context.fill(&mut data_to_broadcast[..]);
                    info!(data = ?data_to_broadcast, "Actor: generated data to broadcast");
                    // And then: self.broadcaster.send(data_to_broadcast).await;
                }
                ActorMessage::MessageReceived { sender_id, payload } => {
                    // Process the received message.
                    // This actor would handle application-specific logic based on the message.
                    info!(from = ?sender_id, payload = ?payload, "Actor: received message");
                }
            }
        }
    }
}
