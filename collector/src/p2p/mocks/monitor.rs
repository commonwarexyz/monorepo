use super::Response;
use commonware_cryptography::ed25519::PublicKey;
use futures::{channel::mpsc, SinkExt};

/// Events that can be observed from the monitor
#[derive(Debug, Clone)]
pub enum Event {
    /// Monitor collected a response
    Collected {
        handler: PublicKey,
        response: Response,
        count: usize,
    },
}

/// A mock monitor for testing
#[derive(Clone)]
pub struct Monitor {
    /// Channel to send events
    sender: mpsc::UnboundedSender<Event>,
}

impl Monitor {
    /// Create a new mock monitor
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Event>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self { sender }, receiver)
    }

    /// Create a dummy monitor that doesn't track events
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded();
        Self { sender }
    }
}

impl crate::Monitor for Monitor {
    type PublicKey = PublicKey;
    type Response = Response;

    async fn collected(
        &mut self,
        handler: Self::PublicKey,
        response: Self::Response,
        count: usize,
    ) {
        let _ = self
            .sender
            .send(Event::Collected {
                handler,
                response,
                count,
            })
            .await;
    }
}
