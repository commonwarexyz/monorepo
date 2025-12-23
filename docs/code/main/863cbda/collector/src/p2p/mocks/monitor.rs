use super::types::Response;
use commonware_cryptography::ed25519::PublicKey;
use futures::{channel::mpsc, SinkExt};

/// A mock [crate::Monitor] collected a response.
#[derive(Debug, Clone)]
pub struct Collected {
    pub handler: PublicKey,
    pub response: Response,
    pub count: usize,
}

/// A mock [crate::Monitor].
#[derive(Clone)]
pub struct Monitor {
    sender: mpsc::UnboundedSender<Collected>,
}

impl Monitor {
    /// Create a new [Monitor].
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Collected>) {
        let (sender, receiver) = mpsc::unbounded();
        (Self { sender }, receiver)
    }

    /// Create a dummy [Monitor] that doesn't track events.
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
            .send(Collected {
                handler,
                response,
                count,
            })
            .await;
    }
}
