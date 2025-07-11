use super::types::{Request, Response};
use commonware_cryptography::ed25519::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::collections::HashMap;

/// A mock [crate::Handler] received a request.
#[derive(Debug, Clone)]
pub struct Processed {
    pub origin: PublicKey,
    pub request: Request,
    pub responded: bool,
}

/// A mock [crate::Handler].
#[derive(Clone)]
pub struct Handler {
    sender: mpsc::UnboundedSender<Processed>,

    /// Configured responses for specific request IDs
    responses: HashMap<u64, Response>,

    /// Whether to respond by default (if no specific response configured)
    respond_by_default: bool,
}

impl Handler {
    /// Create a new [Handler].
    pub fn new(respond_by_default: bool) -> (Self, mpsc::UnboundedReceiver<Processed>) {
        let (sender, receiver) = mpsc::unbounded();
        (
            Self {
                sender,
                responses: HashMap::new(),
                respond_by_default,
            },
            receiver,
        )
    }

    /// Create a dummy [Handler] that doesn't track events.
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded();
        Self {
            sender,
            responses: HashMap::new(),
            respond_by_default: true,
        }
    }

    /// Configure a specific response for a request ID.
    pub fn set_response(&mut self, request_id: u64, response: Response) {
        self.responses.insert(request_id, response);
    }
}

impl crate::Handler for Handler {
    type PublicKey = PublicKey;
    type Request = Request;
    type Response = Response;

    async fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
        responder: oneshot::Sender<Self::Response>,
    ) {
        let request_id = request.id;

        // Determine if we should respond
        let should_respond = self.responses.contains_key(&request_id) || self.respond_by_default;

        // Send event
        let _ = self
            .sender
            .send(Processed {
                origin: origin.clone(),
                request: request.clone(),
                responded: should_respond,
            })
            .await;

        // Send response if configured
        if let Some(response) = self.responses.get(&request_id) {
            let _ = responder.send(response.clone());
        } else if self.respond_by_default {
            let _ = responder.send(Response {
                id: request_id,
                result: request.data.wrapping_mul(2) as u64,
            });
        }
    }
}
