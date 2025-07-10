use super::{Request, Response};
use commonware_cryptography::ed25519::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::collections::HashMap;

/// Events that can be observed from the handler
#[derive(Debug, Clone)]
pub enum Event {
    /// Handler received a request
    ReceivedRequest {
        origin: PublicKey,
        request: Request,
        responded: bool,
    },
}

/// A mock handler for testing
#[derive(Clone)]
pub struct Handler {
    /// Channel to send events
    sender: mpsc::UnboundedSender<Event>,

    /// Configured responses for specific request IDs
    responses: HashMap<u64, Response>,

    /// Whether to respond by default (if no specific response configured)
    respond_by_default: bool,
}

impl Handler {
    /// Create a new mock handler
    pub fn new(respond_by_default: bool) -> (Self, mpsc::UnboundedReceiver<Event>) {
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

    /// Create a dummy handler that doesn't track events
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded();
        Self {
            sender,
            responses: HashMap::new(),
            respond_by_default: true,
        }
    }

    /// Configure a specific response for a request ID
    pub fn set_response(&mut self, request_id: u64, response: Response) {
        self.responses.insert(request_id, response);
    }

    /// Remove a configured response
    pub fn remove_response(&mut self, request_id: &u64) -> Option<Response> {
        self.responses.remove(request_id)
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
            .send(Event::ReceivedRequest {
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
                result: request.data.wrapping_mul(2),
            });
        }
        // Otherwise, drop the responder to indicate no response
    }
}
