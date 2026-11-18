use super::types::{Request, Response};
use commonware_cryptography::ed25519::PublicKey;
use commonware_utils::channel::{fallible::OneshotExt, mpsc, oneshot};
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
    /// Reports each request the handler processes
    sender: mpsc::UnboundedSender<Processed>,

    /// Configured responses for specific request IDs
    responses: HashMap<u64, Response>,

    /// Whether to respond by default (if no specific response configured)
    respond_by_default: bool,
}

impl Handler {
    /// Create a new [Handler].
    pub fn new(respond_by_default: bool) -> (Self, mpsc::UnboundedReceiver<Processed>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                sender,
                responses: HashMap::new(),
                respond_by_default,
            },
            receiver,
        )
    }

    /// Create a [Handler] that responds to every request and reports no events.
    pub fn dummy() -> Self {
        let (sender, _) = mpsc::unbounded_channel();
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

    fn process(
        &mut self,
        origin: Self::PublicKey,
        request: Self::Request,
    ) -> oneshot::Receiver<Self::Response> {
        let request_id = request.id;

        // Determine if we should respond
        let should_respond = self.responses.contains_key(&request_id) || self.respond_by_default;

        // Send event
        let _ = self.sender.send(Processed {
            origin,
            request: request.clone(),
            responded: should_respond,
        });

        // Send response if configured
        let (responder, receiver) = oneshot::channel();
        if let Some(response) = self.responses.get(&request_id) {
            responder.send_lossy(response.clone());
        } else if self.respond_by_default {
            responder.send_lossy(Response {
                id: request_id,
                result: u64::from(request.data.wrapping_mul(2)),
            });
        }
        receiver
    }
}

/// A mock [crate::Handler] that hands each request and its responder to the test.
#[derive(Clone)]
pub struct Deferring {
    sender: mpsc::UnboundedSender<(Request, oneshot::Sender<Response>)>,
}

impl Deferring {
    /// Create a new [Deferring] handler and the receiver of each request with its responder.
    #[allow(clippy::type_complexity)]
    pub fn new() -> (
        Self,
        mpsc::UnboundedReceiver<(Request, oneshot::Sender<Response>)>,
    ) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }
}

impl crate::Handler for Deferring {
    type PublicKey = PublicKey;
    type Request = Request;
    type Response = Response;

    fn process(
        &mut self,
        _origin: Self::PublicKey,
        request: Self::Request,
    ) -> oneshot::Receiver<Self::Response> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.send((request, responder));
        receiver
    }
}
