use crate::simplex::{signing_scheme::Scheme, types::Voter};
use commonware_cryptography::Digest;
use futures::channel::mpsc;

/// Mailbox for broadcasting certificates to observers.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Voter<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub(super) fn new(sender: mpsc::Sender<Voter<S, D>>) -> Self {
        Self { sender }
    }

    /// Sends a certificate to all connected observers.
    ///
    /// This is a non-blocking send using try_send. If the observer actor's
    /// channel is full or closed, the message is dropped to avoid blocking
    /// the resolver.
    pub fn send(&mut self, certificate: Voter<S, D>) {
        let _ = self.sender.try_send(certificate);
    }
}