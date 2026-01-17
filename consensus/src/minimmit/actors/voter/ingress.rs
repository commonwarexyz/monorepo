//! Mailbox and message types for the voter actor.

use crate::{
    minimmit::types::{Certificate, Notarize, Nullify, Proposal},
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc};
use tracing::warn;

/// Messages that can be sent to the voter actor.
pub enum Message<S: Scheme, D: Digest> {
    /// A verified notarize vote from the batcher.
    VerifiedNotarize(Notarize<S, D>),
    /// A verified nullify vote from the batcher.
    VerifiedNullify(Nullify<S>),
    /// A verified certificate from the batcher or resolver.
    ///
    /// The boolean indicates whether the certificate came from the resolver.
    /// When true, the voter should avoid sending the same certificate back to
    /// the resolver (boomerang suppression).
    Verified(Certificate<S, D>, bool),
    /// A proposal from the batcher (leader's proposal).
    Proposal(Proposal<D>),
}

/// Mailbox for sending messages to the voter actor.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox with the given sender.
    pub const fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a verified notarize vote to the voter.
    pub async fn verified_notarize(&mut self, notarize: Notarize<S, D>) {
        self.sender
            .send_lossy(Message::VerifiedNotarize(notarize))
            .await;
    }

    /// Send a verified nullify vote to the voter.
    pub async fn verified_nullify(&mut self, nullify: Nullify<S>) {
        self.sender
            .send_lossy(Message::VerifiedNullify(nullify))
            .await;
    }

    /// Send a verified certificate to the voter.
    pub async fn verified_certificate(&mut self, certificate: Certificate<S, D>) {
        self.sender
            .send_lossy(Message::Verified(certificate, false))
            .await;
    }

    /// Send a proposal to the voter.
    pub async fn proposal(&mut self, proposal: Proposal<D>) {
        self.sender.send_lossy(Message::Proposal(proposal)).await;
    }

    /// Send a resolved or recovered certificate to the voter.
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn resolved_certificate(&mut self, certificate: Certificate<S, D>) -> bool {
        let view = certificate.view();
        if !self
            .sender
            .try_send_lossy(Message::Verified(certificate, true))
        {
            warn!(%view, "voter mailbox full, dropping resolved certificate");
            return false;
        }
        true
    }
}
