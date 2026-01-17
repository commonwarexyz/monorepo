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
    /// A verified certificate from the batcher.
    VerifiedCertificate(Certificate<S, D>),
    /// A proposal from the batcher (leader's proposal).
    Proposal(Proposal<D>),
    /// A certificate resolved from the resolver or recovered from storage.
    ResolvedCertificate(Certificate<S, D>),
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
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn verified_notarize(&mut self, notarize: Notarize<S, D>) -> bool {
        let view = notarize.view();
        if !self
            .sender
            .try_send_lossy(Message::VerifiedNotarize(notarize))
        {
            warn!(%view, "voter mailbox full, dropping verified notarize");
            return false;
        }
        true
    }

    /// Send a verified nullify vote to the voter.
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn verified_nullify(&mut self, nullify: Nullify<S>) -> bool {
        let view = nullify.view();
        if !self
            .sender
            .try_send_lossy(Message::VerifiedNullify(nullify))
        {
            warn!(%view, "voter mailbox full, dropping verified nullify");
            return false;
        }
        true
    }

    /// Send a verified certificate to the voter.
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn verified_certificate(&mut self, certificate: Certificate<S, D>) -> bool {
        let view = certificate.view();
        if !self
            .sender
            .try_send_lossy(Message::VerifiedCertificate(certificate))
        {
            warn!(%view, "voter mailbox full, dropping verified certificate");
            return false;
        }
        true
    }

    /// Send a proposal to the voter.
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn proposal(&mut self, proposal: Proposal<D>) -> bool {
        let view = proposal.view();
        if !self.sender.try_send_lossy(Message::Proposal(proposal)) {
            warn!(%view, "voter mailbox full, dropping proposal");
            return false;
        }
        true
    }

    /// Send a resolved or recovered certificate to the voter.
    ///
    /// Returns `true` if the message was successfully queued, `false` if the
    /// mailbox was full (message is dropped with a warning).
    pub fn resolved_certificate(&mut self, certificate: Certificate<S, D>) -> bool {
        let view = certificate.view();
        if !self
            .sender
            .try_send_lossy(Message::ResolvedCertificate(certificate))
        {
            warn!(%view, "voter mailbox full, dropping resolved certificate");
            return false;
        }
        true
    }
}
