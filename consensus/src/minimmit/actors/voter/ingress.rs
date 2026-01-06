//! Mailbox and message types for the voter actor.

#![allow(dead_code)] // Skeleton implementation

use crate::minimmit::types::{Certificate, Proposal};
use commonware_cryptography::{certificate::Scheme, Digest};
use futures::channel::mpsc;

/// Message types that can be sent to the voter actor.
#[derive(Debug)]
pub enum Message<S: Scheme, D: Digest> {
    /// A proposal received from a leader (via network or local).
    Proposal(Proposal<D>),
    /// A verified certificate received (bool indicates if from resolver).
    Verified(Certificate<S, D>, bool),
}

/// Mailbox for sending messages to the voter actor.
#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Creates a new mailbox with the given sender.
    pub const fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Sends a proposal to the voter.
    pub fn proposal(&mut self, proposal: Proposal<D>) -> bool {
        self.sender.try_send(Message::Proposal(proposal)).is_ok()
    }

    /// Sends a verified certificate to the voter (not from resolver).
    pub fn verified(&mut self, certificate: Certificate<S, D>) -> bool {
        self.sender
            .try_send(Message::Verified(certificate, false))
            .is_ok()
    }

    /// Sends a resolved certificate to the voter (from resolver).
    pub fn resolved(&mut self, certificate: Certificate<S, D>) -> bool {
        self.sender
            .try_send(Message::Verified(certificate, true))
            .is_ok()
    }
}
