use crate::{
    simplex::{
        metrics::TimeoutReason,
        types::{Certificate, Proposal, Vote},
    },
    types::View,
    Viewable,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use std::collections::VecDeque;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CertificateKind {
    Notarization,
    Nullification,
    Finalization,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VoteKind {
    Notarization,
    Nullification,
    Finalization,
}

/// Messages sent to the [super::actor::Actor].
pub enum Message<S: Scheme, D: Digest> {
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
    /// Signal that the current view should timeout (if not already).
    Timeout(View, TimeoutReason),
    /// Certificate from batcher or resolver.
    ///
    /// The boolean indicates if the certificate came from the resolver.
    /// When true, the voter will not send it back to the resolver (to avoid "boomerang").
    Verified(Certificate<S, D>, bool),
    /// Retry broadcasting a vote that p2p could not enqueue.
    RetryVote(Vote<S, D>),
    /// Retry broadcasting a certificate that p2p could not enqueue.
    RetryCertificate(Certificate<S, D>),
}

fn certificate_key<S: Scheme, D: Digest>(
    certificate: &Certificate<S, D>,
) -> (CertificateKind, View) {
    match certificate {
        Certificate::Notarization(certificate) => {
            (CertificateKind::Notarization, certificate.view())
        }
        Certificate::Nullification(certificate) => {
            (CertificateKind::Nullification, certificate.view())
        }
        Certificate::Finalization(certificate) => {
            (CertificateKind::Finalization, certificate.view())
        }
    }
}

fn vote_key<S: Scheme, D: Digest>(vote: &Vote<S, D>) -> (VoteKind, View) {
    match vote {
        Vote::Notarize(vote) => (VoteKind::Notarization, vote.view()),
        Vote::Nullify(vote) => (VoteKind::Nullification, vote.view()),
        Vote::Finalize(vote) => (VoteKind::Finalization, vote.view()),
    }
}

impl<S: Scheme, D: Digest> Policy for Message<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Proposal(proposal) => {
                let view = proposal.view();
                if let Some(index) = overflow.iter().rposition(|pending| {
                    matches!(
                        pending,
                        Self::Timeout(timeout_view, TimeoutReason::Inactivity)
                            if *timeout_view <= view
                    )
                }) {
                    overflow.remove(index);
                }
            }
            Self::Timeout(view, _) => {
                let view = *view;
                if let Some(index) = overflow.iter().rposition(
                    |pending| matches!(pending, Self::Timeout(pending_view, _) if *pending_view == view),
                ) {
                    overflow.remove(index);
                }
            }
            Self::Verified(certificate, _) => {
                let key = certificate_key(certificate);
                if let Some(Self::Verified(pending_certificate, pending_resolved)) =
                    overflow.iter_mut().rev().find(|pending| {
                        matches!(
                            pending,
                            Self::Verified(pending_certificate, _)
                                if certificate_key(pending_certificate) == key
                        )
                    })
                {
                    let Self::Verified(certificate, resolved) = message else {
                        unreachable!();
                    };
                    *pending_certificate = certificate;
                    *pending_resolved |= resolved;
                    return true;
                }
                if let Some(index) = overflow
                    .iter()
                    .rposition(|pending| matches!(pending, Self::Timeout(view, _) if *view <= key.1))
                {
                    overflow.remove(index);
                }
            }
            Self::RetryVote(vote) => {
                let key = vote_key(vote);
                if let Some(index) = overflow.iter().rposition(
                    |pending| matches!(pending, Self::RetryVote(vote) if vote_key(vote) == key),
                ) {
                    overflow.remove(index);
                }
            }
            Self::RetryCertificate(certificate) => {
                let key = certificate_key(certificate);
                if let Some(index) = overflow.iter().rposition(|pending| {
                    matches!(
                        pending,
                        Self::RetryCertificate(certificate) if certificate_key(certificate) == key
                    )
                }) {
                    overflow.remove(index);
                }
            }
        };
        overflow.push_back(message);
        true
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mailbox::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mailbox::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a leader's proposal.
    pub fn proposal(&mut self, proposal: Proposal<D>) -> Feedback {
        self.sender.enqueue(Message::Proposal(proposal))
    }

    /// Signal that the current view should timeout (if not already).
    pub fn timeout(&mut self, view: View, reason: TimeoutReason) -> Feedback {
        self.sender.enqueue(Message::Timeout(view, reason))
    }

    /// Send a recovered certificate.
    pub fn recovered(&mut self, certificate: Certificate<S, D>) -> Feedback {
        self.sender.enqueue(Message::Verified(certificate, false))
    }

    /// Send a resolved certificate.
    pub fn resolved(&mut self, certificate: Certificate<S, D>) -> Feedback {
        self.sender.enqueue(Message::Verified(certificate, true))
    }

}
