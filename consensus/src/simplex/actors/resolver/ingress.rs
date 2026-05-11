use crate::{
    simplex::types::Certificate,
    types::View,
    Viewable,
};
use bytes::Bytes;
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::{
    channel::oneshot,
    sequence::U64,
};
use std::collections::VecDeque;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CertificateKind {
    Notarization,
    Nullification,
    Finalization,
}

/// Messages sent to the resolver actor from the voter.
pub enum MailboxMessage<S: Scheme, D: Digest> {
    /// A certificate was received or produced.
    Certificate(Certificate<S, D>),
    /// Certification result for a view.
    Certified { view: View, success: bool },
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

impl<S: Scheme, D: Digest> Policy for MailboxMessage<S, D> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Certificate(certificate) => {
                let key = certificate_key(certificate);
                if let Some(index) = overflow.iter().rposition(
                    |pending| matches!(pending, Self::Certificate(pending) if certificate_key(pending) == key),
                ) {
                    overflow.remove(index);
                }
            }
            Self::Certified { view, success } => {
                let view = *view;
                let success = *success;
                if let Some(Self::Certified {
                    success: pending_success,
                    ..
                }) = overflow
                    .iter_mut()
                    .rev()
                    .find(|pending| matches!(pending, Self::Certified { view: pending_view, .. } if *pending_view == view))
                {
                    *pending_success |= success;
                    return true;
                }
            }
        }
        overflow.push_back(message);
        true
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mailbox::Sender<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub const fn new(sender: mailbox::Sender<MailboxMessage<S, D>>) -> Self {
        Self { sender }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) -> Feedback {
        self.sender
            .enqueue(MailboxMessage::Certificate(certificate))
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, view: View, success: bool) -> Feedback {
        self.sender
            .enqueue(MailboxMessage::Certified { view, success })
    }

}

#[derive(Debug)]
pub enum HandlerMessage {
    Deliver {
        view: View,
        data: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        view: View,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone)]
pub struct Handler {
    sender: mailbox::Sender<HandlerMessage>,
}

impl Handler {
    pub const fn new(sender: mailbox::Sender<HandlerMessage>) -> Self {
        Self { sender }
    }
}

impl Policy for HandlerMessage {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match &message {
            Self::Deliver { .. } => {
                if let Some(index) = overflow
                    .iter()
                    .rposition(|pending| matches!(pending, Self::Produce { .. }))
                {
                    overflow.remove(index);
                }
            }
            Self::Produce { view, .. } => {
                let view = *view;
                if let Some(index) = overflow.iter().rposition(
                    |pending| matches!(pending, Self::Produce { view: pending, .. } if *pending == view),
                ) {
                    overflow.remove(index);
                }
            }
        };
        overflow.push_back(message);
        true
    }
}

impl Consumer for Handler {
    type Key = U64;
    type Value = Bytes;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        let result = self.sender.enqueue(HandlerMessage::Deliver {
            view: View::new(key.into()),
            data: value,
            response,
        });
        if !result.accepted() {
            return false;
        }
        receiver.await.unwrap_or(false)
    }
}

impl Producer for Handler {
    type Key = U64;

    #[allow(clippy::unused_async)]
    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        let result = self.sender.enqueue(HandlerMessage::Produce {
            view: View::new(key.into()),
            response,
        });
        if !result.accepted() {
            return receiver;
        }
        receiver
    }
}
