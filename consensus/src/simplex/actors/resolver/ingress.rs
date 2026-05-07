use crate::{
    simplex::types::Certificate,
    types::View,
    Viewable,
};
use bytes::Bytes;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::{p2p::Producer, Consumer};
use commonware_utils::{
    channel::{
        actor::{self, ActorMailbox, Enqueue, FullPolicy, MessagePolicy},
        oneshot,
    },
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

impl<S: Scheme, D: Digest> MessagePolicy for MailboxMessage<S, D> {
    fn kind(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "certificate",
            Self::Certified { .. } => "certified",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        FullPolicy::Replace
    }

    fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        match &message {
            Self::Certificate(certificate) => {
                let key = certificate_key(certificate);
                actor::replace_last(queue, message, |pending| {
                    matches!(pending, Self::Certificate(pending) if certificate_key(pending) == key)
                })
            }
            Self::Certified { view, success } => {
                let view = *view;
                let success = *success;
                let mut message = Some(message);
                for pending in queue.iter_mut().rev() {
                    let Self::Certified {
                        view: pending_view,
                        success: pending_success,
                    } = pending
                    else {
                        continue;
                    };
                    if *pending_view != view {
                        continue;
                    }
                    *pending_success |= success;
                    message.take();
                    return Ok(());
                }
                Err(message.expect("message was not replaced"))
            }
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: ActorMailbox<MailboxMessage<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Create a new mailbox.
    pub fn new(sender: impl Into<ActorMailbox<MailboxMessage<S, D>>>) -> Self {
        Self {
            sender: sender.into(),
        }
    }

    /// Send a certificate.
    pub fn updated(&mut self, certificate: Certificate<S, D>) -> Enqueue {
        self.sender
            .enqueue(MailboxMessage::Certificate(certificate))
    }

    /// Notify the resolver of a certification result.
    pub fn certified(&mut self, view: View, success: bool) -> Enqueue {
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
    sender: ActorMailbox<HandlerMessage>,
}

impl Handler {
    pub fn new(sender: impl Into<ActorMailbox<HandlerMessage>>) -> Self {
        Self {
            sender: sender.into(),
        }
    }
}

impl MessagePolicy for HandlerMessage {
    fn kind(&self) -> &'static str {
        match self {
            Self::Deliver { .. } => "deliver",
            Self::Produce { .. } => "produce",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        FullPolicy::Replace
    }

    fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        match &message {
            Self::Deliver { .. } => actor::replace_last(queue, message, |pending| {
                matches!(pending, Self::Produce { .. })
            }),
            Self::Produce { view, .. } => {
                let view = *view;
                actor::replace_last(queue, message, |pending| {
                    matches!(pending, Self::Produce { view: pending, .. } if *pending == view)
                })
            }
        }
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
        if !matches!(result, Enqueue::Queued | Enqueue::Replaced) {
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
        if !matches!(result, Enqueue::Queued | Enqueue::Replaced) {
            return receiver;
        }
        receiver
    }
}
