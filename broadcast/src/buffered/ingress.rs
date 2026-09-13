use crate::Broadcaster;
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

/// Message types that can be sent to the `Mailbox`
pub(crate) enum Message<P: PublicKey, M: Digestible> {
    /// Broadcast a [crate::Broadcaster::Message] to the network.
    Broadcast {
        recipients: Recipients<P>,
        message: Arc<M>,
    },

    /// Subscribe to receive a message by digest.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    Subscribe {
        digest: M::Digest,
        responder: oneshot::Sender<Arc<M>>,
    },

    /// Get a message by digest.
    Get {
        digest: M::Digest,
        responder: oneshot::Sender<Option<Arc<M>>>,
    },
}

impl<P: PublicKey, M: Digestible> Message<P, M> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Subscribe { responder, .. } => responder.is_closed(),
            Self::Get { responder, .. } => responder.is_closed(),
            Self::Broadcast { .. } => false,
        }
    }
}

enum PendingEntry<P: PublicKey, M: Digestible> {
    Message(Message<P, M>),
    Broadcast { digest: M::Digest, message: Arc<M> },
}

pub(crate) struct Pending<P: PublicKey, M: Digestible> {
    queue: VecDeque<PendingEntry<P, M>>,
    broadcasts: BTreeMap<M::Digest, Recipients<P>>,
}

impl<P: PublicKey, M: Digestible> Default for Pending<P, M> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            broadcasts: BTreeMap::new(),
        }
    }
}

impl<P: PublicKey, M: Digestible> Overflow<Message<P, M>> for Pending<P, M> {
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<P, M>) -> Option<Message<P, M>>,
    {
        while let Some(entry) = self.queue.pop_front() {
            let (message, digest) = match entry {
                PendingEntry::Message(message) => {
                    if message.response_closed() {
                        continue;
                    }
                    (message, None)
                }
                PendingEntry::Broadcast { digest, message } => {
                    let recipients = self
                        .broadcasts
                        .remove(&digest)
                        .expect("every queued broadcast has recipients");
                    (
                        Message::Broadcast {
                            recipients,
                            message,
                        },
                        Some(digest),
                    )
                }
            };

            let Some(message) = push(message) else {
                continue;
            };
            match (digest, message) {
                (
                    Some(digest),
                    Message::Broadcast {
                        recipients,
                        message,
                    },
                ) => {
                    self.broadcasts.insert(digest, recipients);
                    self.queue
                        .push_front(PendingEntry::Broadcast { digest, message });
                }
                (_, message) => self.queue.push_front(PendingEntry::Message(message)),
            }
            break;
        }
    }
}

impl<P: PublicKey, M: Digestible> Policy for Message<P, M> {
    type Overflow = Pending<P, M>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        if let Self::Broadcast {
            recipients,
            message,
        } = message
        {
            let digest = message.digest();
            if let Some(queued) = overflow.broadcasts.get_mut(&digest) {
                merge_recipients(queued, recipients);
                return;
            }
            overflow.broadcasts.insert(digest, recipients);
            overflow
                .queue
                .push_back(PendingEntry::Broadcast { digest, message });
            return;
        }

        overflow.queue.push_back(PendingEntry::Message(message));
    }
}

fn merge_recipients<P: PublicKey>(current: &mut Recipients<P>, incoming: Recipients<P>) {
    let previous = std::mem::replace(current, Recipients::Some(Vec::new()));
    *current = match (previous, incoming) {
        (Recipients::All, _) | (_, Recipients::All) => Recipients::All,
        (left, right) => {
            let mut recipients = match left {
                Recipients::One(peer) => vec![peer],
                Recipients::Some(peers) => peers,
                Recipients::All => unreachable!("all recipients handled above"),
            };
            match right {
                Recipients::One(peer) => {
                    if !recipients.contains(&peer) {
                        recipients.push(peer);
                    }
                }
                Recipients::Some(peers) => {
                    for peer in peers {
                        if !recipients.contains(&peer) {
                            recipients.push(peer);
                        }
                    }
                }
                Recipients::All => unreachable!("all recipients handled above"),
            }
            match recipients.as_slice() {
                [peer] => Recipients::One(peer.clone()),
                _ => Recipients::Some(recipients),
            }
        }
    };
}

/// Ingress mailbox for [super::Engine].
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, M: Digestible + Codec> {
    sender: Sender<Message<P, M>>,
}

impl<P: PublicKey, M: Digestible + Codec> Mailbox<P, M> {
    pub(super) const fn new(sender: Sender<Message<P, M>>) -> Self {
        Self { sender }
    }

    /// Subscribe to a message by digest.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    pub fn subscribe(&self, digest: M::Digest) -> oneshot::Receiver<Arc<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::Subscribe { digest, responder });
        receiver
    }

    /// Get a message by digest.
    ///
    /// If the engine has shut down, returns `None`.
    pub async fn get(&self, digest: M::Digest) -> Option<Arc<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Get { digest, responder });
        receiver.await.unwrap_or_default()
    }

    /// Broadcast a shared message to recipients.
    ///
    /// If the engine has shut down, returns [`Feedback::Closed`].
    pub fn broadcast_shared(&self, recipients: Recipients<P>, message: Arc<M>) -> Feedback {
        self.sender.enqueue(Message::Broadcast {
            recipients,
            message,
        })
    }
}

impl<P: PublicKey, M: Digestible + Codec> Broadcaster for Mailbox<P, M> {
    type Recipients = Recipients<P>;
    type Message = M;

    /// Broadcast a message to recipients.
    ///
    /// If the engine has shut down, returns [`Feedback::Closed`].
    fn broadcast(&self, recipients: Self::Recipients, message: Self::Message) -> Feedback {
        self.broadcast_shared(recipients, Arc::new(message))
    }
}
