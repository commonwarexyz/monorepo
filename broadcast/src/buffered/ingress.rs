use crate::Broadcaster;
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digested, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::oneshot;
use std::collections::{BTreeMap, VecDeque};

/// Message types that can be sent to the `Mailbox`
pub(crate) enum Message<P: PublicKey, M: Digestible> {
    /// Broadcast a [crate::Broadcaster::Message] to the network.
    Broadcast {
        recipients: Recipients<P>,
        message: Digested<M>,
    },

    /// Subscribe to receive a message by digest.
    Subscribe {
        digest: M::Digest,
        responder: oneshot::Sender<Digested<M>>,
    },

    /// Get a message by digest.
    Get {
        digest: M::Digest,
        responder: oneshot::Sender<Option<Digested<M>>>,
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

/// A queued request with broadcast recipients stored separately for coalescing.
enum PendingEntry<P: PublicKey, M: Digestible> {
    /// A get or subscription request.
    Message(Message<P, M>),
    /// A broadcast whose recipients are held in [`Pending::broadcasts`].
    Broadcast(Digested<M>),
}

/// Requests waiting for room in the engine's inbox.
///
/// Each pending broadcast digest occurs exactly once in both `queue` and `broadcasts`.
pub(crate) struct Pending<P: PublicKey, M: Digestible> {
    /// Requests in arrival order, with coalesced broadcasts at their first position.
    queue: VecDeque<PendingEntry<P, M>>,
    /// Recipients for exactly the broadcasts in `queue`.
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

impl<P: PublicKey, M: Digestible> Pending<P, M> {
    /// Restores a rejected message and its recipient index at the front of the queue.
    fn requeue_front(&mut self, rejected: Message<P, M>) {
        match rejected {
            Message::Broadcast {
                recipients,
                message,
            } => {
                self.broadcasts.insert(message.digest(), recipients);
                self.queue.push_front(PendingEntry::Broadcast(message));
            }
            message => self.queue.push_front(PendingEntry::Message(message)),
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
            // Skip canceled requests and rebuild broadcasts with their coalesced recipients.
            let message = match entry {
                PendingEntry::Message(message) => {
                    if message.response_closed() {
                        continue;
                    }
                    message
                }
                PendingEntry::Broadcast(message) => {
                    let recipients = self
                        .broadcasts
                        .remove(&message.digest())
                        .expect("queued broadcast must have recipients");
                    Message::Broadcast {
                        recipients,
                        message,
                    }
                }
            };

            // Retain the rejected message before allowing any later request to advance.
            if let Some(rejected) = push(message) {
                self.requeue_front(rejected);
                break;
            }
        }
    }
}

impl<P: PublicKey, M: Digestible> Policy for Message<P, M> {
    type Overflow = Pending<P, M>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }

        // Merge at the first queued occurrence so duplicates cannot postpone its delivery.
        if let Self::Broadcast {
            recipients,
            message,
        } = message
        {
            let digest = message.digest();
            if let Some(queued) = overflow.broadcasts.get_mut(&digest) {
                queued.union_with(recipients);
                return;
            }
            overflow.broadcasts.insert(digest, recipients);
            overflow.queue.push_back(PendingEntry::Broadcast(message));
            return;
        }

        // Keep each get or subscription request in arrival order with its own responder.
        overflow.queue.push_back(PendingEntry::Message(message));
    }
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
    /// Resolves with the message if cached when this request is handled. Otherwise, waits for
    /// a matching local broadcast or network message to be handled. Dropping the receiver
    /// cancels the request.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    pub fn subscribe(&self, digest: M::Digest) -> oneshot::Receiver<Digested<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::Subscribe { digest, responder });
        receiver
    }

    /// Get the message cached under this digest when the request is handled.
    ///
    /// If the engine has shut down, returns `None`.
    pub async fn get(&self, digest: M::Digest) -> Option<Digested<M>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Get { digest, responder });
        receiver.await.unwrap_or_default()
    }
}

impl<P: PublicKey, M: Digestible + Codec> Broadcaster for Mailbox<P, M> {
    type Recipients = Recipients<P>;
    type Message = Digested<M>;

    /// Broadcast a message to recipients.
    ///
    /// If the engine has shut down, returns [`Feedback::Closed`].
    fn broadcast(&self, recipients: Self::Recipients, message: Self::Message) -> Feedback {
        self.sender.enqueue(Message::Broadcast {
            recipients,
            message,
        })
    }
}
