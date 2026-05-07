use crate::Resolver;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::actor::{self, ActorMailbox, Backpressure, Enqueue, MessagePolicy},
    vec::NonEmptyVec,
    Span,
};
use std::collections::VecDeque;

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P> {
    /// The key to fetch.
    pub key: K,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<K, P>>),

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Predicate<K> },
}

fn merge_targets<P: PartialEq>(
    existing: &mut Option<NonEmptyVec<P>>,
    incoming: Option<NonEmptyVec<P>>,
) {
    match (existing, incoming) {
        (existing @ Some(_), None) => *existing = None,
        (Some(existing), Some(incoming)) => {
            for peer in incoming.into_vec() {
                if !existing.contains(&peer) {
                    existing.push(peer);
                }
            }
        }
        (None, _) => {}
    }
}

fn merge_fetches<K: Eq, P: PartialEq>(
    pending: &mut Vec<FetchRequest<K, P>>,
    incoming: Vec<FetchRequest<K, P>>,
) {
    for request in incoming {
        match pending.iter_mut().find(|pending| pending.key == request.key) {
            Some(pending) => merge_targets(&mut pending.targets, request.targets),
            None => pending.push(request),
        }
    }
}

impl<K: Span, P: PublicKey> MessagePolicy for Message<K, P> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::replace_or_queue(match message {
            Self::Fetch(requests) => {
                if requests.is_empty() {
                    Ok(())
                } else if let Some(Self::Fetch(existing)) =
                    actor::find_last_mut(queue, |pending| matches!(pending, Self::Fetch(_)))
                {
                    merge_fetches(existing, requests);
                    Ok(())
                } else {
                    Err(Self::Fetch(requests))
                }
            }
            Self::Cancel { key } => {
                actor::replace_last(queue, Self::Cancel { key: key.clone() }, |pending| {
                    matches!(pending, Self::Cancel { key: pending } if pending == &key)
                })
            }
            Self::Clear => {
                queue.clear();
                queue.push_back(Self::Clear);
                Ok(())
            }
            Self::Retain { predicate } => actor::replace_last(
                queue,
                Self::Retain { predicate },
                |pending| matches!(pending, Self::Retain { .. }),
            ),
        }, queue)
    }
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K: Span, P: PublicKey> {
    /// The channel that delivers messages to the peer actor.
    sender: ActorMailbox<Message<K, P>>,
}

impl<K: Span, P: PublicKey> Mailbox<K, P> {
    /// Create a new mailbox.
    pub(super) fn new(sender: ActorMailbox<Message<K, P>>) -> Self {
        Self { sender }
    }
}

impl<K: Span, P: PublicKey> Resolver for Mailbox<K, P> {
    type Key = K;
    type Message = self::Message<K, P>;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch(&mut self, key: Self::Key) -> Enqueue<Self::Message> {
        self.sender
            .enqueue(Message::Fetch(vec![FetchRequest { key, targets: None }]))
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all(&mut self, keys: Vec<Self::Key>) -> Enqueue<Self::Message> {
        let requests: Vec<_> = keys
            .into_iter()
            .map(|key| FetchRequest { key, targets: None })
            .collect();
        if requests.is_empty() {
            return Enqueue::Rejected(Message::Fetch(requests));
        }
        self.sender.enqueue(Message::Fetch(requests))
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        key: Self::Key,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Enqueue<Self::Message> {
        self.sender
            .enqueue(Message::Fetch(vec![FetchRequest {
                key,
                targets: Some(targets),
            }]))
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) -> Enqueue<Self::Message> {
        let requests: Vec<_> = requests
            .into_iter()
            .map(|(key, targets)| FetchRequest {
                key,
                targets: Some(targets),
            })
            .collect();
        if requests.is_empty() {
            return Enqueue::Rejected(Message::Fetch(requests));
        }
        self.sender.enqueue(Message::Fetch(requests))
    }

    /// Send a cancel request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn cancel(&mut self, key: Self::Key) -> Enqueue<Self::Message> {
        self.sender.enqueue(Message::Cancel { key })
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key) -> bool + Send + 'static,
    ) -> Enqueue<Self::Message> {
        self.sender.enqueue(Message::Retain {
            predicate: Box::new(predicate),
        })
    }

    /// Send a clear request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn clear(&mut self) -> Enqueue<Self::Message> {
        self.sender.enqueue(Message::Clear)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519::PublicKey;

    #[commonware_macros::test_async]
    async fn full_mailbox_merges_fetch_requests() {
        let (sender, mut receiver) = actor::channel(1);
        let mut mailbox = Mailbox::<u64, PublicKey>::new(sender);

        assert!(matches!(mailbox.fetch(1), Enqueue::Queued));
        assert!(matches!(mailbox.fetch(2), Enqueue::Replaced));

        let Some(Message::Fetch(requests)) = receiver.recv().await else {
            panic!("expected fetch message");
        };
        let keys = requests
            .into_iter()
            .map(|request| request.key)
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 2]);
    }
}
