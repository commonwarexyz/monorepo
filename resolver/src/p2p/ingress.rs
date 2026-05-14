use crate::Resolver;
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{vec::NonEmptyVec, Span};
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

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<K, P> {
    messages: VecDeque<Message<K, P>>,
}

impl<K, P> Default for Pending<K, P> {
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }
}

impl<K, P> Overflow<Message<K, P>> for Pending<K, P> {
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, P>) -> Option<Message<K, P>>,
    {
        while let Some(message) = self.messages.pop_front() {
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
        }
    }
}

impl<K: Eq, P: Clone + Eq> Pending<K, P> {
    fn push_request(&mut self, request: FetchRequest<K, P>) {
        for message in self.messages.iter_mut().rev() {
            match message {
                Message::Fetch(requests) => {
                    let Some(existing) = requests
                        .iter_mut()
                        .find(|existing| existing.key == request.key)
                    else {
                        continue;
                    };
                    merge_targets(&mut existing.targets, request.targets);
                    return;
                }
                Message::Cancel { key } if key == &request.key => break,
                Message::Clear | Message::Retain { .. } => break,
                Message::Cancel { .. } => {}
            }
        }
        self.messages.push_back(Message::Fetch(vec![request]));
    }

    fn remove_fetches(&mut self, mut keep: impl FnMut(&K) -> bool) {
        for message in &mut self.messages {
            if let Message::Fetch(requests) = message {
                requests.retain(|request| keep(&request.key));
            }
        }
        self.messages
            .retain(|message| !matches!(message, Message::Fetch(requests) if requests.is_empty()));
    }

    fn remove_cancels(&mut self, key: &K) {
        self.messages
            .retain(|message| !matches!(message, Message::Cancel { key: old } if old == key));
    }
}

fn merge_targets<P: Clone + Eq>(
    existing: &mut Option<NonEmptyVec<P>>,
    incoming: Option<NonEmptyVec<P>>,
) {
    let Some(incoming) = incoming else {
        *existing = None;
        return;
    };
    let Some(existing) = existing else {
        return;
    };

    let incoming = std::mem::replace(existing, incoming);
    let mut targets = incoming.into_vec();
    for target in existing.iter() {
        if !targets.contains(target) {
            targets.push(target.clone());
        }
    }
    *existing = NonEmptyVec::from_unchecked(targets);
}

impl<K: Eq, P: Clone + Eq> Policy for Message<K, P> {
    type Overflow = Pending<K, P>;

    fn handle(overflow: &mut Pending<K, P>, message: Self) {
        match message {
            Self::Fetch(requests) => {
                for request in requests {
                    overflow.push_request(request);
                }
            }
            Self::Cancel { key } => {
                overflow.remove_fetches(|old| old != &key);
                overflow.remove_cancels(&key);
                overflow.messages.push_back(Self::Cancel { key });
            }
            Self::Clear => {
                overflow.messages.clear();
                overflow.messages.push_back(Self::Clear);
            }
            Self::Retain { predicate } => {
                overflow.remove_fetches(|key| predicate(key));
                overflow.messages.push_back(Self::Retain { predicate });
            }
        }
    }
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K: Eq, P: Clone + Eq> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<K, P>>,
}

impl<K: Eq, P: Clone + Eq> Mailbox<K, P> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<K, P>>) -> Self {
        Self { sender }
    }
}

impl<K: Span, P: PublicKey> Resolver for Mailbox<K, P> {
    type Key = K;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch(&mut self, key: Self::Key) -> Feedback {
        self.sender
            .enqueue(Message::Fetch(vec![FetchRequest { key, targets: None }]))
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all(&mut self, keys: Vec<Self::Key>) -> Feedback {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|key| FetchRequest { key, targets: None })
                .collect(),
        ))
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        key: Self::Key,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
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
    ) -> Feedback {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|(key, targets)| FetchRequest {
                    key,
                    targets: Some(targets),
                })
                .collect(),
        ))
    }

    /// Send a cancel request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn cancel(&mut self, key: Self::Key) -> Feedback {
        self.sender.enqueue(Message::Cancel { key })
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) -> Feedback {
        self.sender.enqueue(Message::Retain {
            predicate: Box::new(predicate),
        })
    }

    /// Send a clear request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn clear(&mut self) -> Feedback {
        self.sender.enqueue(Message::Clear)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch(key: u8, targets: Option<NonEmptyVec<u8>>) -> Message<u8, u8> {
        Message::Fetch(vec![FetchRequest { key, targets }])
    }

    fn targets(values: &[u8]) -> NonEmptyVec<u8> {
        NonEmptyVec::from_unchecked(values.to_vec())
    }

    fn drain(pending: &mut Pending<u8, u8>) -> Vec<Message<u8, u8>> {
        let mut messages = Vec::new();
        Overflow::drain(pending, |message| {
            messages.push(message);
            None
        });
        messages
    }

    fn assert_fetch(
        message: &Message<u8, u8>,
        expected_key: u8,
        expected_targets: Option<&[u8]>,
    ) {
        let Message::Fetch(requests) = message else {
            panic!("expected fetch");
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].key, expected_key);
        match (&requests[0].targets, expected_targets) {
            (None, None) => {}
            (Some(actual), Some(expected)) => assert_eq!(&actual[..], expected),
            _ => panic!("unexpected targets"),
        }
    }

    #[test]
    fn targeted_fetches_for_same_key_are_merged() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, Some(targets(&[2, 3]))));
        Policy::handle(&mut pending, fetch(1, Some(targets(&[3, 4]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, Some(&[2, 3, 4]));
    }

    #[test]
    fn unrestricted_fetch_dominates_targeted_fetches() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, Some(targets(&[2]))));
        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, fetch(1, Some(targets(&[3]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, None);
    }

    #[test]
    fn cancel_removes_pending_fetch_but_is_retained() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, fetch(2, None));
        Policy::handle(&mut pending, Message::Cancel { key: 1 });

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert_fetch(&messages[0], 2, None);
        assert!(matches!(messages[1], Message::Cancel { key: 1 }));
    }

    #[test]
    fn fetch_after_cancel_preserves_order() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, Message::Cancel { key: 1 });
        Policy::handle(&mut pending, fetch(1, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { key: 1 }));
        assert_fetch(&messages[1], 1, None);
    }

    #[test]
    fn retain_removes_fetches_for_dropped_keys() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, fetch(2, None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|key| *key == 2),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert_fetch(&messages[0], 2, None);
        assert!(matches!(messages[1], Message::Retain { .. }));
    }

    #[test]
    fn clear_supersedes_prior_pending_actions() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, Message::Cancel { key: 2 });
        Policy::handle(&mut pending, Message::Clear);
        Policy::handle(&mut pending, fetch(3, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Clear));
        assert_fetch(&messages[1], 3, None);
    }
}
