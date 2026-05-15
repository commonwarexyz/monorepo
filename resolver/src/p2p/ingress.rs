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

enum Modification<K> {
    Cancel { key: K },
    Retain { predicate: Predicate<K> },
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<K, P> {
    clear: bool,
    modifications: VecDeque<Modification<K>>,
    fetches: Vec<FetchRequest<K, P>>,
}

impl<K, P> Default for Pending<K, P> {
    fn default() -> Self {
        Self {
            clear: false,
            modifications: VecDeque::new(),
            fetches: Vec::new(),
        }
    }
}

impl<K, P> Overflow<Message<K, P>> for Pending<K, P> {
    fn is_empty(&self) -> bool {
        !self.clear && self.modifications.is_empty() && self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, P>) -> Option<Message<K, P>>,
    {
        if self.clear {
            self.clear = false;
            if let Some(message) = push(Message::Clear) {
                self.push_front(message);
                return;
            }
        }

        while let Some(modification) = self.modifications.pop_front() {
            let message = match modification {
                Modification::Cancel { key } => Message::Cancel { key },
                Modification::Retain { predicate } => Message::Retain { predicate },
            };
            if let Some(message) = push(message) {
                self.push_front(message);
                return;
            }
        }

        if !self.fetches.is_empty() {
            let fetches = std::mem::take(&mut self.fetches);
            if let Some(message) = push(Message::Fetch(fetches)) {
                self.push_front(message);
            }
        }
    }
}

impl<K, P> Pending<K, P> {
    fn push_front(&mut self, message: Message<K, P>) {
        match message {
            Message::Clear => self.clear = true,
            Message::Retain { predicate } => {
                self.modifications
                    .push_front(Modification::Retain { predicate });
            }
            Message::Cancel { key } => {
                self.modifications.push_front(Modification::Cancel { key });
            }
            Message::Fetch(fetches) => {
                self.fetches.splice(0..0, fetches);
            }
        }
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
        if overflow.clear {
            return;
        }

        match message {
            Self::Fetch(requests) => {
                for request in requests {
                    let FetchRequest { key, targets } = request;

                    // Drop fetches already canceled or pruned in overflow
                    if overflow.modifications.iter().any(|modification| {
                        matches!(modification, Modification::Cancel { key: cancel } if cancel == &key)
                            || matches!(modification, Modification::Retain { predicate } if !predicate(&key))
                    }) {
                        continue;
                    }

                    // Merge duplicate fetches for the same key
                    if let Some(existing) = overflow
                        .fetches
                        .iter_mut()
                        .find(|existing| existing.key == key)
                    {
                        merge_targets(&mut existing.targets, targets);
                    } else {
                        overflow.fetches.push(FetchRequest { key, targets });
                    }
                }
            }
            Self::Cancel { key } => {
                // Cancel supersedes pending fetches for the key
                overflow.fetches.retain(|request| request.key != key);

                // Retain only the first queued cancel for a key
                if overflow
                    .modifications
                    .iter()
                    .all(|modification| {
                        !matches!(modification, Modification::Cancel { key: cancel } if cancel == &key)
                    })
                {
                    overflow.modifications.push_back(Modification::Cancel { key });
                }
            }
            Self::Clear => {
                // Clear supersedes pending modifications and fetches
                overflow.clear = true;
                overflow.modifications.clear();
                overflow.fetches.clear();
            }
            Self::Retain { predicate } => {
                // Retain prunes pending fetches before queued fetches drain
                overflow.fetches.retain(|request| predicate(&request.key));
                overflow
                    .modifications
                    .push_back(Modification::Retain { predicate });
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

    fn assert_fetch(message: &Message<u8, u8>, expected_key: u8, expected_targets: Option<&[u8]>) {
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
        assert!(matches!(messages[0], Message::Cancel { key: 1 }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn fetch_after_cancel_is_ignored() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, Message::Cancel { key: 1 });
        Policy::handle(&mut pending, fetch(1, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], Message::Cancel { key: 1 }));
    }

    #[test]
    fn duplicate_cancel_keeps_original_position() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, Message::Cancel { key: 1 });
        Policy::handle(&mut pending, fetch(2, None));
        Policy::handle(&mut pending, Message::Cancel { key: 1 });

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { key: 1 }));
        assert_fetch(&messages[1], 2, None);
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
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn clear_supersedes_prior_pending_actions() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, Message::Cancel { key: 2 });
        Policy::handle(&mut pending, Message::Clear);
        Policy::handle(&mut pending, fetch(3, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], Message::Clear));
    }

    #[test]
    fn fetch_after_retain_is_ignored_when_key_is_dropped() {
        let mut pending = Pending::default();

        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|key| *key != 1),
            },
        );
        Policy::handle(&mut pending, fetch(1, None));
        Policy::handle(&mut pending, fetch(2, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn clear_supersedes_modifications() {
        let mut pending = Pending::default();

        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|key| *key != 1),
            },
        );
        Policy::handle(&mut pending, Message::Clear);
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|key| *key != 2),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], Message::Clear));
    }
}
