use crate::{Resolver, Subscribers};
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{vec::NonEmptyVec, Span};
use std::collections::VecDeque;

type Predicate<R> = Box<dyn Fn(&R) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P, R = K> {
    /// The key to fetch.
    pub key: K,
    /// The subscribers used to decide whether the fetch should be retained.
    pub subscribers: Vec<R>,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P, R = K> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<K, P, R>>),

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests without a subscriber that satisfies the predicate.
    Retain { predicate: Predicate<R> },
}

enum Modification<K, R> {
    Cancel { key: K },
    Retain { predicate: Predicate<R> },
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<K, P, R = K> {
    clear: bool,
    modifications: VecDeque<Modification<K, R>>,
    fetches: Vec<FetchRequest<K, P, R>>,
}

impl<K, P, R> Default for Pending<K, P, R> {
    fn default() -> Self {
        Self {
            clear: false,
            modifications: VecDeque::new(),
            fetches: Vec::new(),
        }
    }
}

impl<K, P, R> Overflow<Message<K, P, R>> for Pending<K, P, R> {
    fn is_empty(&self) -> bool {
        !self.clear && self.modifications.is_empty() && self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, P, R>) -> Option<Message<K, P, R>>,
    {
        // Clear drains before later modifications and fetches.
        if self.clear {
            self.clear = false;
            if let Some(message) = push(Message::Clear) {
                self.push_front(message);
                return;
            }
        }

        // Drain cancels and retains in the order they were received.
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

        // Fetches are deduplicated and drained as one batch.
        if !self.fetches.is_empty() {
            let fetches = std::mem::take(&mut self.fetches);
            if let Some(message) = push(Message::Fetch(fetches)) {
                self.push_front(message);
            }
        }
    }
}

impl<K, P, R> Pending<K, P, R> {
    fn push_front(&mut self, message: Message<K, P, R>) {
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

fn retain_subscribers<K: Clone, R: From<K>>(
    key: &K,
    subscribers: &mut Vec<R>,
    predicate: &dyn Fn(&R) -> bool,
) -> bool {
    if subscribers.is_empty() {
        return predicate(&R::from(key.clone()));
    }

    subscribers.retain(|subscriber| predicate(subscriber));
    !subscribers.is_empty()
}

// Merge target metadata for duplicate pending fetches.
fn merge_targets<P: Eq>(existing: &mut Option<NonEmptyVec<P>>, incoming: Option<NonEmptyVec<P>>) {
    // An unrestricted fetch clears existing targets.
    let Some(incoming) = incoming else {
        *existing = None;
        return;
    };

    // Existing unrestricted fetch already covers all targets.
    let Some(existing) = existing else {
        return;
    };

    // Merge target sets without duplicating peers.
    for target in incoming {
        if !existing.contains(&target) {
            existing.push(target);
        }
    }
}

impl<K, P, R> Policy for Message<K, P, R>
where
    K: Clone + Eq,
    P: Eq,
    R: From<K>,
{
    type Overflow = Pending<K, P, R>;

    fn handle(overflow: &mut Pending<K, P, R>, message: Self) {
        match message {
            Self::Fetch(requests) => {
                for request in requests {
                    let FetchRequest {
                        key,
                        subscribers,
                        targets,
                    } = request;

                    // Merge duplicate fetches for the same key.
                    if let Some(existing) = overflow
                        .fetches
                        .iter_mut()
                        .find(|existing| existing.key == key)
                    {
                        existing.subscribers.extend(subscribers);
                        merge_targets(&mut existing.targets, targets);
                    } else {
                        overflow.fetches.push(FetchRequest {
                            key,
                            subscribers,
                            targets,
                        });
                    }
                }
            }
            Self::Cancel { key } => {
                // Cancel supersedes pending fetches for the key.
                overflow.fetches.retain(|request| request.key != key);

                // Retain only the first queued cancel for a key.
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
                // Clear supersedes pending modifications and fetches.
                overflow.clear = true;
                overflow.modifications.clear();
                overflow.fetches.clear();
            }
            Self::Retain { predicate } => {
                // Retain prunes pending fetch subscribers before queued fetches drain.
                overflow.fetches.retain_mut(|request| {
                    retain_subscribers(&request.key, &mut request.subscribers, predicate.as_ref())
                });
                overflow
                    .modifications
                    .push_back(Modification::Retain { predicate });
            }
        }
    }
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K: Span, P: Eq, R: From<K> = K> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<K, P, R>>,
}

impl<K: Span, P: Eq, R: From<K>> Mailbox<K, P, R> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<K, P, R>>) -> Self {
        Self { sender }
    }
}

impl<K, P, R> Resolver for Mailbox<K, P, R>
where
    K: Span,
    P: PublicKey,
    R: Clone + From<K> + Send + 'static,
{
    type Key = K;
    type Subscriber = R;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch<D>(&mut self, request: D) -> Feedback
    where
        D: Into<Subscribers<Self::Key, Self::Subscriber>> + Send,
    {
        let request = request.into();
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            key: request.request,
            subscribers: request.subscribers,
            targets: None,
        }]))
    }

    /// Send a fetch request to the peer actor for a batch of requests.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all<D>(&mut self, requests: Vec<D>) -> Feedback
    where
        D: Into<Subscribers<Self::Key, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|request| {
                    let request = request.into();
                    FetchRequest {
                        key: request.request,
                        subscribers: request.subscribers,
                        targets: None,
                    }
                })
                .collect(),
        ))
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        request: impl Into<Subscribers<Self::Key, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        let request = request.into();
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            key: request.request,
            subscribers: request.subscribers,
            targets: Some(targets),
        }]))
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted<D>(
        &mut self,
        requests: Vec<(D, NonEmptyVec<Self::PublicKey>)>,
    ) -> Feedback
    where
        D: Into<Subscribers<Self::Key, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|(request, targets)| {
                    let request = request.into();
                    FetchRequest {
                        key: request.request,
                        subscribers: request.subscribers,
                        targets: Some(targets),
                    }
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
    fn retain(&mut self, predicate: impl Fn(&Self::Subscriber) -> bool + Send + 'static) -> Feedback {
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
        Message::Fetch(vec![FetchRequest {
            key,
            subscribers: vec![key],
            targets,
        }])
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

    fn assert_fetch_keys(message: &Message<u8, u8>, expected: &[u8]) {
        let Message::Fetch(requests) = message else {
            panic!("expected fetch");
        };
        let keys: Vec<_> = requests.iter().map(|request| request.key).collect();
        assert_eq!(keys, expected);
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
    fn fetch_after_cancel_is_retained() {
        let mut pending = Pending::default();

        Policy::handle(&mut pending, Message::Cancel { key: 1 });
        Policy::handle(&mut pending, fetch(1, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { key: 1 }));
        assert_fetch(&messages[1], 1, None);
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
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Clear));
        assert_fetch(&messages[1], 3, None);
    }

    #[test]
    fn fetch_after_retain_is_retained_when_key_is_dropped() {
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
        assert_fetch_keys(&messages[1], &[1, 2]);
    }

    #[test]
    fn clear_supersedes_prior_modifications() {
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
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Clear));
        let Message::Retain { predicate } = &messages[1] else {
            panic!("expected retain");
        };
        assert!(predicate(&1));
        assert!(!predicate(&2));
    }
}
