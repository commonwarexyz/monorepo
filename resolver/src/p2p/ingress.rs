use crate::{Fetch, Resolver};
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{vec::NonEmptyVec, Span};
use std::collections::VecDeque;

type Predicate<K, S> = Box<dyn Fn(&K, &S) -> bool + Send>;

/// A key to fetch data for, optionally with target peers.
pub struct FetchKey<K, P, S> {
    /// The key to fetch.
    pub key: K,
    /// The subscribers used to decide whether the fetch should be retained.
    pub subscribers: NonEmptyVec<S>,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P, S> {
    /// Initiate fetches.
    Fetch(Vec<FetchKey<K, P, S>>),

    /// Retain only fetch subscribers that satisfy the predicate.
    Retain { predicate: Predicate<K, S> },
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<K, P, S> {
    modifications: VecDeque<Predicate<K, S>>,
    fetches: Vec<FetchKey<K, P, S>>,
}

impl<K, P, S> Default for Pending<K, P, S> {
    fn default() -> Self {
        Self {
            modifications: VecDeque::new(),
            fetches: Vec::new(),
        }
    }
}

impl<K, P, S> Overflow<Message<K, P, S>> for Pending<K, P, S> {
    fn is_empty(&self) -> bool {
        self.modifications.is_empty() && self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, P, S>) -> Option<Message<K, P, S>>,
    {
        // Drain retains in the order they were received.
        while let Some(predicate) = self.modifications.pop_front() {
            let message = Message::Retain { predicate };
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

impl<K, P, S> Pending<K, P, S> {
    fn push_front(&mut self, message: Message<K, P, S>) {
        match message {
            Message::Retain { predicate } => {
                self.modifications.push_front(predicate);
            }
            Message::Fetch(fetches) => {
                self.fetches.splice(0..0, fetches);
            }
        }
    }
}

fn retain_fetch<K, P, S>(
    mut fetch: FetchKey<K, P, S>,
    predicate: &(dyn Fn(&K, &S) -> bool + Send),
) -> Option<FetchKey<K, P, S>> {
    let mut subscribers = fetch.subscribers.into_vec();
    subscribers.retain(|subscriber| predicate(&fetch.key, subscriber));
    fetch.subscribers = NonEmptyVec::try_from(subscribers).ok()?;
    Some(fetch)
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

impl<K, P, S> Policy for Message<K, P, S>
where
    K: Clone + Eq,
    P: Eq,
    S: Eq,
{
    type Overflow = Pending<K, P, S>;

    fn handle(overflow: &mut Pending<K, P, S>, message: Self) -> bool {
        match message {
            Self::Fetch(keys) => {
                for key in keys {
                    let FetchKey {
                        key,
                        subscribers,
                        targets,
                    } = key;

                    // Merge duplicate fetches for the same key.
                    if let Some(existing) = overflow
                        .fetches
                        .iter_mut()
                        .find(|existing| existing.key == key)
                    {
                        existing.subscribers.extend(subscribers);
                        merge_targets(&mut existing.targets, targets);
                    } else {
                        overflow.fetches.push(FetchKey {
                            key,
                            subscribers,
                            targets,
                        });
                    }
                }
            }
            Self::Retain { predicate } => {
                // Retain prunes pending fetch subscribers before queued fetches drain.
                overflow.fetches = std::mem::take(&mut overflow.fetches)
                    .into_iter()
                    .filter_map(|fetch| retain_fetch(fetch, predicate.as_ref()))
                    .collect();
                overflow.modifications.push_back(predicate);
            }
        }
        true
    }
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K: Span, P: Eq, S: Eq = ()> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<K, P, S>>,
}

impl<K: Span, P: Eq, S: Eq> Mailbox<K, P, S> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<K, P, S>>) -> Self {
        Self { sender }
    }
}

impl<K, P, S> Resolver for Mailbox<K, P, S>
where
    K: Span,
    P: PublicKey,
    S: Clone + Eq + Send + 'static,
{
    type Key = K;
    type Subscriber = S;
    type PublicKey = P;

    /// Send a fetch to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch<D>(&mut self, key: D) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        let key = key.into();
        let (key, subscriber) = key.into_parts();
        self.sender.enqueue(Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::new(subscriber),
            targets: None,
        }]))
    }

    /// Send fetches to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all<D>(&mut self, keys: Vec<D>) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|key| {
                    let (key, subscriber) = key.into().into_parts();
                    FetchKey {
                        key,
                        subscribers: NonEmptyVec::new(subscriber),
                        targets: None,
                    }
                })
                .collect(),
        ))
    }

    /// Send a targeted fetch to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        key: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        let key = key.into();
        let (key, subscriber) = key.into_parts();
        self.sender.enqueue(Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::new(subscriber),
            targets: Some(targets),
        }]))
    }

    /// Send targeted fetches to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted<D>(&mut self, keys: Vec<(D, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|(key, targets)| {
                    let (key, subscriber) = key.into().into_parts();
                    FetchKey {
                        key,
                        subscribers: NonEmptyVec::new(subscriber),
                        targets: Some(targets),
                    }
                })
                .collect(),
        ))
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.sender.enqueue(Message::Retain {
            predicate: Box::new(predicate),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestMessage = Message<u8, u8, u16>;
    type TestPending = Pending<u8, u8, u16>;

    fn fetch(key: u8, subscriber: u16, targets: Option<NonEmptyVec<u8>>) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::new(subscriber),
            targets,
        }])
    }

    fn fetch_with_subscribers(
        key: u8,
        subscribers: Vec<u16>,
        targets: Option<NonEmptyVec<u8>>,
    ) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::from_unchecked(subscribers),
            targets,
        }])
    }

    fn subscriber_is(value: u16) -> impl Fn(&u8, &u16) -> bool + Send {
        move |_, subscriber| *subscriber == value
    }

    fn targets(values: &[u8]) -> NonEmptyVec<u8> {
        NonEmptyVec::from_unchecked(values.to_vec())
    }

    fn drain(pending: &mut TestPending) -> Vec<TestMessage> {
        let mut messages = Vec::new();
        Overflow::drain(pending, |message| {
            messages.push(message);
            None
        });
        messages
    }

    fn assert_fetch(message: &TestMessage, expected_key: u8, expected_targets: Option<&[u8]>) {
        let Message::Fetch(keys) = message else {
            panic!("expected fetch");
        };
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, expected_key);
        match (&keys[0].targets, expected_targets) {
            (None, None) => {}
            (Some(actual), Some(expected)) => assert_eq!(&actual[..], expected),
            _ => panic!("unexpected targets"),
        }
    }

    fn assert_fetch_keys(message: &TestMessage, expected: &[u8]) {
        let Message::Fetch(keys) = message else {
            panic!("expected fetch");
        };
        let actual: Vec<_> = keys.iter().map(|key| key.key).collect();
        assert_eq!(actual, expected);
    }

    fn assert_fetch_subscribers(
        message: &TestMessage,
        expected_key: u8,
        expected_subscribers: &[u16],
    ) {
        let Message::Fetch(keys) = message else {
            panic!("expected fetch");
        };
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, expected_key);
        assert_eq!(&keys[0].subscribers[..], expected_subscribers);
    }

    #[test]
    fn targeted_fetches_for_same_key_are_merged() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, Some(targets(&[2, 3]))));
        Policy::handle(&mut pending, fetch(1, 11, Some(targets(&[3, 4]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, Some(&[2, 3, 4]));
        assert_fetch_subscribers(&messages[0], 1, &[10, 11]);
    }

    #[test]
    fn duplicate_fetches_for_same_key_merge_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10], None));
        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![11], None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch_subscribers(&messages[0], 1, &[10, 11]);
    }

    #[test]
    fn unrestricted_fetch_dominates_targeted_fetches() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, Some(targets(&[2]))));
        Policy::handle(&mut pending, fetch(1, 11, None));
        Policy::handle(&mut pending, fetch(1, 12, Some(targets(&[3]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, None);
    }

    #[test]
    fn retain_removes_fetches_for_dropped_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, fetch(2, 11, None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(11)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn retain_prunes_pending_fetch_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11], None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(11)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch_subscribers(&messages[1], 1, &[11]);
    }

    #[test]
    fn retain_drops_pending_fetch_when_all_subscribers_are_dropped() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11], None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(12)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], Message::Retain { .. }));
    }

    #[test]
    fn fetch_after_retain_is_retained_when_subscriber_is_dropped() {
        let mut pending = TestPending::default();

        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|_, subscriber| *subscriber != 10),
            },
        );
        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, fetch(2, 11, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch_keys(&messages[1], &[1, 2]);
    }
}
