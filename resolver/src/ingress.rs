//! Mailbox ingress helpers for resolver implementations.
//!
//! This module provides the common actor-facing message shape for resolvers
//! that coalesce fetches by key and prune queued work with retain predicates.

use crate::Fetch;
use commonware_actor::mailbox::{Overflow, Policy};
use commonware_utils::vec::NonEmptyVec;
use std::collections::VecDeque;

/// Predicate used to retain subscribers for resolver keys.
pub type Predicate<K, S> = Box<dyn Fn(&K, &S) -> bool + Send>;

/// A peer-visible key plus local subscribers waiting on it.
pub struct FetchKey<K, S> {
    /// The key to fetch.
    pub key: K,

    /// Subscribers used to decide whether the fetch should be retained.
    pub subscribers: NonEmptyVec<S>,
}

impl<K, S> From<Fetch<K, S>> for FetchKey<K, S> {
    fn from(fetch: Fetch<K, S>) -> Self {
        Self {
            key: fetch.key,
            subscribers: NonEmptyVec::new(fetch.subscriber),
        }
    }
}

/// Actor message for fetch and retain ingress.
pub enum Message<K, S> {
    /// Initiate fetches.
    Fetch(Vec<FetchKey<K, S>>),

    /// Retain only fetch subscribers that satisfy the predicate.
    Retain {
        /// Predicate applied to each tracked `(key, subscriber)` pair.
        predicate: Predicate<K, S>,
    },
}

/// Pending resolver messages retained after a mailbox fills.
pub struct Pending<K, S> {
    /// Retain predicates waiting to run before fetches are admitted.
    modifications: VecDeque<Predicate<K, S>>,

    /// Coalesced fetches that could not fit in the ready queue.
    fetches: Vec<FetchKey<K, S>>,
}

impl<K, S> Default for Pending<K, S> {
    fn default() -> Self {
        Self {
            modifications: VecDeque::new(),
            fetches: Vec::new(),
        }
    }
}

impl<K, S> Overflow<Message<K, S>> for Pending<K, S> {
    fn is_empty(&self) -> bool {
        self.modifications.is_empty() && self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, S>) -> Option<Message<K, S>>,
    {
        // Retain predicates must run before pending fetches so the actor never
        // starts work for subscribers already pruned by an older retain.
        while let Some(predicate) = self.modifications.pop_front() {
            let message = Message::Retain { predicate };
            if let Some(message) = push(message) {
                self.push_front(message);
                return;
            }
        }

        if !self.fetches.is_empty() {
            // Fetches are coalesced while pending and drained as one batch.
            let fetches = std::mem::take(&mut self.fetches);
            if let Some(message) = push(Message::Fetch(fetches)) {
                self.push_front(message);
            }
        }
    }
}

impl<K, S> Pending<K, S> {
    /// Restore a message that could not be pushed into the ready queue.
    fn push_front(&mut self, message: Message<K, S>) {
        match message {
            Message::Fetch(fetches) => {
                self.fetches.splice(0..0, fetches);
            }
            Message::Retain { predicate } => {
                self.modifications.push_front(predicate);
            }
        }
    }
}

/// Apply a retain predicate to one pending fetch.
fn retain_fetch<K, S>(
    mut fetch: FetchKey<K, S>,
    predicate: &(dyn Fn(&K, &S) -> bool + Send),
) -> Option<FetchKey<K, S>> {
    let mut subscribers = fetch.subscribers.into_vec();
    subscribers.retain(|subscriber| predicate(&fetch.key, subscriber));
    fetch.subscribers = NonEmptyVec::try_from(subscribers).ok()?;
    Some(fetch)
}

/// Add incoming subscribers that are not already attached to the pending fetch.
fn merge_subscribers<S: Eq>(existing: &mut NonEmptyVec<S>, incoming: NonEmptyVec<S>) {
    for subscriber in incoming {
        if !existing.contains(&subscriber) {
            existing.push(subscriber);
        }
    }
}

impl<K, S> Policy for Message<K, S>
where
    K: Clone + Eq,
    S: Eq,
{
    type Overflow = Pending<K, S>;

    fn handle(overflow: &mut Pending<K, S>, message: Self) {
        match message {
            Self::Fetch(fetches) => {
                for fetch in fetches {
                    // Backpressure should not multiply work for the same key.
                    // Merge subscribers into the retained fetch instead.
                    if let Some(existing) = overflow
                        .fetches
                        .iter_mut()
                        .find(|existing| existing.key == fetch.key)
                    {
                        merge_subscribers(&mut existing.subscribers, fetch.subscribers);
                    } else {
                        overflow.fetches.push(fetch);
                    }
                }
            }
            Self::Retain { predicate } => {
                // Retain applies immediately to queued fetch subscribers, then
                // the predicate is kept so the actor prunes active work too.
                overflow.fetches = std::mem::take(&mut overflow.fetches)
                    .into_iter()
                    .filter_map(|fetch| retain_fetch(fetch, predicate.as_ref()))
                    .collect();
                overflow.modifications.push_back(predicate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::non_empty_vec;

    type TestMessage = Message<u8, u16>;
    type TestPending = Pending<u8, u16>;

    fn fetch(key: u8, subscriber: u16) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::new(subscriber),
        }])
    }

    fn fetch_with_subscribers(key: u8, subscribers: Vec<u16>) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::from_unchecked(subscribers),
        }])
    }

    fn subscriber_is(value: u16) -> impl Fn(&u8, &u16) -> bool + Send {
        move |_, subscriber| *subscriber == value
    }

    fn drain(pending: &mut TestPending) -> Vec<TestMessage> {
        let mut messages = Vec::new();
        Overflow::drain(pending, |message| {
            messages.push(message);
            None
        });
        messages
    }

    fn assert_fetch_subscribers(
        message: &TestMessage,
        expected_key: u8,
        expected_subscribers: &[u16],
    ) {
        let Message::Fetch(fetches) = message else {
            panic!("expected fetch");
        };
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].key, expected_key);
        assert_eq!(&fetches[0].subscribers[..], expected_subscribers);
    }

    #[test]
    fn duplicate_fetches_for_same_key_merge_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11]));
        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![11, 12]));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch_subscribers(&messages[0], 1, &[10, 11, 12]);
    }

    #[test]
    fn retain_prunes_pending_fetch_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11]));
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

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11]));
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
    fn retain_messages_drain_before_fetches() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|_, _| true),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch_subscribers(&messages[1], 1, &[10]);
    }

    #[test]
    fn from_fetch_creates_single_subscriber_fetch_key() {
        let fetch = Fetch {
            key: 7,
            subscriber: 8,
        };
        let key = FetchKey::from(fetch);

        assert_eq!(key.key, 7);
        assert_eq!(key.subscribers, non_empty_vec![8]);
    }
}
