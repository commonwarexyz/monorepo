//! Coalesce queued fetches without extending response receiver lifetimes.

use crate::{Fetch, Subscriber};
use commonware_actor::mailbox::{Overflow, Policy};
use commonware_utils::vec::NonEmptyVec;

/// Metadata associated with repeated fetches on the same response route.
pub(crate) trait Metadata {
    fn merge(&mut self, incoming: Self);
}

impl Metadata for () {
    fn merge(&mut self, _incoming: Self) {}
}

impl<T: Eq> Metadata for Option<NonEmptyVec<T>> {
    fn merge(&mut self, incoming: Self) {
        let Some(incoming) = incoming else {
            *self = None;
            return;
        };
        let Some(existing) = self else {
            return;
        };
        for item in incoming {
            if !existing.contains(&item) {
                existing.push(item);
            }
        }
    }
}

/// A key and its local response routes. Target metadata stays attached to its
/// route until admission so a canceled queued request cannot broaden targeting.
pub struct FetchKey<K, S, R, M = ()> {
    pub key: K,
    pub subscribers: NonEmptyVec<(Subscriber<S, R>, M)>,
}

impl<K, S, R, M> FetchKey<K, S, R, M> {
    pub fn into_live(mut self) -> Option<Self> {
        let mut subscribers = self.subscribers.into_vec();
        subscribers.retain(|(subscriber, _)| !subscriber.response.is_closed());
        self.subscribers = NonEmptyVec::try_from(subscribers).ok()?;
        Some(self)
    }
}

impl<K, S, R> From<Fetch<K, S, R>> for FetchKey<K, S, R> {
    fn from(fetch: Fetch<K, S, R>) -> Self {
        Self {
            key: fetch.key,
            subscribers: NonEmptyVec::new((
                Subscriber {
                    subscriber: fetch.subscriber,
                    response: fetch.response,
                    span: fetch.span,
                },
                (),
            )),
        }
    }
}

pub enum Message<K, S, R, M = ()> {
    Fetch(Vec<FetchKey<K, S, R, M>>),
}

/// Fetches waiting for mailbox capacity, coalesced by key and exact route.
pub struct Pending<K, S, R, M = ()> {
    fetches: Vec<FetchKey<K, S, R, M>>,
}

impl<K, S, R, M> Default for Pending<K, S, R, M> {
    fn default() -> Self {
        Self {
            fetches: Vec::new(),
        }
    }
}

impl<K, S, R, M> Overflow<Message<K, S, R, M>> for Pending<K, S, R, M> {
    fn is_empty(&self) -> bool {
        self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<K, S, R, M>) -> Option<Message<K, S, R, M>>,
    {
        let fetches: Vec<_> = std::mem::take(&mut self.fetches)
            .into_iter()
            .filter_map(FetchKey::into_live)
            .collect();
        if !fetches.is_empty()
            && let Some(Message::Fetch(fetches)) = push(Message::Fetch(fetches))
        {
            self.fetches = fetches;
        }
    }
}

impl<K: Clone + Eq, S: Eq, R, M: Metadata> Policy for Message<K, S, R, M> {
    type Overflow = Pending<K, S, R, M>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        let Self::Fetch(fetches) = message;
        for fetch in fetches.into_iter().filter_map(FetchKey::into_live) {
            if let Some(existing) = overflow
                .fetches
                .iter_mut()
                .find(|existing| existing.key == fetch.key)
            {
                for (subscriber, metadata) in fetch.subscribers {
                    if let Some((_, existing_metadata)) = existing
                        .subscribers
                        .iter_mut()
                        .find(|(existing, _)| *existing == subscriber)
                    {
                        existing_metadata.merge(metadata);
                    } else {
                        existing.subscribers.push((subscriber, metadata));
                    }
                }
            } else {
                overflow.fetches.push(fetch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{channel::mpsc, non_empty_vec};

    type TestMessage = Message<u8, u16, u8>;
    type TestPending = Pending<u8, u16, u8>;

    fn subscriber(value: u16) -> (Subscriber<u16, u8>, mpsc::Receiver<u8>) {
        let (response, receiver) = mpsc::channel(1);
        (
            Subscriber {
                subscriber: value,
                response,
                span: tracing::Span::none(),
            },
            receiver,
        )
    }

    fn fetch(key: u8, subscribers: NonEmptyVec<Subscriber<u16, u8>>) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: NonEmptyVec::from_unchecked(
                subscribers
                    .into_iter()
                    .map(|subscriber| (subscriber, ()))
                    .collect(),
            ),
        }])
    }

    fn drain(pending: &mut TestPending) -> Vec<TestMessage> {
        let mut messages = Vec::new();
        Overflow::drain(pending, |message| {
            messages.push(message);
            None
        });
        messages
    }

    fn fetched(message: &TestMessage) -> &FetchKey<u8, u16, u8> {
        let Message::Fetch(fetches) = message;
        assert_eq!(fetches.len(), 1);
        &fetches[0]
    }

    #[test]
    fn duplicate_exact_routes_are_coalesced() {
        let mut pending = TestPending::default();
        let (subscriber, _receiver) = subscriber(10);

        Policy::handle(&mut pending, fetch(1, non_empty_vec![subscriber.clone()]));
        Policy::handle(&mut pending, fetch(1, non_empty_vec![subscriber]));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_eq!(fetched(&messages[0]).subscribers.len().get(), 1);
    }

    #[test]
    fn equal_metadata_on_independent_channels_remains_independent() {
        let mut pending = TestPending::default();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(10);

        Policy::handle(&mut pending, fetch(1, non_empty_vec![first]));
        Policy::handle(&mut pending, fetch(1, non_empty_vec![second]));

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 2);
        assert!(
            !fetch.subscribers[0]
                .0
                .response
                .same_channel(&fetch.subscribers[1].0.response)
        );
    }

    #[test]
    fn dropped_receivers_are_filtered_on_admission_and_drain() {
        let mut pending = TestPending::default();
        let (closed_on_admission, receiver) = subscriber(10);
        drop(receiver);
        let (closed_on_drain, receiver) = subscriber(11);
        let (live, _live_receiver) = subscriber(12);

        Policy::handle(&mut pending, fetch(1, non_empty_vec![closed_on_admission]));
        Policy::handle(
            &mut pending,
            fetch(2, non_empty_vec![closed_on_drain, live]),
        );
        drop(receiver);

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.key, 2);
        assert_eq!(fetch.subscribers.len().get(), 1);
        assert_eq!(fetch.subscribers[0].0.subscriber, 12);
    }

    #[test]
    fn all_closed_routes_leave_overflow_empty() {
        let mut pending = TestPending::default();
        let (subscriber, receiver) = subscriber(10);
        Policy::handle(&mut pending, fetch(1, non_empty_vec![subscriber]));
        drop(receiver);

        assert!(drain(&mut pending).is_empty());
        assert!(Overflow::is_empty(&pending));
    }

    #[test]
    fn rejected_push_can_be_drained_again() {
        let mut pending = TestPending::default();
        let (subscriber, _receiver) = subscriber(10);
        Policy::handle(&mut pending, fetch(1, non_empty_vec![subscriber]));

        let mut rejected = 0;
        Overflow::drain(&mut pending, |message| {
            rejected += 1;
            Some(message)
        });
        assert_eq!(rejected, 1);
        assert!(!Overflow::is_empty(&pending));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_eq!(fetched(&messages[0]).key, 1);
        assert!(Overflow::is_empty(&pending));
    }

    #[test]
    fn replacement_channel_survives_old_receiver_closure() {
        let mut pending = TestPending::default();
        let (old, old_receiver) = subscriber(10);
        let (replacement, _replacement_receiver) = subscriber(10);
        let replacement_response = replacement.response.clone();

        Policy::handle(&mut pending, fetch(1, non_empty_vec![old]));
        Policy::handle(&mut pending, fetch(1, non_empty_vec![replacement]));
        drop(old_receiver);

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 1);
        assert!(
            fetch.subscribers[0]
                .0
                .response
                .same_channel(&replacement_response)
        );
    }

    #[test]
    fn from_fetch_preserves_response_route() {
        let (response, _receiver) = mpsc::channel::<u8>(1);
        let expected = response.clone();
        let key = FetchKey::from(Fetch {
            key: 7,
            subscriber: 8,
            response,
            span: tracing::Span::none(),
        });

        assert_eq!(key.key, 7);
        assert_eq!(key.subscribers.first().0.subscriber, 8);
        assert!(key.subscribers.first().0.response.same_channel(&expected));
    }

    #[test]
    fn metadata_merges_only_for_the_exact_route() {
        let mut pending = Pending::<u8, u16, u8, Option<NonEmptyVec<u8>>>::default();
        let (first, _first_receiver) = subscriber(10);
        let same_route = first.clone();
        let (independent, _independent_receiver) = subscriber(10);

        Policy::handle(
            &mut pending,
            Message::Fetch(vec![FetchKey {
                key: 1,
                subscribers: non_empty_vec![(first, Some(non_empty_vec![2, 3]))],
            }]),
        );
        Policy::handle(
            &mut pending,
            Message::Fetch(vec![FetchKey {
                key: 1,
                subscribers: non_empty_vec![
                    (same_route, Some(non_empty_vec![3, 4])),
                    (independent, Some(non_empty_vec![5])),
                ],
            }]),
        );

        let mut messages = Vec::new();
        Overflow::drain(&mut pending, |message| {
            messages.push(message);
            None
        });
        let Message::Fetch(fetches) = &messages[0];
        assert_eq!(fetches[0].subscribers.len().get(), 2);
        assert_eq!(fetches[0].subscribers[0].1, Some(non_empty_vec![2, 3, 4]));
        assert_eq!(fetches[0].subscribers[1].1, Some(non_empty_vec![5]));
    }
}
