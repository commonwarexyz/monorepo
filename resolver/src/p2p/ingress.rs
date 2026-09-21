use crate::{Fetch, Resolver, Subscriber, TargetedResolver, ingress};
use commonware_actor::{Feedback, mailbox::Sender};
use commonware_cryptography::PublicKey;
use commonware_utils::{Span, vec::NonEmptyVec};

/// A key to fetch data for, optionally with target peers.
pub type FetchKey<K, P, S, R> = ingress::FetchKey<K, S, R, Option<NonEmptyVec<P>>>;

/// Messages that can be sent to the peer actor.
pub type Message<K, P, S, R> = ingress::Message<K, S, R, Option<NonEmptyVec<P>>>;

fn fetch_key<K, P, S, R>(
    fetch: Fetch<K, S, R>,
    targets: Option<NonEmptyVec<P>>,
) -> FetchKey<K, P, S, R> {
    FetchKey {
        key: fetch.key,
        subscribers: NonEmptyVec::new((
            Subscriber {
                subscriber: fetch.subscriber,
                response: fetch.response,
                span: fetch.span,
            },
            targets,
        )),
    }
}

/// A way to send messages to the peer actor.
pub struct Mailbox<K: Span, P: Eq, S: Eq, R> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<K, P, S, R>>,
}

impl<K: Span, P: Eq, S: Eq, R> Clone for Mailbox<K, P, S, R> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<K: Span, P: Eq, S: Eq, R> Mailbox<K, P, S, R> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<K, P, S, R>>) -> Self {
        Self { sender }
    }
}

impl<K, P, S, R> Resolver for Mailbox<K, P, S, R>
where
    K: Span,
    P: PublicKey,
    S: Clone + Eq + Send + 'static,
    R: Send + 'static,
{
    type Key = K;
    type Subscriber = S;
    type Response = R;

    /// Send a fetch to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch<D>(&mut self, key: D) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send,
    {
        self.sender
            .enqueue(Message::Fetch(vec![fetch_key(key.into(), None)]))
    }

    /// Send fetches to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all<D>(&mut self, keys: Vec<D>) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|key| fetch_key(key.into(), None))
                .collect(),
        ))
    }
}

impl<K, P, S, R> TargetedResolver for Mailbox<K, P, S, R>
where
    K: Span,
    P: PublicKey,
    S: Clone + Eq + Send + 'static,
    R: Send + 'static,
{
    type PublicKey = P;

    /// Send a targeted fetch to the peer actor.
    ///
    /// If a fetch is already in progress for this key:
    /// - If the existing fetch has targets, the new targets are added to the set.
    /// - If the existing fetch has no targets, it remains unrestricted.
    ///
    /// To clear targeting and fall back to any peer, call [`fetch`](Self::fetch).
    ///
    /// Targets are automatically cleared when the fetch succeeds or is canceled.
    /// A target blocked for invalid data is skipped until the network unblocks it.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        key: impl Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.sender
            .enqueue(Message::Fetch(vec![fetch_key(key.into(), Some(targets))]))
    }

    /// Send targeted fetches to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted<D>(&mut self, keys: Vec<(D, NonEmptyVec<Self::PublicKey>)>) -> Feedback
    where
        D: Into<Fetch<Self::Key, Self::Subscriber, Self::Response>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|(key, targets)| fetch_key(key.into(), Some(targets)))
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_actor::mailbox::{Overflow, Policy};
    use commonware_utils::{channel::mpsc, non_empty_vec};

    type TestMessage = Message<u8, u8, u16, u8>;
    type TestPending = ingress::Pending<u8, u16, u8, Option<NonEmptyVec<u8>>>;

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

    fn fetch(
        key: u8,
        subscriber: Subscriber<u16, u8>,
        targets: Option<NonEmptyVec<u8>>,
    ) -> TestMessage {
        Message::Fetch(vec![FetchKey {
            key,
            subscribers: non_empty_vec![(subscriber, targets)],
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

    fn fetched(message: &TestMessage) -> &FetchKey<u8, u8, u16, u8> {
        let Message::Fetch(fetches) = message;
        assert_eq!(fetches.len(), 1);
        &fetches[0]
    }

    #[test]
    fn targeted_fetches_merge_targets_for_the_same_route() {
        let mut pending = TestPending::default();
        let (subscriber, _receiver) = subscriber(10);

        Policy::handle(
            &mut pending,
            fetch(1, subscriber.clone(), Some(non_empty_vec![2, 3])),
        );
        Policy::handle(
            &mut pending,
            fetch(1, subscriber, Some(non_empty_vec![3, 4])),
        );

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 1);
        assert_eq!(fetch.subscribers[0].1, Some(non_empty_vec![2, 3, 4]));
    }

    #[test]
    fn equal_metadata_on_independent_channels_remains_separate() {
        let mut pending = TestPending::default();
        let (first, _first_receiver) = subscriber(10);
        let (second, _second_receiver) = subscriber(10);

        Policy::handle(&mut pending, fetch(1, first, Some(non_empty_vec![2])));
        Policy::handle(&mut pending, fetch(1, second, Some(non_empty_vec![2])));

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 2);
        assert!(
            !fetch.subscribers[0]
                .0
                .response
                .same_channel(&fetch.subscribers[1].0.response)
        );
        assert_eq!(fetch.subscribers[0].1, Some(non_empty_vec![2]));
        assert_eq!(fetch.subscribers[1].1, Some(non_empty_vec![2]));
    }

    #[test]
    fn canceled_unrestricted_demand_does_not_broaden_surviving_targeted_demand() {
        let mut pending = TestPending::default();
        let (unrestricted, unrestricted_receiver) = subscriber(10);
        let (targeted, _targeted_receiver) = subscriber(11);

        Policy::handle(&mut pending, fetch(1, unrestricted, None));
        Policy::handle(&mut pending, fetch(1, targeted, Some(non_empty_vec![2, 3])));
        drop(unrestricted_receiver);

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 1);
        assert_eq!(fetch.subscribers[0].0.subscriber, 11);
        assert_eq!(fetch.subscribers[0].1, Some(non_empty_vec![2, 3]));
    }

    #[test]
    fn unrestricted_metadata_dominates_only_its_own_route() {
        let mut pending = TestPending::default();
        let (first, _first_receiver) = subscriber(10);
        let same_route = first.clone();
        let (targeted, _targeted_receiver) = subscriber(11);

        Policy::handle(&mut pending, fetch(1, first, Some(non_empty_vec![2])));
        Policy::handle(&mut pending, fetch(1, same_route, None));
        Policy::handle(&mut pending, fetch(1, targeted, Some(non_empty_vec![3])));

        let messages = drain(&mut pending);
        let fetch = fetched(&messages[0]);
        assert_eq!(fetch.subscribers.len().get(), 2);
        assert!(fetch.subscribers[0].1.is_none());
        assert_eq!(fetch.subscribers[1].1, Some(non_empty_vec![3]));
    }

    #[test]
    fn replacement_channel_with_same_metadata_survives() {
        let mut pending = TestPending::default();
        let (old, old_receiver) = subscriber(10);
        let (replacement, _replacement_receiver) = subscriber(10);
        let replacement_response = replacement.response.clone();

        Policy::handle(&mut pending, fetch(1, old, Some(non_empty_vec![2])));
        Policy::handle(&mut pending, fetch(1, replacement, Some(non_empty_vec![2])));
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
        assert_eq!(fetch.subscribers[0].1, Some(non_empty_vec![2]));
    }

    #[test]
    fn all_closed_routes_are_not_admitted() {
        let mut pending = TestPending::default();
        let (subscriber, receiver) = subscriber(10);
        drop(receiver);

        Policy::handle(&mut pending, fetch(1, subscriber, None));

        assert!(drain(&mut pending).is_empty());
        assert!(Overflow::is_empty(&pending));
    }
}
