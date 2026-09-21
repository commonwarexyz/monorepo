//! Actor-owned resolver response routes.

use commonware_utils::{channel::mpsc, sync::Mutex};
use futures::{
    Future, FutureExt as _, StreamExt as _,
    future::{AbortHandle, Abortable, poll_fn},
    stream::FuturesUnordered,
};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A response route shared with its wait future.
struct Route<R> {
    receiver: Mutex<Option<mpsc::Receiver<R>>>,
}

impl<R> Route<R> {
    const fn new(receiver: mpsc::Receiver<R>) -> Self {
        Self {
            receiver: Mutex::new(Some(receiver)),
        }
    }

    fn close(&self) {
        self.receiver.lock().take();
    }

    fn poll_recv(&self, context: &mut Context<'_>) -> Poll<Option<R>> {
        let mut receiver = self.receiver.lock();
        let Some(receiver) = receiver.as_mut() else {
            return Poll::Ready(None);
        };
        receiver.poll_recv(context)
    }
}

/// A response route and its active ready-pool wait.
struct Entry<R> {
    sender: mpsc::WeakSender<R>,
    route: Arc<Route<R>>,
    wait: AbortHandle,
}

impl<R> Drop for Entry<R> {
    fn drop(&mut self) {
        // Dropping the receiver directly closes the route without waiting for
        // its aborted pool entry to be polled.
        self.route.close();
        self.wait.abort();
    }
}

/// A completed receive operation tied to its exact response route.
struct Received<K, S, R> {
    key: K,
    subscriber: S,
    route: Arc<Route<R>>,
    response: Option<R>,
}

/// A typed receive future for one response route.
struct Receive<K, S, R> {
    identity: Option<(K, S)>,
    route: Arc<Route<R>>,
}

// Receive owns no self-referential or structurally pinned state.
impl<K, S, R> Unpin for Receive<K, S, R> {}

impl<K, S, R> Future for Receive<K, S, R> {
    type Output = Received<K, S, R>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let response = match this.route.poll_recv(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(response) => response,
        };
        let (key, subscriber) = this
            .identity
            .take()
            .expect("completed receive future must not be polled again");
        Poll::Ready(Received {
            key,
            subscriber,
            route: this.route.clone(),
            response,
        })
    }
}

/// Multiplexes actual resolver response receivers by semantic demand.
pub(crate) struct Responses<K, S, R> {
    entries: BTreeMap<(K, S), Entry<R>>,
    waits: FuturesUnordered<Abortable<Receive<K, S, R>>>,
}

impl<K, S, R> Default for Responses<K, S, R> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            waits: FuturesUnordered::new(),
        }
    }
}

impl<K, S, R> Responses<K, S, R>
where
    K: Clone + Ord,
    S: Clone + Ord,
{
    /// Creates an empty response registry.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the live response sender for a semantic demand.
    pub(crate) fn register(&mut self, key: K, subscriber: S) -> mpsc::Sender<R> {
        let identity = (key, subscriber);
        if let Some(sender) = self
            .entries
            .get(&identity)
            .and_then(|entry| entry.sender.upgrade())
        {
            return sender;
        }

        // A failed upgrade proves that no sender can keep the old demand live,
        // even if its terminal event has not been drained from the pool yet.
        self.entries.remove(&identity);

        let (sender, receiver) = mpsc::channel(1);
        let route = Arc::new(Route::new(receiver));
        let wait = self.arm(identity.0.clone(), identity.1.clone(), route.clone());
        self.entries.insert(
            identity,
            Entry {
                sender: sender.downgrade(),
                route,
                wait,
            },
        );
        sender
    }

    /// Removes one semantic demand.
    pub(crate) fn remove(&mut self, key: &K, subscriber: &S) -> bool {
        self.entries
            .remove(&(key.clone(), subscriber.clone()))
            .is_some()
    }

    /// Removes a demand only when it still owns the supplied response channel.
    pub(crate) fn remove_matching(
        &mut self,
        key: &K,
        subscriber: &S,
        response: &mpsc::Sender<R>,
    ) -> bool {
        let identity = (key.clone(), subscriber.clone());
        let matches = self
            .entries
            .get(&identity)
            .and_then(|entry| entry.sender.upgrade())
            .is_some_and(|sender| sender.same_channel(response));
        matches && self.remove(key, subscriber)
    }

    /// Retains semantic demands selected by actor-owned protocol state.
    pub(crate) fn retain(&mut self, mut retain: impl FnMut(&K, &S) -> bool) {
        self.entries
            .retain(|(key, subscriber), _| retain(key, subscriber));
    }

    /// Returns whether a semantic demand is registered.
    #[cfg(test)]
    pub(crate) fn contains(&self, key: &K, subscriber: &S) -> bool {
        self.entries
            .contains_key(&(key.clone(), subscriber.clone()))
    }

    /// Returns the number of registered semantic demands.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no registered semantic demands.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Waits for the next response from a live route.
    pub(crate) async fn recv(&mut self) -> R {
        loop {
            let completed = poll_fn(|context| match self.waits.poll_next_unpin(context) {
                Poll::Ready(Some(completed)) => Poll::Ready(completed),
                Poll::Ready(None) | Poll::Pending => Poll::Pending,
            })
            .await;
            let Ok(received) = completed else {
                continue;
            };
            if let Some(response) = self.handle(received) {
                return response;
            }
        }
    }

    /// Returns the next response that is ready without waiting.
    pub(crate) fn try_recv(&mut self) -> Option<R> {
        loop {
            let completed = self.waits.next().now_or_never()??;
            let Ok(received) = completed else {
                continue;
            };
            if let Some(response) = self.handle(received) {
                return Some(response);
            }
        }
    }

    fn arm(&mut self, key: K, subscriber: S, route: Arc<Route<R>>) -> AbortHandle {
        let (handle, registration) = AbortHandle::new_pair();
        self.waits.push(Abortable::new(
            Receive {
                identity: Some((key, subscriber)),
                route,
            },
            registration,
        ));
        handle
    }

    fn handle(&mut self, received: Received<K, S, R>) -> Option<R> {
        let identity = (received.key.clone(), received.subscriber.clone());
        let entry = self.entries.get(&identity)?;
        if !Arc::ptr_eq(&entry.route, &received.route) {
            return None;
        }

        let Some(response) = received.response else {
            self.entries.remove(&identity);
            return None;
        };

        // Re-arm before exposing the response so actor-local retirement can
        // close the actual receiver while the candidate is being processed.
        let wait = self.arm(received.key, received.subscriber, received.route);
        let entry = self
            .entries
            .get_mut(&identity)
            .expect("matching response route must remain while it is rearmed");
        entry.wait = wait;
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::Responses;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::channel::oneshot;
    use std::rc::Rc;

    #[test]
    fn registry_is_send_and_sync() {
        fn assert_send_and_sync<T: Send + Sync>() {}
        assert_send_and_sync::<Responses<u64, u8, u64>>();
    }

    #[test]
    fn registry_does_not_require_send_or_static_values() {
        let key = String::from("key");
        let subscriber = Rc::new(1u8);
        let mut responses = Responses::<&str, Rc<u8>, Rc<u8>>::new();
        let sender = responses.register(key.as_str(), subscriber);
        sender.try_send(Rc::new(2)).unwrap();

        assert_eq!(*responses.try_recv().unwrap(), 2);
    }

    #[test]
    fn duplicate_demand_reuses_live_response_channel() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let first = responses.register(7, 1);
        let duplicate = responses.register(7, 1);

        assert!(first.same_channel(&duplicate));
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn awaits_next_response() {
        let runtime = deterministic::Runner::default();
        runtime.start(|_| async move {
            let mut responses = Responses::<u64, u8, u64>::new();
            let sender = responses.register(7, 1);
            sender.send(11).await.unwrap();

            assert_eq!(responses.recv().await, 11);
            assert!(responses.contains(&7, &1));
        });
    }

    #[test]
    fn terminal_stream_removes_demand_without_retained_sender() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let sender = responses.register(7, 1);
        drop(sender);

        assert_eq!(responses.try_recv(), None);
        assert!(responses.is_empty());
    }

    #[test]
    fn ended_demand_is_replaced_before_terminal_event_is_drained() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let ended = responses.register(7, 1);
        drop(ended);

        let replacement = responses.register(7, 1);
        replacement.try_send(12).unwrap();

        assert_eq!(responses.try_recv(), Some(12));
        assert!(responses.contains(&7, &1));
    }

    #[test]
    fn stale_wait_cannot_remove_replacement() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let old = responses.register(7, 1);
        old.try_send(11).unwrap();
        assert!(responses.remove(&7, &1));

        let replacement = responses.register(7, 1);
        assert!(!old.same_channel(&replacement));
        replacement.try_send(12).unwrap();

        assert_eq!(responses.try_recv(), Some(12));
        assert!(responses.contains(&7, &1));
    }

    #[test]
    fn exact_removal_preserves_replacement() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let old = responses.register(7, 1);
        assert!(responses.remove(&7, &1));
        let replacement = responses.register(7, 1);

        assert!(!responses.remove_matching(&7, &1, &old));
        assert!(responses.contains(&7, &1));
        assert!(responses.remove_matching(&7, &1, &replacement));
        assert!(responses.is_empty());
    }

    #[test]
    fn receiver_remains_cancellable_while_response_is_held() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let sender = responses.register(7, 1);
        sender.try_send(11).unwrap();

        let response = responses.try_recv().unwrap();
        assert!(responses.remove(&7, &1));

        assert_eq!(response, 11);
        assert!(sender.is_closed());
    }

    #[test]
    fn removal_drops_queued_response() {
        let mut responses = Responses::<u64, u8, oneshot::Sender<()>>::new();
        let sender = responses.register(7, 1);
        let (verdict, mut received) = oneshot::channel();
        sender.try_send(verdict).unwrap();

        assert!(responses.remove(&7, &1));

        assert!(sender.is_closed());
        assert!(matches!(
            received.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn retain_filters_only_selected_semantic_demand() {
        let mut responses = Responses::<u64, u8, u64>::new();
        let removed = responses.register(7, 1);
        let retained = responses.register(7, 2);

        responses.retain(|key, subscriber| *key != 7 || *subscriber != 1);

        assert!(removed.is_closed());
        assert!(!retained.is_closed());
        assert!(!responses.contains(&7, &1));
        assert!(responses.contains(&7, &2));
    }
}
