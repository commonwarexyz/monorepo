use crate::Consumer;
use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::histogram, Clock};
use commonware_utils::{
    futures::{AbortablePool, Aborter},
    Span,
};
use futures::future::Aborted;
use std::{collections::HashMap, future::Future};

/// A completed delivery to the consumer.
pub(super) struct Delivery<P: PublicKey, Key: Span> {
    pub(super) peer: P,
    pub(super) key: Key,
    pub(super) valid: bool,
}

/// Tracks per-key state for an in-flight fetch.
///
/// `delivery` is `Some` while the consumer is validating a response, and `None` while
/// the request is still pending in the fetcher.
struct Entry<E: Clock> {
    timer: histogram::Timer<E>,
    delivery: Option<Aborter>,
}

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<E: Clock, P: PublicKey, Key: Span> {
    /// Per-key entries tracking fetch duration timers and (when validating a response)
    /// the [Aborter] that cancels the in-flight consumer delivery.
    entries: HashMap<Key, Entry<E>>,

    /// Holds futures that resolve once the `Consumer` has validated fetched data.
    deliveries: AbortablePool<Delivery<P, Key>>,
}

impl<E: Clock, P: PublicKey, Key: Span> Default for Inflight<E, P, Key> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deliveries: AbortablePool::default(),
        }
    }
}

impl<E: Clock, P: PublicKey, Key: Span> Inflight<E, P, Key> {
    /// Returns true if there is an in-flight entry for the key.
    pub(super) fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Insert a new in-flight entry for the key.
    pub(super) fn insert(&mut self, key: Key, timer: histogram::Timer<E>) {
        self.entries.insert(
            key,
            Entry {
                timer,
                delivery: None,
            },
        );
    }

    /// Remove the in-flight entry for the key and cancel its duration timer (suppressing
    /// the recording). Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Key) -> bool {
        let Some(entry) = self.entries.remove(key) else {
            return false;
        };
        // Dropping `entry` aborts the in-flight delivery (if any).
        entry.timer.cancel(); // don't record duration metric
        true
    }

    /// Mark the in-flight entry for the key as complete, recording its duration via the
    /// timer's drop. Panics if no entry exists for the key.
    pub(super) fn complete(&mut self, key: &Key) {
        self.entries.remove(key).expect("inflight entry");
    }

    /// Drop entries for which the predicate returns false. Cancels the timer
    /// for each dropped entry. Returns the count of dropped entries.
    pub(super) fn retain<F: FnMut(&Key) -> bool>(&mut self, mut predicate: F) -> usize {
        let removed: Vec<_> = self.entries.extract_if(|k, _| !predicate(k)).collect();
        let count = removed.len();
        for (_, entry) in removed {
            entry.timer.cancel();
        }
        count
    }

    /// Drop all entries, canceling each timer. Returns the count of dropped entries.
    pub(super) fn drain(&mut self) -> usize {
        let removed: Vec<_> = self.entries.drain().collect();
        let count = removed.len();
        for (_, entry) in removed {
            entry.timer.cancel();
        }
        count
    }

    /// Clear the delivery handle for an entry, leaving the entry in place.
    pub(super) fn clear_delivery(&mut self, key: &Key) {
        self.entries.get_mut(key).expect("inflight entry").delivery = None;
    }

    /// Begin a consumer delivery for the entry, attaching the abort handle.
    /// Spawns `consumer.deliver(key, value)` as an in-flight future and records
    /// the result for later handling.
    pub(super) fn start_delivery<Con, V>(
        &mut self,
        key: Key,
        peer: P,
        value: V,
        mut consumer: Con,
    ) where
        Con: Consumer<Key = Key, Value = V>,
        V: Send + 'static,
    {
        let lookup_key = key.clone();
        let deliver_key = key.clone();
        let aborter = self.deliveries.push(async move {
            let valid = consumer.deliver(deliver_key, value).await;
            Delivery { peer, key, valid }
        });
        let entry = self.entries.get_mut(&lookup_key).expect("inflight entry");
        assert!(entry.delivery.replace(aborter).is_none());
    }

    /// Returns a future that resolves to the next completed delivery, or [Aborted] if
    /// the delivery was canceled.
    pub(super) fn next_delivery(
        &mut self,
    ) -> impl Future<Output = Result<Delivery<P, Key>, Aborted>> + '_ {
        self.deliveries.next_completed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::{Consumer as MockConsumer, Event, Key as MockKey};
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_runtime::{
        deterministic::{Context, Runner},
        telemetry::metrics::{histogram::Buckets, MetricsExt},
        Metrics, Runner as _,
    };
    use std::sync::Arc;

    type TestInflight = Inflight<Context, PublicKey, MockKey>;

    fn make_timed(context: &Context) -> histogram::Timed<Context> {
        let registered = context.histogram("test_duration", "Test histogram", Buckets::LOCAL);
        histogram::Timed::new(registered, Arc::new(context.clone()))
    }

    fn pubkey() -> PublicKey {
        PrivateKey::from_seed(0).public_key()
    }

    #[test]
    fn test_insert_contains_cancel_remove_round_trip() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();

            assert!(!inflight.contains(&MockKey(1)));
            inflight.insert(MockKey(1), timed.timer());
            assert!(inflight.contains(&MockKey(1)));

            assert!(inflight.cancel(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(1)));
            // Subsequent cancel of an absent key returns false.
            assert!(!inflight.cancel(&MockKey(1)));
        });
    }

    #[test]
    fn test_cancel_suppresses_duration_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();

            inflight.insert(MockKey(1), timed.timer());
            inflight.cancel(&MockKey(1));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_complete_records_duration_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();

            inflight.insert(MockKey(1), timed.timer());
            inflight.complete(&MockKey(1));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 1"));
        });
    }

    #[test]
    #[should_panic(expected = "inflight entry")]
    fn test_complete_panics_on_missing_key() {
        let runner = Runner::default();
        runner.start(|_context| async move {
            let mut inflight: TestInflight = Inflight::default();
            inflight.complete(&MockKey(1));
        });
    }

    #[test]
    #[should_panic(expected = "inflight entry")]
    fn test_clear_delivery_panics_on_missing_key() {
        let runner = Runner::default();
        runner.start(|_context| async move {
            let mut inflight: TestInflight = Inflight::default();
            inflight.clear_delivery(&MockKey(1));
        });
    }

    #[test]
    fn test_retain_drops_non_matching_and_suppresses_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();

            inflight.insert(MockKey(1), timed.timer());
            inflight.insert(MockKey(2), timed.timer());
            inflight.insert(MockKey(3), timed.timer());

            let dropped = inflight.retain(|k| k.0 % 2 == 1);
            assert_eq!(dropped, 1);
            assert!(inflight.contains(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(2)));
            assert!(inflight.contains(&MockKey(3)));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_drain_removes_all_and_suppresses_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();

            inflight.insert(MockKey(1), timed.timer());
            inflight.insert(MockKey(2), timed.timer());

            assert_eq!(inflight.drain(), 2);
            assert!(!inflight.contains(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(2)));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_start_delivery_completes_with_consumer_result() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();
            let (consumer, mut events) = MockConsumer::<MockKey, Bytes>::new();
            let peer = pubkey();
            let key = MockKey(7);
            let value = Bytes::from("data");

            inflight.insert(key.clone(), timed.timer());
            inflight.start_delivery(key.clone(), peer.clone(), value.clone(), consumer);

            let delivery = inflight.next_delivery().await.expect("delivery aborted");
            assert_eq!(delivery.key, key);
            assert_eq!(delivery.peer, peer);
            assert!(delivery.valid);

            // The consumer was actually invoked.
            let Event::Success(k, v) = events.recv().await.unwrap();
            assert_eq!(k, key);
            assert_eq!(v, value);
        });
    }

    #[test]
    fn test_start_delivery_aborts_when_entry_dropped_before_poll() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer());
            inflight.start_delivery(key.clone(), peer, Bytes::from("v"), consumer);

            // Drop the entry (and its aborter) before the delivery future is ever polled.
            assert!(inflight.cancel(&key));

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_drain_aborts_in_flight_deliveries() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = Inflight::default();
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer());
            inflight.start_delivery(key, peer, Bytes::from("v"), consumer);

            assert_eq!(inflight.drain(), 1);

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }
}
