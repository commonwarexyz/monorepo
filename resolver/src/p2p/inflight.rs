use crate::{Consumer, Subscribers};
use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::histogram, Clock};
use commonware_utils::{
    futures::{AbortablePool, Aborter},
    Span,
};
use futures::future::Aborted;
use std::{collections::HashMap, marker::PhantomData};

/// Tracks per-key state for an in-flight fetch.
///
/// `delivery` is `Some` while the consumer is validating a response, and `None` while
/// the request is still pending in the fetcher.
struct Entry {
    timer: histogram::Timer,
    delivery: Option<Aborter>,
}

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<E: Clock, Con: Consumer<Key = Key>, P: PublicKey, Key: Span> {
    /// Per-key entries tracking fetch duration timers and (when validating a response)
    /// the [Aborter] that cancels the in-flight consumer delivery.
    entries: HashMap<Key, Entry>,

    /// Holds futures that resolve once the `Consumer` has validated fetched data.
    /// Each completion yields `(peer, key, valid)`.
    deliveries: AbortablePool<(P, Key, bool)>,

    /// Consumer cloned per delivery to validate fetched data.
    consumer: Con,

    /// Clock type used to observe timers on completion.
    _clock: PhantomData<E>,
}

impl<E: Clock, Con: Consumer<Key = Key>, P: PublicKey, Key: Span> Inflight<E, Con, P, Key>
where
    Con::Value: Send + 'static,
{
    pub(super) fn new(consumer: Con) -> Self {
        Self {
            entries: HashMap::new(),
            deliveries: AbortablePool::default(),
            consumer,
            _clock: PhantomData,
        }
    }

    /// Returns true if there is an in-flight entry for the key.
    pub(super) fn contains(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }

    /// Insert a new in-flight entry for the key.
    pub(super) fn insert(&mut self, key: Key, timer: histogram::Timer) {
        self.entries.insert(
            key,
            Entry {
                timer,
                delivery: None,
            },
        );
    }

    /// Remove the in-flight entry for the key and cancel its duration timer (suppressing
    /// the recording). If delivery validation was in progress, it is aborted and any
    /// invalid result is discarded. Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Key) -> bool {
        let Some(_entry) = self.entries.remove(key) else {
            return false;
        };
        // Dropping the entry aborts the in-flight delivery (if any) and suppresses duration
        // recording.
        true
    }

    /// Mark the in-flight entry for the key as complete, recording its duration.
    /// Panics if no entry exists for the key.
    pub(super) fn complete(&mut self, key: &Key, clock: &E) {
        self.entries
            .remove(key)
            .expect("inflight entry")
            .timer
            .observe(clock);
    }

    /// Drop entries for which the predicate returns false. Returns the count of dropped entries.
    pub(super) fn retain<F: FnMut(&Key) -> bool>(&mut self, mut predicate: F) -> usize {
        let removed: Vec<_> = self.entries.extract_if(|k, _| !predicate(k)).collect();
        removed.len()
    }

    /// Drop all entries. Returns the count of dropped entries.
    pub(super) fn drain(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    /// Begin a consumer delivery for the entry, attaching the abort handle.
    /// Spawns `consumer.deliver(subscribers, value)` as an in-flight future and records
    /// the result for later handling.
    pub(super) fn deliver(
        &mut self,
        key: Key,
        subscribers: Subscribers<Key, Con::Subscriber>,
        peer: P,
        value: Con::Value,
    ) {
        let lookup_key = key.clone();
        let mut consumer = self.consumer.clone();
        let aborter = self.deliveries.push(async move {
            let valid = consumer.deliver(subscribers, value).await;
            (peer, key, valid)
        });
        let entry = self.entries.get_mut(&lookup_key).expect("inflight entry");
        assert!(entry.delivery.replace(aborter).is_none());
    }

    /// Returns the next completed delivery as `(peer, key, valid)`, or [Aborted] if the
    /// delivery was canceled. Clears the entry's delivery aborter so the slot is available
    /// for a retry.
    pub(super) async fn next_delivery(&mut self) -> Result<(P, Key, bool), Aborted> {
        let (peer, key, valid) = self.deliveries.next_completed().await?;
        let entry = self.entries.get_mut(&key).expect("inflight entry");
        entry.delivery = None;
        Ok((peer, key, valid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::{Consumer as MockConsumer, Key as MockKey};
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

    type TestInflight = Inflight<Context, MockConsumer<MockKey, Bytes>, PublicKey, MockKey>;

    fn dummy_inflight() -> TestInflight {
        Inflight::new(MockConsumer::dummy())
    }

    fn make_timed(context: &Context) -> histogram::Timed {
        let registered = context.histogram("test_duration", "Test histogram", Buckets::LOCAL);
        histogram::Timed::new(registered)
    }

    fn pubkey() -> PublicKey {
        PrivateKey::from_seed(0).public_key()
    }

    #[test]
    fn test_insert_contains_cancel_remove_round_trip() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            assert!(!inflight.contains(&MockKey(1)));
            inflight.insert(MockKey(1), timed.timer(&context));
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
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
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
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.complete(&MockKey(1), &context);

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 1"));
        });
    }

    #[test]
    #[should_panic(expected = "inflight entry")]
    fn test_complete_panics_on_missing_key() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut inflight: TestInflight = dummy_inflight();
            inflight.complete(&MockKey(1), &context);
        });
    }

    #[test]
    fn test_retain_drops_non_matching_and_suppresses_metric() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.insert(MockKey(2), timed.timer(&context));
            inflight.insert(MockKey(3), timed.timer(&context));

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
            let mut inflight: TestInflight = dummy_inflight();

            inflight.insert(MockKey(1), timed.timer(&context));
            inflight.insert(MockKey(2), timed.timer(&context));

            assert_eq!(inflight.drain(), 2);
            assert!(!inflight.contains(&MockKey(1)));
            assert!(!inflight.contains(&MockKey(2)));

            let metrics = context.encode();
            assert!(metrics.contains("test_duration_count 0"));
        });
    }

    #[test]
    fn test_deliver_completes_with_consumer_result() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, mut events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(7);
            let value = Bytes::from("data");

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                key.clone(),
                Subscribers::new(key.clone()),
                peer.clone(),
                value.clone(),
            );

            let (delivered_peer, delivered_key, valid) =
                inflight.next_delivery().await.expect("delivery aborted");
            assert_eq!(delivered_key, key);
            assert_eq!(delivered_peer, peer);
            assert!(valid);

            // The consumer was actually invoked.
            let (k, v) = events.recv().await.unwrap();
            assert_eq!(k, key);
            assert_eq!(v, value);
        });
    }

    #[test]
    fn test_deliver_aborts_when_entry_dropped_before_poll() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                key.clone(),
                Subscribers::new(key.clone()),
                peer,
                Bytes::from("v"),
            );

            // Drop the entry (and its aborter) before the delivery future is ever polled.
            assert!(inflight.cancel(&key));

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_cancel_after_completion_is_idempotent() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                key.clone(),
                Subscribers::new(key.clone()),
                peer,
                Bytes::from("v"),
            );

            let (_, delivered_key, valid) =
                inflight.next_delivery().await.expect("delivery completed");
            assert_eq!(delivered_key, key);
            assert!(valid);
            inflight.complete(&key, &context);

            // Late cancel finds no entry; must not panic.
            assert!(!inflight.cancel(&key));
        });
    }

    #[test]
    fn test_cancel_wins_race_with_completion() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(
                key.clone(),
                Subscribers::new(key.clone()),
                peer,
                Bytes::from("v"),
            );

            // Cancel before any poll of the pool: drops the Aborter, removes the entry.
            assert!(inflight.cancel(&key));

            // Subsequent poll must yield Err (cancel won the race), not Ok.
            let result = inflight.next_delivery().await;
            assert!(matches!(result, Err(Aborted)));
        });
    }

    #[test]
    fn test_drain_aborts_in_flight_deliveries() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let timed = make_timed(&context);
            let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
            let mut inflight: TestInflight = Inflight::new(consumer);
            let peer = pubkey();
            let key = MockKey(1);

            inflight.insert(key.clone(), timed.timer(&context));
            inflight.deliver(key.clone(), Subscribers::new(key), peer, Bytes::from("v"));

            assert_eq!(inflight.drain(), 1);

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }
}
