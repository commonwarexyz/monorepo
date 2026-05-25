use crate::{
    delivery::{Completion, Tracker},
    Consumer, Delivery,
};
use commonware_runtime::{telemetry::metrics::histogram, Clock};
use futures::future::Aborted;

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<Con, P>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    P: Clone + Send + 'static,
{
    /// Resolver-agnostic delivery state shared with non-P2P resolver implementations.
    deliveries: Tracker<Con, P, histogram::Timer>,
}

impl<Con, P> Inflight<Con, P>
where
    Con: Consumer,
    Con::Value: Clone + Send + 'static,
    P: Clone + Send + 'static,
{
    pub(super) fn new(consumer: Con) -> Self {
        Self {
            deliveries: Tracker::new(consumer),
        }
    }

    /// Returns true if there is an in-flight entry for the key.
    pub(super) fn contains(&self, key: &Con::Key) -> bool {
        self.deliveries.contains(key)
    }

    /// Insert a new in-flight entry for the key.
    pub(super) fn insert(&mut self, key: Con::Key, timer: histogram::Timer) {
        assert!(
            self.deliveries.insert_with_state(key, timer),
            "inflight entry"
        );
    }

    /// Remove the in-flight entry for the key and cancel its duration timer (suppressing
    /// the recording). If delivery validation was in progress, it is aborted and any
    /// invalid result is discarded. Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Con::Key) -> bool {
        self.deliveries.remove(key)
    }

    /// Mark the in-flight entry for the key as complete, recording its duration.
    /// Panics if no entry exists for the key.
    pub(super) fn complete<E: Clock>(&mut self, key: &Con::Key, clock: &E) {
        if let Some(timer) = self
            .deliveries
            .remove_with_state(key)
            .expect("inflight entry")
        {
            timer.observe(clock);
        }
    }

    /// Drop entries for which the predicate returns false. Returns the count of dropped entries.
    pub(super) fn retain<F: FnMut(&Con::Key) -> bool>(&mut self, predicate: F) -> usize {
        self.deliveries.retain(predicate)
    }

    /// Drop all entries. Returns the count of dropped entries.
    pub(super) fn drain(&mut self) -> usize {
        self.deliveries.drain()
    }

    /// Begin a consumer delivery for a network response, attaching the abort handle.
    /// Spawns `consumer.deliver(delivery, value)` as an in-flight future and records
    /// the response so later subscribers can be delivered the same accepted bytes.
    pub(super) fn deliver(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        peer: P,
        value: Con::Value,
    ) {
        self.deliveries.deliver(delivery, peer, value);
    }

    /// Begin another consumer delivery for an already received response.
    pub(super) fn redeliver(&mut self, delivery: Delivery<Con::Key, Con::Subscriber>) {
        self.deliveries.redeliver(delivery);
    }

    /// Returns whether the current response has already been accepted by the consumer.
    pub(super) fn response_accepted(&self, key: &Con::Key) -> bool {
        self.deliveries.response_accepted(key)
    }

    /// Mark the current response accepted and record the fetch duration.
    pub(super) fn accept_response<E: Clock>(&mut self, key: &Con::Key, clock: &E) {
        self.deliveries.accept_response(key);
        if let Some(timer) = self.deliveries.take_state(key) {
            timer.observe(clock);
        }
    }

    /// Drop the current response without completing the fetch.
    pub(super) fn discard_response(&mut self, key: &Con::Key) {
        self.deliveries.discard_response(key);
    }

    /// Returns the next completed delivery as `(peer, delivery, valid)`, or [Aborted] if the
    /// delivery was canceled. Clears the entry's delivery aborter so the slot is available
    /// for a retry.
    pub(super) async fn next_delivery(
        &mut self,
    ) -> Result<(P, Delivery<Con::Key, Con::Subscriber>, bool), Aborted> {
        let Completion {
            context,
            delivery,
            valid,
        } = self.deliveries.next_completion().await?;
        Ok((context, delivery, valid))
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
    use commonware_utils::non_empty_vec;

    type TestInflight = Inflight<MockConsumer<MockKey, Bytes>, PublicKey>;

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

    fn delivery(key: MockKey) -> Delivery<MockKey, ()> {
        Delivery {
            key,
            subscribers: non_empty_vec![()],
        }
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
            inflight.deliver(delivery(key.clone()), peer.clone(), value.clone());

            let (delivered_peer, delivered, valid) =
                inflight.next_delivery().await.expect("delivery aborted");
            assert_eq!(delivered.key, key);
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
            inflight.deliver(delivery(key.clone()), peer, Bytes::from("v"));

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
            inflight.deliver(delivery(key.clone()), peer, Bytes::from("v"));

            let (_, delivered, valid) = inflight.next_delivery().await.expect("delivery completed");
            assert_eq!(delivered.key, key);
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
            inflight.deliver(delivery(key.clone()), peer, Bytes::from("v"));

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
            inflight.deliver(delivery(key), peer, Bytes::from("v"));

            assert_eq!(inflight.drain(), 1);

            let result = inflight.next_delivery().await;
            assert!(result.is_err());
        });
    }
}
