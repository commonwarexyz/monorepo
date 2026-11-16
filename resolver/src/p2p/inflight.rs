use crate::{
    Consumer, Delivery,
    delivery::{Completion, Tracker},
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, telemetry::metrics::histogram};
use futures::future::Aborted;
use std::time::Duration;

/// Tracks all in-flight fetch state.
pub(super) struct Inflight<Con, P>
where
    Con: Consumer<Value = Bytes>,
    P: PublicKey,
{
    /// Resolver-agnostic delivery state shared with non-P2P resolver implementations.
    deliveries: Tracker<Con, (P, Duration, usize), histogram::Timer>,
}

impl<Con, P> Inflight<Con, P>
where
    Con: Consumer<Value = Bytes>,
    P: PublicKey,
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
    /// the recording). Accepted verdicts remain available for source accounting.
    /// Returns true if an entry was present.
    pub(super) fn cancel(&mut self, key: &Con::Key) -> bool {
        self.deliveries.remove(key)
    }

    /// Mark the in-flight entry for the key as complete, recording its duration.
    /// Panics if no entry exists for the key.
    pub(super) fn complete<E: Clock>(&mut self, clock: &E, key: &Con::Key) {
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

    /// Begin a consumer delivery for a network response and cache the response so
    /// later subscribers can be delivered the same bytes.
    pub(super) fn deliver(
        &mut self,
        delivery: Delivery<Con::Key, Con::Subscriber>,
        peer: P,
        elapsed: Duration,
        value: Con::Value,
    ) {
        self.deliveries
            .deliver(delivery, (peer, elapsed, value.len()), value);
    }

    /// Begin another consumer delivery for an already received response.
    pub(super) fn redeliver(&mut self, delivery: Delivery<Con::Key, Con::Subscriber>) {
        self.deliveries.redeliver(delivery);
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

    /// Returns the next verdict, or [Aborted] for cancellation without a verdict.
    /// Canceled completions retain source feedback but cannot affect current demand.
    pub(super) async fn next_delivery(
        &mut self,
    ) -> Result<Completion<Con::Key, Con::Subscriber, (P, Duration, usize)>, Aborted> {
        self.deliveries.next_completion().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Outcome, Resolution,
        p2p::mocks::{Consumer as MockConsumer, Key as MockKey},
    };
    use bytes::Bytes;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        Metrics, Runner as _,
        deterministic::{Context, Runner},
        telemetry::metrics::{MetricsExt, histogram::Buckets},
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
            subscribers: non_empty_vec![((), tracing::Span::none())],
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
            inflight.complete(&context, &MockKey(1));

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
            inflight.complete(&context, &MockKey(1));
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
                delivery(key.clone()),
                peer.clone(),
                Duration::from_millis(17),
                value.clone(),
            );

            let completed = inflight.next_delivery().await.expect("delivery aborted");
            assert_eq!(completed.delivery.key, key);
            assert_eq!(
                completed.context,
                (peer, Duration::from_millis(17), value.len())
            );
            assert_eq!(
                completed.outcome,
                Some(Outcome::Resolved(Resolution::Complete))
            );
            assert!(!completed.canceled);

            // The consumer was actually invoked.
            let (k, v) = events.recv().await.unwrap();
            assert_eq!(k, key);
            assert_eq!(v, value);
        });
    }

    #[test]
    fn test_cancellation_preserves_ready_verdict_without_recording_duration() {
        for drain in [false, true] {
            Runner::default().start(move |context| async move {
                let timed = make_timed(&context);
                let (consumer, _events) = MockConsumer::<MockKey, Bytes>::new();
                let mut inflight: TestInflight = Inflight::new(consumer);
                let peer = pubkey();
                let key = MockKey(1);

                // The consumer accepts the response before cancellation is polled.
                inflight.insert(key.clone(), timed.timer(&context));
                inflight.deliver(
                    delivery(key.clone()),
                    peer.clone(),
                    Duration::ZERO,
                    Bytes::from("v"),
                );
                if drain {
                    assert_eq!(inflight.drain(), 1);
                } else {
                    assert!(inflight.cancel(&key));
                }

                // Source feedback survives independently of the canceled fetch timer.
                let completed = inflight.next_delivery().await.unwrap();
                assert!(completed.canceled);
                assert_eq!(completed.context, (peer, Duration::ZERO, 1));
                assert_eq!(
                    completed.outcome,
                    Some(Outcome::Resolved(Resolution::Complete))
                );
                assert!(!inflight.contains(&key));
                assert!(context.encode().contains("test_duration_count 0"));
            });
        }
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
                delivery(key.clone()),
                peer,
                Duration::ZERO,
                Bytes::from("v"),
            );

            let completed = inflight.next_delivery().await.expect("delivery completed");
            assert_eq!(completed.delivery.key, key);
            assert_eq!(
                completed.outcome,
                Some(Outcome::Resolved(Resolution::Complete))
            );
            inflight.complete(&context, &key);

            // Late cancel finds no entry; must not panic.
            assert!(!inflight.cancel(&key));
        });
    }
}
