use super::{Buffer, Variant};
use crate::{Heightable, types::Height};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    future::poll_fn,
    task::Poll,
};
use tracing::{Span, info_span};

/// A set of local subscribers waiting for one block.
///
/// Each caller remains registered until delivery, caller cancellation, or actor shutdown.
/// Resolver acquisition remains available after the backing buffer closes its waiter.
///
/// Dropping the subscription aborts the backing buffer waiter, if one exists.
struct BlockSubscription<V: Variant> {
    subscribers: Vec<Subscriber<V>>,
    _aborter: Option<Aborter>,
}

/// A waiter for a block, carrying the span of its mailbox request.
struct Subscriber<V: Variant> {
    span: Span,
    sender: oneshot::Sender<V::Block>,
}

/// Delivers a block to a subscriber inside the dequeue-side child of its
/// carried span, marking fulfillment in the trace.
fn deliver<V: Variant>(subscriber: Subscriber<V>, block: &V::Block) {
    let _guard = info_span!(parent: &subscriber.span, "marshal.actor.notify").entered();
    subscriber.sender.send_lossy(block.clone());
}

pub(super) struct Subscriptions<V: Variant> {
    entries: BTreeMap<V::Commitment, BlockSubscription<V>>,
}

impl<V: Variant> Subscriptions<V> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub(super) fn contains(&self, commitment: &V::Commitment) -> bool {
        self.entries.contains_key(commitment)
    }

    /// Removes canceled subscribers and returns commitments with no remaining callers.
    pub(super) fn retain_open(&mut self) -> Vec<V::Commitment> {
        let mut removed = Vec::new();
        self.entries.retain(|commitment, subscription| {
            subscription
                .subscribers
                .retain(|subscriber| !subscriber.sender.is_closed());
            if subscription.subscribers.is_empty() {
                removed.push(*commitment);
                false
            } else {
                true
            }
        });
        removed
    }

    /// Waits until cancellation removes the last caller for a commitment.
    pub(super) async fn closed(&mut self) -> Vec<V::Commitment> {
        poll_fn(|cx| {
            for subscription in self.entries.values_mut() {
                for subscriber in &mut subscription.subscribers {
                    let _ = subscriber.sender.poll_closed(cx);
                }
            }
            let removed = self.retain_open();
            if removed.is_empty() {
                Poll::Pending
            } else {
                Poll::Ready(removed)
            }
        })
        .await
    }

    /// Notifies matching subscribers and returns whether a subscription was removed.
    pub(super) fn notify(&mut self, block: V::Block) -> bool {
        let Some(subscription) = self.entries.remove(&V::commitment(&block)) else {
            return false;
        };
        for subscriber in subscription.subscribers {
            deliver(subscriber, &block);
        }
        true
    }

    pub(super) fn insert<Buf: Buffer<V>>(
        &mut self,
        span: Span,
        commitment: V::Commitment,
        response: oneshot::Sender<V::Block>,
        waiters: &mut AbortablePool<'_, Option<V::Block>>,
        buffer: &Buf,
    ) {
        let subscriber = Subscriber {
            span,
            sender: response,
        };
        match self.entries.entry(commitment) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(subscriber);
            }
            Entry::Vacant(entry) => {
                let aborter = buffer
                    .subscribe_by_commitment(commitment)
                    .map(|rx| waiters.push(async move { rx.await.ok() }));
                entry.insert(BlockSubscription {
                    subscribers: vec![subscriber],
                    _aborter: aborter,
                });
            }
        }
    }
}

/// Local waiters for canonical block bodies at finalized heights.
pub(super) struct Finalized<V: Variant> {
    entries: BTreeMap<Height, Vec<Subscriber<V>>>,
}

impl<V: Variant> Finalized<V> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub(super) fn insert(
        &mut self,
        span: Span,
        height: Height,
        response: oneshot::Sender<V::Block>,
    ) {
        self.entries.entry(height).or_default().push(Subscriber {
            span,
            sender: response,
        });
    }

    /// Delivers a body whose canonical finalization has been established by the actor.
    pub(super) fn notify(&mut self, block: &V::Block) -> bool {
        let Some(subscribers) = self.entries.remove(&block.height()) else {
            return false;
        };
        for subscriber in subscribers {
            deliver(subscriber, block);
        }
        true
    }

    pub(super) fn prune(&mut self, min: Height) {
        self.entries = self.entries.split_off(&min);
    }

    /// Removes canceled callers, waking the actor even when no bodies arrive.
    pub(super) async fn closed(&mut self) {
        poll_fn(|cx| {
            let mut closed = false;
            self.entries.retain(|_, subscribers| {
                subscribers.retain_mut(|subscriber| {
                    if subscriber.sender.poll_closed(cx).is_ready() {
                        closed = true;
                        false
                    } else {
                        true
                    }
                });
                !subscribers.is_empty()
            });
            if closed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{core::variant::NoBuffer, mocks::block::EmptyBlock, standard::Standard},
        types::{Height, Round},
    };
    use commonware_cryptography::{
        Digestible,
        ed25519::PublicKey,
        sha256::{Digest, Sha256},
    };
    use commonware_macros::select;
    use commonware_p2p::Recipients;
    use commonware_runtime::{Clock, Runner as _, deterministic};
    use commonware_utils::sync::Mutex;
    use futures::FutureExt;
    use std::sync::Arc;

    type TestBlock = EmptyBlock<Sha256>;
    type TestVariant = Standard<TestBlock>;
    type TestWaiters = AbortablePool<'static, Option<Arc<TestBlock>>>;
    type Subscriber = oneshot::Sender<Arc<TestBlock>>;
    type Subscribers = Arc<Mutex<Vec<Subscriber>>>;

    #[derive(Clone, Default)]
    struct TestBuffer {
        commitment_subscribers: Subscribers,
    }

    impl TestBuffer {
        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscribers.lock().len()
        }
    }

    impl Buffer<TestVariant> for TestBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, _digest: Digest) -> Option<Arc<TestBlock>> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Digest) -> Option<Arc<TestBlock>> {
            None
        }

        fn subscribe_by_commitment(
            &self,
            _commitment: Digest,
        ) -> Option<oneshot::Receiver<Arc<TestBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscribers.lock().push(sender);
            Some(receiver)
        }

        fn retire(&self, _update: crate::marshal::core::Retirement<Digest>) {}

        fn send(&self, _round: Round, _block: Arc<TestBlock>, _recipients: Recipients<PublicKey>) {}
    }

    fn block(height: u64, timestamp: u64) -> TestBlock {
        TestBlock::new(Sha256::fill(0), Height::new(height), timestamp)
    }

    fn assert_receives(receiver: oneshot::Receiver<Arc<TestBlock>>, expected: &TestBlock) {
        let received = receiver
            .now_or_never()
            .expect("receiver should be ready")
            .expect("sender should deliver block");
        assert_eq!(received.digest(), expected.digest());
    }

    #[test]
    fn insert_coalesces_duplicate_keys() {
        let test_buffer = TestBuffer::default();
        let buffer = test_buffer.clone();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(1, 10);

        let (first_sender, first_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            first_sender,
            &mut waiters,
            &buffer,
        );
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            second_sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(test_buffer.commitment_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 1);

        assert!(subscriptions.notify(Arc::new(block.clone())));
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn finalized_waiters_share_delivery_and_close_below_prune() {
        let mut subscriptions = Finalized::<TestVariant>::new();
        let block = Arc::new(block(5, 50));
        let (stale_sender, mut stale_receiver) = oneshot::channel();
        let (first_sender, first_receiver) = oneshot::channel();
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(Span::none(), Height::new(4), stale_sender);
        subscriptions.insert(Span::none(), block.height(), first_sender);
        subscriptions.insert(Span::none(), block.height(), second_sender);
        subscriptions.prune(block.height());
        assert!(matches!(
            stale_receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(subscriptions.notify(&block));
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(!subscriptions.notify(&block));
    }

    #[test]
    fn finalized_cancellation_wakes_without_block_delivery() {
        deterministic::Runner::default().start(|context| async move {
            let mut subscriptions = Finalized::<TestVariant>::new();
            let (response, receiver) = oneshot::channel();
            subscriptions.insert(Span::none(), Height::new(5), response);
            select! {
                _ = subscriptions.closed() => {},
                _ = async {
                    context.sleep(std::time::Duration::from_millis(1)).await;
                    drop(receiver);
                    std::future::pending::<()>().await;
                } => unreachable!(),
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("cancellation must wake finalized waiter cleanup");
                },
            }
            assert!(subscriptions.entries.is_empty());
        });
    }

    #[test]
    fn retain_open_drops_closed_subscribers_and_keeps_open_ones() {
        let buffer = TestBuffer::default();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(3, 30);

        let (closed_sender, closed_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            closed_sender,
            &mut waiters,
            &buffer,
        );
        let (open_sender, open_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            open_sender,
            &mut waiters,
            &buffer,
        );
        drop(closed_receiver);

        assert!(subscriptions.retain_open().is_empty());
        let subscription = subscriptions
            .entries
            .get(&block.digest())
            .expect("open subscriber should remain");
        assert_eq!(subscription.subscribers.len(), 1);

        assert!(subscriptions.notify(Arc::new(block.clone())));
        assert_receives(open_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn insert_without_buffer_keeps_local_subscriber() {
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let buffer = NoBuffer::<PublicKey>::new();
        let block = block(5, 50);

        let (sender, receiver) = oneshot::channel();
        subscriptions.insert(Span::none(), block.digest(), sender, &mut waiters, &buffer);

        assert_eq!(subscriptions.entries.len(), 1);
        assert!(!subscriptions.notify(Arc::new(TestBlock::new(
            Sha256::fill(1),
            Height::new(9),
            90
        ))));
        assert!(subscriptions.entries.contains_key(&block.digest()));
        assert!(subscriptions.notify(Arc::new(block.clone())));
        assert_receives(receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn shared_cancellation_wakes_when_last_caller_closes() {
        deterministic::Runner::default().start(|context| async move {
            let buffer = TestBuffer::default();
            let mut waiters = TestWaiters::default();
            let mut subscriptions = Subscriptions::<TestVariant>::new();
            let commitment = block(6, 60).digest();
            let (first_sender, first_receiver) = oneshot::channel();
            let (second_sender, second_receiver) = oneshot::channel();
            subscriptions.insert(
                Span::none(),
                commitment,
                first_sender,
                &mut waiters,
                &buffer,
            );
            subscriptions.insert(
                Span::none(),
                commitment,
                second_sender,
                &mut waiters,
                &buffer,
            );
            assert_eq!(buffer.commitment_subscription_count(), 1);

            drop(first_receiver);
            assert!(subscriptions.closed().now_or_never().is_none());
            assert!(subscriptions.entries.contains_key(&commitment));
            assert!(!buffer.commitment_subscribers.lock()[0].is_closed());

            select! {
                removed = subscriptions.closed() => {
                    assert_eq!(removed, vec![commitment]);
                },
                _ = async {
                    context.sleep(std::time::Duration::from_millis(1)).await;
                    drop(second_receiver);
                    std::future::pending::<()>().await;
                } => unreachable!(),
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("last cancellation must wake subscription cleanup");
                },
            }
            assert!(!subscriptions.entries.contains_key(&commitment));
            assert!(waiters.next_completed().await.is_err());
            assert!(buffer.commitment_subscribers.lock()[0].is_closed());
            assert!(subscriptions.retain_open().is_empty());
        });
    }

    #[test]
    fn buffer_closure_keeps_shared_subscription_until_delivery_or_cancellation() {
        deterministic::Runner::default().start(|_| async move {
            let buffer = TestBuffer::default();
            let mut waiters = TestWaiters::default();
            let mut subscriptions = Subscriptions::<TestVariant>::new();
            let block = block(7, 70);
            let commitment = block.digest();
            let (first_sender, mut first_receiver) = oneshot::channel();
            let (second_sender, mut second_receiver) = oneshot::channel();
            subscriptions.insert(
                Span::none(),
                commitment,
                first_sender,
                &mut waiters,
                &buffer,
            );
            subscriptions.insert(
                Span::none(),
                commitment,
                second_sender,
                &mut waiters,
                &buffer,
            );

            buffer.commitment_subscribers.lock().clear();
            let closed = waiters
                .next_completed()
                .await
                .expect("waiter was not aborted");
            assert!(closed.is_none());
            assert!(matches!(
                first_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                second_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            drop(first_receiver);
            assert!(subscriptions.retain_open().is_empty());
            assert!(subscriptions.entries.contains_key(&commitment));
            assert!(subscriptions.notify(Arc::new(block.clone())));
            assert_receives(second_receiver, &block);
            assert!(!subscriptions.entries.contains_key(&commitment));
        });
    }
}
