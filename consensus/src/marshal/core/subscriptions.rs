use super::{Buffer, Variant};
use crate::{Heightable, types::Height};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
};
use std::collections::{BTreeMap, btree_map::Entry};
use tracing::{Span, info_span};

/// A set of local subscribers waiting for one block.
///
/// Each caller remains registered until delivery, caller cancellation, or actor shutdown.
/// Resolver acquisition remains available after the backing buffer closes its waiter.
///
/// Dropping the subscription aborts the backing buffer waiter, if one exists.
struct BlockSubscription<V: Variant> {
    /// Callers that requested the block from peers.
    fetching: Vec<Subscriber<V>>,
    /// Callers that wait without requesting the block from peers.
    waiting: Vec<Subscriber<V>>,
    /// Aborts the backing buffer waiter when the subscription drops.
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

/// Local callers waiting for blocks by exact commitment.
pub(super) struct Subscriptions<V: Variant> {
    entries: BTreeMap<V::Commitment, BlockSubscription<V>>,
}

impl<V: Variant> Subscriptions<V> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns whether a caller waiting for `commitment` requested it from peers.
    ///
    /// Includes closed callers until [`Self::retain_open`] removes them. This keeps speculative
    /// demand from sharing a request that pending cancellation can remove.
    pub(super) fn fetching(&self, commitment: &V::Commitment) -> bool {
        self.entries
            .get(commitment)
            .is_some_and(|subscription| !subscription.fetching.is_empty())
    }

    /// Removes canceled callers and returns the commitments whose last fetching caller left.
    /// Canceled callers that only wait are removed without being reported.
    pub(super) fn retain_open(&mut self) -> Vec<V::Commitment> {
        let mut ended = Vec::new();
        self.entries.retain(|commitment, subscription| {
            // Report the commitment only when its last fetching caller closed here.
            let fetching = !subscription.fetching.is_empty();
            subscription
                .fetching
                .retain(|subscriber| !subscriber.sender.is_closed());
            subscription
                .waiting
                .retain(|subscriber| !subscriber.sender.is_closed());
            if fetching && subscription.fetching.is_empty() {
                ended.push(*commitment);
            }
            !subscription.fetching.is_empty() || !subscription.waiting.is_empty()
        });
        ended
    }

    /// Notifies matching subscribers and returns whether a subscription was removed.
    pub(super) fn notify(&mut self, block: &V::Block) -> bool {
        let Some(subscription) = self.entries.remove(&V::commitment(block)) else {
            return false;
        };
        for subscriber in subscription
            .fetching
            .into_iter()
            .chain(subscription.waiting)
        {
            deliver(subscriber, block);
        }
        true
    }

    /// Registers a caller for `commitment`, recording whether it requested the block from peers.
    pub(super) fn insert<Buf: Buffer<V>>(
        &mut self,
        span: Span,
        commitment: V::Commitment,
        fetch: bool,
        response: oneshot::Sender<V::Block>,
        waiters: &mut AbortablePool<'_, Option<V::Block>>,
        buffer: &Buf,
    ) {
        let subscriber = Subscriber {
            span,
            sender: response,
        };

        // The first caller for a commitment opens the buffer waiter that later callers share, if
        // the buffer provides one.
        let subscription = match self.entries.entry(commitment) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let aborter = buffer
                    .subscribe_by_commitment(commitment)
                    .map(|rx| waiters.push(async move { rx.await.ok() }));
                entry.insert(BlockSubscription {
                    fetching: Vec::new(),
                    waiting: Vec::new(),
                    _aborter: aborter,
                })
            }
        };

        // Callers that fetch are tracked apart so their cancellation can end peer demand.
        if fetch {
            subscription.fetching.push(subscriber);
        } else {
            subscription.waiting.push(subscriber);
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

    /// Registers a caller for the finalized block at `height`.
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

    /// Drops waiters below `min`, closing their receivers.
    pub(super) fn prune(&mut self, min: Height) {
        self.entries = self.entries.split_off(&min);
    }

    /// Removes canceled callers.
    pub(super) fn retain_open(&mut self) {
        self.entries.retain(|_, subscribers| {
            subscribers.retain(|subscriber| !subscriber.sender.is_closed());
            !subscribers.is_empty()
        });
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
        Digested, Digestible,
        ed25519::PublicKey,
        sha256::{Digest, Sha256},
    };
    use commonware_p2p::Recipients;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::sync::Mutex;
    use futures::FutureExt;
    use std::sync::Arc;

    type TestBlock = EmptyBlock<Sha256>;
    type TestVariant = Standard<TestBlock>;
    type TestWaiters = AbortablePool<'static, Option<Digested<TestBlock>>>;
    type Subscriber = oneshot::Sender<Digested<TestBlock>>;
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

        async fn find_by_digest(&self, _digest: Digest) -> Option<Digested<TestBlock>> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Digest) -> Option<Digested<TestBlock>> {
            None
        }

        fn subscribe_by_commitment(
            &self,
            _commitment: Digest,
        ) -> Option<oneshot::Receiver<Digested<TestBlock>>> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscribers.lock().push(sender);
            Some(receiver)
        }

        fn send(
            &self,
            _round: Round,
            _block: Digested<TestBlock>,
            _recipients: Recipients<PublicKey>,
        ) {
        }
    }

    fn block(height: u64, timestamp: u64) -> Digested<TestBlock> {
        let block = TestBlock::new(Sha256::fill(0), Height::new(height), timestamp);
        let digest = block.digest();
        Digested::precomputed(block, digest)
    }

    /// Subscriptions that wait on a recording buffer.
    struct Fixture {
        buffer: TestBuffer,
        waiters: TestWaiters,
        subscriptions: Subscriptions<TestVariant>,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                buffer: TestBuffer::default(),
                waiters: TestWaiters::default(),
                subscriptions: Subscriptions::new(),
            }
        }

        /// Registers a caller for `commitment`. The caller fetches it when `fetch` is set.
        fn subscribe(
            &mut self,
            commitment: Digest,
            fetch: bool,
        ) -> oneshot::Receiver<Digested<TestBlock>> {
            let (sender, receiver) = oneshot::channel();
            self.subscriptions.insert(
                Span::none(),
                commitment,
                fetch,
                sender,
                &mut self.waiters,
                &self.buffer,
            );
            receiver
        }
    }

    fn assert_receives(
        receiver: oneshot::Receiver<Digested<TestBlock>>,
        expected: &Digested<TestBlock>,
    ) {
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
            true,
            first_sender,
            &mut waiters,
            &buffer,
        );
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            true,
            second_sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(test_buffer.commitment_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 1);

        assert!(subscriptions.notify(&block));
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    /// Pruning closes finalized waiters below the prune height and keeps those at it. One delivery
    /// answers every waiter at the block's height and removes them.
    #[test]
    fn finalized_waiters_share_delivery_and_close_below_prune() {
        // Two waiters at the block's height and one below it.
        let mut subscriptions = Finalized::<TestVariant>::new();
        let block = block(5, 50);
        let (stale_sender, mut stale_receiver) = oneshot::channel();
        let (first_sender, first_receiver) = oneshot::channel();
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(Span::none(), Height::new(4), stale_sender);
        subscriptions.insert(Span::none(), block.height(), first_sender);
        subscriptions.insert(Span::none(), block.height(), second_sender);

        // Pruning to the block's height closes only the waiter below it.
        subscriptions.prune(block.height());
        assert!(matches!(
            stale_receiver.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));

        // One notification answers both remaining waiters and leaves nothing to notify.
        assert!(subscriptions.notify(&block));
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(!subscriptions.notify(&block));
    }

    /// Cleanup removes a canceled finalized waiter and keeps an open one at the same height for its
    /// delivery. A height whose only waiter cancels loses its entry, though no block arrives there.
    #[test]
    fn finalized_retain_open_drops_canceled_waiters() {
        // Two waiters register at one height, and one cancels.
        let mut subscriptions = Finalized::<TestVariant>::new();
        let block = block(5, 50);
        let (canceled, canceled_receiver) = oneshot::channel();
        let (open, open_receiver) = oneshot::channel();
        subscriptions.insert(Span::none(), block.height(), canceled);
        subscriptions.insert(Span::none(), block.height(), open);
        drop(canceled_receiver);

        // Cleanup keeps the open waiter, and the delivery answers it.
        subscriptions.retain_open();
        assert!(subscriptions.notify(&block));
        assert_receives(open_receiver, &block);

        // A registered waiter cancels.
        let (response, receiver) = oneshot::channel();
        subscriptions.insert(Span::none(), block.height(), response);
        drop(receiver);

        // Cleanup removes the waiter and leaves no entry for its height.
        subscriptions.retain_open();
        assert!(subscriptions.entries.is_empty());
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
            true,
            closed_sender,
            &mut waiters,
            &buffer,
        );
        let (open_sender, open_receiver) = oneshot::channel();
        subscriptions.insert(
            Span::none(),
            block.digest(),
            true,
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
        assert_eq!(subscription.fetching.len(), 1);

        assert!(subscriptions.notify(&block));
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
        subscriptions.insert(
            Span::none(),
            block.digest(),
            true,
            sender,
            &mut waiters,
            &buffer,
        );

        assert_eq!(subscriptions.entries.len(), 1);
        let other = TestBlock::new(Sha256::fill(1), Height::new(9), 90);
        let other_digest = other.digest();
        assert!(!subscriptions.notify(&Digested::precomputed(other, other_digest)));
        assert!(subscriptions.entries.contains_key(&block.digest()));
        assert!(subscriptions.notify(&block));
        assert_receives(receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    /// Fetching callers that share a commitment keep its subscription and buffer waiter until the
    /// last of them cancels. Cleanup then reports the commitment and aborts the buffer waiter.
    #[test]
    fn shared_subscription_ends_when_last_caller_cancels() {
        deterministic::Runner::default().start(|_| async move {
            // Two fetching callers share one buffer waiter.
            let mut fixture = Fixture::new();
            let commitment = block(6, 60).digest();
            let first_receiver = fixture.subscribe(commitment, true);
            let second_receiver = fixture.subscribe(commitment, true);
            assert_eq!(fixture.buffer.commitment_subscription_count(), 1);

            // Canceling one caller reports nothing and keeps the buffer waiter open.
            drop(first_receiver);
            assert!(fixture.subscriptions.retain_open().is_empty());
            assert!(fixture.subscriptions.entries.contains_key(&commitment));
            assert!(!fixture.buffer.commitment_subscribers.lock()[0].is_closed());

            // Canceling the last caller reports the commitment.
            drop(second_receiver);
            assert_eq!(fixture.subscriptions.retain_open(), vec![commitment]);

            // The subscription is gone and its buffer waiter was aborted.
            assert!(!fixture.subscriptions.entries.contains_key(&commitment));
            assert!(fixture.waiters.next_completed().await.is_err());
            assert!(fixture.buffer.commitment_subscribers.lock()[0].is_closed());
            assert!(fixture.subscriptions.retain_open().is_empty());
        });
    }

    /// Cleanup reports a commitment when its last fetching caller cancels, while a remaining
    /// waiting caller keeps the subscription and buffer waiter. A waiting caller's cancellation is
    /// never reported.
    #[test]
    fn retain_open_reports_only_the_last_fetching_caller() {
        deterministic::Runner::default().start(|_| async move {
            // One waiting and one fetching caller share a buffer waiter.
            let mut fixture = Fixture::new();
            let commitment = block(8, 80).digest();
            let waiting_receiver = fixture.subscribe(commitment, false);
            assert!(!fixture.subscriptions.fetching(&commitment));
            let fetching_receiver = fixture.subscribe(commitment, true);
            assert!(fixture.subscriptions.fetching(&commitment));
            assert_eq!(fixture.buffer.commitment_subscription_count(), 1);

            // Canceling the only fetching caller ends peer demand but keeps the local wait.
            drop(fetching_receiver);
            assert_eq!(fixture.subscriptions.retain_open(), vec![commitment]);
            assert!(!fixture.subscriptions.fetching(&commitment));
            assert!(fixture.subscriptions.entries.contains_key(&commitment));
            assert!(!fixture.buffer.commitment_subscribers.lock()[0].is_closed());

            // Canceling the remaining wait removes the subscription without reporting it.
            drop(waiting_receiver);
            assert!(fixture.subscriptions.retain_open().is_empty());
            assert!(!fixture.subscriptions.entries.contains_key(&commitment));
            assert!(fixture.waiters.next_completed().await.is_err());
            assert!(fixture.buffer.commitment_subscribers.lock()[0].is_closed());
        });
    }

    /// A buffer that closes its waiter answers no caller and leaves the subscription registered. A
    /// caller that remains after another cancels receives a later delivery.
    #[test]
    fn buffer_closure_keeps_shared_subscription_until_delivery_or_cancellation() {
        deterministic::Runner::default().start(|_| async move {
            // Two fetching callers share a buffer waiter.
            let mut fixture = Fixture::new();
            let block = block(7, 70);
            let commitment = block.digest();
            let mut first_receiver = fixture.subscribe(commitment, true);
            let mut second_receiver = fixture.subscribe(commitment, true);

            // Closing the buffer completes the waiter with nothing and answers neither caller.
            fixture.buffer.commitment_subscribers.lock().clear();
            let closed = fixture
                .waiters
                .next_completed()
                .await
                .expect("buffer closure must complete the waiter without aborting it");
            assert!(closed.is_none());
            assert!(matches!(
                first_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                second_receiver.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));

            // After one caller cancels, the other still receives a later delivery.
            drop(first_receiver);
            assert!(fixture.subscriptions.retain_open().is_empty());
            assert!(fixture.subscriptions.entries.contains_key(&commitment));
            assert!(fixture.subscriptions.notify(&block));
            assert_receives(second_receiver, &block);
            assert!(!fixture.subscriptions.entries.contains_key(&commitment));
        });
    }
}
