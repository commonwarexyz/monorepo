use super::{Buffer, Variant};
use commonware_cryptography::Digestible;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter},
};
use std::collections::{btree_map::Entry, BTreeMap};

/// A set of local subscribers waiting for one block.
struct BlockSubscription<V: Variant> {
    subscribers: Vec<oneshot::Sender<V::Block>>,
    _aborter: Aborter,
}

/// The key used to track block subscriptions.
///
/// Digest-scoped and commitment-scoped subscriptions are intentionally distinct
/// so a block that aliases on digest cannot satisfy a different commitment wait.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Key<C, D> {
    Digest(D),
    Commitment(C),
}

pub(super) type KeyFor<V> =
    Key<<V as Variant>::Commitment, <<V as Variant>::Block as Digestible>::Digest>;

pub(super) struct Subscriptions<V: Variant> {
    entries: BTreeMap<KeyFor<V>, BlockSubscription<V>>,
}

impl<V: Variant> Subscriptions<V> {
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub(super) fn remove(&mut self, key: &KeyFor<V>) {
        self.entries.remove(key);
    }

    pub(super) fn retain_open(&mut self) {
        self.entries.retain(|_, subscription| {
            subscription
                .subscribers
                .retain(|subscriber| !subscriber.is_closed());
            !subscription.subscribers.is_empty()
        });
    }

    pub(super) fn notify(&mut self, block: &V::Block) {
        if let Some(mut subscription) = self.entries.remove(&Key::Digest(block.digest())) {
            for subscriber in subscription.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
        if let Some(mut subscription) = self.entries.remove(&Key::Commitment(V::commitment(block)))
        {
            for subscriber in subscription.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
    }

    pub(super) fn insert<Buf: Buffer<V>>(
        &mut self,
        key: KeyFor<V>,
        response: oneshot::Sender<V::Block>,
        waiters: &mut AbortablePool<Result<V::Block, KeyFor<V>>>,
        buffer: &mut Buf,
    ) {
        match self.entries.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(response);
            }
            Entry::Vacant(entry) => {
                let rx = match key {
                    Key::Digest(digest) => buffer.subscribe_by_digest(digest),
                    Key::Commitment(commitment) => buffer.subscribe_by_commitment(commitment),
                };
                let waiter_key = key;
                let aborter = waiters.push(async move { rx.await.map_err(|_| waiter_key) });
                entry.insert(BlockSubscription {
                    subscribers: vec![response],
                    _aborter: aborter,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::{mocks::block::Block, standard::Standard},
        types::{Height, Round},
    };
    use commonware_cryptography::{
        ed25519::PublicKey,
        sha256::{Digest, Sha256},
        Digestible,
    };
    use commonware_macros::select;
    use commonware_p2p::Recipients;
    use commonware_runtime::{deterministic, Clock, Runner as _};
    use commonware_utils::sync::Mutex;
    use futures::FutureExt;
    use std::sync::Arc;

    type TestBlock = Block<Digest, ()>;
    type TestVariant = Standard<TestBlock>;
    type TestWaiters = AbortablePool<Result<TestBlock, KeyFor<TestVariant>>>;
    type Subscriber = oneshot::Sender<TestBlock>;
    type Subscribers = Arc<Mutex<Vec<Subscriber>>>;

    #[derive(Clone, Default)]
    struct TestBuffer {
        digest_subscribers: Subscribers,
        commitment_subscribers: Subscribers,
    }

    impl TestBuffer {
        fn digest_subscription_count(&self) -> usize {
            self.digest_subscribers.lock().len()
        }

        fn commitment_subscription_count(&self) -> usize {
            self.commitment_subscribers.lock().len()
        }
    }

    impl Buffer<TestVariant> for TestBuffer {
        type PublicKey = PublicKey;

        async fn find_by_digest(&self, _digest: Digest) -> Option<TestBlock> {
            None
        }

        async fn find_by_commitment(&self, _commitment: Digest) -> Option<TestBlock> {
            None
        }

        fn subscribe_by_digest(&self, _digest: Digest) -> oneshot::Receiver<TestBlock> {
            let (sender, receiver) = oneshot::channel();
            self.digest_subscribers.lock().push(sender);
            receiver
        }

        fn subscribe_by_commitment(&self, _commitment: Digest) -> oneshot::Receiver<TestBlock> {
            let (sender, receiver) = oneshot::channel();
            self.commitment_subscribers.lock().push(sender);
            receiver
        }

        fn finalized(&self, _commitment: Digest) {}

        fn send(&self, _round: Round, _block: TestBlock, _recipients: Recipients<PublicKey>) {}
    }

    fn block(height: u64, timestamp: u64) -> TestBlock {
        Block::new::<Sha256>((), Sha256::fill(0), Height::new(height), timestamp)
    }

    fn assert_receives(receiver: oneshot::Receiver<TestBlock>, expected: &TestBlock) {
        let received = receiver
            .now_or_never()
            .expect("receiver should be ready")
            .expect("sender should deliver block");
        assert_eq!(received.digest(), expected.digest());
    }

    #[test]
    fn insert_coalesces_duplicate_keys() {
        let mut buffer = TestBuffer::default();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(1, 10);

        let (first_sender, first_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Digest(block.digest()),
            first_sender,
            &mut waiters,
            &mut buffer,
        );
        let (second_sender, second_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Digest(block.digest()),
            second_sender,
            &mut waiters,
            &mut buffer,
        );

        assert_eq!(buffer.digest_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 1);

        subscriptions.notify(&block);
        assert_receives(first_receiver, &block);
        assert_receives(second_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn notify_wakes_digest_and_commitment_subscribers() {
        let mut buffer = TestBuffer::default();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(2, 20);

        let (digest_sender, digest_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Digest(block.digest()),
            digest_sender,
            &mut waiters,
            &mut buffer,
        );
        let (commitment_sender, commitment_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Commitment(block.digest()),
            commitment_sender,
            &mut waiters,
            &mut buffer,
        );

        assert_eq!(buffer.digest_subscription_count(), 1);
        assert_eq!(buffer.commitment_subscription_count(), 1);
        assert_eq!(subscriptions.entries.len(), 2);

        subscriptions.notify(&block);
        assert_receives(digest_receiver, &block);
        assert_receives(commitment_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn retain_open_drops_closed_subscribers_and_keeps_open_ones() {
        let mut buffer = TestBuffer::default();
        let mut waiters = TestWaiters::default();
        let mut subscriptions = Subscriptions::<TestVariant>::new();
        let block = block(3, 30);

        let (closed_sender, closed_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Digest(block.digest()),
            closed_sender,
            &mut waiters,
            &mut buffer,
        );
        let (open_sender, open_receiver) = oneshot::channel();
        subscriptions.insert(
            Key::Digest(block.digest()),
            open_sender,
            &mut waiters,
            &mut buffer,
        );
        drop(closed_receiver);

        subscriptions.retain_open();
        let subscription = subscriptions
            .entries
            .get(&Key::Digest(block.digest()))
            .expect("open subscriber should remain");
        assert_eq!(subscription.subscribers.len(), 1);

        subscriptions.notify(&block);
        assert_receives(open_receiver, &block);
        assert!(subscriptions.entries.is_empty());
    }

    #[test]
    fn remove_drops_waiter_and_aborts_buffer_waiter() {
        deterministic::Runner::default().start(|context| async move {
            let mut buffer = TestBuffer::default();
            let mut waiters = TestWaiters::default();
            let mut subscriptions = Subscriptions::<TestVariant>::new();
            let block = block(4, 40);
            let key = Key::Digest(block.digest());

            let (sender, _receiver) = oneshot::channel();
            subscriptions.insert(key, sender, &mut waiters, &mut buffer);
            subscriptions.remove(&key);

            select! {
                completion = waiters.next_completed() => {
                    assert!(
                        completion.is_err(),
                        "removing the subscription should abort the buffer waiter"
                    );
                },
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("waiter should close after subscription removal");
                },
            }
        });
    }
}
