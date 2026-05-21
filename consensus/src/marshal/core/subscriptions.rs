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
