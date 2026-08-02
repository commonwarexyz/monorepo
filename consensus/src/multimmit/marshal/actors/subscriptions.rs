//! Bounded ownership of unresolved producer-block subscriptions.
//!
//! Subscriptions are logical protocol state, not active router work. Callers waiting for the same
//! exact block share one backing acquisition, while different blocks remain independently polled.

use crate::multimmit::{
    marshal::mailbox,
    types::{BlockRef, TransactionBlock},
};
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, Hasher};
use commonware_macros::select;
use commonware_utils::{
    channel::oneshot,
    futures::{AbortablePool, Aborter, Pool},
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    future::Future,
    sync::Arc,
};

type Result<H, B> = std::result::Result<Arc<TransactionBlock<H, B>>, mailbox::Error>;
type Reply<H, B> = oneshot::Sender<Result<H, B>>;

/// One backing acquisition and every caller waiting for its exact result.
struct Subscription<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    replies: Vec<Reply<H, B>>,
    _aborter: Aborter,
}

/// The result of one independently polled block acquisition.
pub(super) type Completion<H, B> = (BlockRef<<H as Hasher>::Digest>, Result<H, B>);

/// Coalesces exact block subscriptions while bounding the total number of callers.
pub(super) struct Subscriptions<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    entries: BTreeMap<BlockRef<H::Digest>, Subscription<H, B>>,
    pending: usize,
    capacity: usize,
}

impl<H, B> Subscriptions<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(super) const fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            pending: 0,
            capacity,
        }
    }

    pub(super) fn stats(&self) -> (usize, usize) {
        (self.entries.len(), self.pending)
    }

    /// Registers a caller, starting one backing acquisition for a previously unseen block.
    pub(super) fn insert<Fut>(
        &mut self,
        reference: BlockRef<H::Digest>,
        reply: Reply<H, B>,
        completions: &mut AbortablePool<Completion<H, B>>,
        callers: &mut Pool<BlockRef<H::Digest>>,
        acquire: Fut,
    ) where
        Fut: Future<Output = Result<H, B>> + Send + 'static,
    {
        if reply.is_closed() {
            return;
        }
        if self.pending >= self.capacity {
            drop(reply.send(Err(mailbox::Error::Failed(Arc::from(
                "marshal block subscription capacity is exhausted",
            )))));
            return;
        }
        let (relay, receiver) = oneshot::channel();
        callers.push(async move {
            let mut reply = reply;
            select! {
                result = receiver => {
                    if let Ok(result) = result {
                        drop(reply.send(result));
                    }
                },
                _ = reply.closed() => {},
            }
            reference
        });
        self.pending += 1;
        match self.entries.entry(reference) {
            Entry::Occupied(mut entry) => entry.get_mut().replies.push(relay),
            Entry::Vacant(entry) => {
                let aborter = completions.push(async move { (reference, acquire.await) });
                entry.insert(Subscription {
                    replies: vec![relay],
                    _aborter: aborter,
                });
            }
        }
    }

    /// Removes canceled callers for one key and aborts an acquisition with no remaining caller.
    pub(super) fn retain_open(&mut self, reference: BlockRef<H::Digest>) {
        let Entry::Occupied(mut entry) = self.entries.entry(reference) else {
            return;
        };
        let before = entry.get().replies.len();
        entry.get_mut().replies.retain(|reply| !reply.is_closed());
        let removed = before - entry.get().replies.len();
        if entry.get().replies.is_empty() {
            entry.remove();
        }
        self.pending = self
            .pending
            .checked_sub(removed)
            .expect("removed subscriptions were counted as pending");
    }

    /// Completes every caller waiting for an exact block acquisition.
    pub(super) fn complete(&mut self, reference: BlockRef<H::Digest>, result: Result<H, B>) {
        let Some(subscription) = self.entries.remove(&reference) else {
            return;
        };
        self.pending = self
            .pending
            .checked_sub(subscription.replies.len())
            .expect("completed subscriptions were counted as pending");
        for reply in subscription.replies {
            drop(reply.send(result.clone()));
        }
    }
}
