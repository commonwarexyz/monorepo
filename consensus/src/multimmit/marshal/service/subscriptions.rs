//! Bounded ownership of unresolved producer-block subscriptions.
//!
//! Callers waiting for the same block share one acquisition, and different blocks are polled
//! independently. An acquisition has two stages: a race that finds the block, aborted once every
//! caller waiting for it has gone, and a settlement that makes the found block durable custody,
//! which always runs to completion so its side effects never depend on the callers.
//!
//! Simplex marshal's subscriptions track one waiter set per block without a bound. Here the
//! router serves untrusted callers, so the total number of waiting callers is capped, and each
//! caller gets a relay that notices when it stops waiting so an abandoned race is aborted.

use crate::multimmit::{
    actors::util::Waiters,
    marshal::types::Error,
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_cryptography::Hasher;
use commonware_macros::select;
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::{AbortablePool, Aborter, Pool},
};
use std::{future::Future, sync::Arc};
use tracing::Span;

/// The block a subscription's callers receive.
pub(super) type BlockResult<H, B> = Result<Arc<TransactionBlock<H, B>>, Error>;

/// Where a subscription found its block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    /// Buffered broadcast ingress.
    Buffer,
    /// Backfill.
    Backfill,
}

/// A block a subscription's race found.
pub(super) struct Found<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) reference: BlockRef<H::Digest>,
    pub(super) block: Arc<TransactionBlock<H, B>>,
    pub(super) origin: Origin,
    /// The span of the caller that started the subscription.
    pub(super) span: Span,
}

/// Progress the router must act on.
pub(super) enum Event<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// A race found its block; the router settles it with [`Subscriptions::settle`].
    Found(Found<H, B>),
    /// A found block is durable custody and its callers, if any remain, are answered.
    Settled(Found<H, B>),
}

/// A finished race.
struct Race<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    reference: BlockRef<H::Digest>,
    result: Result<Found<H, B>, Error>,
}

/// A finished settlement.
struct Settlement<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    found: Found<H, B>,
    result: Result<(), Error>,
}

/// Subscription pressure reported to router metrics.
pub(super) struct Stats {
    /// Distinct blocks with at least one waiting caller.
    pub(super) blocks: usize,
    /// Callers waiting across every block.
    pub(super) callers: usize,
}

/// Coalesces block subscriptions while bounding the total number of callers.
pub(super) struct Subscriptions<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Callers per block, each block holding the aborter of its one race.
    waiters: Waiters<BlockRef<H::Digest>, BlockResult<H, B>, Aborter>,
    /// One race per block with a waiting caller.
    races: AbortablePool<'static, Race<H, B>>,
    /// Found blocks being made durable custody; never aborted.
    settlements: Pool<'static, Settlement<H, B>>,
    /// One relay per caller, resolving with its block once the caller is answered or gone.
    callers: Pool<'static, BlockRef<H::Digest>>,
    capacity: usize,
}

impl<H, B> Subscriptions<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            waiters: Waiters::new(),
            races: AbortablePool::default(),
            settlements: Pool::default(),
            callers: Pool::default(),
            capacity,
        }
    }

    pub(super) fn stats(&self) -> Stats {
        Stats {
            blocks: self.waiters.keys(),
            callers: self.waiters.pending(),
        }
    }

    /// Registers a caller, starting one race for a block no caller waits for yet.
    ///
    /// `permit` is held until the caller is answered or gone and [`Self::next`] drops it, and is
    /// released right away when the caller is not registered. A reply that is already closed is
    /// dropped without registering. When the caller bound is reached, which the public mailbox's
    /// subscription slots prevent, the reply receives [`Error::SubscriptionCapacity`] immediately.
    pub(super) fn insert<Fut, P>(
        &mut self,
        reference: BlockRef<H::Digest>,
        reply: oneshot::Sender<BlockResult<H, B>>,
        permit: P,
        race: Fut,
    ) where
        Fut: Future<Output = Result<Found<H, B>, Error>> + Send + 'static,
        P: Send + 'static,
    {
        if reply.is_closed() {
            return;
        }
        if self.waiters.pending() >= self.capacity {
            reply.send_lossy(Err(Error::SubscriptionCapacity));
            return;
        }
        let (relay, receiver) = oneshot::channel();
        self.callers.push(async move {
            let mut reply = reply;
            select! {
                result = receiver => {
                    if let Ok(result) = result {
                        reply.send_lossy(result);
                    }
                },
                _ = reply.closed() => {},
            }
            // Released as the router drops this caller, before it handles another request.
            drop(permit);
            reference
        });
        let races = &mut self.races;
        self.waiters.insert(reference, relay, || {
            races.push(async move {
                Race {
                    reference,
                    result: race.await,
                }
            })
        });
    }

    /// Makes a found block durable custody with `admit`, which runs to completion even if every
    /// caller leaves.
    pub(super) fn settle<Fut>(&mut self, found: Found<H, B>, admit: Fut)
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.settlements.push(async move {
            Settlement {
                result: admit.await,
                found,
            }
        });
    }

    /// Resolves after the next finished race, finished settlement, or departed caller.
    ///
    /// A failed race or settlement answers its callers with the error. A departed caller is
    /// dropped, and a race no caller waits for is aborted.
    pub(super) async fn next(&mut self) -> Option<Event<H, B>> {
        select! {
            race = self.races.next_completed() => {
                let Race { reference, result } = race.ok()?;
                match result {
                    Ok(found) => Some(Event::Found(found)),
                    Err(error) => {
                        self.waiters.complete(&reference, Err(error));
                        None
                    }
                }
            },
            settlement = self.settlements.next_completed() => {
                let Settlement { found, result } = settlement;
                match result {
                    Ok(()) => {
                        self.waiters
                            .complete(&found.reference, Ok(Arc::clone(&found.block)));
                        Some(Event::Settled(found))
                    }
                    Err(error) => {
                        self.waiters.complete(&found.reference, Err(error));
                        None
                    }
                }
            },
            reference = self.callers.next_completed() => {
                self.waiters.retain_open(&reference);
                None
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            testing::TestBody,
            types::{ChainId, TransactionBlockHeader},
        },
        types::{Epoch, Height},
    };
    use commonware_cryptography::{Digestible as _, Sha256};
    use futures::{FutureExt as _, executor::block_on};
    use std::future::{pending, ready};

    type TestSubscriptions = Subscriptions<Sha256, TestBody>;

    fn reference(height: u64) -> BlockRef<<Sha256 as Hasher>::Digest> {
        BlockRef::new(
            ChainId::new(0),
            Height::new(height),
            Sha256::hash(&[&height.to_be_bytes()]),
        )
    }

    #[test]
    fn callers_share_one_acquisition_under_a_caller_bound() {
        let mut subscriptions = TestSubscriptions::new(2);
        let (first, _first) = oneshot::channel();
        subscriptions.insert(reference(1), first, (), pending());
        let (second, _second) = oneshot::channel();
        subscriptions.insert(reference(1), second, (), pending());
        let stats = subscriptions.stats();
        assert_eq!((stats.blocks, stats.callers), (1, 2));
        assert_eq!(subscriptions.races.len(), 1);

        let (rejected, mut response) = oneshot::channel();
        subscriptions.insert(reference(2), rejected, (), pending());
        assert!(matches!(
            response.try_recv(),
            Ok(Err(Error::SubscriptionCapacity))
        ));
        let stats = subscriptions.stats();
        assert_eq!((stats.blocks, stats.callers), (1, 2));
        assert_eq!(subscriptions.races.len(), 1);
    }

    #[test]
    fn closed_replies_are_not_registered() {
        let mut subscriptions = TestSubscriptions::new(1);
        let (reply, response) = oneshot::channel();
        drop(response);
        subscriptions.insert(reference(1), reply, (), pending());
        let stats = subscriptions.stats();
        assert_eq!((stats.blocks, stats.callers), (0, 0));
        assert!(subscriptions.races.is_empty());
        assert!(subscriptions.callers.is_empty());
    }

    #[test]
    fn departed_callers_hold_their_permit_until_dropped() {
        block_on(async {
            let mut subscriptions = TestSubscriptions::new(1);
            let permit = Arc::new(());
            let (departed, departure) = oneshot::channel();
            subscriptions.insert(reference(1), departed, Arc::clone(&permit), pending());
            drop(departure);
            // The caller left, but its permit stays held until the router drops it.
            assert_eq!(Arc::strong_count(&permit), 2);

            while subscriptions.stats().callers > 0 {
                subscriptions.next().await;
            }
            assert_eq!(Arc::strong_count(&permit), 1);

            // The freed permit's next caller is registered, never rejected for capacity.
            let (next, mut response) = oneshot::channel();
            subscriptions.insert(reference(2), next, Arc::clone(&permit), pending());
            assert!(matches!(
                response.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(subscriptions.stats().callers, 1);
        });
    }

    #[test]
    fn next_answers_callers_and_aborts_abandoned_acquisitions() {
        block_on(async {
            let mut subscriptions = TestSubscriptions::new(2);
            let (answered, mut answer) = oneshot::channel();
            subscriptions.insert(reference(1), answered, (), ready(Err(Error::Closed)));
            let (departed, departure) = oneshot::channel();
            subscriptions.insert(reference(2), departed, (), pending());
            drop(departure);

            for _ in 0..4 {
                if subscriptions.stats().callers == 0 {
                    break;
                }
                subscriptions.next().await;
            }
            let stats = subscriptions.stats();
            assert_eq!((stats.blocks, stats.callers), (0, 0));
            while subscriptions.next().now_or_never().is_some() {}
            assert!(matches!(answer.try_recv(), Ok(Err(Error::Closed))));
        });
    }

    fn block() -> Arc<TransactionBlock<Sha256, TestBody>> {
        let body = TestBody::new(Sha256::hash(&[b"parent"]), Height::new(1), 1);
        let header = TransactionBlockHeader::new(
            Epoch::new(0),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"producer parent"]),
            body.digest(),
        )
        .unwrap();
        Arc::new(TransactionBlock::new(header, body).unwrap())
    }

    fn found(block: &Arc<TransactionBlock<Sha256, TestBody>>) -> Found<Sha256, TestBody> {
        Found {
            reference: block.reference(),
            block: Arc::clone(block),
            origin: Origin::Buffer,
            span: Span::none(),
        }
    }

    #[test]
    fn settled_blocks_answer_waiting_callers() {
        block_on(async {
            let block = block();
            let mut subscriptions = TestSubscriptions::new(1);
            let (reply, mut response) = oneshot::channel();
            subscriptions.insert(block.reference(), reply, (), ready(Ok(found(&block))));
            let Some(Event::Found(found)) = subscriptions.next().await else {
                panic!("the race finds its block");
            };
            assert!(response.try_recv().is_err());
            subscriptions.settle(found, ready(Ok(())));
            let Some(Event::Settled(settled)) = subscriptions.next().await else {
                panic!("the settlement finishes");
            };
            assert_eq!(settled.block.as_ref(), block.as_ref());
            while subscriptions.stats().callers > 0 || response.try_recv().is_err() {
                subscriptions.next().await;
            }
        });
    }

    #[test]
    fn settlement_completes_after_its_callers_leave() {
        block_on(async {
            let block = block();
            let mut subscriptions = TestSubscriptions::new(1);
            let (reply, response) = oneshot::channel();
            subscriptions.insert(block.reference(), reply, (), ready(Ok(found(&block))));
            let Some(Event::Found(found)) = subscriptions.next().await else {
                panic!("the race finds its block");
            };

            // Admission is still running when the only caller leaves.
            let (admitted, admission) = oneshot::channel::<()>();
            subscriptions.settle(
                found,
                async move { admission.await.map_err(|_| Error::Closed) },
            );
            drop(response);
            assert!(subscriptions.next().await.is_none());
            assert_eq!(subscriptions.stats().callers, 0);

            admitted.send(()).unwrap();
            let Some(Event::Settled(settled)) = subscriptions.next().await else {
                panic!("the settlement outlives its callers");
            };
            assert_eq!(settled.origin, Origin::Buffer);
            assert_eq!(settled.reference, block.reference());
        });
    }
}
