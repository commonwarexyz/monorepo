//! Finalized storage, shared behind one lock.
//!
//! Marshal's loop answers a peer's request for a finalized block by reading two archives from
//! disk. Doing that inline stalls consensus behind a peer that is walking old heights. This module
//! keeps both archives behind a single fair read/write lock: marshal reads and mutates them
//! through [Stores], while a serving task answers peer backfill requests through the read side.
//!
//! Fairness bounds the interference in both directions: a mutation queued behind an in-flight
//! serve waits for at most that one serve, and later serves queue behind the mutation. A serve
//! reads both archives under one guard, so it is atomic with respect to mutations. Backfill
//! serving is bounded and rejects on overflow: a dropped request closes the peer's channel,
//! which the resolver retries.
//!
//! Every guard is scoped to a single call inside this module, so no guard is ever held across
//! an unrelated await. Marshal's writes complete before it forwards a serve, so a height
//! finalized in a batch is servable by that batch's requests.

use super::Variant;
use crate::{
    marshal::store::{Blocks, Certificates},
    simplex::types::Finalization,
    types::Height,
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::Digestible;
use commonware_runtime::{
    Handle, Metrics, Spawner,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    sync::{AsyncRwLockReadGuard, TracedAsyncRwLock},
};
use std::{future::Future, num::NonZeroUsize, sync::Arc};
use tracing::{Span, debug, warn};

/// A mutation panicked mid-write, destroying the stores.
const POISONED: &str = "finalized stores poisoned";

/// A peer's request for a finalized block, answered without marshal's involvement.
///
/// Carries the forwarding span, so a trace follows the request across the task boundary.
struct Serve {
    span: Span,
    height: Height,
    respond: oneshot::Sender<Bytes>,
}

/// The certificate and block stores, behind one lock.
///
/// Marshal holds the only [Stores], so it is the only mutator. The serving task shares the read
/// side through a [Reader].
pub(super) struct Stores<C, B> {
    inner: Arc<TracedAsyncRwLock<Option<(C, B)>>>,
    serving: mpsc::Sender<Serve>,
    /// Backfill requests handed to the serving task.
    forwarded: Counter,
    /// Backfill requests refused because the queue was full (the peer retries).
    refused: Counter,
}

impl<C, B> Stores<C, B> {
    /// Read guard over the certificate store.
    async fn finalizations(&self) -> AsyncRwLockReadGuard<'_, C> {
        AsyncRwLockReadGuard::map(self.inner.read().await, |slot| {
            &slot.as_ref().expect(POISONED).0
        })
    }

    /// Read guard over the block store.
    async fn blocks(&self) -> AsyncRwLockReadGuard<'_, B> {
        AsyncRwLockReadGuard::map(self.inner.read().await, |slot| {
            &slot.as_ref().expect(POISONED).1
        })
    }

    /// Run one consuming mutation over both stores under the write side of the lock.
    ///
    /// A failed mutation destroys the store it consumed, so `f` panics on error and every
    /// later access panics on the emptied slot. That matches marshal's behaviour when it held
    /// the stores directly.
    async fn mutate<T, Fut>(&self, f: impl FnOnce(C, B) -> Fut) -> T
    where
        Fut: Future<Output = (C, B, T)>,
    {
        let mut guard = self.inner.write().await;
        let (finalizations, blocks) = guard.take().expect(POISONED);
        let (finalizations, blocks, out) = f(finalizations, blocks).await;
        *guard = Some((finalizations, blocks));
        out
    }

    /// Hand a peer's backfill request to the serving task, refusing it when the queue is full.
    ///
    /// Never awaits. Call this after the batch's writes have completed, so a height finalized
    /// in that batch is stored before the request is serviced.
    pub fn serve(&self, height: Height, respond: oneshot::Sender<Bytes>) {
        match self.serving.try_send(Serve {
            span: Span::current(),
            height,
            respond,
        }) {
            Ok(()) => self.forwarded.inc(),
            Err(_) => self.refused.inc(),
        };
    }
}

impl<C: Certificates, B: Blocks> Stores<C, B> {
    /// Store a finalized block and, when consensus supplied one, its certificate.
    ///
    /// The write is buffered, not durable; the return is backpressure so consensus cannot
    /// outrun the disk.
    pub async fn put(
        &self,
        height: Height,
        digest: C::BlockDigest,
        block: B::Block,
        finalization: Option<Finalization<C::Scheme, C::Commitment>>,
    ) {
        self.mutate(|finalizations, blocks| async move {
            // The stores are independent, so write them together.
            let (blocks, finalizations) = futures::join!(
                async {
                    blocks
                        .put(block)
                        .await
                        .unwrap_or_else(|e| panic!("failed to store finalized block: {e}"))
                },
                async {
                    match finalization {
                        Some(finalization) => finalizations
                            .put(height, digest, finalization)
                            .await
                            .unwrap_or_else(|e| panic!("failed to store finalization: {e}")),
                        None => finalizations,
                    }
                }
            );
            (finalizations, blocks, ())
        })
        .await
    }

    /// Flush both stores, blocking until durable.
    pub async fn sync(&self) {
        self.mutate(|finalizations, blocks| async move {
            let (blocks, finalizations) = futures::join!(
                async {
                    blocks
                        .sync()
                        .await
                        .unwrap_or_else(|e| panic!("failed to sync finalized blocks: {e}"))
                },
                async {
                    finalizations
                        .sync()
                        .await
                        .unwrap_or_else(|e| panic!("failed to sync finalizations: {e}"))
                }
            );
            (finalizations, blocks, ())
        })
        .await
    }

    /// Begin flushing both stores, returning a handle that completes when durable.
    pub async fn start_sync(&self) -> Handle<()> {
        self.mutate(|finalizations, blocks| async move {
            let ((blocks, blocks_handle), (finalizations, finalizations_handle)) = futures::join!(
                async {
                    blocks
                        .start_sync()
                        .await
                        .unwrap_or_else(|e| panic!("failed to start finalized block sync: {e}"))
                },
                async {
                    finalizations
                        .start_sync()
                        .await
                        .unwrap_or_else(|e| panic!("failed to start finalization sync: {e}"))
                }
            );
            let handle = Handle::from_future(async move {
                let (a, b) = futures::join!(blocks_handle, finalizations_handle);
                a.and(b)
            });
            (finalizations, blocks, handle)
        })
        .await
    }

    /// Prune both stores below `height`.
    pub async fn prune(&self, height: Height) {
        self.mutate(|finalizations, blocks| async move {
            let (blocks, finalizations) = futures::join!(
                async {
                    blocks
                        .prune(height)
                        .await
                        .unwrap_or_else(|e| panic!("failed to prune finalized blocks: {e}"))
                },
                async {
                    finalizations
                        .prune(height)
                        .await
                        .unwrap_or_else(|e| panic!("failed to prune finalizations: {e}"))
                }
            );
            (finalizations, blocks, ())
        })
        .await
    }

    /// The finalized block at `height`.
    pub async fn get_block(&self, height: Height) -> Option<B::Block> {
        self.blocks()
            .await
            .get(ArchiveID::Index(height.get()))
            .await
            .unwrap_or_else(|e| panic!("failed to get finalized block: {e}"))
    }

    /// The certificate at `height`.
    pub async fn get_finalization(
        &self,
        height: Height,
    ) -> Option<Finalization<C::Scheme, C::Commitment>> {
        self.finalizations()
            .await
            .get(ArchiveID::Index(height.get()))
            .await
            .unwrap_or_else(|e| panic!("failed to get finalization: {e}"))
    }

    /// The finalized block with `digest`, whatever its height.
    pub async fn get_block_by_digest(
        &self,
        digest: <B::Block as Digestible>::Digest,
    ) -> Option<B::Block> {
        self.blocks()
            .await
            .get(ArchiveID::Key(&digest))
            .await
            .unwrap_or_else(|e| panic!("failed to get block by digest: {e}"))
    }

    /// Whether a certificate is stored at `height`.
    pub async fn has_finalization(&self, height: Height) -> bool {
        self.finalizations()
            .await
            .has(height)
            .await
            .unwrap_or_else(|e| panic!("failed to check finalization: {e}"))
    }

    /// The highest stored certificate height.
    pub async fn last_finalization(&self) -> Option<Height> {
        self.finalizations().await.last_index()
    }

    /// The highest stored finalized block height.
    pub async fn last_block(&self) -> Option<Height> {
        self.blocks().await.last_index()
    }

    /// Up to `max` finalized block heights missing from `start`.
    pub async fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
        self.blocks().await.missing_items(start, max)
    }

    /// The gap surrounding `height` in the finalized blocks.
    pub async fn next_gap(&self, height: Height) -> (Option<Height>, Option<Height>) {
        self.blocks().await.next_gap(height)
    }
}

/// Read side of the lock, held by the serving task.
struct Reader<C, B>(Arc<TracedAsyncRwLock<Option<(C, B)>>>);

impl<C, B> Reader<C, B> {
    /// Read guard over both stores.
    async fn read(&self) -> AsyncRwLockReadGuard<'_, (C, B)> {
        AsyncRwLockReadGuard::map(self.0.read().await, |slot| slot.as_ref().expect(POISONED))
    }
}

/// Outcome counters for backfill requests. Every forwarded request lands in exactly one.
struct Metered {
    served: Counter,
    missing: Counter,
    failed: Counter,
    abandoned: Counter,
}

/// Wrap the stores and spawn the backfill serving task. `capacity` bounds the serving queue.
///
/// The serving task exits when the returned [Stores] drops; a panic in it is re-raised by the
/// runtime, so its handle need not be held.
pub(super) fn new<E, V, C, B>(
    context: E,
    finalizations: C,
    blocks: B,
    capacity: NonZeroUsize,
) -> Stores<C, B>
where
    E: Spawner + Metrics,
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    let (serving_tx, serving_rx) = mpsc::channel(capacity.get());
    let stores = Stores {
        inner: Arc::new(TracedAsyncRwLock::new(
            "marshal.finalized",
            Some((finalizations, blocks)),
        )),
        serving: serving_tx,
        forwarded: context.counter("forwarded", "Backfill requests handed to the serving task"),
        refused: context.counter(
            "refused",
            "Backfill requests refused because the queue was full",
        ),
    };
    let metrics = Metered {
        served: context.counter("served", "Backfill requests answered"),
        missing: context.counter(
            "missing",
            "Backfill requests for a height either store lacks",
        ),
        failed: context.counter("failed", "Backfill requests dropped by a failed store read"),
        abandoned: context.counter(
            "abandoned",
            "Backfill requests whose requester left before the response",
        ),
    };
    let reader = Reader(stores.inner.clone());
    context.spawn(move |_| run::<V, _, _>(reader, serving_rx, metrics));
    stores
}

/// Answer peer requests until marshal drops its [Stores].
async fn run<V, C, B>(reader: Reader<C, B>, mut requests: mpsc::Receiver<Serve>, metrics: Metered)
where
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    while let Some(request) = requests.recv().await {
        serve::<V, _, _>(&reader, request, &metrics).await;
    }
}

/// Answer one peer request. A miss or a read failure drops the response, which the requester sees
/// as a retryable error.
#[tracing::instrument(name = "marshal.finalized.serve", level = "debug", parent = &request.span, skip_all, fields(height = %request.height))]
async fn serve<V, C, B>(reader: &Reader<C, B>, request: Serve, metrics: &Metered)
where
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    let Serve {
        height, respond, ..
    } = request;

    // The requester may have moved on while this queued.
    if respond.is_closed() {
        metrics.abandoned.inc();
        return;
    }

    // One guard across both reads, so no mutation lands between them.
    let (finalization, block) = {
        let guard = reader.read().await;
        let (finalizations, blocks) = &*guard;
        futures::join!(
            finalizations.get(ArchiveID::Index(height.get())),
            blocks.get(ArchiveID::Index(height.get())),
        )
    };

    let finalization = match finalization {
        Ok(Some(finalization)) => finalization,
        Ok(None) => {
            metrics.missing.inc();
            debug!(%height, "finalization missing on serve");
            return;
        }
        Err(err) => {
            metrics.failed.inc();
            warn!(%height, ?err, "failed to read finalization");
            return;
        }
    };
    let block = match block {
        Ok(Some(block)) => block.into(),
        Ok(None) => {
            metrics.missing.inc();
            debug!(%height, "finalized block missing on serve");
            return;
        }
        Err(err) => {
            metrics.failed.inc();
            warn!(%height, ?err, "failed to read finalized block");
            return;
        }
    };

    if respond.send_lossy((finalization, V::into_inner(block)).encode()) {
        metrics.served.inc();
    } else {
        metrics.abandoned.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner, deterministic, telemetry::metrics::has_metric_value};

    /// Stores whose serving queue holds `capacity`, with the receiver so the test controls
    /// when (or whether) the serving side drains. The archives are never touched, so their
    /// type does not matter and the slot stays empty.
    fn stores(
        context: &deterministic::Context,
        capacity: usize,
    ) -> (Stores<(), ()>, mpsc::Receiver<Serve>) {
        let (serving, receiver) = mpsc::channel(capacity);
        let stores = Stores {
            inner: Arc::new(TracedAsyncRwLock::new("test", None)),
            serving,
            forwarded: context.counter("forwarded", "forwarded"),
            refused: context.counter("refused", "refused"),
        };
        (stores, receiver)
    }

    #[test_traced("ERROR")]
    fn test_saturated_serving_queue_sheds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (stores, _receiver) = stores(&context, 1);

            // The first request fits the queue; the second has nowhere to go, and the peer
            // sees a closed response rather than a hang.
            let (accepted, accepted_rx) = oneshot::channel();
            stores.serve(Height::new(1), accepted);
            let (refused, refused_rx) = oneshot::channel();
            stores.serve(Height::new(2), refused);
            assert!(refused_rx.await.is_err());
            drop(accepted_rx);

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "forwarded_total", 1));
            assert!(has_metric_value(&encoded, "refused_total", 1));
        });
    }

    #[test_traced("ERROR")]
    fn test_serving_drops_when_the_task_is_gone() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (stores, receiver) = stores(&context, 1);

            // Losing the receiver stands in for the serving task exiting. Every later request
            // is refused, which must be counted rather than passing silently.
            drop(receiver);
            let (response, response_rx) = oneshot::channel();
            stores.serve(Height::new(1), response);
            assert!(response_rx.await.is_err());

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "forwarded_total", 0));
            assert!(has_metric_value(&encoded, "refused_total", 1));
        });
    }
}
