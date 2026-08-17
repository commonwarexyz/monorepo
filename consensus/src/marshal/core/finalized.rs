//! Finalized block and certificate storage, shared behind one lock.
//!
//! Answering a peer's backfill request means reading the archives. Doing that on the actor's
//! loop stalls consensus behind a peer that is querying old data. Instead, marshal mutates and
//! reads the storage through [Storage], while a backfill task answers peer requests through the
//! reader: a height's finalized block and certificate, or a finalized block by commitment.
//!
//! The submission channel is bounded. A request that overflows is dropped. Peers can retry.

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
    Handle, Metrics as RuntimeMetrics, Spawner,
    telemetry::{
        metrics::{Counter, MetricsExt as _},
        traces::TracedExt as _,
    },
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

/// A peer's request for finalized data.
struct Request<Cm> {
    /// Span of the forwarding call.
    span: Span,
    /// What the peer asked for.
    kind: Kind<Cm>,
    /// Where the encoded response is sent.
    response_tx: oneshot::Sender<Bytes>,
}

/// The request shapes peers use to fetch finalized data.
enum Kind<Cm> {
    /// The finalized block at a height, paired with its certificate.
    Finalized(Height),
    /// The finalized block with a commitment.
    Block(Cm),
}

/// The certificate and block stores behind one lock.
pub(super) struct Storage<C, B, Cm> {
    // The underlying block and certificate stores.
    inner: Arc<TracedAsyncRwLock<Option<(C, B)>>>,
    /// Requests to the backfill task.
    submission_tx: mpsc::Sender<Request<Cm>>,
    /// Requests dropped because the submission channel was full.
    dropped: Counter,
}

impl<C, B, Cm> Storage<C, B, Cm> {
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

    /// Run a consuming mutation over both stores.
    ///
    /// Mutation failures are fatal.
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

    /// Enqueue `kind` to the backfill task. If the submission channel is full, the
    /// request is dropped and the requester sees a closed `response_tx`.
    fn submit(&self, kind: Kind<Cm>, response_tx: oneshot::Sender<Bytes>) {
        let request = Request {
            span: Span::current(),
            kind,
            response_tx,
        };
        if self.submission_tx.try_send(request).is_err() {
            self.dropped.inc();
        }
    }

    /// Enqueue a request for the finalized block at `height` and its certificate, which
    /// will be sent to `response_tx`. If the submission channel is full, the request is dropped.
    pub fn serve(&self, height: Height, response_tx: oneshot::Sender<Bytes>) {
        self.submit(Kind::Finalized(height), response_tx)
    }

    /// Enqueue a request for the finalized block with `commitment`, which will be sent
    /// to `response_tx`. If the submission channel is full, the request is dropped.
    pub fn serve_block(&self, commitment: Cm, response_tx: oneshot::Sender<Bytes>) {
        self.submit(Kind::Block(commitment), response_tx)
    }
}

impl<C: Certificates, B: Blocks, Cm> Storage<C, B, Cm> {
    /// Store a finalized block and, when consensus supplied one, its certificate.
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

    /// Durably persist both stores, blocking until durable.
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

    /// Begin flushing both stores, returning per-store handles (certificates, blocks)
    /// that complete when durable.
    pub async fn start_sync(&self) -> (Handle<()>, Handle<()>) {
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
            (finalizations, blocks, (finalizations_handle, blocks_handle))
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

    /// The finalized block with `digest`.
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

/// Reader over the stores, held by the backfill task.
struct Reader<C, B>(Arc<TracedAsyncRwLock<Option<(C, B)>>>);

impl<C, B> Reader<C, B> {
    /// Read guard over the stores.
    async fn read(&self) -> AsyncRwLockReadGuard<'_, (C, B)> {
        AsyncRwLockReadGuard::map(self.0.read().await, |slot| slot.as_ref().expect(POISONED))
    }
}

/// Counters for submitted requests. Every submitted request lands in exactly one.
struct Metrics {
    served: Counter,
    missing: Counter,
    failed: Counter,
    abandoned: Counter,
}

/// Wrap the stores and spawn the backfill task. `capacity` bounds the submission channel.
///
/// The task exits when the returned [Storage] drops.
pub(super) fn new<E, V, C, B>(
    context: E,
    finalizations: C,
    blocks: B,
    capacity: NonZeroUsize,
) -> Storage<C, B, V::Commitment>
where
    E: Spawner + RuntimeMetrics,
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    let (submission_tx, submission_rx) = mpsc::channel(capacity.get());
    let storage = Storage {
        inner: Arc::new(TracedAsyncRwLock::new(
            "marshal.finalized",
            Some((finalizations, blocks)),
        )),
        submission_tx,
        dropped: context.counter(
            "dropped",
            "Backfill requests dropped because the submission channel was full",
        ),
    };
    let metrics = Metrics {
        served: context.counter("served", "Backfill requests answered"),
        missing: context.counter("missing", "Backfill requests for data that is not stored"),
        failed: context.counter("failed", "Backfill requests whose store read failed"),
        abandoned: context.counter(
            "abandoned",
            "Backfill requests whose requester left before the response",
        ),
    };
    let reader = Reader(storage.inner.clone());
    context.spawn(move |_| run::<V, _, _>(reader, submission_rx, metrics));
    storage
}

/// Serve backfill requests until every sender of `submission_rx` is dropped.
async fn run<V, C, B>(
    reader: Reader<C, B>,
    mut submission_rx: mpsc::Receiver<Request<V::Commitment>>,
    metrics: Metrics,
) where
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    while let Some(request) = submission_rx.recv().await {
        let Request {
            span,
            kind,
            response_tx,
        } = request;
        if response_tx.is_closed() {
            metrics.abandoned.inc();
            continue;
        }
        match kind {
            Kind::Finalized(height) => {
                serve::<V, _, _>(&reader, span, height, response_tx, &metrics).await
            }
            Kind::Block(commitment) => {
                serve_block::<V, _, _>(&reader, span, commitment, response_tx, &metrics).await
            }
        }
    }
}

/// Serve one height-keyed request. A miss or a read failure drops the response, which the
/// requester sees as a retryable error.
#[tracing::instrument(name = "marshal.finalized.serve", level = "debug", parent = &span, skip_all, fields(height = height.traced()))]
async fn serve<V, C, B>(
    reader: &Reader<C, B>,
    span: Span,
    height: Height,
    response_tx: oneshot::Sender<Bytes>,
    metrics: &Metrics,
) where
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    // One guard across both reads so no mutation lands between them.
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

    if response_tx.send_lossy((finalization, V::into_inner(block)).encode()) {
        metrics.served.inc();
    } else {
        metrics.abandoned.inc();
    }
}

/// Serve one commitment-keyed request. A miss, a commitment mismatch, or a read failure drops
/// the response, which the requester sees as a retryable error.
#[tracing::instrument(name = "marshal.finalized.serve_block", level = "debug", parent = &span, skip_all, fields(commitment = %commitment))]
async fn serve_block<V, C, B>(
    reader: &Reader<C, B>,
    span: Span,
    commitment: V::Commitment,
    response_tx: oneshot::Sender<Bytes>,
    metrics: &Metrics,
) where
    V: Variant,
    C: Certificates<BlockDigest = <V::Block as Digestible>::Digest, Commitment = V::Commitment>,
    B: Blocks<Block = V::StoredBlock>,
{
    let digest = V::commitment_to_inner(commitment);
    let block = {
        let guard = reader.read().await;
        let (_, blocks) = &*guard;
        blocks.get(ArchiveID::Key(&digest)).await
    };

    let block = match block {
        Ok(Some(block)) => block,
        Ok(None) => {
            metrics.missing.inc();
            debug!(%commitment, "block missing on serve");
            return;
        }
        Err(err) => {
            metrics.failed.inc();
            warn!(%commitment, ?err, "failed to read block by commitment");
            return;
        }
    };

    // The archive is keyed by digest; confirm the full commitment matches.
    if V::stored_commitment(&block) != commitment {
        metrics.missing.inc();
        debug!(%commitment, "commitment mismatch on serve");
        return;
    }

    let block: V::Block = block.into();
    if response_tx.send_lossy(block.encode()) {
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

    /// Storage with a submission channel of `capacity`. The archives are never touched,
    /// so the slot stays empty and the receiver is handed back to the test.
    fn storage(
        context: &deterministic::Context,
        capacity: usize,
    ) -> (Storage<(), (), ()>, mpsc::Receiver<Request<()>>) {
        let (submission_tx, submission_rx) = mpsc::channel(capacity);
        let storage = Storage {
            inner: Arc::new(TracedAsyncRwLock::new("test", None)),
            submission_tx,
            dropped: context.counter("dropped", "dropped"),
        };
        (storage, submission_rx)
    }

    #[test_traced("ERROR")]
    fn test_drops_when_channel_full() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (storage, _submission_rx) = storage(&context, 1);

            // The channel holds one: the first request is accepted, the second is
            // dropped and the peer sees a closed channel rather than a hang.
            let (accepted, accepted_rx) = oneshot::channel();
            storage.serve(Height::new(1), accepted);
            let (dropped, dropped_rx) = oneshot::channel();
            storage.serve_block((), dropped);
            assert!(dropped_rx.await.is_err());
            drop(accepted_rx);

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "dropped_total", 1));
        });
    }

    #[test_traced("ERROR")]
    fn test_drops_when_task_gone() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (storage, submission_rx) = storage(&context, 1);

            // Dropping the receiver stands in for the backfill task exiting:
            // requests are dropped and counted, not lost silently.
            drop(submission_rx);
            let (response_tx, response_rx) = oneshot::channel();
            storage.serve(Height::new(1), response_tx);
            assert!(response_rx.await.is_err());

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "dropped_total", 1));
        });
    }
}
