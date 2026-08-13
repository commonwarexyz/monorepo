//! Serving finalized backfill requests off the marshal actor's critical path.
//!
//! When both finalized stores expose readers (see
//! [Certificates::reader](crate::marshal::store::Certificates::reader)), the actor forwards
//! `Key::Finalized` produce requests to a dedicated task, so serving disk reads never block
//! consensus processing. They still share the executor and the disk with everything else.
//!
//! A request this task cannot answer is dropped, not answered: the channel closes, the peer sees a
//! resolver error, and it retries. That covers a height either store has not published, a request
//! arriving while the task is saturated, and a failed store read.
//!
//! Publishing follows the flush, not the fsync, so a height still awaiting its fsync is already
//! readable and never misses. Retrying helps a height that is merely not published yet. A pruned
//! height, or one gap repair stored without its own certificate, is gone for good and the peer must
//! ask elsewhere -- as with the inline path.
//!
//! Publishing before the fsync means a served block is one a crash could lose. That is fine here:
//! the block is finalized and the peer verifies its certificate, so the peer's copy stays valid
//! whatever happens to our disk.

use super::Variant;
use crate::{marshal::store::Reader, simplex::types::Finalization, types::Height};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{
    Metrics, Spawner,
    telemetry::{
        metrics::{Counter, MetricsExt as _},
        traces::TracedExt as _,
    },
};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    futures::Pool,
};
use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicBool, Ordering},
};
use tracing::{debug, warn};

#[derive(Clone)]
struct ServeMetrics {
    /// Produce requests answered.
    served: Counter,
    /// Produce requests for a height either store lacks.
    missing: Counter,
    /// Produce requests dropped by a failed store read.
    failed: Counter,
}

/// Encode a `Key::Finalized` response.
pub(super) fn finalized_response<V: Variant, S: Scheme>(
    finalization: Finalization<S, V::Commitment>,
    block: V::Block,
) -> Bytes {
    (finalization, V::into_inner(block)).encode()
}

/// Forwards produce requests to the serving task.
pub(super) struct Mailbox {
    sender: mpsc::Sender<(Height, oneshot::Sender<Bytes>)>,
    /// Requests forwarded to the serving task.
    forwarded: Counter,
    /// Requests dropped because the serving task was saturated (the peer retries).
    dropped: Counter,
    /// Set once the missing task has been logged, so a permanent failure warns once per node
    /// rather than once per request.
    warned_gone: AtomicBool,
}

impl Mailbox {
    /// Forward a `Key::Finalized` produce request, dropping it when the serving task cannot take
    /// it.
    pub fn forward(&self, height: Height, response: oneshot::Sender<Bytes>) {
        match self.sender.try_send((height, response)) {
            Ok(()) => {
                self.forwarded.inc();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.inc();
            }
            // A closed channel means the task is gone.
            // Warn on the first one: the rest add nothing, and `dropped` keeps counting.
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.dropped.inc();
                if !self.warned_gone.swap(true, Ordering::Relaxed) {
                    warn!("serving task is gone, dropping all finalized backfill");
                }
            }
        }
    }
}

/// Spawn a serving task over the given readers. At most `concurrency` requests are
/// served at once and at most `concurrency` more may queue.
///
/// The task exits when the returned [Mailbox] is dropped.
pub(super) fn spawn<E, V, S>(
    context: E,
    finalizations: Reader<Finalization<S, V::Commitment>>,
    blocks: Reader<V::StoredBlock>,
    concurrency: NonZeroUsize,
) -> Mailbox
where
    E: Spawner + Metrics,
    V: Variant,
    S: Scheme,
{
    let (sender, receiver) = mpsc::channel(concurrency.get());
    let mailbox = Mailbox {
        sender,
        forwarded: context.counter(
            "forwarded",
            "Produce requests forwarded to the serving task",
        ),
        dropped: context.counter(
            "dropped",
            "Produce requests the serving task could not accept",
        ),
        warned_gone: AtomicBool::new(false),
    };
    let metrics = ServeMetrics {
        served: context.counter("served", "Produce requests answered"),
        missing: context.counter(
            "missing",
            "Produce requests for a height either store lacks",
        ),
        failed: context.counter("failed", "Produce requests dropped by a failed store read"),
    };
    context.spawn(move |_| run::<V, S>(receiver, finalizations, blocks, concurrency, metrics));
    mailbox
}

/// Serve forwarded requests until the mailbox closes, at most `concurrency` at a time.
async fn run<V, S>(
    mut receiver: mpsc::Receiver<(Height, oneshot::Sender<Bytes>)>,
    finalizations: Reader<Finalization<S, V::Commitment>>,
    blocks: Reader<V::StoredBlock>,
    concurrency: NonZeroUsize,
    metrics: ServeMetrics,
) where
    V: Variant,
    S: Scheme,
{
    let mut inflight = Pool::default();
    loop {
        // Wait for capacity before taking the next request.
        while inflight.len() >= concurrency.get() {
            inflight.next_completed().await;
        }
        select! {
            request = receiver.recv() => {
                let Some((height, response)) = request else {
                    break;
                };
                inflight.push(serve::<V, S>(
                    finalizations.clone(),
                    blocks.clone(),
                    height,
                    response,
                    metrics.clone(),
                ));
            },
            _ = inflight.next_completed() => {},
        }
    }
    while !inflight.is_empty() {
        inflight.next_completed().await;
    }
}

/// Answer one `Key::Finalized` request. Any miss or failure drops the response, which the
/// requester sees as a retryable error.
///
/// Unlike the actor's inline path, a store read failure is survivable here, so it is logged and
/// counted. That keeps persistent corruption visible as `failed` instead of hiding in `missing`.
#[tracing::instrument(name = "marshal.serving.finalized", level = "debug", skip_all, fields(height = height.traced()))]
async fn serve<V, S>(
    finalizations: Reader<Finalization<S, V::Commitment>>,
    blocks: Reader<V::StoredBlock>,
    height: Height,
    response: oneshot::Sender<Bytes>,
    metrics: ServeMetrics,
) where
    V: Variant,
    S: Scheme,
{
    // The requester may have moved on while this request queued.
    if response.is_closed() {
        return;
    }
    let finalization = match finalizations.get(height).await {
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
    // The requester may have disconnected during the certificate read.
    if response.is_closed() {
        return;
    }
    let block = match blocks.get(height).await {
        Ok(Some(stored)) => stored.into(),
        Ok(None) => {
            metrics.missing.inc();
            debug!(%height, "finalized block missing on serve");
            return;
        }
        Err(err) => {
            metrics.failed.inc();
            warn!(%height, ?err, "failed to read block");
            return;
        }
    };
    if response.send_lossy(finalized_response::<V, _>(finalization, block)) {
        metrics.served.inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{Runner, deterministic, telemetry::metrics::has_metric_value};
    use commonware_utils::NZUsize;

    /// A mailbox over a channel of `capacity`, with its receiver so the test controls closure.
    #[allow(clippy::type_complexity)]
    fn mailbox(
        context: &deterministic::Context,
        capacity: usize,
    ) -> (Mailbox, mpsc::Receiver<(Height, oneshot::Sender<Bytes>)>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let mailbox = Mailbox {
            sender,
            forwarded: context.counter("forwarded", "forwarded"),
            dropped: context.counter("dropped", "dropped"),
            warned_gone: AtomicBool::new(false),
        };
        (mailbox, receiver)
    }

    #[test_traced("ERROR")]
    fn test_forward_drops_when_saturated() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mailbox, _receiver) = mailbox(&context, NZUsize!(1).get());

            // The first request fits the channel; the second has nowhere to go, and the peer sees
            // a closed response rather than a hang.
            let (accepted, accepted_rx) = oneshot::channel();
            mailbox.forward(Height::new(1), accepted);
            let (refused, refused_rx) = oneshot::channel();
            mailbox.forward(Height::new(2), refused);
            assert!(refused_rx.await.is_err());
            drop(accepted_rx);

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "forwarded_total", 1));
            assert!(has_metric_value(&encoded, "dropped_total", 1));
        });
    }

    #[test_traced("ERROR")]
    fn test_forward_drops_when_the_serving_task_is_gone() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mailbox, receiver) = mailbox(&context, NZUsize!(1).get());

            // Losing the receiver stands in for the task exiting. Every later request is dropped,
            // which must be counted rather than passing silently.
            drop(receiver);
            let (response, response_rx) = oneshot::channel();
            mailbox.forward(Height::new(1), response);
            assert!(response_rx.await.is_err());

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "forwarded_total", 0));
            assert!(has_metric_value(&encoded, "dropped_total", 1));
        });
    }
}
