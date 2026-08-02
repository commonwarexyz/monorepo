//! Durable, dense application-delivery actor.
//!
//! Delivery prefers bodies handed off after checkpoint publication, but treats memory only as an
//! optimization and falls back to exact catalog reads. Multiple `Exact` acknowledgements remain in
//! flight so contiguous application progress can share one durable cursor synchronization.

use super::{
    catalog::{self, CatalogClient},
    metrics, promoter,
};
use crate::{
    Reporter,
    multimmit::{
        marshal::types::{OutputIndex, Update},
        types::TransactionBlock,
    },
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_codec::{Codec, EncodeSize as _};
use commonware_cryptography::{Digestible, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_runtime::{Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact, channel::oneshot};
use futures::{FutureExt as _, future::BoxFuture};
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};
use tracing::{Instrument as _, debug_span, info_span};

/// Application delivery stopped before its durable cursor could advance.
#[derive(Debug, thiserror::Error)]
pub(in crate::multimmit::marshal) enum Error {
    /// The application no longer accepts updates.
    #[error("application reporter is closed")]
    ReporterClosed,
    /// An application dropped an acknowledgement without resolving it.
    #[error("application acknowledgement was canceled")]
    AcknowledgementCanceled,
    /// A committed output was not retained for delivery.
    #[error("committed output {0} is missing")]
    Missing(OutputIndex),
    /// The dense output coordinate cannot advance.
    #[error("output index exhausted")]
    IndexExhausted,
    /// Catalog access failed.
    #[error(transparent)]
    Catalog(#[from] catalog::Error),
}

/// One body retained across a successful checkpoint-last publication.
pub(in crate::multimmit::marshal) struct DurableOutput<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub index: OutputIndex,
    pub block: Arc<TransactionBlock<H, B>>,
    pub encoded_len: u64,
}

/// Bodies that became deliverable with one durable catalog checkpoint.
///
/// The batch is an optimization, not durable state. Delivery falls back to the catalog whenever a
/// batch is dropped under pressure or lost across restart.
pub(in crate::multimmit::marshal) struct DurableBatch<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub generation: u64,
    pub committed: OutputIndex,
    pub outputs: Vec<DurableOutput<H, B>>,
    remaining_hot_bytes: u64,
}

impl<H, B> DurableBatch<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) fn new(
        generation: u64,
        committed: OutputIndex,
        outputs: Vec<DurableOutput<H, B>>,
        hot_bytes: u64,
        max_hot_bytes: u64,
    ) -> Self {
        debug_assert_eq!(
            hot_bytes,
            outputs.iter().map(|output| output.encoded_len).sum::<u64>()
        );
        debug_assert!(hot_bytes <= max_hot_bytes);
        Self {
            generation,
            committed,
            outputs,
            remaining_hot_bytes: max_hot_bytes
                .checked_sub(hot_bytes)
                .expect("hot delivery batch fits its byte bound"),
        }
    }

    fn coalesce(&mut self, next: Self) {
        debug_assert_eq!(self.generation, next.generation);
        self.committed = self.committed.max(next.committed);
        for output in next.outputs {
            if self
                .outputs
                .last()
                .is_some_and(|retained| output.index <= retained.index)
            {
                continue;
            }
            if output.encoded_len > self.remaining_hot_bytes {
                continue;
            }
            self.remaining_hot_bytes -= output.encoded_len;
            self.outputs.push(output);
        }
    }
}

/// Notification path from durable publication to ordered delivery.
///
/// Complete batches keep the normal path memory-only. Under mailbox pressure, pending batches
/// coalesce into a byte-bounded set of hot outputs and the newest committed cursor. Delivery
/// materializes omitted outputs from durable custody.
pub(in crate::multimmit::marshal) struct DeliveryClient<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    commands: mailbox::Sender<Command<H, B>>,
}

impl<H, B> Clone for DeliveryClient<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
        }
    }
}

enum Command<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Committed(DurableBatch<H, B>),
    Reset(Vec<oneshot::Sender<()>>),
}

/// Receipt resolved after delivery has applied a generation reset.
pub(in crate::multimmit::marshal) struct ResetWaiter(oneshot::Receiver<()>);

impl ResetWaiter {
    pub(in crate::multimmit::marshal) async fn wait(self) -> bool {
        self.0.await.is_ok()
    }
}

/// Receiving half of the delivery notification channel.
pub(in crate::multimmit::marshal) struct DeliveryReceiver<H, B>(mailbox::Receiver<Command<H, B>>)
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>;

#[cfg(test)]
impl<H, B> DeliveryReceiver<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) async fn next_batch(&mut self) -> DurableBatch<H, B> {
        while let Some(command) = self.0.recv().await {
            if let Command::Committed(batch) = command {
                return batch;
            }
        }
        panic!("delivery mailbox closed before commit");
    }

    pub(in crate::multimmit::marshal) async fn next_reset(&mut self) -> Vec<oneshot::Sender<()>> {
        while let Some(command) = self.0.recv().await {
            if let Command::Reset(waiters) = command {
                return waiters;
            }
        }
        panic!("delivery mailbox closed before reset");
    }
}

impl<H, B> Policy for Command<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) {
        match command {
            Self::Committed(batch) => {
                let after_reset = overflow
                    .iter()
                    .rposition(|command| matches!(command, Self::Reset(_)))
                    .map_or(0, |index| index + 1);
                if let Some(Self::Committed(pending)) = overflow
                    .range_mut(after_reset..)
                    .find(|command| matches!(command, Self::Committed(_)))
                {
                    pending.coalesce(batch);
                } else {
                    overflow.push_back(Self::Committed(batch));
                }
            }
            Self::Reset(mut waiters) => {
                for command in overflow.drain(..) {
                    if let Self::Reset(older) = command {
                        waiters.extend(older);
                    }
                }
                overflow.push_back(Self::Reset(waiters));
            }
        }
    }
}

impl<H, B> DeliveryClient<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    /// Offers newly durable bodies to the bounded in-memory delivery path.
    pub(in crate::multimmit::marshal) fn committed(&self, batch: DurableBatch<H, B>) -> Feedback {
        self.commands.enqueue(Command::Committed(batch))
    }

    /// Enqueues an ordered notification to clear superseded updates after a durable floor install.
    pub(in crate::multimmit::marshal) fn reset(&self) -> Option<ResetWaiter> {
        let (acknowledgement, waiter) = oneshot::channel();
        (self.commands.enqueue(Command::Reset(vec![acknowledgement])) != Feedback::Closed)
            .then_some(ResetWaiter(waiter))
    }
}

/// Allocates the notification channel before the catalog takes ownership of its sender.
pub(in crate::multimmit::marshal) fn channel<H, B>(
    metrics: impl RuntimeMetrics,
) -> (DeliveryClient<H, B>, DeliveryReceiver<H, B>)
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let (commands, receiver) = mailbox::new(metrics, NonZeroUsize::MIN);
    (DeliveryClient { commands }, DeliveryReceiver(receiver))
}

/// A byte-bounded cache of bodies whose publication is already durable.
struct HotDelivery<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    outputs: VecDeque<DurableOutput<H, B>>,
    bytes: u64,
    max_bytes: u64,
}

impl<H, B> HotDelivery<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn new(max_bytes: NonZeroUsize) -> Self {
        Self {
            outputs: VecDeque::new(),
            bytes: 0,
            max_bytes: u64::try_from(max_bytes.get()).unwrap_or(u64::MAX),
        }
    }

    fn insert(&mut self, batch: DurableBatch<H, B>, next: OutputIndex) {
        for output in batch.outputs {
            if output.index < next
                || self
                    .outputs
                    .back()
                    .is_some_and(|retained| output.index <= retained.index)
            {
                continue;
            }
            self.bytes = self.bytes.saturating_add(output.encoded_len);
            self.outputs.push_back(output);
        }
        while self.bytes > self.max_bytes {
            let output = self
                .outputs
                .pop_back()
                .expect("a hot output exists while over its byte bound");
            self.bytes = self.bytes.saturating_sub(output.encoded_len);
        }
    }

    fn take(&mut self, index: OutputIndex) -> Option<DurableOutput<H, B>> {
        while self
            .outputs
            .front()
            .is_some_and(|output| output.index < index)
        {
            let output = self
                .outputs
                .pop_front()
                .expect("a stale hot output is available");
            self.bytes = self.bytes.saturating_sub(output.encoded_len);
        }
        if self.outputs.front()?.index != index {
            return None;
        }
        let output = self
            .outputs
            .pop_front()
            .expect("the requested hot output is available");
        self.bytes = self.bytes.saturating_sub(output.encoded_len);
        Some(output)
    }

    fn clear(&mut self) {
        self.outputs.clear();
        self.bytes = 0;
    }
}

fn next_index(acknowledged: Option<OutputIndex>) -> Result<OutputIndex, Error> {
    acknowledged.map_or(Ok(OutputIndex::ZERO), |index| {
        index.next().ok_or(Error::IndexExhausted)
    })
}

fn is_committed(next: OutputIndex, committed: Option<OutputIndex>) -> bool {
    committed.is_some_and(|committed| next <= committed)
}

struct PendingAck {
    index: OutputIndex,
    waiter: commonware_utils::acknowledgement::ExactWaiter,
}

struct SyncingAcks {
    through: OutputIndex,
    completion: BoxFuture<'static, Result<(), catalog::Error>>,
}

/// Bounded delivery window whose durable retirement is always a contiguous FIFO prefix.
struct PendingAcks {
    queue: VecDeque<PendingAck>,
    syncing: Option<SyncingAcks>,
    max: usize,
}

impl PendingAcks {
    const fn new(max: NonZeroUsize) -> Self {
        Self {
            queue: VecDeque::new(),
            syncing: None,
            max: max.get(),
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.syncing.is_none()
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.syncing = None;
    }

    fn has_capacity(&self) -> bool {
        self.queue.len() < self.max
    }

    fn remaining(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.max - self.queue.len()).expect("delivery window has capacity")
    }

    fn next(&self, acknowledged: Option<OutputIndex>) -> Result<Option<OutputIndex>, Error> {
        self.queue.back().map_or_else(
            || {
                self.syncing.as_ref().map_or_else(
                    || next_index(acknowledged).map(Some),
                    |syncing| Ok(syncing.through.next()),
                )
            },
            |pending| Ok(pending.index.next()),
        )
    }

    fn push(&mut self, index: OutputIndex, waiter: commonware_utils::acknowledgement::ExactWaiter) {
        debug_assert!(self.has_capacity());
        self.queue.push_back(PendingAck { index, waiter });
    }

    fn current(&mut self) -> &mut commonware_utils::acknowledgement::ExactWaiter {
        debug_assert!(self.syncing.is_none());
        &mut self
            .queue
            .front_mut()
            .expect("a pending acknowledgement exists")
            .waiter
    }

    fn complete(
        &mut self,
        result: Result<(), commonware_utils::acknowledgement::Canceled>,
    ) -> Result<OutputIndex, Error> {
        result.map_err(|_| Error::AcknowledgementCanceled)?;
        let mut through = self
            .queue
            .pop_front()
            .expect("the completed acknowledgement is pending")
            .index;
        while let Some(result) = self
            .queue
            .front_mut()
            .and_then(|pending| (&mut pending.waiter).now_or_never())
        {
            result.map_err(|_| Error::AcknowledgementCanceled)?;
            through = self
                .queue
                .pop_front()
                .expect("the ready acknowledgement is pending")
                .index;
        }
        Ok(through)
    }

    fn start_sync(
        &mut self,
        through: OutputIndex,
        completion: BoxFuture<'static, Result<(), catalog::Error>>,
    ) {
        debug_assert!(self.syncing.is_none());
        self.syncing = Some(SyncingAcks {
            through,
            completion,
        });
    }

    const fn is_syncing(&self) -> bool {
        self.syncing.is_some()
    }

    fn sync(&mut self) -> &mut BoxFuture<'static, Result<(), catalog::Error>> {
        &mut self
            .syncing
            .as_mut()
            .expect("an acknowledgement sync is active")
            .completion
    }

    fn complete_sync(&mut self, result: Result<(), catalog::Error>) -> Result<OutputIndex, Error> {
        result?;
        Ok(self
            .syncing
            .take()
            .expect("the completed acknowledgement sync is active")
            .through)
    }
}

async fn run<H, V, B, A>(
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    mut application: A,
    commands: DeliveryReceiver<H, B>,
    metrics: metrics::Delivery,
    bounds: Bounds,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
{
    let DeliveryReceiver(mut commands) = commands;
    let mut pending = PendingAcks::new(bounds.pending_acks);
    let mut hot = HotDelivery::new(bounds.hot_block_bytes);
    let mut progress = catalog.progress().await?;
    loop {
        if let Some(mut next) = pending.next(progress.acknowledged)? {
            'fill: while pending.has_capacity() && is_committed(next, progress.committed) {
                if let Some(output) = hot.take(next)
                    && u64::try_from(output.block.encode_size()).ok() == Some(output.encoded_len)
                {
                    metrics.hot_outputs.inc();
                    report(&mut application, &mut pending, &metrics, next, output.block)?;
                    let Some(following) = next.next() else {
                        break 'fill;
                    };
                    next = following;
                    continue;
                }
                let refs = catalog
                    .output_refs(next, pending.remaining(), bounds.delivery_bytes)
                    .await?;
                if refs.is_empty() {
                    return Err(Error::Missing(next));
                }
                let materialize = info_span!(
                    "multimmit.marshal.delivery.materialize",
                    start = next.get(),
                    outputs = refs.len(),
                );
                let outputs = bodies
                    .materialize(&refs)
                    .instrument(materialize)
                    .await
                    .map_err(|error| Error::Catalog(catalog::Error::storage(error)))?;
                metrics
                    .stored_outputs
                    .inc_by(u64::try_from(outputs.len()).unwrap_or(u64::MAX));
                for (output, block) in refs.into_iter().zip(outputs) {
                    if output.index != next || block.reference() != output.reference {
                        return Err(Error::Missing(next));
                    }
                    let _ = hot.take(next);
                    report(&mut application, &mut pending, &metrics, next, block)?;
                    let Some(following) = next.next() else {
                        break 'fill;
                    };
                    next = following;
                }
            }
        }

        if pending.is_empty() {
            let Some(command) = commands.recv().await else {
                return Ok(());
            };
            handle_command(
                &catalog,
                command,
                &mut pending,
                &mut hot,
                &metrics,
                &mut progress,
            )
            .await?;
            continue;
        }

        if pending.is_syncing() {
            select! {
                result = pending.sync() => {
                    let through = pending.complete_sync(result)?;
                    progress.acknowledged = progress.acknowledged.max(Some(through));
                    metrics.in_flight(pending.queue.len());
                },
                command = commands.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    handle_command(
                        &catalog,
                        command,
                        &mut pending,
                        &mut hot,
                        &metrics,
                        &mut progress,
                    )
                    .await?;
                },
            }
        } else {
            select! {
                result = pending.current() => {
                    let through = pending.complete(result)?;
                    let catalog = catalog.clone();
                    let span = info_span!(
                        "multimmit.marshal.delivery.acknowledge",
                        through = through.get(),
                    );
                    pending.start_sync(
                        through,
                        async move { catalog.acknowledge_through(through).await }
                            .instrument(span)
                            .boxed(),
                    );
                },
                command = commands.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    handle_command(
                        &catalog,
                        command,
                        &mut pending,
                        &mut hot,
                        &metrics,
                        &mut progress,
                    )
                    .await?;
                },
            }
        }
    }
}

fn report<H, B, A>(
    application: &mut A,
    pending: &mut PendingAcks,
    metrics: &metrics::Delivery,
    index: OutputIndex,
    block: Arc<TransactionBlock<H, B>>,
) -> Result<(), Error>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
{
    let span = debug_span!(
        "multimmit.marshal.delivery.report",
        index = index.get(),
        chain = block.header().chain().get(),
        height = block.header().height().get(),
    );
    let _guard = span.enter();
    let (acknowledgement, waiter) = Exact::handle();
    metrics.attempts.inc();
    if application.report(Update::Block {
        index,
        block,
        acknowledgement,
    }) == Feedback::Closed
    {
        return Err(Error::ReporterClosed);
    }
    pending.push(index, waiter);
    metrics.in_flight(pending.queue.len());
    Ok(())
}

async fn handle_command<H, V, B>(
    catalog: &CatalogClient<H, V, B>,
    command: Command<H, B>,
    pending: &mut PendingAcks,
    hot: &mut HotDelivery<H, B>,
    metrics: &metrics::Delivery,
    progress: &mut catalog::Progress<H::Digest>,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    let mut refresh = false;
    let mut reset = None;
    match command {
        Command::Committed(batch) => {
            if batch.generation == progress.generation {
                progress.committed = progress.committed.max(Some(batch.committed));
                if let Some(next) = pending.next(progress.acknowledged)? {
                    hot.insert(batch, next);
                }
            } else {
                refresh = true;
            }
        }
        Command::Reset(waiters) => {
            pending.clear();
            hot.clear();
            metrics.in_flight(0);
            refresh = true;
            reset = Some(waiters);
        }
    }
    if refresh {
        let next = catalog.progress().await?;
        if next.generation != progress.generation {
            pending.clear();
            hot.clear();
            metrics.in_flight(0);
        }
        *progress = next;
    }
    if let Some(waiters) = reset {
        for acknowledgement in waiters {
            let _ = acknowledgement.send(());
        }
    }
    Ok(())
}

/// Resource bounds enforced by the delivery actor.
pub(in crate::multimmit::marshal) struct Bounds {
    pub pending_acks: NonZeroUsize,
    pub delivery_bytes: NonZeroUsize,
    pub hot_block_bytes: NonZeroUsize,
}

/// Starts the single-owner application delivery actor.
pub(in crate::multimmit::marshal) fn spawn<R, H, V, B, A>(
    context: R,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    application: A,
    commands: DeliveryReceiver<H, B>,
    bounds: Bounds,
) -> Handle<Result<(), Error>>
where
    R: Spawner + RuntimeMetrics,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
{
    let metrics = metrics::Delivery::new(&context);
    context
        .shared(false)
        .spawn(move |_| run(catalog, bodies, application, commands, metrics, bounds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::mocks::block::EmptyBlock,
        multimmit::types::{ChainId, TransactionBlockHeader},
        types::{Epoch, Height},
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{Runner as _, deterministic};

    type TestBody = EmptyBlock<Sha256>;

    fn output(index: u64) -> DurableOutput<Sha256, TestBody> {
        let body = TestBody::new(
            Sha256::hash(&[b"body parent", &index.to_be_bytes()]),
            Height::new(index.saturating_add(1)),
            index,
        );
        let header = TransactionBlockHeader::new(
            Epoch::new(7),
            ChainId::new(0),
            Height::new(index.saturating_add(1)),
            Sha256::hash(&[b"block parent", &index.to_be_bytes()]),
            body.digest(),
        )
        .unwrap();
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        DurableOutput {
            index: OutputIndex::new(index),
            encoded_len: u64::try_from(block.encode_size()).unwrap(),
            block,
        }
    }

    fn durable_batch(
        generation: u64,
        committed: u64,
        outputs: Vec<DurableOutput<Sha256, TestBody>>,
        max_hot_bytes: u64,
    ) -> DurableBatch<Sha256, TestBody> {
        let hot_bytes = outputs.iter().map(|output| output.encoded_len).sum();
        DurableBatch::new(
            generation,
            OutputIndex::new(committed),
            outputs,
            hot_bytes,
            max_hot_bytes,
        )
    }

    #[test]
    fn restart_cursor_is_exactly_after_durable_acknowledgement() {
        assert_eq!(next_index(None).unwrap(), OutputIndex::ZERO);
        assert_eq!(
            next_index(Some(OutputIndex::new(41))).unwrap(),
            OutputIndex::new(42)
        );
        assert!(matches!(
            next_index(Some(OutputIndex::new(u64::MAX))),
            Err(Error::IndexExhausted)
        ));
    }

    #[test]
    fn committed_high_water_controls_dense_delivery() {
        let next = OutputIndex::new(4);
        assert!(!is_committed(next, None));
        assert!(!is_committed(next, Some(OutputIndex::new(3))));
        assert!(is_committed(next, Some(next)));
        assert!(is_committed(next, Some(OutputIndex::new(5))));
    }

    #[test]
    fn overflow_coalesces_body_handoff_without_losing_committed_progress() {
        deterministic::Runner::default().start(|context| async move {
            let (client, DeliveryReceiver(mut receiver)) = channel::<Sha256, TestBody>(context);
            let max_hot_bytes = output(1).encoded_len + output(2).encoded_len;
            let batch = |index| durable_batch(0, index, vec![output(index)], max_hot_bytes);

            assert_eq!(client.committed(batch(0)), Feedback::Ok);
            assert_eq!(client.committed(batch(1)), Feedback::Backoff);
            assert_eq!(client.committed(batch(2)), Feedback::Backoff);
            assert_eq!(client.committed(batch(3)), Feedback::Backoff);
            assert!(matches!(receiver.recv().await, Some(Command::Committed(_))));
            let Some(Command::Committed(batch)) = receiver.recv().await else {
                panic!("overflow did not retain the hot delivery handoff");
            };
            assert_eq!(batch.committed, OutputIndex::new(3));
            assert_eq!(
                batch
                    .outputs
                    .iter()
                    .map(|output| output.index)
                    .collect::<Vec<_>>(),
                vec![OutputIndex::new(1), OutputIndex::new(2)]
            );
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn newest_reset_supersedes_older_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let (client, DeliveryReceiver(mut receiver)) = channel(context);
            let batch = |index| durable_batch(0, index, vec![output(index)], u64::MAX);

            assert_eq!(client.committed(batch(0)), Feedback::Ok);
            let first = client.reset().unwrap();
            assert_eq!(client.committed(batch(1)), Feedback::Backoff);
            let second = client.reset().unwrap();
            assert_eq!(client.committed(batch(2)), Feedback::Backoff);
            assert!(matches!(receiver.recv().await, Some(Command::Committed(_))));
            let Some(Command::Reset(waiters)) = receiver.recv().await else {
                panic!("newest reset was not retained");
            };
            assert_eq!(waiters.len(), 2);
            for waiter in waiters {
                let _ = waiter.send(());
            }
            assert!(first.wait().await);
            assert!(second.wait().await);
            let Some(Command::Committed(batch)) = receiver.recv().await else {
                panic!("post-reset publication was not retained");
            };
            assert_eq!(batch.committed, OutputIndex::new(2));
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn hot_delivery_retains_the_earliest_byte_bounded_prefix() {
        let first = output(0);
        let second = output(1);
        let third = output(2);
        let max = usize::try_from(first.encoded_len + second.encoded_len).unwrap();
        let mut hot = HotDelivery::new(NonZeroUsize::new(max).unwrap());
        hot.insert(
            durable_batch(4, 2, vec![first, second, third], u64::MAX),
            OutputIndex::ZERO,
        );

        assert!(hot.take(OutputIndex::ZERO).is_some());
        assert!(hot.take(OutputIndex::new(1)).is_some());
        assert!(hot.take(OutputIndex::new(2)).is_none());
        hot.insert(
            durable_batch(3, 3, vec![output(3)], u64::MAX),
            OutputIndex::new(4),
        );
        assert!(hot.take(OutputIndex::new(3)).is_none());

        let mut hot = HotDelivery::new(NonZeroUsize::MIN);
        hot.insert(
            durable_batch(4, 0, vec![output(0)], u64::MAX),
            OutputIndex::ZERO,
        );
        assert!(hot.take(OutputIndex::ZERO).is_none());
    }

    #[test]
    fn pending_acknowledgements_are_bounded_and_retire_fifo() {
        let mut pending = PendingAcks::new(NonZeroUsize::new(2).unwrap());
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::ZERO));

        let (first, first_waiter) = Exact::handle();
        pending.push(OutputIndex::ZERO, first_waiter);
        let (second, second_waiter) = Exact::handle();
        pending.push(OutputIndex::new(1), second_waiter);
        assert!(!pending.has_capacity());
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(2)));

        second.acknowledge();
        assert!(pending.current().now_or_never().is_none());
        first.acknowledge();
        let result = pending.current().now_or_never().unwrap();
        let through = pending.complete(result).unwrap();
        assert_eq!(through, OutputIndex::new(1));
        assert!(pending.is_empty());

        let (last, last_waiter) = Exact::handle();
        pending.push(OutputIndex::new(u64::MAX), last_waiter);
        assert_eq!(pending.next(None).unwrap(), None);
        last.acknowledge();
        let result = pending.current().now_or_never().unwrap();
        assert_eq!(
            pending.complete(result).unwrap(),
            OutputIndex::new(u64::MAX)
        );
    }

    #[test]
    fn canceled_acknowledgement_stops_fifo_retirement() {
        let mut pending = PendingAcks::new(NonZeroUsize::MIN);
        let (acknowledgement, waiter) = Exact::handle();
        pending.push(OutputIndex::ZERO, waiter);
        drop(acknowledgement);

        let result = pending.current().now_or_never().unwrap();
        assert!(matches!(
            pending.complete(result),
            Err(Error::AcknowledgementCanceled)
        ));
    }

    #[test]
    fn syncing_acknowledgements_release_delivery_capacity() {
        let mut pending = PendingAcks::new(NonZeroUsize::new(2).unwrap());
        let (first, first_waiter) = Exact::handle();
        pending.push(OutputIndex::ZERO, first_waiter);
        let (second, second_waiter) = Exact::handle();
        pending.push(OutputIndex::new(1), second_waiter);
        first.acknowledge();
        second.acknowledge();

        let result = pending.current().now_or_never().unwrap();
        let through = pending.complete(result).unwrap();
        pending.start_sync(through, futures::future::pending().boxed());
        assert!(pending.has_capacity());
        assert_eq!(pending.queue.len(), 0);
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(2)));

        let (_third, third_waiter) = Exact::handle();
        pending.push(OutputIndex::new(2), third_waiter);
        let (_fourth, fourth_waiter) = Exact::handle();
        pending.push(OutputIndex::new(3), fourth_waiter);
        assert!(!pending.has_capacity());
        assert_eq!(pending.queue.len(), 2);
        assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(4)));

        pending.complete_sync(Ok(())).unwrap();
        assert!(!pending.has_capacity());
        assert!(!pending.is_empty());
    }
}
