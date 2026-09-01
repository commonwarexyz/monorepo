//! Durable, dense application-delivery actor.
//!
//! Delivery prefers bodies handed off after checkpoint publication, but treats memory only as an
//! optimization and falls back to exact catalog reads. Application-ready acknowledgement prefixes
//! coalesce while one durable cursor synchronization is active, keeping storage latency out of the
//! bounded application window.

use super::{
    catalog::{self, CatalogClient},
    metrics, promoter,
};
use crate::{
    Reporter,
    multimmit::{
        marshal::{
            storage::{delivery::Store as DeliveryStore, state::StoredRef},
            types::{OutputIndex, Update},
        },
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
use commonware_runtime::{Clock, Handle, Metrics as RuntimeMetrics, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact, channel::oneshot};
use futures::{FutureExt as _, future::BoxFuture};
use std::{collections::VecDeque, mem::size_of, num::NonZeroUsize, sync::Arc};
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
    /// Durable delivery-cursor storage failed.
    #[error(transparent)]
    Storage(#[from] crate::multimmit::marshal::storage::delivery::Error),
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

/// One compact committed output retained with an optional hot body.
pub(in crate::multimmit::marshal) struct DeliveryOutput<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub stored: StoredRef<H::Digest>,
    pub block: Option<Arc<TransactionBlock<H, B>>>,
}

impl<H, B> DeliveryOutput<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    fn retained_bytes(&self) -> u64 {
        self.block
            .as_ref()
            .map_or_else(descriptor_bytes::<H::Digest>, |_| {
                body_bytes::<H::Digest>(self.stored.encoded_len)
            })
    }
}

pub(in crate::multimmit::marshal) fn descriptor_bytes<D>() -> u64
where
    D: commonware_cryptography::Digest,
{
    u64::try_from(size_of::<StoredRef<D>>()).unwrap_or(u64::MAX)
}

pub(in crate::multimmit::marshal) fn body_bytes<D>(encoded_len: u64) -> u64
where
    D: commonware_cryptography::Digest,
{
    encoded_len.max(descriptor_bytes::<D>())
}

/// Outputs that became deliverable with one durable catalog checkpoint.
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
    pub outputs: Vec<DeliveryOutput<H, B>>,
    remaining_bytes: u64,
}

impl<H, B> DurableBatch<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(in crate::multimmit::marshal) fn new(
        generation: u64,
        committed: OutputIndex,
        outputs: Vec<DeliveryOutput<H, B>>,
        retained_bytes: u64,
        max_bytes: u64,
    ) -> Self {
        debug_assert_eq!(
            retained_bytes,
            outputs
                .iter()
                .map(DeliveryOutput::retained_bytes)
                .sum::<u64>()
        );
        debug_assert!(retained_bytes <= max_bytes);
        Self {
            generation,
            committed,
            outputs,
            remaining_bytes: max_bytes
                .checked_sub(retained_bytes)
                .expect("delivery batch fits its byte bound"),
        }
    }

    fn coalesce(&mut self, next: Self) {
        debug_assert_eq!(self.generation, next.generation);
        self.committed = self.committed.max(next.committed);
        for output in next.outputs {
            if self
                .outputs
                .last()
                .is_some_and(|retained| output.stored.index <= retained.stored.index)
            {
                continue;
            }
            let retained_bytes = output.retained_bytes();
            if retained_bytes > self.remaining_bytes {
                continue;
            }
            self.remaining_bytes -= retained_bytes;
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
    Reset {
        generation: u64,
        acknowledged: Option<OutputIndex>,
        waiters: Vec<oneshot::Sender<()>>,
    },
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

    pub(in crate::multimmit::marshal) async fn next_reset(
        &mut self,
    ) -> (u64, Option<OutputIndex>, Vec<oneshot::Sender<()>>) {
        while let Some(command) = self.0.recv().await {
            if let Command::Reset {
                generation,
                acknowledged,
                waiters,
            } = command
            {
                return (generation, acknowledged, waiters);
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
                    .rposition(|command| matches!(command, Self::Reset { .. }))
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
            Self::Reset {
                generation,
                acknowledged,
                mut waiters,
            } => {
                for command in overflow.drain(..) {
                    if let Self::Reset { waiters: older, .. } = command {
                        waiters.extend(older);
                    }
                }
                overflow.push_back(Self::Reset {
                    generation,
                    acknowledged,
                    waiters,
                });
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
    pub(in crate::multimmit::marshal) fn reset(
        &self,
        generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Option<ResetWaiter> {
        let (acknowledgement, waiter) = oneshot::channel();
        (self.commands.enqueue(Command::Reset {
            generation,
            acknowledged,
            waiters: vec![acknowledgement],
        }) != Feedback::Closed)
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

/// A byte-bounded cache of compact output descriptors and optional hot bodies.
struct DeliveryCache<H, B>
where
    H: Hasher,
    B: Codec + Digestible<Digest = H::Digest>,
{
    outputs: VecDeque<DeliveryOutput<H, B>>,
    bytes: u64,
    max_bytes: u64,
}

impl<H, B> DeliveryCache<H, B>
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
            if output.stored.index < next
                || self
                    .outputs
                    .back()
                    .is_some_and(|retained| output.stored.index <= retained.stored.index)
            {
                continue;
            }
            self.bytes = self.bytes.saturating_add(output.retained_bytes());
            self.outputs.push_back(output);
        }
        while self.bytes > self.max_bytes {
            let output = self
                .outputs
                .pop_back()
                .expect("a delivery output exists while over its byte bound");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        }
    }

    fn discard_before(&mut self, index: OutputIndex) {
        while self
            .outputs
            .front()
            .is_some_and(|output| output.stored.index < index)
        {
            let output = self
                .outputs
                .pop_front()
                .expect("a stale delivery output is available");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        }
    }

    fn take_hot(&mut self, index: OutputIndex) -> Option<(Arc<TransactionBlock<H, B>>, u64)> {
        self.discard_before(index);
        let output = self.outputs.front()?;
        if output.stored.index != index || output.block.is_none() {
            return None;
        }
        let output = self
            .outputs
            .pop_front()
            .expect("the requested delivery output is available");
        self.bytes = self.bytes.saturating_sub(output.retained_bytes());
        Some((
            output.block.expect("the requested hot body is available"),
            output.stored.encoded_len,
        ))
    }

    fn take_refs(
        &mut self,
        index: OutputIndex,
        max_items: NonZeroUsize,
        max_bytes: NonZeroUsize,
    ) -> Vec<StoredRef<H::Digest>> {
        self.discard_before(index);
        let mut next = index;
        let mut encoded_bytes = 0u64;
        let max_bytes = u64::try_from(max_bytes.get()).unwrap_or(u64::MAX);
        let mut refs = Vec::new();
        while refs.len() < max_items.get() {
            let Some(output) = self.outputs.front() else {
                break;
            };
            if output.stored.index != next || output.block.is_some() {
                break;
            }
            if !refs.is_empty()
                && encoded_bytes
                    .checked_add(output.stored.encoded_len)
                    .is_none_or(|total| total > max_bytes)
            {
                break;
            }
            let output = self
                .outputs
                .pop_front()
                .expect("the requested delivery descriptor is available");
            self.bytes = self.bytes.saturating_sub(output.retained_bytes());
            encoded_bytes = encoded_bytes.saturating_add(output.stored.encoded_len);
            refs.push(output.stored);
            let Some(following) = next.next() else {
                break;
            };
            next = following;
        }
        refs
    }

    fn cold_prefix(&self, index: OutputIndex, max: NonZeroUsize) -> NonZeroUsize {
        let Some(output) = self.outputs.front() else {
            return max;
        };
        debug_assert!(output.stored.index > index);
        let distance = output.stored.index.get().saturating_sub(index.get());
        let distance = usize::try_from(distance).unwrap_or(usize::MAX);
        NonZeroUsize::new(max.get().min(distance)).expect("the next hot output follows the cursor")
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

/// One contiguous application-ready prefix awaiting its next cursor synchronization.
struct ReadyAcks {
    through: OutputIndex,
    outputs: usize,
    completion_timer: commonware_runtime::telemetry::metrics::histogram::Timer,
}

struct SyncingAcks {
    through: OutputIndex,
    outputs: usize,
    durability_timer: commonware_runtime::telemetry::metrics::histogram::Timer,
    completion_timer: commonware_runtime::telemetry::metrics::histogram::Timer,
    completion: BoxFuture<'static, Result<(), Error>>,
}

/// Unresolved application work plus constant-space ready and durable FIFO prefixes.
struct PendingAcks {
    queue: VecDeque<PendingAck>,
    ready: Option<ReadyAcks>,
    syncing: Option<SyncingAcks>,
    max: usize,
}

impl PendingAcks {
    const fn new(max: NonZeroUsize) -> Self {
        Self {
            queue: VecDeque::new(),
            ready: None,
            syncing: None,
            max: max.get(),
        }
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.ready.is_none() && self.syncing.is_none()
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.ready = None;
        self.syncing = None;
    }

    fn has_capacity(&self) -> bool {
        self.queue.len() < self.max
    }

    fn remaining(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.max - self.queue.len()).expect("delivery window has capacity")
    }

    fn next(&self, acknowledged: Option<OutputIndex>) -> Result<Option<OutputIndex>, Error> {
        if let Some(pending) = self.queue.back() {
            return Ok(pending.index.next());
        }
        if let Some(ready) = &self.ready {
            return Ok(ready.through.next());
        }
        self.syncing.as_ref().map_or_else(
            || next_index(acknowledged).map(Some),
            |syncing| Ok(syncing.through.next()),
        )
    }

    fn push(&mut self, index: OutputIndex, waiter: commonware_utils::acknowledgement::ExactWaiter) {
        debug_assert!(self.has_capacity());
        self.queue.push_back(PendingAck { index, waiter });
    }

    #[cfg(test)]
    fn current(&mut self) -> &mut commonware_utils::acknowledgement::ExactWaiter {
        &mut self
            .queue
            .front_mut()
            .expect("a pending acknowledgement exists")
            .waiter
    }

    fn complete(
        &mut self,
        result: Result<(), commonware_utils::acknowledgement::Canceled>,
    ) -> Result<(OutputIndex, usize), Error> {
        result.map_err(|_| Error::AcknowledgementCanceled)?;
        let mut outputs = 1usize;
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
            outputs = outputs.saturating_add(1);
            through = self
                .queue
                .pop_front()
                .expect("the ready acknowledgement is pending")
                .index;
        }
        Ok((through, outputs))
    }

    fn coalesce_ready<F>(&mut self, through: OutputIndex, outputs: usize, completion_timer: F)
    where
        F: FnOnce() -> commonware_runtime::telemetry::metrics::histogram::Timer,
    {
        debug_assert_ne!(outputs, 0);
        if let Some(ready) = &mut self.ready {
            let first = through
                .get()
                .checked_sub(u64::try_from(outputs - 1).unwrap_or(u64::MAX))
                .map(OutputIndex::new);
            debug_assert_eq!(ready.through.next(), first);
            ready.through = through;
            ready.outputs = ready.outputs.saturating_add(outputs);
        } else {
            self.ready = Some(ReadyAcks {
                through,
                outputs,
                completion_timer: completion_timer(),
            });
        }
    }

    fn start_sync(
        &mut self,
        ready: ReadyAcks,
        durability_timer: commonware_runtime::telemetry::metrics::histogram::Timer,
        completion: BoxFuture<'static, Result<(), Error>>,
    ) {
        debug_assert!(self.syncing.is_none());
        self.syncing = Some(SyncingAcks {
            through: ready.through,
            outputs: ready.outputs,
            durability_timer,
            completion_timer: ready.completion_timer,
            completion,
        });
    }

    fn take_ready(&mut self) -> Option<ReadyAcks> {
        debug_assert!(self.syncing.is_none());
        self.ready.take()
    }

    const fn is_syncing(&self) -> bool {
        self.syncing.is_some()
    }

    fn try_current(&mut self) -> Option<Result<(), commonware_utils::acknowledgement::Canceled>> {
        self.queue
            .front_mut()
            .and_then(|pending| (&mut pending.waiter).now_or_never())
    }

    async fn next_event(&mut self) -> AcknowledgementEvent {
        let current = self.queue.front_mut().map(|pending| &mut pending.waiter);
        let syncing = self.syncing.as_mut().map(|syncing| &mut syncing.completion);
        match (current, syncing) {
            // A ready cursor sync must retire even when application acknowledgements are
            // continuously ready, so durable progress does not depend on an idle delivery window.
            (Some(current), Some(syncing)) => select! {
                result = syncing => AcknowledgementEvent::Durable(result),
                result = current => AcknowledgementEvent::Ready(result),
            },
            (Some(current), None) => AcknowledgementEvent::Ready(current.await),
            (None, Some(syncing)) => AcknowledgementEvent::Durable(syncing.await),
            (None, None) => unreachable!("a pending acknowledgement event exists"),
        }
    }

    fn complete_sync(&mut self, result: Result<(), Error>) -> Result<SyncingAcks, Error> {
        result?;
        Ok(self
            .syncing
            .take()
            .expect("the completed acknowledgement sync is active"))
    }

    fn pending_durability(&self) -> usize {
        self.syncing
            .as_ref()
            .map_or(0, |syncing| syncing.outputs)
            .saturating_add(self.ready.as_ref().map_or(0, |ready| ready.outputs))
    }
}

enum AcknowledgementEvent {
    Ready(Result<(), commonware_utils::acknowledgement::Canceled>),
    Durable(Result<(), Error>),
}

#[allow(clippy::too_many_arguments)]
async fn run<R, H, V, B, A>(
    clock: R,
    mut store: DeliveryStore<R>,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    mut application: A,
    commands: DeliveryReceiver<H, B>,
    metrics: metrics::Delivery,
    bounds: Bounds,
) -> Result<(), Error>
where
    R: Clock + StorageContext,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
{
    let DeliveryReceiver(mut commands) = commands;
    let mut pending = PendingAcks::new(bounds.pending_acks);
    let mut cache = DeliveryCache::new(bounds.hot_block_bytes);
    let mut progress = catalog.progress().await?;
    if store.generation() != progress.generation || store.acknowledged() != progress.acknowledged {
        return Err(Error::Catalog(catalog::Error::Invalid(
            "delivery cursor does not match catalog progress",
        )));
    }
    metrics.progress(progress.acknowledged);
    'delivery: loop {
        if let Some(mut next) = pending.next(progress.acknowledged)? {
            'fill: while pending.has_capacity() && is_committed(next, progress.committed) {
                if let Some((block, encoded_len)) = cache.take_hot(next)
                    && u64::try_from(block.encode_size()).ok() == Some(encoded_len)
                {
                    metrics.hot_outputs.inc();
                    report(&mut application, &mut pending, &metrics, next, block)?;
                    let Some(following) = next.next() else {
                        break 'fill;
                    };
                    next = following;
                    continue;
                }
                let mut refs = cache.take_refs(next, pending.remaining(), bounds.delivery_bytes);
                let max_items = cache.cold_prefix(next, pending.remaining());
                let generation = progress.generation;
                let outputs = {
                    let fetch = async {
                        if refs.is_empty() {
                            refs = catalog
                                .output_refs(next, max_items, bounds.delivery_bytes)
                                .await?;
                        }
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
                        Ok::<_, Error>(outputs)
                    };
                    let mut fetch = std::pin::pin!(fetch);
                    // Reset notifications supersede both descriptor lookup and body reads. Apply a
                    // queued reset before interpreting a result from the superseded generation.
                    loop {
                        select! {
                            command = commands.recv() => {
                                let Some(command) = command else { return Ok(()); };
                                let reset = matches!(command, Command::Reset { .. });
                                handle_command(&catalog, &mut store, command, &mut pending,
                                    &mut cache, &metrics, &mut progress).await?;
                                if reset || progress.generation != generation {
                                    continue 'delivery;
                                }
                            },
                            outputs = &mut fetch => break outputs?,
                        }
                    }
                };
                metrics
                    .stored_outputs
                    .inc_by(u64::try_from(outputs.len()).unwrap_or(u64::MAX));
                for (output, block) in refs.into_iter().zip(outputs) {
                    if output.index != next || block.reference() != output.reference {
                        return Err(Error::Missing(next));
                    }
                    report(&mut application, &mut pending, &metrics, next, block)?;
                    let Some(following) = next.next() else {
                        break 'fill;
                    };
                    next = following;
                }
            }
        }

        if !pending.is_syncing()
            && let Some(ready) = pending.take_ready()
        {
            let span = info_span!(
                "multimmit.marshal.delivery.acknowledge",
                through = ready.through.get(),
            );
            metrics.acknowledgement_starts.inc();
            let sync = store
                .start_acknowledgement(progress.generation, ready.through)
                .instrument(span.clone())
                .await?;
            let durability_timer = metrics.acknowledgement_durability.timer(&clock);
            pending.start_sync(
                ready,
                durability_timer,
                async move {
                    sync.await
                        .map_err(|error| Error::Catalog(catalog::Error::storage(error)))
                }
                .instrument(span)
                .boxed(),
            );
            metrics.pending_durability(pending.pending_durability());
        }

        if pending.is_empty() {
            let Some(command) = commands.recv().await else {
                return Ok(());
            };
            handle_command(
                &catalog,
                &mut store,
                command,
                &mut pending,
                &mut cache,
                &metrics,
                &mut progress,
            )
            .await?;
            continue;
        }

        select! {
            event = pending.next_event() => {
                match event {
                    AcknowledgementEvent::Ready(result) => {
                        let (through, outputs) = pending.complete(result)?;
                        pending.coalesce_ready(through, outputs, || {
                            metrics.acknowledgement_completion.timer(&clock)
                        });
                    }
                    AcknowledgementEvent::Durable(result) => {
                        let syncing = pending.complete_sync(result)?;
                        syncing.durability_timer.observe(&clock);
                        syncing.completion_timer.observe(&clock);
                        progress.acknowledged = Some(syncing.through);
                        metrics.acknowledgements.inc_by(
                            u64::try_from(syncing.outputs).unwrap_or(u64::MAX),
                        );
                        metrics.progress(progress.acknowledged);
                        if catalog.delivery_cursor(progress.generation, progress.acknowledged)
                            == Feedback::Closed
                        {
                            return Err(Error::Catalog(catalog::Error::Closed));
                        }
                        while let Some(result) = pending.try_current() {
                            let (through, outputs) = pending.complete(result)?;
                            pending.coalesce_ready(through, outputs, || {
                                metrics.acknowledgement_completion.timer(&clock)
                            });
                        }
                    }
                }
                metrics.in_flight(pending.queue.len());
                metrics.pending_durability(pending.pending_durability());
                if let Ok(command) = commands.try_recv() {
                    handle_command(
                        &catalog,
                        &mut store,
                        command,
                        &mut pending,
                        &mut cache,
                        &metrics,
                        &mut progress,
                    )
                    .await?;
                }
            },
            command = commands.recv() => {
                let Some(command) = command else {
                    return Ok(());
                };
                handle_command(
                    &catalog,
                    &mut store,
                    command,
                    &mut pending,
                    &mut cache,
                    &metrics,
                    &mut progress,
                )
                .await?;
            },
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

async fn handle_command<R, H, V, B>(
    catalog: &CatalogClient<H, V, B>,
    store: &mut DeliveryStore<R>,
    command: Command<H, B>,
    pending: &mut PendingAcks,
    cache: &mut DeliveryCache<H, B>,
    metrics: &metrics::Delivery,
    progress: &mut catalog::Progress<H::Digest>,
) -> Result<(), Error>
where
    R: StorageContext,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    match command {
        Command::Committed(batch) => {
            if batch.generation == progress.generation {
                progress.committed = progress.committed.max(Some(batch.committed));
                if let Some(next) = pending.next(progress.acknowledged)? {
                    cache.insert(batch, next);
                }
            } else {
                drop(batch);
                let next = catalog.progress().await?;
                if next.generation != progress.generation {
                    pending.clear();
                    cache.clear();
                    metrics.in_flight(0);
                    metrics.pending_durability(0);
                }
                *progress = next;
            }
        }
        Command::Reset {
            generation,
            acknowledged,
            waiters,
        } => {
            pending.clear();
            cache.clear();
            metrics.in_flight(0);
            metrics.pending_durability(0);
            store.reset(generation, acknowledged).await?;
            metrics.progress(acknowledged);
            catalog
                .reset_delivery_cursor(generation, acknowledged)
                .await?;
            let next = catalog.progress().await?;
            if next.generation != generation || next.acknowledged != acknowledged {
                return Err(Error::Catalog(catalog::Error::Invalid(
                    "catalog did not apply the durable delivery cursor reset",
                )));
            }
            *progress = next;
            for acknowledgement in waiters {
                let _ = acknowledgement.send(());
            }
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
    store: DeliveryStore<R>,
    catalog: CatalogClient<H, V, B>,
    bodies: promoter::Bodies<H, V, B>,
    application: A,
    commands: DeliveryReceiver<H, B>,
    bounds: Bounds,
) -> Handle<Result<(), Error>>
where
    R: Clock + Spawner + RuntimeMetrics + StorageContext,
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>, Exact>>,
{
    let metrics = metrics::Delivery::new(&context);
    let clock = context.child("clock");
    context.shared(false).spawn(move |_| {
        run(
            clock,
            store,
            catalog,
            bodies,
            application,
            commands,
            metrics,
            bounds,
        )
    })
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
        max_bytes: u64,
    ) -> DurableBatch<Sha256, TestBody> {
        let outputs = outputs
            .into_iter()
            .map(|output| DeliveryOutput {
                stored: StoredRef {
                    index: output.index,
                    reference: output.block.reference(),
                    encoded_len: output.encoded_len,
                    generation,
                },
                block: Some(output.block),
            })
            .collect::<Vec<_>>();
        let retained_bytes = outputs.iter().map(DeliveryOutput::retained_bytes).sum();
        DurableBatch::new(
            generation,
            OutputIndex::new(committed),
            outputs,
            retained_bytes,
            max_bytes,
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
            let max_bytes = output(1).encoded_len + output(2).encoded_len;
            let batch = |index| durable_batch(0, index, vec![output(index)], max_bytes);

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
                    .map(|output| output.stored.index)
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
            let first = client.reset(1, None).unwrap();
            assert_eq!(client.committed(batch(1)), Feedback::Backoff);
            let second = client.reset(2, Some(OutputIndex::ZERO)).unwrap();
            assert_eq!(client.committed(batch(2)), Feedback::Backoff);
            assert!(matches!(receiver.recv().await, Some(Command::Committed(_))));
            let Some(Command::Reset {
                generation,
                acknowledged,
                waiters,
            }) = receiver.recv().await
            else {
                panic!("newest reset was not retained");
            };
            assert_eq!(generation, 2);
            assert_eq!(acknowledged, Some(OutputIndex::ZERO));
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
    fn delivery_cache_retains_the_earliest_byte_bounded_prefix() {
        let first = output(0);
        let second = output(1);
        let third = output(2);
        let max = usize::try_from(first.encoded_len + second.encoded_len).unwrap();
        let mut cache = DeliveryCache::new(NonZeroUsize::new(max).unwrap());
        cache.insert(
            durable_batch(4, 2, vec![first, second, third], u64::MAX),
            OutputIndex::ZERO,
        );

        assert!(cache.take_hot(OutputIndex::ZERO).is_some());
        assert!(cache.take_hot(OutputIndex::new(1)).is_some());
        assert!(cache.take_hot(OutputIndex::new(2)).is_none());
        cache.insert(
            durable_batch(3, 3, vec![output(3)], u64::MAX),
            OutputIndex::new(4),
        );
        assert!(cache.take_hot(OutputIndex::new(3)).is_none());

        let mut cache = DeliveryCache::new(NonZeroUsize::MIN);
        cache.insert(
            durable_batch(4, 0, vec![output(0)], u64::MAX),
            OutputIndex::ZERO,
        );
        assert!(cache.take_hot(OutputIndex::ZERO).is_none());
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
        let (through, outputs) = pending.complete(result).unwrap();
        assert_eq!(through, OutputIndex::new(1));
        assert_eq!(outputs, 2);
        assert!(pending.is_empty());

        let (last, last_waiter) = Exact::handle();
        pending.push(OutputIndex::new(u64::MAX), last_waiter);
        assert_eq!(pending.next(None).unwrap(), None);
        last.acknowledge();
        let result = pending.current().now_or_never().unwrap();
        assert_eq!(
            pending.complete(result).unwrap(),
            (OutputIndex::new(u64::MAX), 1)
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
    fn completed_cursor_sync_precedes_ready_application_acknowledgements() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = metrics::Delivery::new(&context);
            let mut pending = PendingAcks::new(NonZeroUsize::MIN);
            let (first, waiter) = Exact::handle();
            pending.push(OutputIndex::ZERO, waiter);
            first.acknowledge();
            let result = pending.current().now_or_never().unwrap();
            let (through, outputs) = pending.complete(result).unwrap();
            pending.coalesce_ready(through, outputs, || {
                metrics.acknowledgement_completion.timer(&context)
            });
            let ready = pending.take_ready().unwrap();
            pending.start_sync(
                ready,
                metrics.acknowledgement_durability.timer(&context),
                futures::future::ready(Ok(())).boxed(),
            );

            let (next, waiter) = Exact::handle();
            pending.push(OutputIndex::new(1), waiter);
            next.acknowledge();
            assert!(matches!(
                pending.next_event().await,
                AcknowledgementEvent::Durable(Ok(()))
            ));
            assert_eq!(
                pending.complete_sync(Ok(())).unwrap().through,
                OutputIndex::ZERO
            );
            assert_eq!(pending.queue.len(), 1);
        });
    }

    #[test]
    fn ready_acknowledgements_release_capacity_during_cursor_sync() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = metrics::Delivery::new(&context);
            let mut pending = PendingAcks::new(NonZeroUsize::new(2).unwrap());
            let (first, first_waiter) = Exact::handle();
            pending.push(OutputIndex::ZERO, first_waiter);
            let (second, second_waiter) = Exact::handle();
            pending.push(OutputIndex::new(1), second_waiter);
            first.acknowledge();
            second.acknowledge();

            let result = pending.current().now_or_never().unwrap();
            let (through, outputs) = pending.complete(result).unwrap();
            pending.coalesce_ready(through, outputs, || {
                metrics.acknowledgement_completion.timer(&context)
            });
            let ready = pending.take_ready().unwrap();
            pending.start_sync(
                ready,
                metrics.acknowledgement_durability.timer(&context),
                futures::future::pending().boxed(),
            );
            assert_eq!(pending.pending_durability(), 2);
            assert!(pending.has_capacity());
            assert_eq!(pending.queue.len(), 0);
            assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(2)));

            let (third, third_waiter) = Exact::handle();
            pending.push(OutputIndex::new(2), third_waiter);
            let (fourth, fourth_waiter) = Exact::handle();
            pending.push(OutputIndex::new(3), fourth_waiter);
            assert!(!pending.has_capacity());
            assert_eq!(pending.queue.len(), 2);
            assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(4)));

            third.acknowledge();
            fourth.acknowledge();
            let AcknowledgementEvent::Ready(result) = pending.next_event().await else {
                panic!("pending durability prevented ready acknowledgement processing");
            };
            let (through, outputs) = pending.complete(result).unwrap();
            pending.coalesce_ready(through, outputs, || {
                metrics.acknowledgement_completion.timer(&context)
            });
            assert!(pending.has_capacity());
            assert_eq!(pending.queue.len(), 0);
            assert_eq!(pending.pending_durability(), 4);
            assert_eq!(pending.next(None).unwrap(), Some(OutputIndex::new(4)));

            pending.complete_sync(Ok(())).unwrap();
            assert!(pending.has_capacity());
            assert!(!pending.is_empty());
            assert_eq!(pending.pending_durability(), 2);
        });
    }
}
