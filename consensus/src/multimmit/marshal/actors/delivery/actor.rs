//! The delivery task.

use super::{
    acks::{AcknowledgementEvent, PendingAcks},
    cache::DeliveryCache,
    cursor::DeliveryCursor,
    mailbox::{Message, Receiver},
    metrics::Metrics,
};
use crate::{
    Reporter,
    multimmit::{
        actors::util::gated,
        marshal::{
            MarshalProgress,
            actors::catalog,
            bodies::{self, Bodies},
            storage::{Error as StorageError, catalog::StoredRef},
            types::{OutputIndex, Update},
        },
        types::{Body, TransactionBlock},
    },
};
use commonware_actor::Feedback;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, spawn_cell,
};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement as _, acknowledgement::Exact, channel::fallible::OneshotExt as _,
};
use futures::{FutureExt as _, future::BoxFuture};
use std::{future::pending, num::NonZeroUsize, sync::Arc};
use tracing::{Instrument as _, debug_span, info_span};

/// Delivery stopped before its durable cursor could advance.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
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
    /// Committed bodies could not be read for delivery.
    #[error("delivery body read failed: {0}")]
    Bodies(#[from] bodies::Error),
    /// Durable delivery-cursor storage failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Delivery and catalog disagree on durable progress.
    #[error("delivery invariant violated: {0}")]
    Invariant(&'static str),
}

/// Resource bounds of the delivery task.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounds {
    /// Most reported outputs awaiting an application acknowledgement.
    pub(crate) pending_acks: NonZeroUsize,
    /// Target encoded bytes of one cold read (one larger body is read alone).
    pub(crate) delivery_bytes: NonZeroUsize,
    /// Hot-byte bound of the cache of committed outputs.
    pub(crate) hot_block_bytes: NonZeroUsize,
}

/// Delivery configuration.
pub(crate) struct Config<E, H, V, B, A>
where
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Runtime context of the delivery task.
    pub(crate) context: E,
    /// The durable cursor, opened against the catalog's recovered checkpoint.
    pub(crate) store: DeliveryCursor<E>,
    pub(crate) catalog: catalog::Mailbox<H, V, B>,
    pub(crate) bodies: Bodies<H, V, B>,
    /// Receives each output in order.
    pub(crate) application: A,
    /// The receiving half of [`super::channel`].
    pub(crate) mailbox: Receiver<H, B>,
    pub(crate) bounds: Bounds,
}

/// Committed outputs read back from custody for delivery.
struct ColdOutputs<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    refs: Vec<StoredRef<H::Digest>>,
    blocks: Vec<Arc<TransactionBlock<H, B>>>,
}

/// A cold read in flight, tagged with the generation that started it.
struct Fetch<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    generation: u64,
    /// First output the read returns.
    start: OutputIndex,
    read: BoxFuture<'static, Result<ColdOutputs<H, B>, Error>>,
}

/// The single owner of the delivery cursor and the application window.
pub(crate) struct Actor<E, H, V, B, A>
where
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    context: ContextCell<E>,
    store: DeliveryCursor<E>,
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    application: A,
    mailbox: Receiver<H, B>,
    pending: PendingAcks,
    cache: DeliveryCache<H, B>,
    fetch: Option<Fetch<H, B>>,
    metrics: Metrics,
    bounds: Bounds,
}

impl<E, H, V, B, A> Actor<E, H, V, B, A>
where
    E: Clock + Spawner + RuntimeMetrics + Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    A: Reporter<Activity = Update<TransactionBlock<H, B>>>,
{
    pub(crate) fn new(config: Config<E, H, V, B, A>) -> Self {
        let Config {
            context,
            store,
            catalog,
            bodies,
            application,
            mailbox,
            bounds,
        } = config;
        Self {
            metrics: Metrics::new(&context),
            context: ContextCell::new(context),
            store,
            catalog,
            bodies,
            application,
            mailbox,
            pending: PendingAcks::new(bounds.pending_acks),
            cache: DeliveryCache::new(bounds.hot_block_bytes),
            fetch: None,
            bounds,
        }
    }

    /// Starts the delivery task.
    pub(crate) fn start(mut self) -> Handle<Result<(), Error>> {
        spawn_cell!(self.context, self.run())
    }

    /// Reports outputs in order until the catalog closes the mailbox.
    ///
    /// Each turn first reports hot outputs, starting a cold read at the first output without a
    /// hot body, then starts a cursor sync for the ready acknowledged prefix. It then waits for the
    /// first of: an acknowledgement event, a catalog message, the cold read. While a cold read
    /// runs, acknowledgement events wait; a reset or generation change drops the read.
    async fn run(mut self) -> Result<(), Error> {
        let mut progress = self.catalog.progress().await?;
        if self.store.floor_generation() != progress.floor_generation
            || self.store.acknowledged() != progress.acknowledged
        {
            return Err(Error::Invariant(
                "delivery cursor does not match catalog progress",
            ));
        }
        self.metrics.progress(progress.acknowledged);
        select_loop! {
            self.context,
            on_start => {
                if self.fetch.is_none() {
                    self.fill(&progress)?;
                    if self.fetch.is_none() {
                        self.start_sync(&progress).await?;
                    }
                }
                let acknowledgements_open = self.fetch.is_none() && !self.pending.is_empty();
            },
            on_stopped => {},
            event = gated(acknowledgements_open, self.pending.next_event()) => {
                self.acknowledge(event, &mut progress)?;
                if let Ok(message) = self.mailbox.try_recv() {
                    self.handle(message, &mut progress).await?;
                }
            },
            Some(message) = self.mailbox.recv() else break => {
                let reset = matches!(message, Message::Reset { .. });
                self.handle(message, &mut progress).await?;
                // A reset or a newer generation supersedes the cold read.
                if self
                    .fetch
                    .as_ref()
                    .is_some_and(|fetch| reset || fetch.generation != progress.floor_generation)
                {
                    self.fetch = None;
                }
            },
            outputs = next_fetch(&mut self.fetch) => {
                let start = self
                    .fetch
                    .take()
                    .expect("a finished cold read was in flight")
                    .start;
                self.report_cold(start, outputs?)?;
            },
        }
        Ok(())
    }

    /// Reports hot outputs from the delivery cursor, starting a cold read at the first output
    /// without a hot body.
    fn fill(&mut self, progress: &MarshalProgress<H::Digest>) -> Result<(), Error> {
        let Some(mut next) = self.pending.next(progress.acknowledged)? else {
            return Ok(());
        };
        while self.pending.has_capacity()
            && progress
                .committed
                .is_some_and(|committed| next <= committed)
        {
            let Some(block) = self.cache.take_hot(next) else {
                self.start_fetch(progress.floor_generation, next);
                return Ok(());
            };
            self.metrics.hot_output();
            self.report(next, block)?;
            let Some(following) = next.next() else {
                return Ok(());
            };
            next = following;
        }
        Ok(())
    }

    /// Starts reading outputs from `start` back from custody.
    fn start_fetch(&mut self, generation: u64, start: OutputIndex) {
        let refs =
            self.cache
                .take_refs(start, self.pending.remaining(), self.bounds.delivery_bytes);
        let max_items = self.cache.cold_prefix(start, self.pending.remaining());
        let catalog = self.catalog.clone();
        let bodies = self.bodies.clone();
        let delivery_bytes = self.bounds.delivery_bytes;
        let read = async move {
            let refs = if refs.is_empty() {
                catalog
                    .output_refs(start, max_items, delivery_bytes)
                    .await?
            } else {
                refs
            };
            if refs.is_empty() {
                return Err(Error::Missing(start));
            }
            let materialize = info_span!(
                "multimmit.marshal.delivery.materialize",
                start = start.get(),
                outputs = refs.len(),
            );
            let blocks = bodies.materialize(&refs).instrument(materialize).await?;
            Ok(ColdOutputs { refs, blocks })
        }
        .boxed();
        self.fetch = Some(Fetch {
            generation,
            start,
            read,
        });
    }

    /// Reports outputs a cold read returned, in order from `start`.
    fn report_cold(&mut self, start: OutputIndex, outputs: ColdOutputs<H, B>) -> Result<(), Error> {
        let ColdOutputs { refs, blocks } = outputs;
        self.metrics.stored_outputs(blocks.len());
        let mut next = start;
        for (output, block) in refs.into_iter().zip(blocks) {
            if output.index != next || block.reference() != output.reference {
                return Err(Error::Missing(next));
            }
            self.report(next, block)?;
            let Some(following) = next.next() else {
                break;
            };
            next = following;
        }
        Ok(())
    }

    /// Reports one output to the application and waits for its acknowledgement in the window.
    fn report(
        &mut self,
        index: OutputIndex,
        block: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        let span = debug_span!(
            "multimmit.marshal.delivery.report",
            index = index.get(),
            chain = block.header().chain().get(),
            height = block.header().height().get(),
        );
        let _guard = span.enter();
        let (acknowledgement, waiter) = Exact::handle();
        self.metrics.attempted();
        if self.application.report(Update {
            index,
            block,
            acknowledgement,
        }) == Feedback::Closed
        {
            return Err(Error::ReporterClosed);
        }
        self.pending.push(index, waiter);
        self.metrics.in_flight(self.pending.in_flight());
        Ok(())
    }

    /// Starts syncing the ready acknowledged prefix unless a sync is in flight.
    async fn start_sync(&mut self, progress: &MarshalProgress<H::Digest>) -> Result<(), Error> {
        if self.pending.is_syncing() {
            return Ok(());
        }
        let Some(ready) = self.pending.take_ready() else {
            return Ok(());
        };
        let span = info_span!(
            "multimmit.marshal.delivery.acknowledge",
            through = ready.through.get(),
        );
        self.metrics.acknowledgement_started();
        let sync = self
            .store
            .start_acknowledgement(progress.floor_generation, ready.through)
            .instrument(span.clone())
            .await?;
        let durability_timer = self.metrics.durability_timer(&*self.context);
        self.pending.start_sync(
            ready,
            durability_timer,
            async move { Ok(sync.await.map_err(StorageError::from)?) }
                .instrument(span)
                .boxed(),
        );
        self.metrics
            .pending_durability(self.pending.pending_durability());
        Ok(())
    }

    /// Applies an application acknowledgement or a finished cursor sync.
    fn acknowledge(
        &mut self,
        event: AcknowledgementEvent,
        progress: &mut MarshalProgress<H::Digest>,
    ) -> Result<(), Error> {
        match event {
            AcknowledgementEvent::Ready(result) => {
                let acknowledged = self.pending.complete(result)?;
                self.pending.coalesce_ready(acknowledged, || {
                    self.metrics.completion_timer(&*self.context)
                });
            }
            AcknowledgementEvent::Durable(result) => {
                let syncing = self.pending.complete_sync(result)?;
                syncing.durability_timer.observe(&*self.context);
                syncing.completion_timer.observe(&*self.context);
                progress.acknowledged = Some(syncing.through);
                self.metrics.acknowledged(syncing.outputs);
                self.metrics.progress(progress.acknowledged);
                if self
                    .catalog
                    .delivery_cursor(progress.floor_generation, progress.acknowledged)
                    == Feedback::Closed
                {
                    return Err(Error::Catalog(catalog::Error::Closed));
                }
                while let Some(result) = self.pending.try_current() {
                    let acknowledged = self.pending.complete(result)?;
                    self.pending.coalesce_ready(acknowledged, || {
                        self.metrics.completion_timer(&*self.context)
                    });
                }
            }
        }
        self.metrics.in_flight(self.pending.in_flight());
        self.metrics
            .pending_durability(self.pending.pending_durability());
        Ok(())
    }

    /// Applies a catalog message.
    async fn handle(
        &mut self,
        message: Message<H, B>,
        progress: &mut MarshalProgress<H::Digest>,
    ) -> Result<(), Error> {
        match message {
            Message::Committed(batch) => {
                if batch.floor_generation == progress.floor_generation {
                    progress.committed = progress.committed.max(Some(batch.committed));
                    if let Some(next) = self.pending.next(progress.acknowledged)? {
                        self.cache.insert(batch, next);
                    }
                    return Ok(());
                }
                drop(batch);
                let next = self.catalog.progress().await?;
                if next.floor_generation != progress.floor_generation {
                    self.reset_window();
                }
                *progress = next;
            }
            Message::Reset {
                floor_generation,
                acknowledged,
                waiters,
            } => {
                self.reset_window();
                self.store.reset(floor_generation, acknowledged).await?;
                self.metrics.progress(acknowledged);
                self.catalog
                    .reset_delivery_cursor(floor_generation, acknowledged)
                    .await?;
                let next = self.catalog.progress().await?;
                if next.floor_generation != floor_generation || next.acknowledged != acknowledged {
                    return Err(Error::Invariant(
                        "catalog did not apply the durable delivery cursor reset",
                    ));
                }
                *progress = next;
                for waiter in waiters {
                    waiter.send_lossy(Ok(()));
                }
            }
        }
        Ok(())
    }

    /// Forgets the reported window and cached outputs of a superseded generation.
    fn reset_window(&mut self) {
        self.pending.clear();
        self.cache.clear();
        self.metrics.in_flight(0);
        self.metrics.pending_durability(0);
    }
}

/// Resolves once the cold read finishes, and never while no read is in flight.
async fn next_fetch<H, B>(fetch: &mut Option<Fetch<H, B>>) -> Result<ColdOutputs<H, B>, Error>
where
    H: Hasher,
    B: Body<H>,
{
    match fetch {
        Some(fetch) => (&mut fetch.read).await,
        None => pending().await,
    }
}
