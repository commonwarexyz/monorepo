//! The delivery task.

use super::{
    acks::{AcknowledgementEvent, PendingAcks},
    cache::DeliveryCache,
    cursor::DeliveryCursor,
    finals::{Finals, Segment, WALK_SEGMENT_HEADERS, WalkRequest, Work},
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
            types::{BodyValues, Update},
        },
        types::{BlockRef, Body, CodecConfig, TransactionBlock},
    },
    types::{Epoch, OutputIndex},
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
use tracing::{Instrument as _, debug_span, info_span, warn};

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
    /// Most final blocks each chain reads ahead of the ordered stream at a time.
    pub(crate) final_lookahead: NonZeroUsize,
    /// Most header segments the catalog serves in one read.
    pub(crate) header_requests: NonZeroUsize,
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
    /// Decode bounds for the epoch, which finality facts must match.
    pub(crate) codec: CodecConfig,
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

/// What a read of local custody for final blocks returned.
enum FinalRead<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Output rows in order from the requested start.
    Seeded(Vec<(OutputIndex, BlockRef<H::Digest>)>),
    /// One segment per request.
    Walked {
        requests: Vec<WalkRequest<H::Digest>>,
        segments: Vec<Segment<H::Digest>>,
    },
    /// The bodies of `references`, `None` where custody lacks one.
    Loaded {
        references: Vec<BlockRef<H::Digest>>,
        bodies: BodyValues<H, B>,
    },
}

/// Encoded header bytes one walk reads per chain; ample for its headers, so a segment that ends
/// early within it is rare and resumes on the next walk.
const WALK_SEGMENT_BYTES: usize = WALK_SEGMENT_HEADERS * 1024;

/// A read of local custody for final blocks in flight.
type FinalJob<H, B> = BoxFuture<'static, Result<FinalRead<H, B>, Error>>;

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
    /// Final blocks to report before they are ordered.
    finals: Finals<H::Digest>,
    /// Dropped whenever the generation changes.
    final_job: Option<FinalJob<H, B>>,
    codec: CodecConfig,
    /// Epoch of the published checkpoint, which finality facts must match.
    epoch: Epoch,
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
            codec,
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
            finals: Finals::new(bounds.final_lookahead.get(), bounds.header_requests.get()),
            final_job: None,
            codec,
            epoch: Epoch::zero(),
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
    /// first of: an acknowledgement event, a mailbox message, the cold read, the read for final
    /// blocks. While a cold read runs, acknowledgement events wait; a reset or generation change
    /// drops both reads.
    async fn run(mut self) -> Result<(), Error> {
        let mut progress = self.catalog.progress().await?;
        if self.store.floor_generation() != progress.floor_generation
            || self.store.acknowledged() != progress.acknowledged
        {
            return Err(Error::Invariant(
                "delivery cursor does not match catalog progress",
            ));
        }
        self.reset_finals(progress.acknowledged).await?;
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
                self.start_final();
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
            read = next_final(&mut self.final_job) => {
                self.final_job = None;
                match read {
                    Ok(read) => self.report_finals(read)?,
                    // These reads only serve early reports: a failure retries later, and a catalog
                    // that stopped fails the reads ordered delivery depends on.
                    Err(error) => {
                        warn!(%error, "final block read failed");
                        self.finals.stall();
                    }
                }
            },
        }
        Ok(())
    }

    /// Reports hot outputs from the delivery cursor, starting a cold read at the first output
    /// without a hot body.
    fn fill(&mut self, progress: &MarshalProgress<H::Digest>) -> Result<(), Error> {
        let mut next = self.pending.next(progress.acknowledged);
        while self.pending.has_capacity() && next <= progress.committed {
            let Some(block) = self.cache.take_hot(next) else {
                self.start_fetch(progress.floor_generation, next);
                return Ok(());
            };
            self.metrics.hot_output();
            self.report(next, block)?;
            next = next.next();
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
            next = next.next();
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
        let reference = block.reference();
        if self.application.report(Update::Block {
            index,
            block,
            acknowledgement,
        }) == Feedback::Closed
        {
            return Err(Error::ReporterClosed);
        }
        self.finals.delivered(reference);
        self.pending.push(index, waiter);
        self.metrics.in_flight(self.pending.in_flight());
        Ok(())
    }

    /// Starts reading local custody for the next final blocks unless a read is in flight.
    fn start_final(&mut self) {
        if self.final_job.is_some() {
            return;
        }
        let Some(work) = self.finals.next() else {
            return;
        };
        self.final_job = Some(match work {
            Work::Seed { start, max } => {
                let catalog = self.catalog.clone();
                let max = NonZeroUsize::new(max).unwrap_or(NonZeroUsize::MIN);
                let max_bytes = self.bounds.delivery_bytes;
                async move {
                    let rows = catalog
                        .output_refs(start, max, max_bytes)
                        .await?
                        .into_iter()
                        .map(|row| (row.index, row.reference))
                        .collect();
                    Ok(FinalRead::Seeded(rows))
                }
                .boxed()
            }
            Work::Walk(requests) => {
                let catalog = self.catalog.clone();
                async move {
                    let heads = requests
                        .iter()
                        .map(|(_, tip, items)| (*tip, *items))
                        .collect();
                    let segments = catalog
                        .header_segments(heads, WALK_SEGMENT_BYTES)
                        .await?
                        .into_iter()
                        .map(|headers| {
                            headers
                                .iter()
                                .map(|header| (header.block_ref::<H>(), header.parent_ref()))
                                .collect()
                        })
                        .collect();
                    Ok(FinalRead::Walked { requests, segments })
                }
                .boxed()
            }
            Work::Load(references) => {
                let bodies = self.bodies.clone();
                async move {
                    let values = bodies.blocks(references.clone()).await?;
                    Ok(FinalRead::Loaded {
                        references,
                        bodies: values,
                    })
                }
                .boxed()
            }
        });
    }

    /// Applies a read of local custody, reporting the final blocks it made ready.
    fn report_finals(&mut self, read: FinalRead<H, B>) -> Result<(), Error> {
        match read {
            FinalRead::Seeded(rows) => self.finals.seeded(rows),
            FinalRead::Walked { requests, segments } => self.finals.walked(requests, segments),
            FinalRead::Loaded { references, bodies } => {
                for block in self.finals.loaded(references, bodies) {
                    let _span = debug_span!(
                        "multimmit.marshal.delivery.final",
                        chain = block.header().chain().get(),
                        height = block.header().height().get(),
                    )
                    .entered();
                    if self.application.report(Update::Final(block)) == Feedback::Closed {
                        return Err(Error::ReporterClosed);
                    }
                    self.metrics.final_reported();
                }
            }
        }
        Ok(())
    }

    /// Resumes reporting final blocks from the acknowledgement cursor `acknowledged`, dropping any
    /// read in flight.
    async fn reset_finals(&mut self, acknowledged: OutputIndex) -> Result<(), Error> {
        let checkpoint = self.catalog.checkpoint().await?;
        self.epoch = checkpoint.epoch();
        self.finals.reset(
            checkpoint.emitted(),
            acknowledged.min(checkpoint.committed()),
            checkpoint.committed(),
        );
        self.final_job = None;
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
                progress.acknowledged = syncing.through;
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
                    progress.committed = progress.committed.max(batch.committed);
                    // Committed outputs are final.
                    for output in &batch.outputs {
                        self.finals.final_tip(output.stored().reference);
                    }
                    self.cache
                        .insert(batch, self.pending.next(progress.acknowledged));
                    // The commit may have brought custody a stalled chain lacked.
                    self.finals.retry();
                    return Ok(());
                }
                drop(batch);
                let next = self.catalog.progress().await?;
                if next.floor_generation != progress.floor_generation {
                    self.reset_window();
                    *progress = next;
                    return self.reset_finals(progress.acknowledged).await;
                }
                *progress = next;
            }
            Message::Finality(fact) => {
                if fact.is_well_formed(self.epoch, self.codec) {
                    self.finals.finalized(fact.blocks());
                }
            }
            Message::Admitted(chains) => {
                for chain in chains {
                    self.finals.wake(chain as usize);
                }
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
                self.reset_finals(acknowledged).await?;
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

/// Resolves once the read for final blocks finishes, and never while no read is in flight.
async fn next_final<H, B>(job: &mut Option<FinalJob<H, B>>) -> Result<FinalRead<H, B>, Error>
where
    H: Hasher,
    B: Body<H>,
{
    match job {
        Some(job) => job.await,
        None => pending().await,
    }
}
