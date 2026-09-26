//! The catalog task, its loop, and the requests it serves directly.

use super::{
    admission::{AdmissionState, AdmitRequest, CutCompletion, CutStart},
    cache::BlockCache,
    commit::CommitPipeline,
    cursor::CursorMirror,
    intake::{Intake, Lane, ReadGates, Readiness},
    mailbox::{Command, CursorMessage, Error, Mailbox, Message, Read, Traced},
    materializer::Materializer,
    metrics::{Metrics, Operation, Source, WorkTimer},
    reads::{BodyReads, read_header_segments, read_history_segment, read_output_refs},
    validate,
};
use crate::multimmit::{
    actors::util::gated,
    marshal::{
        MarshalProgress,
        actors::{delivery, metrics::saturating_u64, promoter},
        storage::{
            Error as StorageError,
            catalog::{CatalogStore, InstallRequest},
            pending::BODY_READ_CONCURRENCY,
        },
        types::{OutputIndex, Reply},
    },
    types::{BlockRef, Body},
};
use commonware_actor::{Feedback, mailbox};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, spawn_cell,
    telemetry::metrics::histogram,
};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::{channel::fallible::OneshotExt as _, futures::Pool};
use futures::FutureExt as _;
use std::{num::NonZeroUsize, sync::Arc};
use tracing::{Instrument as _, Span, debug_span, error};

/// Bounds on what one request may carry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bounds {
    /// Most selected L-QCs, and most output rows, in one commit.
    pub(crate) max_commit_outputs: NonZeroUsize,
    /// Most encoded block bytes in one commit's outputs (one larger block may commit alone).
    pub(crate) max_commit_block_bytes: NonZeroUsize,
    /// Most encoded bytes of one admitted producer block.
    pub(crate) max_block_bytes: NonZeroUsize,
}

/// Byte bounds of the catalog's block caches.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheBounds {
    /// Bound of the live cache, which also bounds hot bodies handed to delivery.
    pub(crate) hot_bytes: NonZeroUsize,
    /// Bound of the materialized cache, which also bounds one body read.
    pub(crate) materialized_bytes: NonZeroUsize,
}

/// Catalog configuration.
pub(crate) struct Config<R, T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Runtime context of the catalog task.
    pub(crate) context: R,
    /// Opened stores whose interrupted installation and commit cleanup are already replayed.
    pub(crate) stores: CatalogStore<T, E, H, V, B>,
    /// Capacity of the command and read mailboxes.
    pub(crate) mailbox_size: NonZeroUsize,
    /// Most admissions one durability cut holds, and so one admission request may carry.
    pub(crate) admission_cut_capacity: NonZeroUsize,
    /// Most header segments one request may walk.
    pub(crate) header_request_capacity: NonZeroUsize,
    /// Most custody requests that may wait for admission cuts.
    pub(crate) custody_waiter_capacity: NonZeroUsize,
    /// Most body requests that may wait for materialization.
    pub(crate) body_waiter_capacity: NonZeroUsize,
    /// Most body requests that may materialize at once.
    pub(crate) materialization_capacity: NonZeroUsize,
    /// Bounds on the commits the catalog accepts.
    pub(crate) bounds: Bounds,
    /// Byte bounds of the live and materialized body caches.
    pub(crate) caches: CacheBounds,
    /// Delivery, which receives each published commit's outputs.
    pub(crate) delivery: delivery::Mailbox<H, B>,
    /// The promoter, when finalized bodies move to an immutable archive.
    pub(crate) promoter: Option<promoter::Mailbox<H, B>>,
    /// Delivery's durable acknowledgement, already checked against the recovered checkpoint.
    pub(crate) acknowledged: Option<OutputIndex>,
}

/// The catalog stopped because continuing could break storage or delivery invariants.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fatal {
    #[error("catalog storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("delivery mailbox is closed")]
    DeliveryClosed,
    #[error("immutable promoter mailbox is closed")]
    PromoterClosed,
    #[error("delivery cursor contradicts the catalog: {0}")]
    Cursor(&'static str),
}

/// Splits a storage result into the request's outcome, or the failure that stops the catalog.
///
/// A storage request rejected before any store changed answers the caller; any other storage
/// failure leaves the stores unusable.
pub(super) fn outcome<T>(result: Result<T, StorageError>) -> Result<Result<T, Error>, Fatal> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(StorageError::Invalid(reason)) => Ok(Err(Error::Invalid(reason))),
        Err(error) => Err(Fatal::Storage(error)),
    }
}

/// A finished durability sync.
pub(super) enum DurabilityCompletion<D: Digest> {
    /// An admission cut.
    Admission(CutCompletion<D>),
    /// A commit's finalized archives.
    CommitArchives(histogram::Timer, Result<(), StorageError>),
    /// A commit's checkpoint publication.
    CommitCheckpoint(histogram::Timer, Result<(), StorageError>),
}

impl<D: Digest> DurabilityCompletion<D> {
    /// Returns the work-metric operation of this completion.
    const fn kind(&self) -> Operation {
        match self {
            Self::Admission(_) => Operation::Admission,
            Self::CommitArchives(_, _) => Operation::CommitArchives,
            Self::CommitCheckpoint(_, _) => Operation::Checkpoint,
        }
    }
}

/// One request's processing span and work timer, finished once the request is done.
pub(super) struct Turn {
    /// The request's processing span, which records its handler time.
    process: Span,
    /// The span the request runs in: `process`, or the caller's span when `process` is filtered
    /// out.
    current: Span,
    timer: WorkTimer,
}

impl Turn {
    fn new(parent: &Span, operation: Operation, timer: WorkTimer) -> Self {
        let process = debug_span!(
            parent: parent,
            "multimmit.marshal.catalog.process",
            command = operation.as_str(),
            handler_ns = tracing::field::Empty,
        );
        let current = if process.is_disabled() {
            parent.clone()
        } else {
            process.clone()
        };
        Self {
            process,
            current,
            timer,
        }
    }

    /// Returns the span the request runs in.
    pub(super) const fn current(&self) -> &Span {
        &self.current
    }
}

/// The single owner of every mutable catalog store.
///
/// Storage mutations run one at a time on this task, while their durability syncs, body reads,
/// and retirement markers complete in bounded background pools.
pub(crate) struct Catalog<R, T, E, H, V, B>
where
    R: Clock + Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) context: ContextCell<R>,
    pub(super) stores: CatalogStore<T, E, H, V, B>,
    pub(super) intake: Intake<H, V, B>,
    pub(super) admission: AdmissionState<T, E, H, V, B>,
    pub(super) commits: CommitPipeline<H, B>,
    pub(super) reads: BodyReads<R, E, H, B>,
    pub(super) cursor: CursorMirror,
    /// Admission cuts and commit syncs in flight.
    pub(super) durability: Pool<'static, DurabilityCompletion<H::Digest>>,
    pub(super) bounds: Bounds,
    header_request_capacity: usize,
    pub(super) delivery: delivery::Mailbox<H, B>,
    pub(super) promoter: Option<promoter::Mailbox<H, B>>,
    pub(super) metrics: Metrics,
}

impl<R, T, E, H, V, B> Catalog<R, T, E, H, V, B>
where
    R: Clock + Spawner + RuntimeMetrics,
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    B::Cfg: Clone,
{
    /// Creates the catalog and its mailbox.
    ///
    /// The caller has opened the stores, replayed any interrupted installation and commit
    /// cleanup, and checked delivery's cursor against the recovered checkpoint.
    pub(crate) fn new(config: Config<R, T, E, H, V, B>) -> (Self, Mailbox<H, V, B>) {
        let Config {
            context,
            stores,
            mailbox_size,
            admission_cut_capacity,
            header_request_capacity,
            custody_waiter_capacity,
            body_waiter_capacity,
            materialization_capacity,
            bounds,
            caches,
            delivery,
            promoter,
            acknowledged,
        } = config;
        let metrics = Metrics::new(&context);
        let checkpoint = stores.checkpoint().clone();
        metrics.progress(checkpoint.committed());
        let (commands, command_receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        let (cursors, cursor_receiver) =
            mailbox::new(context.child("delivery_cursor_mailbox"), NonZeroUsize::MIN);
        let (reads, read_receiver) = mailbox::new(context.child("read_mailbox"), mailbox_size);
        let enqueue_clock = context.child("enqueue_clock");
        let mailbox = Mailbox {
            commands,
            cursors,
            reads,
            admission_cut_capacity: admission_cut_capacity.get(),
            now: Arc::new(move || enqueue_clock.current()),
        };
        let mut materializer = Materializer::new(
            context.child("materializer"),
            BODY_READ_CONCURRENCY.get(),
            u64::try_from(caches.materialized_bytes.get()).unwrap_or(u64::MAX),
            materialization_capacity.get(),
            metrics.reader_acquisitions(),
            metrics.materialized_body_bytes(),
        );
        materializer.retain_readers(stores.pending().immutable_body_readers());
        let catalog = Self {
            context: ContextCell::new(context),
            stores,
            intake: Intake {
                commands: Lane::new(command_receiver),
                reads: Lane::new(read_receiver),
                cursors: Lane::new(cursor_receiver),
            },
            admission: AdmissionState::new(
                admission_cut_capacity.get(),
                custody_waiter_capacity.get(),
            ),
            commits: CommitPipeline::new(checkpoint),
            reads: BodyReads::new(
                materializer,
                body_waiter_capacity.get(),
                BlockCache::new(caches.hot_bytes),
                BlockCache::new(caches.materialized_bytes),
            ),
            cursor: CursorMirror::new(acknowledged),
            durability: Pool::default(),
            bounds,
            header_request_capacity: header_request_capacity.get(),
            delivery,
            promoter,
            metrics,
        };
        (catalog, mailbox)
    }

    /// Starts the catalog task.
    ///
    /// The handle resolves with the failure that stopped the catalog, if any, so the marshal
    /// can report why custody stopped. Requests in flight when the catalog stops resolve as
    /// closed.
    pub(crate) fn start(mut self) -> Handle<Result<(), Fatal>> {
        spawn_cell!(self.context, self.run())
    }

    /// Runs the catalog loop, logging the failure that stops it so a sibling's closed mailbox
    /// does not hide the cause.
    async fn run(self) -> Result<(), Fatal> {
        let result = self.serve().await;
        if let Err(fatal) = &result {
            error!(error = %fatal, "catalog stopped");
        }
        result
    }

    /// Serves requests until every lane closes and all work drains.
    ///
    /// Each turn, before waiting, the loop does its priority work in this order, restarting
    /// the turn after any step marked (restart):
    ///
    /// 1. Start the waiting admission cut (restart).
    /// 2. Apply one queued cursor update (restart).
    /// 3. Run at most one ready independent read.
    /// 4. Run the parked command if it is ready (restart); with no parked command and no
    ///    background work that could complete, take one queued command (restart).
    ///
    /// It then waits for the first of: durability, cursor, admission write, materialization,
    /// retirement, command (unless one is parked), read. While an admission write owns a
    /// journal, only the write, materialization, and reads run.
    async fn serve(mut self) -> Result<(), Fatal> {
        select_loop! {
            self.context,
            on_start => {
                let writing = self.admission.is_writing();
                let mut wait = None;
                if !writing {
                    if let CutStart::Started = self.start_cut().await? {
                        continue;
                    }
                    if let Some(message) = self.intake.cursors.try_recv() {
                        let timer =
                            self.metrics.time(Source::Completion, Operation::DeliveryCursor, &*self.context);
                        self.apply_cursor(message)?;
                        self.metrics.finish(timer, &*self.context);
                        continue;
                    }
                }
                let mut gates = self.read_gates();
                if !writing {
                    if let Some(read) = gated(
                        gates.accept,
                        self.intake.reads.next_read(gates.parked_ready),
                    )
                    .now_or_never()
                    {
                        if let Some(read) = read {
                            self.dispatch_read(read).await?;
                        }
                        gates = self.read_gates();
                    }
                    if let Some(command) = self.intake.commands.unpark() {
                        if self.command_ready(&command.message)? {
                            self.dispatch_command(command).await?;
                            continue;
                        }
                        self.intake.commands.park(command);
                    } else if self.durability.is_empty()
                        && self.reads.retirements.is_empty()
                        && self.reads.materializer.is_idle()
                    {
                        // Only drain directly while no background completion can become ready;
                        // otherwise the biased wait below serves completions first.
                        if let Some(mut command) = self.intake.commands.try_recv() {
                            self.note_intake(&mut command);
                            self.intake_command(command).await?;
                            continue;
                        }
                    }
                    if self.is_drained() {
                        break;
                    }
                    let waiting_for = self
                        .intake
                        .commands
                        .parked()
                        .map_or(Operation::Event, |command| command.message.kind());
                    wait = Some(self.metrics.time(Source::Wait, waiting_for, &*self.context));
                }
                let durability_open = !writing;
                let cursors_open = !writing && self.intake.cursors.is_open();
                let commands_open = !writing
                    && self.intake.commands.is_open()
                    && self.intake.commands.parked().is_none();
            },
            on_stopped => {},
            completion = gated(durability_open, self.durability.next_completed()) => {
                self.finish_wait(wait);
                let timer = self.metrics.time(Source::Completion, completion.kind(), &*self.context);
                self.complete_durability(completion).await?;
                self.metrics.finish(timer, &*self.context);
            },
            message = gated(cursors_open, self.intake.cursors.recv()) => {
                self.finish_wait(wait);
                if let Some(message) = message {
                    let timer =
                        self.metrics.time(Source::Completion, Operation::DeliveryCursor, &*self.context);
                    self.apply_cursor(message)?;
                    self.metrics.finish(timer, &*self.context);
                }
            },
            result = self.admission.written() => {
                self.finish_write(result)?;
            },
            completion = self.reads.materializer.complete_next() => {
                if writing {
                    self.reads.finish_materialization(&self.metrics, completion?)?;
                } else {
                    self.finish_wait(wait);
                    let timer =
                        self.metrics.time(Source::Completion, Operation::Materialization, &*self.context);
                    self.reads.finish_materialization(&self.metrics, completion?)?;
                    self.metrics.finish(timer, &*self.context);
                }
            },
            retired = gated(durability_open, self.reads.retirements.next_completed()) => {
                self.finish_wait(wait);
                let timer = self.metrics.time(Source::Completion, Operation::Retire, &*self.context);
                self.reads.finish_retirement(&mut self.stores, retired).await?;
                self.metrics.finish(timer, &*self.context);
            },
            command = gated(commands_open, self.intake.commands.recv()) => {
                self.finish_wait(wait);
                if let Some(mut command) = command {
                    self.note_intake(&mut command);
                    self.intake_command(command).await?;
                }
            },
            read = gated(gates.accept, self.intake.reads.next_read(gates.parked_ready)) => {
                self.finish_wait(wait);
                if let Some(read) = read {
                    self.dispatch_read(read).await?;
                }
            },
        }
        Ok(())
    }

    /// Records the loop's wait for its next event, if this turn measured one.
    fn finish_wait(&self, wait: Option<WorkTimer>) {
        if let Some(wait) = wait {
            self.metrics.finish(wait, &*self.context);
        }
    }

    /// Returns the catalog state that decides whether requests may run.
    pub(super) fn readiness(&self) -> Readiness {
        Readiness {
            barrier: self.commits.is_idle()
                && self.admission.is_idle()
                && self.durability.is_empty(),
            materializer_idle: self.reads.materializer.is_idle(),
            admission_idle: self.admission.is_idle(),
            admission_room: self.admission.room(),
            admission_capacity: self.admission.capacity(),
            body_waiter_room: self.reads.has_waiter_room(),
        }
    }

    /// Returns this turn's read-lane gates.
    fn read_gates(&self) -> ReadGates {
        let readiness = self.readiness();
        ReadGates {
            accept: self.intake.accepts_reads(),
            parked_ready: self
                .intake
                .reads
                .parked()
                .is_none_or(|read| readiness.read(&read.message)),
        }
    }

    /// Returns whether every lane is closed and no work remains.
    fn is_drained(&self) -> bool {
        self.intake.is_drained()
            && self.admission_drained()
            && self.durability.is_empty()
            && self.reads.is_drained()
    }

    /// Records a command's mailbox dwell at its first intake.
    ///
    /// The enqueue time is consumed, so a parked command is never observed twice.
    pub(super) fn note_intake(&self, command: &mut Traced<Message<H, V, B>>) {
        let Some(enqueued) = command.enqueued.take() else {
            return;
        };
        if matches!(command.message, Message::Admit { .. }) {
            self.metrics.admission_dwell(enqueued, &*self.context);
        }
    }

    /// Returns whether `message` may run now.
    ///
    /// A body request runs whenever it can be answered from the caches or started at once, and
    /// waits only when it would need a waiter slot and none is free, so a cache hit never stalls
    /// the command lane.
    fn command_ready(&self, message: &Message<H, V, B>) -> Result<bool, Fatal> {
        if let Message::Command(Command::Bodies { references, .. }) = message
            && !self.reads.has_waiter_room()
        {
            return Ok(!self.reads.must_wait(&self.stores, references)?);
        }
        Ok(self.readiness().command(message))
    }

    /// Runs `command`, or parks it until catalog state lets it run.
    async fn intake_command(&mut self, command: Traced<Message<H, V, B>>) -> Result<(), Fatal> {
        if !self.command_ready(&command.message)? {
            self.intake.commands.park(command);
            return Ok(());
        }
        self.dispatch_command(command).await
    }

    /// Runs a ready command in its processing span.
    async fn dispatch_command(&mut self, command: Traced<Message<H, V, B>>) -> Result<(), Fatal> {
        let Traced { message, span, .. } = command;
        let turn = self.turn(&span, message.kind());
        match message {
            Message::Admit { admissions, reply } => self.admit(
                AdmitRequest {
                    admissions,
                    reply,
                    span,
                },
                turn,
            ),
            Message::Command(command) => {
                let result = self
                    .process(command)
                    .instrument(turn.current().clone())
                    .await;
                self.finish_turn(turn);
                result
            }
        }
    }

    /// Runs a read in its processing span, dropping it if its caller left and parking it if it
    /// cannot run yet.
    async fn dispatch_read(&mut self, read: Traced<Read<H, B>>) -> Result<(), Fatal> {
        if read.message.is_canceled() {
            return Ok(());
        }
        if !self.readiness().read(&read.message) {
            self.intake.reads.park(read);
            return Ok(());
        }
        let Traced { message, span, .. } = read;
        let turn = self.turn(&span, message.kind());
        let result = self
            .process_read(message)
            .instrument(turn.current().clone())
            .await;
        self.finish_turn(turn);
        result
    }

    /// Starts a request's turn under the caller's span.
    fn turn(&self, parent: &Span, operation: Operation) -> Turn {
        Turn::new(
            parent,
            operation,
            self.metrics
                .time(Source::Command, operation, &*self.context),
        )
    }

    /// Records a finished request's work and handler time.
    pub(super) fn finish_turn(&self, turn: Turn) {
        let elapsed = self.metrics.finish(turn.timer, &*self.context);
        turn.process
            .record("handler_ns", saturating_u64(elapsed.as_nanos()));
    }

    /// Serves an ordered request other than an admission.
    async fn process(&mut self, command: Command<H, V, B>) -> Result<(), Fatal> {
        match command {
            Command::Lqc { id, reply } => {
                reply.send_lossy(outcome(self.stores.lqc(id).await)?);
            }
            Command::FinalLqc { id, reply } => {
                reply.send_lossy(outcome(self.stores.final_lqc(id).await)?);
            }
            Command::LatestLqc { reply } => {
                reply.send_lossy(outcome(self.stores.latest_lqc().await)?);
            }
            Command::History { commitment, reply } => {
                reply.send_lossy(outcome(self.stores.history(commitment).await)?);
            }
            Command::HistorySegment {
                commitment,
                max_items,
                max_bytes,
                reply,
            } => {
                read_history_segment(&self.stores, commitment, max_items, max_bytes, reply).await?
            }
            Command::WaitForCustody { references, reply } => {
                self.wait_for_custody(references, reply).await?;
            }
            Command::Bodies { references, reply } => {
                self.reads
                    .request(&self.stores, &self.metrics, references, reply)?;
            }
            Command::Commit {
                batch,
                handoff,
                reply,
            } => self.accept_commit(batch, handoff, reply).await?,
            Command::Install { request, reply } => self.install(request, reply).await?,
            Command::Prune {
                floor_generation,
                reply,
            } => self.prune(floor_generation, reply).await?,
            Command::Promoted { frontiers, reply } => self.promoted(frontiers, reply).await?,
            Command::Checkpoint { reply } => {
                reply.send_lossy(Ok(self.commits.durable().clone()));
            }
            Command::Progress { reply } => {
                reply.send_lossy(Ok(self.progress()));
            }
        }
        Ok(())
    }

    /// Serves an independent read.
    async fn process_read(&mut self, read: Read<H, B>) -> Result<(), Fatal> {
        match read {
            Read::Bodies { references, reply } => {
                self.reads
                    .request(&self.stores, &self.metrics, references, reply)?;
            }
            Read::BodyCandidate {
                chain,
                digest,
                reply,
            } => {
                let candidate = match self.reads.cached_by_digest(chain, digest) {
                    Some(block) => Some((block.reference(), Some(block))),
                    None => self
                        .stores
                        .pending()
                        .reference_by_digest(chain, digest)
                        .map(|reference| (reference, None)),
                };
                reply.send_lossy(Ok(candidate));
            }
            Read::HeaderSegments {
                requests,
                max_bytes,
                reply,
            } => {
                if requests.len() > self.header_request_capacity {
                    reply.send_lossy(Err(Error::Invalid(
                        "header segment request vector exceeds capacity",
                    )));
                    return Ok(());
                }
                read_header_segments(&self.stores, requests, max_bytes, reply).await?;
            }
            Read::OutputRefs {
                start,
                max_items,
                max_bytes,
                reply,
            } => {
                let Some(committed) = self
                    .commits
                    .durable()
                    .committed()
                    .filter(|committed| start <= *committed)
                else {
                    reply.send_lossy(Err(Error::Invalid(
                        "output range does not begin at a committed row",
                    )));
                    return Ok(());
                };
                read_output_refs(&self.stores, committed, start, max_items, max_bytes, reply)
                    .await?;
            }
        }
        Ok(())
    }

    /// Mirrors a delivery-cursor change.
    fn apply_cursor(&mut self, message: CursorMessage) -> Result<(), Fatal> {
        match message {
            CursorMessage::Update {
                floor_generation,
                acknowledged,
            } => {
                self.cursor
                    .update(self.commits.durable(), floor_generation, acknowledged)
                    .map_err(Fatal::Cursor)?;
                self.update_progress_metrics();
            }
            CursorMessage::Reset {
                floor_generation,
                acknowledged,
                reply,
            } => {
                let result = self
                    .cursor
                    .update(self.commits.durable(), floor_generation, acknowledged)
                    .map_err(Error::Invalid);
                if result.is_ok() {
                    self.update_progress_metrics();
                }
                reply.send_lossy(result);
            }
        }
        Ok(())
    }

    /// Applies a finished durability sync.
    async fn complete_durability(
        &mut self,
        completion: DurabilityCompletion<H::Digest>,
    ) -> Result<(), Fatal> {
        match completion {
            DurabilityCompletion::Admission(cut) => self.finish_cut(cut).await,
            DurabilityCompletion::CommitArchives(timer, result) => {
                timer.observe(&*self.context);
                self.archives_synced(result).await
            }
            DurabilityCompletion::CommitCheckpoint(timer, result) => {
                timer.observe(&*self.context);
                self.checkpoint_published(result).await
            }
        }
    }

    /// Installs a verified floor, then resets delivery and the promoter to its generation.
    async fn install(
        &mut self,
        request: InstallRequest<V, H::Digest>,
        reply: Reply<delivery::ResetWaiter, Error>,
    ) -> Result<(), Fatal> {
        self.cleanup().await?;
        let chains = self.stores.pending().chain_count();
        if let Err(error) = validate::install::<H, V>(self.stores.checkpoint(), chains, &request) {
            reply.send_lossy(Err(error));
            return Ok(());
        }
        self.reads.materializer.clear_reader_cache();
        let installed = request.checkpoint.clone();
        if let Err(error) = outcome(self.stores.install(request).await)? {
            reply.send_lossy(Err(error));
            return Ok(());
        }
        self.reads.clear_caches(&self.metrics);
        self.commits.installed(installed.clone());
        self.cursor.reset();
        self.metrics.floor_installed();
        self.update_progress_metrics();
        if self.promoter.as_ref().is_some_and(|promoter| {
            promoter.installed(
                installed.floor_generation(),
                installed.committed(),
                installed.emitted().to_vec(),
            ) == Feedback::Closed
        }) {
            return Err(Fatal::PromoterClosed);
        }
        let reset = self
            .delivery
            .reset(installed.floor_generation(), installed.committed())
            .ok_or(Fatal::DeliveryClosed)?;
        reply.send_lossy(Ok(reset));
        Ok(())
    }

    /// Prunes finalized storage up to delivery's cursor for `floor_generation`.
    async fn prune(&mut self, floor_generation: u64, reply: Reply<(), Error>) -> Result<(), Fatal> {
        let pinned = self.reads.pinned_segments();
        let acknowledged = self
            .cursor
            .acknowledged_in(self.commits.durable(), floor_generation);
        let result = self
            .stores
            .prune_finalized(floor_generation, acknowledged, &pinned)
            .await;
        match outcome(result)? {
            Ok(reclaimed) => {
                self.reads.materializer.release_readers(reclaimed);
                self.reads.clear_caches(&self.metrics);
                reply.send_lossy(Ok(()));
            }
            Err(error) => {
                reply.send_lossy(Err(error));
            }
        }
        Ok(())
    }

    /// Reclaims pending bodies the promoter durably copied through `frontiers`.
    async fn promoted(
        &mut self,
        frontiers: Vec<BlockRef<H::Digest>>,
        reply: Reply<(), Error>,
    ) -> Result<(), Fatal> {
        let pinned = self.reads.pinned_segments();
        let result = self.stores.promoted(frontiers.clone(), &pinned).await;
        match outcome(result)? {
            Ok(reclaimed) => {
                self.reads.materializer.release_readers(reclaimed);
                self.reads.prune_caches(&self.metrics, &frontiers);
                reply.send_lossy(Ok(()));
            }
            Err(error) => {
                reply.send_lossy(Err(error));
            }
        }
        Ok(())
    }

    /// Returns durable progress.
    const fn progress(&self) -> MarshalProgress<H::Digest> {
        let durable = self.commits.durable();
        MarshalProgress {
            floor_generation: durable.floor_generation(),
            floor: durable.floor(),
            committed: durable.committed(),
            acknowledged: self.cursor.acknowledged(),
        }
    }

    /// Publishes the durable commit high-water.
    pub(super) fn update_progress_metrics(&self) {
        self.metrics.progress(self.commits.durable().committed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::sync::Mutex;
    use tracing::info_span;
    use tracing_subscriber::{Layer, layer::Context as LayerContext, prelude::*};

    /// Records the spans that receive field values.
    #[derive(Clone, Default)]
    struct SpanRecords(Arc<Mutex<Vec<tracing::span::Id>>>);

    impl<S: tracing::Subscriber> Layer<S> for SpanRecords {
        fn on_record(
            &self,
            id: &tracing::span::Id,
            _: &tracing::span::Record<'_>,
            _: LayerContext<'_, S>,
        ) {
            self.0.lock().push(id.clone());
        }
    }

    #[test]
    fn filtered_processing_span_does_not_record_into_the_ambient_span() {
        deterministic::Runner::default().start(|context| async move {
            let records = SpanRecords::default();
            let subscriber = tracing_subscriber::registry().with(records.clone()).with(
                tracing_subscriber::filter::filter_fn(|metadata| {
                    metadata.name() != "multimmit.marshal.catalog.process"
                }),
            );
            let _guard = tracing::subscriber::set_default(subscriber);
            let metrics = Metrics::new(&context);
            let ambient = info_span!("test.ambient", handler_ns = tracing::field::Empty);
            ambient.in_scope(|| {
                let turn = Turn::new(
                    &Span::none(),
                    Operation::Bodies,
                    metrics.time(Source::Command, Operation::Bodies, &context),
                );
                assert!(turn.process.is_disabled());
                turn.process.record("handler_ns", 1u64);
                let _ = metrics.finish(turn.timer, &context);
            });
            assert!(records.0.lock().is_empty());
        });
    }
}
