//! Admission batching, the write phase, and the durability cuts that make admissions custody.
//!
//! An admission command runs in batches:
//!
//! 1. Join queued admission commands while they fit the waiting cut.
//! 2. Validate every admission, then write them to pending storage. A write owns its journal,
//!    so the catalog enters the write phase until the journal returns.
//! 3. Make the batch readable, answer buffered replies, and add it to the waiting cut.
//! 4. Continue with the next queued admission command while the cut has room.
//!
//! The catalog loop starts the waiting cut once no cut is syncing. A finished cut makes its
//! blocks custody and answers its durable replies.

use super::{
    actor::{Catalog, DurabilityCompletion, Fatal, Turn, outcome},
    mailbox::{AdmissionReply, Error, Message, Traced},
    metrics::{CutTrigger, Operation, Source},
    validate,
};
use crate::multimmit::{
    marshal::{
        storage::{
            Error as StorageError,
            catalog::{Admission, AdmissionFuture, AdmissionWrite, Footprint, StagedAdmission},
            commit::CustodyRef,
        },
        types::{CustodyValues, Reply},
    },
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Clock, Handle, Metrics as RuntimeMetrics, Spawner, telemetry::metrics::histogram,
};
use commonware_storage::{Context, translator::Translator};
use commonware_utils::channel::fallible::OneshotExt as _;
use futures::future::try_join_all;
use std::{
    collections::{HashSet, VecDeque},
    iter::Peekable,
    sync::Arc,
    vec,
};
use tracing::{Instrument as _, Span, debug_span, instrument::Instrumented};

/// Largest reply-free admission cut that the `admission_cut_triggers` metric labels `eager`.
///
/// Larger reply-free cuts are labeled `items`. Only the metric label depends on this value; cut
/// starts do not.
const EAGER_CUT_LABEL_MAX_ITEMS: usize = 15;

/// Buffered admissions that the next durability cut will make custody.
pub(super) struct PendingCut<D: Digest> {
    /// Pending families the cut must sync.
    footprint: Footprint,
    /// Replies owed once the cut is durable.
    replies: Vec<Reply<(), Error>>,
    /// Blocks that become custody once the cut is durable.
    blocks: Vec<BlockRef<D>>,
    /// Admissions buffered into the cut.
    items: usize,
    span: Span,
}

/// A finished admission cut.
pub(super) struct CutCompletion<D: Digest> {
    replies: Vec<Reply<(), Error>>,
    blocks: Vec<BlockRef<D>>,
    timer: histogram::Timer,
    result: Result<(), StorageError>,
    span: Span,
}

/// Whether [`Catalog::start_cut`] started a durability cut.
pub(super) enum CutStart {
    /// A cut started syncing.
    Started,
    /// No cut was waiting, or one is already syncing.
    Skipped,
}

/// A custody request waiting for its blocks' first admission cut.
pub(super) type CustodyWaiter<H> = (
    Vec<BlockRef<<H as Hasher>::Digest>>,
    Reply<CustodyValues<<H as Hasher>::Digest>, Error>,
);

/// Admissions of a validated batch not yet written.
type Remaining<H, V, B> = Peekable<Unwritten<H, V, B>>;

/// Admitted blocks and their references.
pub(super) type AdmittedBlocks<H, B> =
    Vec<(BlockRef<<H as Hasher>::Digest>, Arc<TransactionBlock<H, B>>)>;

/// Yields the admissions of staged writes in order.
struct Unwritten<H, V, B>(vec::IntoIter<StagedAdmission<H, V, B>>)
where
    H: Hasher,
    V: Variant,
    B: Body<H>;

impl<H, V, B> Iterator for Unwritten<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Item = Admission<H, V, B>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|write| write.admission)
    }
}

/// Custody lookups resolved for one request, counted by where each was found.
struct CustodyLookup<D: Digest> {
    values: Vec<Option<CustodyRef<D>>>,
    cache_hits: u64,
    storage_hits: u64,
    misses: u64,
}

impl<D: Digest> CustodyLookup<D> {
    /// Collects per-reference results, each paired with whether the live cache resolved it.
    fn collect(results: Vec<(Option<CustodyRef<D>>, bool)>) -> Self {
        let mut lookup = Self {
            values: Vec::with_capacity(results.len()),
            cache_hits: 0,
            storage_hits: 0,
            misses: 0,
        };
        for (value, cached) in results {
            let count = if cached {
                &mut lookup.cache_hits
            } else if value.is_some() {
                &mut lookup.storage_hits
            } else {
                &mut lookup.misses
            };
            *count = count.saturating_add(1);
            lookup.values.push(value);
        }
        lookup
    }
}

/// One admission request taken from the command lane.
pub(super) struct AdmitRequest<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) admissions: Vec<Admission<H, V, B>>,
    pub(super) reply: AdmissionReply,
    /// The caller's span.
    pub(super) span: Span,
}

/// Admissions validated together, and the replies they owe.
struct Batch<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Pending families the batch writes durably, or `None` when it needs no cut.
    footprint: Option<Footprint>,
    /// Admitted blocks, cached once written.
    blocks: AdmittedBlocks<H, B>,
    /// Replies owed once the batch is durable.
    durable: Vec<Reply<(), Error>>,
    /// Replies owed once the batch is written.
    buffered: Vec<Reply<(), Error>>,
    /// Admissions in the batch.
    admitted: usize,
}

impl<H, B> Batch<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn fail(self, error: Error) {
        for reply in self.durable.into_iter().chain(self.buffered) {
            reply.send_lossy(Err(error));
        }
    }
}

/// An admission command whose write owns a pending journal.
pub(super) struct Writing<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// The started write.
    write: Instrumented<AdmissionFuture<T, E, H, V, B>>,
    remaining: Remaining<H, V, B>,
    batch: Batch<H, B>,
    turn: Turn,
}

/// Where an admission command continues.
enum Resume<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Start a batch with this request.
    Start(AdmitRequest<H, V, B>),
    /// Write the rest of a validated batch.
    Write(Batch<H, B>, Remaining<H, V, B>),
    /// Continue with the next queued admission.
    Next,
}

/// The outcome of one step of an admission command.
enum Step<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Write this validated batch.
    Write(Batch<H, B>, Remaining<H, V, B>),
    /// A write owns a journal until it finishes.
    Writing(
        Instrumented<AdmissionFuture<T, E, H, V, B>>,
        Batch<H, B>,
        Remaining<H, V, B>,
    ),
    /// The request is parked until the waiting cut has room.
    Parked,
    /// The batch is written or answered.
    Done,
}

/// Buffered admissions and the durability cuts that make them custody.
pub(super) struct AdmissionState<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// The cut accumulating buffered admissions.
    pending: Option<PendingCut<H::Digest>>,
    /// Whether a cut is syncing.
    syncing: bool,
    /// Buffered blocks whose first cut has not finished: readable, but not custody yet.
    volatile: HashSet<BlockRef<H::Digest>>,
    custody_waiters: VecDeque<CustodyWaiter<H>>,
    custody_waiter_capacity: usize,
    /// Most admissions one cut holds.
    capacity: usize,
    /// The admission command whose write owns a journal.
    writing: Option<Writing<T, E, H, V, B>>,
}

impl<T, E, H, V, B> AdmissionState<T, E, H, V, B>
where
    T: Translator,
    E: Context,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) fn new(capacity: usize, custody_waiter_capacity: usize) -> Self {
        Self {
            pending: None,
            syncing: false,
            volatile: HashSet::new(),
            custody_waiters: VecDeque::new(),
            custody_waiter_capacity,
            capacity,
            writing: None,
        }
    }

    /// Returns whether no cut is syncing or waiting to start.
    pub(super) const fn is_idle(&self) -> bool {
        !self.syncing && self.pending.is_none()
    }

    /// Returns whether an admission write owns a journal.
    pub(super) const fn is_writing(&self) -> bool {
        self.writing.is_some()
    }

    /// Returns admissions the waiting cut can still take.
    pub(super) fn room(&self) -> usize {
        let items = self.pending.as_ref().map_or(0, |cut| cut.items);
        self.capacity
            .checked_sub(items)
            .expect("the waiting admission cut is bounded")
    }

    /// Returns most admissions one cut holds.
    pub(super) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns whether the waiting cut is full.
    fn is_full(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|cut| cut.items >= self.capacity)
    }

    /// Resolves once the in-flight write finishes, and never while no write is in flight.
    pub(super) async fn written(&mut self) -> Result<AdmissionWrite<T, E, H, V, B>, StorageError> {
        match &mut self.writing {
            Some(writing) => (&mut writing.write).await,
            None => std::future::pending().await,
        }
    }
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
    /// Runs an admission command until it finishes, parks, or a write owns a journal.
    pub(super) fn admit(
        &mut self,
        request: AdmitRequest<H, V, B>,
        turn: Turn,
    ) -> Result<(), Fatal> {
        let instrument = turn.current().clone();
        instrument.in_scope(|| self.drive_admission(Resume::Start(request), turn))
    }

    /// Resumes the admission command whose write returned its journal.
    pub(super) fn finish_write(
        &mut self,
        result: Result<AdmissionWrite<T, E, H, V, B>, StorageError>,
    ) -> Result<(), Fatal> {
        let Writing {
            remaining,
            batch,
            turn,
            ..
        } = self
            .admission
            .writing
            .take()
            .expect("a finished write was in flight");
        let instrument = turn.current().clone();
        instrument.in_scope(|| {
            let finished = result.and_then(|write| self.stores.finish_admission(write));
            let resume = match outcome(finished)? {
                Ok(()) => Resume::Write(batch, remaining),
                Err(error) => {
                    batch.fail(error);
                    Resume::Next
                }
            };
            self.drive_admission(resume, turn)
        })
    }

    /// Runs admission batches until one parks, a write owns a journal, or no queued admission
    /// can continue the command.
    fn drive_admission(&mut self, mut resume: Resume<H, V, B>, turn: Turn) -> Result<(), Fatal> {
        loop {
            let step = match resume {
                Resume::Start(request) => self.start_batch(request)?,
                Resume::Write(batch, remaining) => self.write_batch(batch, remaining)?,
                Resume::Next => Step::Done,
            };
            resume = match step {
                Step::Write(batch, remaining) => Resume::Write(batch, remaining),
                Step::Writing(write, batch, remaining) => {
                    self.admission.writing = Some(Writing {
                        write,
                        remaining,
                        batch,
                        turn,
                    });
                    return Ok(());
                }
                Step::Parked => {
                    self.finish_turn(turn);
                    return Ok(());
                }
                Step::Done => match self.next_admission() {
                    Some(request) => Resume::Start(request),
                    None => {
                        self.finish_turn(turn);
                        return Ok(());
                    }
                },
            };
        }
    }

    /// Takes the next queued admission to continue the command, unless a request is parked or
    /// the waiting cut is full.
    fn next_admission(&mut self) -> Option<AdmitRequest<H, V, B>> {
        if self.intake.commands.parked().is_some() || self.admission.is_full() {
            return None;
        }
        self.try_next_admission(usize::MAX)
    }

    /// Takes the next queued command if it is an admission of at most `room` items, parking any
    /// other command.
    fn try_next_admission(&mut self, room: usize) -> Option<AdmitRequest<H, V, B>> {
        let mut command = self.intake.commands.try_recv()?;
        self.note_intake(&mut command);
        match command.message {
            Message::Admit { admissions, reply } if admissions.len() <= room => {
                follow(&Span::current(), &command.span);
                Some(AdmitRequest {
                    admissions,
                    reply,
                    span: command.span,
                })
            }
            message => {
                self.intake.commands.park(Traced {
                    message,
                    span: command.span,
                    enqueued: command.enqueued,
                });
                None
            }
        }
    }

    /// Answers, parks, or validates a batch starting with `request`.
    fn start_batch(
        &mut self,
        request: AdmitRequest<H, V, B>,
    ) -> Result<Step<T, E, H, V, B>, Fatal> {
        let AdmitRequest {
            admissions,
            reply,
            span,
        } = request;
        if admissions.is_empty() {
            reply.empty();
            return Ok(Step::Done);
        }
        if admissions.len() > self.admission.capacity() {
            reply.fail(Error::Invalid("admission batch exceeds catalog capacity"));
            return Ok(Step::Done);
        }
        let readiness = self.readiness();
        if !readiness.admits(admissions.len()) {
            self.intake.commands.park(Traced {
                message: Message::Admit { admissions, reply },
                span,
                enqueued: None,
            });
            return Ok(Step::Parked);
        }
        let room = readiness.admission_room;
        let mut items = admissions.len();
        let mut requests = vec![AdmitRequest {
            admissions,
            reply,
            span,
        }];
        while items < room {
            let Some(request) = self.try_next_admission(room - items) else {
                break;
            };
            items += request.admissions.len();
            requests.push(request);
        }
        self.validate_batch(requests)
    }

    /// Validates each request of a batch and reserves its durability footprint.
    fn validate_batch(
        &mut self,
        requests: Vec<AdmitRequest<H, V, B>>,
    ) -> Result<Step<T, E, H, V, B>, Fatal> {
        let capacity = requests
            .iter()
            .map(|request| request.admissions.len())
            .sum();
        let mut writes = Vec::with_capacity(capacity);
        let mut blocks = Vec::new();
        let mut durable = Vec::with_capacity(requests.len());
        let mut buffered = Vec::with_capacity(requests.len());
        let epoch = self.stores.checkpoint().epoch();
        let chains = self.stores.pending().chain_count();
        for AdmitRequest {
            admissions, reply, ..
        } in requests
        {
            if let Err(error) = admissions.iter().try_for_each(|admission| {
                validate::admission(epoch, chains, self.bounds.max_block_bytes.get(), admission)
            }) {
                reply.fail(error);
                continue;
            }
            let is_durable = reply.is_durable();
            for admission in admissions {
                if let Admission::Block(reference, block) = &admission {
                    blocks.push((*reference, Arc::clone(block)));
                }
                writes.push(StagedAdmission {
                    admission,
                    durable: is_durable,
                });
            }
            match reply {
                AdmissionReply::Buffered(reply) => buffered.push(reply),
                AdmissionReply::Durable(reply) => durable.push(reply),
                AdmissionReply::Staged {
                    accepted,
                    durable: custody,
                } => {
                    buffered.push(accepted);
                    durable.push(custody);
                }
            }
        }
        if writes.is_empty() {
            return Ok(Step::Done);
        }
        let admitted = writes.len();
        let footprint = match outcome(self.stores.admission_footprint(&writes))? {
            Ok(footprint) => footprint,
            Err(error) => {
                for reply in durable.into_iter().chain(buffered) {
                    reply.send_lossy(Err(error));
                }
                return Ok(Step::Done);
            }
        };
        let batch = Batch {
            footprint,
            blocks,
            durable,
            buffered,
            admitted,
        };
        Ok(Step::Write(batch, Unwritten(writes.into_iter()).peekable()))
    }

    /// Starts the batch's next write, or finishes the batch once every admission is written.
    fn write_batch(
        &mut self,
        batch: Batch<H, B>,
        mut remaining: Remaining<H, V, B>,
    ) -> Result<Step<T, E, H, V, B>, Fatal> {
        while remaining.peek().is_some() {
            match outcome(self.stores.start_admission(&mut remaining))? {
                Ok(Some(write)) => {
                    return Ok(Step::Writing(
                        write.instrument(Span::current()),
                        batch,
                        remaining,
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    batch.fail(error);
                    return Ok(Step::Done);
                }
            }
        }
        self.finish_batch(batch);
        Ok(Step::Done)
    }

    /// Makes a written batch readable, answers its buffered replies, and adds it to the waiting
    /// cut.
    fn finish_batch(&mut self, batch: Batch<H, B>) {
        let Batch {
            footprint,
            blocks,
            durable,
            buffered,
            admitted,
        } = batch;
        let references = blocks
            .iter()
            .map(|(reference, _)| *reference)
            .collect::<Vec<_>>();
        self.admission.volatile.extend(references.iter().copied());
        self.reads.cache_admitted(&self.metrics, blocks);
        self.metrics.admitted(admitted);
        for reply in buffered {
            reply.send_lossy(Ok(()));
        }
        let Some(footprint) = footprint else {
            if let Some(cut) = &mut self.admission.pending {
                cut.items += admitted;
            }
            return;
        };
        if let Some(cut) = &mut self.admission.pending {
            follow(&cut.span, &Span::current());
            cut.footprint.merge(footprint);
            cut.replies.extend(durable);
            cut.blocks.extend(references);
            cut.items += admitted;
        } else {
            self.admission.pending = Some(PendingCut {
                footprint,
                replies: durable,
                blocks: references,
                items: admitted,
                span: Span::current(),
            });
        }
    }

    /// Starts syncing the waiting cut unless one is already syncing.
    pub(super) async fn start_cut(&mut self) -> Result<CutStart, Fatal> {
        if self.admission.syncing {
            return Ok(CutStart::Skipped);
        }
        let Some(cut) = self.admission.pending.take() else {
            return Ok(CutStart::Skipped);
        };
        let work = self
            .metrics
            .time(Source::Internal, Operation::AdmissionStart, &*self.context);
        let trigger = if !cut.replies.is_empty() {
            CutTrigger::Reply
        } else if cut.items > EAGER_CUT_LABEL_MAX_ITEMS {
            CutTrigger::Items
        } else {
            CutTrigger::Eager
        };
        self.metrics.cut_started(trigger, cut.items);
        let span = debug_span!(
            parent: &cut.span,
            "multimmit.marshal.catalog.admission_cut",
            items = cut.items,
            blocks = cut.blocks.len(),
        );
        let completion_span = span.clone();
        let timer = self.metrics.admission_durability_timer(&*self.context);
        let handles = self
            .stores
            .start_admission_sync(cut.footprint)
            .instrument(span.clone())
            .await?;
        self.admission.syncing = true;
        self.durability.push(
            async move {
                DurabilityCompletion::Admission(CutCompletion {
                    replies: cut.replies,
                    blocks: cut.blocks,
                    timer,
                    result: join_syncs(handles).await,
                    span: completion_span,
                })
            }
            .instrument(span),
        );
        self.metrics.finish(work, &*self.context);
        Ok(CutStart::Started)
    }

    /// Makes a finished cut's blocks custody, answers its replies, and serves custody waiters.
    pub(super) async fn finish_cut(
        &mut self,
        completion: CutCompletion<H::Digest>,
    ) -> Result<(), Fatal> {
        let CutCompletion {
            replies,
            blocks,
            timer,
            result,
            span,
        } = completion;
        timer.observe(&*self.context);
        self.admission.syncing = false;
        result?;
        self.reads
            .materializer
            .retain_readers(self.stores.pending().immutable_body_readers());
        for reference in blocks {
            self.admission.volatile.remove(&reference);
        }
        for reply in replies {
            reply.send_lossy(Ok(()));
        }
        self.reads.start_retirement(&mut self.stores, &span)?;
        let waiting = std::mem::take(&mut self.admission.custody_waiters);
        for (references, reply) in waiting {
            if let Some(waiter) = self.custody_or_wait(references, reply).await? {
                self.admission.custody_waiters.push_back(waiter);
            }
        }
        Ok(())
    }

    /// Answers a custody request, or waits while any of its blocks awaits its first cut.
    pub(super) async fn wait_for_custody(
        &mut self,
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<CustodyValues<H::Digest>, Error>,
    ) -> Result<(), Fatal> {
        let Some((references, reply)) = self.custody_or_wait(references, reply).await? else {
            return Ok(());
        };
        if self.admission.custody_waiters.len() >= self.admission.custody_waiter_capacity {
            reply.send_lossy(Err(Error::CustodyWaitersFull));
            return Ok(());
        }
        self.admission
            .custody_waiters
            .push_back((references, reply));
        Ok(())
    }

    /// Answers a custody request unless one of its blocks awaits its first cut, in which case the
    /// request is returned to wait.
    async fn custody_or_wait(
        &mut self,
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<CustodyValues<H::Digest>, Error>,
    ) -> Result<Option<CustodyWaiter<H>>, Fatal> {
        if references
            .iter()
            .any(|reference| self.admission.volatile.contains(reference))
        {
            return Ok(Some((references, reply)));
        }
        let live = self.reads.live();
        let stores = &self.stores;
        let results = try_join_all(references.into_iter().map(|reference| async move {
            if let Some(custody) = live.custody(reference) {
                return Ok((Some(custody), true));
            }
            let meta = stores.block_meta(reference).await?;
            Ok((meta.map(|meta| CustodyRef::new(reference, meta)), false))
        }))
        .await;
        match outcome(results)? {
            Ok(results) => {
                let lookup = CustodyLookup::collect(results);
                self.metrics
                    .custody_lookup(lookup.cache_hits, lookup.storage_hits, lookup.misses);
                reply.send_lossy(Ok(lookup.values));
            }
            Err(error) => {
                reply.send_lossy(Err(error));
            }
        }
        Ok(None)
    }

    /// Returns whether no admission work remains.
    pub(super) const fn admission_drained(&self) -> bool {
        self.admission.is_idle() && self.admission.writing.is_none()
    }
}

/// Links `span` to `from` unless they are the same span.
///
/// Commands from one caller share its span, and span layers may lock both ends of a link, so a
/// span must never follow itself.
pub(super) fn follow(span: &Span, from: &Span) {
    if span.id() != from.id() {
        span.follows_from(from.id());
    }
}

/// Awaits every sync handle of one durability wave.
pub(super) async fn join_syncs(handles: Vec<Handle<()>>) -> Result<(), StorageError> {
    try_join_all(handles).await?;
    Ok(())
}
