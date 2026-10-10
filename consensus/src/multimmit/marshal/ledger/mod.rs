//! The owner of marshal's state.
//!
//! One task owns every store and machine, and every transition is synchronous: storage, reads,
//! certificate verification and serving run as jobs on other tasks and come back as [`Event`]s.
//! The owner polls, in priority order: job completions, acknowledgements, the public mailbox,
//! the consensus feed, peer responses, peer requests, and a periodic tick. Peer responses and
//! requests also take a bounded turn every iteration, so inputs that are always ready under load
//! never starve them.
//!
//! - [`order`]: the proven positions and the exact block of each.
//! - [`feed`]: proofs from consensus and peers, the order's target, and record walks.
//! - [`deliver`]: fetching, dispatch, acknowledgements and the progress record.
//! - [`finals`]: final blocks reported ahead of their ordered delivery.
//! - [`custody`]: staged and subscribed blocks, lookups and certificates.
//! - [`floor`]: floors and pruning.
//! - [`serve`]: answering peers.

mod custody;
mod deliver;
mod ends;
mod feed;
mod finals;
mod floor;
mod hot;
pub(super) mod order;
mod requests;
mod serve;

use super::{
    config::Limits,
    input::{Delivered, Lane, Message, Request},
    metrics::Metrics,
    store::{
        Error as StoreError,
        blocks::{self, Block, Blocks, Stream},
        log::{self, Access, Opened},
        meta::{self, Ack, Meta},
        proofs::{self, CutEntry, Part, Proofs, Stored},
    },
    types::{Cause, Error, Failure, LqcVerifier, Update},
    wire::Key,
};
use crate::{
    Reporter,
    multimmit::{
        order::{Lanes, SweepFact},
        scheme::Scheme,
        types::{
            BlockRef, Body, CertificateId, CodecConfig, LqcProof, TipRecord, TransactionBlock,
        },
    },
    types::Height,
};
use commonware_broadcast::buffered;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_macros::select;
use commonware_resolver::{Outcome, Resolver};
use commonware_runtime::Spawner;
use commonware_storage::Context;
use commonware_utils::{
    acknowledgement::Canceled,
    channel::{mpsc, oneshot},
    futures::Pool,
};
use finals::Finals;
use futures::{
    FutureExt as _, StreamExt as _,
    future::{BoxFuture, pending},
    stream::FuturesOrdered,
};
use order::{Order, Slot, Target};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Peer responses and peer requests the owner takes each turn, ahead of its biased select.
const PEER_TURN: usize = 8;

/// How often the owner wakes without other input, to retry fetches and walks.
const TICK: Duration = Duration::from_millis(250);

/// How long marshal waits for consensus to report a proof before asking peers.
const QUIET: Duration = Duration::from_secs(2);

/// Most bytes one block append takes.
const APPEND_BYTES: u64 = 32 * 1024 * 1024;

/// Appends to one log after which a cut starts even while more appends are queued, so a steady
/// stream of appends cannot postpone durability indefinitely.
const MAX_UNCUT_APPENDS: u32 = 4;

/// A stored part to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum PartKey<D: commonware_cryptography::Digest> {
    Record(D),
    Lqc(CertificateId<D>),
    Cut(CertificateId<D>),
}

/// A value read from a log, with the segment opened for it, if any.
pub(super) struct Read<E: Context, V: commonware_codec::CodecShared> {
    value: V,
    opened: Option<Opened<E, V>>,
}

/// Why a peer L-QC was verified.
pub(super) enum Verify<D: commonware_cryptography::Digest> {
    /// A proof answering a `Proofs` request, with its leader's history record and the verdict
    /// on the peer's response.
    Proof(D, Arc<TipRecord<D>>, oneshot::Sender<Outcome>),
    /// An L-QC fetched by identifier, with the verdict on the peer's response.
    Fetched(oneshot::Sender<Outcome>),
    /// The anchor of a floor being installed.
    Floor,
}

/// A verified L-QC with the finality it proves.
pub(super) type Proven<S, D> = (LqcProof<S, D>, Arc<SweepFact<D>>);

/// Where the order an L-QC proves ends: the certificate, its leader history, and the emitted
/// height of every chain.
pub(super) type End<D> = (CertificateId<D>, D, Vec<Height>);

/// Callers waiting on exact blocks.
type Waiters<D, T> = HashMap<BlockRef<D>, Vec<oneshot::Sender<Result<T, Error>>>>;

/// A completed job.
pub(super) enum Event<E: Context, H: Hasher, S: Scheme, B: Body<H>> {
    Blocks(Stream, Result<blocks::Done<E, H, B>, StoreError>),
    BlocksDurable(Stream, Result<u64, StoreError>),
    Proofs(Result<proofs::Done<E, S, H::Digest>, StoreError>),
    ProofsDurable(Result<u64, StoreError>),
    Meta(Result<meta::Written<E, H::Digest>, StoreError>),
    Body(
        BlockRef<H::Digest>,
        Stream,
        Result<Read<E, Block<H, B>>, StoreError>,
    ),
    Part(
        PartKey<H::Digest>,
        Result<Read<E, Part<S, H::Digest>>, StoreError>,
    ),
    Fact(CertificateId<H::Digest>, Option<Arc<SweepFact<H::Digest>>>),
    Verified(Verify<H::Digest>, Option<Proven<S, H::Digest>>),
    Buffered(BlockRef<H::Digest>, Option<Height>, Option<Block<H, B>>),
    OpenedBlocks(Stream, Result<Opened<E, Block<H, B>>, StoreError>),
    OpenedProofs(Result<Opened<E, Part<S, H::Digest>>, StoreError>),
    Served,
    Nothing,
    Task(commonware_runtime::Error),
}

/// One input the owner handles.
enum Input<E: Context, H: Hasher, S: Scheme, B: Body<H>> {
    Event(Event<E, H, S, B>),
    Ack(Box<Slot<H::Digest>>, Result<(), Canceled>),
    Message(Option<Message<H, S, B>>),
    Feed,
    Delivered(Option<Delivered<H, S, B>>),
    Request(Option<Request<H::Digest>>),
    Tick,
}

/// An acknowledgement the application owes, with the position it acknowledges.
type AckFuture<D> = BoxFuture<'static, (Box<Slot<D>>, Result<(), Canceled>)>;

/// The stores marshal opened.
pub(crate) struct Stores<E: Context, H: Hasher, S: Scheme, B: Body<H>> {
    pub(crate) blocks: Blocks<E, H, B>,
    pub(crate) proofs: Proofs<E, S, H::Digest>,
    pub(crate) meta: Meta<E, H::Digest>,
}

/// Where the owner's inputs come from.
pub(crate) struct Inputs<H: Hasher, S: Scheme, B: Body<H>> {
    pub(crate) mailbox: mpsc::Receiver<Message<H, S, B>>,
    pub(crate) lane: Arc<Lane<S, H::Digest>>,
    pub(crate) signal: mpsc::Receiver<()>,
    pub(crate) deliveries: mpsc::Receiver<Delivered<H, S, B>>,
    pub(crate) requests: mpsc::Receiver<Request<H::Digest>>,
}

/// The services the owner drives.
pub(crate) struct Services<P: PublicKey, H: Hasher, B: Body<H>, R, V, A> {
    pub(crate) resolver: R,
    pub(crate) verifier: V,
    pub(crate) application: A,
    pub(crate) buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,
}

/// The owner of marshal's state.
pub(crate) struct Ledger<E, H, S, B, P, R, V, A>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
{
    context: E,
    codec: CodecConfig,
    limits: Limits,
    metrics: Metrics,

    blocks: Blocks<E, H, B>,
    proofs: Proofs<E, S, H::Digest>,
    meta: Meta<E, H::Digest>,

    mailbox: mpsc::Receiver<Message<H, S, B>>,
    lane: Arc<Lane<S, H::Digest>>,
    signal: mpsc::Receiver<()>,
    deliveries: mpsc::Receiver<Delivered<H, S, B>>,
    requests: mpsc::Receiver<Request<H::Digest>>,
    jobs: Pool<'static, Event<E, H, S, B>>,
    acks: FuturesOrdered<AckFuture<H::Digest>>,

    resolver: R,
    verifier: V,
    application: A,
    buffer: buffered::Mailbox<P, TransactionBlock<H, B>>,

    /// Appends to each block stream, and to the proofs log, since its last cut started.
    uncut: [u32; 2],
    proofs_uncut: u32,
    /// Whether the next output waits only for its blocks to become durable.
    durability_wanted: bool,
    /// Stored parts and bodies being read.
    reading: HashSet<PartKey<H::Digest>>,
    reading_bodies: HashSet<H::Digest>,
    /// Bodies held in memory.
    hot: hot::Hot<H, B>,

    /// Records held in memory, by commitment: those the order still needs, and recent ones.
    records: HashMap<H::Digest, Arc<TipRecord<H::Digest>>>,
    /// L-QCs held in memory, by identifier.
    lqcs: HashMap<CertificateId<H::Digest>, LqcProof<S, H::Digest>>,
    /// Cut entries held in memory, by L-QC.
    cuts: HashMap<CertificateId<H::Digest>, Arc<CutEntry<H::Digest>>>,
    /// The finality each known L-QC proves.
    facts: HashMap<CertificateId<H::Digest>, Arc<SweepFact<H::Digest>>>,
    /// L-QCs whose facts are being derived.
    extracting: HashSet<CertificateId<H::Digest>>,
    /// The proven positions from the delivered cut.
    order: Order<H::Digest>,
    /// The L-QC the order is fed up to.
    target: Option<Target<H::Digest>>,
    /// Where the order each L-QC proves ends, and the floors delivery closes there.
    ends: ends::Ends<H::Digest>,

    /// The exact last delivered block of every chain.
    delivered: Vec<BlockRef<H::Digest>>,
    /// Final blocks to report ahead of their ordered delivery.
    finals: Finals<H::Digest>,
    /// Whether a final tip, a held block or delivery changed since the reports last advanced.
    finals_dirty: bool,
    /// The acknowledged cut, ahead of [`Meta`] until written.
    acked: Ack<H::Digest>,
    /// Outputs delivered and not yet acknowledged.
    outstanding: usize,

    /// Custody tokens waiting for their blocks to become durable.
    custody: Waiters<H::Digest, ()>,
    /// Subscriptions waiting for their blocks to become durable.
    subscribers: Waiters<H::Digest, Block<H, B>>,
    /// Lookups and fetches waiting for their blocks.
    waiting: Waiters<H::Digest, Option<Block<H, B>>>,
    /// Blocks fetched from peers on request, whether or not they are held.
    fetching: HashSet<BlockRef<H::Digest>>,
    /// Blocks looked up in the broadcast buffer.
    buffering: HashSet<BlockRef<H::Digest>>,
    /// Broadcast-buffer subscriptions, each cancelled by dropping its sender: when its last
    /// subscriber leaves or the block is held.
    subscribing: HashMap<BlockRef<H::Digest>, oneshot::Sender<()>>,

    /// Peer requests being answered.
    serving: usize,
    /// Peer requests waiting for their data to become readable.
    parked: Vec<Request<H::Digest>>,
    /// Requests to peers in flight or waiting for the fetch budget.
    asked: requests::Requests<H::Digest>,
    /// The newest placement run of each chain not yet fetched.
    hints: Vec<Option<(BlockRef<H::Digest>, Height)>>,

    /// The record walk in progress.
    walk: Option<feed::Walk<H::Digest>>,
    /// When consensus last reported a proof.
    last_proof: SystemTime,
    /// When marshal last asked peers for a proof.
    last_ask: Option<SystemTime>,

    /// The newest height each chain released, from durable certificate records.
    released: Vec<Option<Height>>,
    /// The owner of the progress-record write in flight, if any.
    writing: Option<floor::Writer>,
    /// The floor install in progress.
    install: Option<floor::Install<S, H::Digest>>,
    /// Floor and prune requests waiting for answers.
    floor_waiters: Vec<floor::Waiter<S, H::Digest>>,
    /// Certificate requests waiting for answers.
    certificate_waiters: Vec<custody::CertificateWaiter<S, H::Digest>>,
}

impl<E, H, S, B, P, R, V, A> Ledger<E, H, S, B, P, R, V, A>
where
    E: Context + Spawner,
    H: Hasher,
    S: Scheme,
    B: Body<H>,
    P: PublicKey,
    R: Resolver<Key = Key<H::Digest>, Subscriber = ()>,
    V: LqcVerifier<H, S> + Clone,
    A: Reporter<Activity = Update<TransactionBlock<H, B>>>,
{
    /// Creates the owner of `stores`, ordering with the payment chains of `lanes`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: E,
        codec: CodecConfig,
        lanes: Lanes,
        limits: Limits,
        stores: Stores<E, H, S, B>,
        inputs: Inputs<H, S, B>,
        services: Services<P, H, B, R, V, A>,
    ) -> Result<Self, Error> {
        let Stores {
            blocks,
            proofs,
            meta,
        } = stores;
        let state = meta.durable().clone();
        let cut = state
            .ack
            .cut()
            .ok_or_else(|| failed(Cause::Safety("the acknowledged cut is malformed")))?;
        let ordinal = proofs
            .index()
            .ordinal(&state.ack.history)
            .ok_or_else(|| failed(Cause::Safety("the acknowledged history is not stored")))?;
        let capacity = 4 * codec.chains() * codec.pipeline_depth().max(1);
        let metrics = Metrics::new(&context);
        metrics.delivered.set(state.ack.index() as i64);
        metrics.acknowledged.set(state.ack.index() as i64);
        let now = context.current();
        Ok(Self {
            metrics,
            codec,
            blocks,
            proofs,
            mailbox: inputs.mailbox,
            lane: inputs.lane,
            signal: inputs.signal,
            deliveries: inputs.deliveries,
            requests: inputs.requests,
            jobs: Pool::default(),
            acks: FuturesOrdered::new(),
            resolver: services.resolver,
            verifier: services.verifier,
            application: services.application,
            buffer: services.buffer,
            uncut: [0; 2],
            proofs_uncut: 0,
            durability_wanted: false,
            reading: HashSet::new(),
            reading_bodies: HashSet::new(),
            hot: hot::Hot::new(limits.max_hot_bytes.get(), limits.max_block_bytes.get()),
            records: HashMap::new(),
            lqcs: HashMap::new(),
            cuts: HashMap::new(),
            facts: HashMap::new(),
            extracting: HashSet::new(),
            order: Order::new(cut, ordinal, capacity, lanes),
            target: None,
            ends: ends::Ends::new(ordinal),
            delivered: state.ack.emitted.clone(),
            finals: Finals::new(
                limits.final_lookahead,
                &state
                    .ack
                    .emitted
                    .iter()
                    .map(BlockRef::height)
                    .collect::<Vec<_>>(),
            ),
            finals_dirty: false,
            acked: state.ack,
            outstanding: 0,
            custody: HashMap::new(),
            subscribers: HashMap::new(),
            waiting: HashMap::new(),
            fetching: HashSet::new(),
            buffering: HashSet::new(),
            subscribing: HashMap::new(),
            serving: 0,
            parked: Vec::new(),
            asked: requests::Requests::new(deliver::MAX_DEFERRED),
            hints: vec![None; codec.chains()],
            walk: None,
            last_proof: now,
            last_ask: None,
            released: vec![None; codec.chains()],
            writing: None,
            install: None,
            floor_waiters: Vec::new(),
            certificate_waiters: Vec::new(),
            limits,
            meta,
            context,
        })
    }

    /// Runs until the public mailbox closes or a failure stops marshal.
    pub(crate) async fn run(mut self) -> Result<(), Error> {
        loop {
            // The select below is biased, and local inputs (jobs, the mailbox, the feed) can be
            // ready continuously under load: peer traffic takes a bounded turn every iteration so
            // it is never starved, which would leave peers unserved and responses unread.
            for _ in 0..PEER_TURN {
                let Ok(delivered) = self.deliveries.try_recv() else {
                    break;
                };
                self.on_delivered(delivered)?;
            }
            for _ in 0..PEER_TURN {
                let Ok(request) = self.requests.try_recv() else {
                    break;
                };
                self.on_request(request);
            }
            self.drive()?;
            let input = {
                let acks = &mut self.acks;
                let next_ack = async move {
                    if acks.is_empty() {
                        pending::<()>().await;
                    }
                    acks.next().await.expect("acknowledgements are pending")
                };
                select! {
                    event = self.jobs.next_completed() => Input::Event(event),
                    (slot, result) = next_ack => Input::Ack(slot, result),
                    message = self.mailbox.recv() => Input::Message(message),
                    _ = self.signal.recv() => Input::Feed,
                    delivered = self.deliveries.recv() => Input::Delivered(delivered),
                    request = self.requests.recv() => Input::Request(request),
                    _ = self.context.sleep(TICK) => Input::Tick,
                }
            };
            match input {
                Input::Event(event) => self.on_event(event)?,
                Input::Ack(slot, result) => self.on_ack(*slot, result)?,
                Input::Message(Some(message)) => self.on_message(message)?,
                Input::Message(None) => return Ok(()),
                Input::Feed => self.on_feed()?,
                Input::Delivered(Some(delivered)) => self.on_delivered(delivered)?,
                Input::Request(Some(request)) => self.on_request(request),
                Input::Delivered(None) | Input::Request(None) | Input::Tick => {}
            }
        }
    }

    /// Advances every machine as far as its inputs allow.
    fn drive(&mut self) -> Result<(), Error> {
        self.drive_feed()?;
        self.drive_order()?;
        self.drive_dispatch()?;
        self.drive_finals()?;
        self.drive_acquire();
        self.reassert();
        self.drive_walk();
        self.drive_floors()?;
        self.drive_custody();
        self.drive_storage()?;
        self.drive_meta();
        Ok(())
    }

    /// Spawns `job`, turning its result into an event.
    fn spawn<T: Send + 'static>(
        &mut self,
        label: &'static str,
        job: impl std::future::Future<Output = T> + Send + 'static,
        event: impl FnOnce(T) -> Event<E, H, S, B> + Send + 'static,
    ) {
        let handle = self.context.child(label).spawn(move |_| job);
        self.jobs.push(async move {
            match handle.await {
                Ok(result) => event(result),
                Err(error) => Event::Task(error),
            }
        });
    }

    /// Starts every storage job whose log is idle.
    ///
    /// Appends batch while more are queued; a log cuts once its queue drains, after
    /// [`MAX_UNCUT_APPENDS`] appends, or (block streams) when the next output waits only for
    /// durability. Cuts return before their sync completes, so appends continue meanwhile.
    fn drive_storage(&mut self) -> Result<(), Error> {
        for stream in Stream::ALL {
            if !self.blocks.idle(stream) {
                continue;
            }
            let dirty = self.blocks.dirty(stream);
            let cut_first = dirty
                && (self.uncut[stream.index()] >= MAX_UNCUT_APPENDS || self.durability_wanted);
            let max_bytes = (self.limits.max_fetch_bytes.get() as u64).max(APPEND_BYTES);
            let job = if cut_first {
                self.blocks.start_cut(stream).map_err(storage)?
            } else {
                match self.blocks.start_append(stream, max_bytes) {
                    Some(job) => Some(job),
                    None if dirty => self.blocks.start_cut(stream).map_err(storage)?,
                    None => self.blocks.start_reclaim(stream),
                }
            };
            if let Some(job) = job {
                match job {
                    blocks::Job::Append(_) => self.uncut[stream.index()] += 1,
                    blocks::Job::Cut(_) => {
                        self.uncut[stream.index()] = 0;
                        if stream == Stream::Custody {
                            self.metrics.custody_cuts.inc();
                        }
                    }
                    blocks::Job::Reclaim(_) => {}
                }
                self.spawn("blocks", job.run(), move |done| Event::Blocks(stream, done));
            }
        }
        if self.proofs.idle() {
            let dirty = self.proofs.dirty();
            let job = if dirty && self.proofs_uncut >= MAX_UNCUT_APPENDS {
                self.proofs.start_cut().map_err(storage)?
            } else {
                match self.proofs.start_append() {
                    Some(job) => Some(job),
                    None if dirty => self.proofs.start_cut().map_err(storage)?,
                    None => self.proofs.start_reclaim(),
                }
            };
            if let Some(job) = job {
                match job {
                    log::Job::Append(_) => self.proofs_uncut += 1,
                    log::Job::Cut(_) => self.proofs_uncut = 0,
                    log::Job::Reclaim(_) => {}
                }
                self.spawn("proofs", job.run(), Event::Proofs);
            }
        }
        Ok(())
    }

    fn on_event(&mut self, event: Event<E, H, S, B>) -> Result<(), Error> {
        match event {
            Event::Blocks(stream, done) => {
                let done = done.map_err(storage)?;
                match self.blocks.finish(stream, done) {
                    // Appended fetched blocks free fetch budget.
                    blocks::Finished::Appended => self.issue_deferred(),
                    blocks::Finished::Cut(durability) => {
                        self.jobs
                            .push(async move { Event::BlocksDurable(stream, durability.await) });
                    }
                    blocks::Finished::Reclaimed => {}
                }
            }
            Event::BlocksDurable(stream, end) => {
                let end = end.map_err(storage)?;
                self.blocks.mark_durable(stream, end);
                self.retry_parked();
            }
            Event::Proofs(done) => {
                let done = done.map_err(storage)?;
                match self.proofs.finish(done).map_err(storage)? {
                    proofs::Finished::Appended { connected, lqcs } => {
                        self.on_connected(&connected);
                        self.on_indexed(&lqcs);
                    }
                    proofs::Finished::Cut(durability) => {
                        self.jobs
                            .push(async move { Event::ProofsDurable(durability.await) });
                    }
                    proofs::Finished::Reclaimed => {}
                }
            }
            Event::ProofsDurable(end) => {
                let end = end.map_err(storage)?;
                self.proofs.mark_durable(end);
                self.retry_parked();
            }
            Event::Meta(written) => {
                let written = written.map_err(storage)?;
                self.meta.finish(written);
                let writer = self
                    .writing
                    .take()
                    .ok_or_else(|| failed(Cause::Safety("a progress record no write owns")))?;
                self.on_meta_durable(writer)?;
            }
            Event::Body(reference, stream, read) => {
                self.reading_bodies.remove(&reference.digest());
                let Read { value, opened } = read.map_err(storage)?;
                if let Some(opened) = opened {
                    self.blocks.finish_open(stream, opened);
                }
                if value.reference() != reference {
                    return Err(failed(Cause::Safety(
                        "a stored block does not match its index",
                    )));
                }
                self.on_block(value);
            }
            Event::Part(key, read) => {
                self.reading.remove(&key);
                let Read { value, opened } = read.map_err(storage)?;
                if let Some(opened) = opened {
                    self.proofs.finish_open(opened);
                }
                self.on_part(key, value)?;
            }
            Event::Fact(id, fact) => {
                self.extracting.remove(&id);
                match fact {
                    Some(fact) => {
                        // Its end is projected on the next drive.
                        if self.proofs.known(&id.get()) {
                            self.facts.insert(id, fact);
                        }
                    }
                    None => {
                        return Err(failed(Cause::Safety(
                            "a stored L-QC does not prove a sweep",
                        )));
                    }
                }
            }
            Event::Verified(verify, verified) => self.on_verified(verify, verified),
            Event::Buffered(reference, low, block) => self.on_buffered(reference, low, block),
            Event::OpenedBlocks(stream, opened) => {
                self.blocks.finish_open(stream, opened.map_err(storage)?);
                self.retry_parked();
            }
            Event::OpenedProofs(opened) => {
                self.proofs.finish_open(opened.map_err(storage)?);
                self.retry_parked();
            }
            Event::Served => self.serving -= 1,
            Event::Nothing => {}
            Event::Task(error) => return Err(failed(Cause::Task(error))),
        }
        Ok(())
    }

    /// Reads the body of a held block, unless it is being read.
    fn read_body(&mut self, reference: BlockRef<H::Digest>) {
        if self.reading_bodies.contains(&reference.digest()) {
            return;
        }
        let Some(held) = self.blocks.index().get(reference) else {
            return;
        };
        let stream = held.stream;
        let Some((access, (offset, size))) = self.blocks.access(reference) else {
            return;
        };
        let job = match access {
            Access::Ready(reader) => async move {
                Ok(Read {
                    value: reader.get(offset, size).await?,
                    opened: None,
                })
            }
            .boxed(),
            Access::Open(open) => async move {
                let opened = open.run().await?;
                let value = opened.reader().get(offset, size).await?;
                Ok(Read {
                    value,
                    opened: Some(opened),
                })
            }
            .boxed(),
            Access::Opening | Access::Uncut => return,
        };
        self.reading_bodies.insert(reference.digest());
        self.spawn("read_body", job, move |read| {
            Event::Body(reference, stream, read)
        });
    }

    /// Reads a stored part, unless it is being read.
    fn read_part(&mut self, key: PartKey<H::Digest>, stored: Stored) {
        if self.reading.contains(&key) {
            return;
        }
        let (offset, size) = stored.location;
        let job = match self.proofs.access(stored) {
            Access::Ready(reader) => async move {
                Ok(Read {
                    value: reader.get(offset, size).await?,
                    opened: None,
                })
            }
            .boxed(),
            Access::Open(open) => async move {
                let opened = open.run().await?;
                let value = opened.reader().get(offset, size).await?;
                Ok(Read {
                    value,
                    opened: Some(opened),
                })
            }
            .boxed(),
            Access::Opening | Access::Uncut => return,
        };
        self.reading.insert(key);
        self.spawn("read_part", job, move |read| Event::Part(key, read));
    }

    /// Takes a read part into memory.
    fn on_part(&mut self, key: PartKey<H::Digest>, part: Part<S, H::Digest>) -> Result<(), Error> {
        match (key, part) {
            // A part dropped while it was read is not cached again.
            (PartKey::Record(commitment), Part::Record(record)) => {
                if self.proofs.known(&commitment) {
                    self.records.insert(commitment, record);
                }
            }
            (PartKey::Lqc(id), part @ Part::Lqc(_)) => {
                let proof = part
                    .into_proof(id)
                    .ok_or_else(|| failed(Cause::Safety("a stored L-QC part is not an L-QC")))?;
                if self.proofs.known(&id.get()) {
                    self.lqcs.insert(id, proof);
                    if !self.facts.contains_key(&id) {
                        self.extract(id);
                    }
                }
            }
            (PartKey::Cut(id), Part::Cut(cut)) => {
                if self.proofs.index().cut_of(&id).is_some() {
                    self.cuts.insert(id, cut);
                }
            }
            _ => return Err(failed(Cause::Safety("a stored part has the wrong kind"))),
        }
        Ok(())
    }

    /// Takes a block into memory and wakes whatever waits for it.
    fn on_block(&mut self, block: Block<H, B>) {
        let reference = block.reference();
        if let Some(waiters) = self.waiting.remove(&reference) {
            for waiter in waiters {
                let _ = waiter.send(Ok(Some(Arc::clone(&block))));
            }
        }
        self.hot.insert(block);
        self.metrics.hot_bytes.set(self.hot.bytes as i64);
        self.finals_dirty = true;
    }

    /// Queues a block for `stream` and holds its body in memory.
    fn insert_block(&mut self, stream: Stream, block: Block<H, B>) {
        if self.blocks.insert(stream, Arc::clone(&block)) == blocks::Inserted::Refused {
            return;
        }
        self.on_block(block);
    }
}

/// Wraps a cause as a marshal failure.
fn failed(cause: Cause) -> Error {
    Error::Failed(Failure::from(cause))
}

/// Wraps a storage failure.
fn storage(error: StoreError) -> Error {
    failed(Cause::Storage(error))
}
