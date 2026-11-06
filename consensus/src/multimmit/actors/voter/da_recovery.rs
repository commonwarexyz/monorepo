//! Certificate recovery for the producer's own chain, run on its own task.
//!
//! A producer runs one task for its own chain. The voter forwards each of the chain's
//! data-availability shares once the machine has ordered it and checked its structure, and reports
//! every certified-anchor advance. The task pools shares per header and, once a header holds a
//! quorum, assembles the certificate on the shared strategy and returns it for the machine to
//! admit durably. It never touches durable state and publishes nothing.
//!
//! On a payment chain (see
//! [`Parameters::payment_chain`](crate::multimmit::config::Parameters::payment_chain)) the task
//! keeps pooling the shares of a header it certified after the anchor passes it, for up to the
//! chain's pipeline window of certified heights, and assembles `n - f` of them into a receipt it
//! returns as a [`ReceiptUpdate`]. Receipts are volatile and best effort: a restart, a full
//! queue, or a share lost after its signer recorded the certificate can leave a header without
//! one.
//!
//! ```text
//! voter                                        DA recovery task
//!   |-- observe(share) --------------------------->| pool shares per header
//!   |-- anchor_advanced(height) ------------------>| drop settled pools
//!   |                                              | assemble a quorum on the strategy
//!   |<------------------------- DaUpdate(cert) ----|
//!   |<--------------------- ReceiptUpdate(rcpt) ---| payment chains: n - f shares
//! ```
//!
//! The task holds only volatile state. After a restart the voter starts a fresh task seeded with the
//! recovered certified anchor, and the pools refill from re-observed shares.
//!
//! The voter never blocks on the task. The mailbox marks a share at or below the latest certified
//! height it sent, less the receipt window, as settled, since the task would drop it on arrival. Commands beyond
//! `mailbox_size` wait in a [`DaOverflow`], which drops settled shares and keeps only the latest
//! anchor and reconfiguration and the shares above the anchor, so its size is bounded by the
//! unsettled shares of the chain rather than by how long the task stalls or how many settled shares
//! peers replay or forge.

use super::actor::ChainUpdate;
use crate::{
    multimmit::{
        actors::util::{WorkerPanicked, offload},
        machine::{ChainCommand, Generation},
        scheme::{DaRecoveryError, Generic, Scheme},
        types::{BlockRef, ChainId, DaCertificate, DaVote, TransactionBlockHeader},
    },
    types::{Attributable as _, Height, Participant},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy},
};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, Histogram, HistogramExt as _},
};
use commonware_utils::futures::Pool;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    ops::ControlFlow,
    sync::Arc,
    time::SystemTime,
};
use tracing::Span;

/// A command from the voter to the DA recovery task.
///
/// The machine orders and structurally checks every share before it crosses this boundary. Shares
/// are not authenticated one by one; recovery authenticates the quorum it assembles.
enum DaCommand<S: Scheme, D: Digest> {
    /// A command the machine issued for the chain.
    Chain(ChainCommand<S, D>),
    /// A new process generation began; drop volatile pools and stamp later results with it.
    Reconfigure(Reconfiguration),
    /// A share at or below the latest certified height sent, which the task drops on arrival.
    ///
    /// The mailbox sends this in place of the share, so the task wakes as it would have, and a
    /// full queue drops it instead of retaining the share.
    Settled,
}

/// The process generation and certified height of the chain the task restarts from.
#[derive(Clone, Copy)]
struct Reconfiguration {
    generation: Generation,
    certified: Height,
}

impl<S: Scheme, D: Digest> Policy for DaCommand<S, D> {
    type Overflow = DaOverflow<S, D>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push(message);
    }
}

/// The commands waiting behind a full task queue, reduced to what the task would still act on.
///
/// The task drops every share at or below its certified height, ignores an anchor that does not
/// advance it, and drops all volatile state on a reconfiguration. The overflow applies the same
/// rules as commands arrive: a reconfiguration discards every command queued before it, an anchor
/// at or below the highest queued height is dropped, a higher one replaces it and drops the shares
/// it settles, and a share at or below the highest queued height is dropped.
///
/// It delivers the reconfiguration, the anchor, and then the shares in arrival order. Every
/// retained share sits above every queued height, so delivering it after the anchor changes
/// nothing, and draining the overflow leaves the task with the pools the full command sequence
/// would have.
///
/// # Bound
///
/// The overflow holds at most two control commands (a reconfiguration and an anchor) plus shares
/// above the mailbox watermark and every queued anchor: the mailbox's watermark marks a share at or
/// below the latest height sent before it as settled and the overflow drops it, which excludes
/// settled shares the machine replays or a peer forges, and a later queued anchor drops the shares
/// it settles. The machine forwards a share of the chain once while it retains it and retains it
/// until the certified anchor passes it, so the retained shares are shares the machine still holds,
/// which its artifact cache bounds however long the task stalls.
pub(crate) struct DaOverflow<S: Scheme, D: Digest> {
    reconfiguration: Option<Reconfiguration>,
    /// The highest queued certified height.
    anchor: Option<Height>,
    /// Shares above every queued height, in arrival order.
    shares: VecDeque<Arc<DaVote<S, D>>>,
}

impl<S: Scheme, D: Digest> Default for DaOverflow<S, D> {
    fn default() -> Self {
        Self {
            reconfiguration: None,
            anchor: None,
            shares: VecDeque::new(),
        }
    }
}

impl<S: Scheme, D: Digest> DaOverflow<S, D> {
    /// Retains `command` unless the task would ignore it, dropping what it supersedes.
    fn push(&mut self, command: DaCommand<S, D>) {
        match command {
            DaCommand::Reconfigure(reconfiguration) => {
                *self = Self::default();
                self.reconfiguration = Some(reconfiguration);
            }
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                if self.settles(height) {
                    return;
                }
                self.shares.retain(|share| share.header().height() > height);
                self.anchor = Some(height);
            }
            DaCommand::Chain(ChainCommand::Observe(share)) => {
                if self.settles(share.header().height()) {
                    return;
                }
                self.shares.push_back(share);
            }
            DaCommand::Settled => {}
        }
    }

    /// Returns whether a queued height, which the task applies first, settles `height`.
    fn settles(&self, height: Height) -> bool {
        [
            self.reconfiguration
                .map(|reconfiguration| reconfiguration.certified),
            self.anchor,
        ]
        .into_iter()
        .flatten()
        .any(|certified| height <= certified)
    }

    /// Removes the next command in delivery order.
    fn pop(&mut self) -> Option<DaCommand<S, D>> {
        if let Some(reconfiguration) = self.reconfiguration.take() {
            return Some(DaCommand::Reconfigure(reconfiguration));
        }
        if let Some(height) = self.anchor.take() {
            return Some(DaCommand::Chain(ChainCommand::AnchorAdvanced(height)));
        }
        self.shares
            .pop_front()
            .map(|share| DaCommand::Chain(ChainCommand::Observe(share)))
    }

    /// Returns a command the queue could not take to the front of the delivery order.
    fn unpop(&mut self, command: DaCommand<S, D>) {
        match command {
            DaCommand::Reconfigure(reconfiguration) => {
                self.reconfiguration = Some(reconfiguration);
            }
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => self.anchor = Some(height),
            DaCommand::Chain(ChainCommand::Observe(share)) => self.shares.push_front(share),
            // The overflow never retains one, so none comes back.
            DaCommand::Settled => {}
        }
    }
}

impl<S: Scheme, D: Digest> Overflow<DaCommand<S, D>> for DaOverflow<S, D> {
    fn is_empty(&self) -> bool {
        self.reconfiguration.is_none() && self.anchor.is_none() && self.shares.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(DaCommand<S, D>) -> Option<DaCommand<S, D>>,
    {
        while let Some(command) = self.pop() {
            if let Some(command) = push(command) {
                self.unpop(command);
                break;
            }
        }
    }
}

/// A certificate assembled by the DA recovery task.
///
/// It carries the task's process generation when the recovery finished, and the voter drops a
/// result from a superseded generation. A recovery still running across a reconfiguration finishes
/// under the new generation, and the machine rechecks it on admission.
pub(crate) struct DaUpdate<S: Scheme, D: Digest> {
    /// The process generation the task ran under.
    pub(crate) generation: Generation,
    /// The certified block.
    pub(crate) block: BlockRef<D>,
    /// The recovered certificate.
    pub(crate) certificate: DaCertificate<S, D>,
}

/// A payment chain's receipt assembled by the DA recovery task: a DA certificate counting at least
/// `n - f` signers.
pub(crate) struct ReceiptUpdate<S: Scheme, D: Digest> {
    /// The process generation the task ran under.
    pub(crate) generation: Generation,
    /// The receipt.
    pub(crate) receipt: DaCertificate<S, D>,
}

/// Configuration for the DA recovery task.
pub(crate) struct Config<S: Scheme, D: Digest, T: Strategy> {
    /// Verifies and assembles shares.
    pub(crate) scheme: Arc<Generic<S>>,
    /// Runs recovery cryptography.
    pub(crate) strategy: T,
    /// The chain whose certificates the task recovers.
    pub(crate) chain: ChainId,
    /// Shares that assemble one certificate.
    pub(crate) da_quorum: usize,
    /// Most recoveries kept in flight at once.
    ///
    /// At most a pipeline window of the chain's headers are uncertified above the anchor, so that
    /// many concurrent recoveries suffice and cannot exceed the machine's certificate capacity for
    /// the chain.
    pub(crate) recovery_slots: usize,
    /// Certified heights below the anchor whose shares the task keeps pooling toward a receipt,
    /// or zero when the chain forms no receipts.
    ///
    /// A payment chain's task uses the chain's pipeline window, so it holds the shares of at
    /// most two windows of headers.
    pub(crate) receipt_window: u64,
    /// Receives assembled certificates.
    pub(crate) updates: mailbox::Sender<ChainUpdate<S, D>>,
    /// Observes recovery latency.
    pub(crate) latency: Histogram,
    /// Counts recoveries that failed and re-armed.
    pub(crate) fallbacks: Counter,
    /// Commands the queue holds before the rest wait in its [`DaOverflow`].
    pub(crate) mailbox_size: NonZeroUsize,
}

/// Commands to the DA recovery task.
pub(crate) struct Mailbox<S: Scheme, D: Digest> {
    chain: ChainId,
    commands: mailbox::Sender<DaCommand<S, D>>,
    sent: SentHeight,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    /// Returns the chain whose certificates the task recovers.
    pub(crate) const fn chain(&self) -> ChainId {
        self.chain
    }

    /// Records the certified height the task starts above, which settles every share at or below
    /// it.
    pub(crate) const fn started(&mut self, certified: Height) {
        self.sent.certified = certified;
    }

    /// Delivers one command the machine issued for the chain; a share the task would drop on
    /// arrival goes as [`DaCommand::Settled`].
    pub(crate) fn command(&mut self, command: ChainCommand<S, D>) -> Feedback {
        self.send(DaCommand::Chain(command))
    }

    /// Moves the task to process generation `generation` with certified anchor `certified`.
    pub(crate) fn reconfigure(&mut self, generation: Generation, certified: Height) -> Feedback {
        self.send(DaCommand::Reconfigure(Reconfiguration {
            generation,
            certified,
        }))
    }

    fn send(&mut self, command: DaCommand<S, D>) -> Feedback {
        self.commands.enqueue(self.sent.mark(command))
    }
}

/// The task's certified height once it applies every command sent so far, and its receipt window.
///
/// The task drops a share at or below its certified height less its receipt window on arrival. The
/// mailbox replaces such a share with [`DaCommand::Settled`], which a full queue drops: this
/// watermark is what keeps settled shares, replayed or forged, out of a stalled task's queue.
#[derive(Clone, Copy, Default)]
struct SentHeight {
    certified: Height,
    receipt_window: u64,
}

impl SentHeight {
    /// Returns `command`, or [`DaCommand::Settled`] for a share the task would drop on arrival,
    /// recording the height the command sets.
    fn mark<S: Scheme, D: Digest>(&mut self, command: DaCommand<S, D>) -> DaCommand<S, D> {
        match &command {
            DaCommand::Chain(ChainCommand::Observe(share))
                if share.header().height().get()
                    <= self.certified.get().saturating_sub(self.receipt_window) =>
            {
                return DaCommand::Settled;
            }
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                self.certified = self.certified.max(*height);
            }
            DaCommand::Reconfigure(reconfiguration) => {
                self.certified = reconfiguration.certified;
            }
            DaCommand::Chain(ChainCommand::Observe(_)) | DaCommand::Settled => {}
        }
        command
    }
}

/// One producer header's accumulated shares, keyed in the task by the header digest.
struct VotePool<S: Scheme, D: Digest> {
    header: TransactionBlockHeader<D>,
    shares: BTreeMap<Participant, Arc<DaVote<S, D>>>,
    /// Signers a failed recovery attributed an invalid share for this header to.
    ///
    /// Shares enter on structural checks alone, so recovery is where an invalid one is discovered.
    /// Remembering the signer keeps a rejected share out of every later selection. Bounded by the
    /// committee.
    rejected: BTreeSet<Participant>,
    /// Signers whose shares were part of a recovery that failed without attributing a share.
    ///
    /// A failure no share is blamed for would repeat on the same shares, so every later attempt
    /// includes a share outside this set, and the pool waits for one when it holds none. Shares
    /// that arrive while a recovery runs are not in it. Bounded by the committee.
    tried: BTreeSet<Participant>,
    /// Whether this task certified the header, so its pool may keep collecting toward a receipt
    /// once the anchor passes it.
    certified: bool,
}

impl<S: Scheme, D: Digest> VotePool<S, D> {
    /// Returns whether the pool holds a quorum with a share no unattributed failure has used.
    fn armed(&self, quorum: usize) -> bool {
        self.shares.len() >= quorum
            && self.shares.keys().any(|signer| !self.tried.contains(signer))
    }

    /// Returns the quorum the next recovery assembles and its signers: the shares no
    /// unattributed failure has used first, then the others, each in signer order.
    fn select(&self, quorum: usize) -> (Vec<Participant>, Vec<DaVote<S, D>>) {
        let untried = self
            .shares
            .iter()
            .filter(|(signer, _)| !self.tried.contains(signer));
        let tried = self
            .shares
            .iter()
            .filter(|(signer, _)| self.tried.contains(signer));
        untried
            .chain(tried)
            .take(quorum)
            .map(|(signer, vote)| (*signer, vote.as_ref().clone()))
            .unzip()
    }

    /// Records a recovery over `signers` that failed without attributing a share.
    fn unattributed(&mut self, signers: &[Participant]) {
        self.tried.extend(signers.iter().copied());
    }
}

/// One completed recovery dispatch, correlated to its header digest.
struct Recovery<S: Scheme, D: Digest> {
    header: D,
    /// Whether the dispatch assembled a receipt rather than a certificate.
    receipt: bool,
    block: BlockRef<D>,
    /// Signers of the shares the recovery assembled.
    signers: Vec<Participant>,
    started_at: SystemTime,
    outcome: RecoveryOutcome<S, D>,
}

/// The outcome of one recovery dispatch.
enum RecoveryOutcome<S: Scheme, D: Digest> {
    /// The quorum assembled into a certificate.
    Certificate(DaCertificate<S, D>),
    /// The group check failed and attributed these signers' shares.
    Invalid(Vec<Participant>),
    /// The recovery could not attribute a culprit; the block re-arms and retries.
    Unattributed,
}

/// The task's volatile recovery state for the current process generation.
struct RecoveryState<S: Scheme, D: Digest> {
    /// Header digest -> accumulated shares.
    pools: BTreeMap<D, VotePool<S, D>>,
    /// Header digests whose pool reached quorum and awaits a recovery slot.
    ready: BTreeSet<D>,
    /// Header digests with a recovery in flight or already returned to the voter.
    ///
    /// A returned certificate stays here until the voter confirms it through an anchor advance, so
    /// a later share for the same block never re-arms a redundant recovery. It is retired only by
    /// anchor advance (the certificate landed) or by a failed attempt (which re-arms).
    pending: BTreeSet<D>,
    /// The greatest certified height of the chain the voter has reported.
    certified_through: Height,
    /// The process generation stamped on results.
    generation: Generation,
    /// Certified heights below `certified_through` whose headers keep collecting toward a
    /// receipt; zero when the chain forms no receipts.
    receipt_window: u64,
    /// Header digest -> shares of a header this task certified, at or below `certified_through`
    /// and within the receipt window, that has no receipt yet.
    receipts: BTreeMap<D, VotePool<S, D>>,
    /// Receipt pools that hold a receipt quorum and await a recovery slot.
    receipt_ready: BTreeSet<D>,
    /// Receipt pools with an assembly in flight.
    receipt_pending: BTreeSet<D>,
}

/// Where a pooled share landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pooled<D> {
    /// The pool of a header above the certified height.
    Certificate(D),
    /// The receipt pool of a header this task certified.
    Receipt(D),
}

impl<S: Scheme, D: Digest> RecoveryState<S, D> {
    /// Returns empty state for process generation `generation` above `certified`, keeping
    /// certified headers' shares for `receipt_window` heights.
    const fn new(generation: Generation, certified: Height, receipt_window: u64) -> Self {
        Self {
            pools: BTreeMap::new(),
            ready: BTreeSet::new(),
            pending: BTreeSet::new(),
            certified_through: certified,
            generation,
            receipt_window,
            receipts: BTreeMap::new(),
            receipt_ready: BTreeSet::new(),
            receipt_pending: BTreeSet::new(),
        }
    }

    /// Pools one share of the chain, keeping the first share per signer that no failed recovery
    /// rejected, and returns where it pooled.
    ///
    /// A share above the certified height pools under its header. A share at or below it pools
    /// only into the receipt pool of a header this task certified.
    fn pool<H: Hasher<Digest = D>>(
        &mut self,
        chain: ChainId,
        share: &Arc<DaVote<S, D>>,
    ) -> Option<Pooled<D>> {
        let header = share.header();
        if header.chain() != chain {
            return None;
        }
        let digest = header.digest::<H>();
        let (pool, pooled) = if header.height() <= self.certified_through {
            (self.receipts.get_mut(&digest)?, Pooled::Receipt(digest))
        } else {
            let pool = self.pools.entry(digest).or_insert_with(|| VotePool {
                header: header.clone(),
                shares: BTreeMap::new(),
                rejected: BTreeSet::new(),
                tried: BTreeSet::new(),
                certified: false,
            });
            (pool, Pooled::Certificate(digest))
        };
        if pool.header != *header {
            return None;
        }
        let signer = share.signer();
        if !pool.rejected.contains(&signer) {
            pool.shares
                .entry(signer)
                .or_insert_with(|| Arc::clone(share));
        }
        Some(pooled)
    }

    /// Advances the certified height to `height` and drops every pool it settles, returning
    /// whether it advanced.
    ///
    /// A settled pool whose header this task certified moves to the receipt pools while it stays
    /// within the receipt window, and receipt pools that fall out of the window are dropped.
    fn settle(&mut self, height: Height) -> bool {
        if height <= self.certified_through {
            return false;
        }
        self.certified_through = height;
        let floor = height.get().saturating_sub(self.receipt_window);
        let settled = self
            .pools
            .iter()
            .filter(|(_, pool)| pool.header.height() <= height)
            .map(|(digest, _)| *digest)
            .collect::<Vec<_>>();
        for digest in settled {
            self.ready.remove(&digest);
            self.pending.remove(&digest);
            let Some(mut pool) = self.pools.remove(&digest) else {
                continue;
            };
            if pool.certified && pool.header.height().get() > floor {
                // Failures of certificate attempts say nothing about the receipt's shares.
                pool.tried.clear();
                self.receipts.insert(digest, pool);
            }
        }
        self.receipts
            .retain(|_, pool| pool.header.height().get() > floor);
        let receipts = &self.receipts;
        self.receipt_ready
            .retain(|digest| receipts.contains_key(digest));
        self.receipt_pending
            .retain(|digest| receipts.contains_key(digest));
        true
    }
}

/// The DA recovery task before it starts.
pub(crate) struct Actor<E, H, S, T>
where
    E: Clock + CryptoRng + Spawner + Metrics,
    H: Hasher,
    S: Scheme,
    T: Strategy,
{
    context: E,
    config: Config<S, H::Digest, T>,
    commands: mailbox::Receiver<DaCommand<S, H::Digest>>,
}

impl<E, H, S, T> Actor<E, H, S, T>
where
    E: Clock + CryptoRng + Spawner + Metrics,
    H: Hasher,
    S: Scheme,
    T: Strategy,
{
    /// Creates the task and its command mailbox.
    pub(crate) fn new(
        context: E,
        config: Config<S, H::Digest, T>,
    ) -> (Self, Mailbox<S, H::Digest>) {
        let (commands, receiver) = mailbox::new(context.child("commands"), config.mailbox_size);
        let chain = config.chain;
        let receipt_window = config.receipt_window;
        (
            Self {
                context,
                config,
                commands: receiver,
            },
            Mailbox {
                chain,
                commands,
                sent: SentHeight {
                    certified: Height::zero(),
                    receipt_window,
                },
            },
        )
    }

    /// Starts the task in process generation `generation` above certified anchor `certified`.
    ///
    /// The task lives until the runtime stops or the voter drops the mailbox; later generations
    /// reconfigure it.
    pub(crate) fn start(self, generation: Generation, certified: Height) -> Handle<()> {
        let Self {
            context,
            config,
            commands,
        } = self;
        // The task runs under a `task` child so it and its command queue keep distinct labels.
        let state = RecoveryState::new(generation, certified, config.receipt_window);
        let mut running = Running::<_, H, _, _> {
            context: ContextCell::new(context.child("task")),
            config,
            commands,
            state,
        };
        spawn_cell!(running.context, running.run())
    }
}

/// The running DA recovery task.
struct Running<E, H, S, T>
where
    E: Clock + CryptoRng + Spawner + Metrics,
    H: Hasher,
    S: Scheme,
    T: Strategy,
{
    context: ContextCell<E>,
    config: Config<S, H::Digest, T>,
    commands: mailbox::Receiver<DaCommand<S, H::Digest>>,
    state: RecoveryState<S, H::Digest>,
}

impl<E, H, S, T> Running<E, H, S, T>
where
    E: Clock + CryptoRng + Spawner + Metrics,
    H: Hasher,
    S: Scheme,
    T: Strategy,
{
    /// Drains commands and recovery completions until the voter drops the mailbox or the runtime
    /// stops.
    async fn run(mut self) {
        let mut recoveries: Pool<'static, Recovery<S, H::Digest>> = Pool::default();
        select_loop! {
            self.context,
            on_stopped => {},
            Some(command) = self.commands.recv() else break => {
                self.handle_command(&mut recoveries, command);
            },
            done = recoveries.next_completed() => {
                if self.recovered(done).is_break() {
                    break;
                }
                self.drive(&mut recoveries);
            },
        }
    }

    fn handle_command(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<S, H::Digest>>,
        command: DaCommand<S, H::Digest>,
    ) {
        match command {
            DaCommand::Chain(ChainCommand::Observe(share)) => self.observe(recoveries, &share),
            DaCommand::Settled => {}
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                self.advance_anchor(recoveries, height)
            }
            DaCommand::Reconfigure(Reconfiguration {
                generation,
                certified,
            }) => {
                // Dropping the pools rebuilds the projection from the new generation's re-observed
                // shares. A recovery still running finishes under the new generation, and the
                // machine rechecks it on admission.
                self.state = RecoveryState::new(generation, certified, self.config.receipt_window);
            }
        }
    }

    fn observe(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<S, H::Digest>>,
        share: &Arc<DaVote<S, H::Digest>>,
    ) {
        match self.state.pool::<H>(self.config.chain, share) {
            Some(Pooled::Certificate(digest)) => self.refresh(digest),
            Some(Pooled::Receipt(digest)) => self.refresh_receipt(digest),
            None => return,
        }
        self.drive(recoveries);
    }

    fn advance_anchor(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<S, H::Digest>>,
        height: Height,
    ) {
        if self.state.settle(height) {
            let receipts = self.state.receipts.keys().copied().collect::<Vec<_>>();
            for digest in receipts {
                self.refresh_receipt(digest);
            }
            self.drive(recoveries);
        }
    }

    /// Recomputes one pool's recovery readiness.
    fn refresh(&mut self, digest: H::Digest) {
        let state = &mut self.state;
        let ready = state.pools.get(&digest).is_some_and(|pool| {
            pool.header.height() > state.certified_through
                && !state.pending.contains(&digest)
                && pool.armed(self.config.da_quorum)
        });
        if ready {
            state.ready.insert(digest);
        } else {
            state.ready.remove(&digest);
        }
    }

    /// Recomputes one receipt pool's readiness.
    fn refresh_receipt(&mut self, digest: H::Digest) {
        let state = &mut self.state;
        let ready = self.config.scheme.receipt_quorum();
        let ready = state.receipts.get(&digest).is_some_and(|pool| {
            !state.receipt_pending.contains(&digest) && pool.armed(ready)
        });
        if ready {
            state.receipt_ready.insert(digest);
        } else {
            state.receipt_ready.remove(&digest);
        }
    }

    /// Dispatches ready recoveries up to the in-flight slot bound, certificates before receipts.
    fn drive(&mut self, recoveries: &mut Pool<'static, Recovery<S, H::Digest>>) {
        while recoveries.len() < self.config.recovery_slots {
            let state = &mut self.state;
            let Some(digest) = state.ready.iter().next().copied() else {
                break;
            };
            state.ready.remove(&digest);
            let Some(pool) = state.pools.get(&digest) else {
                continue;
            };
            if !pool.armed(self.config.da_quorum) {
                continue;
            }
            let block = pool.header.block_ref::<H>();
            let (signers, votes) = pool.select(self.config.da_quorum);
            state.pending.insert(digest);
            self.dispatch(recoveries, digest, block, signers, votes, false);
        }
        let quorum = self.config.scheme.receipt_quorum();
        while recoveries.len() < self.config.recovery_slots {
            let state = &mut self.state;
            let Some(digest) = state.receipt_ready.iter().next().copied() else {
                break;
            };
            state.receipt_ready.remove(&digest);
            let Some(pool) = state.receipts.get(&digest) else {
                continue;
            };
            if !pool.armed(quorum) {
                continue;
            }
            let block = pool.header.block_ref::<H>();
            let (signers, votes) = pool.select(quorum);
            state.receipt_pending.insert(digest);
            self.dispatch(recoveries, digest, block, signers, votes, true);
        }
    }

    /// Assembles `votes` into a certificate, or a receipt when `receipt` is set, on the strategy.
    fn dispatch(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<S, H::Digest>>,
        digest: H::Digest,
        block: BlockRef<H::Digest>,
        signers: Vec<Participant>,
        votes: Vec<DaVote<S, H::Digest>>,
        receipt: bool,
    ) {
        let scheme = Arc::clone(&self.config.scheme);
        let strategy = self.config.strategy.clone();
        let mut rng = StdRng::from_rng(self.context.as_mut());
        let started_at = self.context.current();
        recoveries.push(async move {
            // The group check runs on the shared pool, and a worker panic is reconciled into an
            // unattributed failure rather than escaping the task.
            let weight = votes.len();
            let (_, outcome) = offload(strategy, weight, Span::none(), move |strategy| {
                if receipt {
                    scheme.assemble_receipt_optimistic(&mut rng, &votes, &strategy)
                } else {
                    scheme.assemble_da_certificate_optimistic(&mut rng, &votes, &strategy)
                }
            })
            .await;
            let outcome = match outcome {
                Ok(Ok(certificate)) => RecoveryOutcome::Certificate(certificate),
                Ok(Err(DaRecoveryError::InvalidShares(invalid))) => {
                    RecoveryOutcome::Invalid(invalid)
                }
                Ok(Err(DaRecoveryError::Scheme(_))) | Err(WorkerPanicked) => {
                    RecoveryOutcome::Unattributed
                }
            };
            Recovery {
                header: digest,
                receipt,
                block,
                signers,
                started_at,
                outcome,
            }
        });
    }

    /// Applies one recovery completion; breaks once the voter stopped receiving results.
    fn recovered(&mut self, done: Recovery<S, H::Digest>) -> ControlFlow<()> {
        if done.receipt {
            return self.receipted(done);
        }
        self.config
            .latency
            .observe_between(done.started_at, self.context.current());
        match done.outcome {
            RecoveryOutcome::Certificate(certificate) => {
                // The block stays pending until the voter confirms the anchor, so a later share
                // cannot re-arm a redundant recovery for a block already certified here. Its pool
                // then keeps collecting toward a receipt, when the chain forms them.
                if self.state.receipt_window > 0
                    && let Some(pool) = self.state.pools.get_mut(&done.header)
                {
                    pool.certified = true;
                }
                let update = DaUpdate {
                    generation: self.state.generation,
                    block: done.block,
                    certificate,
                };
                if self.config.updates.enqueue(update.into()).accepted() {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                }
            }
            RecoveryOutcome::Invalid(invalid) => {
                self.config.fallbacks.inc();
                if let Some(pool) = self.state.pools.get_mut(&done.header) {
                    for signer in &invalid {
                        pool.shares.remove(signer);
                        pool.rejected.insert(*signer);
                    }
                }
                self.state.pending.remove(&done.header);
                self.refresh(done.header);
                ControlFlow::Continue(())
            }
            RecoveryOutcome::Unattributed => {
                self.config.fallbacks.inc();
                if let Some(pool) = self.state.pools.get_mut(&done.header) {
                    pool.unattributed(&done.signers);
                }
                self.state.pending.remove(&done.header);
                self.refresh(done.header);
                ControlFlow::Continue(())
            }
        }
    }

    /// Applies one receipt assembly's completion; breaks once the voter stopped receiving
    /// results.
    fn receipted(&mut self, done: Recovery<S, H::Digest>) -> ControlFlow<()> {
        let state = &mut self.state;
        state.receipt_pending.remove(&done.header);
        match done.outcome {
            RecoveryOutcome::Certificate(receipt) => {
                // A header receives one receipt; later shares for it are dropped.
                state.receipts.remove(&done.header);
                state.receipt_ready.remove(&done.header);
                let update = ReceiptUpdate {
                    generation: state.generation,
                    receipt,
                };
                return if self.config.updates.enqueue(update.into()).accepted() {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                };
            }
            RecoveryOutcome::Invalid(invalid) => {
                self.config.fallbacks.inc();
                if let Some(pool) = state.receipts.get_mut(&done.header) {
                    for signer in &invalid {
                        pool.shares.remove(signer);
                        pool.rejected.insert(*signer);
                    }
                }
            }
            RecoveryOutcome::Unattributed => {
                self.config.fallbacks.inc();
                if let Some(pool) = state.receipts.get_mut(&done.header) {
                    pool.unattributed(&done.signers);
                }
            }
        }
        self.refresh_receipt(done.header);
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Protocol,
            mocks::Bls,
            scheme::{Generic, bls12381::Aggregate},
            types::{CertificateId, DaAttestation, EpochGenesis, PathLimits},
        },
        types::{Epoch, Participant},
    };
    use commonware_codec::types::lazy::Lazy;
    use commonware_cryptography::{
        Sha256, Signer as _,
        bls12381::primitives::variant::{MinPk, Variant},
        ed25519::PrivateKey as Ed25519PrivateKey,
        sha256::Digest,
    };
    use commonware_math::algebra::Additive as _;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::Runner,
        telemetry::metrics::{MetricsExt as _, histogram},
    };
    use commonware_utils::{TestRng, ordered::Set, test_rng};
    use rand::TryRng as _;
    use std::num::NonZeroUsize;

    const PARTICIPANTS: u32 = 6;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_DA_TASK_TEST";

    fn digest(label: &[u8]) -> Digest {
        Sha256::hash(&[label])
    }

    fn config() -> Protocol<Digest> {
        let epoch = Epoch::new(9);
        let tips = (0..PARTICIPANTS)
            .map(|chain| BlockRef::new(ChainId::new(chain), Height::zero(), digest(b"genesis")))
            .collect();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"leader genesis"),
            CertificateId::new(digest(b"vqc genesis")),
            CertificateId::new(digest(b"lqc genesis")),
            tips,
        )
        .unwrap();
        Protocol::new(
            NAMESPACE,
            PARTICIPANTS as usize,
            (0..PARTICIPANTS).map(Participant::new).collect(),
            PathLimits::new(2, 2),
            genesis,
        )
        .unwrap()
    }

    /// Builds signer schemes and a verifier over one deterministic threshold sharing.
    fn fixture() -> (Vec<Generic<Bls<MinPk>>>, Generic<Bls<MinPk>>) {
        let protocol = config();
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let dealt =
            Bls::<MinPk>::deal(&mut TestRng::new(7), protocol.parameters(), &identities).unwrap();
        (dealt.signers, dealt.verifier)
    }

    fn own_header() -> TransactionBlockHeader<Digest> {
        TransactionBlockHeader::new(
            Epoch::new(9),
            ChainId::new(0),
            Height::new(1),
            digest(b"genesis"),
            digest(b"own body"),
        )
        .unwrap()
    }

    fn latency<E: commonware_runtime::Metrics>(context: &E) -> Histogram {
        context.histogram("latency", "", histogram::Buckets::CRYPTOGRAPHY)
    }

    /// A quorum of shares crossing the task boundary recovers a verifiable certificate.
    #[test]
    fn own_chain_quorum_crosses_the_boundary_and_recovers() {
        Runner::default().start(|context| async move {
            let (signers, verifier) = fixture();
            let da_quorum = verifier.codec_config().da_quorum();
            let scheme = Arc::new(verifier);
            let header = own_header();
            let (updates, mut update_rx) =
                mailbox::new(context.child("updates"), NonZeroUsize::new(64).unwrap());
            let verify = Arc::clone(&scheme);
            let (actor, mut da) = Actor::<_, Sha256, Bls<MinPk>, _>::new(
                context.child("da"),
                Config {
                    scheme,
                    strategy: Sequential,
                    chain: ChainId::new(0),
                    da_quorum,
                    recovery_slots: 2,
                    receipt_window: 0,
                    updates,
                    latency: latency(&context),
                    fallbacks: context.counter("fallbacks", ""),
                    mailbox_size: NonZeroUsize::new(64).unwrap(),
                },
            );
            let _task = actor.start(Generation::new(1), Height::zero());
            for signer in signers.iter().take(da_quorum) {
                let vote = signer.sign_da_vote(header.clone()).unwrap();
                assert!(da.command(ChainCommand::Observe(Arc::new(vote))).accepted());
            }
            match update_rx.recv().await.expect("the task returns a recovery") {
                ChainUpdate::Recovered(DaUpdate {
                    generation,
                    block,
                    certificate,
                }) => {
                    assert_eq!(generation, Generation::new(1));
                    assert_eq!(block, header.block_ref::<Sha256>());
                    assert!(verify.verify_da_certificate(
                        &mut test_rng(),
                        &certificate,
                        &Sequential
                    ));
                }
                ChainUpdate::DaVoteReady(_) | ChainUpdate::Receipt(_) => {
                    panic!("the recovery task returns only a certificate here")
                }
            }
        });
    }

    /// The suite with aggregate DA certificates.
    type Payments = Bls<MinPk, Aggregate>;

    /// Builds signers and a verifier with aggregate DA certificates for an epoch with payments.
    fn payment_fixture() -> (Vec<Generic<Payments>>, Generic<Payments>) {
        let protocol = config();
        let parameters = Arc::new(
            Arc::unwrap_or_clone(Arc::clone(protocol.parameters())).with_payments(true),
        );
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let dealt =
            Bls::<MinPk, Aggregate>::deal(&mut TestRng::new(7), &parameters, &identities).unwrap();
        (dealt.signers, dealt.verifier)
    }

    /// A payment chain's producer keeps pooling the shares of a header it certified after the
    /// anchor passes it, and assembles `n - f` of them into a receipt.
    #[test]
    fn a_payment_producer_assembles_a_receipt_after_its_certificate() {
        Runner::default().start(|context| async move {
            let (signers, verifier) = payment_fixture();
            let da_quorum = verifier.codec_config().da_quorum();
            let receipt_quorum = verifier.receipt_quorum();
            assert!(da_quorum < receipt_quorum);
            let scheme = Arc::new(verifier);
            let header = own_header();
            let (updates, mut update_rx) =
                mailbox::new(context.child("updates"), NonZeroUsize::new(64).unwrap());
            let verify = Arc::clone(&scheme);
            let (actor, mut da) = Actor::<_, Sha256, Bls<MinPk, Aggregate>, _>::new(
                context.child("da"),
                Config {
                    scheme,
                    strategy: Sequential,
                    chain: ChainId::new(0),
                    da_quorum,
                    recovery_slots: 2,
                    receipt_window: 2,
                    updates,
                    latency: latency(&context),
                    fallbacks: context.counter("fallbacks", ""),
                    mailbox_size: NonZeroUsize::new(64).unwrap(),
                },
            );
            let _task = actor.start(Generation::new(1), Height::zero());
            let votes = signers
                .iter()
                .map(|signer| Arc::new(signer.sign_da_vote(header.clone()).unwrap()))
                .collect::<Vec<_>>();
            for vote in &votes[..da_quorum] {
                assert!(da.command(ChainCommand::Observe(Arc::clone(vote))).accepted());
            }
            let Some(ChainUpdate::Recovered(DaUpdate { certificate, .. })) = update_rx.recv().await
            else {
                panic!("the task certifies first");
            };
            assert!(!verify.is_receipt(certificate.certificate()));

            // The machine records the certificate and advances the anchor past the header; the
            // remaining shares arrive late and complete a receipt.
            assert!(
                da.command(ChainCommand::AnchorAdvanced(header.height()))
                    .accepted()
            );
            for vote in &votes[da_quorum..receipt_quorum] {
                assert!(da.command(ChainCommand::Observe(Arc::clone(vote))).accepted());
            }
            let Some(ChainUpdate::Receipt(ReceiptUpdate {
                generation,
                receipt,
            })) = update_rx.recv().await
            else {
                panic!("the task forms a receipt");
            };
            assert_eq!(generation, Generation::new(1));
            assert_eq!(receipt.header(), &header);
            assert_eq!(verify.da_signers(receipt.certificate()), Some(receipt_quorum));
            assert!(verify.verify_receipt(&mut test_rng(), &receipt, &Sequential));
        });
    }

    /// A late share pools toward a receipt only for a header the task certified, within the
    /// receipt window, and only when the chain forms receipts.
    #[test]
    fn late_shares_pool_only_into_certified_headers_within_the_receipt_window() {
        let (signers, _) = fixture();
        let header = own_header();
        let share = |signer: usize| Arc::new(signers[signer].sign_da_vote(header.clone()).unwrap());
        for window in [0, 1] {
            let mut state = RecoveryState::<Bls<MinPk>, Digest>::new(
                Generation::new(0),
                Height::zero(),
                window,
            );
            let Some(Pooled::Certificate(digest)) = state.pool::<Sha256>(ChainId::new(0), &share(0))
            else {
                panic!("a share above the anchor pools for a certificate");
            };
            state.pools.get_mut(&digest).unwrap().certified = true;
            assert!(state.settle(header.height()));
            let late = state.pool::<Sha256>(ChainId::new(0), &share(1));
            if window == 0 {
                assert_eq!(late, None, "a chain without receipts drops late shares");
                continue;
            }
            assert_eq!(late, Some(Pooled::Receipt(digest)));
            assert_eq!(state.receipts[&digest].shares.len(), 2);

            // A header past the window is dropped, and later shares for it with it.
            assert!(state.settle(header.height().next()));
            assert!(state.receipts.is_empty());
            assert_eq!(state.pool::<Sha256>(ChainId::new(0), &share(2)), None);
        }

        // A header the task did not certify, such as one certified elsewhere, forms no receipt.
        let mut state =
            RecoveryState::<Bls<MinPk>, Digest>::new(Generation::new(0), Height::zero(), 2);
        state.pool::<Sha256>(ChainId::new(0), &share(0));
        assert!(state.settle(header.height()));
        assert!(state.receipts.is_empty());
        assert_eq!(state.pool::<Sha256>(ChainId::new(0), &share(1)), None);
    }

    /// The mailbox settles a share only below the receipt window under the latest anchor.
    #[test]
    fn the_mailbox_passes_late_shares_within_the_receipt_window() {
        let late = || share(1, 0, 1);
        for (window, passes) in [(0, false), (1, true)] {
            let mut sent = SentHeight {
                certified: Height::zero(),
                receipt_window: window,
            };
            assert!(matches!(sent.mark(anchor(1)), DaCommand::Chain(_)));
            let marked = sent.mark(late());
            assert_eq!(!matches!(marked, DaCommand::Settled), passes, "window {window}");
            // Once the anchor passes the window, the share is settled either way.
            sent.mark(anchor(2));
            assert!(matches!(sent.mark(late()), DaCommand::Settled));
        }
    }

    /// A rejected share re-arms a fresh quorum that excludes its signer.
    #[test]
    fn rejected_share_re_arms_a_quorum_excluding_the_signer() {
        Runner::default().start(|context| async move {
            let (signers, verifier) = fixture();
            let da_quorum = verifier.codec_config().da_quorum();
            let scheme = Arc::new(verifier);
            let header = own_header();
            let (updates, mut update_rx) =
                mailbox::new(context.child("updates"), NonZeroUsize::new(64).unwrap());
            let verify = Arc::clone(&scheme);
            let (actor, mut da) = Actor::<_, Sha256, Bls<MinPk>, _>::new(
                context.child("da"),
                Config {
                    scheme,
                    strategy: Sequential,
                    chain: ChainId::new(0),
                    da_quorum,
                    recovery_slots: 2,
                    receipt_window: 0,
                    updates,
                    latency: latency(&context),
                    fallbacks: context.counter("fallbacks", ""),
                    mailbox_size: NonZeroUsize::new(64).unwrap(),
                },
            );
            let _task = actor.start(Generation::new(1), Height::zero());
            // The culprit's share is structurally valid but signs the wrong subject, so the
            // group check fails and the task attributes exactly its signer. A fresh signer then
            // completes a quorum that excludes the rejected culprit.
            let culprit_index = da_quorum - 1;
            let replacement_index = da_quorum;
            let wrong = signers[culprit_index]
                .sign_da_vote(
                    TransactionBlockHeader::new(
                        Epoch::new(9),
                        ChainId::new(0),
                        Height::new(2),
                        digest(b"genesis"),
                        digest(b"other body"),
                    )
                    .unwrap(),
                )
                .unwrap();
            let invalid = DaVote::new(header.clone(), wrong.attestation().clone());
            for signer in signers.iter().take(da_quorum - 1) {
                let vote = signer.sign_da_vote(header.clone()).unwrap();
                assert!(da.command(ChainCommand::Observe(Arc::new(vote))).accepted());
            }
            assert!(
                da.command(ChainCommand::Observe(Arc::new(invalid)))
                    .accepted()
            );
            // A fresh signer re-arms a quorum that excludes the rejected culprit.
            let replacement = signers[replacement_index]
                .sign_da_vote(header.clone())
                .unwrap();
            assert!(
                da.command(ChainCommand::Observe(Arc::new(replacement)))
                    .accepted()
            );
            match update_rx
                .recv()
                .await
                .expect("the task recovers after re-arming")
            {
                ChainUpdate::Recovered(DaUpdate {
                    block, certificate, ..
                }) => {
                    assert_eq!(block, header.block_ref::<Sha256>());
                    assert!(verify.verify_da_certificate(
                        &mut test_rng(),
                        &certificate,
                        &Sequential
                    ));
                }
                ChainUpdate::DaVoteReady(_) | ChainUpdate::Receipt(_) => {
                    panic!("the recovery task returns only a certificate here")
                }
            }
        });
    }

    fn share(height: u64, fork: u8, signer: u32) -> DaCommand<Bls<MinPk>, Digest> {
        let header = TransactionBlockHeader::new(
            Epoch::new(9),
            ChainId::new(0),
            Height::new(height),
            digest(&(height - 1).to_be_bytes()),
            digest(&[&height.to_be_bytes()[..], &[fork]].concat()),
        )
        .unwrap();
        DaCommand::Chain(ChainCommand::Observe(Arc::new(DaVote::new(
            header,
            DaAttestation::<Bls<MinPk>> {
                signer: Participant::new(signer),
                signature: Lazy::from(<MinPk as Variant>::Signature::zero()),
            },
        ))))
    }

    fn anchor(height: u64) -> DaCommand<Bls<MinPk>, Digest> {
        DaCommand::Chain(ChainCommand::AnchorAdvanced(Height::new(height)))
    }

    fn reconfigure(generation: u64, certified: u64) -> DaCommand<Bls<MinPk>, Digest> {
        DaCommand::Reconfigure(Reconfiguration {
            generation: Generation::new(generation),
            certified: Height::new(certified),
        })
    }

    /// A command's kind and the height it names, for asserting delivery order.
    #[derive(Debug, PartialEq, Eq)]
    enum Delivered {
        Reconfigure(u64),
        Anchor(u64),
        Observe(u64),
        Settled,
    }

    fn drain_all(overflow: &mut DaOverflow<Bls<MinPk>, Digest>) -> Vec<Delivered> {
        let mut delivered = Vec::new();
        overflow.drain(|command| {
            delivered.push(match command {
                DaCommand::Reconfigure(reconfiguration) => {
                    Delivered::Reconfigure(reconfiguration.certified.get())
                }
                DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                    Delivered::Anchor(height.get())
                }
                DaCommand::Chain(ChainCommand::Observe(share)) => {
                    Delivered::Observe(share.header().height().get())
                }
                DaCommand::Settled => Delivered::Settled,
            });
            None
        });
        delivered
    }

    /// The pools a recovery state keeps: its generation, certified height, and the signers
    /// pooled per header.
    #[derive(Debug, PartialEq, Eq)]
    struct Pools {
        generation: u64,
        certified: u64,
        signers: BTreeMap<Digest, BTreeSet<Participant>>,
    }

    fn pools(state: &RecoveryState<Bls<MinPk>, Digest>) -> Pools {
        Pools {
            generation: state.generation.get(),
            certified: state.certified_through.get(),
            signers: state
                .pools
                .iter()
                .map(|(digest, pool)| (*digest, pool.shares.keys().copied().collect()))
                .collect(),
        }
    }

    fn fresh_state() -> RecoveryState<Bls<MinPk>, Digest> {
        RecoveryState::new(Generation::new(0), Height::zero(), 0)
    }

    /// Applies `command` through the state transitions the running task calls.
    fn apply(
        state: &mut RecoveryState<Bls<MinPk>, Digest>,
        command: DaCommand<Bls<MinPk>, Digest>,
    ) {
        match command {
            DaCommand::Chain(ChainCommand::Observe(share)) => {
                state.pool::<Sha256>(ChainId::new(0), &share);
            }
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                state.settle(height);
            }
            DaCommand::Reconfigure(Reconfiguration {
                generation,
                certified,
            }) => *state = RecoveryState::new(generation, certified, state.receipt_window),
            DaCommand::Settled => {}
        }
    }

    #[test]
    fn an_unattributed_failure_waits_for_a_share_it_did_not_use() {
        let (signers, verifier) = fixture();
        let quorum = verifier.codec_config().da_quorum();
        assert!(signers.len() >= quorum + 2);
        let header = own_header();
        let mut state = fresh_state();
        let add = |state: &mut RecoveryState<_, _>, index: usize| {
            let vote = Arc::new(signers[index].sign_da_vote(header.clone()).unwrap());
            match state.pool::<Sha256>(ChainId::new(0), &vote).unwrap() {
                Pooled::Certificate(digest) => digest,
                Pooled::Receipt(_) => panic!("shares above the anchor pool for a certificate"),
            }
        };
        // The highest signers form the first quorum.
        let mut digest = None;
        for index in signers.len() - quorum..signers.len() {
            digest = Some(add(&mut state, index));
        }
        let digest = digest.unwrap();
        let pool = &state.pools[&digest];
        assert!(pool.armed(quorum));
        let (first, _) = pool.select(quorum);

        // A lower signer's share arrives while that recovery runs, then it fails unattributed:
        // the new share was not used, so the pool stays armed and the retry includes it.
        let late = signers.len() - quorum - 1;
        add(&mut state, late);
        let pool = state.pools.get_mut(&digest).unwrap();
        pool.unattributed(&first);
        assert!(pool.armed(quorum));
        let (second, votes) = pool.select(quorum);
        assert_eq!(votes.len(), quorum);
        assert!(second.contains(&Participant::from_usize(late)));

        // Once every held share was used by a failure, the pool waits for another one.
        pool.unattributed(&second);
        assert!(!pool.armed(quorum));
        let lower = signers.len() - quorum - 2;
        add(&mut state, lower);
        let pool = &state.pools[&digest];
        assert!(pool.armed(quorum));
        assert!(pool.select(quorum).0.contains(&Participant::from_usize(lower)));
    }

    #[test]
    fn overflow_keeps_the_highest_height_and_the_shares_above_it() {
        let mut overflow = DaOverflow::default();
        for command in [
            anchor(2),
            share(1, 0, 0),
            share(3, 0, 1),
            anchor(1),
            anchor(4),
            share(5, 0, 2),
        ] {
            Policy::handle(&mut overflow, command);
        }
        assert_eq!(
            drain_all(&mut overflow),
            [Delivered::Anchor(4), Delivered::Observe(5)]
        );

        for command in [anchor(6), share(7, 0, 0), reconfigure(1, 1), share(2, 0, 3)] {
            Policy::handle(&mut overflow, command);
        }
        assert_eq!(
            drain_all(&mut overflow),
            [Delivered::Reconfigure(1), Delivered::Observe(2)]
        );
        assert!(overflow.is_empty());
    }

    #[test]
    fn overflow_stays_bounded_while_the_task_stalls() {
        const PIPELINE: u64 = 2;
        let mut overflow = DaOverflow::default();
        for height in PIPELINE + 1..=2_000u64 {
            for signer in 0..PARTICIPANTS {
                Policy::handle(&mut overflow, share(height, 0, signer));
            }
            Policy::handle(&mut overflow, anchor(height - PIPELINE));
            assert!(overflow.reconfiguration.is_none() && overflow.anchor.is_some());
            assert!(
                overflow.shares.len() <= (PARTICIPANTS as usize) * PIPELINE as usize,
                "only shares above the newest anchor are retained"
            );
        }
    }

    #[test]
    fn drained_overflow_leaves_the_task_pools_of_the_full_sequence() {
        for seed in 0..1_000u64 {
            let commands = |seed| {
                let mut rng = TestRng::new(seed);
                let mut draw = |bound: u32| rng.try_next_u32().unwrap() % bound;
                let mut generation = 0;
                (0..48)
                    .map(|_| match draw(10) {
                        0..=5 => share(u64::from(draw(10)) + 1, draw(2) as u8, draw(PARTICIPANTS)),
                        6..=8 => anchor(u64::from(draw(11))),
                        _ => {
                            generation += 1;
                            reconfigure(generation, u64::from(draw(5)))
                        }
                    })
                    .collect::<Vec<_>>()
            };
            let mut expected = fresh_state();
            for command in commands(seed) {
                apply(&mut expected, command);
            }

            // Every command the mailbox admits after the first `ready` waits in the overflow while
            // the task stalls.
            let mut rng = TestRng::new(seed ^ 0x5eed);
            let ready = rng.try_next_u32().unwrap() as usize % 8;
            let mut sent = SentHeight::default();
            let mut stalled = fresh_state();
            let mut overflow = DaOverflow::default();
            for (index, command) in commands(seed).into_iter().enumerate() {
                let command = sent.mark(command);
                if index < ready {
                    apply(&mut stalled, command);
                } else {
                    Policy::handle(&mut overflow, command);
                }
            }
            overflow.drain(|command| {
                apply(&mut stalled, command);
                None
            });
            assert_eq!(pools(&stalled), pools(&expected), "seed {seed}");
        }
    }

    #[test]
    fn settled_shares_never_queue_behind_a_stalled_task() {
        let mut expected = fresh_state();
        let mut stalled = fresh_state();
        let mut sent = SentHeight::default();
        let mut overflow = DaOverflow::default();

        // The task received the anchor already, so no height stays queued in the overflow.
        apply(&mut expected, anchor(50));
        apply(&mut stalled, sent.mark(anchor(50)));

        // Settled shares, replayed or forged for headers that never existed, never queue.
        for index in 0..10_000u32 {
            let height = u64::from(index % 50) + 1;
            let settled = || share(height, (index % 7) as u8, index % PARTICIPANTS);
            apply(&mut expected, settled());
            Policy::handle(&mut overflow, sent.mark(settled()));
            assert!(overflow.is_empty());
        }

        // An unsettled share still queues, and the drained task matches the full sequence.
        apply(&mut expected, share(51, 0, 0));
        Policy::handle(&mut overflow, sent.mark(share(51, 0, 0)));
        assert_eq!(overflow.shares.len(), 1);
        overflow.drain(|command| {
            apply(&mut stalled, command);
            None
        });
        assert_eq!(pools(&stalled), pools(&expected));
    }
}
