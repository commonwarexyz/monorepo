//! Certificate recovery for the own producer chain, run on its own task.
//!
//! The voter forwards each own-chain data-availability share once the machine has ordered it and
//! checked its structure, and reports every certified-anchor advance. The task pools shares per
//! header and, once a header holds a quorum, assembles the certificate on the shared strategy and
//! returns it for the machine to admit durably and publish. It never touches durable state and
//! publishes nothing.
//!
//! ```text
//! voter                                        DA recovery task
//!   |-- observe(share) --------------------------->| pool shares per header
//!   |-- anchor_advanced(height) ------------------>| drop settled pools
//!   |                                              | assemble a quorum on the strategy
//!   |<------------------------- DaUpdate(cert) ----|
//! ```
//!
//! The task holds only volatile state. After a restart the voter starts a fresh task seeded with the
//! recovered certified anchor, and the pools refill from re-observed shares.
//!
//! The voter never blocks on the task. The mailbox marks a share at or below the latest certified
//! height it sent as settled, since the task would drop it on arrival. Commands beyond
//! `mailbox_size` wait in a [`DaOverflow`], which drops settled shares and keeps only the latest
//! anchor and reconfiguration and the shares above the anchor, so its size is bounded by the
//! unsettled own-chain shares rather than by how long the task stalls or how many settled shares
//! peers replay or forge.

use super::actor::ChainUpdate;
use crate::{
    multimmit::{
        actors::util::{WorkerPanicked, offload},
        machine::{ChainCommand, Generation},
        scheme::bls12381_threshold::{DaRecoveryError, Scheme},
        types::{BlockRef, ChainId, DaCertificate, DaVote, TransactionBlockHeader},
    },
    types::{Attributable as _, Height, Participant},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy},
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::metrics::{Counter, Histogram, HistogramExt as _},
};
use commonware_utils::futures::Pool;
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
enum DaCommand<V: Variant, D: Digest> {
    /// A command the machine issued for the own chain.
    Chain(ChainCommand<V, D>),
    /// A new process generation began; drop volatile pools and stamp later results with it.
    Reconfigure(Reconfiguration),
    /// A share at or below the latest certified height sent, which the task drops on arrival.
    ///
    /// The mailbox sends this in place of the share, so the task wakes as it would have, and a
    /// full queue drops it instead of retaining the share.
    Settled,
}

/// The process generation and certified own-chain height the task restarts from.
#[derive(Clone, Copy)]
struct Reconfiguration {
    generation: Generation,
    certified: Height,
}

impl<V: Variant, D: Digest> Policy for DaCommand<V, D> {
    type Overflow = DaOverflow<V, D>;

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
/// it settles. The machine forwards an own-chain share once while it retains it and retains it
/// until the certified anchor passes it, so the retained shares are shares the machine still holds,
/// which its artifact cache bounds however long the task stalls.
pub(crate) struct DaOverflow<V: Variant, D: Digest> {
    reconfiguration: Option<Reconfiguration>,
    /// The highest queued certified height.
    anchor: Option<Height>,
    /// Shares above every queued height, in arrival order.
    shares: VecDeque<Arc<DaVote<V, D>>>,
}

impl<V: Variant, D: Digest> Default for DaOverflow<V, D> {
    fn default() -> Self {
        Self {
            reconfiguration: None,
            anchor: None,
            shares: VecDeque::new(),
        }
    }
}

impl<V: Variant, D: Digest> DaOverflow<V, D> {
    /// Retains `command` unless the task would ignore it, dropping what it supersedes.
    fn push(&mut self, command: DaCommand<V, D>) {
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
    fn pop(&mut self) -> Option<DaCommand<V, D>> {
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
    fn unpop(&mut self, command: DaCommand<V, D>) {
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

impl<V: Variant, D: Digest> Overflow<DaCommand<V, D>> for DaOverflow<V, D> {
    fn is_empty(&self) -> bool {
        self.reconfiguration.is_none() && self.anchor.is_none() && self.shares.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(DaCommand<V, D>) -> Option<DaCommand<V, D>>,
    {
        while let Some(command) = self.pop() {
            if let Some(command) = push(command) {
                self.unpop(command);
                break;
            }
        }
    }
}

/// An own-chain certificate assembled by the DA recovery task.
///
/// It carries the task's process generation when the recovery finished, and the voter drops a
/// result from a superseded generation. A recovery still running across a reconfiguration finishes
/// under the new generation, and the machine rechecks it on admission.
pub(crate) struct DaUpdate<V: Variant, D: Digest> {
    /// The process generation the task ran under.
    pub(crate) generation: Generation,
    /// The certified block.
    pub(crate) block: BlockRef<D>,
    /// The recovered certificate.
    pub(crate) certificate: DaCertificate<V, D>,
}

/// Configuration for the DA recovery task.
pub(crate) struct Config<P: PublicKey, V: Variant, D: Digest, T: Strategy> {
    /// Verifies and assembles shares.
    pub(crate) scheme: Arc<Scheme<P, V>>,
    /// Runs recovery cryptography.
    pub(crate) strategy: T,
    /// The chain this validator produces.
    pub(crate) own_chain: ChainId,
    /// Shares that assemble one certificate.
    pub(crate) da_quorum: usize,
    /// Most recoveries kept in flight at once.
    ///
    /// At most pipeline-depth own-chain headers are uncertified above the anchor, so that many
    /// concurrent recoveries suffice and cannot exceed the machine's certificate capacity for the
    /// chain.
    pub(crate) recovery_slots: usize,
    /// Receives assembled certificates.
    pub(crate) updates: mailbox::Sender<ChainUpdate<V, D>>,
    /// Observes recovery latency.
    pub(crate) latency: Histogram,
    /// Counts recoveries that failed and re-armed.
    pub(crate) fallbacks: Counter,
    /// Commands the queue holds before the rest wait in its [`DaOverflow`].
    pub(crate) mailbox_size: NonZeroUsize,
}

/// Commands to the DA recovery task.
pub(crate) struct Mailbox<V: Variant, D: Digest> {
    commands: mailbox::Sender<DaCommand<V, D>>,
    sent: SentHeight,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    /// Records the certified height the task starts above, which settles every share at or below
    /// it.
    pub(crate) const fn started(&mut self, certified: Height) {
        self.sent = SentHeight(certified);
    }

    /// Delivers one command the machine issued for the own chain; a share the task would drop on
    /// arrival goes as [`DaCommand::Settled`].
    pub(crate) fn command(&mut self, command: ChainCommand<V, D>) -> Feedback {
        self.send(DaCommand::Chain(command))
    }

    /// Moves the task to process generation `generation` with certified anchor `certified`.
    pub(crate) fn reconfigure(&mut self, generation: Generation, certified: Height) -> Feedback {
        self.send(DaCommand::Reconfigure(Reconfiguration {
            generation,
            certified,
        }))
    }

    fn send(&mut self, command: DaCommand<V, D>) -> Feedback {
        self.commands.enqueue(self.sent.mark(command))
    }
}

/// The task's certified height once it applies every command sent so far.
///
/// The task drops a share at or below its certified height on arrival. The mailbox replaces such
/// a share with [`DaCommand::Settled`], which a full queue drops: this watermark is what keeps
/// settled shares, replayed or forged, out of a stalled task's queue.
#[derive(Clone, Copy, Default)]
struct SentHeight(Height);

impl SentHeight {
    /// Returns `command`, or [`DaCommand::Settled`] for a share the task would drop on arrival,
    /// recording the height the command sets.
    fn mark<V: Variant, D: Digest>(&mut self, command: DaCommand<V, D>) -> DaCommand<V, D> {
        match &command {
            DaCommand::Chain(ChainCommand::Observe(share)) if share.header().height() <= self.0 => {
                return DaCommand::Settled;
            }
            DaCommand::Chain(ChainCommand::AnchorAdvanced(height)) => {
                self.0 = self.0.max(*height);
            }
            DaCommand::Reconfigure(reconfiguration) => {
                self.0 = reconfiguration.certified;
            }
            DaCommand::Chain(ChainCommand::Observe(_)) | DaCommand::Settled => {}
        }
        command
    }
}

/// One producer header's accumulated shares, keyed in the task by the header digest.
struct VotePool<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    shares: BTreeMap<Participant, Arc<DaVote<V, D>>>,
    /// Signers a failed recovery attributed an invalid share for this header to.
    ///
    /// Shares enter on structural checks alone, so recovery is where an invalid one is discovered.
    /// Remembering the signer keeps a rejected share out of every later selection. Bounded by the
    /// committee.
    rejected: BTreeSet<Participant>,
}

/// One completed recovery dispatch, correlated to its header digest.
struct Recovery<V: Variant, D: Digest> {
    header: D,
    block: BlockRef<D>,
    started_at: SystemTime,
    outcome: RecoveryOutcome<V, D>,
}

/// The outcome of one recovery dispatch.
enum RecoveryOutcome<V: Variant, D: Digest> {
    /// The quorum assembled into a certificate.
    Certificate(DaCertificate<V, D>),
    /// The group check failed and attributed these signers' shares.
    Invalid(Vec<Participant>),
    /// The recovery could not attribute a culprit; the block re-arms and retries.
    Unattributed,
}

/// The task's volatile recovery state for the current process generation.
struct RecoveryState<V: Variant, D: Digest> {
    /// Header digest -> accumulated shares.
    pools: BTreeMap<D, VotePool<V, D>>,
    /// Header digests whose pool reached quorum and awaits a recovery slot.
    ready: BTreeSet<D>,
    /// Header digests with a recovery in flight or already returned to the voter.
    ///
    /// A returned certificate stays here until the voter confirms it through an anchor advance, so
    /// a later share for the same block never re-arms a redundant recovery. It is retired only by
    /// anchor advance (the certificate landed) or by a failed attempt (which re-arms).
    pending: BTreeSet<D>,
    /// The greatest certified own-chain height the voter has reported.
    certified_through: Height,
    /// The process generation stamped on results.
    generation: Generation,
}

impl<V: Variant, D: Digest> RecoveryState<V, D> {
    /// Returns empty state for process generation `generation` above `certified`.
    const fn new(generation: Generation, certified: Height) -> Self {
        Self {
            pools: BTreeMap::new(),
            ready: BTreeSet::new(),
            pending: BTreeSet::new(),
            certified_through: certified,
            generation,
        }
    }

    /// Pools one share of the own chain above the certified height, keeping the first share per
    /// signer that no failed recovery rejected, and returns the digest of the header it pooled
    /// under.
    fn pool<H: Hasher<Digest = D>>(
        &mut self,
        own_chain: ChainId,
        share: &Arc<DaVote<V, D>>,
    ) -> Option<D> {
        let header = share.header();
        if header.chain() != own_chain || header.height() <= self.certified_through {
            return None;
        }
        let digest = header.digest::<H>();
        let pool = self.pools.entry(digest).or_insert_with(|| VotePool {
            header: header.clone(),
            shares: BTreeMap::new(),
            rejected: BTreeSet::new(),
        });
        if pool.header != *header {
            return None;
        }
        let signer = share.signer();
        if !pool.rejected.contains(&signer) {
            pool.shares
                .entry(signer)
                .or_insert_with(|| Arc::clone(share));
        }
        Some(digest)
    }

    /// Advances the certified height to `height` and drops every pool it settles, returning
    /// whether it advanced.
    fn settle(&mut self, height: Height) -> bool {
        if height <= self.certified_through {
            return false;
        }
        self.certified_through = height;
        let settled = self
            .pools
            .iter()
            .filter(|(_, pool)| pool.header.height() <= height)
            .map(|(digest, _)| *digest)
            .collect::<Vec<_>>();
        for digest in settled {
            self.pools.remove(&digest);
            self.ready.remove(&digest);
            self.pending.remove(&digest);
        }
        true
    }
}

/// The DA recovery task before it starts.
pub(crate) struct Actor<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    context: E,
    config: Config<P, V, H::Digest, T>,
    commands: mailbox::Receiver<DaCommand<V, H::Digest>>,
}

impl<E, H, P, V, T> Actor<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    /// Creates the task and its command mailbox.
    pub(crate) fn new(
        context: E,
        config: Config<P, V, H::Digest, T>,
    ) -> (Self, Mailbox<V, H::Digest>) {
        let (commands, receiver) = mailbox::new(context.child("commands"), config.mailbox_size);
        (
            Self {
                context,
                config,
                commands: receiver,
            },
            Mailbox {
                commands,
                sent: SentHeight::default(),
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
        let mut running = Running::<_, H, _, _, _> {
            context: ContextCell::new(context.child("task")),
            config,
            commands,
            state: RecoveryState::new(generation, certified),
        };
        spawn_cell!(running.context, running.run())
    }
}

/// The running DA recovery task.
struct Running<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    context: ContextCell<E>,
    config: Config<P, V, H::Digest, T>,
    commands: mailbox::Receiver<DaCommand<V, H::Digest>>,
    state: RecoveryState<V, H::Digest>,
}

impl<E, H, P, V, T> Running<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    /// Drains commands and recovery completions until the voter drops the mailbox or the runtime
    /// stops.
    async fn run(mut self) {
        let mut recoveries: Pool<'static, Recovery<V, H::Digest>> = Pool::default();
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
        recoveries: &mut Pool<'static, Recovery<V, H::Digest>>,
        command: DaCommand<V, H::Digest>,
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
                self.state = RecoveryState::new(generation, certified);
            }
        }
    }

    fn observe(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<V, H::Digest>>,
        share: &Arc<DaVote<V, H::Digest>>,
    ) {
        let Some(digest) = self.state.pool::<H>(self.config.own_chain, share) else {
            return;
        };
        self.refresh(digest);
        self.drive(recoveries);
    }

    fn advance_anchor(
        &mut self,
        recoveries: &mut Pool<'static, Recovery<V, H::Digest>>,
        height: Height,
    ) {
        if self.state.settle(height) {
            self.drive(recoveries);
        }
    }

    /// Recomputes one pool's recovery readiness.
    fn refresh(&mut self, digest: H::Digest) {
        let state = &mut self.state;
        let ready = state.pools.get(&digest).is_some_and(|pool| {
            pool.header.height() > state.certified_through
                && !state.pending.contains(&digest)
                && pool.shares.len() >= self.config.da_quorum
        });
        if ready {
            state.ready.insert(digest);
        } else {
            state.ready.remove(&digest);
        }
    }

    /// Dispatches ready recoveries up to the in-flight slot bound.
    fn drive(&mut self, recoveries: &mut Pool<'static, Recovery<V, H::Digest>>) {
        let state = &mut self.state;
        while recoveries.len() < self.config.recovery_slots {
            let Some(digest) = state.ready.iter().next().copied() else {
                break;
            };
            state.ready.remove(&digest);
            let Some(pool) = state.pools.get(&digest) else {
                continue;
            };
            if pool.shares.len() < self.config.da_quorum {
                continue;
            }
            let block = pool.header.block_ref::<H>();
            let votes = pool
                .shares
                .values()
                .take(self.config.da_quorum)
                .map(|vote| vote.as_ref().clone())
                .collect::<Vec<_>>();
            state.pending.insert(digest);
            let scheme = Arc::clone(&self.config.scheme);
            let strategy = self.config.strategy.clone();
            let started_at = self.context.current();
            recoveries.push(async move {
                // The group check runs on the shared pool, and a worker panic is reconciled into
                // an unattributed failure rather than escaping the task.
                let weight = votes.len();
                let (_, outcome) = offload(strategy, weight, Span::none(), move |strategy| {
                    scheme.assemble_da_certificate_optimistic(&votes, &strategy)
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
                    block,
                    started_at,
                    outcome,
                }
            });
        }
    }

    /// Applies one recovery completion; breaks once the voter stopped receiving results.
    fn recovered(&mut self, done: Recovery<V, H::Digest>) -> ControlFlow<()> {
        self.config
            .latency
            .observe_between(done.started_at, self.context.current());
        match done.outcome {
            RecoveryOutcome::Certificate(certificate) => {
                // The block stays pending until the voter confirms the anchor, so a later share
                // cannot re-arm a redundant recovery for a block already certified here.
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
                self.state.pending.remove(&done.header);
                self.refresh(done.header);
                ControlFlow::Continue(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Protocol,
            mocks::keys::keys,
            scheme::bls12381_threshold::Scheme,
            types::{CertificateId, EpochGenesis, PathLimits, ThresholdShare},
        },
        types::{Epoch, Participant},
    };
    use commonware_codec::types::lazy::Lazy;
    use commonware_cryptography::{
        Sha256, Signer as _, bls12381::primitives::variant::MinPk,
        ed25519::PrivateKey as Ed25519PrivateKey, sha256::Digest,
    };
    use commonware_math::algebra::Additive as _;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::Runner,
        telemetry::metrics::{MetricsExt as _, histogram},
    };
    use commonware_utils::{TestRng, ordered::Set};
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
            PathLimits::new(2, 2).unwrap(),
            genesis,
        )
        .unwrap()
    }

    /// Builds signer schemes and a verifier over one deterministic threshold sharing.
    fn fixture() -> (
        Vec<Scheme<Ed25519PublicKey, MinPk>>,
        Scheme<Ed25519PublicKey, MinPk>,
    ) {
        let protocol = config();
        let identities = Set::try_from(
            (0..PARTICIPANTS)
                .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let keys = keys::<MinPk>(&mut TestRng::new(7), &protocol, &identities);
        (keys.signers, keys.verifier)
    }

    type Ed25519PublicKey = commonware_cryptography::ed25519::PublicKey;

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
            let (actor, mut da) = Actor::<_, Sha256, _, MinPk, _>::new(
                context.child("da"),
                Config {
                    scheme,
                    strategy: Sequential,
                    own_chain: ChainId::new(0),
                    da_quorum,
                    recovery_slots: 2,
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
                    assert!(verify.verify_da_certificate(&certificate));
                }
                ChainUpdate::DaVoteReady(_) => {
                    panic!("the own-chain recovery task never offers da-vote candidates")
                }
            }
        });
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
            let (actor, mut da) = Actor::<_, Sha256, _, MinPk, _>::new(
                context.child("da"),
                Config {
                    scheme,
                    strategy: Sequential,
                    own_chain: ChainId::new(0),
                    da_quorum,
                    recovery_slots: 2,
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
            let invalid = DaVote::new(header.clone(), wrong.share().clone());
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
                    assert!(verify.verify_da_certificate(&certificate));
                }
                ChainUpdate::DaVoteReady(_) => {
                    panic!("the own-chain recovery task never offers da-vote candidates")
                }
            }
        });
    }

    fn share(height: u64, fork: u8, signer: u32) -> DaCommand<MinPk, Digest> {
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
            ThresholdShare::new(
                Participant::new(signer),
                Lazy::from(<MinPk as Variant>::Signature::zero()),
            ),
        ))))
    }

    fn anchor(height: u64) -> DaCommand<MinPk, Digest> {
        DaCommand::Chain(ChainCommand::AnchorAdvanced(Height::new(height)))
    }

    fn reconfigure(generation: u64, certified: u64) -> DaCommand<MinPk, Digest> {
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

    fn drain_all(overflow: &mut DaOverflow<MinPk, Digest>) -> Vec<Delivered> {
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

    fn pools(state: &RecoveryState<MinPk, Digest>) -> Pools {
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

    fn fresh_state() -> RecoveryState<MinPk, Digest> {
        RecoveryState::new(Generation::new(0), Height::zero())
    }

    /// Applies `command` through the state transitions the running task calls.
    fn apply(state: &mut RecoveryState<MinPk, Digest>, command: DaCommand<MinPk, Digest>) {
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
            }) => *state = RecoveryState::new(generation, certified),
            DaCommand::Settled => {}
        }
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
