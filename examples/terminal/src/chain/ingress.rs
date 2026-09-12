//! Bounded transaction qualification, gossip, and proposal reservations.
//!
//! Authenticated peers share ordinary/recovery raw allowances per network key;
//! public submissions share two allowances. One supervised shared-runtime job
//! decodes and trials canonical state before reserving deployment capacity.
//! Queued and leased entries share fixed byte/count budgets and retention.
//! Execution remains authoritative when a qualified request becomes stale.

use crate::{
    chain::{
        app::Finalized,
        native::NativeGenesis,
        registry::RegistryView,
        state::{self, Preflight, ProofAction},
        tx::SettlementTx,
        types::{Block, Database, MAX_TX_BYTES},
    },
    protocol::Timing,
};
use anyhow::Context as _;
use bytes::{Buf, Bytes};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver as MailboxReceiver, Sender as MailboxSender},
};
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _, ReadExt as _};
use commonware_consensus::{Reporter, marshal::Update};
use commonware_cryptography::{Hasher as _, Sha256, ed25519, sha256::Digest};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{ContextCell, Handle, IoBuf, Spawner, spawn_cell};
use commonware_storage::Context as StorageContext;
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt as _, oneshot},
    ordered::Set,
};
use futures::FutureExt as _;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::Arc,
};

/// Serves pending settlement transactions to block proposals.
///
/// Handles are cloned per proposal, so they must be cheap to clone.
pub(crate) trait Provider: Clone + Send + Sync + 'static {
    /// Returns at most `max` pending transactions whose aggregate encoded
    /// size is at most `budget`. Other entries remain available for later drains.
    fn drain(
        &mut self,
        max: usize,
        budget: usize,
    ) -> impl Future<Output = Vec<SettlementTx>> + Send;
}

/// No-op provider for a node that never proposes blocks.
impl Provider for () {
    async fn drain(&mut self, _: usize, _: usize) -> Vec<SettlementTx> {
        Vec::new()
    }
}

/// Ingress actor configuration. Each registered deployment owns two lane
/// budgets, and native traffic owns one additional lane budget.
pub(crate) struct Config {
    /// Mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
    /// Maximum transactions retained per deployment and traffic class,
    /// including outstanding proposal leases.
    pub(crate) capacity: NonZeroUsize,
    /// Maximum aggregate encoded bytes per deployment and traffic class,
    /// including outstanding proposal leases.
    pub(crate) bytes: NonZeroUsize,
    /// Finalized blocks a drained transaction stays leased before it is
    /// re-offered to proposals. Must be positive and less than `retention`.
    pub(crate) lease: u64,
    /// Finalized blocks an entry may remain from intake, across all leases.
    pub(crate) retention: u64,
}

/// Advisory result of one unauthenticated local submission. Accepted entries
/// are eligible for gossip and proposal attempts during their retention window;
/// inclusion and execution success are not promised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Submission {
    /// Queued for upcoming proposals and gossiped to peers.
    Accepted,
    /// Already retained, queued or leased.
    Duplicate,
    /// The encoding exceeds the per-transaction wire bound.
    Oversized,
    /// Capacity or canonical eligibility is unavailable. Retry later.
    Full,
}

impl commonware_codec::Write for Submission {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        let tag: u8 = match self {
            Self::Accepted => 0,
            Self::Duplicate => 1,
            Self::Oversized => 2,
            Self::Full => 3,
        };
        tag.write(buf);
    }
}

impl commonware_codec::EncodeSize for Submission {
    fn encode_size(&self) -> usize {
        1
    }
}

impl commonware_codec::Read for Submission {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Accepted),
            1 => Ok(Self::Duplicate),
            2 => Ok(Self::Oversized),
            3 => Ok(Self::Full),
            tag => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

/// A message sent to the ingress [`Actor`].
pub(crate) enum Message<A: Acknowledgement> {
    /// A local (RPC) submission.
    Submit {
        bytes: IoBuf,
        response: oneshot::Sender<anyhow::Result<Submission>>,
    },
    /// A proposal borrowing pending transactions: at most `max`, within an
    /// aggregate encoded-byte `budget`.
    Drain {
        max: usize,
        budget: usize,
        response: oneshot::Sender<Vec<SettlementTx>>,
    },
    /// A finalized block from the marshal reporter stream.
    Finalized { block: Arc<Block>, response: A },
}

impl<A: Acknowledgement> Policy for Message<A> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        match message {
            Self::Submit { response, .. } => {
                response.send_lossy(Ok(Submission::Full));
            }
            control => overflow.push_back(control),
        }
    }
}

/// Inbox for the ingress [`Actor`].
pub(crate) struct Mailbox<A: Acknowledgement = Exact> {
    sender: MailboxSender<Message<A>>,
}

impl<A: Acknowledgement> Clone for Mailbox<A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<A: Acknowledgement> Mailbox<A> {
    /// Submits owned bytes for bounded qualification. Acceptance is advisory.
    pub(crate) async fn submit_raw(&self, bytes: IoBuf) -> anyhow::Result<Submission> {
        if bytes.remaining() > MAX_TX_BYTES {
            return Ok(Submission::Oversized);
        }
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Submit { bytes, response });
        receiver.await.context("ingress actor stopped")?
    }
}

impl<A: Acknowledgement> Provider for Mailbox<A> {
    async fn drain(&mut self, max: usize, budget: usize) -> Vec<SettlementTx> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Drain {
            max,
            budget,
            response,
        });
        receiver.await.unwrap_or_default()
    }
}

impl<A: Acknowledgement> Reporter for Mailbox<A> {
    type Activity = Update<Block, A>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        let Update::Block(block, response) = update else {
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized { block, response })
    }
}

/// Separate reserves for normal settlement work and permissionless recovery.
/// A missing deployment identifies native transfers and registry admission.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct LaneId {
    deployment: Option<Digest>,
    recovery: bool,
}

/// One retained transaction, whether queued or borrowed by a proposal.
struct Entry {
    digest: Digest,
    action: Option<ProofAction>,
    tx: SettlementTx,
    /// Finalized height at which retention ends, independent of lease renewals.
    expiry: u64,
    lease: Option<u64>,
}

#[derive(Default)]
struct Lane {
    entries: VecDeque<Entry>,
    bytes: usize,
}

// Raw budgets include the running job. The fixed committee and bounded registry
// bound authenticated origins; public callers have one shared origin.
const RAW_COUNT: usize = 4;
const RAW_BYTES: usize = 2 * MAX_TX_BYTES;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Origin {
    peer: Option<ed25519::PublicKey>,
    recovery: bool,
}

struct Raw {
    bytes: IoBuf,
    expiry: u64,
    response: Option<oneshot::Sender<anyhow::Result<Submission>>>,
}

#[derive(Default)]
struct Staging {
    queued: VecDeque<Raw>,
    count: usize,
    bytes: usize,
}

struct Qualified {
    tx: SettlementTx,
    encoded: Bytes,
    digest: Digest,
    action: Option<ProofAction>,
}

struct Active {
    origin: Origin,
    size: usize,
    expiry: u64,
    response: Option<oneshot::Sender<anyhow::Result<Submission>>>,
    handle: Handle<anyhow::Result<Option<Qualified>>>,
}

/// The fixed codec tag determines only a raw scheduling class, never authority.
const fn recovery(tag: u8) -> Option<bool> {
    match tag {
        1 | 4..=9 => Some(true),
        0 | 2 | 3 | 10..=12 => Some(false),
        _ => None,
    }
}

/// The ingress actor: bounded deduplicating deployment queues fed by the p2p
/// channel and the local mailbox, drained by proposals, and retired by the
/// finalized stream.
pub(crate) struct Actor<E, A = Exact>
where
    E: StorageContext + Spawner,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    mailbox: MailboxReceiver<Message<A>>,
    registry: RegistryView,
    capacity: usize,
    /// Maximum aggregate encoded bytes retained by one lane.
    bytes: usize,
    lease: u64,
    retention: u64,
    lanes: BTreeMap<LaneId, Lane>,
    /// The first lane considered by the next proposal drain.
    next: Option<LaneId>,
    staging: BTreeMap<Origin, Staging>,
    ready: VecDeque<Origin>,
    /// Latest finalized height observed from the reporter stream.
    height: u64,
    #[cfg(test)]
    completed: Option<commonware_utils::channel::mpsc::Sender<()>>,
}

impl<E, A> Actor<E, A>
where
    E: StorageContext + Spawner,
    A: Acknowledgement,
{
    /// Creates bounded proposal queues against the canonical membership view.
    pub(crate) fn new(context: E, config: Config, registry: RegistryView) -> (Self, Mailbox<A>) {
        assert!(
            config.lease > 0 && config.retention > config.lease,
            "retention must exceed a positive proposal lease"
        );
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                registry,
                capacity: config.capacity.get(),
                bytes: config.bytes.get(),
                lease: config.lease,
                retention: config.retention,
                lanes: BTreeMap::new(),
                next: None,
                staging: BTreeMap::new(),
                ready: VecDeque::new(),
                height: 0,
                #[cfg(test)]
                completed: None,
            },
            Mailbox { sender },
        )
    }

    /// Observes actual worker completion for deterministic causal tests.
    #[cfg(test)]
    pub(crate) fn observe_completion(
        &mut self,
        completed: commonware_utils::channel::mpsc::Sender<()>,
    ) {
        self.completed = Some(completed);
    }

    /// Starts qualification after the canonical databases are subscribed.
    pub(crate) fn start<Se, Re>(
        mut self,
        chan: (Se, Re),
        db: Database<E>,
        finalized: Finalized,
        native: NativeGenesis,
        timing: Timing,
        committee: Set<ed25519::PublicKey>,
    ) -> Handle<()>
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        spawn_cell!(
            self.context,
            self.run(chan, db, finalized, native, timing, committee)
        )
    }

    async fn run<Se, Re>(
        mut self,
        (mut sender, mut receiver): (Se, Re),
        db: Database<E>,
        finalized: Finalized,
        native: NativeGenesis,
        timing: Timing,
        committee: Set<ed25519::PublicKey>,
    ) where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        let native = Arc::new(native);
        self.height = finalized.latest().map_or(0, |tip| tip.height);
        let mut active: Option<Active> = None;
        loop {
            // Each ready source receives one turn before another blocking select.
            // A continuously ready mailbox or network cannot starve completion.
            let mut progressed = false;
            if let Some(job) = active.as_mut()
                && let Some(result) = (&mut job.handle).now_or_never()
            {
                let job = active.take().expect("completed job exists");
                self.complete(job, result, &mut sender);
                progressed = true;
            }
            if let Some(message) = self.mailbox.recv().now_or_never() {
                let Some(message) = message else { return };
                self.message(message);
                progressed = true;
            }
            if let Some(message) = receiver.recv().now_or_never() {
                let Ok((peer, bytes)) = message else { return };
                if committee.position(&peer).is_some() || self.registry.contains_peer(&peer) {
                    self.stage(Some(peer), bytes, None);
                }
                progressed = true;
            }
            if active.is_none()
                && let Some(origin) = self.ready.pop_front()
            {
                let lane = self.staging.get_mut(&origin).expect("ready origin exists");
                let raw = lane.queued.pop_front().expect("ready origin has work");
                if !lane.queued.is_empty() {
                    self.ready.push_back(origin.clone());
                }
                let size = raw.bytes.remaining();
                let db = db.clone();
                let finalized = finalized.clone();
                let native = native.clone();
                let handle =
                    self.context
                        .child("qualification")
                        .shared(true)
                        .spawn(move |_| async move {
                            let Ok(tx) = SettlementTx::decode_cfg(raw.bytes, &()) else {
                                return Ok(None);
                            };
                            let Preflight::Eligible { action } =
                                state::preflight(&db, &finalized, &native, &timing, &tx).await?
                            else {
                                return Ok(None);
                            };
                            let encoded = tx.encode();
                            let digest = Sha256::hash(&[&encoded]);
                            Ok(Some(Qualified {
                                tx,
                                encoded,
                                digest,
                                action,
                            }))
                        });
                active = Some(Active {
                    origin,
                    size,
                    expiry: raw.expiry,
                    response: raw.response,
                    handle,
                });
                progressed = true;
            }

            // Ready intake must yield so the shared qualification worker can run.
            if progressed {
                commonware_runtime::reschedule().await;
                continue;
            }
            select! {
                result = async {
                    match active.as_mut() {
                        Some(job) => (&mut job.handle).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let job = active.take().expect("completed job exists");
                    self.complete(job, result, &mut sender);
                },
                message = self.mailbox.recv() => {
                    let Some(message) = message else { return };
                    self.message(message);
                },
                message = receiver.recv() => {
                    let Ok((peer, bytes)) = message else { return };
                    if committee.position(&peer).is_some() || self.registry.contains_peer(&peer) {
                        self.stage(Some(peer), bytes, None);
                    }
                },
            }
        }
    }

    fn message(&mut self, message: Message<A>) {
        match message {
            Message::Submit { bytes, response } => self.stage(None, bytes, Some(response)),
            Message::Drain {
                max,
                budget,
                response,
            } => {
                response.send_lossy(self.drain(max, budget));
            }
            Message::Finalized { block, response } => {
                self.finalized(&block);
                response.acknowledge();
            }
        }
    }

    fn stage(
        &mut self,
        peer: Option<ed25519::PublicKey>,
        bytes: IoBuf,
        response: Option<oneshot::Sender<anyhow::Result<Submission>>>,
    ) {
        let size = bytes.remaining();
        let class = bytes.chunk().first().copied().and_then(recovery);
        let submission = if size > MAX_TX_BYTES {
            Submission::Oversized
        } else if let (Some(recovery), Some(expiry)) =
            (class, self.height.checked_add(self.retention))
        {
            let origin = Origin { peer, recovery };
            let lane = self.staging.entry(origin.clone()).or_default();
            if lane.count < RAW_COUNT && size <= RAW_BYTES - lane.bytes {
                if lane.queued.is_empty() {
                    self.ready.push_back(origin);
                }
                lane.count += 1;
                lane.bytes += size;
                lane.queued.push_back(Raw {
                    bytes,
                    expiry,
                    response,
                });
                return;
            }
            Submission::Full
        } else {
            Submission::Full
        };
        if let Some(response) = response {
            response.send_lossy(Ok(submission));
        }
    }

    fn complete<Se: Sender>(
        &mut self,
        job: Active,
        result: Result<anyhow::Result<Option<Qualified>>, commonware_runtime::Error>,
        sender: &mut Se,
    ) {
        #[cfg(test)]
        if let Some(completed) = &mut self.completed {
            let _ = completed.try_send(());
        }
        let lane = self
            .staging
            .get_mut(&job.origin)
            .expect("running origin is charged");
        lane.count -= 1;
        lane.bytes -= job.size;
        if lane.count == 0 {
            self.staging.remove(&job.origin);
        }
        let result = result
            .context("qualification task failed")
            .and_then(|result| result);
        match result {
            Ok(qualified) => {
                let submission = qualified.map_or(Submission::Full, |qualified| {
                    self.promote(qualified, job.expiry, sender)
                });
                if let Some(response) = job.response {
                    response.send_lossy(Ok(submission));
                }
            }
            Err(error) => {
                let message = format!("ingress qualification failed: {error:#}");
                if let Some(response) = job.response {
                    response.send_lossy(Err(error));
                }
                panic!("{message}");
            }
        }
    }

    /// Reserves protected capacity only after the canonical trial succeeds.
    fn promote<Se: Sender>(
        &mut self,
        qualified: Qualified,
        expiry: u64,
        sender: &mut Se,
    ) -> Submission {
        let Qualified {
            tx,
            encoded,
            digest,
            action,
        } = qualified;
        let size = encoded.len();
        let deployment = tx.deployment();
        let id = LaneId {
            deployment,
            recovery: match &tx {
                SettlementTx::QueueWithdrawal(_)
                | SettlementTx::ClaimWithdrawal(_)
                | SettlementTx::ClaimExternalPayout(_)
                | SettlementTx::Challenge(_)
                | SettlementTx::BeginHardFaultSettlement(_)
                | SettlementTx::ClaimHardFault(_)
                | SettlementTx::ClaimPendingDeposit(_) => true,
                SettlementTx::RegisterDeployment(_)
                | SettlementTx::NativeTransfer(_)
                | SettlementTx::Deposit(_)
                | SettlementTx::ClaimDeposit(_)
                | SettlementTx::RegisterEpoch(_)
                | SettlementTx::Admit(_) => false,
            },
        };
        if expiry <= self.height {
            return Submission::Full;
        }
        if let Some(lane) = self.lanes.get(&id)
            && lane.entries.iter().any(|entry| entry.digest == digest)
        {
            return Submission::Duplicate;
        }
        if action.as_ref().is_some_and(|action| {
            self.lanes.values().any(|lane| {
                lane.entries
                    .iter()
                    .any(|entry| entry.action.as_ref() == Some(action))
            })
        }) {
            return Submission::Full;
        }
        if let Some(lane) = self.lanes.get(&id) {
            if lane.entries.len() >= self.capacity || size > self.bytes - lane.bytes {
                return Submission::Full;
            }
        } else if size > self.bytes {
            return Submission::Full;
        }
        let lane = self.lanes.entry(id).or_default();
        lane.entries.push_back(Entry {
            digest,
            action,
            tx,
            expiry,
            lease: None,
        });
        lane.bytes += size;

        // Re-gossip so any leader can include the transaction. Delivery is
        // best effort: a dropped message only delays inclusion until the
        // submitter retries or another peer re-gossips.
        let _ = sender.send(Recipients::All, encoded, false);
        Submission::Accepted
    }

    /// Offers fitting transactions in lane order. The first lane with work
    /// deferred by the remaining byte budget gets the next proposal's full
    /// budget, while smaller transactions may fill this proposal's remainder.
    fn drain(&mut self, max: usize, budget: usize) -> Vec<SettlementTx> {
        let expiry = self.height.saturating_add(self.lease);
        let mut drained = Vec::new();
        let mut bytes = 0_usize;
        let lanes = self.lanes.keys().copied().collect::<Vec<_>>();
        let mut deferred = None;
        while drained.len() < max {
            let start = lanes.partition_point(|id| Some(*id) < self.next);
            let mut offered = false;
            for offset in 0..lanes.len() {
                let lane_index = (start + offset) % lanes.len();
                let id = lanes[lane_index];
                let lane = self
                    .lanes
                    .get_mut(&id)
                    .expect("lane keys were collected above");
                let Some(index) = lane.entries.iter().position(|entry| {
                    if entry.lease.is_some() {
                        return false;
                    }
                    let size = entry.tx.encode_size();
                    if size <= budget - bytes {
                        return true;
                    }
                    if size <= budget {
                        deferred.get_or_insert(id);
                    }
                    false
                }) else {
                    continue;
                };
                let mut entry = lane.entries.remove(index).expect("entry was located above");
                bytes += entry.tx.encode_size();
                drained.push(entry.tx.clone());
                entry.lease = Some(expiry);
                lane.entries.push_back(entry);
                self.next = Some(lanes[(lane_index + 1) % lanes.len()]);
                offered = true;
                break;
            }
            if !offered {
                break;
            }
        }
        if let Some(id) = deferred {
            self.next = Some(id);
        }
        drained
    }

    /// Retires transactions included by a finalized block and re-offers
    /// leases that outlived their inclusion window.
    fn finalized(&mut self, block: &Block) {
        self.height = self.height.max(block.height.get());
        let landed = block
            .transactions
            .iter()
            .map(SettlementTx::digest)
            .collect::<BTreeSet<_>>();
        self.lanes.retain(|_, lane| {
            let mut retry = VecDeque::new();
            for _ in 0..lane.entries.len() {
                let mut entry = lane
                    .entries
                    .pop_front()
                    .expect("retained entry count is known");
                if landed.contains(&entry.digest) || entry.expiry <= self.height {
                    lane.bytes -= entry.tx.encode_size();
                    continue;
                }
                if entry.lease.is_some_and(|expiry| expiry <= self.height) {
                    entry.lease = None;
                    retry.push_back(entry);
                } else {
                    lane.entries.push_back(entry);
                }
            }
            lane.entries.extend(retry);
            !lane.entries.is_empty()
        });
    }
}
