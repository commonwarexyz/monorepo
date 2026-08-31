//! Transaction ingress: the network and local intake feeding block proposals.
//!
//! The [`Actor`] owns one deduplicating queue with two intake surfaces: a p2p
//! channel carrying codec-bounded [`SettlementTx`] broadcasts from peers, and
//! a local mailbox for validator-side RPC submission. First-seen transactions
//! are re-gossiped so any leader can include them, and the digests remembered
//! for dedupe are bounded by a deterministic-capacity LRU.
//!
//! Draining for a proposal is a borrow, not a hand-off: drained transactions
//! stay leased and return to the front of the queue unless a finalized block
//! includes them within the configured lease. Finalized blocks arrive through
//! the marshal reporter stream ([`Mailbox`] implements [`Reporter`]), which
//! retires landed transactions and expires stale leases.

use crate::chain::{
    tx::SettlementTx,
    types::{Block, MAX_TX_BYTES},
};
use bytes::Buf;
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy, Receiver as MailboxReceiver, Sender as MailboxSender},
};
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _, ReadExt as _};
use commonware_consensus::{Reporter, marshal::Update};
use commonware_cryptography::sha256::Digest;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt as _, oneshot},
};
use std::{
    collections::{BTreeSet, VecDeque},
    future::Future,
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::debug;

/// Serves pending settlement transactions to block proposals.
///
/// The production queue treats a drain as a borrow: drained transactions are
/// leased and re-offered unless a finalized block includes them within the
/// lease. Handles are cloned per proposal, so they must be cheap to clone.
pub(crate) trait Provider: Clone + Send + Sync + 'static {
    /// Removes and returns pending transactions: at most `max`, stopping
    /// before their aggregate encoded size exceeds `budget`. Transactions
    /// left behind stay queued for later drains.
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

/// Ingress actor configuration.
pub(crate) struct Config {
    /// Mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
    /// Maximum transactions retained for upcoming proposals.
    pub(crate) capacity: NonZeroUsize,
    /// Maximum aggregate encoded transaction bytes retained for upcoming
    /// proposals.
    pub(crate) bytes: NonZeroUsize,
    /// Maximum first-seen digests remembered for dedupe.
    pub(crate) seen: NonZeroUsize,
    /// Finalized blocks a drained transaction stays leased before it is
    /// re-offered to proposals.
    pub(crate) lease: u64,
}

/// Advisory result of one unauthenticated local submission: acceptance into
/// the queue promises gossip and proposal attempts, never inclusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Submission {
    /// Queued for upcoming proposals and gossiped to peers.
    Accepted,
    /// Already queued, leased, or recently seen.
    Duplicate,
    /// The encoding exceeds the per-transaction wire bound.
    Oversized,
    /// The queue is full. The submitter should retry later.
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
#[allow(clippy::large_enum_variant)]
pub(crate) enum Message<A: Acknowledgement> {
    /// A local (RPC) submission.
    Submit {
        tx: SettlementTx,
        response: oneshot::Sender<Submission>,
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
        overflow.push_back(message);
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
    /// Submits one transaction into the queue, returning the advisory
    /// admission result. Returns [`Submission::Full`] when the actor is gone.
    pub(crate) async fn submit(&self, tx: SettlementTx) -> Submission {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Submit { tx, response });
        receiver.await.unwrap_or(Submission::Full)
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

/// One drained transaction awaiting inclusion.
struct Lease {
    digest: Digest,
    tx: SettlementTx,
    /// Finalized height after which the lease is re-offered.
    expiry: u64,
}

/// The ingress actor: one deduplicating transaction queue fed by the p2p
/// channel and the local mailbox, drained by proposals, and retired by the
/// finalized stream.
pub(crate) struct Actor<E, A = Exact>
where
    E: Spawner + Metrics,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    mailbox: MailboxReceiver<Message<A>>,
    capacity: usize,
    /// Maximum aggregate encoded bytes across the pending queue.
    bytes: usize,
    lease: u64,
    /// First-seen transactions awaiting a proposal, oldest first.
    pending: VecDeque<(Digest, SettlementTx)>,
    /// Aggregate encoded bytes across the pending queue.
    pending_bytes: usize,
    /// Drained transactions awaiting inclusion, in drain order (expiries are
    /// non-decreasing, so expired leases always sit at the front).
    leased: VecDeque<Lease>,
    /// Recently seen digests, evicted first-seen-first.
    seen: BTreeSet<Digest>,
    seen_order: VecDeque<Digest>,
    seen_capacity: usize,
    /// Latest finalized height observed from the reporter stream.
    height: u64,
}

impl<E, A> Actor<E, A>
where
    E: Spawner + Metrics,
    A: Acknowledgement,
{
    pub(crate) fn new(context: E, config: Config) -> (Self, Mailbox<A>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                capacity: config.capacity.get(),
                bytes: config.bytes.get(),
                lease: config.lease,
                pending: VecDeque::new(),
                pending_bytes: 0,
                leased: VecDeque::new(),
                seen: BTreeSet::new(),
                seen_order: VecDeque::new(),
                seen_capacity: config.seen.get(),
                height: 0,
            },
            Mailbox { sender },
        )
    }

    /// Starts the actor on the settlement transaction channel.
    pub(crate) fn start<Se, Re>(mut self, chan: (Se, Re)) -> Handle<()>
    where
        Se: Sender,
        Re: Receiver<PublicKey = Se::PublicKey>,
    {
        spawn_cell!(self.context, self.run(chan))
    }

    async fn run<Se, Re>(mut self, (mut sender, mut receiver): (Se, Re))
    where
        Se: Sender,
        Re: Receiver<PublicKey = Se::PublicKey>,
    {
        loop {
            select! {
                message = self.mailbox.recv() => {
                    let Some(message) = message else {
                        return;
                    };
                    match message {
                        Message::Submit { tx, response } => {
                            let submission = self.intake(tx, &mut sender);
                            response.send_lossy(submission);
                        }
                        Message::Drain {
                            max,
                            budget,
                            response,
                        } => {
                            let drained = self.drain(max, budget);
                            response.send_lossy(drained);
                        }
                        Message::Finalized { block, response } => {
                            self.finalized(&block);
                            response.acknowledge();
                        }
                    }
                },
                message = receiver.recv() => {
                    let Ok((peer, mut bytes)) = message else {
                        return;
                    };
                    if bytes.remaining() > MAX_TX_BYTES {
                        continue;
                    }
                    let Ok(tx) = SettlementTx::decode_cfg(&mut bytes, &()) else {
                        debug!(?peer, "dropping undecodable settlement transaction");
                        continue;
                    };
                    self.intake(tx, &mut sender);
                },
            }
        }
    }

    /// Returns whether `digest` is queued, leased, or recently seen.
    fn tracked(&self, digest: &Digest) -> bool {
        self.seen.contains(digest)
            || self.pending.iter().any(|(pending, _)| pending == digest)
            || self.leased.iter().any(|lease| &lease.digest == digest)
    }

    /// Remembers `digest` in the bounded dedupe window.
    fn remember(&mut self, digest: Digest) {
        if !self.seen.insert(digest) {
            return;
        }
        self.seen_order.push_back(digest);
        if self.seen_order.len() > self.seen_capacity {
            let oldest = self
                .seen_order
                .pop_front()
                .expect("a digest was pushed above");
            self.seen.remove(&oldest);
        }
    }

    /// Admits one transaction from either intake surface, gossiping it to
    /// peers when it is first seen.
    fn intake<Se: Sender>(&mut self, tx: SettlementTx, sender: &mut Se) -> Submission {
        let size = tx.encode_size();
        if size > MAX_TX_BYTES {
            return Submission::Oversized;
        }
        let digest = tx.digest();
        if self.tracked(&digest) {
            return Submission::Duplicate;
        }
        if self.pending.len() >= self.capacity
            || self.pending_bytes.saturating_add(size) > self.bytes
        {
            return Submission::Full;
        }
        self.remember(digest);
        let encoded = tx.encode();
        self.pending.push_back((digest, tx));
        self.pending_bytes += size;

        // Re-gossip so any leader can include the transaction. Delivery is
        // best effort: a dropped message only delays inclusion until the
        // submitter retries or another peer re-gossips.
        let _ = sender.send(Recipients::All, encoded, false);
        Submission::Accepted
    }

    /// Borrows pending transactions for one proposal: at most `max`, stopping
    /// before the aggregate encoded size exceeds `budget`. Transactions left
    /// behind stay pending, so the next proposal is offered them immediately.
    fn drain(&mut self, max: usize, budget: usize) -> Vec<SettlementTx> {
        let expiry = self.height.saturating_add(self.lease);
        let mut drained = Vec::new();
        let mut bytes = 0_usize;
        while drained.len() < max {
            let Some((_, front)) = self.pending.front() else {
                break;
            };
            let size = front.encode_size();
            if bytes.saturating_add(size) > budget {
                break;
            }
            bytes += size;
            let (digest, tx) = self
                .pending
                .pop_front()
                .expect("the front was inspected above");
            self.pending_bytes -= size;
            drained.push(tx.clone());
            self.leased.push_back(Lease { digest, tx, expiry });
        }
        drained
    }

    /// Retires transactions included by a finalized block and re-offers
    /// leases that outlived their inclusion window.
    fn finalized(&mut self, block: &Block) {
        self.height = self.height.max(block.height.get());
        for tx in &block.transactions {
            let digest = tx.digest();

            // A landed transaction leaves the queue entirely, dedupe window
            // included: execution's domain-state guards make replays
            // harmless, and dropping the digest lets a submitter retry a
            // transaction that landed with a retryable rejection.
            if self.seen.remove(&digest) {
                self.seen_order.retain(|seen| seen != &digest);
            }
            let mut freed = 0_usize;
            self.pending.retain(|(pending, tx)| {
                if pending == &digest {
                    freed += tx.encode_size();
                    return false;
                }
                true
            });
            self.pending_bytes -= freed;
            self.leased.retain(|lease| lease.digest != digest);
        }

        // Expired leases return to the front of the queue in their original
        // order, ahead of newer submissions. The re-offer ignores the count
        // and byte capacities: the overflow is transient and bounded by the
        // leases outstanding.
        let mut expired = Vec::new();
        while let Some(front) = self.leased.front() {
            if front.expiry > self.height {
                break;
            }
            let lease = self
                .leased
                .pop_front()
                .expect("the front lease was inspected above");
            expired.push((lease.digest, lease.tx));
        }
        for entry in expired.into_iter().rev() {
            self.pending_bytes += entry.1.encode_size();
            self.pending.push_front(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{
            app::initial_sync_target,
            types::{Block, MAX_BLOCK_BYTES},
        },
        protocol::DepositEvent,
    };
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Hasher as _, Sha256, Signer as _, ed25519, sha256::Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::NZUsize;

    /// A finalized block at `height` carrying `transactions`.
    fn block(height: u64, transactions: Vec<SettlementTx>) -> Block {
        let target = initial_sync_target::<deterministic::Context>();
        Block {
            context: Context {
                round: Round::new(Epoch::zero(), View::new(height)),
                leader: ed25519::PrivateKey::from_seed(0).public_key(),
                parent: (View::zero(), Digest::EMPTY),
            },
            parent: Digest::EMPTY,
            height: Height::new(height),
            timestamp: height,
            state_root: Digest::EMPTY,
            ops_root: target.root,
            range: target.range,
            transactions,
        }
    }

    /// Reports one finalized block and waits for the actor to process it.
    async fn report(mailbox: &Mailbox, block: Block) {
        let (ack, waiter) = Exact::handle();
        let mut reporter = mailbox.clone();
        reporter.report(Update::Block(Arc::new(block), ack));
        waiter.await.expect("the actor acknowledges the block");
    }

    #[test]
    fn drains_are_borrows_and_inclusion_retires() {
        deterministic::Runner::default().start(|context| async move {
            let (actor, mailbox) = Actor::<_, Exact>::new(
                context.child("ingress"),
                Config {
                    mailbox_size: NZUsize!(16),
                    capacity: NZUsize!(8),
                    bytes: NZUsize!(MAX_BLOCK_BYTES),
                    seen: NZUsize!(8),
                    lease: 2,
                },
            );
            let chan = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
            actor.start(chan);

            let tx = SettlementTx::Deposit(crate::chain::tx::DepositRequest {
                deployment: crate::protocol::deployment(),
                event: DepositEvent {
                    id: Sha256::hash(&[b"ingress-lease"]),
                    account: crate::protocol::identities()[0].key.clone(),
                    amount: 1,
                },
            });
            assert_eq!(mailbox.submit(tx.clone()).await, Submission::Accepted);
            assert_eq!(mailbox.submit(tx.clone()).await, Submission::Duplicate);

            // A drain borrows the transaction: nothing else is offered and a
            // resubmission stays a duplicate while the lease is live.
            let mut provider = mailbox.clone();
            assert_eq!(provider.drain(8, MAX_BLOCK_BYTES).await, vec![tx.clone()]);
            assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
            assert_eq!(mailbox.submit(tx.clone()).await, Submission::Duplicate);

            // The lease survives one finalized block without the transaction
            // and is re-offered once the lease window elapses.
            report(&mailbox, block(1, Vec::new())).await;
            assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
            report(&mailbox, block(2, Vec::new())).await;
            assert_eq!(provider.drain(8, MAX_BLOCK_BYTES).await, vec![tx.clone()]);

            // Inclusion in a finalized block retires the lease and clears the
            // dedupe window, so an explicit resubmission is admitted again
            // (execution's domain guards make the replay a harmless no-op).
            report(&mailbox, block(3, vec![tx.clone()])).await;
            assert!(provider.drain(8, MAX_BLOCK_BYTES).await.is_empty());
            assert_eq!(mailbox.submit(tx).await, Submission::Accepted);
        });
    }

    /// A deposit transaction with a distinct id derived from `seed`.
    fn deposit(seed: u64) -> SettlementTx {
        SettlementTx::Deposit(crate::chain::tx::DepositRequest {
            deployment: crate::protocol::deployment(),
            event: DepositEvent {
                id: Sha256::hash(&[b"ingress-bytes", &seed.to_be_bytes()]),
                account: crate::protocol::identities()[0].key.clone(),
                amount: 1,
            },
        })
    }

    #[test]
    fn queue_and_drains_bound_aggregate_bytes() {
        deterministic::Runner::default().start(|context| async move {
            let size = deposit(0).encode_size();
            let (actor, mailbox) = Actor::<_, Exact>::new(
                context.child("ingress"),
                Config {
                    mailbox_size: NZUsize!(16),
                    capacity: NZUsize!(8),
                    bytes: NZUsize!(3 * size),
                    seen: NZUsize!(8),
                    lease: 2,
                },
            );
            let chan = commonware_p2p::utils::mocks::inert_channel::<ed25519::PublicKey>([]);
            actor.start(chan);

            // The queue admits transactions by aggregate encoded bytes, not
            // just count: the fourth submission overflows the byte bound.
            for seed in 0..3 {
                assert_eq!(mailbox.submit(deposit(seed)).await, Submission::Accepted);
            }
            assert_eq!(mailbox.submit(deposit(3)).await, Submission::Full);

            // A drain stops before its byte budget and leaves the remainder
            // pending, so the next drain is offered it immediately.
            let mut provider = mailbox.clone();
            assert_eq!(provider.drain(8, 2 * size).await.len(), 2);
            assert_eq!(provider.drain(8, 2 * size).await, vec![deposit(2)]);

            // Draining freed queue bytes, so the overflowed submission fits.
            assert_eq!(mailbox.submit(deposit(3)).await, Submission::Accepted);
        });
    }
}
