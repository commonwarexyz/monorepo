//! Mallory's network-fault controllers: the topology authority ([`Topology`])
//! and the packet-fault layer ([`PacketFaultCell`] / [`pump`] /
//! [`PacketFaultReceiver`]).
//!
//! [`Topology`] is the ONLY place Mallory mutates the simulated network
//! topology (link set). It owns a clone of the setup [`Oracle`] and drives every
//! partition through [`crate::utils::apply_partition`]. Each transient partition
//! is applied for one observation window and then [`Topology::heal`]ed back to a
//! full mesh, so at most one is ever active, the v1 "at most one transient
//! network fault" contract (see [`crate::mallory`]).
//!
//! The packet-fault layer sits BELOW the sniffer so the sniffer records exactly
//! what the engine receives. The receive stack for each honest node's each
//! channel is:
//!
//! ```text
//! simulated receiver -> [pump] -> PacketFaultReceiver (internal FIFO)
//!     -> SniffingReceiver -> Simplex engine
//! ```
//!
//! A [`pump`] task owns the simulated receiver and pushes each message into an
//! unbounded internal FIFO, applying the single active packet fault held in the
//! shared [`PacketFaultCell`]. With no matching fault the pump is a transparent
//! in-order relay, so liveness and order are unchanged. All randomness is sampled
//! by the runner at enact time (see [`crate::mallory::fault`]); the pump applies
//! a deterministic, param-driven transform and draws none of its own, so a
//! replayed input relays identically. Exactly one fault is active at a time (the
//! runner heals every step), and each pump acts only on the fault whose
//! `(node, channel)` matches its own.

use crate::{
    utils::{apply_partition, SetPartition},
    SniffChannel, BYZANTINE_IDX,
};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Error, Link, Oracle},
    Message,
};
use commonware_runtime::{Clock, IoBuf};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use std::{
    collections::VecDeque,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

/// The canonical `n = 4` partition `{{0},{1,2,3}}` that isolates node 0. Node 0
/// is [`BYZANTINE_IDX`], the single faultable identity, so this leaves the other
/// three, an N4F0C4 quorum, connected. Index 4 isolates node 0 specifically,
/// which is correct only because the v1 contract fixes the faultable identity at
/// index 0.
const ISOLATE_BYZANTINE: usize = 4;
const _: () = assert!(
    BYZANTINE_IDX == 0,
    "n4(4) isolates node 0, so BYZANTINE_IDX must be 0"
);

/// Mallory's network-fault controller: a clone of the setup [`Oracle`], the
/// ordered participant set, and the [`Link`] re-established on every permitted
/// edge.
pub(crate) struct Topology<P: PublicKey, E: Clock> {
    oracle: Oracle<P, E>,
    participants: Vec<P>,
    link: Link,
}

impl<P: PublicKey, E: Clock> Topology<P, E> {
    /// Build the controller. `oracle` must be a clone of the setup oracle (its
    /// interior state is shared), `participants` the same ordered validator set
    /// the engines were spawned with, and `link` the edge to re-establish.
    pub(crate) fn new(oracle: Oracle<P, E>, participants: Vec<P>, link: Link) -> Self {
        Self {
            oracle,
            participants,
            link,
        }
    }

    /// Isolate [`BYZANTINE_IDX`] (node 0) from the other three validators
    /// (`{{0},{1,2,3}}`). The remaining three still form the quorum of three, so
    /// they keep finalizing; node 0 stalls and catches up after [`Self::heal`]
    /// via resolver backfill.
    pub(crate) async fn isolate_byzantine(&self) {
        apply_partition(
            &self.oracle,
            &self.participants,
            Some(&SetPartition::n4(ISOLATE_BYZANTINE)),
            &self.link,
        )
        .await;
    }

    /// Apply an arbitrary set partition. Mallory only passes the balanced 2-2
    /// splits here (see [`crate::mallory::fault`]).
    pub(crate) async fn partition(&self, sp: &SetPartition) {
        apply_partition(&self.oracle, &self.participants, Some(sp), &self.link).await;
    }

    /// Restore the full mesh. Idempotent: healing an already-connected topology
    /// re-adds every edge, so it is safe to call unconditionally.
    pub(crate) async fn heal(&self) {
        apply_partition(&self.oracle, &self.participants, None, &self.link).await;
    }
}

/// The reply half a heal-time flush carries (the F3 quiescence barrier). The
/// runner sends the [`oneshot::Sender`] to a [`pump`] and awaits its receiver; the
/// pump replies with `()` only AFTER draining its held reorder buffer and finishing
/// any in-flight per-packet delay, so once the runner's await returns that pump
/// holds no fault-injected packet and the fault can be cleared without leaking into
/// the next decision step.
pub(crate) type FlushAck = oneshot::Sender<()>;

/// The deterministic, param-driven transform a [`pump`] applies to one honest
/// node's one channel. Every parameter is sampled by the runner from the runtime
/// RNG (see [`crate::mallory::fault`]); the pump draws none, so a replayed input
/// relays identically.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PacketFaultKind {
    /// Sleep the pump `per_packet` before forwarding each matching packet: a
    /// coarse, in-order channel slowdown (never a drop or reorder).
    Delay { per_packet: Duration },
    /// Drop the next `drop_count` matching packets, then forward. A dropped packet
    /// never reaches the sniffer, so it is absent from the happens-before log.
    Loss { drop_count: u32 },
    /// Corrupt the raw wire bytes of the next `count` matching packets WITHOUT
    /// re-signing, XOR the byte at `offset % len` with `mask`, then forward
    /// unchanged. A corrupted message fails to decode, so the sniffer drops it
    /// from the happens-before log and the engine rejects it. `count` is bounded
    /// like a loss so a run still completes.
    Corrupt { count: u32, offset: u16, mask: u8 },
    /// Forward each matching packet, then push `extra` additional identical copies
    /// into the internal FIFO. `extra` is hard-bounded so the FIFO cannot blow up;
    /// the engine's vote handling is idempotent, so a run still completes.
    Duplicate { extra: u32 },
    /// Hold matching packets in a per-pump bounded reorder buffer of capacity
    /// `buffer` and release them out of arrival order under a deterministic policy
    /// (see [`pump`]). A heal-time flush drains any held packets in order, so none
    /// is lost mid-episode. `buffer` is hard-bounded.
    Reorder { buffer: u32 },
}

/// A concrete, active packet fault: the [`PacketFaultKind`] transform plus its
/// target, the receiving honest node index and the [`SniffChannel`] the pump
/// matches its own `(node, channel)` against.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PacketFault {
    pub node: usize,
    pub channel: SniffChannel,
    pub kind: PacketFaultKind,
}

/// The single active packet fault, shared (cheap `Arc` clone) by the runner,
/// which [`set`](Self::set)s it at a step's start and [`clear`](Self::clear)s it
/// at the step's end, and every [`pump`], which reads it per packet. Exactly
/// one fault is active at a time, so a pump acts only when the active fault's
/// `(node, channel)` matches its own.
#[derive(Clone)]
pub(crate) struct PacketFaultCell {
    inner: Arc<PacketFaultState>,
}

struct PacketFaultState {
    /// The active fault, or `None` when every pump is a transparent FIFO relay.
    active: Mutex<Option<PacketFault>>,
    /// Set by a pump the first time it acts on a matching packet, so the runner
    /// can log a fault that installed but matched nothing (a wiring smell).
    matched: AtomicBool,
    /// Packets a `Loss` fault still drops before it starts forwarding.
    remaining_drops: AtomicU32,
    /// Packets a `Corrupt` fault still mutates before it starts forwarding
    /// unchanged.
    remaining_corrupts: AtomicU32,
}

/// What a [`pump`] does with the next packet on its `(node, channel)`.
enum PumpDecision {
    /// Forward unchanged (no matching fault, or a spent `Loss`/`Corrupt` budget).
    Forward,
    /// Drop it (a `Loss` within its budget); it never reaches the sniffer.
    Drop,
    /// Sleep this long, then forward (a `Delay`).
    Delay(Duration),
    /// XOR `mask` into the byte at `offset % len`, then forward the mutated bytes
    /// (a `Corrupt` within its budget).
    Corrupt { offset: u16, mask: u8 },
    /// Forward the packet plus `extra` identical copies (a `Duplicate`).
    Duplicate { extra: u32 },
    /// Run the pump's local bounded-reorder transform with capacity `buffer`.
    Reorder { buffer: u32 },
}

impl PacketFaultCell {
    /// An idle cell: no active fault, so every pump is a transparent relay.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(PacketFaultState {
                active: Mutex::new(None),
                matched: AtomicBool::new(false),
                remaining_drops: AtomicU32::new(0),
                remaining_corrupts: AtomicU32::new(0),
            }),
        }
    }

    /// Install `fault` as the single active fault: reset the match flag and arm
    /// the per-packet budget of a `Loss` (drops) or a `Corrupt` (mutations). The
    /// previous fault (if any) must have been [`clear`](Self::clear)ed first,
    /// the runner heals every step.
    pub(crate) fn set(&self, fault: PacketFault) {
        let (drops, corrupts) = match fault.kind {
            PacketFaultKind::Loss { drop_count } => (drop_count, 0),
            PacketFaultKind::Corrupt { count, .. } => (0, count),
            PacketFaultKind::Delay { .. }
            | PacketFaultKind::Duplicate { .. }
            | PacketFaultKind::Reorder { .. } => (0, 0),
        };
        self.inner.matched.store(false, Ordering::Relaxed);
        self.inner.remaining_drops.store(drops, Ordering::Relaxed);
        self.inner
            .remaining_corrupts
            .store(corrupts, Ordering::Relaxed);
        *self.inner.active.lock() = Some(fault);
    }

    /// Clear the active fault: every pump reverts to a transparent FIFO relay and
    /// the match / drop / corrupt counters reset. Idempotent. A pump's reorder
    /// buffer is held locally; the runner drains it via the per-pump flush signal
    /// before clearing (see [`crate::mallory::runner`]), so clearing the cell only
    /// stops future buffering.
    pub(crate) fn clear(&self) {
        *self.inner.active.lock() = None;
        self.inner.matched.store(false, Ordering::Relaxed);
        self.inner.remaining_drops.store(0, Ordering::Relaxed);
        self.inner.remaining_corrupts.store(0, Ordering::Relaxed);
    }

    /// Whether any pump has acted on a matching packet since the last
    /// [`set`](Self::set). The runner logs this so an applied-but-matched-nothing
    /// fault is diagnosable.
    pub(crate) fn matched(&self) -> bool {
        self.inner.matched.load(Ordering::Relaxed)
    }

    /// Decide what the pump for `(node, channel)` does with its next packet. Pure
    /// and synchronous: a `Delay` returns the sleep for the pump to perform after
    /// this returns, so no lock is ever held across an await.
    fn decide(&self, node: usize, channel: SniffChannel) -> PumpDecision {
        let Some(fault) = *self.inner.active.lock() else {
            return PumpDecision::Forward;
        };
        if fault.node != node || fault.channel != channel {
            return PumpDecision::Forward;
        }
        match fault.kind {
            PacketFaultKind::Delay { per_packet } => {
                self.inner.matched.store(true, Ordering::Relaxed);
                PumpDecision::Delay(per_packet)
            }
            PacketFaultKind::Loss { .. } => {
                // Only the single pump whose `(node, channel)` matches the active
                // fault ever reaches here, and the runner does not touch the
                // counter during the window, so this load-then-store is race-free
                // (and `decide` has no await, so it is atomic w.r.t. other tasks).
                let remaining = self.inner.remaining_drops.load(Ordering::Relaxed);
                if remaining > 0 {
                    self.inner
                        .remaining_drops
                        .store(remaining - 1, Ordering::Relaxed);
                    self.inner.matched.store(true, Ordering::Relaxed);
                    PumpDecision::Drop
                } else {
                    PumpDecision::Forward
                }
            }
            PacketFaultKind::Corrupt { offset, mask, .. } => {
                // Same race-free load/store discipline as `Loss`: only the single
                // matching pump reaches here and `decide` has no await.
                let remaining = self.inner.remaining_corrupts.load(Ordering::Relaxed);
                if remaining > 0 {
                    self.inner
                        .remaining_corrupts
                        .store(remaining - 1, Ordering::Relaxed);
                    self.inner.matched.store(true, Ordering::Relaxed);
                    PumpDecision::Corrupt { offset, mask }
                } else {
                    PumpDecision::Forward
                }
            }
            PacketFaultKind::Duplicate { extra } => {
                self.inner.matched.store(true, Ordering::Relaxed);
                PumpDecision::Duplicate { extra }
            }
            PacketFaultKind::Reorder { buffer } => {
                self.inner.matched.store(true, Ordering::Relaxed);
                PumpDecision::Reorder { buffer }
            }
        }
    }
}

/// XOR the byte at `offset % len` of `message`'s payload with `mask`, returning
/// the mutated message. The wire bytes change WITHOUT re-signing, so the message
/// no longer decodes or verifies. An empty payload is returned unchanged.
fn corrupt_message<P: PublicKey>(message: Message<P>, offset: u16, mask: u8) -> Message<P> {
    let (from, payload) = message;
    let bytes = payload.as_ref();
    if bytes.is_empty() {
        return (from, payload);
    }
    let idx = (offset as usize) % bytes.len();
    let mut mutated = bytes.to_vec();
    mutated[idx] ^= mask;
    (from, IoBuf::copy_from_slice(&mutated))
}

/// Push `message` into the bounded reorder `buffer` and return the packet (if
/// any) to release now under a deterministic non-FIFO policy. `toggle` is a
/// per-pump counter that draws no randomness. Rules honored:
/// - never grow past `cap`: a would-be overflow releases the OLDEST (front)
///   packet, so memory is bounded;
/// - otherwise release the NEWEST (back) on alternating packets (a LIFO reorder)
///   and hold on the others, so the buffer fills and delivery order diverges from
///   arrival order.
///
/// Held packets are drained in order by the [`pump`]'s flush path.
fn reorder_step<P: PublicKey>(
    buffer: &mut VecDeque<Message<P>>,
    toggle: &mut u64,
    message: Message<P>,
    cap: u32,
) -> Option<Message<P>> {
    let cap = (cap.max(1)) as usize;
    buffer.push_back(message);
    *toggle = toggle.wrapping_add(1);
    if buffer.len() > cap {
        // Overflow: release the oldest to bound memory (never grow past `cap`).
        return buffer.pop_front();
    }
    if toggle.is_multiple_of(2) {
        // Non-FIFO release: newest first (LIFO), jumping ahead of held packets.
        buffer.pop_back()
    } else {
        // Hold: let the buffer grow so a later LIFO release reorders the queue.
        None
    }
}

/// Relay one honest node's one channel from the simulated receiver `sim_rx` into
/// the internal FIFO `internal_tx` the [`PacketFaultReceiver`] drains, applying
/// the active packet fault from `cell`. With no matching fault the pump is a
/// transparent, in-order relay, an unbounded FIFO, so liveness and order are
/// unchanged. It draws no randomness (the fault's parameters were sampled by the
/// runner; `select!` is biased, not random), so two same-seed runs relay
/// identically.
///
/// A `Reorder` fault holds packets in a per-pump bounded buffer; every other path
/// leaves that buffer empty, so the pump stays a direct FIFO relay. `flush_rx`
/// carries the runner's heal-time flush requests, each a [`FlushAck`] the pump
/// replies on: it drains the held buffer in order, then acks, so the runner can
/// WAIT for quiescence before clearing the fault (the F3 barrier). The flush branch
/// is biased first so a pending flush drains promptly even under a steady packet
/// stream, and a per-packet delay in the sim branch is polled to completion before
/// the flush is handled, so the ack implies no in-flight delayed packet remains.
/// Breaks when the simulated channel closes, the internal receiver is dropped, or
/// the runner drops the flush sender at teardown (any buffer still held is then
/// discarded).
pub(crate) async fn pump<P, R, E>(
    context: E,
    mut sim_rx: R,
    internal_tx: mpsc::UnboundedSender<Message<P>>,
    mut flush_rx: mpsc::UnboundedReceiver<FlushAck>,
    cell: PacketFaultCell,
    node: usize,
    channel: SniffChannel,
) where
    P: PublicKey,
    R: commonware_p2p::Receiver<PublicKey = P>,
    E: Clock,
{
    // Per-pump reorder state. Only a `Reorder` fault targeting this
    // `(node, channel)` ever pushes into `buffer`, so every other path leaves it
    // empty and the pump stays a direct FIFO relay. `toggle` drives the
    // deterministic non-FIFO release policy and draws no randomness.
    let mut buffer: VecDeque<Message<P>> = VecDeque::new();
    let mut toggle: u64 = 0;
    loop {
        select! {
            // Heal-time flush (biased first): drain any held reorder packets in
            // arrival order, then ACK so the runner's request-reply flush can wait
            // for quiescence before clearing the fault (F3). `None` means the runner
            // dropped the flush sender at teardown. The ack is sent even if the
            // internal receiver has gone away, so the runner's await never hangs.
            ack = flush_rx.recv() => {
                let Some(ack) = ack else {
                    break;
                };
                let mut alive = true;
                while let Some(held) = buffer.pop_front() {
                    if internal_tx.send(held).is_err() {
                        alive = false;
                        break;
                    }
                }
                let _ = ack.send(());
                if !alive {
                    return;
                }
            },
            message = sim_rx.recv() => {
                let Ok(message) = message else {
                    break;
                };
                match cell.decide(node, channel) {
                    PumpDecision::Forward => {
                        if internal_tx.send(message).is_err() {
                            break;
                        }
                    }
                    PumpDecision::Drop => {}
                    PumpDecision::Delay(per_packet) => {
                        context.sleep(per_packet).await;
                        if internal_tx.send(message).is_err() {
                            break;
                        }
                    }
                    PumpDecision::Corrupt { offset, mask } => {
                        if internal_tx
                            .send(corrupt_message(message, offset, mask))
                            .is_err()
                        {
                            break;
                        }
                    }
                    PumpDecision::Duplicate { extra } => {
                        // The original packet plus `extra` identical copies (the
                        // engine's vote handling is idempotent); bounded so the
                        // FIFO cannot blow up.
                        let mut copies_ok = true;
                        for _ in 0..extra {
                            if internal_tx.send(message.clone()).is_err() {
                                copies_ok = false;
                                break;
                            }
                        }
                        if !copies_ok || internal_tx.send(message).is_err() {
                            break;
                        }
                    }
                    PumpDecision::Reorder { buffer: cap } => {
                        if let Some(release) = reorder_step(&mut buffer, &mut toggle, message, cap) {
                            if internal_tx.send(release).is_err() {
                                break;
                            }
                        }
                    }
                }
            },
        }
    }
}

/// The engine-facing receiver below the sniffer: drains the internal FIFO the
/// [`pump`] pushes into. It applies no fault logic itself (the pump already did),
/// only surfacing the relayed `(PublicKey, Bytes)` messages as a
/// [`commonware_p2p::Receiver`], mirroring the simulated receiver it replaces
/// (down to reporting [`Error::NetworkClosed`] when the pump stops and drops its
/// sender).
pub(crate) struct PacketFaultReceiver<P: PublicKey> {
    inner: mpsc::UnboundedReceiver<Message<P>>,
}

impl<P: PublicKey> PacketFaultReceiver<P> {
    pub(crate) fn new(inner: mpsc::UnboundedReceiver<Message<P>>) -> Self {
        Self { inner }
    }
}

impl<P: PublicKey> fmt::Debug for PacketFaultReceiver<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketFaultReceiver").finish()
    }
}

impl<P: PublicKey> commonware_p2p::Receiver for PacketFaultReceiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.inner.recv().await.ok_or(Error::NetworkClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
        Signer as _,
    };
    use commonware_p2p::Receiver as _;
    use commonware_runtime::{deterministic, IoBuf, Runner, Spawner, Supervisor as _};

    const NODE: usize = 1;

    fn sender() -> Ed25519PublicKey {
        PrivateKey::from_seed(0).public_key()
    }

    /// Drive the pump for `(NODE, channel)` over the one-byte-tagged `tags`,
    /// applying `fault` (if any), and return the tags the engine-facing receiver
    /// observes in delivery order plus whether the pump matched. All packets are
    /// enqueued and the source closed before the pump runs, so the pump drains,
    /// forwards past the fault, then stops.
    fn drive(fault: Option<PacketFault>, channel: SniffChannel, tags: &[u8]) -> (Vec<u8>, bool) {
        let tags = tags.to_vec();
        let executor = deterministic::Runner::seeded(1);
        executor.start(move |context| async move {
            let from = sender();
            let (src_tx, src_rx) = mpsc::unbounded_channel::<Message<Ed25519PublicKey>>();
            let (internal_tx, internal_rx) = mpsc::unbounded_channel();
            // Held for the whole drive so the pump never sees a dropped flush
            // sender; these forward tests never signal a flush.
            let (flush_tx, flush_rx) = mpsc::unbounded_channel::<FlushAck>();
            let cell = PacketFaultCell::new();
            if let Some(f) = fault {
                cell.set(f);
            }
            for &t in &tags {
                src_tx
                    .send((from.clone(), IoBuf::copy_from_slice(&[t])))
                    .unwrap();
            }
            drop(src_tx);

            let pump_cell = cell.clone();
            context.child("packet_pump").spawn(move |ctx| {
                pump(
                    ctx,
                    PacketFaultReceiver::new(src_rx),
                    internal_tx,
                    flush_rx,
                    pump_cell,
                    NODE,
                    channel,
                )
            });

            let mut out = PacketFaultReceiver::new(internal_rx);
            let mut got = Vec::new();
            while let Ok((_, payload)) = out.recv().await {
                got.push(payload.as_ref()[0]);
            }
            drop(flush_tx);
            (got, cell.matched())
        })
    }

    /// Drive a `Reorder` fault over `tags`, then (after the pump has drained the
    /// source in deterministic time) signal a flush and close the source, so the
    /// pump releases whatever it held. Returns the tags in delivery order.
    fn drive_reorder_flushed(buffer: u32, channel: SniffChannel, tags: &[u8]) -> Vec<u8> {
        let tags = tags.to_vec();
        let executor = deterministic::Runner::seeded(1);
        executor.start(move |context| async move {
            let from = sender();
            let (src_tx, src_rx) = mpsc::unbounded_channel::<Message<Ed25519PublicKey>>();
            let (internal_tx, internal_rx) = mpsc::unbounded_channel();
            let (flush_tx, flush_rx) = mpsc::unbounded_channel::<FlushAck>();
            let cell = PacketFaultCell::new();
            cell.set(PacketFault {
                node: NODE,
                channel,
                kind: PacketFaultKind::Reorder { buffer },
            });
            for &t in &tags {
                src_tx
                    .send((from.clone(), IoBuf::copy_from_slice(&[t])))
                    .unwrap();
            }

            let pump_cell = cell.clone();
            context.child("packet_pump").spawn(move |ctx| {
                pump(
                    ctx,
                    PacketFaultReceiver::new(src_rx),
                    internal_tx,
                    flush_rx,
                    pump_cell,
                    NODE,
                    channel,
                )
            });

            // The pump drains the queued source at t=0; wake later to flush the
            // held buffer in order (request-reply: await the pump's ack), then close
            // the source so the pump stops.
            context.child("flusher").spawn(move |ctx| async move {
                ctx.sleep(Duration::from_secs(1)).await;
                let (ack_tx, ack_rx) = oneshot::channel();
                let _ = flush_tx.send(ack_tx);
                let _ = ack_rx.await;
                drop(src_tx);
            });

            let mut out = PacketFaultReceiver::new(internal_rx);
            let mut got = Vec::new();
            while let Ok((_, payload)) = out.recv().await {
                got.push(payload.as_ref()[0]);
            }
            got
        })
    }

    /// A one-byte-tagged message from the fixed sender, for the reorder-buffer
    /// unit tests that exercise [`reorder_step`] directly.
    fn tagged(t: u8) -> Message<Ed25519PublicKey> {
        (sender(), IoBuf::copy_from_slice(&[t]))
    }

    /// The one-byte tag carried by a message.
    fn tag_of(m: &Message<Ed25519PublicKey>) -> u8 {
        m.1.as_ref()[0]
    }

    #[test]
    fn idle_pump_is_a_transparent_in_order_relay() {
        // No active fault: every packet is forwarded, unchanged and in order.
        let (got, matched) = drive(None, SniffChannel::Vote, &[1, 2, 3, 4, 5]);
        assert!(!matched, "an idle pump acts on nothing");
        assert_eq!(got, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn loss_drops_are_absent_from_the_forwarded_stream() {
        // A Loss drops the first `drop_count` matching packets below the sniffer,
        // so they never reach the engine-facing stream (hence absent from HB).
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Vote,
            kind: PacketFaultKind::Loss { drop_count: 2 },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2, 3, 4, 5]);
        assert!(
            matched,
            "a forced loss must record that it dropped a packet"
        );
        assert_eq!(
            got,
            vec![3, 4, 5],
            "the first two matching packets are dropped"
        );
    }

    #[test]
    fn loss_only_acts_on_its_target_channel() {
        // The fault targets Certificate; a Vote pump forwards everything and never
        // records a match, so gating is per (node, channel).
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Certificate,
            kind: PacketFaultKind::Loss { drop_count: 4 },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2, 3]);
        assert!(!matched, "a non-matching channel must not act");
        assert_eq!(
            got,
            vec![1, 2, 3],
            "a non-matching channel forwards everything"
        );
    }

    #[test]
    fn loss_beyond_budget_drops_all_and_forwards_nothing() {
        // Fewer matching packets than the drop budget: all are dropped, none
        // forwarded, and the budget is simply not exhausted.
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Resolver,
            kind: PacketFaultKind::Loss { drop_count: 8 },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Resolver, &[1, 2, 3]);
        assert!(matched);
        assert!(
            got.is_empty(),
            "all three packets fit within the drop budget"
        );
    }

    #[test]
    fn delay_delivers_every_packet_in_order() {
        // A Delay is a FIFO slowdown, never a drop or reorder: all packets arrive,
        // in their original order.
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Vote,
            kind: PacketFaultKind::Delay {
                per_packet: Duration::from_millis(50),
            },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2, 3, 4]);
        assert!(matched, "a delay acts on every matching packet");
        assert_eq!(got, vec![1, 2, 3, 4], "delay preserves delivery and order");
    }

    #[test]
    fn corrupt_mutates_the_next_count_then_forwards_unchanged() {
        // The first `count` matching packets have a payload byte XOR-mutated (no
        // re-signing); the rest pass through unchanged. The engine-visible stream
        // differs from the input, so a corrupted message is dropped from HB by
        // its decode failure.
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Vote,
            kind: PacketFaultKind::Corrupt {
                count: 2,
                offset: 0,
                mask: 0xff,
            },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2, 3, 4, 5]);
        assert!(matched, "a corrupt must record that it mutated a packet");
        assert_eq!(
            got,
            vec![1 ^ 0xff, 2 ^ 0xff, 3, 4, 5],
            "the first two packets are byte-mutated, the rest unchanged"
        );
    }

    #[test]
    fn corrupt_only_acts_on_its_target_channel() {
        // The fault targets Certificate; a Vote pump forwards everything intact
        // and never records a match, so corruption is per (node, channel).
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Certificate,
            kind: PacketFaultKind::Corrupt {
                count: 4,
                offset: 0,
                mask: 0xff,
            },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2, 3]);
        assert!(!matched, "a non-matching channel must not act");
        assert_eq!(
            got,
            vec![1, 2, 3],
            "a non-matching channel forwards unchanged"
        );
    }

    #[test]
    fn duplicate_emits_the_original_plus_extra_copies() {
        // Each matching packet is delivered `extra + 1` times; the engine's
        // idempotent vote handling tolerates the duplicates.
        let fault = PacketFault {
            node: NODE,
            channel: SniffChannel::Vote,
            kind: PacketFaultKind::Duplicate { extra: 2 },
        };
        let (got, matched) = drive(Some(fault), SniffChannel::Vote, &[1, 2]);
        assert!(matched, "a duplicate acts on every matching packet");
        assert_eq!(
            got,
            vec![1, 1, 1, 2, 2, 2],
            "each packet is delivered extra+1 = 3 times"
        );
    }

    #[test]
    fn reorder_step_reorders_and_bounds_the_buffer() {
        // With capacity 3 and the alternating LIFO policy, packets 2 and 4 are
        // released ahead of the still-held 1, 3, 5, so delivery order diverges
        // from arrival order while the buffer never grows past capacity.
        let cap = 3u32;
        let mut buffer: VecDeque<Message<Ed25519PublicKey>> = VecDeque::new();
        let mut toggle = 0u64;
        let mut released = Vec::new();
        for t in [1u8, 2, 3, 4, 5] {
            if let Some(r) = reorder_step(&mut buffer, &mut toggle, tagged(t), cap) {
                released.push(tag_of(&r));
            }
            assert!(
                buffer.len() <= cap as usize,
                "the reorder buffer never grows past its capacity"
            );
        }
        assert_eq!(
            released,
            vec![2, 4],
            "newest-on-alternating-packet is released early"
        );
        let held: Vec<u8> = buffer.iter().map(tag_of).collect();
        assert_eq!(
            held,
            vec![1, 3, 5],
            "held packets stay in arrival order for the flush"
        );
    }

    #[test]
    fn reorder_step_full_buffer_releases_the_oldest() {
        // Capacity 2: once full, an arriving packet releases the OLDEST (front)
        // rather than growing, so 1, 3, 4 leave in that order as the window slides.
        let cap = 2u32;
        let mut buffer: VecDeque<Message<Ed25519PublicKey>> = VecDeque::new();
        let mut toggle = 0u64;
        let mut released = Vec::new();
        for t in [1u8, 2, 3, 4, 5, 6] {
            if let Some(r) = reorder_step(&mut buffer, &mut toggle, tagged(t), cap) {
                released.push(tag_of(&r));
            }
            assert!(buffer.len() <= cap as usize, "capacity is never exceeded");
        }
        assert_eq!(
            released,
            vec![2, 1, 3, 4],
            "overflow releases the oldest held packet (1 before 3 before 4)"
        );
        let held: Vec<u8> = buffer.iter().map(tag_of).collect();
        assert_eq!(held, vec![5, 6], "the two most recent packets remain held");
    }

    #[test]
    fn reorder_flush_delivers_every_held_packet_in_order() {
        // End-to-end reorder through the pump: the early LIFO releases (2, 4)
        // arrive first, then the heal-time flush drains the held 1, 3, 5 in order,
        // so the stream is reordered but no packet is lost (liveness).
        let got = drive_reorder_flushed(3, SniffChannel::Vote, &[1, 2, 3, 4, 5]);
        assert_eq!(
            got,
            vec![2, 4, 1, 3, 5],
            "flush drains the held buffer in order"
        );
        let mut sorted = got.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![1, 2, 3, 4, 5],
            "the flush delivers every packet exactly once"
        );
    }

    #[test]
    fn flush_ack_implies_the_reorder_buffer_is_drained() {
        // F3 request-reply barrier: the pump replies to a flush only AFTER draining
        // its held reorder buffer, so once the runner's ack await returns, every held
        // packet is already queued for the engine, none remains buffered in the
        // pump to leak into the next decision step.
        let executor = deterministic::Runner::seeded(1);
        let drained = executor.start(|context| async move {
            let from = sender();
            let (src_tx, src_rx) = mpsc::unbounded_channel::<Message<Ed25519PublicKey>>();
            let (internal_tx, mut internal_rx) = mpsc::unbounded_channel();
            let (flush_tx, flush_rx) = mpsc::unbounded_channel::<FlushAck>();
            let cell = PacketFaultCell::new();
            cell.set(PacketFault {
                node: NODE,
                channel: SniffChannel::Vote,
                kind: PacketFaultKind::Reorder { buffer: 8 },
            });
            for t in [1u8, 2, 3] {
                src_tx
                    .send((from.clone(), IoBuf::copy_from_slice(&[t])))
                    .unwrap();
            }

            let pump_cell = cell.clone();
            context.child("packet_pump").spawn(move |ctx| {
                pump(
                    ctx,
                    PacketFaultReceiver::new(src_rx),
                    internal_tx,
                    flush_rx,
                    pump_cell,
                    NODE,
                    SniffChannel::Vote,
                )
            });

            // Let the pump process the queued source (some released, some held).
            context.sleep(Duration::from_millis(10)).await;
            // Request-reply flush and WAIT for the ack.
            let (ack_tx, ack_rx) = oneshot::channel();
            flush_tx.send(ack_tx).unwrap();
            ack_rx.await.expect("the pump must ack the flush");
            // After the ack, every packet (released + drained-on-flush) is already
            // queued in the engine-facing receiver.
            let mut drained = Vec::new();
            while let Ok((_, payload)) = internal_rx.try_recv() {
                drained.push(payload.as_ref()[0]);
            }
            drained.sort_unstable();
            drained
        });
        assert_eq!(
            drained,
            vec![1, 2, 3],
            "the ack must imply every packet is drained (none left buffered)"
        );
    }
}
