//! Delivery: resolving and fetching blocks, dispatch, acknowledgements and the progress record.
//!
//! A position is dispatched only when its proof, the identity path from its tip down to it, and
//! its body are durable, and the acknowledgement window has room. Acknowledgements drain in
//! order; each drained group is written to the progress record, one write at a time.

use super::{Error, Event, Ledger, failed, order::Slot};
use crate::{
    Reporter,
    multimmit::{
        marshal::{
            input::Delivered,
            store::{blocks::Stream, meta::State},
            types::{Cause, LqcVerifier, OutputIndex, Update},
            wire::{Key, MAX_BLOCKS},
        },
        scheme::Scheme,
        types::{BlockRef, Body, CertificateId, TransactionBlock},
    },
    types::Height,
};
use commonware_actor::Feedback;
use commonware_cryptography::{Hasher, PublicKey};
use commonware_resolver::{Outcome, Resolution, Resolver};
use commonware_runtime::Spawner;
use commonware_storage::Context;
use commonware_utils::acknowledgement::{Acknowledgement as _, Canceled, Exact};
use futures::FutureExt as _;
use std::{num::NonZeroU16, sync::Arc};

/// Most positions whose bodies are read ahead of dispatch (fewer when the hot cache cannot pin
/// that many maximum-size blocks).
const READ_AHEAD: usize = 32;

/// How long a request may stay in flight before marshal asks the resolver for it again.
const REASSERT: std::time::Duration = std::time::Duration::from_secs(5);

/// Most requests waiting for the fetch budget.
pub(super) const MAX_DEFERRED: usize = 1024;

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
    /// Takes proven positions into the window and resolves their blocks, fetching what is
    /// missing.
    pub(super) fn drive_order(&mut self) -> Result<(), Error> {
        if self
            .install
            .as_ref()
            .is_some_and(|install| install.fenced())
        {
            return Ok(());
        }
        self.order
            .fill()
            .map_err(|_| failed(Cause::Safety("authenticated proofs do not form an order")))?;
        self.metrics.proven.set(self.order.cut().index() as i64);
        let blocks = &self.blocks;
        let needs = self
            .order
            .resolve(|block| blocks.header(block).map(|header| header.parent_ref()));
        for need in needs {
            self.want(need.block, need.low);
        }
        // A resolved position whose block is not held yet still needs it.
        let unheld = self
            .order
            .window()
            .iter()
            .filter_map(|slot| slot.block)
            .filter(|block| !self.blocks.known(*block))
            .collect::<Vec<_>>();
        for block in unheld {
            self.want(block, block.height());
        }
        Ok(())
    }

    /// Dispatches every position that is ready, in order.
    pub(super) fn drive_dispatch(&mut self) -> Result<(), Error> {
        if self
            .install
            .as_ref()
            .is_some_and(|install| install.fenced())
        {
            return Ok(());
        }
        self.durability_wanted = false;
        while self.outstanding < self.limits.max_pending_acks.get() {
            let blocks = &self.blocks;
            let Some(slot) = self.order.ready(|block| blocks.durable(block)) else {
                // A resolved front whose path is all held waits only for a cut.
                self.durability_wanted = self
                    .order
                    .window()
                    .front()
                    .and_then(|slot| slot.block)
                    .is_some_and(|block| self.blocks.known(block));
                break;
            };
            let block = slot.block.expect("ready positions are resolved");
            let Some(body) = self.hot.get(block).cloned() else {
                self.read_body(block);
                break;
            };
            let slot = self.order.pop().expect("a ready position is first");
            self.hot.remove(block);
            self.dispatch(slot, body)?;
        }
        // Read the bodies of the next positions ahead of their turn, no more than the hot cache
        // pins.
        let read_ahead = READ_AHEAD.min(self.hot.max_pinned());
        let ahead = self
            .order
            .window()
            .iter()
            .take(read_ahead)
            .filter_map(|slot| slot.block)
            .filter(|block| self.hot.get(*block).is_none() && self.blocks.durable(*block))
            .collect::<Vec<_>>();
        // The next positions' bodies stay in memory until dispatched.
        let next = self
            .order
            .window()
            .iter()
            .take(read_ahead)
            .filter_map(|slot| slot.block);
        self.hot.pin(next);
        for block in ahead {
            self.read_body(block);
        }
        self.metrics.hot_bytes.set(self.hot.bytes as i64);
        Ok(())
    }

    /// Delivers one position to the application.
    fn dispatch(
        &mut self,
        slot: Slot<H::Digest>,
        body: Arc<TransactionBlock<H, B>>,
    ) -> Result<(), Error> {
        let block = slot.block.expect("dispatched positions are resolved");
        let chain = slot.chain();
        self.delivered[chain] = block;
        let index = slot.position.index;
        let (acknowledgement, waiter) = Exact::handle();
        let slot = Box::new(slot);
        self.acks
            .push_back(waiter.map(move |result| (slot, result)).boxed());
        self.outstanding += 1;
        self.metrics.delivered.set(index as i64);
        self.write_cut_entries(index);
        let update = Update {
            index: OutputIndex::new(index),
            block: body,
            acknowledgement,
        };
        if self.application.report(update) == Feedback::Closed {
            return Err(failed(Cause::Application));
        }
        Ok(())
    }

    /// Takes the next acknowledgement, in delivery order.
    pub(super) fn on_ack(
        &mut self,
        slot: Slot<H::Digest>,
        result: Result<(), Canceled>,
    ) -> Result<(), Error> {
        result.map_err(|_| failed(Cause::Acknowledgement))?;
        self.outstanding -= 1;
        let block = slot.block.expect("acknowledged positions are resolved");
        self.acked.emitted[slot.chain()] = block;
        self.acked.history = slot.history;
        if self.acked.ordered.as_slice() != &*slot.ordered {
            self.acked.ordered = slot.ordered.to_vec();
        }
        self.metrics.acknowledged.set(slot.position.index as i64);
        Ok(())
    }

    /// Writes the acknowledged cut once the previous write is durable.
    pub(super) fn drive_meta(&mut self) {
        // Only a fenced install holds acknowledgements back: until then they stay durable.
        if self.writing.is_some()
            || self
                .install
                .as_ref()
                .is_some_and(|install| install.fenced())
            || self.pruning()
        {
            return;
        }
        let durable = self.meta.durable();
        if durable.ack == self.acked {
            return;
        }
        let state = State {
            ack: self.acked.clone(),
            ..durable.clone()
        };
        self.write_meta(state, super::floor::Writer::Ack);
    }

    /// Starts writing `state` for `writer`, which continues once it is durable.
    pub(super) fn write_meta(&mut self, state: State<H::Digest>, writer: super::floor::Writer) {
        let job = self
            .meta
            .start(state)
            .expect("one progress-record write runs at a time");
        debug_assert!(self.writing.is_none());
        self.writing = Some(writer);
        self.spawn("meta", job.run(), Event::Meta);
    }

    /// Wants the exact block `block` and its ancestors down to `low`.
    pub(super) fn want(&mut self, block: BlockRef<H::Digest>, low: Height) {
        if self.blocks.known(block) || self.buffering.contains(&block) {
            return;
        }
        if self.asked.requests_head(&block) {
            return;
        }
        // The broadcast buffer is local: try it before asking peers.
        let buffer = self.buffer.clone();
        self.buffering.insert(block);
        self.spawn(
            "buffer",
            async move { buffer.get(block.digest()).await },
            move |found| {
                Event::Buffered(
                    block,
                    Some(low),
                    found.map(|digested| digested.inner_shared()),
                )
            },
        );
    }

    /// Fetches `head` and its ancestors down to `low` from peers.
    pub(super) fn fetch_range(&mut self, head: BlockRef<H::Digest>, low: Height) {
        let per_response = (self.limits.max_response_bytes.get()
            / self.limits.max_block_bytes.get())
        .clamp(1, usize::from(MAX_BLOCKS)) as u64;
        let span = head.height().get().saturating_sub(low.get()) + 1;
        let len = NonZeroU16::new(span.min(per_response) as u16).expect("at least one block");
        let reserve = u64::from(len.get()) * self.limits.max_block_bytes.get() as u64;
        self.fetch(Key::Blocks { head, len }, reserve);
    }

    /// Issues `key` to peers, reserving `reserve` bytes, unless it is in flight. A request over
    /// the byte budget waits, in order, until reservations settle (see [`Self::settle`]).
    ///
    /// One request always fits, so a maximum-size block is never starved.
    pub(super) fn fetch(&mut self, key: Key<H::Digest>, reserve: u64) {
        if self.asked.contains(&key) {
            return;
        }
        if !self.admits(reserve) {
            self.asked.defer(key, reserve);
            return;
        }
        self.issue(key, reserve);
    }

    /// Returns whether a request reserving `reserve` bytes fits the budget now. Fetched blocks
    /// not yet appended count against it until their append runs.
    fn admits(&self, reserve: u64) -> bool {
        self.asked.idle()
            || self.asked.bytes() + self.blocks.pending_bytes(Stream::Bulk) + reserve
                <= self.limits.max_fetch_bytes.get() as u64
    }

    /// Issues a request that fits the budget.
    fn issue(&mut self, key: Key<H::Digest>, reserve: u64) {
        if matches!(key, Key::Blocks { .. }) {
            self.metrics.fetches.inc();
        }
        self.asked.issue(key, reserve, self.context.current());
        let _ = self.resolver.fetch(key);
    }

    /// Asks the resolver again for every request in flight longer than [`REASSERT`]: demand is
    /// level triggered, so a request the resolver lost (or kept sending to unresponsive peers) is
    /// never waited on forever. Fetching a key in flight is idempotent.
    pub(super) fn reassert(&mut self) {
        let now = self.context.current();
        let Some(before) = now.checked_sub(REASSERT) else {
            return;
        };
        for key in self.asked.stale(before, now) {
            let _ = self.resolver.fetch(key);
        }
    }

    /// Releases an in-flight request and issues the deferred requests that now fit.
    pub(super) fn settle(&mut self, key: &Key<H::Digest>) -> bool {
        if !self.asked.settle(key) {
            return false;
        }
        self.issue_deferred();
        true
    }

    /// Issues the deferred requests that fit the budget, oldest first, skipping blocks held
    /// meanwhile.
    pub(super) fn issue_deferred(&mut self) {
        while let Some((key, reserve)) = self.asked.next_deferred() {
            if let Key::Blocks { head, .. } = key
                && self.blocks.known(head)
            {
                self.asked.take_deferred();
                continue;
            }
            if !self.admits(reserve) {
                break;
            }
            self.asked.take_deferred();
            self.issue(key, reserve);
        }
    }

    /// Walks placement hints down from their tips and fetches what is missing.
    pub(super) fn drive_acquire(&mut self) {
        let window = (4 * self.codec.pipeline_depth().max(1)) as u64;
        for chain in 0..self.hints.len() {
            let Some((tip, low)) = self.hints[chain] else {
                continue;
            };
            let delivered = self.delivered[chain].height();
            // Hints far beyond delivery would only grow memory; the order wants them in time.
            if low <= delivered || tip.height().get() > delivered.get() + window {
                if low <= delivered {
                    self.hints[chain] = None;
                }
                continue;
            }
            let mut cursor = tip;
            let mut missing = None;
            while cursor.height() >= low {
                match self.blocks.header(cursor) {
                    Some(header) => cursor = header.parent_ref(),
                    None => {
                        missing = Some(cursor);
                        break;
                    }
                }
            }
            match missing {
                Some(block) => self.want(block, low),
                None => self.hints[chain] = None,
            }
        }
    }

    /// Takes a peer response.
    pub(super) fn on_delivered(&mut self, delivered: Delivered<H, S, B>) -> Result<(), Error> {
        match delivered {
            Delivered::Blocks {
                head,
                len,
                blocks,
                verdict,
            } => {
                let requested = self.settle(&Key::Blocks { head, len });
                let explicit = self.fetching.remove(&head);
                if !requested && !explicit {
                    let _ = verdict.send(Outcome::Ignored);
                    return Ok(());
                }
                self.metrics.fetched_blocks.inc_by(blocks.len() as u64);
                for block in blocks {
                    self.insert_block(Stream::Bulk, block);
                }
                let _ = verdict.send(Outcome::Resolved(Resolution::Complete));
            }
            Delivered::Records {
                before,
                records,
                verdict,
            } => {
                if !self.settle(&Key::Records { before }) {
                    let _ = verdict.send(Outcome::Ignored);
                    return Ok(());
                }
                let progressed = self.on_records(records);
                let _ = verdict.send(if progressed {
                    Outcome::Resolved(Resolution::Complete)
                } else {
                    Outcome::Unresolved
                });
            }
            Delivered::Pruned { before, verdict } => {
                if self.asked.in_flight(&Key::Records { before }) {
                    self.on_pruned();
                }
                // Another server may still hold the history.
                let _ = verdict.send(Outcome::Unresolved);
            }
            Delivered::Proof {
                after,
                id,
                lqc,
                record,
                verdict,
            } => {
                if !self.settle(&Key::Proofs { after }) {
                    let _ = verdict.send(Outcome::Ignored);
                    return Ok(());
                }
                let commitment = lqc.leader().history();
                // The verdict waits for the certificate's verification.
                self.verify(super::Verify::Proof(commitment, record, verdict), id, lqc);
            }
            Delivered::Lqc { id, lqc, verdict } => {
                if !self.settle(&Key::Lqc { id }) {
                    let _ = verdict.send(Outcome::Ignored);
                    return Ok(());
                }
                self.verify(super::Verify::Fetched(verdict), id, lqc);
            }
        }
        Ok(())
    }

    /// Returns whether a prune waits for its progress record.
    pub(super) fn pruning(&self) -> bool {
        self.floor_waiters.iter().any(|waiter| waiter.writing())
    }

    /// Drops in-memory state the delivered cut has passed, and every cached part the store no
    /// longer holds or queues (a prune or floor dropped it).
    pub(super) fn trim(&mut self) {
        let proofs = &self.proofs;
        let index = proofs.index();
        // Opened cuts above the acknowledged history may still project late L-QCs' ends.
        let Some(floor) = index.ordinal(&self.acked.history) else {
            return;
        };
        let floor = floor.min(self.order.queued());
        self.order.forget_below(floor);
        self.records.retain(|commitment, _| {
            index
                .ordinal(commitment)
                .map_or_else(|| proofs.known(commitment), |ordinal| ordinal + 1 >= floor)
        });
        let keep = |id: &CertificateId<H::Digest>| {
            index.lqc(id).map_or_else(
                || proofs.known(&id.get()),
                |entry| {
                    index
                        .ordinal(&entry.history)
                        .is_none_or(|ordinal| ordinal >= floor)
                },
            )
        };
        self.facts.retain(|id, _| keep(id));
        self.lqcs.retain(|id, _| keep(id));
        self.cuts.retain(|id, _| index.cut_of(id).is_some());
        // Ends at or below the delivered output are written or will never be reached.
        let delivered = self
            .delivered
            .iter()
            .map(|block| block.height().get())
            .sum::<u64>();
        self.ends.trim(keep, delivered);
    }
}
