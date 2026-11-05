//! Floors and pruning.
//!
//! A floor is an L-QC, the history record its leader commits to, and the exact last block of
//! every chain once the order the L-QC proves is emitted. [`Ledger::floor_at`] serves the newest
//! one marshal holds at or below an index; [`Ledger::install_floor`] jumps to one from another
//! node; [`Ledger::prune`] drops what the newest one at or below an index makes obsolete.
//!
//! An install is verified before any state changes: the certificate, its record, and the
//! boundary blocks, each of which must be the ancestor at its height of the tip the L-QC (or its
//! record) authenticates. It is then fenced: dispatch stops, the progress write in flight
//! completes, and freshness is checked again against the durable acknowledgement before the
//! floor's parts and the new progress record are written. Nothing older is deleted until that
//! record is durable.

use super::{Error, Ledger, PartKey, failed, order::Order};
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        marshal::{
            input::Reply,
            store::{
                meta::{Ack, State},
                proofs::CutEntry,
            },
            types::{Cause, Floor, LqcVerifier, OutputIndex, Update},
            wire::Key,
        },
        order::{FinalSweep, SweepFact},
        scheme::Scheme,
        types::{Artifact, BlockRef, Body, CertificateId, LqcProof, TransactionBlock},
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_resolver::Resolver;
use commonware_runtime::Spawner;
use commonware_storage::Context;
use futures::stream::FuturesOrdered;
use std::sync::Arc;

/// A floor or prune request waiting for its parts or its progress record.
pub(super) enum Waiter<S: Scheme, D: Digest> {
    /// Serve the newest floor at or below `at`.
    FloorAt {
        at: u64,
        reply: Reply<Option<(OutputIndex, Floor<S, D>)>>,
    },
    /// Prune to the newest floor at or below `below`; `writing` once its record is in flight.
    Prune {
        below: u64,
        reply: Reply<()>,
        writing: Option<State<D>>,
    },
}

impl<S: Scheme, D: Digest> Waiter<S, D> {
    /// Returns whether the waiter's progress record is being written.
    pub(super) const fn writing(&self) -> bool {
        matches!(
            self,
            Self::Prune {
                writing: Some(_),
                ..
            }
        )
    }
}

/// The operation a progress-record write in flight belongs to.
///
/// One record write runs at a time; its owner continues when the record is durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Writer {
    /// The acknowledged cut advanced.
    Ack,
    /// A prune moves the base and retention.
    Prune,
    /// A floor install publishes its floor.
    Install,
}

/// The stage of a floor install.
pub(super) enum Stage<D: Digest> {
    /// The certificate is being verified.
    Verifying,
    /// The boundary blocks are being resolved from their authenticated tips.
    Boundary(Arc<SweepFact<D>>),
    /// Dispatch is fenced while the progress write in flight completes.
    Fencing,
    /// The floor's parts and boundary blocks are being made durable.
    Storing,
    /// The progress record is being written.
    Publishing(State<D>),
}

/// A floor install in progress.
pub(super) struct Install<S: Scheme, D: Digest> {
    floor: Floor<S, D>,
    id: CertificateId<D>,
    commitment: D,
    stage: Stage<D>,
    /// The verified anchor and its finality, stored only once the install is fenced and fresh.
    proof: Option<super::Proven<S, D>>,
    reply: Reply<()>,
}

impl<S: Scheme, D: Digest> Install<S, D> {
    /// Returns the floor's history commitment.
    pub(super) const fn commitment(&self) -> D {
        self.commitment
    }

    /// Returns whether dispatch is fenced.
    pub(super) const fn fenced(&self) -> bool {
        matches!(
            self.stage,
            Stage::Fencing | Stage::Storing | Stage::Publishing(_)
        )
    }
}

/// Returns the acknowledged cut of a floor.
fn floor_ack<S: Scheme, D: Digest>(floor: &Floor<S, D>, commitment: D) -> Ack<D> {
    Ack {
        history: commitment,
        ordered: floor.history().tips().to_vec(),
        emitted: floor.emitted().to_vec(),
    }
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
    /// Serves the newest floor at or below `at`.
    pub(super) fn floor_at(
        &mut self,
        at: OutputIndex,
        reply: crate::multimmit::marshal::input::FloorReply<S, H::Digest>,
    ) {
        self.floor_waiters.push(super::floor::Waiter::FloorAt {
            at: at.get(),
            reply,
        });
    }

    /// Starts installing `floor`.
    pub(super) fn install_floor(&mut self, floor: Floor<S, H::Digest>, reply: Reply<()>) {
        if self.install.is_some() {
            let _ = reply.send(Err(Error::Busy));
            return;
        }
        let commitment = floor.history().commitment::<H>();
        if commitment != floor.anchor().leader().history() {
            let _ = reply.send(Err(Error::Rejected(
                "the record is not the anchor's history",
            )));
            return;
        }
        if let Err(reason) = self.fresh(&floor, commitment) {
            let _ = reply.send(Err(Error::Rejected(reason)));
            return;
        }
        let id = floor.anchor().id::<H>();
        let lqc = floor.anchor().clone();
        self.install = Some(Install {
            floor,
            id,
            commitment,
            stage: Stage::Verifying,
            proof: None,
            reply,
        });
        self.verify(super::Verify::Floor, id, lqc);
    }

    /// Checks that `floor` is newer than the durable floor and not behind the durable
    /// acknowledgement.
    fn fresh(
        &self,
        floor: &Floor<S, H::Digest>,
        commitment: H::Digest,
    ) -> Result<(), &'static str> {
        let durable = self.meta.durable();
        if let Some(current) = durable.floor {
            if let Some(entry) = self.proofs.index().lqc(&current) {
                if floor.anchor().view() <= entry.view {
                    return Err("the floor is not newer than the installed floor");
                }
            }
        }
        let ack = &durable.ack;
        let index: u64 = floor
            .emitted()
            .iter()
            .map(|block| block.height().get())
            .sum();
        if index > ack.index() {
            for (ours, theirs) in ack.emitted.iter().zip(floor.emitted()) {
                if theirs.height() < ours.height()
                    || (theirs.height() == ours.height() && theirs != ours)
                {
                    return Err("the floor conflicts with or is behind delivered blocks");
                }
            }
            return Ok(());
        }
        if index == ack.index() {
            // Only records that emit nothing may lie between: the floor's history must descend
            // from the acknowledged one.
            let ordinals = self.proofs.index();
            if let (Some(ours), Some(theirs)) = (
                ordinals.ordinal(&ack.history),
                ordinals.ordinal(&commitment),
            ) {
                if theirs > ours && floor.emitted() == ack.emitted.as_slice() {
                    return Ok(());
                }
            }
        }
        Err("the floor is behind the acknowledged output")
    }

    /// Takes a verified floor certificate.
    pub(super) fn on_floor_verified(
        &mut self,
        proof: LqcProof<S, H::Digest>,
        fact: Arc<SweepFact<H::Digest>>,
    ) {
        let Some(install) = &mut self.install else {
            return;
        };
        if proof.id() != install.id {
            return;
        }
        // The boundary must be exactly where the certificate's own sweep ends above its record.
        let record = install.floor.history();
        let placed =
            FinalSweep::placed(record.tips(), fact.tips(), fact.proposed(), fact.settled());
        let matches = placed.is_ok_and(|placed| {
            placed
                .iter()
                .zip(install.floor.emitted())
                .all(|(height, block)| *height == block.height())
        });
        if !matches {
            self.reject("the boundary is not where the certificate's sweep ends");
            return;
        }
        install.stage = Stage::Boundary(Arc::clone(&fact));
        install.proof = Some((proof, fact));
    }

    /// Fails the install in progress, leaving state unchanged.
    pub(super) fn reject(&mut self, reason: &'static str) {
        if let Some(install) = self.install.take() {
            let _ = install.reply.send(Err(Error::Rejected(reason)));
        }
    }

    /// Advances the install and the waiting floor and prune requests.
    pub(super) fn drive_floors(&mut self) -> Result<(), Error> {
        self.drive_install()?;
        let waiters = std::mem::take(&mut self.floor_waiters);
        for waiter in waiters {
            if let Some(waiter) = self.drive_waiter(waiter)? {
                self.floor_waiters.push(waiter);
            }
        }
        Ok(())
    }

    fn drive_install(&mut self) -> Result<(), Error> {
        let Some(install) = &self.install else {
            return Ok(());
        };
        match &install.stage {
            Stage::Verifying | Stage::Publishing(_) => {}
            Stage::Boundary(fact) => {
                // Every boundary block must be the ancestor at its height of the tip that
                // authenticates it: the record's tip when the sweep placed nothing on the chain,
                // otherwise the certificate's final tip.
                let fact = Arc::clone(fact);
                let record = install.floor.history();
                let emitted = install.floor.emitted().to_vec();
                let mut wants = Vec::new();
                let mut done = true;
                for (chain, boundary) in emitted.iter().enumerate() {
                    let base = record.tips()[chain];
                    let tip = if boundary.height() == base.height() {
                        base
                    } else {
                        fact.tips()[chain]
                    };
                    let mut cursor = tip;
                    while cursor.height() > boundary.height() {
                        match self.blocks.header(cursor) {
                            Some(header) => cursor = header.parent_ref(),
                            None => break,
                        }
                    }
                    if cursor.height() > boundary.height() {
                        wants.push((cursor, boundary.height()));
                        done = false;
                        continue;
                    }
                    if cursor != *boundary {
                        self.reject("a boundary block is not on the authenticated path");
                        return Ok(());
                    }
                    // A chain that emitted nothing ends at its genesis tip, which is not a block.
                    if !boundary.height().is_zero() && !self.blocks.known(*boundary) {
                        wants.push((*boundary, boundary.height()));
                        done = false;
                    }
                }
                for (block, low) in wants {
                    self.want(block, low);
                }
                if done {
                    if let Some(install) = &mut self.install {
                        install.stage = Stage::Fencing;
                    }
                }
            }
            Stage::Fencing => {
                if self.writing.is_some() {
                    return Ok(());
                }
                let floor = install.floor.clone();
                let commitment = install.commitment;
                if let Err(reason) = self.fresh(&floor, commitment) {
                    self.reject(reason);
                    return Ok(());
                }
                let id = install.id;
                let cut = CutEntry {
                    lqc: id,
                    boundary: floor.emitted().to_vec(),
                };
                // Nothing of the floor is stored before the install is fenced and fresh.
                if let Some((proof, fact)) = self
                    .install
                    .as_mut()
                    .and_then(|install| install.proof.take())
                {
                    self.accept_proof(proof, fact);
                }
                if self
                    .proofs
                    .insert_record(commitment, Arc::new(floor.history().clone()))
                {
                    self.metrics.records.inc();
                }
                self.proofs.insert_cut(commitment, cut);
                if let Some(install) = &mut self.install {
                    install.stage = Stage::Storing;
                }
            }
            Stage::Storing => {
                let index = self.proofs.index();
                let id = install.id;
                let stored = |stored: Option<crate::multimmit::marshal::store::proofs::Stored>| {
                    stored.is_some_and(|stored| self.proofs.durable(stored))
                };
                let parts = stored(index.lqc(&id).map(|entry| entry.stored))
                    && stored(index.record(&install.commitment).map(|entry| entry.stored))
                    && stored(index.cut_of(&id).map(|(_, row)| row.stored));
                let bodies = install
                    .floor
                    .emitted()
                    .iter()
                    .all(|block| block.height().is_zero() || self.blocks.durable(*block));
                if !parts || !bodies || self.writing.is_some() {
                    return Ok(());
                }
                let durable = self.meta.durable();
                let retained = self.retained(durable.retained.clone(), install.floor.emitted());
                let state = State {
                    epoch: durable.epoch,
                    ack: floor_ack(&install.floor, install.commitment),
                    floor: Some(id),
                    base: install.commitment,
                    retained,
                };
                if let Some(install) = &mut self.install {
                    install.stage = Stage::Publishing(state.clone());
                }
                self.write_meta(state, Writer::Install);
            }
        }
        Ok(())
    }

    /// Returns the retention floors after a floor whose boundary is `boundary`: each chain keeps
    /// its boundary block, and every block the engine may still verify.
    fn retained(&self, current: Vec<Height>, boundary: &[BlockRef<H::Digest>]) -> Vec<Height> {
        current
            .into_iter()
            .zip(boundary)
            .zip(&self.released)
            .map(|((current, boundary), released)| {
                released.map_or(current, |released| {
                    current.max(boundary.height().min(Height::new(released.get() + 1)))
                })
            })
            .collect()
    }

    /// Continues the operation whose progress-record write is durable.
    pub(super) fn on_meta_durable(&mut self, writer: Writer) -> Result<(), Error> {
        let durable = self.meta.durable().clone();
        self.metrics.acknowledged.set(durable.ack.index() as i64);
        match writer {
            Writer::Ack => {}
            Writer::Install => {
                let install = self
                    .install
                    .take_if(|install| {
                        matches!(&install.stage, Stage::Publishing(state) if *state == durable)
                    })
                    .ok_or_else(|| {
                        failed(Cause::Safety("a published floor is not the install in progress"))
                    })?;
                self.apply_base(&durable)?;
                // Delivery restarts at the floor: acknowledgements of outputs delivered before
                // it are no longer awaited.
                let ordinal =
                    self.proofs.index().ordinal(&durable.base).ok_or_else(|| {
                        failed(Cause::Safety("the installed floor is not stored"))
                    })?;
                let cut = durable
                    .ack
                    .cut()
                    .ok_or_else(|| failed(Cause::Safety("the installed floor is malformed")))?;
                let capacity = 4 * self.codec.chains() * self.codec.pipeline_depth().max(1);
                self.order = Order::new(cut, ordinal, capacity);
                self.ends.reset(ordinal);
                self.target = None;
                self.delivered = durable.ack.emitted.clone();
                self.acked = durable.ack.clone();
                self.acks = FuturesOrdered::new();
                self.outstanding = 0;
                self.walk = None;
                self.hints.iter_mut().for_each(|hint| *hint = None);
                self.metrics.floors.inc();
                self.metrics.delivered.set(durable.ack.index() as i64);
                let _ = install.reply.send(Ok(()));
            }
            Writer::Prune => {
                let mut replies = Vec::new();
                let waiters = std::mem::take(&mut self.floor_waiters);
                for waiter in waiters {
                    match waiter {
                        Waiter::Prune {
                            writing: Some(state),
                            reply,
                            ..
                        } if state == durable => replies.push(reply),
                        waiter => self.floor_waiters.push(waiter),
                    }
                }
                if replies.is_empty() {
                    return Err(failed(Cause::Safety(
                        "a published prune has no waiting request",
                    )));
                }
                self.apply_base(&durable)?;
                self.metrics.prunes.inc();
                for reply in replies {
                    let _ = reply.send(Ok(()));
                }
            }
        }
        self.trim();
        Ok(())
    }

    /// Drops what the durable progress record's base and retention make obsolete.
    fn apply_base(&mut self, durable: &State<H::Digest>) -> Result<(), Error> {
        self.proofs
            .rebase(durable.base, durable.floor)
            .map_err(super::storage)?;
        self.blocks.prune(&durable.retained);
        // Bodies held in memory go with their blocks.
        let index = self.blocks.index();
        self.hot.retain(|block| index.admits(block.reference()));
        self.metrics.hot_bytes.set(self.hot.bytes as i64);
        Ok(())
    }

    /// Starts pruning to the newest floor at or below `below`.
    pub(super) fn prune(&mut self, below: OutputIndex, reply: Reply<()>) {
        self.floor_waiters.push(Waiter::Prune {
            below: below.get(),
            reply,
            writing: None,
        });
    }

    /// Returns the newest durable floor at or below `at` whose history is connected, with its
    /// output index.
    fn newest_floor(&self, at: u64) -> Option<(u64, CertificateId<H::Digest>, H::Digest)> {
        let index = self.proofs.index();
        index.cuts_at_most(at).find_map(|(cut, row)| {
            let lqc = index.lqc(&row.lqc)?;
            let record = index.record(&row.history);
            (index.ordinal(&row.history).is_some()
                && self.proofs.durable(row.stored)
                && self.proofs.durable(lqc.stored)
                && record.is_some_and(|record| self.proofs.durable(record.stored)))
            .then_some((cut, row.lqc, row.history))
        })
    }

    /// Advances one floor or prune request, returning it while it still waits.
    fn drive_waiter(
        &mut self,
        waiter: Waiter<S, H::Digest>,
    ) -> Result<Option<Waiter<S, H::Digest>>, Error> {
        match waiter {
            Waiter::FloorAt { at, reply } => {
                if reply.is_closed() {
                    return Ok(None);
                }
                let Some((index, id, history)) = self.newest_floor(at) else {
                    let _ = reply.send(Ok(None));
                    return Ok(None);
                };
                let Some(parts) = self.floor_parts(id, history) else {
                    return Ok(Some(Waiter::FloorAt { at, reply }));
                };
                let _ = reply.send(Ok(Some((OutputIndex::new(index), parts))));
                Ok(None)
            }
            Waiter::Prune {
                below,
                reply,
                writing: Some(state),
            } => Ok(Some(Waiter::Prune {
                below,
                reply,
                writing: Some(state),
            })),
            Waiter::Prune {
                below,
                reply,
                writing: None,
            } => {
                if self.install.is_some() || self.writing.is_some() {
                    return Ok(Some(Waiter::Prune {
                        below,
                        reply,
                        writing: None,
                    }));
                }
                let durable = self.meta.durable().clone();
                let at = below.min(durable.ack.index());
                let Some((index, id, history)) = self.newest_floor(at) else {
                    let _ = reply.send(Ok(()));
                    return Ok(None);
                };
                if Some(id) == durable.floor && history == durable.base {
                    // Nothing new to prune.
                    let _ = reply.send(Ok(()));
                    return Ok(None);
                }
                let Some(cut) = self.cuts.get(&id).cloned() else {
                    if let Some((_, row)) = self.proofs.index().cut_of(&id) {
                        let stored = row.stored;
                        self.read_part(PartKey::Cut(id), stored);
                    }
                    return Ok(Some(Waiter::Prune {
                        below,
                        reply,
                        writing: None,
                    }));
                };
                let Some(record) = self.records.get(&history).cloned() else {
                    if let Some(entry) = self.proofs.index().record(&history).copied() {
                        self.read_part(PartKey::Record(history), entry.stored);
                    }
                    return Ok(Some(Waiter::Prune {
                        below,
                        reply,
                        writing: None,
                    }));
                };
                // Only records that emit nothing lie between a floor at the acknowledged index
                // and the acknowledgement: move the acknowledgement forward to the floor so the
                // chain from it never needs a dropped record.
                let index_ordinal = self.proofs.index().ordinal(&history);
                let ack_ordinal = self.proofs.index().ordinal(&durable.ack.history);
                let ack = if index == durable.ack.index() && index_ordinal > ack_ordinal {
                    Ack {
                        history,
                        ordered: record.tips().to_vec(),
                        emitted: cut.boundary.clone(),
                    }
                } else {
                    durable.ack.clone()
                };
                let state = State {
                    epoch: durable.epoch,
                    ack,
                    floor: Some(id),
                    base: history,
                    retained: self.retained(durable.retained.clone(), &cut.boundary),
                };
                if self.acked.index() <= state.ack.index() && state.ack != durable.ack {
                    self.acked = state.ack.clone();
                }
                self.write_meta(state.clone(), Writer::Prune);
                Ok(Some(Waiter::Prune {
                    below,
                    reply,
                    writing: Some(state),
                }))
            }
        }
    }

    /// Returns the floor of L-QC `id` when its parts are in memory, reading the ones that are
    /// not.
    fn floor_parts(
        &mut self,
        id: CertificateId<H::Digest>,
        history: H::Digest,
    ) -> Option<Floor<S, H::Digest>> {
        let index = self.proofs.index();
        let lqc = self.lqcs.get(&id).cloned();
        let record = self.records.get(&history).cloned();
        let cut = self.cuts.get(&id).cloned();
        if lqc.is_none() {
            let stored = index.lqc(&id)?.stored;
            self.read_part(PartKey::Lqc(id), stored);
        }
        if record.is_none() {
            let stored = self.proofs.index().record(&history)?.stored;
            self.read_part(PartKey::Record(history), stored);
        }
        if cut.is_none() {
            let stored = self.proofs.index().cut_of(&id)?.1.stored;
            self.read_part(PartKey::Cut(id), stored);
        }
        let (lqc, record, cut) = (lqc?, record?, cut?);
        let Artifact::Lqc(anchor) = lqc.artifact().as_ref() else {
            return None;
        };
        Some(Floor::new(
            Arc::new(anchor.clone()),
            record,
            cut.boundary.clone(),
        ))
    }
}
