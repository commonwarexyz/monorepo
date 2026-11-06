//! Proofs: what consensus and peers report, the order's target, and record walks.
//!
//! Every L-QC consensus verifies arrives with the finality it proves and the history records
//! placed since the last one; records are stored at once, connected or not. The order is fed up
//! to the strongest durable L-QC whose leader history is durable and connected (its target). An
//! L-QC whose history does not connect starts a walk: records are fetched backward from its
//! history, each authenticated by the one after it, until they meet the stored chain.

use super::{
    Error, Event, Ledger, PartKey, Verify, failed,
    order::{Feed, Target},
};
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        marshal::{
            types::{Cause, LqcVerifier, Update},
            wire::Key,
        },
        order::{FinalSweep, SweepFact},
        scheme::Scheme,
        types::{Artifact, Body, CertificateId, Lqc, LqcProof, TransactionBlock},
    },
    types::Height,
};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_resolver::{Outcome, Resolution, Resolver};
use commonware_runtime::Spawner;
use commonware_storage::Context;
use std::sync::Arc;

/// A walk of records backward from an L-QC's history toward the stored chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Walk<D: commonware_cryptography::Digest> {
    /// The history the walk connects.
    target: D,
    /// The oldest commitment reached below the target through stored records: the next record
    /// to fetch. It only moves down, so each stored record is stepped over once.
    before: D,
    /// Responses reporting the history pruned since the walk last progressed.
    pruned: usize,
}

/// Records read ahead of the openings that need them.
const RECORD_READ_AHEAD: u64 = 8;

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
    /// Takes what consensus reported.
    pub(super) fn on_feed(&mut self) -> Result<(), Error> {
        let fed = self.lane.take();
        if fed.overflowed {
            return Err(failed(Cause::Backlog));
        }
        for record in fed.records {
            let commitment = record.commitment::<H>();
            if self.proofs.insert_record(commitment, Arc::clone(&record)) {
                self.metrics.records.inc();
            }
            self.records.insert(commitment, record);
        }
        if !fed.proofs.is_empty() {
            self.last_proof = self.context.current();
        }
        for (proof, fact) in fed.proofs {
            // Consensus extracted the fact from the verified certificate, so nothing is hashed
            // or verified again here.
            let Ok(fact) = SweepFact::try_from(&fact) else {
                continue;
            };
            self.accept_proof(proof, Arc::new(fact));
        }
        for run in fed.placed {
            let chain = run.tip().chain().get() as usize;
            let Some(delivered) = self.delivered.get(chain) else {
                continue;
            };
            if run.height() <= delivered.height() {
                continue;
            }
            let low = Height::new(run.above().get().max(delivered.height().get()) + 1);
            let hint = &mut self.hints[chain];
            if hint.is_none_or(|(tip, _)| tip.height() < run.tip().height()) {
                *hint = Some((run.tip(), low));
            }
        }
        for (chain, released) in fed.released.into_iter().enumerate() {
            if let Some(released) = released {
                let known = &mut self.released[chain];
                *known = Some(known.map_or(released, |known| known.max(released)));
            }
        }
        Ok(())
    }

    /// Stores a verified L-QC and keeps the finality it proves.
    pub(super) fn accept_proof(
        &mut self,
        proof: LqcProof<S, H::Digest>,
        fact: Arc<SweepFact<H::Digest>>,
    ) {
        // An L-QC no newer than the floor proves nothing marshal still orders, and its history
        // can never connect above the base.
        let durable = self.meta.durable();
        let floor_view = durable
            .floor
            .and_then(|floor| self.proofs.index().lqc(&floor))
            .map(|entry| entry.view);
        if floor_view.is_some_and(|floor| proof.lqc().view() <= floor) {
            return;
        }
        let id = proof.id();
        if self.proofs.insert_lqc(&proof) {
            self.metrics.lqcs.inc();
        }
        self.facts.insert(id, fact);
        self.lqcs.insert(id, proof);
    }

    /// Queues the ends of newly indexed L-QCs whose history the order already opened.
    pub(super) fn on_indexed(&mut self, lqcs: &[CertificateId<H::Digest>]) {
        self.ends.indexed(lqcs, self.proofs.index());
    }

    /// Records connected to the stored chain.
    pub(super) fn on_connected(&mut self, connected: &[H::Digest]) {
        if let Some(walk) = &self.walk {
            if self.proofs.index().ordinal(&walk.target).is_some()
                || connected.contains(&walk.target)
            {
                self.walk = None;
            }
        }
    }

    /// Chooses the target and feeds the order toward it.
    ///
    /// The target is the strongest durable L-QC at the highest connected ordinal at or above the
    /// queued one: the index keeps L-QCs by their history's ordinal, so choosing costs only the
    /// L-QCs at that ordinal. Their facts and their record are read first when not in memory.
    pub(super) fn drive_feed(&mut self) -> Result<(), Error> {
        if self
            .install
            .as_ref()
            .is_some_and(|install| install.fenced())
        {
            return Ok(());
        }
        self.settle_ends();
        let floor = self.order.queued();
        let mut best: Option<(Target<H::Digest>, crate::types::View)> = None;
        let mut extract = Vec::new();
        let mut read = Vec::new();
        let index = self.proofs.index();
        for (ordinal, ids) in index.connected_from(floor).rev() {
            let durable = ids
                .iter()
                .filter_map(|id| index.lqc(id).map(|entry| (*id, *entry)))
                .filter(|(_, entry)| self.proofs.durable(entry.stored))
                .collect::<Vec<_>>();
            let Some((_, first)) = durable.first() else {
                continue;
            };
            // Every L-QC here shares one leader history, so one record scores them all.
            let history = first.history;
            let tips = match self.records.get(&history) {
                Some(record) => Some(record.tips()),
                None if history == self.order.cut().history() => Some(self.order.cut().ordered()),
                None => None,
            };
            let Some(tips) = tips else {
                if let Some(entry) = index.record(&history) {
                    read.push((PartKey::Record(history), entry.stored));
                }
                break;
            };
            for (id, entry) in durable {
                let Some(fact) = self.facts.get(&id) else {
                    if self.lqcs.contains_key(&id) {
                        extract.push(id);
                    } else {
                        read.push((PartKey::Lqc(id), entry.stored));
                    }
                    continue;
                };
                let strength = FinalSweep::placed(
                    tips,
                    fact.tips(),
                    fact.proposed(),
                    fact.settled(),
                    self.order.lanes(),
                )
                .map(|placed| placed.iter().map(|height| height.get()).sum())
                .unwrap_or(0);
                let candidate = Target {
                    id,
                    history,
                    ordinal,
                    fact: Arc::clone(fact),
                    strength,
                };
                // The newest view breaks ties, so the choice never depends on storage order.
                if best.as_ref().is_none_or(|(best, view)| {
                    (candidate.strength, entry.view) > (best.strength, *view)
                }) {
                    best = Some((candidate, entry.view));
                }
            }
            break;
        }
        for id in extract {
            self.extract(id);
        }
        for (key, stored) in read {
            self.read_part(key, stored);
        }
        let Some((best, _)) = best else {
            return Ok(());
        };
        // A target the order already swept is replaced only by a stronger or later one.
        if let Some(current) = &self.target {
            if self.order.swept() == Some(current.id)
                && (best.ordinal, best.strength) <= (current.ordinal, current.strength)
            {
                return Ok(());
            }
        }
        let mut fed = self.feed_toward(&best);
        while let Feed::Unprojected(ordinal) = fed {
            // Openings just queued place new ends: feeding continues once they are known.
            self.settle_ends();
            if !self.ends.projected_through(ordinal) {
                break;
            }
            fed = self.feed_toward(&best);
        }
        // Read the records the next openings need, a few at a time.
        if matches!(fed, Feed::Record(_) | Feed::Ahead | Feed::Unprojected(_)) {
            let from = self.order.queued() + 1;
            let through = best.ordinal.min(from + RECORD_READ_AHEAD - 1);
            for ordinal in from..=through {
                let Some(commitment) = self.proofs.index().at(ordinal) else {
                    break;
                };
                if self.records.contains_key(&commitment) {
                    continue;
                }
                if let Some(entry) = self.proofs.index().record(&commitment).copied() {
                    self.read_part(PartKey::Record(commitment), entry.stored);
                }
            }
        }
        self.target = Some(best);
        // Openings just queued place new ends; project them before anything is dispatched.
        self.settle_ends();
        Ok(())
    }

    /// Feeds the order toward `target`, opening no record past an ordinal whose L-QCs' ends
    /// are not all projected.
    fn feed_toward(&mut self, target: &Target<H::Digest>) -> Feed {
        let proofs = &self.proofs;
        let records = &self.records;
        let ends = &self.ends;
        self.order.feed(
            target,
            |ordinal| {
                let commitment = proofs.index().at(ordinal)?;
                let entry = proofs.index().record(&commitment)?;
                if !proofs.durable(entry.stored) {
                    return None;
                }
                records
                    .get(&commitment)
                    .map(|record| (commitment, Arc::clone(record)))
            },
            |ordinal| ends.projected_through(ordinal),
        )
    }

    /// Projects the ends of the L-QCs at every opened ordinal, reads or derives the facts they
    /// still need, and writes the cut entries of the ends delivery already stands at.
    pub(super) fn settle_ends(&mut self) {
        let view = super::ends::View {
            index: self.proofs.index(),
            order: &self.order,
            facts: &self.facts,
            delivered: &self.delivered,
        };
        let (missing, closed) = self.ends.settle(&view);
        for id in missing {
            // Reads and derivations already in flight are not started again; a read the store
            // cannot start yet is retried on a later call.
            if self.lqcs.contains_key(&id) {
                self.extract(id);
            } else if let Some(entry) = self.proofs.index().lqc(&id).copied() {
                self.read_part(PartKey::Lqc(id), entry.stored);
            }
        }
        for closed in closed {
            self.proofs.insert_cut(closed.history, closed.entry);
        }
    }

    /// Derives the finality a stored L-QC proves, off the owner.
    pub(super) fn extract(&mut self, id: CertificateId<H::Digest>) {
        let Some(proof) = self.lqcs.get(&id) else {
            return;
        };
        if !self.extracting.insert(id) {
            return;
        }
        let artifact = Arc::clone(proof.artifact());
        let codec = self.codec;
        let handle = self
            .context
            .child("extract")
            .shared(true)
            .spawn(move |_| async move {
                let Artifact::Lqc(lqc) = artifact.as_ref() else {
                    return None;
                };
                SweepFact::from_lqc::<H, S>(lqc, codec).ok().map(Arc::new)
            });
        self.jobs.push(async move {
            match handle.await {
                Ok(fact) => Event::Fact(id, fact),
                Err(error) => Event::Task(error),
            }
        });
    }

    /// Writes the cut entries of the L-QCs whose order delivery just completed at output
    /// index, with the exact last delivered block of every chain as their boundary.
    pub(super) fn write_cut_entries(&mut self, index: u64) {
        let view = super::ends::View {
            index: self.proofs.index(),
            order: &self.order,
            facts: &self.facts,
            delivered: &self.delivered,
        };
        for closed in self.ends.reached(index, &view) {
            self.proofs.insert_cut(closed.history, closed.entry);
        }
    }

    /// Verifies a peer L-QC, off the owner.
    pub(super) fn verify(
        &mut self,
        verify: Verify<H::Digest>,
        id: CertificateId<H::Digest>,
        lqc: Lqc<S, H::Digest>,
    ) {
        let mut verifier = self.verifier.clone();
        let codec = self.codec;
        self.spawn(
            "verify",
            async move {
                verifier.verify(&lqc).await.ok()?;
                let fact = SweepFact::from_lqc::<H, S>(&lqc, codec).ok()?;
                let proof = LqcProof::new(id, Arc::new(Artifact::Lqc(lqc)))?;
                Some((proof, Arc::new(fact)))
            },
            move |verified| Event::Verified(verify, verified),
        );
    }

    /// Takes a verified peer L-QC.
    pub(super) fn on_verified(
        &mut self,
        verify: Verify<H::Digest>,
        verified: Option<super::Proven<S, H::Digest>>,
    ) {
        let Some((proof, fact)) = verified else {
            // The verdict blames the peer that served the certificate; a floor is the caller's.
            match verify {
                Verify::Proof(_, _, verdict) | Verify::Fetched(verdict) => {
                    self.metrics.invalid_responses.inc();
                    let _ = verdict.send(Outcome::Invalid);
                }
                Verify::Floor => self.reject("the floor's certificate does not verify"),
            }
            return;
        };
        match verify {
            Verify::Proof(commitment, record, verdict) => {
                let _ = verdict.send(Outcome::Resolved(Resolution::Complete));
                if self.proofs.insert_record(commitment, Arc::clone(&record)) {
                    self.metrics.records.inc();
                }
                self.records.insert(commitment, record);
                self.accept_proof(proof, fact);
            }
            Verify::Fetched(verdict) => {
                let _ = verdict.send(Outcome::Resolved(Resolution::Complete));
                self.accept_proof(proof, fact);
            }
            Verify::Floor => self.on_floor_verified(proof, fact),
        }
    }

    /// Connects the newest unconnected L-QC's history by walking records backward from it, and
    /// asks peers for a proof when consensus has been quiet.
    pub(super) fn drive_walk(&mut self) {
        let index = self.proofs.index();
        // The newest unconnected L-QC is the target; a newer one, or a prune or floor that
        // dropped the old target, replaces the walk in progress. A floor being installed is
        // never walked: the install skips its history.
        let installing = self.install.as_ref().map(|install| install.commitment());
        let target = index
            .unconnected()
            .map(|(_, entry)| entry.history)
            .find(|history| Some(*history) != installing);
        match target {
            Some(target) if self.walk.is_none_or(|walk| walk.target != target) => {
                self.metrics.walks.inc();
                self.walk = Some(Walk {
                    target,
                    before: target,
                    pruned: 0,
                });
            }
            Some(_) => {}
            None => self.walk = None,
        }
        let mut fetch = None;
        if let Some(walk) = &mut self.walk {
            // Step over the records stored since the last turn.
            while let Some(entry) = index.record(&walk.before) {
                if walk.before == entry.parent {
                    break;
                }
                walk.before = entry.parent;
            }
            // Connection is reported when the record linking it is stored.
            if index.ordinal(&walk.before).is_none() {
                fetch = Some(walk.before);
            }
        }
        if let Some(before) = fetch {
            self.fetch(Key::Records { before }, 0);
        }
        let now = self.context.current();
        let quiet = now.duration_since(self.last_proof).unwrap_or_default() >= super::QUIET;
        let asked = self
            .last_ask
            .is_some_and(|asked| now.duration_since(asked).unwrap_or_default() < super::QUIET);
        if quiet && !asked && self.order.exhausted() && self.order.window().is_empty() {
            self.last_ask = Some(now);
            self.fetch(
                Key::Proofs {
                    after: Some(self.order.cut().history()),
                },
                0,
            );
        }
    }

    /// Takes records answering a walk.
    pub(super) fn on_records(
        &mut self,
        records: Vec<crate::multimmit::marshal::wire::Committed<H::Digest>>,
    ) -> bool {
        let mut stored = false;
        for (commitment, record) in records {
            if self.proofs.insert_record(commitment, record) {
                self.metrics.records.inc();
                stored = true;
            }
        }
        if stored {
            if let Some(walk) = &mut self.walk {
                walk.pruned = 0;
            }
            self.metrics.beyond_retention.set(0);
        }
        stored
    }

    /// Notes a peer reporting the walked history pruned.
    pub(super) fn on_pruned(&mut self) {
        let Some(walk) = &mut self.walk else {
            return;
        };
        walk.pruned += 1;
        // More reports than the faults the protocol tolerates come from at least one correct
        // server, so the history is gone: a floor install is needed.
        if walk.pruned > self.codec.max_faults() {
            self.metrics.beyond_retention.set(1);
        }
    }
}
