//! Tip-history openings and final sweeps that advance the synchronized output prefix.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::{Error, FinalityProofs},
    ports::{CatalogPort, Fetcher},
    publish::PublicationBatch,
    walk::ProducerWalk,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            actors::metrics::FetchReason,
            protocol::{
                order::{FinalSweep, HistoryState, Slot, SlotStream},
                paths::Branch,
            },
            storage::{
                commit::{HistoryOpening, SelectedLqc},
                scratch::{BlockStack, HistoryLink, HistoryStack},
            },
            types::LqcVerifier,
        },
        types::{BlockRef, Body},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{cmp::Ordering, collections::VecDeque, sync::Arc};

/// Returns the canonical order across a bounded oldest-first run of history openings.
fn history_order<H: Hasher>(
    base: &[BlockRef<H::Digest>],
    links: &[HistoryLink<H>],
) -> Result<VecDeque<Slot<H::Digest>>, Error> {
    let mut base = base.to_vec();
    let mut slots = VecDeque::new();
    for link in links {
        slots.extend(SlotStream::new(
            &base,
            link.record.tips(),
            link.record.proposed(),
        )?);
        base = link.record.tips().to_vec();
    }
    Ok(slots)
}

/// An oldest-first run of staged history openings whose outputs fit in one custody window.
struct HistoryWindow<H: Hasher> {
    links: Vec<HistoryLink<H>>,
    /// The first opening after the window, if any.
    next: Option<HistoryLink<H>>,
}

/// The ancestry walk of a history window.
struct StagedWindow<D: Digest> {
    /// Emitted frontier once every opening of the window is emitted.
    emitted: Vec<BlockRef<D>>,
    /// Authenticated forward path per chain, where the path cache covered the walk.
    forward: Vec<Option<Branch<D>>>,
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    I: Absorb<V, H::Digest>,
    C: CatalogPort<H, V, B>,
    F: Fetcher<H, V, B>,
    S: HistoryStack<H>,
    K: BlockStack<H::Digest>,
    Q: LqcVerifier<H, V>,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    Error: From<C::Error> + From<F::Error> + From<S::Error> + From<K::Error>,
{
    /// Synchronizes to the same-view finalized `proofs`: opens every tip-history record they
    /// commit to, then emits each proof's final sweep and selects it.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.resolve_finality",
        level = "info",
        skip_all,
        fields(proofs = proofs.len())
    )]
    pub(super) async fn synchronize_proofs(
        &mut self,
        proofs: FinalityProofs<V, H::Digest>,
    ) -> Result<(), Error> {
        let selected = self.new_proofs(proofs).await?;
        let Some(first) = selected.first() else {
            return Ok(());
        };
        let view = first.view;
        let commitment = first.proof.leader().history();
        if selected
            .iter()
            .any(|selected| selected.proof.leader().history() != commitment)
        {
            return Err(Error::Invalid(
                "same-view LQCs do not commit to one history",
            ));
        }
        self.stage_history(view, commitment).await?;
        let mut batch = PublicationBatch::new(self.bounds.max_commit_outputs, selected.len());
        self.open_history(&mut batch).await?;
        for selected in selected {
            self.select(selected, &mut batch).await?;
        }
        self.commit_pending(&mut batch).await
    }

    /// Emits the final sweep of the pending direct-pool finality fact at the floor, if any.
    ///
    /// A fact applies only when it describes the floor proof's leader proposal.
    pub(super) async fn synchronize_pending_finality(&mut self) -> Result<(), Error> {
        while let Some(fact) = self.finality.take_pending() {
            match fact.round().view().cmp(&self.floor_view) {
                Ordering::Less => continue,
                Ordering::Greater => {
                    self.finality.restore_pending(fact);
                    return Ok(());
                }
                Ordering::Equal => {}
            }
            let Some(proof) = self.catalog.lqc(self.floor).await? else {
                continue;
            };
            if fact.round() != proof.leader().round()
                || fact.leader() != proof.leader().digest::<H>()
                || fact.parent() != proof.leader().parent()
            {
                continue;
            }
            let Ok(sweep) = FinalSweep::new(
                self.state.ordered(),
                fact.blocks().to_vec(),
                fact.proposed(),
                fact.settled().to_vec(),
            ) else {
                continue;
            };
            self.metrics.final_sweeps.inc();
            self.metrics.emitted_slots.inc_by(sweep.planned());
            let unsettled = fact.settled().iter().filter(|settled| !**settled).count();
            self.metrics.unsettled_chains.inc_by(unsettled as u64);
            if sweep.halted() {
                self.metrics.emission_halts.inc();
            }
            let mut batch = PublicationBatch::new(self.bounds.max_commit_outputs, 0);
            self.sweep(sweep.into_stream(), &mut batch).await?;
            self.commit_pending(&mut batch).await?;
        }
        Ok(())
    }

    /// Returns the proofs to select from `proofs`: all of them above the floor view, and at the
    /// floor view those not yet selected.
    async fn new_proofs(
        &mut self,
        proofs: FinalityProofs<V, H::Digest>,
    ) -> Result<Vec<SelectedLqc<V, H>>, Error> {
        let Some(view) = proofs.values().next().map(|proof| proof.view()) else {
            return Ok(Vec::new());
        };
        if proofs.iter().any(|(id, proof)| {
            proof.id::<H>() != *id || proof.epoch() != self.epoch || proof.view() != view
        }) {
            return Err(Error::Invalid("LQC identity, epoch, or view mismatch"));
        }
        if view < self.floor_view {
            return Ok(Vec::new());
        }
        let mut selected = Vec::with_capacity(proofs.len());
        for (id, proof) in proofs {
            if view == self.floor_view && (id == self.floor || self.catalog.final_lqc(id).await?) {
                continue;
            }
            selected.push(SelectedLqc { view, id, proof });
        }
        Ok(selected)
    }

    /// Stages the tip-history records from `commitment` back to the active history, newest
    /// first.
    async fn stage_history(&mut self, view: View, commitment: H::Digest) -> Result<(), Error> {
        self.history_stack.reset().await?;
        let mut cursor = commitment;
        while cursor != self.state.history() {
            let records = self
                .fetcher
                .history(FetchReason::Finality, view, cursor)
                .await?;
            if records.is_empty() {
                return Err(Error::Invalid("history response is empty"));
            }
            for record in records.iter() {
                if cursor == self.state.history() {
                    break;
                }
                if record.commitment::<H>() != cursor {
                    return Err(Error::Invalid("history response does not match commitment"));
                }
                self.history_stack
                    .push(HistoryLink {
                        commitment: cursor,
                        record: Arc::clone(record),
                    })
                    .await?;
                cursor = record.parent();
            }
        }
        Ok(())
    }

    /// Opens every staged tip-history record, oldest first, in custody-window-sized runs.
    async fn open_history(&mut self, batch: &mut PublicationBatch<H, V, B>) -> Result<(), Error> {
        let mut next = self.history_stack.read_oldest().await?;
        while let Some(first) = next.take() {
            let window = self.read_history_window(first).await?;
            next = window.next;
            if window.links.len() > 1 {
                self.open_window(window.links, batch).await?;
            } else {
                for link in window.links {
                    self.open(link, batch).await?;
                }
            }
        }
        self.history_stack.reset().await.map_err(Error::from)
    }

    /// Emits the final sweep of `selected` and selects it.
    async fn select(
        &mut self,
        selected: SelectedLqc<V, H>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let preview = HistoryState::new(
            self.state.history(),
            self.state.ordered().to_vec(),
            self.state.ordered().to_vec(),
        )?;
        let sweep =
            preview.final_sweep::<H, V>(&selected.proof, self.codec, self.state.ordered())?;
        self.sweep(sweep.into_stream(), batch).await?;
        batch.selected.push(selected);
        if batch.selected.len() == self.bounds.max_commit_outputs {
            self.commit_pending(batch).await?;
        }
        Ok(())
    }

    /// Emits the outputs of a final sweep's `stream` above the emitted frontier.
    async fn sweep(
        &mut self,
        mut stream: SlotStream<H::Digest>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let target = stream.target().to_vec();
        let emitted = self.state.emitted().to_vec();
        let plan = self.stage(stream.maxima(), &target, &emitted).await?;
        self.state.validate_reconciliation(&target, &plan.common)?;
        self.drive(&mut stream, &emitted, &plan.forward, batch)
            .await
    }

    /// Collects the largest oldest-first run of staged openings whose outputs fit in one custody
    /// window. An oversized opening forms a window of its own.
    async fn read_history_window(
        &mut self,
        first: HistoryLink<H>,
    ) -> Result<HistoryWindow<H>, Error> {
        let output_limit = u64::try_from(self.bounds.custody_window_outputs).unwrap_or(u64::MAX);
        let mut history = self.state.history();
        let mut ordered = self.state.ordered().to_vec();
        let mut outputs = 0u64;
        let mut links = Vec::with_capacity(self.bounds.max_commit_outputs);
        let mut current = Some(first);
        while let Some(link) = current.take() {
            if link.record.parent() != history || link.record.commitment::<H>() != link.commitment {
                return Err(Error::Invalid(
                    "tip-history opening does not extend its recovery window",
                ));
            }
            let opening_outputs =
                SlotStream::count(&ordered, link.record.tips(), link.record.proposed())?;
            let window_outputs = outputs
                .checked_add(opening_outputs)
                .ok_or(Error::OutputExhausted)?;
            if !links.is_empty() && window_outputs > output_limit {
                return Ok(HistoryWindow {
                    links,
                    next: Some(link),
                });
            }
            history = link.commitment;
            ordered = link.record.tips().to_vec();
            outputs = window_outputs;
            links.push(link);
            if outputs > output_limit || links.len() == self.bounds.max_commit_outputs {
                let next = self.history_stack.read_oldest().await?;
                return Ok(HistoryWindow { links, next });
            }
            current = self.history_stack.read_oldest().await?;
        }
        Ok(HistoryWindow { links, next: None })
    }

    /// Opens one tip-history record.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.open_history",
        level = "info",
        skip_all,
        fields(tips = link.record.tips().len())
    )]
    pub(super) async fn open(
        &mut self,
        link: HistoryLink<H>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let emitted = self.state.emitted().to_vec();
        let mut stream = SlotStream::new(
            self.state.ordered(),
            link.record.tips(),
            link.record.proposed(),
        )?;
        let plan = self
            .stage(stream.maxima(), link.record.tips(), &emitted)
            .await?;
        self.state
            .validate_opening::<H>(link.commitment, &link.record, &plan.common)?;
        self.drive(&mut stream, &emitted, &plan.forward, batch)
            .await?;
        self.record_opening(link, batch).await
    }

    /// Opens a run of tip-history records with one ancestry walk and one custody window.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.open_history_window",
        level = "info",
        skip_all,
        fields(openings = links.len())
    )]
    async fn open_window(
        &mut self,
        links: Vec<HistoryLink<H>>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let emitted = self.state.emitted().to_vec();
        let mut stream = history_order(self.state.ordered(), &links)?.into_iter();
        let staged = self.stage_window(&links, &emitted).await?;

        // Validate every opening before the first output mutates ordering state. The single
        // ancestry walk proves each opening tip lies on the future emitted frontier.
        let mut preview = HistoryState::new(
            self.state.history(),
            self.state.ordered().to_vec(),
            staged.emitted,
        )?;
        for link in &links {
            preview.validate_opening::<H>(link.commitment, &link.record, link.record.tips())?;
            preview.finish_opening::<H>(link.commitment, &link.record)?;
        }

        self.drive(&mut stream, &emitted, &staged.forward, batch)
            .await?;
        for link in links {
            self.record_opening(link, batch).await?;
        }
        Ok(())
    }

    /// Authenticates every producer frontier of a history window with one ancestry walk.
    async fn stage_window(
        &mut self,
        links: &[HistoryLink<H>],
        emitted: &[BlockRef<H::Digest>],
    ) -> Result<StagedWindow<H::Digest>, Error> {
        let ordered = self.state.ordered();
        if ordered.len() != emitted.len() {
            return Err(Error::Invalid("frontier lengths differ"));
        }
        let walks = emitted
            .iter()
            .zip(ordered)
            .enumerate()
            .map(|(chain, (emitted, ordered))| {
                let tips = links
                    .iter()
                    .map(|link| link.record.tips().get(chain).copied())
                    .collect::<Option<Vec<_>>>()
                    .ok_or(Error::Invalid("frontier lengths differ"))?;
                ProducerWalk::window(&tips, *emitted, *ordered)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bounds = walks.iter().map(ProducerWalk::bounds).collect::<Vec<_>>();
        let plan = self.walk(walks, FetchReason::Finality).await?;
        if plan
            .common
            .iter()
            .zip(&bounds)
            .any(|(common, bounds)| *common != bounds.low)
        {
            return Err(Error::Invalid(
                "history window does not descend to its recovery frontier",
            ));
        }
        Ok(StagedWindow {
            emitted: bounds.into_iter().map(|bounds| bounds.high).collect(),
            forward: plan.forward,
        })
    }

    /// Advances the authenticated history frontier past `link` and queues its durable row.
    async fn record_opening(
        &mut self,
        link: HistoryLink<H>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        self.state
            .finish_opening::<H>(link.commitment, &link.record)?;
        self.history_index = Some(match self.history_index {
            Some(index) => index.checked_add(1).ok_or(Error::HistoryIndexExhausted)?,
            None => 0,
        });
        batch.history.push(HistoryOpening {
            commitment: link.commitment,
            record: link.record,
        });
        if batch.history.len() == self.bounds.max_commit_outputs {
            self.commit_pending(batch).await?;
        }
        Ok(())
    }
}
