//! Tips-history openings that advance the synchronized output prefix through resolved views.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::{Error, FinalityProofs, Target},
    ports::{CatalogPort, Fetcher},
    publish::PublicationBatch,
    walk::ProducerWalk,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            actors::metrics::FetchReason,
            protocol::order::{self, HistoryState},
            storage::{
                commit::{HistoryOpening, SelectedLqc},
                scratch::{BlockStack, HistoryLink, HistoryStack},
            },
            types::LqcVerifier,
        },
        types::{Body, HistoryRecord},
    },
    types::View,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use std::{cmp::Ordering, pin::pin, sync::Arc};

/// The error of a tips-history chain that skips the synchronized view.
const PASSES_SYNCHRONIZED: Error =
    Error::Invalid("tips-history chain passes the synchronized view");

/// An oldest-first run of staged history openings whose outputs fit in one custody window.
struct HistoryWindow<H: Hasher> {
    links: Vec<HistoryLink<H>>,
    /// The first opening after the window, if any.
    next: Option<HistoryLink<H>>,
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
    /// Synchronizes through `target`: opens every tips-history record from the active history to
    /// the target's commitment, and selects each of the target's L-QCs once the opening it pins is
    /// the newest one.
    ///
    /// A target below the synchronized view opens nothing. A target at the synchronized view must
    /// name its commitment. L-QCs pinning a view the pass does not end an opening at are dropped.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.synchronize_target",
        level = "info",
        skip_all,
        fields(view = target.view.get(), proofs = target.proofs.len())
    )]
    pub(super) async fn synchronize_target(
        &mut self,
        target: Target<V, H::Digest>,
    ) -> Result<(), Error> {
        let Target {
            view,
            commitment,
            record,
            mut proofs,
            conflict,
            ..
        } = target;
        if conflict {
            return Err(Error::Invalid(
                "synchronization targets commit to different histories at one view",
            ));
        }
        let mut batch = PublicationBatch::new(self.bounds.max_commit_outputs, proofs.len());
        match view.cmp(&self.state.view()) {
            Ordering::Less => {}
            Ordering::Equal if commitment != self.state.history() => {
                return Err(Error::Invalid(
                    "synchronization target conflicts with the synchronized history",
                ));
            }
            Ordering::Equal => {}
            Ordering::Greater => {
                self.stage_history(view, commitment, record).await?;
                self.open_history(&mut proofs, &mut batch).await?;
            }
        }
        self.select_pinned(&mut proofs, &mut batch).await?;
        self.commit_pending(&mut batch).await
    }

    /// Selects the L-QCs of `proofs` that pin the synchronized history, removing them, and starts
    /// a commit whose checkpoint names that history.
    ///
    /// An L-QC at the floor view is selected once.
    async fn select_pinned(
        &mut self,
        proofs: &mut FinalityProofs<V, H::Digest>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let history = self.state.history();
        let pinned = proofs
            .iter()
            .filter(|(_, proof)| proof.leader().history() == history)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        if pinned.is_empty() {
            return Ok(());
        }
        for id in pinned {
            let proof = proofs.remove(&id).expect("pinned proof is retained");
            let view = proof.view();
            if proof.id::<H>() != id || proof.epoch() != self.epoch {
                return Err(Error::Invalid("LQC identity or epoch mismatch"));
            }
            if view < self.floor_view
                || (view == self.floor_view
                    && (id == self.floor || self.catalog.final_lqc(id).await?))
            {
                continue;
            }
            batch.selected.push(SelectedLqc { view, id, proof });
            if batch.selected.len() == self.bounds.max_commit_outputs {
                self.commit_pending(batch).await?;
            }
        }
        self.commit_pending(batch).await
    }

    /// Stages the tips-history records from `commitment`, the opening of `view`, back to the
    /// active history, newest first, taking in input while they are fetched.
    ///
    /// Each record opens the view after its parent's, so the chain from the target's view must
    /// reach the active history exactly at the synchronized view.
    async fn stage_history(
        &mut self,
        view: View,
        commitment: H::Digest,
        record: Option<Arc<HistoryRecord<H::Digest>>>,
    ) -> Result<(), Error> {
        self.history_stack.reset().await?;
        let mut cursor = commitment;
        let mut view = view;
        if let Some(record) = record {
            self.push_history(&mut cursor, &mut view, record).await?;
        }
        while cursor != self.state.history() {
            if view <= self.state.view() {
                return Err(PASSES_SYNCHRONIZED);
            }
            let mut fetcher = self.fetcher.clone();
            let mut fetch = pin!(fetcher.history(FetchReason::Finality, view, cursor));
            let records = loop {
                select! {
                    records = &mut fetch => break records?,
                    absorbed = self.absorb_hint() => {
                        absorbed?;
                    },
                }
            };
            if records.is_empty() {
                return Err(Error::Invalid("history response is empty"));
            }
            for record in records.iter() {
                if cursor == self.state.history() {
                    break;
                }
                self.push_history(&mut cursor, &mut view, Arc::clone(record))
                    .await?;
            }
        }
        if view != self.state.view() {
            return Err(Error::Invalid(
                "tips-history chain does not match its resolved views",
            ));
        }
        Ok(())
    }

    /// Stages `record` as the opening of `cursor` at `view`, then moves both to its parent.
    async fn push_history(
        &mut self,
        cursor: &mut H::Digest,
        view: &mut View,
        record: Arc<HistoryRecord<H::Digest>>,
    ) -> Result<(), Error> {
        if *view <= self.state.view() {
            return Err(PASSES_SYNCHRONIZED);
        }
        let commitment = *cursor;
        if record.commitment::<H>() != commitment {
            return Err(Error::Invalid("history response does not match commitment"));
        }
        *cursor = record.parent();
        *view = view
            .previous()
            .expect("view is above the synchronized view");
        self.history_stack
            .push(HistoryLink { commitment, record })
            .await?;
        Ok(())
    }

    /// Opens every staged tips-history record, oldest first, in custody-window-sized runs, and
    /// selects the L-QCs of `proofs` pinning each opening as it is recorded.
    async fn open_history(
        &mut self,
        proofs: &mut FinalityProofs<V, H::Digest>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let mut next = self.history_stack.read_oldest().await?;
        while let Some(first) = next.take() {
            let window = self.read_history_window(first).await?;
            next = window.next;
            self.open_window(window.links, proofs, batch).await?;
        }
        self.history_stack.reset().await.map_err(Error::from)
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
            if link.record.parent() != history {
                return Err(Error::Invalid(
                    "tips-history opening does not extend its recovery window",
                ));
            }
            let opening_outputs = order::outputs(&ordered, link.record.tips())?;
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

    /// Opens a run of tips-history records with one ancestry walk and one custody window, then
    /// records them oldest first, selecting the L-QCs of `proofs` that pin each.
    ///
    /// Every resolved view's tips extend the previous view's, so the newest tips' paths pass
    /// through every older opening's tips and through the emitted frontier. The window's order is
    /// generated lazily.
    #[tracing::instrument(
        name = "multimmit.marshal.synchronizer.open_history_window",
        level = "info",
        skip_all,
        fields(openings = links.len())
    )]
    pub(super) async fn open_window(
        &mut self,
        links: Vec<HistoryLink<H>>,
        proofs: &mut FinalityProofs<V, H::Digest>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        let emitted = self.state.emitted().to_vec();
        let ordered = self.state.ordered().to_vec();
        let order = || order::horizontal(&ordered, links.iter().map(|link| link.record.tips()));
        self.state.check_prefix(order()?)?;

        let walks = emitted
            .iter()
            .zip(&ordered)
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
        let common = self.walk(walks, FetchReason::Finality).await?;
        if common
            .iter()
            .zip(&bounds)
            .any(|(common, bounds)| *common != bounds.low)
        {
            return Err(Error::Invalid(
                "tips-history openings do not extend the emitted frontier",
            ));
        }

        // Check every opening's links before the first output mutates ordering state. The single
        // ancestry walk proves each opening tip lies on the future emitted frontier.
        let mut preview = HistoryState::new(
            self.state.view(),
            self.state.history(),
            ordered.clone(),
            bounds.into_iter().map(|bounds| bounds.high).collect(),
        )?;
        for link in &links {
            preview.finish_opening::<H>(link.commitment, &link.record)?;
        }

        self.drive(&mut order()?, &emitted, batch).await?;
        for link in links {
            self.record_opening(link, batch).await?;
            self.select_pinned(proofs, batch).await?;
        }
        Ok(())
    }

    /// Advances the authenticated history frontier past `link` and queues its durable row.
    async fn record_opening(
        &mut self,
        link: HistoryLink<H>,
        batch: &mut PublicationBatch<H, V, B>,
    ) -> Result<(), Error> {
        self.state
            .finish_opening::<H>(link.commitment, &link.record)?;
        self.history_index = Some(self.next_history_index()?);
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
