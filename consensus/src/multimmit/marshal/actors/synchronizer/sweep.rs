//! The open view's sweep, emitted ahead of the view's resolution.

use super::{
    actor::Core,
    inbox::Absorb,
    mailbox::Error,
    ports::{CatalogPort, Fetcher},
    publish::PublicationBatch,
};
use crate::{
    multimmit::{
        marshal::{
            protocol::order,
            storage::scratch::{BlockStack, HistoryStack},
            types::LqcVerifier,
        },
        types::{BlockRef, Body, ChainSet},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{cmp::Ordering, sync::Arc};
use tracing::debug;

/// The latest sweep local consensus reported for one view.
///
/// Within one view, successive sweeps never retreat: final tips only rise and settled chains stay
/// settled.
pub(super) struct OpenSweep<D: Digest> {
    pub(super) view: View,
    finals: Arc<[BlockRef<D>]>,
    settled: ChainSet,
    /// Whether the sweep's blocks were emitted.
    emitted: bool,
}

impl<I, C, F, S, K, Q, H, V, B> Core<I, C, F, S, K, Q, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Keeps the sweep of `view` until the synchronized view reaches `view`; it applies once the
    /// synchronized view is the one before it.
    ///
    /// A sweep for an earlier view than the retained one is stale and dropped. One that retreats
    /// from the retained sweep of the same view, or names another block at a retained final
    /// height, is a local consensus fault. The router admits only
    /// sweeps shaped for the epoch, and the sweep order rejects any other.
    pub(super) fn retain_sweep(
        &mut self,
        view: View,
        finals: Arc<[BlockRef<H::Digest>]>,
        settled: ChainSet,
    ) -> Result<(), Error> {
        if let Some(current) = &self.sweep {
            match view.cmp(&current.view) {
                Ordering::Less => return Ok(()),
                Ordering::Equal => {
                    let retreats =
                        finals
                            .iter()
                            .zip(current.finals.iter())
                            .any(|(next, current)| {
                                next.height() < current.height()
                                    || (next.height() == current.height() && next != current)
                            });
                    if retreats || !current.settled.is_subset(&settled) {
                        return Err(Error::Invalid("sweep retreats within its view"));
                    }
                    if *finals == *current.finals && settled == current.settled {
                        return Ok(());
                    }
                }
                Ordering::Greater => {}
            }
        }
        self.sweep = Some(OpenSweep {
            view,
            finals,
            settled,
            emitted: false,
        });
        Ok(())
    }
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
    /// Emits the retained sweep once it belongs to the view after the synchronized one.
    ///
    /// The sweep places blocks in the view's horizontal order above the ordered frontier until
    /// its first unsettled chain above its final tip; the order is generated lazily and the blocks
    /// already emitted are skipped. Blocks an earlier sweep of the view emitted must be a prefix
    /// of that order; a sweep that does not cover them is stale (a consensus restart may report a
    /// lower one) and waits for a later report. A final tip that does not
    /// extend the emitted frontier fails the walk.
    pub(super) async fn synchronize_sweep(&mut self) -> Result<(), Error> {
        let Some(sweep) = &self.sweep else {
            return Ok(());
        };
        let next = self.state.view().next();
        if sweep.view < next {
            self.sweep = None;
            return Ok(());
        }
        if sweep.view > next || sweep.emitted {
            return Ok(());
        }
        let finals = Arc::clone(&sweep.finals);
        let ordered = self.state.ordered().to_vec();
        let settled = order::settled_flags(ordered.len(), &sweep.settled)?;
        let slots = || order::sweep(&ordered, &finals, &settled);
        if self.state.check_prefix(slots()?).is_err() {
            debug!(view = next.get(), "sweep does not cover the emitted prefix");
            self.metrics.stale_sweeps.inc();
            self.mark_sweep_emitted(&finals);
            return Ok(());
        }
        self.metrics.sweeps.inc();
        let emitted = self.state.emitted().to_vec();
        let maxima = order::sweep_maxima(&ordered, &finals, &settled);
        let common = self.stage(maxima, &finals, &emitted).await?;
        self.state.validate_reconciliation(&finals, &common)?;
        let mut batch = PublicationBatch::default();
        self.drive(&mut slots()?, &emitted, &mut batch).await?;
        self.commit_pending(&mut batch).await?;
        self.mark_sweep_emitted(&finals);
        Ok(())
    }

    /// Marks the retained sweep with final tips `finals` as handled. A later report of its view
    /// that replaced it during the pass stays pending.
    fn mark_sweep_emitted(&mut self, finals: &Arc<[BlockRef<H::Digest>]>) {
        if let Some(sweep) = &mut self.sweep
            && Arc::ptr_eq(&sweep.finals, finals)
        {
            sweep.emitted = true;
        }
    }
}
