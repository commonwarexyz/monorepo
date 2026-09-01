//! Direct-pool finality facts held until the synchronizer can emit their final sweeps.

use crate::{
    multimmit::types::{CodecConfig, FinalityFact},
    types::{Epoch, View},
};
use commonware_cryptography::Digest;
use std::cmp::Ordering;

/// Keeps the later of `fact` and the fact in `slot`.
///
/// A later round wins. Within one round, a fact for the same leader proposal replaces the current
/// one only when it carries more votes.
fn retain_later<D: Digest>(slot: &mut Option<FinalityFact<D>>, fact: FinalityFact<D>) {
    let replace = slot
        .as_ref()
        .is_none_or(|current| match fact.round().cmp(&current.round()) {
            Ordering::Greater => true,
            Ordering::Equal
                if fact.leader() == current.leader() && fact.parent() == current.parent() =>
            {
                fact.votes() > current.votes()
            }
            Ordering::Equal | Ordering::Less => false,
        });
    if replace {
        *slot = Some(fact);
    }
}

/// The best finality fact for the usable view and the best one above it.
///
/// The usable view is the view being synchronized during a pass and the floor view otherwise. A
/// fact at the usable view may emit its final sweep once the floor reaches it; a later fact waits
/// and is reclassified whenever the usable view changes.
pub(super) struct FinalityHints<D: Digest> {
    epoch: Epoch,
    codec: CodecConfig,
    /// Best fact at the usable view.
    pending: Option<FinalityFact<D>>,
    /// Best fact above the usable view.
    future: Option<FinalityFact<D>>,
    /// View of the synchronization pass in progress, if any.
    synchronizing: Option<View>,
}

impl<D: Digest> FinalityHints<D> {
    pub(super) const fn new(epoch: Epoch, codec: CodecConfig) -> Self {
        Self {
            epoch,
            codec,
            pending: None,
            future: None,
            synchronizing: None,
        }
    }

    /// Keeps `fact` if it is well formed and not below the usable view.
    pub(super) fn retain(&mut self, fact: FinalityFact<D>, floor_view: View) {
        if !fact.is_well_formed(self.epoch, self.codec) || fact.round().view() < floor_view {
            return;
        }
        let usable = self.synchronizing.unwrap_or(floor_view);
        match fact.round().view().cmp(&usable) {
            Ordering::Less => {}
            Ordering::Equal => retain_later(&mut self.pending, fact),
            Ordering::Greater => retain_later(&mut self.future, fact),
        }
    }

    /// Marks a synchronization pass to `view` as started and reclassifies the held facts.
    pub(super) fn prepare(&mut self, view: View, floor_view: View) {
        self.synchronizing = Some(view);
        self.reclassify(floor_view);
    }

    /// Marks the synchronization pass as finished and reclassifies the held facts.
    pub(super) fn finish(&mut self, floor_view: View) {
        self.synchronizing = None;
        self.reclassify(floor_view);
    }

    /// Takes the fact at the usable view, if any.
    pub(super) const fn take_pending(&mut self) -> Option<FinalityFact<D>> {
        self.pending.take()
    }

    /// Returns a fact taken with [`Self::take_pending`] that cannot emit yet.
    pub(super) fn restore_pending(&mut self, fact: FinalityFact<D>) {
        self.pending = Some(fact);
    }

    fn reclassify(&mut self, floor_view: View) {
        let pending = self.pending.take();
        let future = self.future.take();
        if let Some(fact) = pending {
            self.retain(fact, floor_view);
        }
        if let Some(fact) = future {
            self.retain(fact, floor_view);
        }
    }
}
