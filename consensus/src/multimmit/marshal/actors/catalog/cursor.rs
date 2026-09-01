//! The catalog's mirror of delivery's durable acknowledgement cursor.
//!
//! Delivery owns the cursor. The catalog mirrors it only to report progress and to bound
//! finalized pruning.

use crate::multimmit::marshal::{storage::catalog_state::Checkpoint, types::OutputIndex};
use commonware_cryptography::Digest;

/// The highest output delivery durably acknowledged in the current floor generation.
pub(super) struct CursorMirror {
    acknowledged: Option<OutputIndex>,
}

impl CursorMirror {
    pub(super) const fn new(acknowledged: Option<OutputIndex>) -> Self {
        Self { acknowledged }
    }

    /// Returns the mirrored acknowledgement.
    pub(super) const fn acknowledged(&self) -> Option<OutputIndex> {
        self.acknowledged
    }

    /// Returns the mirrored acknowledgement if `floor_generation` is the durable generation.
    pub(super) fn acknowledged_in<D: Digest>(
        &self,
        durable: &Checkpoint<D>,
        floor_generation: u64,
    ) -> Option<OutputIndex> {
        (durable.floor_generation() == floor_generation)
            .then_some(self.acknowledged)
            .flatten()
    }

    /// Mirrors a durable cursor position.
    ///
    /// A cursor from an older generation is ignored. A cursor from a newer generation, or past
    /// the durable commit, contradicts the catalog.
    pub(super) fn update<D: Digest>(
        &mut self,
        durable: &Checkpoint<D>,
        floor_generation: u64,
        acknowledged: Option<OutputIndex>,
    ) -> Result<(), &'static str> {
        if floor_generation < durable.floor_generation() {
            return Ok(());
        }
        if floor_generation > durable.floor_generation() {
            return Err("delivery cursor generation exceeds the catalog generation");
        }
        if acknowledged > durable.committed() {
            return Err("delivery cursor exceeds the committed output");
        }
        if acknowledged > self.acknowledged {
            self.acknowledged = acknowledged;
        }
        Ok(())
    }

    /// Forgets the mirrored acknowledgement after a floor installation.
    pub(super) const fn reset(&mut self) {
        self.acknowledged = None;
    }
}
