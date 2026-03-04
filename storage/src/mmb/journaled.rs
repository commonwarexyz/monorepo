//! An MMB backed by a fixed-item-length journal.
//!
//! Thin wrapper around the generic [`crate::merkle::journaled`] module, fixing the Merkle family
//! to [`super::Mmb`] and the in-memory representation to [`mem::CleanMmb`].

pub use crate::merkle::journaled::Config;

use crate::{
    merkle,
    mmb::{mem, proof::Proof, verification, Error, Location},
};
use commonware_cryptography::Digest;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use core::ops::Range;

/// Sync configuration for a journal-backed MMB.
pub type SyncConfig<D> = crate::merkle::journaled::SyncConfig<super::Mmb, D>;

/// A clean (merkleized) journaled MMB.
pub type CleanMmb<E, D> = merkle::journaled::Clean<super::Mmb, E, D, mem::CleanMmb<D>>;

/// A dirty (unmerkleized) journaled MMB.
pub type DirtyMmb<E, D> = merkle::journaled::Dirty<super::Mmb, E, D, mem::CleanMmb<D>>;

// ---------------------------------------------------------------------------
// CleanMmb-specific methods (proofs)
// ---------------------------------------------------------------------------

impl<E: RStorage + Clock + Metrics, D: Digest> CleanMmb<E, D> {
    /// Return an inclusion proof for the element at location `loc` against a historical state.
    pub async fn historical_proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        leaves: Location,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.historical_range_proof(hasher, leaves, loc..loc + 1)
            .await
    }

    /// Return an inclusion proof for the elements in `range` against a historical state.
    pub async fn historical_range_proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        self.validate_historical_leaves(leaves)?;
        verification::historical_range_proof(self, hasher, leaves, range).await
    }

    /// Return an inclusion proof for the element at `loc` against the current root.
    pub async fn proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).await
    }

    /// Return an inclusion proof for elements in the given range against the current root.
    pub async fn range_proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        self.historical_range_proof(hasher, self.leaves(), range)
            .await
    }
}

// ---------------------------------------------------------------------------
// DirtyMmb-specific methods (proofs)
// ---------------------------------------------------------------------------

impl<E: RStorage + Clock + Metrics, D: Digest> DirtyMmb<E, D> {
    /// Return a historical proof for a single element, if sufficiently merkleized.
    pub async fn historical_proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        leaves: Location,
        loc: Location,
    ) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.historical_range_proof(hasher, leaves, loc..loc + 1)
            .await
    }

    /// Return a historical range proof, if sufficiently merkleized.
    pub async fn historical_range_proof(
        &self,
        hasher: &mut impl super::hasher::Hasher<super::Mmb, Digest = D>,
        leaves: Location,
        range: Range<Location>,
    ) -> Result<Proof<D>, Error> {
        self.validate_dirty_historical_range_proof(leaves, &range)?;
        verification::historical_range_proof(self, hasher, leaves, range).await
    }
}

#[cfg(test)]
mod tests {
    use super::mem;
    use crate::mmb::StandardHasher;
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    #[test_traced]
    fn test_journaled_mmb_init_sync_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_sync_empty::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_journaled_mmb_init_sync_nonempty_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_sync_nonempty_exact_match::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_journaled_mmb_init_sync_partial_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_sync_partial_overlap::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_journaled_mmb_init_stale_metadata_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_stale_metadata_returns_error::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_journaled_mmb_init_metadata_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_metadata_ahead::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced]
    fn test_journaled_mmb_init_sync_computes_pinned_nodes_before_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_init_sync_computes_pinned_nodes_before_pruning::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_journaled_mmb_recovery_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            crate::merkle::journaled::tests::test_recovery_with_pruning::<crate::mmb::Mmb, _, mem::CleanMmb<_>>(
                context, &mut hasher,
            )
            .await;
        });
    }
}
