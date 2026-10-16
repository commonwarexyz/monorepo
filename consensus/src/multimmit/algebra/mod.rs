//! Pure extraction and ordering algebra shared by the machine, marshal, and scheme.
//!
//! Callers provide already-authenticated protocol objects and a view of the producer headers they
//! hold ([`Ancestry`]); the algebra deterministically computes what those objects endorse. Nothing
//! here holds protocol state, touches storage, or performs runtime work.
//!
//! - [`Path`] rebuilds producer headers from payload hashes, and [`path::PathAncestry`] indexes
//!   rebuilt paths as an [`Ancestry`].
//! - [`tips::tips`], [`Bindings`], and [`det`] compute, chain by chain, `Tips(Q)` of a V-QC,
//!   settledness, and `Det(G)` of final votes.
//! - [`designated`] finds the leader block a V-QC designates.
//! - [`Horiz`] and [`Sweep`] enumerate the horizontal order in which resolved tips and an open
//!   view's sweep place blocks.
//! - [`validate_vqc`] and [`validate_floor`] check certificates beyond their encoding.

mod order;
mod path;
mod tips;
mod validate;

#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod reference;
#[cfg(test)]
mod tests;

use crate::{
    multimmit::types::{self, BlockRef, ChainId},
    types::Height,
};
use commonware_cryptography::Digest;
pub(crate) use order::{Append, Horiz, Step, Sweep};
pub(crate) use path::Path;
#[cfg(test)]
pub(crate) use tips::Settledness;
pub(crate) use tips::{Bindings, Reach, binding, det, reach};
#[cfg(any(test, feature = "mocks"))]
pub(crate) use tips::{final_tip, settled, tips};
pub(crate) use validate::{designated, validate_floor, validate_vqc};

/// Read access to producer-chain ancestry.
pub(crate) trait Ancestry<D: Digest> {
    /// Returns the ancestor of `tip` at `height` (`tip` itself at its own height), or `None` when
    /// `height` is above `tip` or the headers in between are unknown.
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>>;
}

impl<D: Digest, A: Ancestry<D> + ?Sized> Ancestry<D> for &A {
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>> {
        (**self).ancestor(tip, height)
    }
}

/// A malformed input to the algebra.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// A per-chain vector does not hold one entry per chain in chain order.
    #[error("per-chain vector is not one entry per chain in chain order")]
    ChainOrder,
    /// A target vector lies below its origin on a chain.
    #[error("target lies below its origin on chain {0}")]
    Regression(ChainId),
    /// Rebuilding a path would overflow the chain height.
    #[error("chain height overflow")]
    HeightOverflow,
    /// A rebuilt path does not end at its target.
    #[error("rebuilt path does not end at its target")]
    PathTarget,
    /// A resolution path does not start at its chain's base height.
    #[error("resolution path on chain {0} does not start at the base height")]
    PathHeight(ChainId),
    /// A recorded tip above the base lies on no resolution path.
    #[error("recorded tip on chain {0} is not resolved")]
    Unresolved(ChainId),
    /// A resolution path does not end at a recorded tip.
    #[error("resolution path on chain {0} resolves no recorded tip")]
    UnusedPath(ChainId),
    /// A resolution path ends inside another path.
    #[error("resolution path on chain {0} is covered by another path")]
    RedundantPath(ChainId),
    /// A designated leader block does not name the V-QC's parent and its history.
    #[error("designated leader block does not match the parent")]
    Designation,
    /// A certificate belongs to another epoch.
    #[error("certificate belongs to another epoch")]
    Epoch,
    /// A certificate does not hold exactly `n - f` messages of a live view.
    #[error("certificate does not hold a quorum")]
    Quorum,
    /// A history opening does not hash to the commitment it opens.
    #[error("history opening does not match its commitment")]
    History,
    /// The sum of tip heights overflows.
    #[error("output index overflow")]
    IndexOverflow,
    /// A protocol object could not be constructed.
    #[error(transparent)]
    Types(#[from] types::Error),
}
