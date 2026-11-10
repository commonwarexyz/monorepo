//! Immutable commitments on a selected parent branch.

use commonware_cryptography::Digest;
use std::sync::Arc;

/// Commitments consensus holds on a selected parent branch, in forward order.
///
/// The commitments end at the request's parent, and consecutive re-proposals of one payload
/// contribute one commitment. An anchored history begins at a finalized or genesis anchor, so
/// every block below its first commitment is canonical. A suffix holds only the newest
/// commitments, because consensus does not hold the links below them. Applications that need
/// older blocks of a suffix follow the parent links of the blocks it identifies.
///
/// An empty anchored history selects nothing above canonical history. An empty suffix carries
/// no commitment, and only the request's own context names its parent.
///
/// A history never changes after it is built, and clones share its commitments.
#[derive(Clone, Debug)]
pub struct History<D: Digest> {
    commitments: Arc<[D]>,
    anchored: bool,
}

impl<D: Digest> History<D> {
    /// Creates a history whose first commitment is a finalized or genesis anchor.
    ///
    /// The caller asserts that every block below the first commitment is canonical. With no
    /// commitments, it asserts that of every block the history is read against.
    pub fn anchored(commitments: impl Into<Arc<[D]>>) -> Self {
        Self {
            commitments: commitments.into(),
            anchored: true,
        }
    }

    /// Creates a history that holds only the newest commitments of its branch.
    pub fn suffix(commitments: impl Into<Arc<[D]>>) -> Self {
        Self {
            commitments: commitments.into(),
            anchored: false,
        }
    }

    /// Returns the commitments in forward order.
    pub const fn commitments(&self) -> &Arc<[D]> {
        &self.commitments
    }

    /// Returns whether the first commitment is a finalized or genesis anchor.
    pub const fn is_anchored(&self) -> bool {
        self.anchored
    }
}
