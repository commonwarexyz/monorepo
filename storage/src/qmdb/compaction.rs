//! Budgets for QMDB floor raising.
//!
//! Merkleizing a batch raises the inactivity floor by moving active entries from below it to the
//! log's tip. [`UnmerkleizedBatch::merkleize`](crate::qmdb::any::batch::UnmerkleizedBatch::merkleize)
//! moves at most `user_steps + 1` entries and scans as far as needed to find them, so the floor
//! advances at a rate set by each batch's own operation count, but the scan can cross an
//! arbitrarily long inactive range.
//!
//! [`UnmerkleizedBatch::merkleize_with_compaction_plan`](crate::qmdb::any::batch::UnmerkleizedBatch::merkleize_with_compaction_plan)
//! lets the caller choose the [`CompactionBudget`] instead, capping both the entries moved and
//! the locations scanned. After resolving the batch's mutations, it passes [`CompactionStats`]
//! to a caller-supplied closure, which returns the budget and the CommitFloor metadata. This
//! suits deployments where execution time is scarcer than disk space, such as a batch that must
//! finalize within a block-production deadline. A caller can spend a fixed budget per batch,
//! choose one from the batch's shape (for example, compacting only below an active-key density),
//! skip compaction with a zero budget, or commit an empty batch to do compaction-only work.
//!
//! Space is reclaimed more slowly under a bounded budget, so sustained budgets must outpace the
//! rate at which batches render operations inactive. All participants reproducing a root must
//! choose budgets and metadata with the same deterministic function of [`CompactionStats`].
//! Disabling compaction or providing insufficient sustained work can leave retained history
//! unbounded.
//!
//! # Example
//!
//! ```ignore
//! let batch = batch
//!     .merkleize_with_compaction_plan(&db, |stats| {
//!         let retained = *stats.tip - *stats.inactivity_floor;
//!         let max_scan = if retained > 2 * stats.total_active_keys as u64 {
//!             4096
//!         } else {
//!             0
//!         };
//!         let budget = CompactionBudget { max_moves: stats.user_steps + 1, max_scan };
//!         (budget, metadata)
//!     })
//!     .await?;
//! ```
//!
//! [`CompactionBudget`] has no `Default` implementation: callers must choose the move and scan
//! limits explicitly.

use crate::merkle::{Family, Location};

/// Shape of a batch after its mutations are resolved and before compaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionStats<F: Family> {
    /// Operations the batch appends that supersede an existing key's operation (updates and
    /// deletes, not creates). The default budget moves `user_steps + 1` entries, the extra move
    /// accounting for the previous CommitFloor becoming inactive.
    pub user_steps: u64,
    /// Active keys once the batch is applied. Compaction does not change this count.
    pub total_active_keys: usize,
    /// Location where compaction starts scanning. Equals `tip` when the batch leaves no active
    /// keys, in which case compaction has nothing to scan.
    pub inactivity_floor: Location<F>,
    /// Log size after the batch's operations, excluding compaction moves and the CommitFloor.
    /// Compaction scans no further than this location.
    pub tip: Location<F>,
}

impl<F: Family> CompactionStats<F> {
    /// The budget [`UnmerkleizedBatch::merkleize`](crate::qmdb::any::batch::UnmerkleizedBatch::merkleize)
    /// uses: `user_steps + 1` moves with no scan limit.
    pub const fn default_budget(&self) -> CompactionBudget {
        CompactionBudget {
            max_moves: self.user_steps + 1,
            max_scan: u64::MAX,
        }
    }
}

/// Maximum compaction work for one merkleization.
///
/// Limits apply to entry moves and the operation-location interval searched, not elapsed time
/// or bytes copied. Bitmap access is chunk-granular: a chunk intersecting the interval may be
/// read in full. Either limit being zero skips compaction. Use `u64::MAX` for no limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionBudget {
    /// Maximum number of active entries copied to the log's tip.
    pub max_moves: u64,
    /// Maximum number of operation locations searched, including inactive gaps.
    pub max_scan: u64,
}
