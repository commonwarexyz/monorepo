//! Scheduling controls for QMDB floor raising.
//!
//! A prepared batch accepts zero or more explicit compaction rounds before finalization.
//! Callers can implement their own scheduling policy by choosing a budget for each round.
//! The existing `UnmerkleizedBatch::merkleize` path retains its default automatic compaction.
//! All participants reproducing a root must use the same deterministic policy. Disabling
//! compaction or providing insufficient sustained work can leave retained history unbounded.
//!
//! # Example
//!
//! An application can split compaction into bounded rounds and finalize the batch separately:
//!
//! ```ignore
//! let prepared = batch.prepare(&db).await?;
//! let budget = CompactionBudget { max_moves: 32, max_scan: 4096 };
//! let (prepared, progress) = prepared.compact(&db, budget).await?;
//! println!("moved {} entries across {} locations", progress.moved, progress.scanned);
//! let batch = prepared.merkleize(&db, metadata).await?;
//! ```
//!
//! `CompactionBudget` has no `Default` implementation: callers must choose the move and scan
//! limits explicitly. The existing automatic path continues to use its established policy.

use crate::merkle::{Family, Location};

/// Maximum work for one compaction round.
///
/// Limits apply to entry moves and the operation-location interval searched, not elapsed time
/// or bytes copied. Bitmap access is chunk-granular: a chunk intersecting the interval may be
/// read in full. Either limit being zero disables the round. Use `u64::MAX` for no limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionBudget {
    /// Maximum number of active entries copied to the log's tip.
    pub max_moves: u64,
    /// Maximum number of operation locations searched, including inactive gaps.
    pub max_scan: u64,
}

/// Progress made by one compaction round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionResult<F: Family> {
    /// Number of active entries copied to the tip.
    pub moved: u64,
    /// Length of the operation-location interval searched by this round.
    pub scanned: u64,
    /// Resulting inactivity floor. It never passes an unprocessed active entry.
    pub floor: Location<F>,
    /// Whether the scan reached the tip fixed when the batch was prepared.
    ///
    /// Budget exhaustion alone does not imply scan exhaustion. Later rounds continue the same
    /// scan and never revisit entries moved by an earlier round of this prepared batch.
    pub exhausted: bool,
}
