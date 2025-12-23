//! A historical wrapper around [crate::bitmap::Prunable] that maintains snapshots via diff-based batching.
//!
//! The Historical bitmap maintains one full [crate::bitmap::Prunable] bitmap (the current/head state).
//! All historical states and batch mutations are represented as diffs, not full bitmap clones.
//!
//! # Examples
//!
//! ## Basic Batching
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let mut bitmap: BitMap<4> = BitMap::new();
//!
//! // Create and commit a batch
//! bitmap.with_batch(1, |batch| {
//!     batch.push(true);
//!     batch.push(false);
//! }).unwrap();
//!
//! assert_eq!(bitmap.len(), 2);
//! assert!(bitmap.get_bit(0));
//! assert!(!bitmap.get_bit(1));
//! ```
//!
//! ## Read-Through Semantics
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let mut bitmap: BitMap<4> = BitMap::new();
//! bitmap.with_batch(1, |batch| { batch.push(false); }).unwrap();
//!
//! // Before modification
//! assert!(!bitmap.get_bit(0));
//!
//! {
//!     let mut batch = bitmap.start_batch();
//!     batch.set_bit(0, true);
//!
//!     // Read through batch sees the modification
//!     assert!(batch.get_bit(0));
//!
//!     batch.commit(2).unwrap();
//! }
//!
//! // After commit, modification is in current
//! assert!(bitmap.get_bit(0));
//! ```
//!
//! ## Abort on Drop
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! # let mut bitmap: BitMap<4> = BitMap::new();
//! # bitmap.with_batch(1, |batch| { batch.push(true); }).unwrap();
//! let len_before = bitmap.len();
//!
//! {
//!     let mut batch = bitmap.start_batch();
//!     batch.push(true);
//!     batch.push(false);
//!     // Drop without commit = automatic abort
//! }
//!
//! assert_eq!(bitmap.len(), len_before); // Unchanged
//! ```
//!
//! ## Commit History Management
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! # let mut bitmap: BitMap<4> = BitMap::new();
//! for i in 1..=5 {
//!     bitmap.with_batch(i, |batch| {
//!         batch.push(true);
//!     }).unwrap();
//! }
//!
//! assert_eq!(bitmap.commits().count(), 5);
//!
//! // Prune old commits
//! bitmap.prune_commits_before(3);
//! assert_eq!(bitmap.commits().count(), 3);
//! ```

mod batch;
pub use batch::BatchGuard;
mod bitmap;
pub use bitmap::BitMap;
mod error;
pub use error::Error;

#[cfg(test)]
mod tests;
