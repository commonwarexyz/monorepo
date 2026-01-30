//! A historical wrapper around [crate::bitmap::Prunable] that maintains snapshots via diff-based batching.
//!
//! The Historical bitmap maintains one full [crate::bitmap::Prunable] bitmap (the current/head state).
//! All historical states are represented as diffs, not full bitmap clones.
//!
//! Uses a type-state pattern to track whether the bitmap is clean (no pending mutations) or
//! dirty (has pending mutations). This provides compile-time guarantees about when mutations
//! are allowed.
//!
//! # Examples
//!
//! ## Usage
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let bitmap: BitMap<4> = BitMap::new();
//!
//! // Transition to dirty state to make mutations
//! let mut dirty = bitmap.into_dirty();
//! dirty.push(true);
//! dirty.push(false);
//!
//! // Commit changes and return to clean state
//! let bitmap = dirty.commit(1).unwrap();
//!
//! assert_eq!(bitmap.len(), 2);
//! assert!(bitmap.get_bit(0));
//! assert!(!bitmap.get_bit(1));
//! ```
//!
//! ## Usage with closure
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let mut bitmap: BitMap<4> = BitMap::new();
//!
//! bitmap = bitmap.apply(1, |dirty| {
//!     dirty.push(true);
//!     dirty.push(false);
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
//! bitmap = bitmap.apply(1, |dirty| { dirty.push(false); }).unwrap();
//!
//! // Before modification
//! assert!(!bitmap.get_bit(0));
//!
//! let mut dirty = bitmap.into_dirty();
//! dirty.set_bit(0, true);
//!
//! // Read through dirty state sees the modification
//! assert!(dirty.get_bit(0));
//!
//! let bitmap = dirty.commit(2).unwrap();
//!
//! // After commit, modification is in current
//! assert!(bitmap.get_bit(0));
//! ```
//!
//! ## Abort Mutations
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let mut bitmap: BitMap<4> = BitMap::new();
//! bitmap = bitmap.apply(1, |dirty| { dirty.push(true); }).unwrap();
//! let len_before = bitmap.len();
//!
//! // Make changes in dirty state
//! let mut dirty = bitmap.into_dirty();
//! dirty.push(true);
//! dirty.push(false);
//!
//! // Abort to discard changes and return to clean state
//! let bitmap = dirty.abort();
//!
//! assert_eq!(bitmap.len(), len_before); // Unchanged
//! ```
//!
//! ## Commit History Management
//!
//! ```
//! # use commonware_utils::bitmap::historical::BitMap;
//! let mut bitmap: BitMap<4> = BitMap::new();
//! for i in 1..=5 {
//!     bitmap = bitmap.apply(i, |dirty| {
//!         dirty.push(true);
//!     }).unwrap();
//! }
//!
//! assert_eq!(bitmap.commits().count(), 5);
//!
//! // Prune old commits
//! bitmap.prune_commits_before(3);
//! assert_eq!(bitmap.commits().count(), 3);
//! ```

mod bitmap;
pub use bitmap::{BitMap, Clean, CleanBitMap, Dirty, DirtyBitMap, State};
mod error;
pub use error::Error;

#[cfg(test)]
mod tests;
