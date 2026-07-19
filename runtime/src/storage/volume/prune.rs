//! Prefix pruning: drop a blob's bytes below a chunk-aligned floor.
//!
//! Pruning is a MUTATION, not a durability point: like a write or a
//! resize, it publishes at the blob's next commit — the captured entry
//! carries the floor, and the freed extents release only once that commit
//! confirms (the last confirmed table still references them). A crash
//! before the commit regresses the floor to the adopted commit's: prefix
//! bytes reappear, never the reverse, and callers re-prune.

use super::state::{check_not_removed, BlobCore, Ready};
use crate::Error;

/// Prune bytes below `offset`, exactly: the floor IS `offset`, and reads,
/// writes, and shrinks below it fail from this call on. Physical surgery
/// is chunk-granular (a chunk straddling the floor keeps its low bytes on
/// disk — the checksum granularity requires them — but they are logically
/// dead and never served). The blob's `write_lock` MUST be held, and per
/// the blob's single-writer contract no batch may hold staged state over
/// the blob (staged overlays reference base runs by key, which pruning
/// re-keys).
pub(super) fn prune_locked<S: crate::Storage>(
    ready: &Ready<S>,
    blob: &BlobCore,
    offset: u64,
) -> Result<(), Error> {
    ready.check_poisoned()?;
    check_not_removed(blob)?;
    let mut state = ready.state.lock();
    let mut inner = blob.inner.lock();
    assert_eq!(
        inner.staged_batches(),
        0,
        "prune while a batch stages over the blob (single-writer contract)"
    );
    if offset > inner.size() {
        return Err(Error::BlobInsufficientLength);
    }
    if offset <= inner.floor() {
        return Ok(());
    }
    inner.prune_to(offset);
    // The next commit must capture the blob: its entry records the floor,
    // and the pruned extents release when it confirms.
    state.mark_dirty(blob.id);
    Ok(())
}
