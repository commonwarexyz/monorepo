//! V2-native contiguous journals.
//!
//! These journals are an explicit opt-in. They use append-only atomic blobs and embedded batch
//! decisions; the legacy contiguous journals and their storage format remain unchanged.
//!
//! The atomic root's application tag is split between journal authority and checked-page state:
//!
//! ```text
//! +------------------------------+----------------------+
//! | journal start + 1 (u64, BE)  | partial CRC32C (u32) |
//! +------------------------------+----------------------+
//! ```
//!
//! A zero start field means that section is not active. Exactly one section (or one matching
//! data/offsets pair for a variable journal) carries a nonzero field. Its name identifies the
//! active tail, its tag identifies the exact retained start, and its committed length identifies
//! the tail end. Sealed section names fill the interval between start and tail. This is sufficient
//! to reconstruct bounds without a separate `Metadata` object or a frame scan.
//!
//! ```text
//! append bytes (unpublished)               sync
//!          |                                 |
//!          v                                 v
//! +----------------+              +-------------------------+
//! | active payload | ------------>| root(s) + marker move   |
//! +----------------+              | one embedded UNO group  |
//!          |                      +-------------------------+
//!          | rollover stages sealed         |
//!          | unmarked roots                  |
//!          v                    old state <--+--> new state
//! ```
//!
//! Payload reaches storage as each append arrives. A rollover may durably stage a sealed section,
//! but its unmarked root remains unreachable. Until publication, recovery selects the old roots
//! and discards any surviving subset of unpublished writes. Publication makes the new length,
//! partial-page checksum, and marker durable together. The decision includes only the previous
//! authority and current tail, regardless of how many sections were crossed. Variable journals
//! place their data and fixed-width offsets roots in the same group, so neither side can advance
//! alone. Rewind and clear first publish a bounded marker move, then remove sections that the new
//! marker makes unreachable.
//!
//! Opening scans section names and bounded atomic roots. A fixed section may read its final partial
//! checked page. Sealed variable sections are page-complete and retain a final offset sentinel, so
//! only the active data and offsets tails need the equivalent validation. Historical data pages are
//! otherwise validated lazily when read. Opening never walks frames or hashes complete sections.

use super::{Contiguous, Many, scan_rewind_size};
use crate::journal::Error;
use commonware_runtime::Handle;

/// A V2-native [`Contiguous`] journal that supports append, rewind, prune, and atomic sync.
///
/// Mutating methods consume the journal. If one fails or its future is cancelled, reopen the
/// journal rather than reusing partially updated in-memory state.
pub trait MutableV2: Contiguous + Sized {
    /// Append one item and return its stable position.
    fn append(
        self,
        item: &Self::Item,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send;

    /// Append one or more item slices and return the last appended position.
    ///
    /// Returns [`Error::EmptyAppend`] if `items` is empty.
    fn append_many(
        self,
        items: Many<'_, Self::Item>,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send
    where
        Self::Item: Sync;

    /// Prune items strictly before `min_position` where section alignment permits.
    ///
    /// Returns whether any data was pruned.
    fn prune(
        self,
        min_position: u64,
    ) -> impl std::future::Future<Output = Result<(Self, bool), Error>> + Send;

    /// Rewind the journal to contain exactly `size` items.
    fn rewind(self, size: u64)
    -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Begin atomically publishing the current journal state.
    ///
    /// A successful call starts publication of the state present when the call began and returns
    /// that state as a new journal value. Awaiting the returned handle waits until publication is
    /// durable and active. Mutations made through the returned journal belong to the next epoch
    /// and require another sync. Dropping the handle does not cancel publication.
    fn start_sync(
        self,
    ) -> impl std::future::Future<Output = Result<(Self, Handle<()>), Error>> + Send;

    /// Atomically publish the current journal state and wait until it is active.
    fn sync(self) -> impl std::future::Future<Output = Result<Self, Error>> + Send;

    /// Destroy all journal storage.
    ///
    /// This final teardown is not crash-safe. Use a concrete journal's reset operation when the
    /// journal must remain recoverable if teardown is interrupted.
    fn destroy(self) -> impl std::future::Future<Output = Result<(), Error>> + Send;

    /// Rewind to the last item matching `predicate`, or to the pruning boundary if none match.
    fn rewind_to<P>(
        mut self,
        predicate: P,
    ) -> impl std::future::Future<Output = Result<(Self, u64), Error>> + Send
    where
        P: FnMut(&Self::Item) -> bool + Send,
    {
        async move {
            let rewind_size = scan_rewind_size(&self, predicate).await?;
            if rewind_size != self.bounds().end {
                self = self.rewind(rewind_size).await?;
            }
            Ok((self, rewind_size))
        }
    }
}

pub mod fixed;
pub mod variable;
