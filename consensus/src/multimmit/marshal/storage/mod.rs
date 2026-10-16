//! Catalog-owned durable state and disposable synchronization scratch.
//!
//! # Families
//!
//! Marshal stores three artifact families (L-QCs, tip-history openings, and producer blocks) with
//! two lifetimes:
//!
//! - Pending: unfinalized candidates admitted from consensus, peers, or local producers. L-QCs and
//!   history live in prunable archives indexed by view; blocks live in segmented pending custody
//!   ([`pending`]).
//! - Finalized: rows recorded by a commit. L-QC and history rows hold the artifacts themselves.
//!   An L-QC that establishes a floor is recorded with the tips its history opening names
//!   ([`floors::FloorRecord`]), at the same ordinal and with the same retention.
//!   Block rows ([`blocks::FinalBlockMeta`]) hold only the header, the encoded length and the
//!   floor generation that committed them; the body stays in pending custody until it is pruned
//!   or copied into the immutable body archive by the promoter.
//!
//! ```text
//!   admission --> pending custody --commit--> finalized rows --promote--> immutable bodies
//! ```
//!
//! # Owners
//!
//! - [`catalog::CatalogStore`] (catalog actor): pending archives, pending custody, finalized rows,
//!   and the [`catalog_state::CatalogState`] record.
//! - [`scratch`] (synchronizer): spill stacks for history and producer walks, emptied on open.
//!
//! Delivery and the promoter keep their own records beside their actors: the acknowledgement
//! cursor and the promotion cursor with the immutable body archive. Each builds on
//! [`record::DurableRecord`] and the [`archive`] wrappers here.
//!
//! # Publication
//!
//! A commit makes its finalized rows durable before it publishes the checkpoint that names them.
//! After a crash, an output is either absent from the recovered checkpoint or recoverable with
//! its complete body.
//!
//! # Resource Bounds
//!
//! - Pending L-QCs and history are pruned to the selected view after each commit and to the
//!   floor after each installation. Pending block custody is divided into bounded append
//!   segments; a segment is deleted once every chain's floor has passed its rows, so a stalled
//!   chain pins only the segments it inhabits. A full segment is retired with one final marker
//!   sync, so reopening it replays no bodies.
//! - Finalized archives grow with retained chain history. Prunable finalized rows are reclaimed by
//!   application pruning; immutable finalized archives retain their complete prefix. The prunable
//!   backend indexes retained rows in memory.
//! - Each commit syncs every archive it touched once, then publishes one checkpoint that also
//!   carries its pending-archive cleanup obligation. A floor installation adds one intent sync
//!   before its finalized-archive syncs.
//! - Each namespace checkpoint binds the L-QC, history, and block archive backends; reopening with
//!   a different layout fails before any actor starts.
//! - Walk scratch spills to a journal, so catch-up distance does not become memory use.
//!
//! # Versions
//!
//! The catalog record and the pending-custody manifest lead with a version byte. Loading a record
//! whose version this binary does not know aborts the process, so a binary downgrade stops at
//! open instead of misreading state.

pub(super) mod archive;
pub(super) mod blocks;
pub(super) mod catalog;
pub(super) mod catalog_state;
pub(super) mod commit;
pub(super) mod floors;
pub(super) mod pending;
pub(super) mod record;
pub(super) mod scratch;

use commonware_storage::{archive as storage_archive, journal, metadata};

/// A marshal storage operation failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The request was rejected before any store changed, so the stores remain usable.
    #[error("invalid storage request: {0}")]
    Invalid(&'static str),
    /// Stored state contradicts itself or the operation applied to it.
    #[error("storage is inconsistent: {0}")]
    Inconsistent(&'static str),
    /// An archive index is already bound to another key.
    #[error("archive index {index} is bound to another key")]
    KeyMismatch {
        /// Conflicting archive index.
        index: u64,
    },
    /// A mutable store was lost to a failed or canceled mutation.
    #[error("storage is unavailable after a failed or canceled mutation")]
    Poisoned,
    /// An archive operation failed.
    #[error(transparent)]
    Archive(#[from] storage_archive::Error),
    /// A journal operation failed.
    #[error(transparent)]
    Journal(#[from] journal::Error),
    /// A metadata operation failed.
    #[error(transparent)]
    Metadata(#[from] metadata::Error),
    /// A stored value could not be decoded.
    #[error(transparent)]
    Codec(#[from] commonware_codec::Error),
    /// A storage task failed.
    #[error(transparent)]
    Runtime(#[from] commonware_runtime::Error),
}
