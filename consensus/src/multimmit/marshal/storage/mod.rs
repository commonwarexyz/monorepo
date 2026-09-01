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
//! - Marshal uses bounded actor mailboxes, router jobs, backfill requests, subscriptions, and commit
//!   batches. Delivery holds at most `max_pending_acks` waiters; the application owns the
//!   corresponding complete blocks. History and ancestry walks use segmented disk scratch and discard
//!   segments as they are consumed, so catch-up distance does not become RAM use. Sparse ordering
//!   sweeps visit only real slots, and backfill completion indexes keys instead of scanning unrelated
//!   pending requests.
//! - Catalog admits ready producer blocks in bounded cross-chain waves. One active custody cut and
//!   one trailing cut coalesce body and metadata durability without delaying unrelated catalog
//!   commands. A cut always establishes complete custody before its block can satisfy
//!   synchronization; no timer or peer-controlled delay decides when durability begins.
//! - Catalog batches a selected L-QC, history openings, and dense outputs into one commit and syncs
//!   each mutated archive once before one checkpoint sync. That checkpoint also carries the ordinary
//!   cleanup marker, so a crash between publication and temporary pruning needs no second hot-path
//!   metadata sync. Prunable block archives append compact authenticated references and synchronize
//!   the already-written producer custody once; immutable block archives append complete blocks and
//!   reclaim temporary candidates after checkpoint publication. Catalog-issued custody tokens remove
//!   body rereads from this publication path. Duplicate L-QC and history custody avoids no-op archive
//!   syncs. Runtime floor installation adds one bounded intent sync before its parallel
//!   finalized-archive syncs; idempotent recovery consumes that intent before ordinary
//!   synchronization. Floor cleanup durably advances chain-local frontiers before physical
//!   reclamation. Shared pending-block custody is divided into bounded append segments: rows are
//!   retired logically as chain floors advance, and a segment is deleted by name, without reopening
//!   it, once no live row remains. A stalled chain therefore cannot pin later segments it does not
//!   inhabit. A full segment is retired with one final checkpoint sync off the admission path, so
//!   reopening it replays no bodies; cold segments are opened transiently and read through sequential
//!   replay, and cleanup touches only segments that lost rows in bounded concurrent waves, so work
//!   and file-descriptor use do not grow with the manifest. Cleanup never scans finalized history. No
//!   consensus certificate is expanded into its constituent votes for marshal.
//! - Final archives may grow with chain history. Temporary L-QC/history rows, immutable block
//!   candidates, and scratch storage advance internal prune frontiers after commit or floor
//!   installation. Prunable finalized blocks retain their authoritative bodies in producer custody
//!   until explicit application pruning reclaims both rows together; immutable finalized archives
//!   intentionally retain their complete prefix. The prunable archive backend indexes retained rows
//!   in memory, so its index grows with still-needed rows and contracts as the application prune
//!   frontier advances.
//! - Each namespace checkpoint binds the independently selected L-QC, history, and block archive
//!   backends; reopening with a different layout fails before any actor starts.
//! - Temporary disk usage and the prunable backend index are bounded by advancement of the
//!   finality-driven prune frontier; if that frontier stalls, rows that may still be needed remain
//!   retained. Finalized archives grow with retained chain history.
//!
//! # Versions
//!
//! Every stored record leads with a version byte. Loading a record whose version this binary does
//! not know aborts the process, so a binary downgrade stops at open instead of misreading state.

pub(super) mod archive;
pub(super) mod blocks;
pub(super) mod catalog;
pub(super) mod catalog_state;
pub(super) mod commit;
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
