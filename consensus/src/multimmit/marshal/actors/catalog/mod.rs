//! The catalog: the single owner of marshal's mutable storage.
//!
//! One task orders every storage mutation, so recovery depends only on the checkpoint it last
//! published. Durability syncs, body reads, and retirement markers complete in bounded
//! background pools. See the [marshal overview](super::super) for how the catalog fits the
//! other actors.
//!
//! # Lanes
//!
//! - Commands keep mailbox order: a lookup observes every admission queued before it.
//! - Independent reads may overtake queued admissions; they serve committed or advisory state
//!   and never establish custody.
//! - Cursor updates mirror delivery's durable acknowledgement cursor for progress and pruning.
//!
//! A request that cannot run yet parks in its lane and stops that lane until it runs.
//!
//! # Admission
//!
//! 1. Queued admission commands join one batch while they fit the waiting cut.
//! 2. The batch is validated and written to pending storage. A write owns its journal, so while
//!    it runs only reads and materialization completions are served.
//! 3. Written admissions become readable, buffered replies are answered, and the batch joins
//!    the waiting cut.
//! 4. Once no cut is syncing, the waiting cut starts; when it is durable its blocks become
//!    custody and its durable replies are answered.
//!
//! # Commit pipeline
//!
//! ```text
//!   accept --> sync finalized archives --> publish checkpoint --> hand off to delivery
//!                 (second commit may sync here while the first publishes)
//! ```
//!
//! Commits publish in acceptance order. Every published commit owes a pending-archive cleanup,
//! which runs after a bounded number of commits or before a floor installation.
//!
//! # Reads and caches
//!
//! Body requests are answered from two advisory caches (live admissions and materialized
//! reads) before planned reads of pending custody. A cache miss never changes a result.
//!
//! # Glossary
//!
//! - Custody: a block this node has durably stored and can serve after a crash.
//! - Cut: one durability sync that covers every admission buffered before it.
//! - Hot: a body handed to delivery with its commit, so delivery need not read it back.
//! - Handoff: bodies the committing caller already holds and passes with the commit.
//! - Materialize: read a body back from pending custody.
//! - Barrier: a request (pruning or floor installation) that waits for in-flight commits and
//!   cuts to finish.

mod actor;
mod admission;
mod cache;
mod commit;
mod cursor;
mod handoff;
mod intake;
mod mailbox;
mod materializer;
mod metrics;
mod reads;
mod validate;

#[cfg(test)]
mod tests;

pub(crate) use actor::{Bounds, CacheBounds, Catalog, Config, Fatal};
pub(crate) use mailbox::{Error, Mailbox};
