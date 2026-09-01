//! The promoter: copies committed bodies into the immutable archive.
//!
//! Commits never wait for promotion. The catalog checkpoint is the work queue: the promoter
//! copies bodies after its durable cursor through the newest committed output, then advances the
//! cursor. The catalog reclaims pending custody only below the promoted frontier, so every crash
//! cut replays.
//!
//! # Lifecycle
//!
//! 1. A published commit moves the target and hands over the bodies the catalog still holds.
//! 2. Each step copies one batch after the cursor, reading bodies the handoff lacks from the
//!    catalog, syncs the archive, then syncs the cursor and reports the frontier to the catalog.
//! 3. Once caught up, the promoter applies the newest floor installation to its frontier.
//!
//! Queued messages, immutable reads among them, run before each step.
//!
//! The catalog needs the promoter's mailbox before the promoter exists, and the promoter reads
//! committed outputs through the catalog, so [`channel`] creates the mailbox first.

mod actor;
mod mailbox;
mod metrics;
mod store;

#[cfg(test)]
mod tests;

pub(crate) use actor::{Actor, Bounds, Config, Error, PendingFloor};
pub(crate) use mailbox::{Mailbox, channel};
pub(crate) use store::{PromotionSeed, PromotionStore};
