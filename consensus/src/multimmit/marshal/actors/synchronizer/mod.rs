//! Synchronizes finalized Multimmit targets into a durable, dense output prefix.
//!
//! # Inputs
//!
//! - `Synchronize`: finalized L-QCs to synchronize to. Targets that arrive during a pass merge
//!   into the next one, which keeps only the highest view's proofs.
//! - `Finality`: a direct-pool finality fact at the floor view, whose final sweep emits outputs
//!   before the next L-QC arrives.
//! - `Header` and `Commitments`: authenticated producer headers and forward paths, used as
//!   ancestry hints.
//! - `InstallFloor`: a floor checkpoint that replaces the durable cut once verified.
//!
//! # Synchronization pass
//!
//! 1. Collect the same-view proofs above the floor that are not yet selected.
//! 2. Walk tip history back from the proofs' history commitment to the active history.
//! 3. For each history opening, oldest first, then for each proof's final sweep: walk producer
//!    ancestry from the target frontier down to the emitted frontier. Forward paths and cached
//!    headers come first, then the catalog, then backfill for the chains the catalog misses.
//!    Adjacent openings whose outputs fit one custody window share one walk.
//! 4. Resolve the custody of every planned output in a sliding custody window: catalog lookups
//!    first, then backfill fetches for the blocks the catalog lacks. Lookups and fetches finish
//!    out of order; only the contiguous resolved prefix advances.
//! 5. Assign dense output indices in canonical order.
//! 6. Publish outputs, openings and selected proofs in bounded commits whose checkpoint is
//!    written last, with up to two commits waiting for durability.
//!
//! ```text
//! L-QCs -> history walk -> ancestry walk -> custody window -> dense outputs -> commits
//!               |                |                 |
//!           backfill     catalog, backfill  catalog, backfill
//! ```
//!
//! While a pass waits, hints apply at once and synchronization targets merge into the next pass.
//! A floor install taken during a pass stops further intake until the floor install itself runs,
//! so no later command overtakes it.
//!
//! # Floor installation
//!
//! A floor checkpoint is verified (its anchor proof, its frontiers against the current state,
//! and the producer ancestry between its emitted frontier and the anchor's final tips), then
//! installed once every started commit is durable.
//!
//! # Recovery
//!
//! Walk and window state is disposable. On start, the synchronizer reads the durable checkpoint
//! and finishes synchronizing to the latest retained L-QC before it serves its mailbox.

mod actor;
mod custody;
mod finality;
mod floor;
mod history;
mod inbox;
mod mailbox;
mod ports;
mod publish;
mod walk;

pub(crate) use actor::{Actor, Config};
pub(crate) use custody::CUSTODY_LOOKUP_CONCURRENCY;
pub(crate) use mailbox::{Error, Mailbox};
pub(crate) use ports::CustodyFetcher;

#[cfg(test)]
mod tests;
