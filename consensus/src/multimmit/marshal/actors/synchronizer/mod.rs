//! Synchronizes resolved Multimmit views into a durable, dense output prefix.
//!
//! # Inputs
//!
//! - `Synchronize`: a resolved view to synchronize through, named by its tips-history commitment.
//!   Local consensus resolves views with their openings (`ViewResolved`); an L-QC of view `v`
//!   pins view `v - 1` (`LeaderFinalized`, or the latest retained L-QC at recovery). Targets that
//!   arrive during a pass merge into the next one, which keeps the highest view.
//! - `Sweep`: the open view's sweep, whose blocks are emitted before the view resolves.
//! - `Header`: authenticated producer headers, used as ancestry hints.
//! - `InstallFloor`: a floor checkpoint that replaces the durable cut once verified.
//!
//! # Synchronization pass
//!
//! 1. Stage the tips-history records from the target's commitment back to the synchronized one.
//!    Each record opens the view after its parent's, so the chain must end exactly at the
//!    synchronized view. Every record is authenticated by its hash: the target's commitment
//!    comes from local consensus or a verified L-QC, and each record names its parent's.
//! 2. For runs of records whose outputs fit one custody window, oldest first: walk producer
//!    ancestry from the newest tips down to the emitted frontier. Cached headers come first, then the catalog, then backfill for the chains the catalog misses.
//! 3. Resolve the custody of every planned output in a sliding custody window: catalog lookups
//!    first, then backfill fetches for the blocks the catalog lacks. Lookups and fetches finish
//!    out of order; only the contiguous resolved prefix advances.
//! 4. Assign dense output indices in canonical order: `Horiz` of each resolved view, skipping the
//!    prefix the open view's sweep already emitted.
//! 5. Select the target's L-QCs as floor material.
//! 6. Publish outputs, openings and selected proofs in bounded commits whose checkpoint is
//!    written last, with up to two commits waiting for durability.
//!
//! ```text
//! targets -> history walk -> ancestry walk -> custody window -> dense outputs -> commits
//!                 |                |                 |
//!         catalog, backfill  catalog, backfill  catalog, backfill
//! ```
//!
//! After every command, the retained sweep of the view after the synchronized one emits the
//! blocks it places above the emitted frontier through the same walk, window and commits.
//!
//! While a pass waits, hints apply at once and synchronization targets merge into the next pass.
//! A floor install taken during a pass stops further intake until the floor install itself runs,
//! so no later command overtakes it. It also stops the pass, which may be waiting for history that
//! peers no longer serve: the started commits finish, the planned state is dropped, and the floor
//! install runs before the pass's target is synchronized again.
//!
//! # Floor installation
//!
//! A floor is verified (its L-QC and the opening of its history commitment, and its opened tips
//! against the current state), then installed once every started commit is durable.
//!
//! # Recovery
//!
//! Walk and window state is disposable. On start, the synchronizer reads the durable checkpoint
//! and finishes synchronizing to the latest retained L-QC before it serves its mailbox.

mod actor;
mod custody;
mod floor;
mod history;
mod inbox;
mod mailbox;
mod ports;
mod publish;
mod sweep;
mod walk;

pub(crate) use actor::{Actor, Config};
pub(crate) use custody::CUSTODY_LOOKUP_CONCURRENCY;
pub(crate) use mailbox::{Error, Mailbox};
pub(crate) use ports::CustodyFetcher;

#[cfg(test)]
mod tests;
