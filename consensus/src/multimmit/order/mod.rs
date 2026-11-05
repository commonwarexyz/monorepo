//! Extraction of Multimmit's canonical block order from finalized leaders.
//!
//! Finality of a leader fixes a prefix of the total order: the order its tip-history record
//! carries, extended by the final sweep toward the leader's finalized tips. These pure mechanisms
//! are shared by consensus, which reports the placement its local finality fixes, and marshal,
//! which reconstructs and delivers the order from portable proofs.

// TODO(marshal-v2): remove once marshal consumes symbolic cuts.
#[allow(dead_code)]
mod cut;
mod error;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
mod history;
mod sweep;

pub(crate) use cut::{Cut, Expansion, SweepFact};
pub(crate) use error::Error;
pub(crate) use history::{HistoryState, Reconciliation};
pub(crate) use sweep::{FinalSweep, Slot, SlotStream};
