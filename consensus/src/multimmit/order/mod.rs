//! Extraction of Multimmit's canonical block order from finalized leaders.
//!
//! Finality of a leader fixes a prefix of the total order: the order its tip-history record
//! carries, extended by the final sweep toward the leader's finalized tips. These pure mechanisms
//! are shared by consensus, which reports the placement its local finality fixes, and marshal,
//! which reconstructs and delivers the order from portable proofs.
//!
//! - [`SlotStream`] and [`FinalSweep`]: the slots one opening or one sweep adds, offset by offset.
//! - [`Cut`] and [`Expansion`]: positions in the order without block digests, and the positions
//!   between two of them, resumable from any cut.

mod cut;
mod error;
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
mod sweep;

pub(crate) use cut::{Cut, Expansion, Position, SweepFact};
pub(crate) use error::Error;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use sweep::Slot;
pub(crate) use sweep::{FinalSweep, SlotStream};
