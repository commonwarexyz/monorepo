//! The [`Machine`](machine::Machine) and its input reduction, one file per concern.
//!
//! - `machine`: the `Machine` struct, construction, restore, and inspection.
//! - `step`: entry points: input steps, resumable input passes, work polls, and replay.
//! - `observe`: admission of observed artifacts and their prechecks.
//! - `dependencies`: verification verdicts, dependency waits, and readiness.
//! - `completions`: completions of work the machine issued.
//! - `drive`: component drivers for finality, DA, views, floors, and forwarding.
//! - `persistence`: staging durable changes and the journal barrier pipeline.
//! - `capacity`: artifact, reservation, and outbox occupancy checks.
//! - `retention`: retention floors, view compaction, and retired-artifact sweeps.
//! - `store`, `ledger`: the retained artifact store and the durable ledger the machine owns.

mod capacity;
mod completions;
mod dependencies;
mod drive;
mod ledger;
pub(super) mod machine;
mod observe;
mod persistence;
mod retention;
mod step;
mod store;

#[cfg(test)]
pub(crate) use persistence::DeferredRelease;
pub(crate) use persistence::{
    MAX_BATCH_BYTES, MAX_BATCH_EVENTS, MAX_INFLIGHT_BARRIERS, MAX_STAGED_BARRIERS,
};
pub(crate) use step::InputPass;
