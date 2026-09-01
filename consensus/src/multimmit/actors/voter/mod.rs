//! The voter: the runtime around the serial Multimmit core.
//!
//! The voter runs the core on one dedicated task. It admits runtime inputs into the core's
//! lanes, executes the capabilities each step returns, and reports machine-authorized activity.
//! It never derives a protocol fact or retires a durable publication on its own authority.
//!
//! ```text
//!     ingress, verifier                                  resolver
//!             | observations, verdicts                      | resolutions
//!             v                                             v
//!   +------------------------------ voter task --------------------------------+
//!   |  inputs -> CoreState -> capabilities -> egress, timers                   |
//!   |                                     -> builds, custody, crypto (pooled)  |
//!   +--------+------------------------+------------------------------+---------+
//!            | appends, checkpoints    | own-chain shares             | blocks, anchors,
//!            | ^ durability            | ^ certificates               | choices ^ offers
//!            v |                       v |                            v |
//!   persistence actor             DA recovery task             chain plane, one per
//!   journal and snapshots         (producers only)             producer chain
//! ```
//!
//! Durability acknowledgements reenter the core through its highest-weight lane in prefix
//! order, so later staged work never overtakes them. Application and cryptographic work may overlap
//! a pending sync, while signature-bearing effects wait behind the core's durable exposure floor.
//!
//! # Lifecycle
//!
//! - Startup: [`Actor::new`] registers metrics and inbound queues. [`Actor::start`] spawns the voter
//!   task, which starts the persistence actor, stages the fresh start or recovery, and serves the
//!   core until its startup barrier is durable. It then seeds the resolver and reports ready.
//! - Live: each cycle admits the ready inputs, then runs at most one unit of machine work before
//!   yielding. The chain tasks start on the first process generation.
//! - Shutdown: the voter stops on runtime shutdown or its first fatal error; its child tasks stop
//!   with it.

mod actor;
mod chain_plane;
mod config;
mod da_recovery;
mod egress;
mod mailbox;
mod persistence;
mod tasks;
mod telemetry;
#[cfg(test)]
mod tests;

pub(crate) use actor::{Actor, Planes, VoterTypes};
pub(crate) use config::{
    Config, VoterLimits, blocked_counter, validation_capacity, validation_parallelism,
};
pub(crate) use mailbox::{
    Completed, Completions, Endpoints, Inspector, Mailbox, Observations, Observed, Resolutions,
};
#[cfg(test)]
pub(crate) use mailbox::{Inbox, Message, Query};
#[cfg(any(test, feature = "mocks"))]
pub(crate) use persistence::Flusher;
