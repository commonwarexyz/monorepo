//! Decode and fairly buffer peer traffic for one Multimmit epoch.
//!
//! # Flow
//!
//! 1. Receive: each network plane (data, consensus, certificate) has its own channel. A plane is
//!    read only while fewer decodes than its capacity are in flight, so excess frames wait in the
//!    bounded network backlog.
//! 2. Decode: frames are decoded and identified on strategy pools, data frames on the bulk pool
//!    and consensus and certificate frames on the view-critical pool.
//! 3. Lane: each decoded group joins its plane's lane (one lane per producer chain for data).
//!    Each lane is split into `f + 1` equal peer shares, so faulty peers cannot fill a correct
//!    peer's share. A group that would overflow its lane or share is dropped, and so is a
//!    data-availability vote whose claimed signer is not the sending peer.
//! 4. Cohort: while the voter has observation credit, each flush forwards one single-plane cohort,
//!    rotating across planes and across producer chains within the data plane. Consensus and
//!    certificate cohorts stay small so a view-critical verdict never waits out a large batch.
//! 5. Credit: the voter returns one credit per consumed cohort. Without credit, traffic waits in
//!    the lanes.
//!
//! The actor never blocks a peer, since an undecodable frame is not portable proof of a protocol
//! fault, and never admits an artifact: the machine does when the voter consumes a cohort.
//!
//! The ingress loop also serves the [`verifier`](super::verifier), ahead of its own traffic, so a
//! verification job the voter issues runs in the same scheduler turn and between any two ingress
//! turns.
//!
//! Deployments must bound each physical channel's backlog and per-peer ingress quota so their
//! aggregate admitted traffic does not exceed the actor's service capacity. Plane rotation bounds
//! service among already-admitted messages; it does not replace those admission controls.

mod actor;
mod config;
mod lanes;
mod mailbox;
mod metrics;
mod receiver;
#[cfg(test)]
mod tests;

pub(crate) use actor::Actor;
pub(crate) use config::{Config, IngressLimits};
pub(crate) use mailbox::Mailbox;
