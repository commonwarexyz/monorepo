//! Attached runtime actors for one fixed Multimmit epoch.
//!
//! These actors execute machine-selected work only. They own scheduling, networking, bounded
//! ingress, cryptographic execution, persistence, and application dispatch, but never admission,
//! quorum, finality, ordering, or durability decisions.

pub(crate) mod ingress;
mod metrics;
pub(crate) mod resolver;
pub(crate) mod util;
pub(crate) mod verifier;
pub(crate) mod voter;

pub use metrics::WAN_LATENCY;
