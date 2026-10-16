//! Run verification jobs on the configured strategy pools for one Multimmit epoch.
//!
//! The machine batches untrusted artifacts into verification jobs, and the voter reserves an
//! execution permit for each before sending it here. Jobs run with the scheme's batch APIs on
//! strategy pools, not shared runtime tasks:
//!
//! ```text
//! machine -> voter --verify--> verifier -+- view-critical job -> critical pool -+
//!                                        +- other job ---------> bulk pool -----+
//! machine <- voter <--completed------------------------------------------------+
//! ```
//!
//! A job carrying view progress runs on the view-critical pool, so a vote-update or certificate
//! verdict never queues behind bulk header verification. Completions return to the voter; only
//! the machine admits artifacts.
//!
//! The verifier has no task of its own: the ingress loop started by
//! [`ingress::Actor::start`](super::ingress::Actor::start) serves its inputs ahead of ingress.

mod actor;
mod config;
mod mailbox;
mod metrics;
#[cfg(test)]
mod tests;
mod verify;

pub(crate) use actor::{Fatal, Verifier};
pub(crate) use config::Config;
pub(crate) use mailbox::Mailbox;
#[cfg(any(test, feature = "mocks"))]
pub(crate) use verify::verify;
