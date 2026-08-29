//! The settlement role: the chain owner, its RPC dispatch, and its durable input log.

mod chain;
pub(crate) mod rpc;
pub(crate) mod store;

#[cfg(test)]
pub(crate) use chain::{AdmissionOutcome, ClaimOutcome};
pub(crate) use chain::{Settlement, SettlementSubmission};
