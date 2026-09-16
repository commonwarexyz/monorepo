//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.

mod actor;
mod qmdb;
pub(crate) mod rpc;
mod store;
mod verify;

#[cfg(test)]
pub(crate) use actor::CloseEvent;
pub(crate) use actor::{DEFAULT_AMOUNT, Operator, SendsOutcome};
pub(crate) use store::StagedDeposit;
pub(crate) use verify::{MAX_VERIFICATION_BATCHES, VerifiedSends, verify_sends};
