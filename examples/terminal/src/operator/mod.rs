//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.

mod actor;
mod qmdb;
pub(crate) mod rpc;
mod store;
mod verify;

#[cfg(test)]
pub(crate) use actor::{CloseEvent, Stage};
pub(crate) use actor::{CloseStarted, DEFAULT_AMOUNT, Operator, SendsOutcome};
pub(crate) use store::{StagedDeposit, StagedWithdrawal};
pub(crate) use verify::{MAX_VERIFICATION_BATCHES, VerifiedSends, verify_sends};
