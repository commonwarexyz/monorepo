//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.

mod actor;
mod qmdb;
pub(crate) mod rpc;
mod store;

#[cfg(test)]
pub(crate) use actor::CloseEvent;
pub(crate) use actor::{DEFAULT_AMOUNT, Operator};
pub(crate) use store::StagedDeposit;
