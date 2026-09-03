//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.

mod actor;
pub(crate) mod rpc;
mod store;

pub(crate) use actor::{CloseEvent, DEFAULT_AMOUNT, Operator};
pub(crate) use store::StagedDeposit;
