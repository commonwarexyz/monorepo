//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.

mod actor;
pub(crate) mod rpc;
mod store;

pub(crate) use actor::{DEFAULT_AMOUNT, Operator};
