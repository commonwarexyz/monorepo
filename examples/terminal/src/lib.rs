//! Three-role terminal for `commonware-clearing`.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![recursion_limit = "256"]

mod agent;
mod chain;
mod operator;
mod protocol;
mod rpc;
mod service;
mod store;
mod ui;

use anyhow::Result;
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf};

/// Entry points for the settlement chain binary.
#[doc(hidden)]
#[commonware_macros::stability(ALPHA)]
pub mod chain_main {
    pub use crate::chain::{
        setup::{
            OperatorSetup, RegisterOperator, Setup, prepare_operator, register_operator,
            run as run_setup,
        },
        validator::{Validator, run as run_validator},
    };
}

/// Runs the SQLite-backed operator role as a follower node of the chain.
#[doc(hidden)]
#[commonware_macros::stability(ALPHA)]
pub fn run_operator(
    bind: SocketAddr,
    node_dir: PathBuf,
    database: PathBuf,
    workers: NonZeroUsize,
) -> Result<()> {
    service::run_operator(bind, node_dir, database, workers)
}

/// Runs one wallet-owning Ratatui agent as a chain client, bound to one
/// operator and its authenticated registered deployment.
#[doc(hidden)]
#[commonware_macros::stability(ALPHA)]
#[allow(clippy::too_many_arguments)]
pub fn run_agent(
    operator: SocketAddr,
    genesis: PathBuf,
    queries: Vec<SocketAddr>,
    database: Option<PathBuf>,
    identity: usize,
    deployment: String,
    scripted: bool,
    native_balance: bool,
    transfer: Option<(String, u64)>,
) -> Result<()> {
    service::run_agent(
        operator,
        genesis,
        queries,
        database,
        identity,
        deployment,
        scripted,
        native_balance,
        transfer,
    )
}
