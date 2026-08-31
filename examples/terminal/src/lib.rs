//! Three-role terminal for `commonware-clearing`.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

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
pub mod chain_main {
    pub use crate::chain::{
        setup::{Setup, run as run_setup},
        validator::{Validator, run as run_validator},
    };
}

/// Runs the SQLite-backed operator role as a follower node of the chain.
#[doc(hidden)]
pub fn run_operator(
    bind: SocketAddr,
    node_dir: PathBuf,
    database: PathBuf,
    workers: NonZeroUsize,
) -> Result<()> {
    service::run_operator(bind, node_dir, database, workers)
}

/// Runs one wallet-owning Ratatui agent as a chain client, bound to one
/// operator and its genesis-configured deployment.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn run_agent(
    operator: SocketAddr,
    genesis: PathBuf,
    queries: Vec<SocketAddr>,
    database: PathBuf,
    identity: usize,
    deployment: usize,
    scripted: bool,
) -> Result<()> {
    service::run_agent(
        operator, genesis, queries, database, identity, deployment, scripted,
    )
}
