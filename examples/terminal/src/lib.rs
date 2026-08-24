//! Three-role terminal for `commonware-clearing`.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

mod agent;
mod operator;
mod operator_rpc;
mod protocol;
mod rpc;
mod service;
mod settlement;
mod settlement_rpc;
mod store;
mod ui;

use anyhow::Result;
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf};

/// Runs the settlement role.
#[doc(hidden)]
pub fn run_settlement(bind: SocketAddr) -> Result<()> {
    service::run_settlement(bind)
}

/// Runs the SQLite-backed operator role.
#[doc(hidden)]
pub fn run_operator(
    bind: SocketAddr,
    settlement: SocketAddr,
    database: PathBuf,
    workers: NonZeroUsize,
) -> Result<()> {
    service::run_operator(bind, settlement, database, workers)
}

/// Runs one wallet-owning Ratatui agent.
#[doc(hidden)]
pub fn run_agent(
    operator: SocketAddr,
    settlement: SocketAddr,
    identity: usize,
    scripted: bool,
) -> Result<()> {
    service::run_agent(operator, settlement, identity, scripted)
}
