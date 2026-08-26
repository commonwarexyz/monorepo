use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Run one Commonware Clearing wallet agent")]
struct Args {
    /// Operator RPC address.
    #[arg(long, default_value = "127.0.0.1:7001")]
    operator: SocketAddr,

    /// Settlement RPC address.
    #[arg(long, default_value = "127.0.0.1:7000")]
    settlement: SocketAddr,

    /// Agent wallet index: 0=Alice, 1=Bob, 2=Carol, 3=Dave, 4=Eve (external).
    #[arg(long, default_value_t = 0)]
    identity: usize,

    /// SQLite wallet database path. Defaults to terminal-agent-<identity>.sqlite.
    #[arg(long)]
    database: Option<PathBuf>,

    /// Run a terminal-free walkthrough.
    #[arg(long)]
    scripted: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let database = args
        .database
        .unwrap_or_else(|| PathBuf::from(format!("terminal-agent-{}.sqlite", args.identity)));
    commonware_terminal::run_agent(
        args.operator,
        args.settlement,
        database,
        args.identity,
        args.scripted,
    )
}
