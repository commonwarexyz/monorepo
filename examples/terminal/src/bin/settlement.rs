use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Run the Bajillion SQLite settlement role")]
struct Args {
    /// Native codec RPC listener.
    #[arg(long, default_value = "127.0.0.1:7000")]
    bind: SocketAddr,

    /// SQLite database path. Use `:memory:` for an ephemeral run.
    #[arg(long, default_value = "terminal-settlement.sqlite")]
    database: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    commonware_terminal::run_settlement(args.bind, args.database)
}
