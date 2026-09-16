use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, num::NonZeroUsize, path::PathBuf};

#[derive(Parser)]
#[command(about = "Run the Bajillion SQLite operator role")]
struct Args {
    /// Native codec RPC listener.
    #[arg(long, default_value = "127.0.0.1:7001")]
    bind: SocketAddr,

    /// Operator node directory containing config, genesis, and storage
    /// (written by `terminal-chain setup` as `operator-<index>/`). The
    /// directory's clearing key names the deployment this operator runs.
    #[arg(long, default_value = "data/operator-0")]
    node_dir: PathBuf,

    /// SQLite database path. Use `:memory:` for an ephemeral run.
    #[arg(long, default_value = "terminal-operator.sqlite")]
    database: PathBuf,

    /// Disable the local native proof replica; clients fetch proofs from other replicas.
    #[arg(long)]
    no_proof_replica: bool,

    /// Workers for maintaining the optional native proof replica.
    #[arg(long, default_value_t = default_workers())]
    workers: NonZeroUsize,
}

fn default_workers() -> NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)
}

fn main() -> Result<()> {
    let args = Args::parse();
    commonware_terminal::run_operator(
        args.bind,
        args.node_dir,
        args.database,
        args.workers,
        !args.no_proof_replica,
    )
}
