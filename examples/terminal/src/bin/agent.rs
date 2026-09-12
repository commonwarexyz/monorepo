use anyhow::Result;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(about = "Run one Bajillion wallet agent")]
struct Args {
    /// Operator RPC address.
    #[arg(long, default_value = "127.0.0.1:7001")]
    operator: SocketAddr,

    /// Settlement chain genesis file holding the committee threshold identity
    /// (written by `terminal-chain setup` as `genesis.json`).
    #[arg(long, default_value = "data/validator-0/genesis.json")]
    genesis: PathBuf,

    /// Validator query addresses. One suffices for verified reads, and extra
    /// addresses give failover rotation past stale or unreachable validators.
    #[arg(long = "query", required = true)]
    queries: Vec<SocketAddr>,

    /// Agent wallet index: 0=Alice, 1=Bob, 2=Carol, 3=Dave, 4=Eve (external).
    #[arg(long, default_value_t = 0)]
    identity: usize,

    /// Registered deployment digest in hex, or a genesis deployment index.
    #[arg(long, default_value = "0")]
    deployment: String,

    /// Print the certified shared native balance and exit.
    #[arg(long, conflicts_with_all = ["scripted", "transfer_to"])]
    native_balance: bool,

    /// Transfer native funds to this hex-encoded account key and exit.
    #[arg(long, requires = "amount", conflicts_with = "scripted")]
    transfer_to: Option<String>,

    /// Native amount to transfer (for example, to fund a new operator).
    #[arg(long, requires = "transfer_to")]
    amount: Option<u64>,

    /// SQLite wallet database path. Defaults to
    /// `terminal-agent-<deployment>-<identity>.sqlite`.
    #[arg(long)]
    database: Option<PathBuf>,

    /// Run a terminal-free walkthrough.
    #[arg(long)]
    scripted: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    commonware_terminal::run_agent(
        args.operator,
        args.genesis,
        args.queries,
        args.database,
        args.identity,
        args.deployment,
        args.scripted,
        args.native_balance,
        args.transfer_to.zip(args.amount),
    )
}
