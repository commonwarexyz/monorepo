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

    /// Deployment index in the genesis deployment list (operator N runs
    /// deployment N). Must match the operator behind --operator.
    #[arg(long, default_value_t = 0)]
    deployment: usize,

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
    let database = args.database.unwrap_or_else(|| {
        PathBuf::from(format!(
            "terminal-agent-{}-{}.sqlite",
            args.deployment, args.identity
        ))
    });
    commonware_terminal::run_agent(
        args.operator,
        args.genesis,
        args.queries,
        database,
        args.identity,
        args.deployment,
        args.scripted,
    )
}
