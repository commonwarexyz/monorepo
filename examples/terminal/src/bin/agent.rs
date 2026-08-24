use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;

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

    /// Run a terminal-free walkthrough.
    #[arg(long)]
    scripted: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    commonware_terminal::run_agent(args.operator, args.settlement, args.identity, args.scripted)
}
