use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser)]
#[command(about = "Run the Commonware Clearing settlement role")]
struct Args {
    /// Native codec RPC listener.
    #[arg(long, default_value = "127.0.0.1:7000")]
    bind: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();
    commonware_terminal::run_settlement(args.bind)
}
