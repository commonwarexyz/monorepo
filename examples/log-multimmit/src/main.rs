#![doc = include_str!("../README.md")]

mod application;
mod bench;
mod committee;
mod config;
mod deploy;
mod gui;
mod marshal;
mod node;
mod progress;
mod trace_file;

use clap::{Parser, Subcommand};
use commonware_runtime::{Runner as _, tokio};
use config::{RunArgs, RunConfig};

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Log target of the progress and startup lines, kept stable for tooling that selects them by
/// target.
const LOG_TARGET: &str = "commonware_log_multimmit";

/// Generate secret logs across concurrent producer chains with Multimmit.
#[derive(Parser)]
#[command(name = "commonware-log-multimmit", subcommand_negates_reqs = true)]
struct Cli {
    /// Generate deployment artifacts.
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a remote deployment bundle.
    Deploy(deploy::Deploy),
}

fn main() {
    let cli = Cli::parse();
    if let Some(Command::Deploy(args)) = cli.command {
        tracing_subscriber::fmt().init();
        args.run();
        return;
    }

    let config = RunConfig::load(cli.run);
    if let Err(error) = config.validate() {
        panic!("invalid configuration: {error}");
    }
    let pools = node::buffer_pools(config.worker_threads);
    let runtime = tokio::Config::new()
        .with_worker_threads(config.worker_threads.get())
        .with_storage_directory(&config.identity.storage_dir)
        .with_network_buffer_pool_config(pools.network)
        .with_storage_buffer_pool_config(pools.storage);
    tokio::Runner::new(runtime).start(|context| node::run(context, config));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_does_not_require_run_arguments() {
        assert!(Cli::try_parse_from(["log-multimmit", "deploy"]).is_ok());
        assert!(Cli::try_parse_from(["log-multimmit"]).is_err());
    }
}
