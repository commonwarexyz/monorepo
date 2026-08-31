//! Settlement chain node: `setup` generates the fixed-committee artifacts and
//! `validator` runs one validator with the certified query server.

use clap::{Parser, Subcommand};
use commonware_runtime::{
    Runner as _, Supervisor as _,
    tokio::{self, telemetry::Logs},
};
use commonware_terminal::chain_main::{Setup, Validator, run_setup, run_validator};
use std::path::PathBuf;
use tracing::Level;

#[derive(Parser)]
struct Cli {
    /// Minimum trace level emitted by the node.
    #[arg(long, default_value_t = Level::INFO)]
    log_level: Level,

    /// Number of Tokio worker threads.
    #[arg(long, default_value_t = 3)]
    worker_threads: usize,

    /// Command to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Setup(Setup),
    Validator(Validator),
}

impl Command {
    fn runtime_dir(&self) -> PathBuf {
        match self {
            Self::Setup(args) => args.node_dir.join("runtime"),
            Self::Validator(args) => args.node_dir.join("runtime"),
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let runtime_dir = cli.command.runtime_dir();
    let config = tokio::Config::new()
        .with_worker_threads(cli.worker_threads)
        .with_catch_panics(false)
        .with_storage_directory(runtime_dir);
    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        tokio::telemetry::init(
            context.child("telemetry"),
            Logs {
                level: cli.log_level,
                json: false,
            },
            None,
            None,
        );

        match cli.command {
            Command::Setup(args) => run_setup(args),
            Command::Validator(args) => run_validator(context, args).await,
        }
    });
}
