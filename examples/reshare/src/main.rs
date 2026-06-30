#![doc = include_str!("../README.md")]

use clap::{Parser, Subcommand};
use commonware_runtime::{
    tokio::{self, telemetry::Logs},
    Runner, Supervisor as _,
};
use std::path::PathBuf;
use tracing::Level;

mod application;
mod config;
mod dkg;
mod setup;
mod types;
mod validator;

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
    Dkg(dkg::Dkg),
    Setup(setup::Setup),
    Validator(validator::Validator),
}

impl Command {
    fn runtime_dir(&self) -> PathBuf {
        match self {
            Self::Dkg(args) => args.node_dir.join("runtime"),
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
            Command::Dkg(args) => dkg::run(context, args).await,
            Command::Setup(args) => setup::run(args),
            Command::Validator(args) => validator::run(context, args).await,
        }
    });
}
