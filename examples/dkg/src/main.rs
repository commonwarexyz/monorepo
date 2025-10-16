#![doc = include_str!("../README.md")]

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tracing::Level;

mod application;
mod dkg;
mod engine;
mod participant;
mod setup;
mod utils;

/// DKG CLI.
#[derive(Parser)]
pub struct App {
    /// Args for the runtime configuration.
    #[command(flatten)]
    runtime_args: RuntimeArgs,

    /// The subcommand to run
    #[command(subcommand)]
    subcommand: Subcommands,
}

#[derive(Args)]
pub struct RuntimeArgs {
    /// The log level for traces. opts: (error, debug, info, warn, trace)
    #[arg(long, default_value_t = Level::INFO)]
    log_level: Level,

    /// The number of worker threads for the runtime to use
    #[arg(long, default_value_t = 3)]
    worker_threads: usize,
}

/// Subcommands for the DKG example.
#[derive(Subcommand)]
pub enum Subcommands {
    /// Set up a new DKG network's participants.
    Setup(SetupArgs),

    /// Start a validator node.
    Participant(ParticipantArgs),
}

/// Arguments for the `setup` subcommand.
#[derive(Args)]
pub struct SetupArgs {
    /// The number of peers in the network.
    #[arg(long, default_value_t = 4)]
    num_participants: u32,

    /// The number of bootstrappers in the network.
    #[arg(long, default_value_t = 2)]
    num_bootstrappers: usize,

    /// The directory to store the generated participant configurations.
    #[arg(long, default_value = "./data")]
    datadir: PathBuf,

    /// The base port for P2P communication. Each participant will be assigned a port
    /// added to this base port.
    #[arg(long, default_value_t = 3000)]
    base_port: u16,
}

#[derive(Args)]
pub struct ParticipantArgs {
    /// The path to the participant's configuration file.
    #[arg(long = "cfg")]
    config_path: PathBuf,

    /// The path to the peers configuration file.
    #[arg(long = "peers")]
    peers_path: PathBuf,
}

fn main() {
    let app = App::parse();

    match app.subcommand {
        Subcommands::Setup(setup_args) => setup::run(app.runtime_args, setup_args),
        Subcommands::Participant(participant_args) => {
            participant::run(app.runtime_args, participant_args)
        }
    }
}
