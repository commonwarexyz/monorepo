#![doc = include_str!("../README.md")]

use crate::application::{EdScheme, ThresholdScheme};
use clap::{Args, Parser, Subcommand};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_runtime::{
    tokio::{self, telemetry::Logging},
    Metrics, Runner,
};
use std::path::PathBuf;
use tracing::Level;

mod application;
mod dkg;
mod engine;
mod orchestrator;
mod setup;
mod validator;

/// The number of blocks in an epoch.
///
/// Production systems should use a much larger value, as safety in the DKG/reshare depends on
/// synchrony. All players must be online for a small duration during this window.
pub const BLOCKS_PER_EPOCH: u64 = 200;

/// Reshare example CLI.
#[derive(Parser)]
pub struct App {
    /// The log level for traces. opts: (error, debug, info, warn, trace)
    #[arg(long, default_value_t = Level::INFO)]
    log_level: Level,

    /// The number of worker threads for the runtime to use
    #[arg(long, default_value_t = 3)]
    worker_threads: usize,

    /// The subcommand to run
    #[command(subcommand)]
    subcommand: Subcommands,
}

/// Subcommands available in the CLI.
#[derive(Subcommand)]
pub enum Subcommands {
    /// Set up a new network's participants.
    Setup(SetupArgs),

    /// Run a DKG over ED25519 simplex to distribute initial threshold shares.
    Dkg(ParticipantArgs),

    /// Start a validator node.
    Validator(ParticipantArgs),
}

/// Arguments for the `setup` subcommand.
#[derive(Args)]
pub struct SetupArgs {
    /// The number of peers in the network.
    #[arg(long, default_value_t = 6)]
    num_peers: u32,

    /// The number of bootstrappers in the network.
    #[arg(long, default_value_t = 2)]
    num_bootstrappers: usize,

    /// The number of participants per epoch.
    #[arg(long, default_value_t = 4)]
    num_participants_per_epoch: u32,

    /// The directory to store the generated participant configurations.
    #[arg(long, default_value = "./data")]
    datadir: PathBuf,

    /// The base port for P2P communication. Each participant will be assigned a port
    /// added to this base port.
    #[arg(long, default_value_t = 3000)]
    base_port: u16,

    /// Whether or not to set up peers for an initial DKG.
    #[arg(long, default_value_t = false)]
    with_dkg: bool,
}

/// Arguments for the `validator` and `dkg` subcommand.
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

    let config = tokio::Config::new()
        .with_worker_threads(app.worker_threads)
        .with_tcp_nodelay(Some(true))
        .with_catch_panics(false);
    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        // Initialize telemetry.
        tokio::telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: app.log_level,
                json: false,
            },
            None,
            None,
        );

        match app.subcommand {
            Subcommands::Setup(args) => setup::run(args),
            Subcommands::Dkg(args) => validator::run::<EdScheme>(context, args).await,
            Subcommands::Validator(args) => {
                validator::run::<ThresholdScheme<MinSig>>(context, args).await
            }
        }
    });
}
