#![doc = include_str!("../README.md")]

use crate::{
    application::{EdScheme, ThresholdScheme},
    dkg::{ContinueOnUpdate, PostUpdate, Update, UpdateCallBack},
    setup::ParticipantConfig,
};
use clap::{Args, Parser, Subcommand};
use commonware_codec::Encode;
use commonware_consensus::simplex::elector::{Random, RoundRobin};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_runtime::{
    tokio::{self, telemetry::Logging},
    Metrics, Runner,
};
use commonware_utils::hex;
use std::{future::Future, path::PathBuf, pin::Pin};
use tracing::Level;

mod application;
mod dkg;
mod engine;
mod namespace;
mod orchestrator;
mod setup;
mod validator;

/// This exists to implement [`UpdateCallBack`] for the simple case of saving the DKG result.
///
/// This is used to do an initial setup for using the result to run a threshold-signature
/// based consensus. In order to bootstrap the initial shares, we run a non-threshold
/// version of consensus, until we successfully complete a DKG, and then save the
/// public output and our private share to a file.
///
/// For a more production-oriented version of this pattern, you'd probably want
/// to have this use [`commonware_storage`], with the same backing store that you
/// use for storing the shares later, e.g. [`commonware_storage::metadata`].
///
/// In this example, this saves to a file to make the result more easily inspectable.
struct SaveFileOnUpdate {
    path: PathBuf,
}

impl SaveFileOnUpdate {
    pub fn boxed(path: PathBuf) -> Box<Self> {
        Box::new(Self { path })
    }
}

impl UpdateCallBack<MinSig, PublicKey> for SaveFileOnUpdate {
    fn on_update(
        &mut self,
        update: Update<MinSig, PublicKey>,
    ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>> {
        let config_path = self.path.clone();
        Box::pin(async move {
            match update {
                Update::Failure { .. } => PostUpdate::Continue,
                Update::Success { output, share, .. } => {
                    let config_str =
                        std::fs::read_to_string(&config_path).expect("failed to read config file");
                    let config: ParticipantConfig = serde_json::from_str(&config_str)
                        .expect("Failed to deserialize participant configuration");
                    config.update_and_write(&config_path, |config| {
                        config.output = Some(hex(output.encode().as_ref()));
                        config.share = share;
                    });
                    PostUpdate::Stop
                }
            }
        })
    }
}

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
            Subcommands::Dkg(args) => {
                let config_path = args.config_path.clone();
                validator::run::<EdScheme, RoundRobin>(
                    context,
                    args,
                    SaveFileOnUpdate::boxed(config_path),
                )
                .await;
            }
            Subcommands::Validator(args) => {
                validator::run::<ThresholdScheme<MinSig>, Random>(
                    context,
                    args,
                    ContinueOnUpdate::boxed(),
                )
                .await
            }
        }
    });
}
