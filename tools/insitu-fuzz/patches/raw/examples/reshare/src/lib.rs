//! Library wrapper for commonware-reshare example.
//!
//! This file is auto-copied by setup.sh to enable fuzzing of reshare tests.
//! The original reshare crate is binary-only, but we need a lib interface
//! to import the test modules into the fuzzing harness.

use clap::Args;
use commonware_utils::NZU64;
use std::{num::NonZeroU64, path::PathBuf};

pub mod application;
pub mod dkg;
pub mod engine;
pub mod namespace;
pub mod orchestrator;
pub mod setup;
pub mod validator;

pub use application::{EdScheme, ThresholdScheme};

/// The number of blocks in an epoch.
pub const BLOCKS_PER_EPOCH: NonZeroU64 = NZU64!(200);

/// Arguments for the `setup` subcommand.
#[derive(Args)]
pub struct SetupArgs {
    /// The number of peers in the network.
    #[arg(long, default_value_t = 6)]
    pub num_peers: u32,

    /// The number of bootstrappers in the network.
    #[arg(long, default_value_t = 2)]
    pub num_bootstrappers: usize,

    /// The number of participants per epoch.
    #[arg(long, default_value_t = 4)]
    pub num_participants_per_epoch: u32,

    /// The directory to store the generated participant configurations.
    #[arg(long, default_value = "./data")]
    pub datadir: PathBuf,

    /// The base port for P2P communication. Each participant will be assigned a port
    /// added to this base port.
    #[arg(long, default_value_t = 3000)]
    pub base_port: u16,

    /// Whether or not to set up peers for an initial DKG.
    #[arg(long, default_value_t = false)]
    pub with_dkg: bool,
}

/// Arguments for the `validator` and `dkg` subcommand.
#[derive(Args)]
pub struct ParticipantArgs {
    /// The path to the participant's configuration file.
    #[arg(long = "cfg")]
    pub config_path: PathBuf,

    /// The path to the peers configuration file.
    #[arg(long = "peers")]
    pub peers_path: PathBuf,
}
