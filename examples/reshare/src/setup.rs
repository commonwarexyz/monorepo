//! `setup` subcommand: generate validator directories and network config.

use crate::{
    config::{self, NetworkConfig, NodeConfig, PeerConfig},
    types::{self, BLOCKS_PER_EPOCH, FileSecretStore, MAX_PARTICIPANTS, Participants},
};
use clap::{Args, ValueEnum};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_glue::dkg::types::{EpochInfo, EpochOutcome};
use commonware_math::algebra::Random;
use commonware_utils::{Faults as _, N3f1, ordered::Map};
use rand::rngs::StdRng;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

type ReshareEpochInfo = EpochInfo<MinSig, PublicKey>;
type TrustedBootstrap = (ReshareEpochInfo, Map<PublicKey, Share>);

/// Generate every validator directory with node, network, and genesis config.
#[derive(Args)]
pub struct Setup {
    /// Directory where validator subdirectories will be generated.
    #[arg(long, default_value = "./data")]
    pub node_dir: PathBuf,

    /// Total number of validators to generate.
    #[arg(long, default_value_t = 6)]
    pub peers: usize,

    /// Number of validators in each epoch committee.
    #[arg(long, default_value_t = 4)]
    pub committee_size: usize,

    /// First local P2P port assigned to validator-0.
    #[arg(long, default_value_t = 3000)]
    pub base_port: u16,

    /// IP address used for generated listen and dial addresses.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
    pub host: IpAddr,

    /// Initial secret generation path.
    #[arg(long, value_enum, default_value = "trusted")]
    pub bootstrap: Bootstrap,
}

/// How the initial threshold secret is generated.
#[derive(Clone, Copy, ValueEnum)]
pub enum Bootstrap {
    /// Generate genesis and epoch-0 shares with a trusted dealer.
    Trusted,
    /// Generate only node and network config; run `dkg` to create genesis.
    Dkg,
}

/// Generate the validator directories and print the commands to run next.
pub fn run(args: Setup) {
    run_inner(args).expect("setup failed");
}

fn run_inner(args: Setup) -> anyhow::Result<()> {
    validate(&args)?;
    if args.node_dir.exists() && args.node_dir.read_dir()?.next().is_some() {
        anyhow::bail!(
            "refusing to write into non-empty directory: {}",
            args.node_dir.display()
        );
    }
    fs::create_dir_all(&args.node_dir)?;

    let mut rng = rand::make_rng::<StdRng>();
    let signers = (0..args.peers)
        .map(|_| PrivateKey::random(&mut rng))
        .collect::<Vec<_>>();
    let peers = signers
        .iter()
        .enumerate()
        .map(|(i, signer)| {
            let port = port(&args, i)?;
            Ok(PeerConfig {
                public_key: signer.public_key(),
                dial: SocketAddr::new(args.host, port),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let network = NetworkConfig {
        participants: signers.iter().map(|signer| signer.public_key()).collect(),
        committee_size: args.committee_size,
        peers,
    };
    let bootstrap = match args.bootstrap {
        Bootstrap::Trusted => Some(trusted_bootstrap(&network)?),
        Bootstrap::Dkg => None,
    };

    for (i, signer) in signers.into_iter().enumerate() {
        let node_dir = args.node_dir.join(format!("validator-{i}"));
        fs::create_dir_all(&node_dir)?;
        let node = NodeConfig {
            signing_key: signer,
            listen: SocketAddr::new(args.host, port(&args, i)?),
            dial: SocketAddr::new(args.host, port(&args, i)?),
        };
        config::write_json(&node_dir.join("node.json"), &node)?;
        config::write_json(&node_dir.join("network.json"), &network)?;

        if let Some((genesis, shares)) = bootstrap.as_ref() {
            types::write_genesis(&node_dir, genesis)?;
            let store = FileSecretStore::load(node_dir.join("secrets.json"))?;
            if let Some(share) = shares.get_value(&node.public_key()).cloned() {
                store.put_initial_share(Epoch::zero(), share)?;
            }
        }
    }

    print_commands(&args, &network)?;
    Ok(())
}

fn trusted_bootstrap(network: &NetworkConfig) -> anyhow::Result<TrustedBootstrap> {
    let participants = Participants::new(network)?;
    let players = participants.get(Epoch::zero());
    let mut rng = rand::make_rng::<StdRng>();
    let (output, shares): (Output<MinSig, PublicKey>, Map<PublicKey, Share>) =
        deal::<MinSig, _, N3f1>(&mut rng, types::SHARING_MODE, players.clone())?;
    let genesis = EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        output,
        players,
        next_players: participants.get(Epoch::new(1)),
    };
    Ok((genesis, shares))
}

fn validate(args: &Setup) -> anyhow::Result<()> {
    if args.peers == 0 {
        anyhow::bail!("peers must not be zero");
    }
    if args.peers > MAX_PARTICIPANTS.get() as usize {
        anyhow::bail!("peers exceeds max supported participants");
    }
    if args.committee_size == 0 {
        anyhow::bail!("committee size must not be zero");
    }
    if args.committee_size > args.peers {
        anyhow::bail!("committee size exceeds peer count");
    }
    if u64::from(N3f1::quorum(args.committee_size)) > dealer_log_slots() {
        anyhow::bail!("committee quorum exceeds available dealer log slots");
    }
    port(args, args.peers - 1)?;
    Ok(())
}

const fn dealer_log_slots() -> u64 {
    let blocks = BLOCKS_PER_EPOCH.get();
    blocks.saturating_sub(blocks / 2 + 1)
}

fn port(args: &Setup, i: usize) -> anyhow::Result<u16> {
    let offset = u16::try_from(i)?;
    args.base_port
        .checked_add(offset)
        .ok_or_else(|| anyhow::anyhow!("base port plus peer index overflows u16"))
}

fn print_commands(args: &Setup, network: &NetworkConfig) -> anyhow::Result<()> {
    if matches!(args.bootstrap, Bootstrap::Dkg) {
        println!("Run DKG with:");
        println!("mprocs {}", commands(args, "dkg", dkg_indexes(network)?));
        println!("Run the cluster with:");
        println!("mprocs {}", commands(args, "validator", 0..args.peers));
        return Ok(());
    }

    println!("Run the cluster with:");
    println!("mprocs {}", commands(args, "validator", 0..args.peers));
    Ok(())
}

fn dkg_indexes(network: &NetworkConfig) -> anyhow::Result<Vec<usize>> {
    let players = Participants::new(network)?.get(Epoch::zero());
    Ok(network
        .participants
        .iter()
        .enumerate()
        .filter_map(|(i, participant)| {
            players
                .iter()
                .any(|player| player == participant)
                .then_some(i)
        })
        .collect())
}

fn commands(args: &Setup, command: &str, indexes: impl IntoIterator<Item = usize>) -> String {
    indexes
        .into_iter()
        .map(|i| {
            format!(
                "\"cargo run --bin commonware-reshare -- {command} --node-dir {}\"",
                args.node_dir.join(format!("validator-{i}")).display()
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_glue::dkg::SecretStore as _;
    use commonware_runtime::Runner as _;

    #[test]
    fn setup_writes_node_configs_genesis_and_shares() {
        let node_dir =
            std::env::temp_dir().join(format!("commonware-reshare-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&node_dir);
        run_inner(Setup {
            node_dir: node_dir.clone(),
            peers: 3,
            committee_size: 2,
            base_port: 4100,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bootstrap: Bootstrap::Trusted,
        })
        .unwrap();

        let first = node_dir.join("validator-0");
        let node = NodeConfig::load(&first).unwrap();
        let network = NetworkConfig::load(&first).unwrap();
        assert_eq!(network.participants.len(), 3);
        assert_eq!(network.committee_size, 2);
        assert!(types::read_genesis(&first).is_ok());

        commonware_runtime::deterministic::Runner::default().start(|_| {
            let mut store = FileSecretStore::load(first.join("secrets.json")).unwrap();
            async move {
                assert!(store.get_share(Epoch::zero()).await.is_some());
            }
        });
        assert_eq!(node.listen.port(), 4100);
        let _ = std::fs::remove_dir_all(node_dir);
    }

    #[test]
    fn setup_rejects_bad_committee_size() {
        let args = Setup {
            node_dir: PathBuf::from("unused"),
            peers: 2,
            committee_size: 3,
            base_port: 3000,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bootstrap: Bootstrap::Trusted,
        };
        assert!(validate(&args).is_err());
    }

    #[test]
    fn setup_rejects_committee_without_enough_dealer_log_slots() {
        let args = Setup {
            node_dir: PathBuf::from("unused"),
            peers: 47,
            committee_size: 47,
            base_port: 3000,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bootstrap: Bootstrap::Trusted,
        };
        assert!(validate(&args).is_err());
    }

    #[test]
    fn dkg_commands_only_include_epoch_zero_players() {
        let mut rng = rand::make_rng::<StdRng>();
        let participants = (0..4)
            .map(|_| PrivateKey::random(&mut rng).public_key())
            .collect::<Vec<_>>();
        let network = NetworkConfig {
            participants,
            committee_size: 2,
            peers: Vec::new(),
        };

        assert_eq!(dkg_indexes(&network).unwrap(), vec![0, 1]);
    }

    #[test]
    fn setup_for_dkg_leaves_bootstrap_artifacts_unwritten() {
        let node_dir = std::env::temp_dir().join(format!(
            "commonware-reshare-setup-dkg-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&node_dir);
        run_inner(Setup {
            node_dir: node_dir.clone(),
            peers: 3,
            committee_size: 2,
            base_port: 4200,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bootstrap: Bootstrap::Dkg,
        })
        .unwrap();

        let first = node_dir.join("validator-0");
        assert!(NodeConfig::load(&first).is_ok());
        assert!(NetworkConfig::load(&first).is_ok());
        assert!(!types::genesis_path(&first).exists());
        assert!(!first.join("secrets.json").exists());
        let _ = std::fs::remove_dir_all(node_dir);
    }

    #[test]
    fn setup_rejects_non_empty_directory() {
        let node_dir = std::env::temp_dir().join(format!(
            "commonware-reshare-setup-non-empty-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&node_dir);
        std::fs::create_dir_all(&node_dir).unwrap();
        std::fs::write(node_dir.join("sentinel"), b"keep").unwrap();
        let result = run_inner(Setup {
            node_dir: node_dir.clone(),
            peers: 1,
            committee_size: 1,
            base_port: 3000,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bootstrap: Bootstrap::Trusted,
        });
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(node_dir);
    }
}
