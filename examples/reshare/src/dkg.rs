//! `dkg` subcommand: one-shot glue DKG bootstrap for the epoch-0 committee.

use crate::{
    config::{NetworkConfig, NodeConfig},
    types::{
        self, BACKFILL_CHANNEL, BLOCKS_PER_EPOCH, BROADCAST_CHANNEL, CERTIFICATE_CHANNEL,
        DKG_CHANNEL, FileSecretStore, MAILBOX_SIZE, MAX_MESSAGE_SIZE, MAX_SUPPORTED_MODE,
        MESSAGE_RATE, NAMESPACE, Participants, RESOLVER_CHANNEL, REVEAL, SHARING_MODE,
        VOTE_CHANNEL,
    },
};
use clap::Args;
use commonware_consensus::types::Epoch;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_glue::dkg::{
    bootstrap,
    types::{EpochInfo, EpochOutcome},
};
use commonware_p2p::authenticated::{self, discovery};
use commonware_runtime::{Strategizer, Supervisor as _, tokio};
use commonware_utils::{NZUsize, sequence::Unit};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tracing::info;

type ReshareEpochInfo = EpochInfo<MinSig, PublicKey>;

/// Run the one-shot DKG bootstrap and write the resulting genesis.
#[derive(Args)]
pub struct Dkg {
    /// Validator node directory containing config, secrets, and runtime storage.
    #[arg(long, default_value = "./data/validator-0")]
    pub node_dir: PathBuf,
}

/// Run the bootstrap engine to completion and distribute the genesis artifact.
pub async fn run(context: tokio::Context, args: Dkg) {
    let node = NodeConfig::load(&args.node_dir).expect("failed to load node config");
    let network = NetworkConfig::load(&args.node_dir).expect("failed to load network config");
    network.validate().expect("invalid network config");
    let participants = Participants::new(&network).expect("invalid participants");
    let local = node.public_key();
    let bootstrappers = network.bootstrappers(&local);
    let max_peers_per_set = authenticated::peer_set_limit(&network.participants, &local);

    let mut p2p_config = discovery::Config::local(
        node.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        node.listen,
        node.dial,
        bootstrappers,
        max_peers_per_set,
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);

    // Channel rates are enforced independently per peer. The network derives each shared inbound
    // mailbox capacity from the retained-peer bound and quota burst size.
    let vote = p2p.register(VOTE_CHANNEL, MESSAGE_RATE);
    let certificate = p2p.register(CERTIFICATE_CHANNEL, MESSAGE_RATE);
    let resolver = p2p.register(RESOLVER_CHANNEL, MESSAGE_RATE);
    let backfill = p2p.register(BACKFILL_CHANNEL, MESSAGE_RATE);
    let broadcast = p2p.register(BROADCAST_CHANNEL, MESSAGE_RATE);
    let dkg = p2p.register(DKG_CHANNEL, MESSAGE_RATE);

    let strategy = context.strategy(NZUsize!(2));
    let store = FileSecretStore::load(args.node_dir.join("secrets.json"))
        .expect("failed to load secret store");
    let engine = bootstrap::Engine::new(
        context.child("bootstrap"),
        bootstrap::Config {
            signer: node.signing_key,
            manager: oracle.clone(),
            blocker: oracle.clone(),
            secret_store: store,
            strategy,
            namespace: NAMESPACE,
            sharing_mode: SHARING_MODE,
            reveal: REVEAL,
            max_supported_mode: MAX_SUPPORTED_MODE,
            partition_prefix: "bootstrap".to_string(),
            participants: participants.get(Epoch::zero()),
            directory: Unit,
            blocks_per_epoch: BLOCKS_PER_EPOCH,
        },
    );

    let p2p_handle = p2p.start();
    let (engine_handle, completion) =
        engine.start(vote, certificate, resolver, backfill, broadcast, dkg);
    let info = completion
        .await
        .expect("bootstrap completion dropped")
        .info
        .expect("bootstrap DKG failed");
    let mut genesis = info;
    genesis.outcome = EpochOutcome::Success;
    genesis.next_players = participants.get(genesis.epoch.next());
    let written = write_genesis_to_sibling_validators(&args.node_dir, &network, &genesis)
        .expect("failed to write genesis");
    info!(
        epoch = genesis.epoch.get(),
        players = genesis.players.len(),
        next_players = genesis.next_players.len(),
        written,
        "wrote genesis"
    );
    p2p_handle.abort();
    engine_handle.abort();
}

/// Write `genesis` into every sibling validator directory that belongs to
/// `network`, or into `node_dir` alone when none are found.
fn write_genesis_to_sibling_validators(
    node_dir: &Path,
    network: &NetworkConfig,
    genesis: &ReshareEpochInfo,
) -> anyhow::Result<usize> {
    let Some(root) = node_dir.parent() else {
        types::write_genesis(node_dir, genesis)?;
        return Ok(1);
    };

    let mut written = 0;
    for entry in fs::read_dir(root)? {
        let candidate = entry?.path();
        if !candidate.is_dir() {
            continue;
        }
        let Ok(node) = NodeConfig::load(&candidate) else {
            continue;
        };
        if !network.participants.contains(&node.public_key()) {
            continue;
        }
        types::write_genesis(&candidate, genesis)?;
        written += 1;
    }

    if written == 0 {
        types::write_genesis(node_dir, genesis)?;
        return Ok(1);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, PeerConfig};
    use commonware_cryptography::{
        Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519::PrivateKey,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{N3f1, ordered::Set, test_rng};

    #[test]
    fn writes_dkg_genesis_to_all_generated_validators() {
        let root =
            std::env::temp_dir().join(format!("commonware-reshare-dkg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let mut rng = test_rng();
        let signers = (0..4)
            .map(|_| PrivateKey::random(&mut rng))
            .collect::<Vec<_>>();
        let network = NetworkConfig {
            participants: signers.iter().map(|signer| signer.public_key()).collect(),
            committee_size: 2,
            peers: signers
                .iter()
                .enumerate()
                .map(|(i, signer)| PeerConfig {
                    public_key: signer.public_key(),
                    dial: format!("127.0.0.1:{}", 4300 + i)
                        .parse()
                        .expect("valid address"),
                })
                .collect(),
        };

        for (i, signer) in signers.into_iter().enumerate() {
            let node_dir = root.join(format!("validator-{i}"));
            std::fs::create_dir_all(&node_dir).unwrap();
            config::write_json(
                &node_dir.join("node.json"),
                &NodeConfig {
                    signing_key: signer,
                    listen: format!("127.0.0.1:{}", 4300 + i)
                        .parse()
                        .expect("valid address"),
                    dial: format!("127.0.0.1:{}", 4300 + i)
                        .parse()
                        .expect("valid address"),
                },
            )
            .unwrap();
            config::write_json(&node_dir.join("network.json"), &network).unwrap();
        }

        let players = Set::from_iter_dedup(network.participants.iter().take(2).cloned());
        let (output, _shares) =
            deal::<MinSig, _, N3f1>(test_rng(), SHARING_MODE, players.clone()).unwrap();
        let genesis = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players,
            next_players: Set::from_iter_dedup(
                network.participants.iter().skip(1).take(2).cloned(),
            ),
            directory: Unit,
        };

        let written =
            write_genesis_to_sibling_validators(&root.join("validator-0"), &network, &genesis)
                .unwrap();

        assert_eq!(written, 4);
        for i in 0..4 {
            assert_eq!(
                types::read_genesis(&root.join(format!("validator-{i}"))).unwrap(),
                genesis
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
