use crate::{
    config::{NetworkConfig, NodeConfig},
    types::{
        self, FileSecretStore, Participants, BACKFILL_CHANNEL, BLOCKS_PER_EPOCH, BROADCAST_CHANNEL,
        CERTIFICATE_CHANNEL, DKG_CHANNEL, MAILBOX_SIZE, MAX_MESSAGE_SIZE, MESSAGE_BACKLOG,
        NAMESPACE, RESOLVER_CHANNEL, VOTE_CHANNEL,
    },
};
use clap::Args;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::primitives::sharing::Mode;
use commonware_glue::dkg::{bootstrap, types::EpochOutcome};
use commonware_p2p::authenticated::discovery;
use commonware_runtime::{tokio, Quota, Supervisor as _, ThreadPooler};
use commonware_utils::{NZUsize, NZU32};
use std::path::PathBuf;
use tracing::info;

#[derive(Args)]
pub struct Dkg {
    #[arg(long, default_value = "./data/validator-0")]
    pub node_dir: PathBuf,
}

pub async fn run(context: tokio::Context, args: Dkg) {
    let node = NodeConfig::load(&args.node_dir).expect("failed to load node config");
    let network = NetworkConfig::load(&args.node_dir).expect("failed to load network config");
    network.validate().expect("invalid network config");
    let participants = Participants::new(&network).expect("invalid participants");
    let local = node.public_key();

    let mut p2p_config = discovery::Config::local(
        node.signing_key.clone(),
        &[NAMESPACE, b"_P2P"].concat(),
        node.listen,
        node.dial,
        network.bootstrappers(&local),
        MAX_MESSAGE_SIZE,
    );
    p2p_config.mailbox_size = MAILBOX_SIZE;
    let (mut p2p, oracle) = discovery::Network::new(context.child("network"), p2p_config);

    let vote = p2p.register(
        VOTE_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let certificate = p2p.register(
        CERTIFICATE_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let resolver = p2p.register(
        RESOLVER_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let backfill = p2p.register(
        BACKFILL_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let broadcast = p2p.register(
        BROADCAST_CHANNEL,
        Quota::per_second(NZU32!(128)),
        MESSAGE_BACKLOG,
    );
    let dkg = p2p.register(DKG_CHANNEL, Quota::per_second(NZU32!(128)), MESSAGE_BACKLOG);

    let strategy = context.create_strategy(NZUsize!(2)).expect("strategy");
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
            sharing_mode: Mode::RootsOfUnity,
            partition_prefix: "bootstrap".to_string(),
            participants: participants.get(Epoch::zero()),
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
    types::write_genesis(&args.node_dir, &genesis).expect("failed to write genesis");
    info!(
        epoch = genesis.epoch.get(),
        players = genesis.players.len(),
        next_players = genesis.next_players.len(),
        "wrote genesis"
    );
    p2p_handle.abort();
    engine_handle.abort();
}
