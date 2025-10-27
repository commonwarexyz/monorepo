use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::actor::Actor;
use crate::dkg::participant::evrf::EVRF;
use crate::dkg::participant::registry::Registry;
use crate::dkg::participant::Participant;
use clap::Parser;
use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
use commonware_cryptography::bls12381::{PrivateKey, PublicKey};
use commonware_cryptography::Signer;
use commonware_macros::select;
use commonware_p2p::authenticated::discovery::{self, Network};
use commonware_runtime::{tokio::Context, Metrics};
use commonware_utils::set::Ordered;
use commonware_utils::{quorum, NZU32};
use governor::Quota;
use tracing::{info, Level};

/// Golden-DKG example CLI.
#[derive(Parser)]
pub struct Cli {
    /// The log level for traces. opts: (error, debug, info, warn, trace)
    #[arg(long, default_value_t = Level::INFO)]
    pub log_level: Level,

    /// The number of worker threads for the runtime to use
    #[arg(long, default_value_t = 3)]
    pub worker_threads: usize,

    /// The port for the network layer
    #[arg(long, default_value_t = 8545)]
    pub port: u16,

    /// Peer index
    #[arg(long)]
    pub peer_index: u32,

    /// Bootstrap node (index@port)
    #[arg(long)]
    pub bootstrapper: Option<String>,

    #[arg(long)]
    pub num_peers: u32,
}

impl Cli {
    const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_GOLDEN_";
    const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 2; // 2 MB
    const DKG_CHANNEL: u64 = 0;
    const GREETINGS_CHANNEL: u64 = 1;
    const DEFAULT_MESSAGE_BACKLOG: usize = 256;

    pub async fn run(self, ctx: Context) {
        let players = self.whitelisted_peers();
        let mut network = self.setup_network(&ctx, players.clone()).await;

        // Register Golden DKG channel
        let dkg_net = network.register(
            Self::DKG_CHANNEL,
            Quota::per_second(NZU32!(10)),
            Self::DEFAULT_MESSAGE_BACKLOG,
        );

        // Register Greetings channel
        let greet_net = network.register(
            Self::GREETINGS_CHANNEL,
            Quota::per_second(NZU32!(10)),
            Self::DEFAULT_MESSAGE_BACKLOG,
        );

        let dkg_actor = self.setup_dkg_actor(&ctx, players);

        select! {
            res=dkg_actor.start(dkg_net, greet_net)=>{
                if let Err(e) = res{
                    panic!("Actor finished with error {e}")
                }

            },
            _=network.start()=>{
                panic!("Network finished")
            }

        }
    }

    fn bootsrappers(&self) -> Vec<(PublicKey, SocketAddr)> {
        let mut bootstrappers = vec![];
        if let Some(b) = &self.bootstrapper {
            let s = b.split("@").collect::<Vec<_>>();
            let index = s[0].parse().expect("Failed to parse bootsrapper index");
            let pubkey = PrivateKey::from(Scalar::from_index(index)).public_key();
            let port: u16 = s[1].parse().expect("failed to parse bootstrapper port");
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            bootstrappers.push((pubkey, addr));
        }
        bootstrappers
    }

    fn whitelisted_peers(&self) -> Ordered<PublicKey> {
        (0..self.num_peers)
            .map(|x| PrivateKey::from(Scalar::from_index(x)).public_key())
            .collect::<Ordered<_>>()
    }

    async fn setup_network(
        &self,
        ctx: &Context,
        players: Ordered<PublicKey>,
    ) -> Network<Context, PrivateKey> {
        let p2p_cfg = discovery::Config::local(
            PrivateKey::from(Scalar::from_index(self.peer_index)),
            Self::APPLICATION_NAMESPACE,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            self.bootsrappers(),
            Self::MAX_MESSAGE_SIZE,
        );

        let (network, mut oracle) = discovery::Network::new(ctx.with_label("network"), p2p_cfg);
        oracle.register(0, players).await;

        network
    }

    fn setup_dkg_actor(&self, ctx: &Context, players: Ordered<PublicKey>) -> Actor {
        let beta = Scalar::one();
        let sk_i = Scalar::from_index(self.peer_index);
        let evrf = EVRF::new(sk_i.clone(), beta);

        let player_id = players
            .position(evrf.pk_i())
            .expect("Identity pubkey not found in players");

        info!(
            "Starting with player id: {player_id}, pubkey identity: {}, ",
            evrf.pk_i()
        );

        let inner = Participant::new(evrf, Registry::default());
        let t = quorum(players.len() as u32);

        Actor::new(
            ctx.with_label("actor"),
            inner,
            players,
            player_id as u32,
            t as usize,
        )
    }
}
