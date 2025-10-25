use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bytes::Buf;
use clap::Parser;
use commonware_broadcast::buffered::{Config as BConfig, Engine, Mailbox};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadRangeExt, Write};
use commonware_cryptography::bls12381::primitives::group::{Element, Scalar};
use commonware_cryptography::bls12381::{PrivateKey, PublicKey};
use commonware_cryptography::sha256::Digest;
use commonware_cryptography::{Committable, Hasher, Sha256};
use commonware_cryptography::{Digestible, Signer};
use commonware_golden::dkg::participant::evrf::EVRF;
use commonware_golden::dkg::participant::registry::Registry;
use commonware_golden::dkg::participant::Participant;
use commonware_p2p::authenticated::discovery::{self, Network};
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::{
    tokio::{self, telemetry::Logging, Context},
    Metrics, Runner,
};
use commonware_utils::set::Ordered;
use commonware_utils::NZU32;
use governor::Quota;
use tracing::Level;

// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_GOLDEN_";
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
const DKG_CHANNEL: u64 = 0;
const DEFAULT_MESSAGE_BACKLOG: usize = 256;

/// Golden-DKG example CLI.
#[derive(Parser)]
pub struct Cli {
    /// The log level for traces. opts: (error, debug, info, warn, trace)
    #[arg(long, default_value_t = Level::INFO)]
    log_level: Level,

    /// The number of worker threads for the runtime to use
    #[arg(long, default_value_t = 3)]
    worker_threads: usize,

    /// The port for the network layer
    #[arg(long, default_value_t = 8545)]
    port: u16,

    /// Peer index
    #[arg(long)]
    peer_index: u32,

    /// Bootstrap node (index@port)
    #[arg(long)]
    bootstrapper: Option<String>,

    #[arg(long)]
    num_peers: u32,
}

#[derive(Clone)]
struct DummyMsg {
    // The commitment of the message.
    pub commitment: Vec<u8>,

    /// The content of the message.
    pub content: Vec<u8>,
}

impl Committable for DummyMsg {
    type Commitment = Digest;
    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&self.commitment)
    }
}

impl Digestible for DummyMsg {
    type Digest = Digest;
    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.content)
    }
}

impl Read for DummyMsg {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = Vec::<u8>::read_range(buf, *range)?;
        let content = Vec::<u8>::read_range(buf, *range)?;
        Ok(Self {
            commitment,
            content,
        })
    }
}

impl Write for DummyMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
        self.content.write(buf);
    }
}

impl EncodeSize for DummyMsg {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.content.encode_size()
    }
}

struct Actor {
    inner: Participant,
    mailbox: Mailbox<PublicKey, DummyMsg>,
}

impl Actor {
    pub fn new(
        ctx: Context,
        inner: Participant,
        network: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) -> Self {
        // Configure broadcast engine
        let broadcast_cfg = BConfig {
            public_key: inner.pk_i().clone(),
            mailbox_size: 1024,
            deque_size: 10, // Cache size per peer
            priority: false,
            codec_config: RangeCfg::new(..),
        };

        // Create engine and mailbox
        let (engine, mailbox) = Engine::<_, _, DummyMsg>::new(ctx, broadcast_cfg);

        // Connect the network layer to the broadcast layer
        engine.start(network);

        Self { inner, mailbox }
    }
}
impl Cli {
    pub async fn run(self, ctx: Context) {
        let mut network = self.setup_network(&ctx).await;

        // // Register peers
        let (sender, receiver) = network.register(
            DKG_CHANNEL,
            Quota::per_second(NZU32!(10)),
            DEFAULT_MESSAGE_BACKLOG,
        );

        // // Connect the network layer to the broadcast layer
        let actor = self.setup_actor(&ctx, sender, receiver);
        network.start().await.expect("Network finished");
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

    async fn setup_network(&self, ctx: &Context) -> Network<Context, PrivateKey> {
        let p2p_cfg = discovery::Config::local(
            PrivateKey::from(Scalar::from_index(self.peer_index)),
            APPLICATION_NAMESPACE,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            self.bootsrappers(),
            MAX_MESSAGE_SIZE,
        );

        let (network, mut oracle) = discovery::Network::new(ctx.with_label("network"), p2p_cfg);
        oracle.register(0, self.whitelisted_peers()).await;

        network
    }

    fn setup_actor(
        &self,
        ctx: &Context,
        sender: impl Sender<PublicKey = PublicKey>,
        receiver: impl Receiver<PublicKey = PublicKey>,
    ) -> Actor {
        let beta = Scalar::one();
        let sk_i = Scalar::from_index(self.peer_index);
        let evrf = EVRF::new(sk_i.clone(), beta);
        let inner = Participant::new(evrf, Registry::default());
        Actor::new(ctx.with_label("actor"), inner, (sender, receiver))
    }
}

fn main() {
    let cli = Cli::parse();
    let config = tokio::Config::new()
        .with_worker_threads(cli.worker_threads)
        .with_tcp_nodelay(Some(true))
        .with_catch_panics(false);
    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        // Initialize telemetry.
        tokio::telemetry::init(
            context.with_label("telemetry"),
            Logging {
                level: cli.log_level,
                json: false,
            },
            None,
            None,
        );

        cli.run(context).await
    });
}
