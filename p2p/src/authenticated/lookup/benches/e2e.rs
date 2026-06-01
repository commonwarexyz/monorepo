use commonware_cryptography::{ed25519, Signer as _};
use commonware_macros::select;
use commonware_p2p::{
    authenticated::lookup::{Config, Network},
    Address, AddressableManager, ChannelConfig, Recipients,
};
use commonware_runtime::{
    deterministic, BufferPoolConfig, Clock as _, IoBuf, Quota, Runner as _, Supervisor as _,
};
use commonware_utils::{ordered::Map, NZUsize, NZU32};
use criterion::{criterion_group, Criterion};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

const CHANNEL: u64 = 0;
const MESSAGE_SIZE: usize = 4 * 1024 * 1024;
const NAMESPACE: &[u8] = b"commonware-p2p-e2e-bench";
const BACKLOG: usize = 128;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(1);
const STARTUP_SETTLE: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
enum Protection {
    Encrypted,
    Unencrypted,
}

impl Protection {
    const fn label(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Unencrypted => "unencrypted",
        }
    }

    fn channel_config(self) -> ChannelConfig {
        let cfg = ChannelConfig::new(CHANNEL, Quota::per_second(NZU32!(1_000_000)), BACKLOG);
        match self {
            Self::Encrypted => cfg.encrypted(),
            Self::Unencrypted => cfg.unencrypted(),
        }
    }
}

fn runtime_config() -> deterministic::Config {
    let pool = BufferPoolConfig::for_network()
        .with_max_size(NZUsize!(8 * 1024 * 1024))
        .with_parallelism(NZUsize!(2));

    deterministic::Config::default()
        .with_timeout(Some(Duration::from_secs(30)))
        .with_network_buffer_pool_config(pool)
}

fn network_config(crypto: ed25519::PrivateKey, listen: SocketAddr) -> Config<ed25519::PrivateKey> {
    let mut cfg = Config::local(crypto, NAMESPACE, listen, MESSAGE_SIZE as u32);
    cfg.mailbox_size = NZUsize!(1_000);
    cfg.send_batch_size = NZUsize!(1);
    cfg.peer_connection_cooldown = Duration::from_millis(10);
    cfg.ping_frequency = Duration::from_secs(60);
    cfg.dial_frequency = Duration::from_millis(10);
    cfg
}

async fn send_until_received(
    ctx: &commonware_runtime::deterministic::Context,
    sender: &mut impl commonware_p2p::Sender<PublicKey = ed25519::PublicKey>,
    receiver: &mut impl commonware_p2p::Receiver<PublicKey = ed25519::PublicKey>,
    peer: ed25519::PublicKey,
    expected_sender: &ed25519::PublicKey,
    message: IoBuf,
) -> IoBuf {
    for _ in 0..5_000 {
        let sent = sender.send(Recipients::One(peer.clone()), message.clone(), true);
        if sent.len() != 1 {
            ctx.sleep(Duration::from_millis(1)).await;
            continue;
        }

        let timeout = ctx.sleep(DELIVERY_TIMEOUT);
        let received = select! {
            received = receiver.recv() => Some(received.expect("receive failed")),
            _ = timeout => None,
        };
        let Some((actual_sender, received)) = received else {
            continue;
        };
        assert_eq!(&actual_sender, expected_sender);
        return received;
    }

    panic!("timed out waiting for connected peer");
}

async fn bench_transfer(
    ctx: commonware_runtime::deterministic::Context,
    protection: Protection,
    iterations: u64,
) -> Duration {
    let sk0 = ed25519::PrivateKey::from_seed(0);
    let sk1 = ed25519::PrivateKey::from_seed(1);
    let pk0 = sk0.public_key();
    let pk1 = sk1.public_key();
    let addr0 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10000);
    let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 10001);
    let peers: Map<_, Address> = [(pk0.clone(), addr0.into()), (pk1.clone(), addr1.into())]
        .try_into()
        .expect("peers should be unique");

    let (mut network0, mut oracle0) = Network::new(ctx.child("peer0"), network_config(sk0, addr0));
    let (mut network1, mut oracle1) = Network::new(ctx.child("peer1"), network_config(sk1, addr1));

    assert!(oracle0.track(0, peers.clone()).accepted());
    assert!(oracle1.track(0, peers).accepted());

    let (mut sender0, _) = network0.register_with(protection.channel_config());
    let (_, mut receiver1) = network1.register_with(protection.channel_config());

    let network0 = network0.start();
    let network1 = network1.start();

    ctx.sleep(STARTUP_SETTLE).await;

    let warmup = IoBuf::from(vec![0; 1]);
    let received = send_until_received(
        &ctx,
        &mut sender0,
        &mut receiver1,
        pk1.clone(),
        &pk0,
        warmup,
    )
    .await;
    assert_eq!(received.len(), 1);

    let message = IoBuf::from(vec![7; MESSAGE_SIZE]);
    let mut total = Duration::ZERO;
    for _ in 0..iterations {
        let start = Instant::now();
        let received = send_until_received(
            &ctx,
            &mut sender0,
            &mut receiver1,
            pk1.clone(),
            &pk0,
            message.clone(),
        )
        .await;
        assert_eq!(received.len(), MESSAGE_SIZE);
        total += start.elapsed();
    }

    drop(sender0);
    drop(receiver1);
    network0.abort();
    network1.abort();
    let _ = network0.await;
    let _ = network1.await;

    total
}

fn bench_e2e(c: &mut Criterion) {
    for protection in [Protection::Encrypted, Protection::Unencrypted] {
        c.bench_function(
            &format!(
                "{}/size={} encryption={}",
                module_path!(),
                MESSAGE_SIZE,
                protection.label()
            ),
            |b| {
                b.iter_custom(|iters| {
                    deterministic::Runner::new(runtime_config())
                        .start(|ctx| bench_transfer(ctx, protection, iters))
                })
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_e2e
}
