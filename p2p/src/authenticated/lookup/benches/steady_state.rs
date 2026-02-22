use commonware_cryptography::{ed25519::PrivateKey, Signer as _};
use commonware_p2p::{
    authenticated::lookup::{self, Config as LookupConfig, Receiver as LookupReceiver, Sender as LookupSender},
    Address, AddressableManager as _, Receiver as _, Recipients, Sender as _,
};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
    Clock as _,
    IoBuf, Metrics as _, Quota,
};
use commonware_utils::ordered::Map;
use criterion::{criterion_group, Criterion, Throughput};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    num::NonZeroU32,
    time::{Duration, Instant},
};

const NAMESPACE: &[u8] = b"p2p_lookup_steady_state_bench";
const CHANNEL: u64 = 0;
const MAILBOX_SIZE: usize = 8_192;
const RECEIVER_BACKLOG: usize = 8_192;
const MESSAGES_PER_ITERATION: u64 = 128;

fn next_local_addr() -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("failed to reserve local address");
    let addr = listener.local_addr().expect("failed to fetch local address");
    drop(listener);
    addr
}

fn network_config(
    signing_key: PrivateKey,
    listen: SocketAddr,
    max_message_size: u32,
) -> LookupConfig<PrivateKey> {
    let mut cfg = lookup::Config::local(signing_key, NAMESPACE, listen, max_message_size);
    cfg.mailbox_size = MAILBOX_SIZE;
    cfg.dial_frequency = Duration::from_millis(20);
    cfg.query_frequency = Duration::from_secs(1);
    cfg
}

fn bench_steady_state(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let mut group = c.benchmark_group(module_path!());

    for message_size in [64usize, 1024, 16 * 1024] {
        group.throughput(Throughput::Bytes(
            message_size as u64 * MESSAGES_PER_ITERATION,
        ));
        group.bench_function(format!("msg_size={message_size}"), |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let context = context::get::<Context>();

                let peer0_sk = PrivateKey::from_seed(21);
                let peer1_sk = PrivateKey::from_seed(22);
                let peer0_pk = peer0_sk.public_key();
                let peer1_pk = peer1_sk.public_key();

                let peer0_addr = next_local_addr();
                let peer1_addr = next_local_addr();
                let max_message_size = (message_size as u32).saturating_mul(2);

                let (mut network0, mut oracle0) = lookup::Network::new(
                    context.with_label("peer_0"),
                    network_config(peer0_sk, peer0_addr, max_message_size),
                );
                let (mut network1, mut oracle1) = lookup::Network::new(
                    context.with_label("peer_1"),
                    network_config(peer1_sk, peer1_addr, max_message_size),
                );

                let peers: Map<_, Address> = vec![
                    (peer0_pk.clone(), peer0_addr.into()),
                    (peer1_pk.clone(), peer1_addr.into()),
                ]
                .try_into()
                .expect("duplicate peers");

                oracle0.track(0, peers.clone()).await;
                oracle1.track(0, peers).await;

                let quota_0 =
                    Quota::per_second(NonZeroU32::new(100_000).expect("non-zero quota"));
                let quota_1 =
                    Quota::per_second(NonZeroU32::new(100_000).expect("non-zero quota"));
                let (mut sender0, _receiver0): (LookupSender<_, Context>, LookupReceiver<_>) =
                    network0.register(CHANNEL, quota_0, RECEIVER_BACKLOG);
                let (_sender1, mut receiver1): (LookupSender<_, Context>, LookupReceiver<_>) =
                    network1.register(CHANNEL, quota_1, RECEIVER_BACKLOG);

                network0.start();
                network1.start();

                let payload = IoBuf::from(vec![0xCD; message_size]);

                // Establish connection before timing.
                loop {
                    let sent = sender0
                        .send(Recipients::One(peer1_pk.clone()), payload.clone(), true)
                        .await
                        .expect("warm-up send failed");
                    if sent.len() == 1 {
                        let (_sender, received) = receiver1.recv().await.expect("warm-up recv failed");
                        debug_assert_eq!(received.len(), message_size);
                        break;
                    }
                    context.sleep(Duration::from_millis(5)).await;
                }

                let start = Instant::now();
                for _ in 0..iters {
                    for _ in 0..MESSAGES_PER_ITERATION {
                        let sent = sender0
                            .send(Recipients::One(peer1_pk.clone()), payload.clone(), true)
                            .await
                            .expect("send failed");
                        debug_assert_eq!(sent.len(), 1);
                        let (_sender, received) = receiver1.recv().await.expect("recv failed");
                        debug_assert_eq!(received.len(), message_size);
                    }
                }
                let elapsed = start.elapsed();

                elapsed
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_steady_state
}
