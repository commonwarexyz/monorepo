use commonware_cryptography::{ed25519::PrivateKey, Signer as _};
use commonware_runtime::{
    benchmarks::{context, tokio},
    tokio::Context,
    IoBuf, Listener as _, Metrics as _, Network as _, Spawner as _,
};
use commonware_stream::encrypted::{self, Config as StreamConfig};
use criterion::{criterion_group, Criterion, Throughput};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

const NAMESPACE: &[u8] = b"stream_encrypted_transport_bench";
const MESSAGES_PER_ITERATION: u64 = 256;
const MAX_MESSAGE_SIZE: u32 = 256 * 1024;

fn stream_config(signing_key: PrivateKey) -> StreamConfig<PrivateKey> {
    StreamConfig {
        signing_key,
        namespace: NAMESPACE.to_vec(),
        max_message_size: MAX_MESSAGE_SIZE,
        synchrony_bound: Duration::from_secs(5),
        max_handshake_age: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
    }
}

fn bench_steady_state(c: &mut Criterion) {
    let runner = tokio::Runner::default();
    let mut group = c.benchmark_group(module_path!());

    for message_size in [64usize, 1024, 16 * 1024, 64 * 1024] {
        group.throughput(Throughput::Bytes(
            message_size as u64 * MESSAGES_PER_ITERATION,
        ));
        group.bench_function(format!("msg_size={message_size}"), |b| {
            b.to_async(&runner).iter_custom(|iters| async move {
                let context = context::get::<Context>();

                let dialer_key = PrivateKey::from_seed(11);
                let listener_key = PrivateKey::from_seed(12);
                let listener_public_key = listener_key.public_key();

                let mut listener = context
                    .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .await
                    .expect("failed to bind listener");
                let listener_addr = listener.local_addr().expect("failed to get listener addr");

                let listener_task =
                    context
                        .clone()
                        .with_label("listener")
                        .spawn(move |context| async move {
                            let (_addr, sink, stream) = listener
                                .accept()
                                .await
                                .expect("failed to accept connection");
                            encrypted::listen(
                                context,
                                |_| async { true },
                                stream_config(listener_key),
                                stream,
                                sink,
                            )
                            .await
                            .expect("listener handshake failed")
                        });

                let (sink, stream) = context
                    .dial(listener_addr)
                    .await
                    .expect("failed to dial listener");
                let (mut sender, _receiver) = encrypted::dial(
                    context.clone(),
                    stream_config(dialer_key),
                    listener_public_key,
                    stream,
                    sink,
                )
                .await
                .expect("dialer handshake failed");

                let (_peer, _sender, mut receiver) =
                    listener_task.await.expect("listener task failed");

                let payload = IoBuf::from(vec![0xABu8; message_size]);
                let start = Instant::now();
                for _ in 0..iters {
                    for _ in 0..MESSAGES_PER_ITERATION {
                        sender.send(payload.clone()).await.expect("send failed");
                        let received = receiver.recv().await.expect("recv failed");
                        debug_assert_eq!(received.len(), message_size);
                    }
                }

                start.elapsed()
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
