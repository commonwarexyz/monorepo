use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use commonware_runtime::mocks;
use commonware_stream::{public_key::Connection, Receiver, Sender};
use criterion::{criterion_group, BatchSize, Criterion};
use futures::executor::block_on;

fn benchmark_receiver_receive(c: &mut Criterion) {
    let kbs = [1, 4, 16, 256, 1024, 4_096, 16_384, 65_536];
    for &kb in &kbs {
        let message_size = kb * 1024;
        let msg = vec![0u8; message_size];
        c.bench_function(&format!("{}/len={}", module_path!(), message_size), |b| {
            b.iter_batched(
                || {
                    // Set up a connection between two parties.
                    // We only send messages in one direction from A to B.
                    let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
                    let (sink, stream) = mocks::Channel::init();
                    let (sink_dummy, stream_dummy) = mocks::Channel::init();
                    let conn_a = Connection::from_preestablished(
                        false,
                        sink,
                        stream_dummy,
                        cipher.clone(),
                        message_size,
                    );
                    let conn_b = Connection::from_preestablished(
                        true,
                        sink_dummy,
                        stream,
                        cipher,
                        message_size,
                    );

                    let (mut sender, _) = conn_a.split();
                    let (_, receiver) = conn_b.split();

                    block_on(async {
                        sender.send(&msg).await.unwrap();
                    });
                    receiver
                },
                |mut receiver| {
                    block_on(async move {
                        receiver.receive().await.unwrap();
                    });
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_receiver_receive);
