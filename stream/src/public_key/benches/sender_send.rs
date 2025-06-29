use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use commonware_runtime::mocks;
use commonware_stream::{public_key::Connection, Sender};
use criterion::{criterion_group, BatchSize, Criterion};
use futures::executor::block_on;

fn benchmark_sender_send(c: &mut Criterion) {
    let kbs = [1, 4, 16, 256, 1024, 4_096, 16_384, 65_536];
    for &kb in &kbs {
        let message_size = kb * 1024;
        let msg = vec![0u8; message_size];
        c.bench_function(&format!("{}/len={}", module_path!(), message_size), |b| {
            b.iter_batched(
                || {
                    let cipher1 = ChaCha20Poly1305::new(&[1u8; 32].into());
                    let cipher2 = ChaCha20Poly1305::new(&[2u8; 32].into());
                    let (sink, stream) = mocks::Channel::init();
                    let connection = Connection::from_preestablished(
                        sink,
                        stream,
                        message_size,
                        cipher1,
                        cipher2,
                    );
                    let (sender, receiver) = connection.split();
                    let msg = msg.clone();
                    (sender, receiver, msg)
                },
                |(mut sender, _receiver, msg)| {
                    block_on(async move {
                        sender.send(&msg).await.unwrap();
                    });
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, benchmark_sender_send);
