use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use commonware_runtime::mocks;
use commonware_stream::{public_key::Connection, Receiver, Sender};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use futures::executor::block_on;

fn benchmark_sender(c: &mut Criterion) {
    let msg = b"hello";
    let max_message_size = 1024 * 1024; // 1MB

    c.bench_function(
        &format!(
            "sender: max_message_size_len={} msg_len={}",
            max_message_size,
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || {
                    let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
                    let (sink, stream) = mocks::Channel::init();
                    let connection = Connection::new(true, sink, stream, cipher, max_message_size);
                    let (sender, _receiver) = connection.split();
                    sender
                },
                |mut sender| async move {
                    sender.send(msg).await.unwrap();
                },
                BatchSize::SmallInput,
            );
        },
    );
}

fn benchmark_receiver(c: &mut Criterion) {
    let msg = b"hello";
    let max_message_size = 1024 * 1024; // 1MB

    c.bench_function(
        &format!(
            "receiver: max_message_size_len={} msg_len={}",
            max_message_size,
            msg.len()
        ),
        |b| {
            b.iter_batched(
                || {
                    let cipher = ChaCha20Poly1305::new(&[0u8; 32].into());
                    let (sink, stream) = mocks::Channel::init();
                    let connection = Connection::new(true, sink, stream, cipher, max_message_size);
                    let (mut sender, receiver) = connection.split();
                    block_on(async {
                        sender.send(msg).await.unwrap();
                    });
                    receiver
                },
                |mut receiver| async move {
                    receiver.receive().await.unwrap();
                },
                BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, benchmark_sender, benchmark_receiver);
criterion_main!(benches);
