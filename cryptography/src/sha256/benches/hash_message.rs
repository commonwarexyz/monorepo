use commonware_cryptography::{Hasher, Sha256};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, Rng};
use std::hint::black_box;

fn benchmark_hash_message(c: &mut Criterion) {
    for message_length in [100, 1000, 10000].into_iter() {
        let mut msg = vec![0u8; message_length];
        thread_rng().fill(msg.as_mut_slice());
        let msg = msg.as_slice();
        c.bench_function(&format!("{}/msg_len={}", module_path!(), msg.len()), |b| {
            b.iter_batched(
                || {
                    let mut hasher = Sha256::new();
                    hasher.update(msg);
                    hasher
                },
                |mut hasher| {
                    black_box((|| {
                        for _ in 0..message_length {
                            hasher.reset();
                            hasher.update(msg);
                            hasher.finalize();
                        }
                    })());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_hash_message
}
