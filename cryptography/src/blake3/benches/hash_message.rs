use commonware_cryptography::{blake3::Blake3, Hasher};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn benchmark_hash_message(c: &mut Criterion) {
    let mut sampler = StdRng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for message_length in cases.into_iter() {
        let mut msg = vec![0u8; message_length];
        sampler.fill_bytes(msg.as_mut_slice());
        let msg = msg.as_slice();
        c.bench_function(&format!("{}/msg_len={}", module_path!(), msg.len()), |b| {
            b.iter(|| {
                let mut hasher = Blake3::new();
                hasher.update(msg);
                hasher.finalize();
            });
        });
    }
}

criterion_group!(benches, benchmark_hash_message);
