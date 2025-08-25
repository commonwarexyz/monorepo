use commonware_coding::zoda::{Commitment, GF128, GF32};
use commonware_cryptography::Sha256;
use criterion::{criterion_group, Criterion};
use rand::RngCore;
use std::time::Instant;

const NUM_BYTES: [usize; 5] = [
    2usize.pow(12),
    2usize.pow(16),
    2usize.pow(20),
    2usize.pow(24),
    2usize.pow(28),
];

const RS_RATES: [usize; 2] = [2, 4];

/// Benchmark the creation of a [`Commitment`].
fn bench_create_commitment(c: &mut Criterion) {
    for inv_rate in RS_RATES {
        for elements in NUM_BYTES {
            c.bench_function(
                &format!(
                    "{}/field=gf32 hasher=sha256 bytes={}",
                    module_path!(),
                    elements
                ),
                |b| {
                    let mut rand = rand::thread_rng();
                    b.iter_custom(|iters| {
                        let mut bytes = vec![0u8; elements];
                        rand.fill_bytes(&mut bytes);

                        let start = Instant::now();
                        let hasher = &mut Sha256::default();
                        for _ in 0..iters {
                            Commitment::<_, GF32>::create(&bytes, hasher, inv_rate).unwrap();
                        }
                        start.elapsed()
                    });
                },
            );

            c.bench_function(
                &format!(
                    "{}/field=gf128 hasher=sha256 bytes={}",
                    module_path!(),
                    elements
                ),
                |b| {
                    let mut rand = rand::thread_rng();
                    b.iter_custom(|iters| {
                        let mut bytes = vec![0u8; elements];
                        rand.fill_bytes(&mut bytes);

                        let start = Instant::now();
                        let hasher = &mut Sha256::default();
                        for _ in 0..iters {
                            Commitment::<_, GF128>::create(&bytes, hasher, inv_rate).unwrap();
                        }
                        start.elapsed()
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_create_commitment
}
