//! Throughput of decoding verifying keys one at a time and as a vector. Every key encodes a curve
//! point, so each decode runs the full point check and succeeds. Fixture generation is not timed.

use commonware_allocator::mimalloc;
use commonware_codec::{Copying, Encode as _, RangeCfg};
use commonware_cryptography_curve25519::signing::{SigningKey, VerifyingKey};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

/// Encodes `n` independent verifying keys as a length-prefixed vector.
fn encode_keys(n: usize) -> Vec<u8> {
    let mut rng = test_rng();
    let keys: Vec<VerifyingKey> = (0..n)
        .map(|_| SigningKey::random(&mut rng).verifying_key())
        .collect();
    keys.encode().to_vec()
}

/// Nested so `module_path!()` includes the crate::module separator the benchmark-name lint (and
/// the benchmark-tracking dashboard) expect.
mod decode_verifying_keys_bench {
    use super::{Copying, Criterion, RangeCfg, Throughput, VerifyingKey, black_box, encode_keys};
    use commonware_codec::Read as _;

    pub fn bench(c: &mut Criterion) {
        let mut group = c.benchmark_group(module_path!());
        for n in [1, 4, 7, 13, 100, 1_000] {
            let encoded = encode_keys(n);
            group.throughput(Throughput::Elements(n as u64));
            group.bench_function(format!("keys={n} path=each"), |b| {
                b.iter(|| {
                    // Skip the length prefix and decode one key at a time.
                    let mut buf = Copying(&encoded[encoded.len() - 32 * n..]);
                    let keys: Vec<VerifyingKey> = (0..n)
                        .map(|_| VerifyingKey::read_cfg(&mut buf, &()).unwrap())
                        .collect();
                    black_box(keys)
                });
            });
            group.bench_function(format!("keys={n} path=vec"), |b| {
                b.iter(|| {
                    let keys = Vec::<VerifyingKey>::read_cfg(
                        &mut Copying(&encoded),
                        &(RangeCfg::from(..), ()),
                    )
                    .unwrap();
                    black_box(keys)
                });
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = decode_verifying_keys_bench::bench
}

criterion_main!(benches);
