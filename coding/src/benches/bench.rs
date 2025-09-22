use commonware_coding::{Config, Scheme};
use criterion::{criterion_main, BatchSize, Criterion};
use rand::{seq::SliceRandom, CryptoRng, RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use rand_core::impls::{next_u32_via_fill, next_u64_via_fill};
use std::{cell::LazyCell, ops::DerefMut};

mod no_coding;
mod reed_solomon;

/// An RNG which has no cost if never used.
///
/// Some schemes use randomness, others don't, and benchmarks should be truly
/// zero cost if the RNG is never used at all. Unfortunately, just initializing
/// an RNG may have a cost, e.g. to hash the initial seed. This uses a [LazyCell]
/// in order to only initialize the RNG when bytes are actually pulled for the
/// first time.
struct LazyRng {
    inner: LazyCell<ChaCha8Rng>,
}

impl LazyRng {
    pub fn new<const SEED: u64>() -> Self {
        Self {
            inner: LazyCell::new(|| ChaCha8Rng::seed_from_u64(SEED)),
        }
    }
}

impl RngCore for LazyRng {
    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.inner.deref_mut().try_fill_bytes(dest)
    }
}

impl CryptoRng for LazyRng {}

pub(crate) fn benchmark_encode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: min as u16,
                extra_shards: (chunks - min) as u16,
            };
            c.bench_function(
                &format!("{}/msg_len={} chunks={}", name, data_length, chunks),
                |b| {
                    b.iter_batched(
                        || {
                            // Generate random data
                            let mut data = vec![0u8; data_length];
                            rng.fill_bytes(&mut data);
                            data
                        },
                        |data| S::encode(&mut LazyRng::new::<1>(), &config, data.as_slice()),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

pub(crate) fn benchmark_decode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: min as u16,
                extra_shards: (chunks - min) as u16,
            };
            c.bench_function(
                &format!("{}/msg_len={} chunks={}", name, data_length, chunks),
                |b| {
                    b.iter_batched(
                        || {
                            // Generate random data
                            let mut data = vec![0u8; data_length];
                            rng.fill_bytes(&mut data);

                            // Encode data
                            let (commitment, mut shards) =
                                S::encode(&mut rng, &config, data.as_slice()).unwrap();

                            shards.shuffle(&mut rng);
                            let my_shard_and_proof = shards.pop().unwrap();
                            let reshards = shards
                                .iter()
                                .take(min)
                                .map(|(shard, proof)| S::check(&commitment, proof, shard).unwrap())
                                .collect::<Vec<_>>();

                            (commitment, my_shard_and_proof, reshards)
                        },
                        // We include the cost of checking your shard as part of decoding
                        |(commitment, (my_shard, my_proof), reshards)| {
                            S::check(&commitment, &my_proof, &my_shard).unwrap();
                            S::decode(&config, &commitment, my_shard, &reshards).unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
}

criterion_main!(reed_solomon::benches, no_coding::benches);
