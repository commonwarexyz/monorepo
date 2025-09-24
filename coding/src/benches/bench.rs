use commonware_coding::{Config, Scheme};
use criterion::{criterion_main, BatchSize, Criterion};
use rand::{seq::SliceRandom, RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

mod no_coding;
mod reed_solomon;

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
                        |data| S::encode(&config, data.as_slice()),
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
                                S::encode(&config, data.as_slice()).unwrap();

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
