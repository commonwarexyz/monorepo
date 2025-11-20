use commonware_coding::{Config, Scheme};
use criterion::{criterion_main, BatchSize, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

mod no_coding;
mod reed_solomon;
mod zoda;

pub(crate) fn benchmark_encode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            for conc in [1, 4, 8] {
                let min = chunks / 3;
                let config = Config {
                    minimum_shards: min as u16,
                    extra_shards: (chunks - min) as u16,
                };
                c.bench_function(
                    &format!("{name}/msg_len={data_length} chunks={chunks} conc={conc}"),
                    |b| {
                        b.iter_batched(
                            || {
                                // Generate random data
                                let mut data = vec![0u8; data_length];
                                rng.fill_bytes(&mut data);
                                data
                            },
                            |data| S::encode(&config, data.as_slice(), conc),
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
}

pub(crate) fn benchmark_decode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10, 25, 50, 100, 250] {
            for conc in [1, 4, 8] {
                let min = chunks / 3;
                let config = Config {
                    minimum_shards: min as u16,
                    extra_shards: (chunks - min) as u16,
                };
                c.bench_function(
                    &format!("{name}/msg_len={data_length} chunks={chunks} conc={conc}"),
                    |b| {
                        b.iter_batched(
                            || {
                                // Generate random data
                                let mut data = vec![0u8; data_length];
                                rng.fill_bytes(&mut data);

                                // Encode data
                                let (commitment, mut shards) =
                                    S::encode(&config, data.as_slice(), conc).unwrap();

                                let my_shard = shards.pop().unwrap();
                                let reshards = shards
                                    .into_iter()
                                    .enumerate()
                                    .take(min)
                                    .map(|(i, shard)| {
                                        let (_, _, reshard) =
                                            S::reshard(&config, &commitment, i as u16, shard)
                                                .unwrap();
                                        reshard
                                    })
                                    .collect::<Vec<_>>();

                                (commitment, my_shard, reshards)
                            },
                            |(commitment, my_shard, reshards)| {
                                let (checking_data, _, _) = S::reshard(
                                    &config,
                                    &commitment,
                                    config.minimum_shards + config.extra_shards - 1,
                                    my_shard,
                                )
                                .unwrap();
                                let checked_shards = reshards
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, reshard)| {
                                        S::check(
                                            &config,
                                            &commitment,
                                            &checking_data,
                                            i as u16,
                                            reshard,
                                        )
                                        .unwrap()
                                    })
                                    .collect::<Vec<_>>();
                                S::decode(
                                    &config,
                                    &commitment,
                                    checking_data,
                                    &checked_shards,
                                    conc,
                                )
                                .unwrap();
                            },
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
}

criterion_main!(reed_solomon::benches, no_coding::benches, zoda::benches);
