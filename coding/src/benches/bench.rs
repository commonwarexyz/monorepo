use commonware_coding::{Config, Scheme};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, NZU16};
use criterion::{criterion_main, BatchSize, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

mod no_coding;
mod reed_solomon;
mod zoda;

pub(crate) fn bench_encode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10u16, 25, 50, 100, 250] {
            for conc in [1, 4, 8] {
                let min = chunks / 3;
                let config = Config {
                    minimum_shards: NZU16!(min),
                    extra_shards: NZU16!(chunks - min),
                };
                let strategy = Rayon::new(NZUsize!(conc)).unwrap();
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
                            |data| {
                                if conc > 1 {
                                    S::encode(&config, data.as_slice(), &strategy).unwrap()
                                } else {
                                    S::encode(&config, data.as_slice(), &Sequential).unwrap()
                                }
                            },
                            BatchSize::SmallInput,
                        );
                    },
                );
            }
        }
    }
}

pub(crate) fn bench_decode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [8, 12, 16, 19, 20, 24].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10u16, 25, 50, 100, 250] {
            for conc in [1, 4, 8] {
                let min = chunks / 3;
                let config = Config {
                    minimum_shards: NZU16!(min),
                    extra_shards: NZU16!(chunks - min),
                };
                let strategy = Rayon::new(NZUsize!(conc)).unwrap();
                c.bench_function(
                    &format!("{name}/msg_len={data_length} chunks={chunks} conc={conc}"),
                    |b| {
                        b.iter_batched(
                            || {
                                // Generate random data
                                let mut data = vec![0u8; data_length];
                                rng.fill_bytes(&mut data);

                                // Encode data
                                let (commitment, mut shards) = if conc > 1 {
                                    S::encode(&config, data.as_slice(), &strategy).unwrap()
                                } else {
                                    S::encode(&config, data.as_slice(), &Sequential).unwrap()
                                };

                                let my_shard = shards.pop().unwrap();
                                let weak_shards = shards
                                    .into_iter()
                                    .enumerate()
                                    .take(min as usize)
                                    .map(|(i, shard)| {
                                        let (_, _, weak_shard) =
                                            S::weaken(&config, &commitment, i as u16, shard)
                                                .unwrap();
                                        weak_shard
                                    })
                                    .collect::<Vec<_>>();

                                (commitment, my_shard, weak_shards)
                            },
                            |(commitment, my_shard, weak_shards)| {
                                let (checking_data, _, _) = S::weaken(
                                    &config,
                                    &commitment,
                                    config.minimum_shards.get() + config.extra_shards.get() - 1,
                                    my_shard,
                                )
                                .unwrap();
                                let checked_shards = weak_shards
                                    .into_iter()
                                    .enumerate()
                                    .map(|(i, weak_shard)| {
                                        S::check(
                                            &config,
                                            &commitment,
                                            &checking_data,
                                            i as u16,
                                            weak_shard,
                                        )
                                        .unwrap()
                                    })
                                    .collect::<Vec<_>>();
                                if conc > 1 {
                                    S::decode(
                                        &config,
                                        &commitment,
                                        checking_data,
                                        &checked_shards,
                                        &strategy,
                                    )
                                    .unwrap()
                                } else {
                                    S::decode(
                                        &config,
                                        &commitment,
                                        checking_data,
                                        &checked_shards,
                                        &Sequential,
                                    )
                                    .unwrap()
                                }
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
