use commonware_coding::{Config, PhasedScheme};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, NZU16};
use criterion::{criterion_main, BatchSize, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use shard_selection::SELECTIONS;

mod shard_selection;
mod zoda_phased;

pub(crate) fn bench_encode_generic<S: PhasedScheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [20, 22, 23].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10u16, 25, 50, 100, 250] {
            for conc in [1, 8] {
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

pub(crate) fn bench_decode_generic<S: PhasedScheme>(name: &str, c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [20, 22, 23].map(|i| 2usize.pow(i));
    for data_length in cases.into_iter() {
        for chunks in [10u16, 25, 50, 100, 250] {
            for conc in [1, 8] {
                let min = chunks / 3;
                let config = Config {
                    minimum_shards: NZU16!(min),
                    extra_shards: NZU16!(chunks - min),
                };
                let strategy = Rayon::new(NZUsize!(conc)).unwrap();
                for selection in SELECTIONS {
                    let sel = selection.label();
                    c.bench_function(
                        &format!(
                            "{name}/msg_len={data_length} chunks={chunks} conc={conc} shard_selection={sel}"
                        ),
                        |b| {
                            b.iter_batched(
                                || {
                                    let mut data = vec![0u8; data_length];
                                    rng.fill_bytes(&mut data);

                                    let (commitment, mut shards) = if conc > 1 {
                                        S::encode(&config, data.as_slice(), &strategy).unwrap()
                                    } else {
                                        S::encode(&config, data.as_slice(), &Sequential).unwrap()
                                    };

                                    let my_shard = shards.pop().unwrap();
                                    let indices = selection.indices(min);
                                    let mut opt_shards: Vec<Option<_>> =
                                        shards.into_iter().map(Some).collect();
                                    let weak_shards: Vec<(u16, _)> = indices
                                        .iter()
                                        .map(|&i| {
                                            let shard = opt_shards[i as usize].take().unwrap();
                                            let (_, _, weak_shard) =
                                                S::weaken(&config, &commitment, i, shard).unwrap();
                                            (i, weak_shard)
                                        })
                                        .collect();

                                    let my_index =
                                        config.minimum_shards.get() + config.extra_shards.get() - 1;
                                    let (checking_data, my_checked_shard, _) =
                                        S::weaken(&config, &commitment, my_index, my_shard)
                                            .unwrap();

                                    (commitment, checking_data, my_checked_shard, weak_shards)
                                },
                                |(commitment, checking_data, my_checked_shard, weak_shards)| {
                                    let mut checked_shards = weak_shards
                                        .into_iter()
                                        .map(|(idx, weak_shard)| {
                                            S::check(
                                                &config,
                                                &commitment,
                                                &checking_data,
                                                idx,
                                                weak_shard,
                                            )
                                            .unwrap()
                                        })
                                        .collect::<Vec<_>>();
                                    checked_shards.push(my_checked_shard);

                                    if conc > 1 {
                                        S::decode(
                                            &config,
                                            &commitment,
                                            checking_data,
                                            checked_shards.iter(),
                                            &strategy,
                                        )
                                        .unwrap()
                                    } else {
                                        S::decode(
                                            &config,
                                            &commitment,
                                            checking_data,
                                            checked_shards.iter(),
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
}

criterion_main!(zoda_phased::benches);
