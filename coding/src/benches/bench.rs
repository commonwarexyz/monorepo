use commonware_coding::{Config, Scheme};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZU16, NZUsize};
use core::slice;
use criterion::{BatchSize, Criterion, criterion_main};
use rand::{Rng, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use shard_selection::{SELECTIONS, ShardSelection};

mod reed_solomon;
mod shard_selection;
mod zoda;

pub(crate) fn bench_encode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
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
                                // Generate random data
                                let mut data = vec![0u8; data_length];
                                rng.fill_bytes(&mut data);
                                data
                            },
                            |data| {
                                // Encode data
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

pub(crate) fn bench_decode_generic<S: Scheme>(
    name: &str,
    c: &mut Criterion,
    extra_cases: &[(usize, u16, usize, ShardSelection)],
) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let cases = [20, 22, 23].map(|i| {
        (
            2usize.pow(i),
            &[10u16, 25, 50, 100, 250][..],
            &[1usize, 8][..],
            &SELECTIONS[..],
        )
    });
    let extra_cases = extra_cases.iter().map(|(bytes, chunks, conc, selection)| {
        (
            *bytes,
            slice::from_ref(chunks),
            slice::from_ref(conc),
            slice::from_ref(selection),
        )
    });
    for (data_length, shard_counts, concs, selections) in cases.into_iter().chain(extra_cases) {
        for &chunks in shard_counts {
            for &conc in concs {
                // Consensus recovers from f + 1 shards, where f = (chunks - 1) / 3.
                let min = chunks.div_ceil(3);
                let config = Config {
                    minimum_shards: NZU16!(min),
                    extra_shards: NZU16!(chunks - min),
                };
                let strategy = Rayon::new(NZUsize!(conc)).unwrap();
                for &selection in selections {
                    let sel = selection.label();
                    c.bench_function(
                        &format!(
                            "{name}/msg_len={data_length} chunks={chunks} min_shards={min} conc={conc} shard_selection={sel}"
                        ),
                        |b| {
                            b.iter_batched(
                                || {
                                    // Generate random data
                                    let mut data = vec![0u8; data_length];
                                    rng.fill_bytes(&mut data);

                                    // Encode data
                                    let (commitment, shards) = if conc > 1 {
                                        S::encode(&config, data.as_slice(), &strategy).unwrap()
                                    } else {
                                        S::encode(&config, data.as_slice(), &Sequential).unwrap()
                                    };

                                    let indices = selection.indices(min);
                                    let selected_shards: Vec<(u16, _)> = indices
                                        .iter()
                                        .map(|&i| {
                                            (i, shards[i as usize].clone())
                                        })
                                        .collect();

                                    let checked_shards: Vec<_> = selected_shards
                                        .iter()
                                        .map(|(idx, shard)| {
                                            S::check(&config, &commitment, *idx, shard).unwrap()
                                        })
                                        .collect();

                                    (commitment, checked_shards)
                                },
                                |(commitment, checked_shards)| {
                                    // Decode data
                                    if conc > 1 {
                                        S::decode(
                                            &config,
                                            &commitment,
                                            checked_shards.iter(),
                                            &strategy,
                                        )
                                            .unwrap()
                                    } else {
                                        S::decode(
                                            &config,
                                            &commitment,
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

criterion_main!(reed_solomon::benches, zoda::benches);
