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

#[derive(Clone, Copy)]
pub(crate) enum ShardSelection {
    Best,
    Exception,
    Worst,
    Interleaved,
}

impl ShardSelection {
    const fn label(self) -> &'static str {
        match self {
            Self::Best => "best",
            Self::Exception => "exception",
            Self::Worst => "worst",
            Self::Interleaved => "interleaved",
        }
    }

    fn indices(self, min: u16) -> Vec<u16> {
        match self {
            Self::Best => (0..min).collect(),
            Self::Exception => (1..=min).collect(),
            Self::Worst => (min..min + min).collect(),
            Self::Interleaved => (0..min)
                .map(|i| {
                    let k = i / 2;
                    // Alternate between original shard indices [0, min) and
                    // recovery shard indices [min, 2 * min).
                    if i % 2 == 0 {
                        k
                    } else {
                        min + k
                    }
                })
                .collect(),
        }
    }
}

const SELECTIONS: [ShardSelection; 4] = [
    ShardSelection::Best,
    ShardSelection::Exception,
    ShardSelection::Worst,
    ShardSelection::Interleaved,
];

pub(crate) fn bench_decode_generic<S: Scheme>(name: &str, c: &mut Criterion) {
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

                                    (commitment, selected_shards)
                                },
                                |(commitment, selected_shards)| {
                                    let checked_shards = selected_shards
                                        .iter()
                                        .map(|(idx, shard)| {
                                            S::check(&config, &commitment, *idx, shard).unwrap()
                                        })
                                        .collect::<Vec<_>>();

                                    // Decode data
                                    if conc > 1 {
                                        S::decode(&config, &commitment, &checked_shards, &strategy)
                                            .unwrap()
                                    } else {
                                        S::decode(
                                            &config,
                                            &commitment,
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
}

criterion_main!(reed_solomon::benches, no_coding::benches, zoda::benches);
