use crate::{bench_decode_generic, bench_encode_generic};
use commonware_coding::{Config, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, NZU16};
use criterion::{criterion_group, BatchSize, Criterion, Throughput};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

type RS = ReedSolomon<Sha256>;

struct EncodeCase {
    field: &'static str,
    data_shards: u16,
    parity_shards: u16,
    shard_size: usize,
    sparse_data_len: Option<usize>,
}

impl EncodeCase {
    fn data_len(&self) -> usize {
        self.sparse_data_len
            .unwrap_or(usize::from(self.data_shards) * self.shard_size - 4)
    }

    fn total_bytes(&self) -> u64 {
        u64::from(self.data_shards + self.parity_shards) * self.shard_size as u64
    }

    const fn config(&self) -> Config {
        Config {
            minimum_shards: NZU16!(self.data_shards),
            extra_shards: NZU16!(self.parity_shards),
        }
    }

    fn label(&self, conc: usize) -> String {
        format!(
            "conc={conc} field={} data={} parity={} shard_size={}",
            self.field, self.data_shards, self.parity_shards, self.shard_size
        )
    }
}

fn bench_encode(c: &mut Criterion) {
    bench_encode_generic::<ReedSolomon<Sha256>>("reed_solomon::encode", c);
}

fn bench_decode(c: &mut Criterion) {
    bench_decode_generic::<ReedSolomon<Sha256>>("reed_solomon::decode", c);
}

fn bench_klauspost_encode(c: &mut Criterion) {
    let cases = [
        EncodeCase {
            field: "gf8",
            data_shards: 5,
            parity_shards: 2,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf8",
            data_shards: 8,
            parity_shards: 8,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf8",
            data_shards: 50,
            parity_shards: 20,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf8",
            data_shards: 128,
            parity_shards: 128,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf16",
            data_shards: 256,
            parity_shards: 256,
            shard_size: 64,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf16",
            data_shards: 512,
            parity_shards: 512,
            shard_size: 64,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf16_sparse",
            data_shards: 4096,
            parity_shards: 4096,
            shard_size: 2,
            sparse_data_len: Some(1024),
        },
    ];

    let mut rng = ChaCha8Rng::seed_from_u64(0);
    for case in cases {
        for conc in [1, 8] {
            let config = case.config();
            let strategy = Rayon::new(NZUsize!(conc)).unwrap();
            let mut group = c.benchmark_group("reed_solomon::klauspost_encode");
            group.throughput(Throughput::Bytes(case.total_bytes()));
            group.bench_function(case.label(conc), |b| {
                b.iter_batched(
                    || {
                        let mut data = vec![0u8; case.data_len()];
                        rng.fill_bytes(&mut data);
                        data
                    },
                    |data| {
                        if conc > 1 {
                            RS::encode(&config, data.as_slice(), &strategy).unwrap()
                        } else {
                            RS::encode(&config, data.as_slice(), &Sequential).unwrap()
                        }
                    },
                    BatchSize::SmallInput,
                );
            });
            group.finish();
        }
    }
}

fn bench_klauspost_decode(c: &mut Criterion) {
    let cases = [
        EncodeCase {
            field: "gf8",
            data_shards: 8,
            parity_shards: 8,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf8",
            data_shards: 50,
            parity_shards: 20,
            shard_size: 1024,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf16",
            data_shards: 256,
            parity_shards: 256,
            shard_size: 64,
            sparse_data_len: None,
        },
        EncodeCase {
            field: "gf16_sparse",
            data_shards: 4096,
            parity_shards: 4096,
            shard_size: 2,
            sparse_data_len: Some(1024),
        },
    ];

    let mut rng = ChaCha8Rng::seed_from_u64(0);
    for case in cases {
        for conc in [1, 8] {
            let config = case.config();
            let strategy = Rayon::new(NZUsize!(conc)).unwrap();
            let mut group = c.benchmark_group("reed_solomon::klauspost_decode");
            group.throughput(Throughput::Bytes(case.total_bytes()));
            group.bench_function(case.label(conc), |b| {
                b.iter_batched(
                    || {
                        let mut data = vec![0u8; case.data_len()];
                        rng.fill_bytes(&mut data);
                        let (commitment, shards) = if conc > 1 {
                            RS::encode(&config, data.as_slice(), &strategy).unwrap()
                        } else {
                            RS::encode(&config, data.as_slice(), &Sequential).unwrap()
                        };
                        let indices = (1..case.data_shards)
                            .chain(core::iter::once(case.data_shards))
                            .collect::<Vec<_>>();
                        let checked_shards = indices
                            .iter()
                            .map(|&idx| {
                                RS::check(&config, &commitment, idx, &shards[idx as usize]).unwrap()
                            })
                            .collect::<Vec<_>>();
                        (commitment, checked_shards)
                    },
                    |(commitment, checked_shards)| {
                        if conc > 1 {
                            RS::decode(&config, &commitment, checked_shards.iter(), &strategy)
                                .unwrap()
                        } else {
                            RS::decode(&config, &commitment, checked_shards.iter(), &Sequential)
                                .unwrap()
                        }
                    },
                    BatchSize::SmallInput,
                );
            });
            group.finish();
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode, bench_klauspost_encode, bench_klauspost_decode
}
