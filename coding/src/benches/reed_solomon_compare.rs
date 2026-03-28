use commonware_coding::{Config, ReedSolomon, ReedSolomonGf8, Scheme};
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZU16, NZUsize};
use criterion::{criterion_group, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;

type Rs = ReedSolomon<Sha256>;
type RsGf8 = ReedSolomonGf8<Sha256>;

fn bench_encode(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let data_len = 1 << 20;
    for chunks in [10u16, 50] {
        for conc in [1usize, 8] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: NZU16!(min),
                extra_shards: NZU16!(chunks - min),
            };
            let strategy = Rayon::new(NZUsize!(conc)).unwrap();
            let mut data = vec![0u8; data_len];
            rng.fill_bytes(&mut data);

            c.bench_function(
                &format!("reed_solomon_compare::encode/backend=simd msg_len={data_len} chunks={chunks} conc={conc}"),
                |b| {
                    b.iter(|| {
                        if conc > 1 {
                            Rs::encode(&config, data.as_slice(), &strategy).unwrap()
                        } else {
                            Rs::encode(&config, data.as_slice(), &Sequential).unwrap()
                        }
                    });
                },
            );

            c.bench_function(
                &format!("reed_solomon_compare::encode/backend=gf8_isa_l msg_len={data_len} chunks={chunks} conc={conc}"),
                |b| {
                    b.iter(|| {
                        if conc > 1 {
                            RsGf8::encode(&config, data.as_slice(), &strategy).unwrap()
                        } else {
                            RsGf8::encode(&config, data.as_slice(), &Sequential).unwrap()
                        }
                    });
                },
            );
        }
    }
}

fn bench_decode(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(9);
    let data_len = 1 << 20;
    for chunks in [10u16, 50] {
        for conc in [1usize, 8] {
            let min = chunks / 3;
            let config = Config {
                minimum_shards: NZU16!(min),
                extra_shards: NZU16!(chunks - min),
            };
            let strategy = Rayon::new(NZUsize!(conc)).unwrap();
            let mut data = vec![0u8; data_len];
            rng.fill_bytes(&mut data);

            let (commitment_simd, shards_simd) = if conc > 1 {
                Rs::encode(&config, data.as_slice(), &strategy).unwrap()
            } else {
                Rs::encode(&config, data.as_slice(), &Sequential).unwrap()
            };
            let checked_simd: Vec<_> = (0..min)
                .map(|i| Rs::check(&config, &commitment_simd, i, &shards_simd[i as usize]).unwrap())
                .collect();

            let (commitment_gf8, shards_gf8) = if conc > 1 {
                RsGf8::encode(&config, data.as_slice(), &strategy).unwrap()
            } else {
                RsGf8::encode(&config, data.as_slice(), &Sequential).unwrap()
            };
            let checked_gf8: Vec<_> = (0..min)
                .map(|i| RsGf8::check(&config, &commitment_gf8, i, &shards_gf8[i as usize]).unwrap())
                .collect();

            c.bench_function(
                &format!("reed_solomon_compare::decode/backend=simd msg_len={data_len} chunks={chunks} conc={conc}"),
                |b| {
                    b.iter(|| {
                        if conc > 1 {
                            Rs::decode(&config, &commitment_simd, checked_simd.iter(), &strategy).unwrap()
                        } else {
                            Rs::decode(&config, &commitment_simd, checked_simd.iter(), &Sequential).unwrap()
                        }
                    });
                },
            );

            c.bench_function(
                &format!("reed_solomon_compare::decode/backend=gf8_isa_l msg_len={data_len} chunks={chunks} conc={conc}"),
                |b| {
                    b.iter(|| {
                        if conc > 1 {
                            RsGf8::decode(&config, &commitment_gf8, checked_gf8.iter(), &strategy).unwrap()
                        } else {
                            RsGf8::decode(&config, &commitment_gf8, checked_gf8.iter(), &Sequential).unwrap()
                        }
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_encode, bench_decode
}
