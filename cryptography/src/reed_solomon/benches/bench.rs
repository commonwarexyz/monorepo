//! Benchmarks for the Reed-Solomon encoder, decoder, rates, and engines.

#[cfg(target_arch = "aarch64")]
use commonware_cryptography::reed_solomon::engine::Neon;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use commonware_cryptography::reed_solomon::engine::{Avx2, Avx512, Ssse3};
use commonware_cryptography::reed_solomon::{
    Decoder, Encoder, SHARD_CHUNK_BYTES,
    engine::{DefaultEngine, Engine, GF_ORDER, Naive, Scalar, ShardsRefMut},
    rate::{
        HighRateDecoder, HighRateEncoder, LowRateDecoder, LowRateEncoder, RateDecoder, RateEncoder,
    },
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::{Rng, RngExt as _, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::hint::black_box;

/// Shard size in bytes used by every benchmark.
const SHARD_BYTES: usize = 1024;

/// Returns `shard_count` shards of `chunk_count` random `SHARD_CHUNK_BYTES`-byte chunks each.
///
/// The bytes come from a `ChaCha8Rng` seeded with `[seed; 32]`, so the output is deterministic.
fn generate_shard_chunks(
    shard_count: usize,
    chunk_count: usize,
    seed: u8,
) -> Vec<Vec<[u8; SHARD_CHUNK_BYTES]>> {
    let mut rng = ChaCha8Rng::from_seed([seed; 32]);
    let mut shards = vec![vec![[0u8; SHARD_CHUNK_BYTES]; chunk_count]; shard_count];
    for shard in &mut shards {
        rng.fill_bytes(shard.as_flattened_mut());
    }
    shards
}

/// Returns `shard_count` random shards of `shard_bytes` bytes each, as [`generate_shard_chunks`]
/// flattened.
///
/// # Panics
///
/// Panics if `shard_bytes` is not a multiple of `SHARD_CHUNK_BYTES`.
fn generate_shards(shard_count: usize, shard_bytes: usize, seed: u8) -> Vec<Vec<u8>> {
    assert_eq!(shard_bytes % SHARD_CHUNK_BYTES, 0);
    generate_shard_chunks(shard_count, shard_bytes / SHARD_CHUNK_BYTES, seed)
        .into_iter()
        .map(|s| s.into_flattened())
        .collect()
}

/// Returns the recovery shards for `original`, encoded with the default [`Encoder`].
///
/// Each shard in `original` must be `SHARD_BYTES` long.
fn encode_recovery(
    original_count: usize,
    recovery_count: usize,
    original: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut encoder = Encoder::new(original_count, recovery_count, SHARD_BYTES).unwrap();
    for shard in original {
        encoder.add_original_shard(shard).unwrap();
    }

    encoder
        .encode()
        .unwrap()
        .recovery_iter()
        .map(<[u8]>::to_vec)
        .collect()
}

/// Benchmarks the default [`Encoder`] and [`Decoder`] over a fixed set of shard counts.
///
/// Decoding runs at 1% and 100% loss. A loss of N% drops N% of
/// `min(original_count, recovery_count)` originals, rounded up, and replaces each with a
/// recovery shard.
fn benchmarks_main(c: &mut Criterion) {
    let cases = [
        // Powers of two with equal original and recovery counts.
        (32, 32),
        (64, 64),
        (128, 128),
        (256, 256),
        (512, 512),
        (1024, 1024),
        (2048, 2048),
        (4096, 4096),
        (8192, 8192),
        (16384, 16384),
        (32768, 32768),
        // Unequal counts and counts that are not powers of two.
        (128, 1024),
        (1000, 100),
        (1000, 10000),
        (1024, 128),
        (1024, 8192),
        (8192, 1024),
        (8192, 16384),
        (8192, 57344),
        (10000, 1000),
        (16384, 8192),
        (16385, 16385), // 2^n + 1
        (57344, 8192),
    ];

    {
        let mut group = c.benchmark_group("reed_solomon::encoder");

        for (original_count, recovery_count) in cases {
            let sample_size = if original_count >= 1000 && recovery_count >= 1000 {
                10
            } else {
                100
            };
            group.sample_size(sample_size);

            let original = generate_shards(original_count, SHARD_BYTES, 0);
            group.throughput(Throughput::Bytes(
                ((original_count + recovery_count) * SHARD_BYTES) as u64,
            ));

            let mut encoder = Encoder::new(original_count, recovery_count, SHARD_BYTES).unwrap();

            let id = format!(
                "original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES}"
            );

            group.bench_with_input(BenchmarkId::from_parameter(id), &original, |b, original| {
                b.iter(|| {
                    for original in original {
                        encoder.add_original_shard(original).unwrap();
                    }
                    encoder.encode().unwrap();
                });
            });
        }

        group.finish();
    }

    {
        let mut group = c.benchmark_group("reed_solomon::decoder");

        for (original_count, recovery_count) in cases {
            let sample_size = if original_count >= 1000 && recovery_count >= 1000 {
                10
            } else {
                100
            };
            group.sample_size(sample_size);

            let original = generate_shards(original_count, SHARD_BYTES, 0);
            let recovery = encode_recovery(original_count, recovery_count, &original);
            let max_original_loss_count = std::cmp::min(original_count, recovery_count);

            for loss_percent in [1, 100] {
                // Round up so at least one shard is lost for low shard counts.
                let original_loss_count = (max_original_loss_count * loss_percent).div_ceil(100);
                let original_provided_count = original_count - original_loss_count;
                let recovery_provided_count = original_loss_count;

                let mut decoder =
                    Decoder::new(original_count, recovery_count, SHARD_BYTES).unwrap();

                let id = format!(
                    "original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES} loss={loss_percent}"
                );

                group.throughput(Throughput::Bytes(
                    ((original_count + recovery_count) * SHARD_BYTES) as u64,
                ));
                group.bench_with_input(
                    BenchmarkId::from_parameter(id),
                    &recovery,
                    |b, recovery| {
                        b.iter(|| {
                            for (index, shard) in
                                original.iter().enumerate().take(original_provided_count)
                            {
                                decoder.add_original_shard(index, shard).unwrap();
                            }
                            for (index, shard) in
                                recovery.iter().enumerate().take(recovery_provided_count)
                            {
                                decoder.add_recovery_shard(index, shard).unwrap();
                            }
                            decoder.decode().unwrap();
                        });
                    },
                );
            }
        }

        group.finish();
    }
}

/// Benchmarks the high and low rate encoders and decoders with `DefaultEngine`.
fn benchmarks_rate(c: &mut Criterion) {
    benchmarks_rate_one(c, "rate", DefaultEngine::new);
}

/// Benchmarks the high and low rate encoders and decoders with engines from `new_engine`,
/// labeling each benchmark with `name`.
///
/// Each decoder benchmark loses `min(original_count, recovery_count)` originals and replaces
/// each with a recovery shard from [`encode_recovery`].
fn benchmarks_rate_one<E: Engine>(c: &mut Criterion, name: &str, new_engine: fn() -> E) {
    let cases = [
        (1024, 1024),
        (1024, 1025),
        (1025, 1024),
        (1024, 2048),
        (2048, 1024),
        (1025, 1025),
        (1025, 2048),
        (2048, 1025),
        (2048, 2048),
    ];

    {
        let mut group = c.benchmark_group("reed_solomon::high_rate_encoder");
        group.sample_size(10);

        for (original_count, recovery_count) in cases {
            let original = generate_shards(original_count, SHARD_BYTES, 0);
            group.throughput(Throughput::Bytes(
                ((original_count + recovery_count) * SHARD_BYTES) as u64,
            ));
            let id = format!(
                "rate={name} original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES}"
            );
            let mut encoder = HighRateEncoder::new(
                original_count,
                recovery_count,
                SHARD_BYTES,
                new_engine(),
                None,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::from_parameter(id), &original, |b, original| {
                b.iter(|| {
                    for original in original {
                        encoder.add_original_shard(original).unwrap();
                    }
                    encoder.encode().unwrap();
                });
            });
        }

        group.finish();
    }

    {
        let mut group = c.benchmark_group("reed_solomon::low_rate_encoder");
        group.sample_size(10);

        for (original_count, recovery_count) in cases {
            let original = generate_shards(original_count, SHARD_BYTES, 0);
            group.throughput(Throughput::Bytes(
                ((original_count + recovery_count) * SHARD_BYTES) as u64,
            ));
            let id = format!(
                "rate={name} original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES}"
            );
            let mut encoder = LowRateEncoder::new(
                original_count,
                recovery_count,
                SHARD_BYTES,
                new_engine(),
                None,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::from_parameter(id), &original, |b, original| {
                b.iter(|| {
                    for original in original {
                        encoder.add_original_shard(original).unwrap();
                    }
                    encoder.encode().unwrap();
                });
            });
        }

        group.finish();
    }

    {
        let mut group = c.benchmark_group("reed_solomon::high_rate_decoder");
        group.sample_size(10);

        for (original_count, recovery_count) in cases {
            let original = generate_shards(original_count, SHARD_BYTES, 0);
            let recovery = encode_recovery(original_count, recovery_count, &original);
            group.throughput(Throughput::Bytes(
                ((original_count + recovery_count) * SHARD_BYTES) as u64,
            ));
            let id = format!(
                "rate={name} original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES}"
            );
            let original_loss_count = std::cmp::min(original_count, recovery_count);
            let original_provided_count = original_count - original_loss_count;
            let recovery_provided_count = original_loss_count;
            let mut decoder = HighRateDecoder::new(
                original_count,
                recovery_count,
                SHARD_BYTES,
                new_engine(),
                None,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::from_parameter(id), &recovery, |b, recovery| {
                b.iter(|| {
                    for (index, shard) in original.iter().enumerate().take(original_provided_count)
                    {
                        decoder.add_original_shard(index, shard).unwrap();
                    }
                    for (index, shard) in recovery.iter().enumerate().take(recovery_provided_count)
                    {
                        decoder.add_recovery_shard(index, shard).unwrap();
                    }
                    decoder.decode(false).unwrap();
                });
            });
        }

        group.finish();
    }

    {
        let mut group = c.benchmark_group("reed_solomon::low_rate_decoder");
        group.sample_size(10);

        for (original_count, recovery_count) in cases {
            let original = generate_shards(original_count, SHARD_BYTES, 0);
            let recovery = encode_recovery(original_count, recovery_count, &original);
            group.throughput(Throughput::Bytes(
                ((original_count + recovery_count) * SHARD_BYTES) as u64,
            ));
            let id = format!(
                "rate={name} original={original_count} recovery={recovery_count} shard_bytes={SHARD_BYTES}"
            );
            let original_loss_count = std::cmp::min(original_count, recovery_count);
            let original_provided_count = original_count - original_loss_count;
            let recovery_provided_count = original_loss_count;
            let mut decoder = LowRateDecoder::new(
                original_count,
                recovery_count,
                SHARD_BYTES,
                new_engine(),
                None,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::from_parameter(id), &recovery, |b, recovery| {
                b.iter(|| {
                    for (index, shard) in original.iter().enumerate().take(original_provided_count)
                    {
                        decoder.add_original_shard(index, shard).unwrap();
                    }
                    for (index, shard) in recovery.iter().enumerate().take(recovery_provided_count)
                    {
                        decoder.add_recovery_shard(index, shard).unwrap();
                    }
                    decoder.decode(false).unwrap();
                });
            });
        }

        group.finish();
    }
}

/// Benchmarks every engine available on the target and detected at runtime.
fn benchmarks_engine(c: &mut Criterion) {
    benchmarks_engine_one(c, "naive", Naive::new());
    benchmarks_engine_one(c, "scalar", Scalar::new());

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("ssse3") {
            benchmarks_engine_one(c, "ssse3", Ssse3::new());
        }
        if is_x86_feature_detected!("avx2") {
            benchmarks_engine_one(c, "avx2", Avx2::new());
        }
        if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("gfni") {
            benchmarks_engine_one(c, "avx512", Avx512::new());
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            benchmarks_engine_one(c, "neon", Neon::new());
        }
    }
}

/// Benchmarks `eval_poly`, `mul`, and 128-shard `fft` and `ifft` for `engine`, labeling each
/// benchmark with `engine_name`.
fn benchmarks_engine_one<E: Engine>(c: &mut Criterion, engine_name: &str, engine: E) {
    let shard_chunk_count = SHARD_BYTES / SHARD_CHUNK_BYTES;

    let mut rng = ChaCha8Rng::from_seed([0; 32]);
    let mut data = [(); GF_ORDER].map(|_| rng.random());

    c.bench_function(
        &format!("reed_solomon::engine_eval_poly/engine={engine_name} elems={GF_ORDER}"),
        |b| b.iter(|| E::eval_poly(black_box(&mut data), GF_ORDER)),
    );

    c.bench_function(
        &format!(
            "reed_solomon::engine_eval_poly/engine={engine_name} elems={} mode=truncated",
            GF_ORDER / 8
        ),
        |b| b.iter(|| E::eval_poly(black_box(&mut data), GF_ORDER / 8)),
    );

    let mut x = generate_shard_chunks(1, shard_chunk_count, 0)
        .pop()
        .unwrap();

    c.bench_function(
        &format!("reed_solomon::engine_mul/engine={engine_name} shard_bytes={SHARD_BYTES}"),
        |b| b.iter(|| engine.mul(black_box(x.as_mut_slice()), black_box(12345))),
    );

    let shards_128_data = &mut generate_shard_chunks(1, 128 * shard_chunk_count, 0)[0];
    let mut shards_128 = ShardsRefMut::new(128, shard_chunk_count, shards_128_data.as_mut());

    c.bench_function(
        &format!("reed_solomon::engine_fft/engine={engine_name} shards=128"),
        |b| {
            b.iter(|| {
                engine.fft(
                    black_box(&mut shards_128),
                    black_box(0),
                    black_box(128),
                    black_box(128),
                    black_box(128),
                )
            })
        },
    );

    c.bench_function(
        &format!("reed_solomon::engine_ifft/engine={engine_name} shards=128"),
        |b| {
            b.iter(|| {
                engine.ifft(
                    black_box(&mut shards_128),
                    black_box(0),
                    black_box(128),
                    black_box(128),
                    black_box(128),
                )
            })
        },
    );
}

criterion_group!(benches_main, benchmarks_main);
criterion_group!(benches_rate, benchmarks_rate);
criterion_group!(benches_engine, benchmarks_engine);
criterion_main!(benches_main, benches_rate, benches_engine);
