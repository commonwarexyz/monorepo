//! Profiling binary for Reed-Solomon encode/decode.
//!
//! Isolates engine and full-pipeline stage costs, including concurrent decode
//! scenarios similar to marshal/coding workloads.

use commonware_coding::{Config, Engine, Gf16, Gf8, ReedSolomon, ReedSolomon8, Scheme};
use commonware_cryptography::Blake3;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::{NZU16, NZUsize};
use std::{hint::black_box, time::Instant};

const STRATEGY: Sequential = Sequential;
const CONCURRENT_DECODE_JOBS: usize = 4;

#[derive(Clone, Copy)]
enum DecodeSelection {
    OriginalsOnly,
    RecoveryOnly,
}

struct DecodeFixture<S: Scheme> {
    commitment: S::Commitment,
    checking_data: S::CheckingData,
    weak_shards: Vec<(u16, S::WeakShard)>,
    checked_shards: Vec<S::CheckedShard>,
}

fn time_iters_ms(iters: usize, mut f: impl FnMut()) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() * 1000.0 / iters as f64
}

fn build_decode_fixture<S: Scheme>(
    config: &Config,
    data: &[u8],
    selection: DecodeSelection,
) -> DecodeFixture<S> {
    let min = config.minimum_shards.get() as usize;
    let total = (config.minimum_shards.get() + config.extra_shards.get()) as usize;
    let (commitment, shards) = S::encode(config, data, &STRATEGY).unwrap();

    // Obtain checking_data from one valid strong shard.
    let checking_idx = total - 1;
    let (checking_data, _, _) = S::weaken(
        config,
        &commitment,
        checking_idx as u16,
        shards[checking_idx].clone(),
    )
    .unwrap();

    let mut selected = Vec::with_capacity(min);
    match selection {
        DecodeSelection::OriginalsOnly => {
            selected.extend(0..min);
        }
        DecodeSelection::RecoveryOnly => {
            selected.extend((min..total).take(min));
            if selected.len() < min {
                selected.extend((0..min - selected.len()).take(min));
            }
        }
    }

    let weak_shards: Vec<(u16, S::WeakShard)> = selected
        .into_iter()
        .map(|idx| {
            let (_, _, weak) =
                S::weaken(config, &commitment, idx as u16, shards[idx].clone()).unwrap();
            (idx as u16, weak)
        })
        .collect();

    let checked_shards: Vec<S::CheckedShard> = weak_shards
        .iter()
        .map(|(idx, weak)| {
            S::check(config, &commitment, &checking_data, *idx, weak.clone()).unwrap()
        })
        .collect();

    DecodeFixture {
        commitment,
        checking_data,
        weak_shards,
        checked_shards,
    }
}

fn bench_engine_encode<V: Engine>(
    label: &str,
    k: usize,
    m: usize,
    data: &[u8],
    iters: usize,
) -> f64 {
    let data_len = data.len();
    let prefixed_len = 4 + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);
    let align = V::SHARD_ALIGNMENT;
    if align > 1 {
        shard_len = shard_len.div_ceil(align) * align;
    }

    let mut padded = vec![0u8; k * shard_len];
    padded[..4].copy_from_slice(&(data_len as u32).to_be_bytes());
    padded[4..4 + data_len].copy_from_slice(data);
    let originals: Vec<Vec<u8>> = padded.chunks(shard_len).map(|c| c.to_vec()).collect();
    let refs: Vec<&[u8]> = originals.iter().map(|v| v.as_slice()).collect();

    // Warm up
    for _ in 0..5 {
        let _ = black_box(V::encode(k, m, &refs).unwrap());
    }

    let ms = time_iters_ms(iters, || {
        let result = V::encode(k, m, &refs).unwrap();
        black_box(&result);
    });
    println!(
        "  {label} engine encode: {:.3} ms/iter ({iters} iters, shard_len={shard_len})",
        ms
    );
    ms
}

fn bench_engine_decode<V: Engine>(
    label: &str,
    k: usize,
    m: usize,
    data: &[u8],
    iters: usize,
) -> f64 {
    let data_len = data.len();
    let prefixed_len = 4 + data_len;
    let mut shard_len = prefixed_len.div_ceil(k);
    let align = V::SHARD_ALIGNMENT;
    if align > 1 {
        shard_len = shard_len.div_ceil(align) * align;
    }

    let mut padded = vec![0u8; k * shard_len];
    padded[..4].copy_from_slice(&(data_len as u32).to_be_bytes());
    padded[4..4 + data_len].copy_from_slice(data);
    let originals: Vec<Vec<u8>> = padded.chunks(shard_len).map(|c| c.to_vec()).collect();
    let refs: Vec<&[u8]> = originals.iter().map(|v| v.as_slice()).collect();

    let recovery = V::encode(k, m, &refs).unwrap();
    let recovery_refs: Vec<(usize, &[u8])> = recovery
        .iter()
        .enumerate()
        .take(k)
        .map(|(i, r)| (i, r.as_slice()))
        .collect();

    // Warm up
    for _ in 0..5 {
        let _ = black_box(V::decode(k, m, shard_len, &[], &recovery_refs).unwrap());
    }

    let ms = time_iters_ms(iters, || {
        let result = V::decode(k, m, shard_len, &[], &recovery_refs).unwrap();
        black_box(&result);
    });
    println!("  {label} engine decode: {:.3} ms/iter", ms);
    ms
}

fn bench_full_encode<S: Scheme>(label: &str, config: &Config, data: &[u8], iters: usize) -> f64 {
    for _ in 0..5 {
        let _ = black_box(S::encode(config, data, &STRATEGY).unwrap());
    }
    let ms = time_iters_ms(iters, || {
        let result = S::encode(config, data, &STRATEGY).unwrap();
        black_box(&result);
    });
    println!("  {label} full encode: {:.3} ms/iter", ms);
    ms
}

fn bench_decode_check_serial<S: Scheme>(
    label: &str,
    config: &Config,
    fixture: &DecodeFixture<S>,
    iters: usize,
) -> f64 {
    let ms = time_iters_ms(iters, || {
        let checked: Vec<_> = fixture
            .weak_shards
            .iter()
            .map(|(idx, weak)| {
                S::check(
                    config,
                    &fixture.commitment,
                    &fixture.checking_data,
                    *idx,
                    weak.clone(),
                )
                .unwrap()
            })
            .collect();
        black_box(&checked);
    });
    println!("  {label} check(serial): {:.3} ms/iter", ms);
    ms
}

fn bench_decode_check_parallel<S: Scheme>(
    label: &str,
    config: &Config,
    fixture: &DecodeFixture<S>,
    workers: usize,
    iters: usize,
) -> f64 {
    let strategy = Rayon::new(NZUsize!(workers)).unwrap();
    let ms = time_iters_ms(iters, || {
        let (checked, blocked): (Vec<_>, Vec<_>) =
            strategy.map_partition_collect_vec(fixture.weak_shards.iter(), |(idx, weak)| {
                let checked = S::check(
                    config,
                    &fixture.commitment,
                    &fixture.checking_data,
                    *idx,
                    weak.clone(),
                );
                (idx, checked.ok())
            });
        black_box(&checked);
        black_box(&blocked);
    });
    println!(
        "  {label} check(parallel workers={workers}): {:.3} ms/iter",
        ms
    );
    ms
}

fn bench_decode_only<S: Scheme>(
    label: &str,
    config: &Config,
    fixture: &DecodeFixture<S>,
    strategy: &impl Strategy,
    iters: usize,
) -> f64 {
    for _ in 0..3 {
        let _ = black_box(
            S::decode(
                config,
                &fixture.commitment,
                fixture.checking_data.clone(),
                &fixture.checked_shards,
                strategy,
            )
            .unwrap(),
        );
    }

    let ms = time_iters_ms(iters, || {
        let result = S::decode(
            config,
            &fixture.commitment,
            fixture.checking_data.clone(),
            &fixture.checked_shards,
            strategy,
        )
        .unwrap();
        black_box(&result);
    });
    println!("  {label} decode-only: {:.3} ms/iter", ms);
    ms
}

fn bench_decode_full<S: Scheme>(
    label: &str,
    config: &Config,
    fixture: &DecodeFixture<S>,
    strategy: &impl Strategy,
    iters: usize,
) -> f64 {
    for _ in 0..3 {
        let checked: Vec<_> = fixture
            .weak_shards
            .iter()
            .map(|(idx, weak)| {
                S::check(
                    config,
                    &fixture.commitment,
                    &fixture.checking_data,
                    *idx,
                    weak.clone(),
                )
                .unwrap()
            })
            .collect();
        let _ = black_box(
            S::decode(
                config,
                &fixture.commitment,
                fixture.checking_data.clone(),
                &checked,
                strategy,
            )
            .unwrap(),
        );
    }

    let ms = time_iters_ms(iters, || {
        let checked: Vec<_> = fixture
            .weak_shards
            .iter()
            .map(|(idx, weak)| {
                S::check(
                    config,
                    &fixture.commitment,
                    &fixture.checking_data,
                    *idx,
                    weak.clone(),
                )
                .unwrap()
            })
            .collect();
        let result = S::decode(
            config,
            &fixture.commitment,
            fixture.checking_data.clone(),
            &checked,
            strategy,
        )
        .unwrap();
        black_box(&result);
    });
    println!("  {label} full decode(check+decode): {:.3} ms/iter", ms);
    ms
}

fn bench_decode_concurrent_ops<S: Scheme>(
    label: &str,
    config: &Config,
    fixture: &DecodeFixture<S>,
    jobs: usize,
    iters: usize,
) -> f64 {
    let outer = Rayon::new(NZUsize!(jobs)).unwrap();

    for _ in 0..2 {
        let outputs = outer.map_collect_vec(0..jobs, |_| {
            S::decode(
                config,
                &fixture.commitment,
                fixture.checking_data.clone(),
                &fixture.checked_shards,
                &STRATEGY,
            )
            .unwrap()
        });
        black_box(&outputs);
    }

    let ms_batch = time_iters_ms(iters, || {
        let outputs = outer.map_collect_vec(0..jobs, |_| {
            S::decode(
                config,
                &fixture.commitment,
                fixture.checking_data.clone(),
                &fixture.checked_shards,
                &STRATEGY,
            )
            .unwrap()
        });
        black_box(&outputs);
    });
    let ms_op = ms_batch / jobs as f64;
    println!(
        "  {label} concurrent decode ops(jobs={jobs}): {:.3} ms/batch ({:.3} ms/op)",
        ms_batch, ms_op
    );
    ms_op
}

fn main() {
    let config = Config {
        minimum_shards: NZU16!(33),
        extra_shards: NZU16!(67),
    };
    let k = 33usize;
    let m = 67usize;
    let data = vec![42u8; 4 * 1024 * 1024];
    let iters = 100;

    println!("=== 4MB / 100 shards (33+67), {iters} iterations ===\n");

    // Measure allocation cost of output vector
    let shard_len = (4 + data.len()).div_ceil(k);
    {
        let start = Instant::now();
        for _ in 0..iters {
            let result: Vec<Vec<u8>> = black_box(vec![vec![0u8; shard_len]; m]);
            black_box(&result);
        }
        let elapsed = start.elapsed();
        println!(
            "  alloc {m} x {shard_len}B vecs: {:.3} ms/iter\n",
            elapsed.as_secs_f64() * 1000.0 / iters as f64
        );
    }

    println!("Engine-only:");
    let gf16_engine_encode = bench_engine_encode::<Gf16>("GF16", k, m, &data, iters);
    let gf8_engine_encode = bench_engine_encode::<Gf8>("GF8 ", k, m, &data, iters);
    println!();
    let gf16_engine_decode = bench_engine_decode::<Gf16>("GF16", k, m, &data, iters);
    let gf8_engine_decode = bench_engine_decode::<Gf8>("GF8 ", k, m, &data, iters);
    println!();

    println!("Full pipeline encode (Blake3):");
    let gf16_full_encode = bench_full_encode::<ReedSolomon<Blake3>>("GF16", &config, &data, iters);
    let gf8_full_encode = bench_full_encode::<ReedSolomon8<Blake3>>("GF8 ", &config, &data, iters);
    println!();

    let decode_iters = 50;
    let fixture_easy_gf16 =
        build_decode_fixture::<ReedSolomon<Blake3>>(&config, &data, DecodeSelection::OriginalsOnly);
    let fixture_easy_gf8 = build_decode_fixture::<ReedSolomon8<Blake3>>(
        &config,
        &data,
        DecodeSelection::OriginalsOnly,
    );
    let fixture_hard_gf16 =
        build_decode_fixture::<ReedSolomon<Blake3>>(&config, &data, DecodeSelection::RecoveryOnly);
    let fixture_hard_gf8 =
        build_decode_fixture::<ReedSolomon8<Blake3>>(&config, &data, DecodeSelection::RecoveryOnly);

    println!(
        "Full pipeline decode stage breakdown (easy: originals-only, Blake3, {decode_iters} iters):"
    );
    let _ = bench_decode_check_serial::<ReedSolomon<Blake3>>(
        "GF16/easy",
        &config,
        &fixture_easy_gf16,
        decode_iters,
    );
    let _ = bench_decode_check_serial::<ReedSolomon8<Blake3>>(
        "GF8 /easy",
        &config,
        &fixture_easy_gf8,
        decode_iters,
    );
    let _ = bench_decode_check_parallel::<ReedSolomon<Blake3>>(
        "GF16/easy",
        &config,
        &fixture_easy_gf16,
        CONCURRENT_DECODE_JOBS,
        decode_iters,
    );
    let _ = bench_decode_check_parallel::<ReedSolomon8<Blake3>>(
        "GF8 /easy",
        &config,
        &fixture_easy_gf8,
        CONCURRENT_DECODE_JOBS,
        decode_iters,
    );
    let _ = bench_decode_only::<ReedSolomon<Blake3>>(
        "GF16/easy",
        &config,
        &fixture_easy_gf16,
        &STRATEGY,
        decode_iters,
    );
    let _ = bench_decode_only::<ReedSolomon8<Blake3>>(
        "GF8 /easy",
        &config,
        &fixture_easy_gf8,
        &STRATEGY,
        decode_iters,
    );
    let _ = bench_decode_full::<ReedSolomon<Blake3>>(
        "GF16/easy",
        &config,
        &fixture_easy_gf16,
        &STRATEGY,
        decode_iters,
    );
    let _ = bench_decode_full::<ReedSolomon8<Blake3>>(
        "GF8 /easy",
        &config,
        &fixture_easy_gf8,
        &STRATEGY,
        decode_iters,
    );
    println!();

    println!(
        "Full pipeline decode stage breakdown (hard: recovery-only, Blake3, {decode_iters} iters):"
    );
    let _ = bench_decode_check_serial::<ReedSolomon<Blake3>>(
        "GF16/hard",
        &config,
        &fixture_hard_gf16,
        decode_iters,
    );
    let _ = bench_decode_check_serial::<ReedSolomon8<Blake3>>(
        "GF8 /hard",
        &config,
        &fixture_hard_gf8,
        decode_iters,
    );
    let gf16_hard_decode_only = bench_decode_only::<ReedSolomon<Blake3>>(
        "GF16/hard",
        &config,
        &fixture_hard_gf16,
        &STRATEGY,
        decode_iters,
    );
    let gf8_hard_decode_only = bench_decode_only::<ReedSolomon8<Blake3>>(
        "GF8 /hard",
        &config,
        &fixture_hard_gf8,
        &STRATEGY,
        decode_iters,
    );
    let _ = bench_decode_full::<ReedSolomon<Blake3>>(
        "GF16/hard",
        &config,
        &fixture_hard_gf16,
        &STRATEGY,
        decode_iters,
    );
    let _ = bench_decode_full::<ReedSolomon8<Blake3>>(
        "GF8 /hard",
        &config,
        &fixture_hard_gf8,
        &STRATEGY,
        decode_iters,
    );
    println!();

    println!(
        "Concurrent decode ops (marshal-style pressure, jobs={CONCURRENT_DECODE_JOBS}, hard fixture):"
    );
    let gf16_concurrent_op = bench_decode_concurrent_ops::<ReedSolomon<Blake3>>(
        "GF16/hard",
        &config,
        &fixture_hard_gf16,
        CONCURRENT_DECODE_JOBS,
        decode_iters,
    );
    let gf8_concurrent_op = bench_decode_concurrent_ops::<ReedSolomon8<Blake3>>(
        "GF8 /hard",
        &config,
        &fixture_hard_gf8,
        CONCURRENT_DECODE_JOBS,
        decode_iters,
    );

    println!("\nSummary deltas:");
    println!(
        "  encode engine delta (GF16-GF8): {:.3} ms",
        gf16_engine_encode - gf8_engine_encode
    );
    println!(
        "  encode full delta   (GF16-GF8): {:.3} ms",
        gf16_full_encode - gf8_full_encode
    );
    println!(
        "  decode engine delta (GF16-GF8): {:.3} ms",
        gf16_engine_decode - gf8_engine_decode
    );
    println!(
        "  decode hard-only delta (GF16-GF8): {:.3} ms",
        gf16_hard_decode_only - gf8_hard_decode_only
    );
    println!(
        "  concurrent hard decode delta/op (GF16-GF8): {:.3} ms",
        gf16_concurrent_op - gf8_concurrent_op
    );
}
