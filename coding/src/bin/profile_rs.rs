//! Profiling binary for Reed-Solomon encode/decode.
//!
//! Isolates engine encode time to identify bottlenecks.

use commonware_coding::{Config, Gf8, Gf16, ReedSolomon, ReedSolomon8, Scheme};
use commonware_coding::reed_solomon::Engine;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_utils::NZU16;
use std::hint::black_box;
use std::time::Instant;

const STRATEGY: Sequential = Sequential;

fn bench_engine_encode<V: Engine>(label: &str, k: usize, m: usize, data: &[u8], iters: usize) {
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

    let start = Instant::now();
    for _ in 0..iters {
        let result = V::encode(k, m, &refs).unwrap();
        black_box(&result);
    }
    let elapsed = start.elapsed();
    println!(
        "  {label} engine encode: {:.3} ms/iter ({iters} iters, shard_len={shard_len})",
        elapsed.as_secs_f64() * 1000.0 / iters as f64
    );
}

fn bench_engine_decode<V: Engine>(label: &str, k: usize, m: usize, data: &[u8], iters: usize) {
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
    let recovery_refs: Vec<(usize, &[u8])> = recovery.iter().enumerate().take(k).map(|(i, r)| (i, r.as_slice())).collect();

    // Warm up
    for _ in 0..5 {
        let _ = black_box(V::decode(k, m, shard_len, &[], &recovery_refs).unwrap());
    }

    let start = Instant::now();
    for _ in 0..iters {
        let result = V::decode(k, m, shard_len, &[], &recovery_refs).unwrap();
        black_box(&result);
    }
    let elapsed = start.elapsed();
    println!(
        "  {label} engine decode: {:.3} ms/iter",
        elapsed.as_secs_f64() * 1000.0 / iters as f64
    );
}

fn bench_full<S: Scheme>(label: &str, config: &Config, data: &[u8], iters: usize) {
    for _ in 0..5 {
        let _ = black_box(S::encode(config, data, &STRATEGY).unwrap());
    }
    let start = Instant::now();
    for _ in 0..iters {
        let result = S::encode(config, data, &STRATEGY).unwrap();
        black_box(&result);
    }
    let elapsed = start.elapsed();
    println!(
        "  {label} full encode: {:.3} ms/iter",
        elapsed.as_secs_f64() * 1000.0 / iters as f64
    );
}

fn bench_full_decode<S: Scheme>(label: &str, config: &Config, data: &[u8], iters: usize) {
    let min = config.minimum_shards.get();
    let (commitment, shards) = S::encode(config, data, &STRATEGY).unwrap();
    let my_shard = shards.last().unwrap().clone();
    let my_idx = min + config.extra_shards.get() - 1;
    let (checking_data, _, _) = S::weaken(config, &commitment, my_idx, my_shard).unwrap();
    let weak_shards: Vec<_> = shards.into_iter().enumerate().take(min as usize)
        .map(|(i, shard)| { let (_, _, weak) = S::weaken(config, &commitment, i as u16, shard).unwrap(); weak }).collect();

    for _ in 0..3 {
        let checked: Vec<_> = weak_shards.iter().enumerate()
            .map(|(i, ws)| S::check(config, &commitment, &checking_data, i as u16, ws.clone()).unwrap()).collect();
        let _ = black_box(S::decode(config, &commitment, checking_data.clone(), &checked, &STRATEGY).unwrap());
    }

    let start = Instant::now();
    for _ in 0..iters {
        let checked: Vec<_> = weak_shards.iter().enumerate()
            .map(|(i, ws)| S::check(config, &commitment, &checking_data, i as u16, ws.clone()).unwrap()).collect();
        let result = S::decode(config, &commitment, checking_data.clone(), &checked, &STRATEGY).unwrap();
        black_box(&result);
    }
    let elapsed = start.elapsed();
    println!(
        "  {label} full decode: {:.3} ms/iter",
        elapsed.as_secs_f64() * 1000.0 / iters as f64
    );
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
        println!("  alloc {m} x {shard_len}B vecs: {:.3} ms/iter\n",
            elapsed.as_secs_f64() * 1000.0 / iters as f64);
    }

    println!("Engine-only:");
    bench_engine_encode::<Gf16>("GF16", k, m, &data, iters);
    bench_engine_encode::<Gf8>("GF8 ", k, m, &data, iters);
    println!();
    bench_engine_decode::<Gf16>("GF16", k, m, &data, iters);
    bench_engine_decode::<Gf8>("GF8 ", k, m, &data, iters);
    println!();

    println!("Full pipeline:");
    bench_full::<ReedSolomon<Sha256>>("GF16", &config, &data, iters);
    bench_full::<ReedSolomon8<Sha256>>("GF8 ", &config, &data, iters);
    println!();
    bench_full_decode::<ReedSolomon<Sha256>>("GF16", &config, &data, iters);
    bench_full_decode::<ReedSolomon8<Sha256>>("GF8 ", &config, &data, iters);
}
