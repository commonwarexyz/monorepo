//! Micro-benchmarks that break down encode/decode into individual steps
//! (coding algorithm vs BMT construction) to identify the bottleneck.

use commonware_cryptography::{Hasher, Sha256};
use commonware_storage::bmt::Builder;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{RngCore, SeedableRng as _};
use rand_chacha::ChaCha8Rng;
use std::hint::black_box;

/// Prepare padded data (shared by both RS and Raptor).
fn make_padded(data: &[u8], k: usize) -> Vec<u8> {
    let prefixed_len = 4 + data.len();
    let symbol_len = prefixed_len.div_ceil(k);
    let padded_len = k * symbol_len;
    let mut padded = vec![0u8; padded_len];
    padded[..4].copy_from_slice(&(data.len() as u32).to_be_bytes());
    padded[4..4 + data.len()].copy_from_slice(data);
    padded
}

/// Benchmark just the coding step (no BMT).
fn bench_coding_only(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for data_length in [1 << 12, 1 << 16, 1 << 20] {
        for (total, min) in [(25u16, 8u16), (100, 33), (250, 83)] {
            let m = (total - min) as usize;
            let k = min as usize;

            let label = format!("msg_len={data_length} chunks={total}");

            // --- Reed-Solomon coding only ---
            c.bench_function(
                &format!("breakdown::rs_coding_only/{label}"),
                |b| {
                    b.iter(|| {
                        let mut data = vec![0u8; data_length];
                        rng.fill_bytes(&mut data);

                        let padded = make_padded(&data, k);
                        let shard_len = padded.len() / k;
                        // Ensure shard_len is even (RS requirement)
                        let shard_len = if shard_len % 2 == 0 {
                            shard_len
                        } else {
                            shard_len + 1
                        };

                        let mut shards: Vec<Vec<u8>> = padded.chunks(padded.len() / k).map(|c| {
                            let mut s = c.to_vec();
                            s.resize(shard_len, 0);
                            s
                        }).collect();

                        let mut encoder =
                            reed_solomon_simd::ReedSolomonEncoder::new(k, m, shard_len).unwrap();
                        for shard in &shards {
                            encoder.add_original_shard(shard).unwrap();
                        }
                        let encoding = encoder.encode().unwrap();
                        let recovery: Vec<Vec<u8>> =
                            encoding.recovery_iter().map(|s| s.to_vec()).collect();
                        shards.extend(recovery);
                        black_box(&shards);
                    });
                },
            );

            // --- Raptor coding only ---
            c.bench_function(
                &format!("breakdown::raptor_coding_only/{label}"),
                |b| {
                    b.iter(|| {
                        let mut data = vec![0u8; data_length];
                        rng.fill_bytes(&mut data);

                        let padded = make_padded(&data, k);
                        let (symbols, _actual_k) =
                            raptor_code::encode_source_block(&padded, k, m).unwrap();
                        black_box(&symbols);
                    });
                },
            );
        }
    }
}

/// Benchmark just the BMT steps (hashing + tree build + proof generation).
fn bench_bmt_only(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0);

    for data_length in [1 << 12, 1 << 16, 1 << 20] {
        for (total, min) in [(25u16, 8u16), (100, 33), (250, 83)] {
            let k = min as usize;
            let m = (total - min) as usize;
            let n = total as usize;
            let label = format!("msg_len={data_length} chunks={total}");

            // Pre-encode to get realistic shard data
            let mut data = vec![0u8; data_length];
            rng.fill_bytes(&mut data);
            let padded = make_padded(&data, k);
            let (symbols, _) =
                raptor_code::encode_source_block(&padded, k, m).unwrap();

            // --- Hash shards only ---
            c.bench_function(
                &format!("breakdown::bmt_hash_shards/{label}"),
                |b| {
                    b.iter(|| {
                        let hashes: Vec<_> = symbols
                            .iter()
                            .map(|shard| {
                                let mut hasher = Sha256::new();
                                hasher.update(shard);
                                hasher.finalize()
                            })
                            .collect();
                        black_box(&hashes);
                    });
                },
            );

            // --- Hash + build tree ---
            c.bench_function(
                &format!("breakdown::bmt_hash_and_build/{label}"),
                |b| {
                    b.iter(|| {
                        let mut builder = Builder::<Sha256>::new(n);
                        for shard in &symbols {
                            let mut hasher = Sha256::new();
                            hasher.update(shard);
                            builder.add(&hasher.finalize());
                        }
                        let tree = builder.build();
                        black_box(tree.root());
                    });
                },
            );

            // --- Hash + build + generate all proofs ---
            c.bench_function(
                &format!("breakdown::bmt_full/{label}"),
                |b| {
                    b.iter(|| {
                        let mut builder = Builder::<Sha256>::new(n);
                        for shard in &symbols {
                            let mut hasher = Sha256::new();
                            hasher.update(shard);
                            builder.add(&hasher.finalize());
                        }
                        let tree = builder.build();
                        let mut proofs = Vec::with_capacity(n);
                        for i in 0..n {
                            proofs.push(tree.proof(i as u32).unwrap());
                        }
                        black_box((tree.root(), proofs));
                    });
                },
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_coding_only, bench_bmt_only
}

criterion_main!(benches);
