//! Pairings with their own final exponentiations, compared with blst.
//!
//! One pairing uses one lane, so `n = 1` measures latency; larger `n` pair independent pairs,
//! filling every lane, as when verifying many signatures separately.

use super::utils::{blst_multi_pairing, pairs};
use commonware_cryptography_bls12381::{GT, pairing, pairings};
use criterion::{Criterion, Throughput, criterion_group};
use std::{hint::black_box, slice};

/// Pair counts.
const SIZES: [usize; 2] = [1, 16];

fn bench_pairing(c: &mut Criterion) {
    let mut group = c.benchmark_group(module_path!());
    let (all_pairs, all_blst_pairs) = pairs(SIZES[SIZES.len() - 1]);
    for n in SIZES {
        let (pairs, blst_pairs) = (&all_pairs[..n], &all_blst_pairs[..n]);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("impl=commonware n={n}"), |bencher| {
            if n == 1 {
                let (p, q) = pairs[0];
                bencher.iter(|| black_box(pairing(black_box(&p), black_box(&q))))
            } else {
                bencher.iter(|| {
                    let mut outputs = vec![GT::ONE; n];
                    pairings(black_box(pairs), &mut outputs);
                    black_box(outputs)
                })
            }
        });
        group.bench_function(format!("impl=blst n={n}"), |bencher| {
            bencher.iter(|| {
                let outputs: Vec<blst::blst_fp12> = black_box(blst_pairs)
                    .iter()
                    .map(|pair| blst_multi_pairing(slice::from_ref(pair)))
                    .collect();
                black_box(outputs)
            })
        });
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_pairing
}
