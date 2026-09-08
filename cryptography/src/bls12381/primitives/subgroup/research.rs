//! Experimental sparse compression. No production caller uses this module.
//!
//! See `cryptography/SUBGROUP_RESEARCH.md` for the soundness argument and scope.

use super::*;
use commonware_math::algebra::{Additive, CryptoGroup};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use rand_core::Rng;
use std::time::{Duration, Instant};

#[path = "research/cycles.rs"]
mod cycles;
#[path = "research/effective.rs"]
mod effective;
#[path = "research/moments.rs"]
mod moments;
#[path = "research/pair.rs"]
mod pair;
#[path = "research/primary.rs"]
mod primary;
#[path = "research/three.rs"]
mod three;
#[path = "research/two.rs"]
mod two;

const BUCKETS: usize = 1 << 16;
const PASSES: usize = 4;

fn order_three() -> G1 {
    let one = G1::generator().as_blst_p1().z;
    G1::from_blst_p1(blst_p1 {
        x: blst_fp::default(),
        y: fp_add(&one, &one),
        z: one,
    })
}

// An on-curve order-eleven fixture, independently checked by descent_bound.py
// and the partial-filter regression.
fn order_eleven() -> G1 {
    let x = [
        0x19b3e2c8c6bbf59du64,
        0x3c326b531fc1e639,
        0xd29200c28624ac60,
        0x4f251a12908c9b7f,
        0x735318617f625954,
        0xcc71cdf03229b1ef,
    ];
    let mut encoded = [0u8; 48];
    for (word, bytes) in x.iter().zip(encoded.chunks_exact_mut(8)) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    encoded[0] |= 0x80;
    G1::read_unchecked(&mut encoded.as_slice()).expect("on-curve order-eleven fixture")
}

fn benchmark_points(n: usize) -> Vec<G1> {
    let generator = G1::generator();
    let one = generator.as_blst_p1().z;
    let mut point = generator;
    let projective: Vec<_> = (0..n)
        .map(|_| {
            point += &generator;
            point
        })
        .collect();
    to_affine(&projective)
        .into_iter()
        .map(|p| {
            G1::from_blst_p1(blst_p1 {
                x: p.x,
                y: p.y,
                z: one,
            })
        })
        .collect()
}

fn draw_distinct_codes(n: usize, mut draw: impl FnMut() -> u64) -> Vec<u64> {
    // Reject the entire assignment if any two unsigned columns coincide.
    let mut codes = vec![0u64; n];
    let mut sorted = vec![0u64; n];
    loop {
        for code in &mut codes {
            *code = draw();
        }
        sorted.copy_from_slice(&codes);
        sorted.sort_unstable();
        if sorted.windows(2).all(|pair| pair[0] != pair[1]) {
            return codes;
        }
    }
}

fn draw_ids(n: usize, rng: &mut impl CryptoRng) -> [Vec<u32>; PASSES] {
    let codes = draw_distinct_codes(n, || rng.next_u64());
    let mut ids: [Vec<u32>; PASSES] = core::array::from_fn(|_| Vec::with_capacity(n));
    for code in codes {
        let signs = rng.next_u32();
        for (pass, ids) in ids.iter_mut().enumerate() {
            let bucket = ((code >> (16 * pass)) & 0xffff) as u32;
            ids.push(bucket | (((signs >> pass) & 1) * ID_NEGATE));
        }
    }
    ids
}

#[test]
fn duplicate_signature_redraws_entire_assignment() {
    let mut words = [7, 7, 99, 2, 3, 4].into_iter();
    let codes = draw_distinct_codes(3, || words.next().expect("scripted assignment"));
    assert_eq!(codes, [2, 3, 4]);
    assert!(words.next().is_none());
}

fn compress(affine: &[blst_p1_affine], ids: &[Vec<u32>; PASSES]) -> Vec<G1> {
    let mut round = Round::new(11);
    round.widen(11);
    let mut sums = Vec::with_capacity(PASSES * BUCKETS);
    for ids in ids {
        sums.extend(compress_round(&mut round, affine, ids));
    }
    sums
}

fn compress_round(round: &mut Round, affine: &[blst_p1_affine], ids: &[u32]) -> Vec<G1> {
    compress_round_with_buckets(round, affine, ids, BUCKETS)
}

fn compress_round_with_buckets(
    round: &mut Round,
    affine: &[blst_p1_affine],
    ids: &[u32],
    buckets: usize,
) -> Vec<G1> {
    let mut sums = Vec::with_capacity(buckets);
    let one = G1::generator().as_blst_p1().z;
    round.accumulate(affine, ids);
    for (point, &live) in round.sums[..buckets].iter().zip(&round.live) {
        if live {
            sums.push(G1::from_blst_p1(blst_p1 {
                x: point.x,
                y: point.y,
                z: one,
            }));
        }
    }
    sums
}

fn sparse_check(points: &[G1], rng: &mut impl CryptoRng) -> (bool, [Duration; 4]) {
    assert!(points.len() <= 3_000_000);
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    let start = Instant::now();
    let ids = draw_ids(affine.len(), rng);
    let sampled = start.elapsed();
    let start = Instant::now();
    let sums = compress(&affine, &ids);
    let compressed = start.elapsed();
    let start = Instant::now();
    let valid = batch_in_g1(&sums, 129, &Sequential, rng);
    (valid, [normalized, sampled, compressed, start.elapsed()])
}

fn sparse_check_separate(points: &[G1], rng: &mut impl CryptoRng) -> (bool, [Duration; 4]) {
    assert!(points.len() <= 3_000_000);
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    let start = Instant::now();
    let ids = draw_ids(affine.len(), rng);
    let sampled = start.elapsed();
    let mut round = Round::new(11);
    round.widen(11);
    let mut compressed = Duration::ZERO;
    let mut checked = Duration::ZERO;
    for ids in ids {
        let start = Instant::now();
        let sums = compress_round(&mut round, &affine, &ids);
        compressed += start.elapsed();
        let start = Instant::now();
        let valid = batch_in_g1(&sums, 80, &Sequential, rng);
        checked += start.elapsed();
        if !valid {
            return (false, [normalized, sampled, compressed, checked]);
        }
    }
    (true, [normalized, sampled, compressed, checked])
}

#[test]
fn compression_matches_direct_sums() {
    let mut rng = test_rng();
    let generator = G1::generator();
    let bad = order_three();
    assert!(!bad.in_subgroup());
    assert_eq!(bad + &bad + &bad, G1::zero());
    let points: Vec<G1> = (0..96)
        .map(|i| match i % 5 {
            0 => G1::zero(),
            1 => generator,
            2 => bad,
            3 => -bad,
            _ => -generator,
        })
        .collect();
    let points: Vec<_> = points.into_iter().filter(|p| *p != G1::zero()).collect();
    let mut ids = draw_ids(points.len(), &mut rng);
    // Deliberate contention covers cancellations and doubling as well as signs.
    for ids in &mut ids {
        for id in ids {
            *id = (*id & ID_NEGATE) | (*id % 8);
        }
    }
    let mut expected = Vec::new();
    for ids in &ids {
        let mut sums = [G1::zero(); 8];
        for (point, &id) in points.iter().zip(ids) {
            let bucket = (id & !ID_NEGATE) as usize;
            if id & ID_NEGATE != 0 {
                sums[bucket] -= point;
            } else {
                sums[bucket] += point;
            }
        }
        expected.extend(sums.into_iter().filter(|p| *p != G1::zero()));
    }
    assert_eq!(compress(&to_affine(&points), &ids), expected);
}

#[test]
fn four_input_concentration_small_groups() {
    // Enumerate every nonzero input quadruple and every signed assignment to
    // two buckets. The maximum atom is 3/(4*2^2) - 3/(8*2^3) = 36/256.
    for order in [3usize, 5, 9, 11] {
        let mut worst = 0;
        for mut inputs in 0..(order - 1).pow(4) {
            let mut values = [0; 4];
            for value in &mut values {
                *value = inputs % (order - 1) + 1;
                inputs /= order - 1;
            }
            let mut counts = vec![0; order * order];
            for mut assignment in 0usize..256 {
                let mut sum = [0; 2];
                for value in values {
                    let bucket = assignment & 1;
                    let signed = if assignment & 2 == 0 {
                        value
                    } else {
                        order - value
                    };
                    sum[bucket] = (sum[bucket] + signed) % order;
                    assignment >>= 2;
                }
                counts[sum[0] + order * sum[1]] += 1;
            }
            worst = worst.max(*counts.iter().max().unwrap());
        }
        assert_eq!(worst, 36);
    }
}

#[test]
fn sparse_check_adversarial_batches() {
    let generator = G1::generator();
    let bad = order_three();
    for count in [0, 1, 2, 3, 4, 6, 32] {
        let mut points = vec![generator; 1000];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(
            sparse_check_separate(&points, &mut test_rng()).0,
            count == 0
        );
    }
}

#[test]
fn five_column_stopping_sets_contain_four() {
    // Five distinct columns of a three-part stopping set occupy at most two
    // buckets per part. Relabel those buckets 0/1 and enumerate the 8 columns.
    for mask in 0u32..256 {
        if mask.count_ones() != 5 {
            continue;
        }
        let stopping = |set: u32, size: u32| {
            (0..3).all(|part| {
                let ones = (0..8)
                    .filter(|&column| set & (1 << column) != 0 && column & (1 << part) != 0)
                    .count() as u32;
                ones != 1 && ones != size - 1
            })
        };
        if stopping(mask, 5) {
            assert!(
                (0..8).any(|column| mask & (1 << column) != 0 && stopping(mask ^ (1 << column), 4))
            );
        }
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_small_stopping_certificate() {
    const MASK: u64 = (1 << 15) - 1;
    for n in [1_000_000usize, 3_000_000] {
        let mut rng = test_rng();
        let start = Instant::now();
        let mut codes: Vec<_> = (0..n).map(|_| rng.next_u64() & ((1 << 45) - 1)).collect();
        codes.sort_unstable();
        let duplicates = codes.windows(2).any(|pair| pair[0] == pair[1]);
        let drawn = start.elapsed();
        let start = Instant::now();
        let mut pairs = Vec::with_capacity(n * n / (2 * (1 << 15)) + n);
        let mut first = 0;
        while first < codes.len() {
            let end =
                first + codes[first..].partition_point(|code| code >> 30 == codes[first] >> 30);
            for i in first..end {
                for j in i + 1..end {
                    let mut key = 0;
                    for shift in [15, 0] {
                        let a = (codes[i] >> shift) & MASK;
                        let b = (codes[j] >> shift) & MASK;
                        let component = if a == b {
                            0
                        } else {
                            (a.min(b) << 15) | a.max(b)
                        };
                        key = (key << 30) | component;
                    }
                    pairs.push(key);
                }
            }
            first = end;
        }
        let built = start.elapsed();
        let start = Instant::now();
        pairs.sort_unstable();
        let stopping_four = pairs.windows(2).any(|pair| pair[0] == pair[1]);
        let sorted = start.elapsed();
        eprintln!(
            "{}::measure_small_stopping_certificate/n={n} pairs={} bytes={} draw={drawn:?} build={built:?} sort={sorted:?} duplicates={duplicates} stopping_four={stopping_four}",
            module_path!(),
            pairs.len(),
            pairs.len() * size_of::<u64>()
        );
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_sparse_compression() {
    let points = benchmark_points(3_000_000);
    for n in [100_000, 1_000_000, 3_000_000] {
        for repeat in 0..3 {
            let mut rng = test_rng();
            let start = Instant::now();
            assert!(batch_in_g1(&points[..n], 128, &Sequential, &mut rng));
            let baseline = start.elapsed();
            let start = Instant::now();
            let (valid, phases) = sparse_check(&points[..n], &mut rng);
            assert!(valid);
            let sparse = start.elapsed();
            eprintln!(
                "{}::measure_sparse_compression/n={n} repeat={repeat} variant=joint baseline={baseline:?} sparse={sparse:?} speedup={:.3} phases={phases:?}",
                module_path!(),
                baseline.as_secs_f64() / sparse.as_secs_f64()
            );
            let start = Instant::now();
            let (valid, phases) = sparse_check_separate(&points[..n], &mut rng);
            assert!(valid);
            let separate = start.elapsed();
            eprintln!(
                "{}::measure_sparse_compression/n={n} repeat={repeat} variant=separate separate={separate:?} speedup={:.3} phases={phases:?}",
                module_path!(),
                baseline.as_secs_f64() / separate.as_secs_f64()
            );
        }
    }
}
