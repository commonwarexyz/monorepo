//! Exact stopping-set certification by joining projected bucket coordinates.

use super::*;
use commonware_utils::TestRng;

const BITS: u32 = 15;
const EMPTY_CELL: u64 = u64::MAX;
const REPEATED: u64 = 1 << 63;
const MIX: u64 = 0x9e3779b97f4a7c15;

struct Relation {
    cells: Vec<u64>,
    shift: u32,
    first_bits: u32,
    mask: u64,
    code_mask: u64,
}

impl Relation {
    fn new(codes: &[u64], first_bits: u32, bits: u32) -> Option<Self> {
        let size = (codes.len().max(1) * 2).next_power_of_two();
        let mut result = Self {
            cells: vec![EMPTY_CELL; size],
            shift: 64 - size.ilog2(),
            first_bits,
            mask: (1 << first_bits) - 1,
            code_mask: (1 << (first_bits + 2 * bits)) - 1,
        };
        for &code in codes {
            let key = code >> first_bits;
            let mut slot = result.index(key);
            let mut repeated = false;
            loop {
                let cell = &mut result.cells[slot];
                if *cell == EMPTY_CELL {
                    *cell = code | if repeated { REPEATED } else { 0 };
                    break;
                }
                if *cell & result.code_mask == code {
                    return None;
                }
                if (*cell & result.code_mask) >> first_bits == key {
                    *cell |= REPEATED;
                    repeated = true;
                }
                slot = (slot + 1) & (size - 1);
            }
        }
        Some(result)
    }

    fn index(&self, key: u64) -> usize {
        (key.wrapping_mul(MIX) >> self.shift) as usize
    }

    fn contains(&self, key: u64, a: u64) -> bool {
        let target = (key << self.first_bits) | a;
        let mut slot = self.index(key);
        loop {
            let cell = self.cells[slot];
            if cell == EMPTY_CELL {
                return false;
            }
            if cell & self.code_mask == target {
                return true;
            }
            slot = (slot + 1) & (self.cells.len() - 1);
        }
    }

    fn common_first(&self, first: u64, second: u64, excluded: Option<u64>) -> bool {
        let mut slot = self.index(first);
        loop {
            let cell = self.cells[slot];
            if cell == EMPTY_CELL {
                return false;
            }
            let a = cell & self.mask;
            if (cell & self.code_mask) >> self.first_bits == first
                && excluded != Some(a)
                && self.contains(second, a)
            {
                return true;
            }
            slot = (slot + 1) & (self.cells.len() - 1);
        }
    }
}

fn certificate(codes: &[u64], bits: u32) -> bool {
    certificate_shaped(codes, bits, bits)
}

fn certificate_shaped(codes: &[u64], first_bits: u32, bits: u32) -> bool {
    exception_codes(codes, first_bits, bits).is_empty()
}

fn exception_codes(codes: &[u64], first_bits: u32, bits: u32) -> Vec<u64> {
    let mut canonical = codes.to_vec();
    canonical.sort_unstable();
    let mut marked: Vec<_> = canonical
        .windows(2)
        .filter(|pair| pair[0] == pair[1])
        .map(|pair| pair[0])
        .collect();
    canonical.dedup();
    let codes = canonical.as_slice();
    let relation = Relation::new(codes, first_bits, bits).expect("canonical columns are distinct");
    let first_buckets = 1usize << first_bits;
    let first_mask = (first_buckets - 1) as u64;
    let mask = (1u64 << bits) - 1;
    // Folding coordinates creates false positives only. Exact joins decide
    // acceptance, so this filter changes neither the certificate nor its law.
    let filter_bits = bits.min(13);
    let filter_mask = (1u64 << filter_bits) - 1;
    let filter_index =
        |key: u64| (((key >> bits) & filter_mask) << filter_bits | (key & filter_mask)) as usize;
    let words = ((1usize << (2 * filter_bits)) / 64).max(1);
    let mut present = vec![0u64; words];
    let mut repeated = vec![0u64; words];
    for &cell in &relation.cells {
        if cell == EMPTY_CELL {
            continue;
        }
        let index = filter_index((cell & relation.code_mask) >> first_bits);
        present[index / 64] |= 1 << (index % 64);
        if cell & REPEATED != 0 {
            repeated[index / 64] |= 1 << (index % 64);
        }
    }
    let mut offsets = vec![0usize; first_buckets + 1];
    for &code in codes {
        offsets[(code & first_mask) as usize + 1] += 1;
    }
    for i in 1..offsets.len() {
        offsets[i] += offsets[i - 1];
    }
    let mut cursors = offsets[..first_buckets].to_vec();
    let mut grouped = vec![0u64; codes.len()];
    for &code in codes {
        let index = filter_index(code >> first_bits);
        let flagged = code
            | if repeated[index / 64] & (1 << (index % 64)) != 0 {
                REPEATED
            } else {
                0
            };
        let cursor = &mut cursors[(code & first_mask) as usize];
        grouped[*cursor] = flagged;
        *cursor += 1;
    }
    let mut same_b = Vec::new();
    let mut same_c = Vec::new();
    for a in 0..first_buckets {
        let group = &grouped[offsets[a]..offsets[a + 1]];
        for (i, &first) in group.iter().enumerate() {
            let bc1 = (first & relation.code_mask) >> first_bits;
            let (b1, c1) = (bc1 >> bits, bc1 & mask);
            for &second in &group[i + 1..] {
                let bc2 = (second & relation.code_mask) >> first_bits;
                if first & second & REPEATED != 0 && relation.common_first(bc1, bc2, Some(a as u64))
                {
                    marked.extend([first & relation.code_mask, second & relation.code_mask]);
                    continue;
                }
                let (b2, c2) = (bc2 >> bits, bc2 & mask);
                // An equal coordinate cancels from the pair's incidence
                // vector, so its value may differ in the matching pair.
                if b1 == b2 {
                    same_b.push((
                        (c1.min(c2) << bits) | c1.max(c2),
                        first & relation.code_mask,
                        second & relation.code_mask,
                    ));
                    continue;
                }
                if c1 == c2 {
                    same_c.push((
                        (b1.min(b2) << bits) | b1.max(b2),
                        first & relation.code_mask,
                        second & relation.code_mask,
                    ));
                    continue;
                }
                let crossed1 = (b1 << bits) | c2;
                let crossed2 = (b2 << bits) | c1;
                let index1 = filter_index(crossed1);
                if present[index1 / 64] & (1 << (index1 % 64)) == 0 {
                    continue;
                }
                let index2 = filter_index(crossed2);
                if present[index2 / 64] & (1 << (index2 % 64)) != 0
                    && relation.common_first(crossed1, crossed2, None)
                {
                    marked.extend([first & relation.code_mask, second & relation.code_mask]);
                }
            }
        }
    }
    for mut pairs in [same_b, same_c] {
        pairs.sort_unstable();
        let mut start = 0;
        while start < pairs.len() {
            let end = start + pairs[start..].partition_point(|pair| pair.0 == pairs[start].0);
            if end - start > 1 {
                for &(_, first, second) in &pairs[start..end] {
                    marked.extend([first, second]);
                }
            }
            start = end;
        }
    }
    marked.sort_unstable();
    marked.dedup();
    marked
}

fn draw_three_ids(
    n: usize,
    first_bits: u32,
    bits: u32,
    rng: &mut impl CryptoRng,
) -> ([Vec<u32>; 3], usize) {
    let code_mask = (1u64 << (first_bits + 2 * bits)) - 1;
    let mut codes = vec![0u64; n];
    let mut attempts = 0;
    loop {
        attempts += 1;
        for code in &mut codes {
            *code = rng.next_u64() & code_mask;
        }
        if certificate_shaped(&codes, first_bits, bits) {
            break;
        }
    }
    (codes_to_ids(&codes, first_bits, bits, rng), attempts)
}

fn codes_to_ids(
    codes: &[u64],
    first_bits: u32,
    bits: u32,
    rng: &mut impl CryptoRng,
) -> [Vec<u32>; 3] {
    let mut ids: [Vec<u32>; 3] = core::array::from_fn(|_| Vec::with_capacity(codes.len()));
    for &code in codes {
        let mut code = code;
        let signs = rng.next_u32();
        for (pass, ids) in ids.iter_mut().enumerate() {
            let width = if pass == 0 { first_bits } else { bits };
            let bucket = (code & ((1 << width) - 1)) as u32;
            code >>= width;
            ids.push(bucket | (((signs >> pass) & 1) * ID_NEGATE));
        }
    }
    ids
}

fn three_pass_check(
    points: &[G1],
    first_bits: u32,
    bits: u32,
    rng: &mut impl CryptoRng,
) -> (bool, [Duration; 4], usize) {
    assert!(points.len() <= 3_000_000);
    assert!(matches!((first_bits, bits), (15, 15) | (17, 14)));
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    let start = Instant::now();
    let (ids, attempts) = draw_three_ids(affine.len(), first_bits, bits, rng);
    let sampled = start.elapsed();
    let width = if first_bits > 16 { 12 } else { 11 };
    let mut round = Round::new(width);
    round.widen(width);
    let mut compressed = Duration::ZERO;
    let mut checked = Duration::ZERO;
    for (pass, ids) in ids.into_iter().enumerate() {
        let start = Instant::now();
        let buckets = 1 << if pass == 0 { first_bits } else { bits };
        let sums = compress_round_with_buckets(&mut round, &affine, &ids, buckets);
        compressed += start.elapsed();
        let start = Instant::now();
        let valid = batch_in_g1(&sums, 100, &Sequential, rng);
        checked += start.elapsed();
        if !valid {
            return (false, [normalized, sampled, compressed, checked], attempts);
        }
    }
    (true, [normalized, sampled, compressed, checked], attempts)
}

pub(super) fn three_pass_exceptions(
    points: &[G1],
    first_bits: u32,
    bits: u32,
    rng: &mut impl CryptoRng,
) -> (bool, [Duration; 4], usize) {
    assert!(points.len() <= 3_000_000);
    assert!(matches!((first_bits, bits), (15, 15) | (17, 14)));
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    let start = Instant::now();
    let code_mask = (1u64 << (first_bits + 2 * bits)) - 1;
    let codes: Vec<_> = (0..affine.len())
        .map(|_| rng.next_u64() & code_mask)
        .collect();
    let (ids, exceptions) = match checked_ids(&affine, &codes, first_bits, bits, rng) {
        Ok(result) => result,
        Err(exceptions) => {
            return (
                false,
                [normalized, start.elapsed(), Duration::ZERO, Duration::ZERO],
                exceptions,
            );
        }
    };
    let sampled = start.elapsed();
    let width = if first_bits > 16 { 12 } else { 11 };
    let mut round = Round::new(width);
    round.widen(width);
    let mut compressed = Duration::ZERO;
    let mut checked = Duration::ZERO;
    for (pass, ids) in ids.into_iter().enumerate() {
        let start = Instant::now();
        let buckets = 1 << if pass == 0 { first_bits } else { bits };
        let sums = compress_round_with_buckets(&mut round, &affine, &ids, buckets);
        compressed += start.elapsed();
        let start = Instant::now();
        let valid = batch_in_g1(&sums, 100, &Sequential, rng);
        checked += start.elapsed();
        if !valid {
            return (
                false,
                [normalized, sampled, compressed, checked],
                exceptions,
            );
        }
    }
    (true, [normalized, sampled, compressed, checked], exceptions)
}

fn checked_ids(
    affine: &[blst_p1_affine],
    codes: &[u64],
    first_bits: u32,
    bits: u32,
    rng: &mut impl CryptoRng,
) -> Result<([Vec<u32>; 3], usize), usize> {
    assert_eq!(affine.len(), codes.len());
    let marked = exception_codes(codes, first_bits, bits);
    let mut exceptions = 0;
    let one = G1::generator().as_blst_p1().z;
    for (point, code) in affine.iter().zip(codes) {
        if marked.binary_search(code).is_ok() {
            exceptions += 1;
            if !G1::from_blst_p1(blst_p1 {
                x: point.x,
                y: point.y,
                z: one,
            })
            .in_subgroup()
            {
                return Err(exceptions);
            }
        }
    }
    // Retain every input and its original iid column, including exact-checked
    // points. The proof uses the unconditioned distribution of these sums.
    Ok((codes_to_ids(codes, first_bits, bits, rng), exceptions))
}

#[test]
fn exact_exceptions_check_every_duplicate_copy() {
    let generator = G1::generator();
    let bad = order_three();
    let points = [G1::zero(), generator, generator + &bad, generator - &bad];
    let affine = to_affine(&points);
    let mut rng = test_rng();
    assert_eq!(checked_ids(&affine, &[0, 0, 0], 15, 15, &mut rng), Err(2));
    assert_eq!(
        rng.next_u64(),
        test_rng().next_u64(),
        "failure precedes sign sampling"
    );
    let affine = to_affine(&[generator; 3]);
    let (ids, checked) = checked_ids(&affine, &[0, 0, 0], 15, 15, &mut rng).unwrap();
    assert_eq!(checked, 3);
    assert!(
        ids.iter()
            .all(|pass| pass.len() == 3 && pass.iter().all(|id| id & !ID_NEGATE == 0))
    );
}

#[test]
fn exact_exceptions_reject_degenerate_cancellation() {
    let generator = G1::generator();
    let bad = order_three();
    let points = [
        generator + &bad,
        generator - &bad,
        generator - &bad,
        generator + &bad,
    ];
    let codes = [0, 4, 17, 21];
    for pass in 0..3 {
        let mut sums = [G1::zero(); 4];
        for (&code, point) in codes.iter().zip(&points) {
            sums[((code >> (2 * pass)) & 3) as usize] += point;
        }
        assert!(sums.iter().all(G1::in_subgroup));
    }
    let mut rng = test_rng();
    assert_eq!(
        checked_ids(&to_affine(&points), &codes, 2, 2, &mut rng),
        Err(1)
    );
    assert_eq!(rng.next_u64(), test_rng().next_u64());
}

#[test]
fn join_certificate_matches_small_stopping_sets() {
    let codes: Vec<_> = (0u64..64)
        .filter(|code| (0..3).all(|part| ((code >> (2 * part)) & 3) < 3))
        .collect();
    assert!(!certificate(&[0, 0], 2));
    for a in 0..codes.len() {
        for b in a + 1..codes.len() {
            for c in b + 1..codes.len() {
                for d in c + 1..codes.len() {
                    let set = [codes[a], codes[b], codes[c], codes[d]];
                    let stopping = (0..3).all(|part| {
                        (0..3).all(|bucket| {
                            set.iter()
                                .filter(|&&code| ((code >> (2 * part)) & 3) == bucket)
                                .count()
                                != 1
                        })
                    });
                    assert_eq!(certificate(&set, 2), !stopping, "{set:?}");
                }
            }
        }
    }
}

fn stopping_set(codes: &[u64], first_bits: u32, bits: u32) -> bool {
    let widths = [first_bits, bits, bits];
    let mut shift = 0;
    for width in widths {
        let mask = (1u64 << width) - 1;
        for &code in codes {
            let bucket = (code >> shift) & mask;
            if codes
                .iter()
                .filter(|&&other| (other >> shift) & mask == bucket)
                .count()
                == 1
            {
                return false;
            }
        }
        shift += width;
    }
    true
}

#[test]
fn exceptions_hit_every_small_stopping_set() {
    let mut rng = test_rng();
    for (first_bits, bits) in [(1, 1), (3, 1), (2, 2), (3, 2)] {
        let mask = (1u64 << (first_bits + 2 * bits)) - 1;
        for _ in 0..128 {
            let n = (rng.next_u32() as usize % 13) + 1;
            let codes: Vec<_> = (0..n).map(|_| rng.next_u64() & mask).collect();
            let marked = exception_codes(&codes, first_bits, bits);
            assert!(marked.iter().all(|code| codes.contains(code)));
            let mut canonical = codes.clone();
            canonical.sort_unstable();
            let mut needs_exception = false;
            for pair in canonical.windows(2).filter(|pair| pair[0] == pair[1]) {
                assert!(marked.contains(&pair[0]));
                needs_exception = true;
            }
            canonical.dedup();
            for i in 0..canonical.len() {
                for j in i + 1..canonical.len() {
                    for k in j + 1..canonical.len() {
                        for l in k + 1..canonical.len() {
                            let set = [canonical[i], canonical[j], canonical[k], canonical[l]];
                            if stopping_set(&set, first_bits, bits) {
                                needs_exception = true;
                                assert!(
                                    set.iter().any(|code| marked.contains(code)),
                                    "unhit {set:?} in {codes:?}"
                                );
                            }
                        }
                    }
                }
            }
            assert_eq!(!marked.is_empty(), needs_exception);
        }
    }
}

#[test]
fn projected_filter_false_positives_are_checked_exactly() {
    let encode = |a: u64, b: u64, c: u64| (((b << 14) | c) << 3) | a;
    let mut codes = vec![encode(0, 0, 0), encode(0, 8192, 8192), encode(1, 0, 8192)];
    assert!(exception_codes(&codes, 3, 14).is_empty());
    codes.push(encode(1, 8192, 0));
    assert!(!exception_codes(&codes, 3, 14).is_empty());
    // Equal-coordinate pairs match even when their erased values differ.
    assert!(!exception_codes(&[0, 4, 17, 21], 2, 2).is_empty());
}

#[test]
fn three_pass_checks_adversarial_inputs() {
    let generator = G1::generator();
    let bad = order_three();
    for count in [0, 1, 2, 3, 4, 5, 6, 32] {
        let mut points = vec![generator; 1000];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        for (first_bits, bits) in [(15, 15), (17, 14)] {
            assert_eq!(
                three_pass_check(&points, first_bits, bits, &mut test_rng()).0,
                count == 0
            );
            assert_eq!(
                three_pass_exceptions(&points, first_bits, bits, &mut test_rng()).0,
                count == 0
            );
        }
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_join_certificate() {
    for n in [1_000_000, 3_000_000] {
        let mut rng = test_rng();
        let codes: Vec<_> = (0..n).map(|_| rng.next_u64() & ((1 << 45) - 1)).collect();
        let start = Instant::now();
        let good = certificate(&codes, BITS);
        eprintln!(
            "{}::measure_join_certificate/n={n} elapsed={:?} good={good}",
            module_path!(),
            start.elapsed()
        );
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_three_pass() {
    let points = benchmark_points(3_000_000);
    for n in [1_000_000, 3_000_000] {
        for repeat in 0..4 {
            for algorithm in if repeat % 2 == 0 {
                [0, 1, 2, 3]
            } else {
                [3, 2, 1, 0]
            } {
                // Independent seeds across repetitions, with identical initial
                // streams for the two three-pass constructions within a pair.
                let mut rng = TestRng::new(repeat);
                let start = Instant::now();
                let shape = if n == 1_000_000 { (15, 15) } else { (17, 14) };
                let (valid, phases, count) = match algorithm {
                    0 => (
                        batch_in_g1(&points[..n], 128, &Sequential, &mut rng),
                        [Duration::ZERO; 4],
                        0,
                    ),
                    1 => {
                        let (valid, phases) = sparse_check_separate(&points[..n], &mut rng);
                        (valid, phases, 1)
                    }
                    2 => three_pass_check(&points[..n], shape.0, shape.1, &mut rng),
                    _ => three_pass_exceptions(&points[..n], shape.0, shape.1, &mut rng),
                };
                assert!(valid);
                eprintln!(
                    "{}::measure_three_pass/n={n} repeat={repeat} algorithm={algorithm} first_bits={} bits={} elapsed={:?} phases={phases:?} attempts_or_exceptions={count}",
                    module_path!(),
                    shape.0,
                    shape.1,
                    start.elapsed()
                );
            }
        }
    }
}
