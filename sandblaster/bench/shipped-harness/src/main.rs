//! The shipped-code harness binary (finish-A, task 4; the held-out harness's
//! protocol, `sandblaster/bench/heldout-harness`).
//!
//! Three subjects of ONE crate source (`subject/lib.rs`), linked into this
//! one binary:
//!
//! | subject | package | what |
//! | --- | --- | --- |
//! | original | `subj_orig` | the original Commonware code (the sandblaster branch's merge base) |
//! | A/A | `subj_aa` | the same code again: the control (its own copies, identical code) |
//! | shipped | `subj_shipped` | the code commonware-codec and commonware-storage compile from sandblaster's emitted and lowered copies |
//!
//! `shipped-bench check` runs the differential check (every subject agrees on
//! every input: generated inputs plus edge cases, each within the function's
//! documented preconditions) and must pass before `shipped-bench bench
//! [--rounds N] [--json PATH]` times anything: per function, N interleaved
//! rounds (the subject order rotates each round), each subject's per-round
//! value the median of 5 samples of about 200 microseconds, its reported value
//! the median of its per-round values (ns per call, one out-of-line call into
//! `probe::<fn>` per invocation).

use std::fmt::Debug;
use std::hint::black_box as bb;
use std::time::Instant;

/// xorshift64*, seeded per function by the FNV-1a hash of its name.
struct Rng(u64);

impl Rng {
    fn new(name: &str) -> Rng {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in name.bytes() {
            h = (h ^ b as u64).wrapping_mul(0x0100_0000_01b3);
        }
        Rng(h | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// Uniform bit length in 0..=bits, then a uniform value of that length.
    fn bits(&mut self, bits: u32) -> u64 {
        let b = self.below(bits as u64 + 1) as u32;
        if b == 0 { 0 } else { (self.next() >> (64 - b)) | (1u64 << (b - 1)) }
    }
    /// A signed value of uniform bit length in 0..=bits, either sign.
    fn signed(&mut self, bits: u32) -> i64 {
        let v = self.bits(bits) as i64;
        if self.below(2) == 0 { v } else { v.wrapping_neg() }
    }
    fn bytes(&mut self, max_len: u64) -> Vec<u8> {
        let n = self.below(max_len + 1) as usize;
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn b32(&mut self) -> [u8; 32] {
        let mut a = [0u8; 32];
        for x in a.iter_mut() {
            *x = self.next() as u8;
        }
        a
    }
}

const N: usize = 512;

fn inputs<T>(name: &str, edge: Vec<T>, mut f: impl FnMut(&mut Rng) -> T) -> Vec<T> {
    let mut r = Rng::new(name);
    let mut v = edge;
    while v.len() < N {
        v.push(f(&mut r));
    }
    v
}

/// LEB128 of `x` (the reference the read inputs are built from), then, one
/// time in eight, a corruption: truncated, an overlong zero byte, or a
/// continuation bit on the last byte.
fn leb(r: &mut Rng, x: u64) -> Vec<u8> {
    let mut v = Vec::new();
    let mut x = x;
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            v.push(b);
            break;
        }
        v.push(b | 0x80);
    }
    match r.below(16) {
        0 => {
            v.pop();
        }
        1 => {
            let l = v.len() - 1;
            v[l] |= 0x80;
            v.push(0);
        }
        2 => {
            let l = v.len() - 1;
            v[l] |= 0x80;
        }
        _ => {}
    }
    // trailing bytes the reader must leave
    for _ in 0..r.below(3) {
        v.push(r.next() as u8);
    }
    v
}

fn zigzag(x: i64) -> u64 {
    ((x << 1) ^ (x >> 63)) as u64
}

/// The MMR size of `n` leaves.
fn mmr_size(n: u64) -> u64 {
    2 * n - n.count_ones() as u64
}

trait Case {
    fn set(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn check(&self) -> Result<usize, String>;
    /// ns per call of subject `s` over `reps` passes of the inputs.
    fn time(&self, s: usize, reps: usize) -> f64;
}

struct Row<T, R, F0, F1, F2> {
    set: &'static str,
    name: &'static str,
    inputs: Vec<T>,
    f: (F0, F1, F2),
    _r: std::marker::PhantomData<R>,
}

impl<T: Debug, R: PartialEq + Debug, F0: Fn(&T) -> R, F1: Fn(&T) -> R, F2: Fn(&T) -> R> Row<T, R, F0, F1, F2> {
    fn new(set: &'static str, name: &'static str, inputs: Vec<T>, f0: F0, f1: F1, f2: F2) -> Self {
        Row { set, name, inputs, f: (f0, f1, f2), _r: std::marker::PhantomData }
    }
}

#[inline(never)]
fn run_loop<T, R, F: Fn(&T) -> R>(inputs: &[T], f: &F, reps: usize) -> f64 {
    let t = Instant::now();
    for _ in 0..reps {
        for x in inputs {
            bb(f(bb(x)));
        }
    }
    t.elapsed().as_nanos() as f64 / (reps * inputs.len()) as f64
}

impl<T: Debug, R: PartialEq + Debug, F0: Fn(&T) -> R, F1: Fn(&T) -> R, F2: Fn(&T) -> R> Case for Row<T, R, F0, F1, F2> {
    fn set(&self) -> &'static str {
        self.set
    }
    fn name(&self) -> &'static str {
        self.name
    }
    fn check(&self) -> Result<usize, String> {
        for x in &self.inputs {
            let (a, b, c) = ((self.f.0)(x), (self.f.1)(x), (self.f.2)(x));
            if a != b || a != c {
                return Err(format!("{}: input {:?}: original {:?}, A/A {:?}, shipped {:?}", self.name, x, a, b, c));
            }
        }
        Ok(self.inputs.len())
    }
    fn time(&self, s: usize, reps: usize) -> f64 {
        match s {
            0 => run_loop(&self.inputs, &self.f.0, reps),
            1 => run_loop(&self.inputs, &self.f.1, reps),
            _ => run_loop(&self.inputs, &self.f.2, reps),
        }
    }
}

/// One row: the three subjects' `probe::$f`, the closure parameter pattern
/// `$x` binding the arguments from one input.
macro_rules! row {
    ($set:literal, $f:ident, $inputs:expr, |$x:pat_param| ($($arg:expr),*)) => {
        Box::new(Row::new(
            $set,
            stringify!($f),
            $inputs,
            |$x| subj_orig::probe::$f($($arg),*),
            |$x| subj_aa::probe::$f($($arg),*),
            |$x| subj_shipped::probe::$f($($arg),*),
        )) as Box<dyn Case>
    };
}

/// The varint rows of one unsigned width.
macro_rules! unsigned_rows {
    ($v:ident, $t:ty, $bits:literal, $w:ident, $r:ident, $s:ident) => {
        $v.push(row!("varint", $w, inputs(stringify!($w), vec![0, 1, 127, 128, <$t>::MAX], |r| r.bits($bits) as $t), |&x| (x)));
        $v.push(row!("varint", $r, inputs(stringify!($r), vec![vec![], vec![0], vec![0x80], vec![0xff; 12]], |r| { let x = r.bits($bits); leb(r, x) }), |b| (b)));
        $v.push(row!("varint", $s, inputs(stringify!($s), vec![0, 1, 127, 128, <$t>::MAX], |r| r.bits($bits) as $t), |&x| (x)));
    };
}

const VERIFIER_LEAVES: u64 = 1024;

fn cases() -> Vec<Box<dyn Case>> {
    let mut v: Vec<Box<dyn Case>> = Vec::new();
    // ---- codec: varint, the verified instances
    unsigned_rows!(v, u16, 16, varint_u16_write, varint_u16_read, varint_u16_size);
    unsigned_rows!(v, u32, 32, varint_u32_write, varint_u32_read, varint_u32_size);
    unsigned_rows!(v, u64, 64, varint_u64_write, varint_u64_read, varint_u64_size);
    v.push(row!("varint", varint_i16_write, inputs("varint_i16_write", vec![0, -1, 1, i16::MIN, i16::MAX], |r| r.signed(15) as i16), |&x| (x)));
    v.push(row!("varint", varint_i16_read, inputs("varint_i16_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(15)) & 0xffff; leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i16_size, inputs("varint_i16_size", vec![0, -1, i16::MIN, i16::MAX], |r| r.signed(15) as i16), |&x| (x)));
    v.push(row!("varint", varint_i32_write, inputs("varint_i32_write", vec![0, -1, 1, i32::MIN, i32::MAX], |r| r.signed(31) as i32), |&x| (x)));
    v.push(row!("varint", varint_i32_read, inputs("varint_i32_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(31)) & 0xffff_ffff; leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i32_size, inputs("varint_i32_size", vec![0, -1, i32::MIN, i32::MAX], |r| r.signed(31) as i32), |&x| (x)));
    v.push(row!("varint", varint_i64_write, inputs("varint_i64_write", vec![0, -1, 1, i64::MIN, i64::MAX], |r| r.signed(63)), |&x| (x)));
    v.push(row!("varint", varint_i64_read, inputs("varint_i64_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(63)); leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i64_size, inputs("varint_i64_size", vec![0, -1, i64::MIN, i64::MAX], |r| r.signed(63)), |&x| (x)));
    v.push(row!("varint", varint_u64_decoder, inputs("varint_u64_decoder", vec![vec![], vec![0x80; 11]], |r| { let x = r.bits(64); leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_u32_decoder, inputs("varint_u32_decoder", vec![vec![], vec![0x80; 6]], |r| { let x = r.bits(32); leb(r, x) }), |b| (b)));
    // ---- storage: the MMR (leaf counts below 2^62: every size, location and
    // position within MAX_NODES / MAX_LEAVES)
    v.push(row!("mmr", mmr_is_valid_size, inputs("mmr_is_valid_size", vec![0, 1, 2, 3, 4, u64::MAX], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&s| (s)));
    v.push(row!("mmr", mmr_to_nearest_size, inputs("mmr_to_nearest_size", vec![0, 1, 2, (1 << 63) - 1], |r| r.bits(63)), |&s| (s)));
    v.push(row!("mmr", mmr_location_to_position, inputs("mmr_location_to_position", vec![0, 1, 1 << 62], |r| r.bits(62)), |&l| (l)));
    v.push(row!("mmr", mmr_position_to_location, inputs("mmr_position_to_location", vec![0, 1, 2, (1 << 63) - 1], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&p| (p)));
    v.push(row!("mmr", mmr_peaks, inputs("mmr_peaks", vec![0, 1, 3, 4, mmr_size(1 << 62)], |r| mmr_size(r.bits(62))), |&s| (s)));
    v.push(row!("mmr", mmr_peak_iterator, inputs("mmr_peak_iterator", vec![0, 1, 3, 4, mmr_size(1 << 62)], |r| mmr_size(r.bits(62))), |&s| (s)));
    // a peak of height >= 1 of a valid size: its position and height
    v.push(row!(
        "mmr",
        mmr_children,
        inputs("mmr_children", vec![(2, 1)], |r| {
            let n = 2 + r.bits(60);
            // the first peak of `n` leaves: height floor(log2 n), at 2^(h+1) - 2
            let h = 63 - n.leading_zeros();
            ((1u64 << (h + 1)) - 2, h)
        }),
        |&(p, h)| (p, h)
    ));
    v.push(row!("mmr", mmr_parent_heights, inputs("mmr_parent_heights", vec![0, 1, 3, 7, u64::MAX >> 2], |r| r.bits(62)), |&l| (l)));
    v.push(row!("mmr", mmr_location_from_position, inputs("mmr_location_from_position", vec![0, 1, 2, 3], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&p| (p)));
    v.push(row!("mmr", mmr_position_from_location, inputs("mmr_position_from_location", vec![0, 1, (1 << 62) + 1], |r| r.bits(63)), |&l| (l)));
    // ---- storage: the Merkle proof verifier's first set
    v.push(row!("verifier", hasher_leaf_digest, inputs("hasher_leaf_digest", vec![(0, vec![])], |r| (r.bits(62), r.bytes(64))), |(p, e)| (*p, e)));
    v.push(row!("verifier", hasher_node_digest, inputs("hasher_node_digest", vec![(2, [0u8; 32], [0u8; 32])], |r| (r.bits(62), r.b32(), r.b32())), |&(p, a, b)| (p, a, b)));
    // each subject's own MMR of VERIFIER_LEAVES leaves and proofs (built once, untimed)
    let v0: &'static subj_orig::probe::Verifier = Box::leak(Box::new(subj_orig::probe::Verifier::new(VERIFIER_LEAVES)));
    let v1: &'static subj_aa::probe::Verifier = Box::leak(Box::new(subj_aa::probe::Verifier::new(VERIFIER_LEAVES)));
    let v2: &'static subj_shipped::probe::Verifier = Box::leak(Box::new(subj_shipped::probe::Verifier::new(VERIFIER_LEAVES)));
    let inputs = inputs("proof_verify_element_inclusion", vec![(0usize, false), (VERIFIER_LEAVES as usize - 1, true)], |r| (r.below(VERIFIER_LEAVES) as usize, r.below(8) == 0));
    v.push(Box::new(Row::new(
        "verifier",
        "proof_verify_element_inclusion",
        inputs,
        move |&(i, t): &(usize, bool)| subj_orig::probe::proof_verify_element_inclusion(v0, i, t),
        move |&(i, t): &(usize, bool)| subj_aa::probe::proof_verify_element_inclusion(v1, i, t),
        move |&(i, t): &(usize, bool)| subj_shipped::probe::proof_verify_element_inclusion(v2, i, t),
    )));
    v
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn quantile(v: &[f64], q: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((s.len() - 1) as f64 * q).round() as usize;
    s[i]
}

fn check(cases: &[Box<dyn Case>]) -> bool {
    let mut ok = true;
    for c in cases {
        match c.check() {
            Ok(n) => println!("agree  {} {} ({n} inputs: original, A/A and shipped)", c.set(), c.name()),
            Err(e) => {
                println!("DIFFER {} {e}", c.set());
                ok = false;
            }
        }
    }
    ok
}

const SUBJECTS: [&str; 3] = ["orig", "aa", "shipped"];

fn bench(cases: &[Box<dyn Case>], rounds: usize, json: Option<&str>) {
    println!("| set | function | original ns | A/A ns | shipped ns | A/A / original | shipped / original | shipped / original, rounds p10..p90 |");
    println!("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |");
    let mut rows = Vec::new();
    for c in cases {
        // calibrate: one sample of about 200 microseconds
        let mut reps = 1;
        loop {
            let t = c.time(0, reps) * (reps * N) as f64;
            if t > 200_000.0 || reps > 1 << 20 {
                break;
            }
            reps *= 2;
        }
        let mut per_round: [Vec<f64>; 3] = [vec![], vec![], vec![]];
        for round in 0..rounds {
            for k in 0..3 {
                let s = (round + k) % 3;
                let mut samples: Vec<f64> = (0..5).map(|_| c.time(s, reps)).collect();
                per_round[s].push(median(&mut samples));
            }
        }
        let ratios: Vec<f64> = (0..rounds).map(|i| per_round[2][i] / per_round[0][i]).collect();
        let aa_ratios: Vec<f64> = (0..rounds).map(|i| per_round[1][i] / per_round[0][i]).collect();
        let ns: Vec<f64> = (0..3).map(|s| median(&mut per_round[s].clone())).collect();
        let (r_ship, r_aa) = (ns[2] / ns[0], ns[1] / ns[0]);
        println!("| {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3}..{:.3} |", c.set(), c.name(), ns[0], ns[1], ns[2], r_aa, r_ship, quantile(&ratios, 0.1), quantile(&ratios, 0.9));
        rows.push(format!(
            "{{\"set\":\"{}\",\"function\":\"{}\",\"reps\":{reps},\"inputs\":{N},\"ns\":{{\"{}\":{:.4},\"{}\":{:.4},\"{}\":{:.4}}},\"shipped_over_orig\":{r_ship:.5},\"aa_over_orig\":{r_aa:.5},\"round_ratios_shipped\":[{}],\"round_ratios_aa\":[{}]}}",
            c.set(),
            c.name(),
            SUBJECTS[0],
            ns[0],
            SUBJECTS[1],
            ns[1],
            SUBJECTS[2],
            ns[2],
            ratios.iter().map(|x| format!("{x:.5}")).collect::<Vec<_>>().join(","),
            aa_ratios.iter().map(|x| format!("{x:.5}")).collect::<Vec<_>>().join(",")
        ));
    }
    if let Some(p) = json {
        std::fs::write(p, format!("{{\"rounds\":{rounds},\"samples_per_round\":5,\"rows\":[\n{}\n]}}\n", rows.join(",\n"))).expect("write json");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cases = cases();
    match args.first().map(String::as_str) {
        Some("check") => {
            if !check(&cases) {
                std::process::exit(1);
            }
        }
        Some("bench") => {
            let mut rounds = 21;
            let mut json = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--rounds" => {
                        rounds = args[i + 1].parse().expect("--rounds N");
                        i += 1;
                    }
                    "--json" => {
                        json = Some(args[i + 1].clone());
                        i += 1;
                    }
                    a => panic!("unknown argument {a}"),
                }
                i += 1;
            }
            assert!(rounds >= 21, "the protocol needs at least 21 rounds");
            // the differential check first: nothing is timed unless every subject agrees
            if !check(&cases) {
                eprintln!("the differential check failed: nothing timed");
                std::process::exit(1);
            }
            bench(&cases, rounds, json.as_deref());
        }
        _ => {
            eprintln!("usage: shipped-bench check | bench [--rounds N (>= 21)] [--json PATH]");
            std::process::exit(2);
        }
    }
}
