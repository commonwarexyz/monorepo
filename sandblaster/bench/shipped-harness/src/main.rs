//! The measurement harness binary (README.md): the original crates at a
//! given commit against the worktree's own crates, in one binary.
//!
//! Three subjects of ONE crate source (`subject/lib.rs` with the probe's
//! `probe.rs`), linked into this one binary:
//!
//! | subject | package | what |
//! | --- | --- | --- |
//! | original | `subj_orig` | the crates at the base commit (`run.sh --base`) |
//! | A/A | `subj_aa` | the same code again: the control (its own copies, identical code) |
//! | worktree | `subj_wt` | the worktree's crates as they are (with the verified module a module-mode build writes to `OUT_DIR`) |
//!
//! `bench-harness check [--only F,..]` runs the differential check (every
//! subject agrees on every input: generated inputs plus edge cases, each
//! within the function's documented preconditions) and must pass before
//! `bench-harness bench [--rounds N] [--json PATH] [--only F,..]` times
//! anything: per function, N >= 21 interleaved rounds (the subject order
//! rotates each round), each subject's per-round value the median of 5
//! samples of about 200 microseconds, its reported value the median of its
//! per-round values (ns per call, one out-of-line call into `probe::<fn>`
//! per invocation).

// a probe's rows use only some of the input helpers
#![allow(dead_code)]

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
                return Err(format!("{}: input {:?}: original {:?}, A/A {:?}, worktree {:?}", self.name, x, a, b, c));
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
            |$x| subj_wt::probe::$f($($arg),*),
        )) as Box<dyn Case>
    };
}

// The probe's rows (`probes/<probe>/rows.rs`, copied by prepare.py):
// `fn cases() -> Vec<Box<dyn Case>>`.
include!("../gen/rows.rs");

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
            Ok(n) => println!("agree  {} {} ({n} inputs: original, A/A and worktree)", c.set(), c.name()),
            Err(e) => {
                println!("DIFFER {} {e}", c.set());
                ok = false;
            }
        }
    }
    ok
}

const SUBJECTS: [&str; 3] = ["orig", "aa", "wt"];

fn bench(cases: &[Box<dyn Case>], rounds: usize, json: Option<&str>) {
    println!("| set | function | original ns | A/A ns | worktree ns | A/A / original | worktree / original | worktree / original, rounds p10..p90 |");
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
        let (r_wt, r_aa) = (ns[2] / ns[0], ns[1] / ns[0]);
        println!("| {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3}..{:.3} |", c.set(), c.name(), ns[0], ns[1], ns[2], r_aa, r_wt, quantile(&ratios, 0.1), quantile(&ratios, 0.9));
        rows.push(format!(
            "{{\"set\":\"{}\",\"function\":\"{}\",\"reps\":{reps},\"inputs\":{N},\"ns\":{{\"{}\":{:.4},\"{}\":{:.4},\"{}\":{:.4}}},\"wt_over_orig\":{r_wt:.5},\"aa_over_orig\":{r_aa:.5},\"round_ratios_wt\":[{}],\"round_ratios_aa\":[{}]}}",
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
    let mut rounds = 21;
    let mut json = None;
    let mut only: Option<Vec<String>> = None;
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
            "--only" => {
                only = Some(args[i + 1].split(',').map(String::from).collect());
                i += 1;
            }
            a => panic!("unknown argument {a}"),
        }
        i += 1;
    }
    let mut cases = cases();
    if let Some(only) = &only {
        for o in only {
            assert!(cases.iter().any(|c| c.name() == o), "--only: no row `{o}`");
        }
        cases.retain(|c| only.iter().any(|o| o == c.name()));
    }
    match args.first().map(String::as_str) {
        Some("check") => {
            if !check(&cases) {
                std::process::exit(1);
            }
        }
        Some("bench") => {
            assert!(rounds >= 21, "the protocol needs at least 21 rounds");
            // the differential check first: nothing is timed unless every subject agrees
            if !check(&cases) {
                eprintln!("the differential check failed: nothing timed");
                std::process::exit(1);
            }
            bench(&cases, rounds, json.as_deref());
        }
        _ => {
            eprintln!("usage: bench-harness check [--only F,..] | bench [--rounds N (>= 21)] [--json PATH] [--only F,..]");
            std::process::exit(2);
        }
    }
}
