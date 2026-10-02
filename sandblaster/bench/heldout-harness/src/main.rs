//! The held-out harness binary (fairness audit plan step 8, J11).
//!
//! Three subjects of ONE crate source (`subject/lib.rs`), linked into this
//! one binary:
//!
//! | subject | package | what |
//! | --- | --- | --- |
//! | rustc | `subj_rustc` | the held-out source as written, compiled by rustc |
//! | A/A | `subj_rustc_aa` | the same source again: the control (identical code) |
//! | optimized | `subj_opt` | the exec-only optimizer's lowered copies |
//!
//! `heldout-bench check` runs the differential check (every subject agrees
//! on every input, generated inputs plus edge cases) and must pass before
//! `heldout-bench bench [--rounds N] [--json PATH]` times anything: per
//! function, N interleaved rounds (the subject order rotates each round),
//! each subject's per-round value the median of 5 samples, its reported
//! value the median of its per-round values (ns per call, one out-of-line
//! call into `probe::<fn>` per invocation). Inputs come from a fixed-seed
//! type-driven generator (uniform bit length for integers) that respects
//! each function's documented preconditions; no profile is involved.

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
        if b == 0 {
            0
        } else {
            (self.next() >> (64 - b)) | (1u64 << (b - 1))
        }
    }
    fn u32(&mut self) -> u32 {
        self.bits(32) as u32
    }
    fn u64(&mut self) -> u64 {
        self.bits(64)
    }
    fn bytes(&mut self, max_len: u64, alphabet: &[u8]) -> Vec<u8> {
        let n = self.below(max_len + 1) as usize;
        (0..n).map(|_| if alphabet.is_empty() { self.next() as u8 } else { alphabet[self.below(alphabet.len() as u64) as usize] }).collect()
    }
}

const N: usize = 512;

fn gen<T>(name: &str, edge: Vec<T>, mut f: impl FnMut(&mut Rng) -> T) -> Vec<T> {
    let mut r = Rng::new(name);
    let mut v = edge;
    while v.len() < N {
        v.push(f(&mut r));
    }
    v
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
                return Err(format!("{}: input {:?}: rustc {:?}, A/A {:?}, optimized {:?}", self.name, x, a, b, c));
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

/// One row: the three subjects' `probe::$f`, the closure parameter
/// pattern `$x` binding the arguments from one input.
macro_rules! row {
    ($set:literal, $f:ident, $inputs:expr, |$x:pat_param| ($($arg:expr),*)) => {
        Box::new(Row::new(
            $set,
            stringify!($f),
            $inputs,
            |$x| subj_rustc::probe::$f($($arg),*),
            |$x| subj_rustc_aa::probe::$f($($arg),*),
            |$x| subj_opt::probe::$f($($arg),*),
        )) as Box<dyn Case>
    };
}

const SPACES: &[u8] = b" \t\n\r\x0b\x0cab";

fn cases() -> Vec<Box<dyn Case>> {
    vec![
        row!("H1", decimal_digits, gen("decimal_digits", vec![0, 9, 10, 99, 100, u64::MAX], |r| r.u64()), |&n| (n)),
        // sizes below usize::MAX / 8 (`n * 8` must not overflow)
        row!("H1", base32_encoded_len, gen("base32_encoded_len", vec![(0, true), (0, false), (5, true), (6, false)], |r| (r.bits(48) as usize, r.below(2) == 0)), |&(n, p)| (n, p)),
        row!("H1", base64_encoded_len, gen("base64_encoded_len", vec![(0, true), (1, false), (2, false), (3, true)], |r| (r.bits(48) as usize, r.below(2) == 0)), |&(n, p)| (n, p)),
        row!("H1", reverse_bits, gen("reverse_bits", vec![0, 1, u32::MAX], |r| r.u32()), |&x| (x)),
        row!("H1", gray_encode, gen("gray_encode", vec![0, 1, u32::MAX], |r| r.u32()), |&x| (x)),
        row!("H1", gray_decode, gen("gray_decode", vec![0, 1, u32::MAX], |r| r.u32()), |&x| (x)),
        row!("H1", next_power_of_two, gen("next_power_of_two", vec![0, 1, 2, 3, 1 << 31, (1 << 31) + 1, u32::MAX], |r| r.u32()), |&x| (x)),
        row!("H1", isqrt, gen("isqrt", vec![0, 1, 15, 16, u64::MAX], |r| r.u64()), |&x| (x)),
        // a tree of 1..=257 entries (small values: the sum cannot overflow), a count below its length
        row!(
            "H1",
            fenwick_prefix_sum,
            gen("fenwick_prefix_sum", vec![], |r| {
                let len = 1 + r.below(257) as usize;
                let tree: Vec<u64> = (0..len).map(|_| r.bits(32)).collect();
                let count = r.below(len as u64) as u32;
                (tree, count)
            }),
            |(t, c)| (t, *c)
        ),
        // min_block nonzero; sizes up to 2^40 (the doubling stays far from overflow)
        row!("H1", buddy_order, gen("buddy_order", vec![(0, 4096), (4096, 4096), (4097, 4096)], |r| (r.bits(40) as usize, 1 + r.bits(20) as usize)), |&(s, m)| (s, m)),
        row!("H1", binomial_meld_carries, gen("binomial_meld_carries", vec![(0, 0), (u64::MAX, 1), (u64::MAX, u64::MAX)], |r| (r.u64(), r.u64())), |&(a, b)| (a, b)),
        row!(
            "H1",
            hamming_distance,
            gen("hamming_distance", vec![(vec![], vec![]), (vec![1], vec![])], |r| {
                let a = r.bytes(64, &[]);
                let b = if r.below(8) == 0 { r.bytes(64, &[]) } else { (0..a.len()).map(|_| r.next() as u8).collect() };
                (a, b)
            }),
            |(a, b)| (a, b)
        ),
        row!("H1", run_count, gen("run_count", vec![vec![]], |r| r.bytes(64, b"aab")), |v| (v)),
        row!("H1", first_newline, gen("first_newline", vec![vec![], b"\n".to_vec()], |r| r.bytes(64, b"abcdefghijklmnopqrstuvwxyz \n")), |v| (v)),
        row!("H1", first_printable, gen("first_printable", vec![vec![], vec![0x1f, 0x20]], |r| r.bytes(64, &[0, 1, 9, 10, 13, 27, 31, 32, 65, 127])), |v| (v)),
        // values of uniform bit length: some slices overflow, some do not
        row!("H1", checked_sum, gen("checked_sum", vec![vec![], vec![u32::MAX, 1]], |r| {
                let n = r.below(33) as usize;
                (0..n)
                    .map(|_| {
                        let width = 28 + r.below(5) as u32;
                        r.bits(width) as u32
                    })
                    .collect::<Vec<u32>>()
            }), |v| (v)),
        // capacity nonzero, head < capacity
        row!(
            "H1",
            ring_index,
            gen("ring_index", vec![(0, 0, 1), (3, 5, 8)], |r| {
                let cap = 1 + r.bits(40) as usize;
                (r.below(cap as u64) as usize, r.u64() as usize, cap)
            }),
            |&(h, o, c)| (h, o, c)
        ),
        // align a power of two; x + align - 1 does not overflow
        row!("H1", align_up, gen("align_up", vec![(0, 1), (1, 4096), (4096, 4096)], |r| (r.bits(62), 1u64 << r.below(32))), |&(x, a)| (x, a)),
        // b nonzero
        row!("H1", ceil_div, gen("ceil_div", vec![(0, 1), (u32::MAX, 1), (u32::MAX, u32::MAX), (7, 2)], |r| (r.u32(), 1 + r.bits(31) as u32)), |&(a, b)| (a, b)),
        row!("H1", crc8, gen("crc8", vec![vec![], b"123456789".to_vec()], |r| r.bytes(64, &[])), |v| (v)),
        row!("H1", parity, gen("parity", vec![0, 1, u32::MAX], |r| r.u32()), |&x| (x)),
        // trailing ones: `!x` of uniform bit length gives every run length
        row!("H1", trailing_ones, gen("trailing_ones", vec![0, 1, u32::MAX], |r| !(r.u32())), |&x| (x)),
        row!("H1", byte_swap, gen("byte_swap", vec![0, 0x0102_0304, u32::MAX], |r| r.u32()), |&x| (x)),
        row!("H1", nibble_popcount, gen("nibble_popcount", (0..=255u8).collect(), |r| r.next() as u8), |&n| (n)),
        row!(
            "H1",
            matrix_sum_4x8,
            gen("matrix_sum_4x8", vec![[[0u8; 8]; 4], [[255u8; 8]; 4]], |r| {
                let mut m = [[0u8; 8]; 4];
                for row in m.iter_mut() {
                    for c in row.iter_mut() {
                        *c = r.next() as u8;
                    }
                }
                m
            }),
            |m| (m)
        ),
        row!(
            "H1",
            seed16_rounds20,
            gen("seed16_rounds20", vec![[0u8; 16], [255u8; 16]], |r| {
                let mut k = [0u8; 16];
                for b in k.iter_mut() {
                    *b = r.next() as u8;
                }
                k
            }),
            |k| (k)
        ),
        row!("H1", count_words, gen("count_words", vec![vec![], b"  a b  ".to_vec()], |r| r.bytes(64, SPACES)), |v| (v)),
        row!("H1", scale_sample, gen("scale_sample", vec![(i16::MIN, i32::MAX, i32::MAX), (i16::MAX, i32::MIN, i32::MIN), (0, 0, 0)], |r| (r.next() as i16, r.next() as i32 >> r.below(32), r.next() as i32 >> r.below(32))), |&(s, g, o)| (s, g, o)),
        row!("H1", remaining_budget, gen("remaining_budget", vec![(0, vec![], 0), (u32::MAX, vec![1, 2], u32::MAX)], |r| (r.u32(), (0..r.below(33)).map(|_| r.bits(28) as u32).collect::<Vec<u32>>(), r.u32())), |(b, c, cap)| (*b, c, *cap)),
        row!("H1", read_u32_le, gen("read_u32_le", vec![(vec![], 0), (vec![1, 2, 3, 4], 0), (vec![1, 2, 3, 4], usize::MAX)], |r| { let d = r.bytes(16, &[]); let off = r.below(d.len() as u64 + 2) as usize; (d, off) }), |(d, o)| (d, *o)),
        row!("H2", mix64, gen("mix64", vec![0, 1, u64::MAX], |r| r.u64()), |&x| (x)),
    ]
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    }
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
            Ok(n) => println!("agree  {} {} ({n} inputs: rustc, A/A and optimized)", c.set(), c.name()),
            Err(e) => {
                println!("DIFFER {} {e}", c.set());
                ok = false;
            }
        }
    }
    ok
}

const SUBJECTS: [&str; 3] = ["rustc", "aa", "opt"];

fn bench(cases: &[Box<dyn Case>], rounds: usize, json: Option<&str>) {
    println!("| set | function | rustc ns | A/A ns | optimized ns | A/A / rustc | optimized / rustc | optimized / rustc, rounds p10..p90 |");
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
        let (r_opt, r_aa) = (ns[2] / ns[0], ns[1] / ns[0]);
        println!(
            "| {} | {} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3} | {:.3}..{:.3} |",
            c.set(),
            c.name(),
            ns[0],
            ns[1],
            ns[2],
            r_aa,
            r_opt,
            quantile(&ratios, 0.1),
            quantile(&ratios, 0.9)
        );
        rows.push(format!(
            "{{\"set\":\"{}\",\"function\":\"{}\",\"reps\":{reps},\"inputs\":{N},\"ns\":{{\"{}\":{:.4},\"{}\":{:.4},\"{}\":{:.4}}},\"opt_over_rustc\":{r_opt:.5},\"aa_over_rustc\":{r_aa:.5},\"round_ratios_opt\":[{}],\"round_ratios_aa\":[{}]}}",
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
            assert!(rounds >= 21, "the held-out protocol needs at least 21 rounds");
            // the differential check first: nothing is timed unless every subject agrees
            if !check(&cases) {
                eprintln!("the differential check failed: nothing timed");
                std::process::exit(1);
            }
            bench(&cases, rounds, json.as_deref());
        }
        _ => {
            eprintln!("usage: heldout-bench check | bench [--rounds N (>= 21)] [--json PATH]");
            std::process::exit(2);
        }
    }
}
