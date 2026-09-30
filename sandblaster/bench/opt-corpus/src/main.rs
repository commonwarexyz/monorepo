//! The general optimizer corpus: differential checks of every subject against the
//! sandblaster-generated code first, then same-binary timings of three subjects per program
//! (docs/optimizer-plan.md O1 and §0.3: checks first; subjects interleaved in one binary,
//! >= 3 rounds in rotating order; the reported value is the median of the per-round medians):
//!
//! * **current**: the corpus as emitted now (`cgen`, written by `run.sh`);
//! * **O1 emission**: the corpus as emitted at plan O1 (`cgen_o1`, the frozen
//!   `baselines/o1-gen.rs`), the reference every milestone's gain is judged against *in this
//!   binary* (`O1 / current`): a gain read across binaries mixes in code placement, which moves
//!   identical code by up to ~17% (P20 at O2);
//! * **ideal**: the hand-written target (`ideal`).
//!
//!   opt-corpus [check | check-reject | bench | all] [quick] [--rounds N] [--only P1,P7] [--json FILE]
//!
//! * `check`: 400k integers, 1M+ varint byte strings, folds, tables, scans (P1-P14), and the
//!   P15-P20 cases; the ideal and the O1 emission must agree with the current emission.
//! * `check-reject`: the same checks must catch every must-reject variant of P15-P20
//!   (`ideal::reject`), so a wrong candidate never reaches timing.
//! * `bench`: the three subjects per input set, with the generated/ideal ratio recorded in
//!   `recorded.tsv` (P1-P14: when the corpus was designed, design §2.3; P15-P20: the O1
//!   emission in the harness composition named there, see `run.sh`).
//!
//! Portable: aarch64 (this machine) and x86_64 (`run.sh` builds both; x86_64-apple-darwin
//! runs its checks under Rosetta 2, x86_64-unknown-linux-gnu is compile-only here).
use std::hint::black_box as bb;
use std::time::{Duration, Instant};

static mut WARM_MS: u64 = 120;
static mut SAMPLES: usize = 31;
static mut SAMPLE_MS: u64 = 5;

/// Median and minimum ns per call of `f` (which performs `per` calls).
fn measure(per: usize, mut f: impl FnMut()) -> (f64, f64) {
    let (warmup, sample, samples) = unsafe { (Duration::from_millis(WARM_MS), Duration::from_millis(SAMPLE_MS), SAMPLES) };
    let mut iters: u64 = 1;
    let start = Instant::now();
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let e = t.elapsed();
        if start.elapsed() >= warmup && e >= sample / 2 {
            iters = ((sample.as_secs_f64() / (e.as_secs_f64() / iters as f64)).ceil() as u64).max(1);
            break;
        }
        if e < sample {
            iters = iters.saturating_mul(2);
        }
    }
    let mut v: Vec<f64> = (0..samples)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            t.elapsed().as_secs_f64() * 1e9 / (iters as f64 * per as f64)
        })
        .collect();
    v.sort_by(f64::total_cmp);
    (v[v.len() / 2], v[0])
}

fn med(mut xs: Vec<f64>) -> f64 {
    xs.sort_by(f64::total_cmp);
    xs[xs.len() / 2]
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    /// Uniform bit length 0..=64.
    fn bits(&mut self) -> u64 {
        let k = self.below(65);
        if k == 0 { 0 } else { (self.next() | (1 << 63)) >> (64 - k) }
    }
}

fn enc(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

// ------------------------------------------------------------------------------------ checks

/// P1-P14: the checks recorded with the corpus (research/optdesign/corpus/src/main.rs), for one
/// emitted subject (`$($g)::+`, a probe module): every ideal must agree with it.
macro_rules! check_p1_p14 {
    ($fname:ident, $subject:expr, $($g:ident)::+) => {
fn $fname() {
    use $($g)::+ as g;
    let same_block = |a: Option<g::Block>, b: Option<ideal::Block>| match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.level == b.level && a.start == b.start && a.rank == b.rank,
        _ => false,
    };
    let mut r = Rng(0xfeed);
    let mut n = 0u64;
    let special = [0u64, 1, 2, 3, 127, 128, 255, 256, (1 << 32) - 1, 1 << 32, 1 << 62, (1 << 62) - 1, 1 << 63, u64::MAX, u64::MAX - 1];
    let mut xs: Vec<u64> = special.to_vec();
    for _ in 0..400_000 {
        xs.push(match r.below(3) {
            0 => r.bits(),
            1 => r.next(),
            _ => r.below(300),
        });
    }
    for &x in &xs {
        assert_eq!(g::bit_length(x), ideal::bit_length(x), "bit_length {x}");
        assert_eq!(g::floor_pow2(x), ideal::floor_pow2(x), "floor_pow2 {x}");
        assert_eq!(g::popcount_loop(x), ideal::popcount_loop(x), "popcount {x}");
        assert_eq!(g::varint_len(x), ideal::varint_len(x), "varint_len {x}");
        assert_eq!(g::trailing_zeros_loop(x), ideal::trailing_zeros_loop(x), "tz {x}");
        let k = r.below(70) as u32;
        assert_eq!(g::rank_above(x, k), ideal::rank_above(x, k), "rank {x} {k}");
        let i = match r.below(4) {
            0 => r.below(x.max(1)),
            1 => r.next(),
            2 => x.wrapping_sub(r.below(3)),
            _ => r.below(x.saturating_add(3)),
        };
        assert!(same_block(g::find_block(x, i), ideal::find_block(x, i)), "find_block {x} {i}");
        n += 1;
    }
    for nn in 0..300u64 {
        for i in 0..nn + 3 {
            assert!(same_block(g::find_block(nn, i), ideal::find_block(nn, i)));
        }
    }
    for s in 0..70_000u32 {
        assert_eq!(g::series(s), ideal::series(s));
    }
    for &s in &[u32::MAX, u32::MAX - 1, 1 << 31] {
        assert_eq!(g::series(s), ideal::series(s));
    }
    // varints: random byte strings biased to continuation bytes, plus every 1-2 byte input
    let mut buf = [0u8; 24];
    let mut nv = 0u64;
    for _ in 0..1_000_000 {
        let len = r.below(24) as usize;
        let cont = r.below(12) as usize;
        for k in 0..len {
            let b = r.next() as u8;
            buf[k] = if k < cont {
                b | 0x80
            } else if r.below(3) == 0 {
                b & 0x7f
            } else {
                b
            };
            if r.below(10) == 0 {
                buf[k] = [0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0xff][r.below(7) as usize];
            }
        }
        let s = &buf[..len];
        assert_eq!(g::leb128(s), ideal::leb128(s), "leb128 {s:02x?}");
        assert_eq!(g::header4(s), ideal::header4(s), "header4 {s:02x?}");
        assert_eq!(g::first_small(s), ideal::first_small(s), "first_small {s:02x?}");
        nv += 1;
    }
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            for s in [&[a][..], &[a, b][..], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, a, b][..], &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, a, b][..], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, a, b, 0][..]] {
                assert_eq!(g::leb128(s), ideal::leb128(s));
                nv += 1;
            }
        }
    }
    // concat_fold, prefix_query, min_max, sum_small
    let pool: Vec<u64> = (0..600).map(|_| r.next()).collect();
    for _ in 0..50_000 {
        let na = r.below(300) as usize;
        let nb = r.below(300) as usize;
        let (a, b) = (&pool[..na], &pool[300..300 + nb]);
        let m = r.next();
        assert_eq!(g::concat_fold(a, m, b), ideal::concat_fold(a, m, b), "concat_fold {na} {nb}");
    }
    for _ in 0..20_000 {
        let mut t = [0u32; 64];
        for x in t.iter_mut() {
            *x = r.next() as u32;
        }
        let k = r.below(80) as usize;
        assert_eq!(g::prefix_query(&t, k), ideal::prefix_query(&t, k));
        let l = r.below(65) as usize;
        assert_eq!(g::min_max(&t[..l]), ideal::min_max(&t[..l]));
        assert_eq!(g::sum_small(&t[..l]), ideal::sum_small(&t[..l]));
    }
    let big: Vec<u32> = (0..70_000).map(|_| r.next() as u32).collect();
    for l in [0usize, 1, 65535, 65536, 65537, 70_000] {
        assert_eq!(g::sum_small(&big[..l]), ideal::sum_small(&big[..l]));
        assert_eq!(g::min_max(&big[..l]), ideal::min_max(&big[..l]));
    }
    println!("check P1-P14 ({}): {n} integer inputs, {nv} varint byte strings, 50000 folds, 20000 tables/scans: every ideal agrees with it", $subject);
}
    };
}
check_p1_p14!(check_p1_p14_current, "current emission", cgen::probe);
check_p1_p14!(check_p1_p14_o1, "O1 emission", cgen_o1::probe);


/// The P15-P20 check inputs, shared by `check` and `check-reject`.
struct Cases {
    trees: Vec<(u32, Vec<u64>)>,
    batches: Vec<([u64; 8], [u64; 8], Box<[[u64; 20]; 8]>)>,
    blocks: Vec<(u16, [u8; 64])>,
    limbs: Vec<([u64; 4], [u64; 4])>,
    lines: Vec<([u64; 3], u64)>,
}

fn cases() -> Cases {
    let mut r = Rng(0x5eed_0015);
    let mut trees = Vec::new();
    for h in 0..=13u32 {
        for _ in 0..40 {
            let n = if h <= 12 { 1usize << h } else { 8192 };
            let len = match r.below(6) {
                0 => n.saturating_sub(1),
                1 => n + 1,
                2 => r.below(2 * n as u64 + 2) as usize,
                _ => n,
            };
            trees.push((h, (0..len).map(|_| r.next()).collect()));
        }
    }
    trees.push((0, vec![]));
    trees.push((40, vec![1, 2]));
    let mut batches = Vec::new();
    for t in 0..20_000 {
        let leaves: [u64; 8] = core::array::from_fn(|_| r.next());
        let indices: [u64; 8] = core::array::from_fn(|_| if t % 5 == 0 { r.below(1 << 20) } else { r.next() });
        let sibs: Box<[[u64; 20]; 8]> = Box::new(core::array::from_fn(|_| core::array::from_fn(|_| if t % 7 == 0 { r.below(4) } else { r.next() })));
        batches.push((leaves, indices, sibs));
    }
    let mut blocks = Vec::new();
    let base: [u8; 64] = core::array::from_fn(|_| r.next() as u8);
    for c in 0..=u16::MAX {
        blocks.push((c, base));
    }
    let specials: [[u8; 64]; 3] = [[0u8; 64], [0xff; 64], core::array::from_fn(|i| if i == 0 || i == 32 { 1 } else { 0 })];
    for s in specials {
        for c in [0u16, 1, 2, 0x8000, 0xffff, 12345] {
            blocks.push((c, s));
        }
    }
    for _ in 0..4000 {
        blocks.push((r.next() as u16, core::array::from_fn(|_| r.next() as u8)));
    }
    let mut limbs = Vec::new();
    const M: u64 = (1 << 28) - 1;
    for t in 0..1_000_000u64 {
        let pick = |r: &mut Rng| match r.below(5) {
            0 => M,
            1 => u64::MAX,
            2 => r.below(1 << 29),
            3 => M ^ (1 << r.below(28)),
            _ => r.next(),
        };
        let a: [u64; 4] = core::array::from_fn(|_| if t % 3 == 0 { pick(&mut r) } else { r.next() });
        let b: [u64; 4] = core::array::from_fn(|_| if t % 3 == 0 { pick(&mut r) } else { r.next() });
        limbs.push((a, b));
    }
    let mut lines = Vec::new();
    for t in 0..200_000u64 {
        let a: [u64; 3] = core::array::from_fn(|_| r.next());
        let c = match t % 4 {
            0 => 0,
            1 => 1 << r.below(64),
            2 => r.below(1 << 8),
            _ => r.next(),
        };
        lines.push((a, c));
    }
    Cases { trees, batches, blocks, limbs, lines }
}

type TreeFn = fn(u32, &[u64]) -> Option<u64>;
type BatchFn = fn(&[u64; 8], &[u64; 8], &[[u64; 20]; 8]) -> [u64; 8];
type BlockFn = fn(u16, &[u8; 64]) -> [u8; 64];
type LimbFn = fn(&[u64; 4], &[u64; 4]) -> [u64; 8];
type LineFn = fn(&[u64; 3], u64) -> [u64; 3];

/// The number of P15-P20 cases on which the subjects disagree with the generated code
/// (per program), stopping at the first disagreement of each.
fn disagreements(cs: &Cases, tree: TreeFn, batch: BatchFn, block: BlockFn, limb: LimbFn, line: LineFn) -> [(&'static str, Option<String>, usize); 5] {
    use cgen::probe as g;
    let mut out = [("P15", None, 0), ("P16", None, 0), ("P17", None, 0), ("P18", None, 0), ("P20", None, 0)];
    for (h, xs) in &cs.trees {
        out[0].2 += 1;
        if g::tree_root(*h, xs) != tree(*h, xs) {
            out[0].1 = Some(format!("tree_root height {h}, {} leaves: gen {:?} subject {:?}", xs.len(), g::tree_root(*h, xs), tree(*h, xs)));
            break;
        }
    }
    for (l, i, s) in &cs.batches {
        out[1].2 += 1;
        if g::batch_roots(l, i, s) != batch(l, i, s) {
            out[1].1 = Some(format!("batch_roots differs (leaves {l:x?})"));
            break;
        }
    }
    for (c, b) in &cs.blocks {
        out[2].2 += 1;
        if g::gf16_mul_block(*c, b) != block(*c, b) {
            out[2].1 = Some(format!("gf16_mul_block differs for c = {c:#06x}"));
            break;
        }
    }
    for (a, b) in &cs.limbs {
        out[3].2 += 1;
        if g::mul_carry(a, b) != limb(a, b) {
            out[3].1 = Some(format!("mul_carry differs on {a:x?} * {b:x?}"));
            break;
        }
        const M: u64 = (1 << 28) - 1;
        let (am, bm): ([u64; 4], [u64; 4]) = (core::array::from_fn(|i| a[i] & M), core::array::from_fn(|i| b[i] & M));
        // SAFETY: masked limbs are < 2^28
        let gl = unsafe { g::mul_carry_limbs(&am, &bm) };
        if gl != ideal::mul_carry_limbs(&am, &bm) || gl != ideal::mul_carry_exact(a, b) {
            out[3].1 = Some(format!("mul_carry_limbs differs on {am:x?} * {bm:x?} (from the ideal or the exact product)"));
            break;
        }
    }
    for (a, c) in &cs.lines {
        out[4].2 += 1;
        if g::line_mul(a, *c) != line(a, *c) {
            out[4].1 = Some(format!("line_mul differs on {a:x?}, {c:#x}"));
            break;
        }
    }
    out
}

fn check_p15_p20(cs: &Cases) {
    use cgen_o1::probe as o;
    for (subject, d) in [
        ("ideal", disagreements(cs, ideal::tree_root, ideal::batch_roots, ideal::gf16_mul_block, ideal::mul_carry, ideal::line_mul)),
        ("O1 emission", disagreements(cs, o::tree_root, o::batch_roots, o::gf16_mul_block, o::mul_carry, o::line_mul)),
    ] {
        for (p, bad, n) in &d {
            assert!(bad.is_none(), "{p}: the {subject} disagrees with the current emission: {}", bad.as_deref().unwrap());
            print!("{p} {n} ");
        }
        println!("cases: the {subject} agrees with the current emission");
    }
    // P18's timed kernel of the O1 emission (the ideal's is checked in `disagreements`)
    const M: u64 = (1 << 28) - 1;
    for (a, b) in &cs.limbs {
        let (am, bm): ([u64; 4], [u64; 4]) = (core::array::from_fn(|i| a[i] & M), core::array::from_fn(|i| b[i] & M));
        // SAFETY: masked limbs are < 2^28
        let (g, ol) = unsafe { (cgen::probe::mul_carry_limbs(&am, &bm), o::mul_carry_limbs(&am, &bm)) };
        assert_eq!(g, ol, "P18 mul_carry_limbs: the O1 emission disagrees on {am:x?} * {bm:x?}");
    }
    println!("P18 mul_carry_limbs: {} masked limb pairs, the O1 emission agrees with the current emission", cs.limbs.len());
}

fn check_reject(cs: &Cases) {
    use ideal::reject as rj;
    let runs: [(&str, [bool; 5], [(&str, Option<String>, usize); 5]); 6] = [
        ("P15 leaf count unchecked", [true, false, false, false, false], disagreements(cs, rj::tree_root, ideal::batch_roots, ideal::gf16_mul_block, ideal::mul_carry, ideal::line_mul)),
        ("P15 one leaf short accepted", [true, false, false, false, false], disagreements(cs, rj::tree_root_len, ideal::batch_roots, ideal::gf16_mul_block, ideal::mul_carry, ideal::line_mul)),
        ("P16 wrong index bit", [false, true, false, false, false], disagreements(cs, ideal::tree_root, rj::batch_roots, ideal::gf16_mul_block, ideal::mul_carry, ideal::line_mul)),
        ("P17 wrong polynomial", [false, false, true, false, false], disagreements(cs, ideal::tree_root, ideal::batch_roots, rj::gf16_mul_block, ideal::mul_carry, ideal::line_mul)),
        ("P18 last carry dropped", [false, false, false, true, false], disagreements(cs, ideal::tree_root, ideal::batch_roots, ideal::gf16_mul_block, rj::mul_carry, ideal::line_mul)),
        ("P20 a[2] dropped", [false, false, false, false, true], disagreements(cs, ideal::tree_root, ideal::batch_roots, ideal::gf16_mul_block, ideal::mul_carry, rj::line_mul)),
    ];
    for (name, expect, d) in &runs {
        for (k, (p, bad, n)) in d.iter().enumerate() {
            if expect[k] {
                assert!(bad.is_some(), "check-reject: {name}: the checks did NOT catch the must-reject variant ({n} cases)");
                println!("check-reject: {name}: caught after {n} case(s): {}", bad.as_deref().unwrap());
            } else {
                assert!(bad.is_none(), "check-reject: {name}: {p} disagrees although it was not mutated: {}", bad.as_deref().unwrap());
            }
        }
    }
    println!("check-reject: all {} must-reject variants of P15-P20 are caught by the checks", runs.len());
}

// ------------------------------------------------------------------------------------ bench

/// The recorded generated/ideal ns per (program, input): `recorded.tsv` next to this crate,
/// read at run time so that re-recording never changes the binary (P1-P14: when the corpus was
/// designed, research/optdesign/run_corpus1.txt, design §2.3; P15-P20: the O1 emission, in the
/// harness composition named by the file's `# composition` line, which `run.sh` checks).
fn recorded(label: &str, input: &str) -> Option<(f64, f64)> {
    static T: std::sync::OnceLock<Vec<(String, String, f64, f64)>> = std::sync::OnceLock::new();
    let t = T.get_or_init(|| {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/recorded.tsv");
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        text.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let f: Vec<&str> = l.split('\t').collect();
                assert!(f.len() >= 4, "{path}: bad line `{l}`");
                (f[0].to_string(), f[1].to_string(), f[2].parse().expect("generated ns"), f[3].parse().expect("ideal ns"))
            })
            .collect()
    });
    t.iter().find(|(l, i, _, _)| l == label && i == input).map(|(_, _, g, i)| (*g, *i))
}

struct Row {
    program: String,
    what: String,
    input: String,
    /// (median, min) ns per call of the current emission, the O1 emission and the ideal.
    generated: (f64, f64),
    o1: (f64, f64),
    ideal: (f64, f64),
}

struct Bench {
    rounds: usize,
    only: Option<Vec<String>>,
    rows: Vec<Row>,
}

impl Bench {
    fn wants(&self, p: &str) -> bool {
        self.only.as_ref().is_none_or(|o| o.iter().any(|x| x == p))
    }

    /// Same-binary timing of the three subjects (current emission, O1 emission, ideal):
    /// `rounds` rounds, the order rotated each round; the value of each subject is the median of
    /// its per-round medians (and the minimum of its minima).
    fn ab(&mut self, program: &str, what: &str, input: &str, per: usize, mut g: impl FnMut(), mut o: impl FnMut(), mut i: impl FnMut()) {
        if !self.wants(program) {
            return;
        }
        let mut per_round: [Vec<f64>; 3] = [vec![], vec![], vec![]];
        let mut mins = [f64::MAX; 3];
        for r in 0..self.rounds {
            for k in 0..3 {
                let j = (k + r) % 3;
                let m = match j {
                    0 => measure(per, &mut g),
                    1 => measure(per, &mut o),
                    _ => measure(per, &mut i),
                };
                per_round[j].push(m.0);
                mins[j] = mins[j].min(m.1);
            }
        }
        let [gs, os, is] = per_round;
        let row = Row { program: program.into(), what: what.into(), input: input.into(), generated: (med(gs), mins[0]), o1: (med(os), mins[1]), ideal: (med(is), mins[2]) };
        let ratio = row.generated.0 / row.ideal.0;
        let recs = match recorded(program, input) {
            Some((g, i)) => {
                let r0 = g / i;
                format!("{r0:.2}x | {:+.1}%", (row.o1.0 / row.ideal.0 / r0 - 1.0) * 100.0)
            }
            None => "— | —".into(),
        };
        println!(
            "| {program} {what} | {input} | {:.2} / {:.2} | {:.2} / {:.2} | {:.2} / {:.2} | {ratio:.2}x | {:.3}x | {recs} |",
            row.generated.0,
            row.generated.1,
            row.o1.0,
            row.o1.1,
            row.ideal.0,
            row.ideal.1,
            row.o1.0 / row.generated.0
        );
        self.rows.push(row);
    }
}

/// `b.ab(..)` with the same body timed for the current emission (`cgen::probe`), the O1
/// emission (`cgen_o1::probe`) and the ideal (`ideal`), the probe module named `$m` in the body.
macro_rules! ab3 {
    ($b:expr, $p:expr, $what:expr, $label:expr, $per:expr, |$m:ident| $body:expr) => {{
        #[allow(unused_unsafe)]
        $b.ab(
            $p,
            $what,
            $label,
            $per,
            || {
                use cgen::probe as $m;
                $body
            },
            || {
                use cgen_o1::probe as $m;
                $body
            },
            || {
                use ideal as $m;
                $body
            },
        );
    }};
}

fn bench(b: &mut Bench) {
    let mut r = Rng(0xabcdef);
    const B: usize = 256;
    let bits: Vec<u64> = (0..B).map(|_| r.bits()).collect();
    let small: Vec<u64> = (0..B).map(|_| r.below(34)).collect();
    let tzs: Vec<u64> = (0..B).map(|_| (r.next() | 1) << r.below(64)).collect();
    println!("\n## general corpus: current emission vs O1 emission vs ideal, one binary (ns per call, median of {} rotating rounds / min; {B} inputs per batch)\n", b.rounds);
    println!("`O1 / current` is the gain over the O1 emission in this binary (where both compiled to the same code, it is code placement alone: see gains.md). `recorded` is generated / ideal from recorded.tsv (P1-P14: design §2.3; P15+: the O1 emission when recorded); `Δ` compares this binary's O1 emission / ideal with it.\n");
    println!("| program | input | current | O1 emission | ideal | current / ideal | O1 / current | recorded | Δ O1 ratio vs recorded |\n| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    macro_rules! u1 {
        ($p:expr, $what:expr, $label:expr, $xs:expr, $f:ident) => {{
            let xs = &$xs;
            ab3!(b, $p, $what, $label, xs.len(), |m| for &x in xs.iter() { bb(m::$f(bb(x))); });
        }};
    }
    u1!("P1", "bit_length", "uniform bit length", bits, bit_length);
    u1!("P1", "bit_length", "x < 34", small, bit_length);
    u1!("P2", "floor_pow2", "uniform bit length", bits, floor_pow2);
    u1!("P2", "floor_pow2", "x < 34", small, floor_pow2);
    u1!("P3", "popcount_loop", "uniform bit length", bits, popcount_loop);
    let fb: Vec<(u64, u64)> = (0..B).map(|_| { let n = r.bits().max(1); (n, r.below(n)) }).collect();
    let fbs: Vec<(u64, u64)> = (0..B).map(|_| { let n = 1 + r.below(33); (n, r.below(n)) }).collect();
    for (label, ps) in [("n uniform bit length", &fb), ("n <= 33", &fbs)] {
        ab3!(b, "P4", "find_block", label, ps.len(), |m| for &(n, i) in ps.iter() { bb(m::find_block(bb(n), bb(i))); });
    }
    let mk = |r: &mut Rng, f: &dyn Fn(&mut Rng) -> u64| -> (Vec<u8>, Vec<usize>) {
        let mut buf = Vec::new();
        let mut offs = Vec::new();
        for _ in 0..B {
            offs.push(buf.len());
            enc(f(r), &mut buf);
            buf.push(0x55);
        }
        buf.extend_from_slice(&[0u8; 16]);
        (buf, offs)
    };
    for (label, f) in [("1 byte", &(|r: &mut Rng| r.below(128)) as &dyn Fn(&mut Rng) -> u64), ("uniform bit length (1-10 B)", &|r: &mut Rng| r.bits()), ("9-10 bytes", &|r: &mut Rng| r.next() | (1 << 62))] {
        let (buf, offs) = mk(&mut r, f);
        ab3!(b, "P5", "leb128", label, offs.len(), |m| for &o in offs.iter() { bb(m::leb128(bb(&buf[o..]))); });
    }
    for (label, f) in [("4 x 1 byte", &(|r: &mut Rng| r.below(128)) as &dyn Fn(&mut Rng) -> u64), ("4 x uniform bit length", &|r: &mut Rng| r.bits())] {
        let mut buf = Vec::new();
        let mut offs = Vec::new();
        for _ in 0..B {
            offs.push(buf.len());
            for _ in 0..4 {
                enc(f(&mut r), &mut buf);
            }
        }
        buf.extend_from_slice(&[0u8; 16]);
        ab3!(b, "P5b", "header4", label, offs.len(), |m| for &o in offs.iter() { bb(m::header4(bb(&buf[o..]))); });
    }
    u1!("P6", "varint_len", "uniform bit length", bits, varint_len);
    u1!("P6", "varint_len", "x < 34", small, varint_len);
    let pool: Vec<u64> = (0..512).map(|_| r.next()).collect();
    for (label, hi) in [("segments 0-3 words", 4u64), ("segments 0-60 words", 61)] {
        let cs: Vec<(usize, usize, u64)> = (0..64).map(|_| (r.below(hi) as usize, r.below(hi) as usize, r.next())).collect();
        ab3!(b, "P7", "concat_fold", label, cs.len(), |m| for &(x, y, mid) in cs.iter() { bb(m::concat_fold(bb(&pool[..x]), bb(mid), bb(&pool[256..256 + y]))); });
    }
    let mut t = [0u32; 64];
    for x in t.iter_mut() {
        *x = r.next() as u32;
    }
    let ks: Vec<usize> = (0..B).map(|_| r.below(65) as usize).collect();
    ab3!(b, "P8", "prefix_query", "k uniform 0..=64", ks.len(), |m| for &k in ks.iter() { bb(m::prefix_query(bb(&t), bb(k))); });
    let big: Vec<u32> = (0..4096).map(|_| r.next() as u32).collect();
    for (label, l) in [("16 words", 16usize), ("4096 words", 4096)] {
        ab3!(b, "P9", "min_max (control)", label, 1, |m| { bb(m::min_max(bb(&big[..l]))); });
        ab3!(b, "P10", "sum_small", label, 1, |m| { bb(m::sum_small(bb(&big[..l]))); });
    }
    u1!("P11", "trailing_zeros_loop", "uniform ctz", tzs, trailing_zeros_loop);
    for (label, len, pos) in [("16 B, stop at 0-9", 16usize, 10u64), ("256 B, stop uniform", 256, 256)] {
        let bufs: Vec<Vec<u8>> = (0..64).map(|_| { let p = r.below(pos) as usize; (0..len).map(|k| if k == p { 0x11 } else if k < p { 0x80 | r.next() as u8 } else { r.next() as u8 }).collect() }).collect();
        ab3!(b, "P12", "first_small", label, bufs.len(), |m| for s in bufs.iter() { bb(m::first_small(bb(&s[..]))); });
    }
    let rk: Vec<(u64, u32)> = (0..B).map(|_| (r.next(), r.below(64) as u32)).collect();
    ab3!(b, "P13", "rank_above", "uniform", rk.len(), |m| for &(n, k) in rk.iter() { bb(m::rank_above(bb(n), bb(k))); });
    let ns: Vec<u32> = (0..B).map(|_| r.below(1 << 16) as u32).collect();
    ab3!(b, "P14", "series (control)", "n < 2^16", ns.len(), |m| for &n in ns.iter() { bb(m::series(bb(n))); });
    // P15-P20
    for (label, h) in [("16 leaves", 4u32), ("256 leaves", 8)] {
        let leaves: Vec<u64> = (0..1usize << h).map(|_| r.next()).collect();
        ab3!(b, "P15", "tree_root", label, 1, |m| { bb(m::tree_root(bb(h), bb(&leaves))); });
    }
    let batches: Vec<([u64; 8], [u64; 8], Box<[[u64; 20]; 8]>)> = (0..16).map(|_| (core::array::from_fn(|_| r.next()), core::array::from_fn(|_| r.below(1 << 20)), Box::new(core::array::from_fn(|_| core::array::from_fn(|_| r.next()))))).collect();
    ab3!(b, "P16", "batch_roots", "K = 8, 20 levels", batches.len(), |m| for (l, i, s) in batches.iter() { bb(m::batch_roots(bb(l), bb(i), bb(s))); });
    let blocks: Vec<[u8; 64]> = (0..B).map(|_| core::array::from_fn(|_| r.next() as u8)).collect();
    let c = 0x3039u16;
    ab3!(b, "P17", "gf16_mul_block", "256 blocks (16 KiB), ns per 64 B block", blocks.len(), |m| for x in blocks.iter() { bb(m::gf16_mul_block(bb(c), bb(x))); });
    // the precondition-bounded kernel (limbs < 2^28), where rustc cannot see the bounds
    let limbs: Vec<([u64; 4], [u64; 4])> = (0..B).map(|_| (core::array::from_fn(|_| r.below(1 << 28)), core::array::from_fn(|_| r.below(1 << 28)))).collect();
    // SAFETY: every limb is < 2^28
    ab3!(b, "P18", "mul_carry_limbs", if overflow_checks() { "256 inputs, overflow-checks = true" } else { "256 inputs" }, limbs.len(), |m| for (x, y) in limbs.iter() { bb(unsafe { m::mul_carry_limbs(bb(x), bb(y)) }); });
    let lines: Vec<([u64; 3], u64)> = (0..B).map(|_| (core::array::from_fn(|_| r.next()), r.next())).collect();
    ab3!(b, "P20", "line_mul", "256 inputs", lines.len(), |m| for (a, c) in lines.iter() { bb(m::line_mul(bb(a), bb(*c))); });
}

/// Plan O2 (E0, checked-arithmetic printing): P18's kernel as emitted now (proven operations
/// through the `crate::__rt::chk` helpers), as emitted at O1 (checked operators,
/// `baselines/o1-gen.rs`) and hand-written with wrapping operations (`ideal`), on the same 256
/// masked inputs, in rotating rounds — checks first. Under `overflow-checks = true` (the
/// `release-oc` binary) the O1 printing pays rustc's overflow checks and the current emission
/// does not (the E0 target: O1 / current ≥ 1.5); in `release` all three compile alike.
fn e0(rounds: usize, json: Option<String>) {
    let mut r = Rng(0xe0e0);
    const M: u64 = (1 << 28) - 1;
    let limbs: Vec<([u64; 4], [u64; 4])> = (0..256).map(|_| (core::array::from_fn(|_| r.below(1 << 28)), core::array::from_fn(|_| r.below(1 << 28)))).collect();
    // checks: the three subjects agree with the exact product on edge and random masked limbs
    let mut n = 0u64;
    for t in 0..200_000u64 {
        let pick = |r: &mut Rng| match r.below(4) {
            0 => M,
            1 => 0,
            2 => M ^ (1 << r.below(28)),
            _ => r.next() & M,
        };
        let a: [u64; 4] = core::array::from_fn(|_| if t % 2 == 0 { pick(&mut r) } else { r.next() & M });
        let b: [u64; 4] = core::array::from_fn(|_| if t % 2 == 0 { pick(&mut r) } else { r.next() & M });
        // SAFETY: masked limbs are < 2^28
        let (g, o) = unsafe { (cgen::probe::mul_carry_limbs(&a, &b), cgen_o1::probe::mul_carry_limbs(&a, &b)) };
        assert!(g == o && g == ideal::mul_carry_limbs(&a, &b) && g == ideal::mul_carry_exact(&a, &b), "P18 subjects disagree on {a:x?} * {b:x?}");
        n += 1;
    }
    println!("check e0: {n} masked limb pairs, the current emission, the O1 emission and the ideal agree with the exact product");
    type F = unsafe fn(&[u64; 4], &[u64; 4]) -> [u64; 8];
    let subjects: [(&str, F); 3] = [("current (E0)", cgen::probe::mul_carry_limbs), ("O1 printing", cgen_o1::probe::mul_carry_limbs), ("ideal (wrapping)", ideal::mul_carry_limbs)];
    let mut per: Vec<Vec<f64>> = vec![vec![]; 3];
    let mut mins = [f64::MAX; 3];
    for round in 0..rounds {
        for jj in 0..3 {
            let j = (jj + round) % 3;
            let f = subjects[j].1;
            // SAFETY: every limb is < 2^28
            let m = measure(limbs.len(), || for (x, y) in limbs.iter() { bb(unsafe { f(bb(x), bb(y)) }); });
            per[j].push(m.0);
            mins[j] = mins[j].min(m.1);
        }
    }
    let ns: Vec<f64> = per.into_iter().map(med).collect();
    let oc = overflow_checks();
    println!("\n## P18 mul_carry_limbs, E0 (plan O2): {} ({rounds} rotating rounds; median of per-round medians / min, ns per call; 256 inputs)\n", if oc { "overflow-checks = true" } else { "no overflow checks" });
    println!("| subject | ns | min ns | vs current |\n| --- | ---: | ---: | ---: |");
    for j in 0..3 {
        println!("| {} | {:.2} | {:.2} | {:.3} |", subjects[j].0, ns[j], mins[j], ns[j] / ns[0]);
    }
    println!("\nE0 gain (O1 printing / current): {:.2}x{}", ns[1] / ns[0], if oc { " (target >= 1.5x under overflow checks)" } else { "" });
    if let Some(p) = json {
        let rows: Vec<String> = (0..3).map(|j| format!("  {{\"subject\": \"{}\", \"ns\": {:.4}, \"min_ns\": {:.4}}}", subjects[j].0, ns[j], mins[j])).collect();
        std::fs::write(&p, format!("{{\"arch\": \"{}\", \"overflow_checks\": {oc}, \"rounds\": {rounds}, \"rows\": [\n{}\n]}}\n", std::env::consts::ARCH, rows.join(",\n"))).expect("write --json");
    }
}

/// Whether this binary was built with overflow checks (the `release-oc` profile).
fn overflow_checks() -> bool {
    static OC: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OC.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let x: u8 = bb(255);
        let r = std::panic::catch_unwind(|| bb(x) + bb(1)).is_err();
        std::panic::set_hook(prev);
        r
    })
}

fn json_rows(b: &Bench) -> String {
    let rows: Vec<String> = b
        .rows
        .iter()
        .map(|r| {
            let rec = recorded(&r.program, &r.input).map_or("null".to_string(), |(g, i)| format!("{:.4}", g / i));
            format!(
                "  {{\"program\": \"{}\", \"function\": \"{}\", \"input\": \"{}\", \"generated_ns\": {:.4}, \"generated_min_ns\": {:.4}, \"o1_ns\": {:.4}, \"o1_min_ns\": {:.4}, \"ideal_ns\": {:.4}, \"ideal_min_ns\": {:.4}, \"ratio\": {:.4}, \"o1_ratio\": {:.4}, \"gain\": {:.4}, \"recorded_ratio\": {rec}}}",
                r.program,
                r.what,
                r.input,
                r.generated.0,
                r.generated.1,
                r.o1.0,
                r.o1.1,
                r.ideal.0,
                r.ideal.1,
                r.generated.0 / r.ideal.0,
                r.o1.0 / r.ideal.0,
                r.o1.0 / r.generated.0
            )
        })
        .collect();
    format!("{{\"arch\": \"{}\", \"overflow_checks\": {}, \"rounds\": {}, \"rows\": [\n{}\n]}}\n", std::env::consts::ARCH, overflow_checks(), b.rounds, rows.join(",\n"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map(|s| s.as_str()).unwrap_or("all");
    let mut rounds = 3usize;
    let mut only = None;
    let mut json = None;
    let mut k = 2;
    while k < args.len() {
        match args[k].as_str() {
            "quick" => unsafe {
                WARM_MS = 40;
                SAMPLES = 11;
                SAMPLE_MS = 3;
            },
            "--rounds" => {
                k += 1;
                rounds = args[k].parse().expect("--rounds N");
            }
            "--only" => {
                k += 1;
                only = Some(args[k].split(',').map(|s| s.to_string()).collect());
            }
            "--json" => {
                k += 1;
                json = Some(args[k].clone());
            }
            a => panic!("unknown argument {a}"),
        }
        k += 1;
    }
    assert!(rounds >= 1);
    println!("target: {} {}{}", std::env::consts::ARCH, if cfg!(target_feature = "avx512f") { "(avx512f)" } else if cfg!(target_feature = "bmi2") { "(bmi2)" } else { "" }, if overflow_checks() { " overflow-checks" } else { "" });
    if what == "all" || what == "check" || what == "check-reject" {
        let t = Instant::now();
        let cs = cases();
        if what != "check-reject" {
            check_p1_p14_current();
            check_p1_p14_o1();
            check_p15_p20(&cs);
        }
        if what != "check" {
            check_reject(&cs);
        }
        println!("checks: {:.1} s", t.elapsed().as_secs_f64());
    }
    if what == "e0" {
        e0(rounds, json.clone());
    }
    if what == "all" || what == "bench" {
        let mut b = Bench { rounds, only, rows: vec![] };
        bench(&mut b);
        if let Some(p) = json {
            std::fs::write(&p, json_rows(&b)).expect("write --json");
        }
    }
}
