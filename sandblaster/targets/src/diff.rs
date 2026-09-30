//! Differential-testing harness: input generators with corner values,
//! campaign drivers and outcome reports (DESIGN.md §9.2 "Validation").
//!
//! §9.2 requires every model to be compared against the real intrinsic on at
//! least 10^7 random inputs **plus corner values** (0, ~0, 0x8000_0000,
//! single-bit words), with every immediate tested exhaustively. This module is
//! architecture-independent: a campaign compares two closures, a `model` and a
//! `reference` (the hardware intrinsic in [`crate::hw`], or a FIPS 180-4
//! formulation in [`crate::consistency`]) and counts mismatches.
//!
//! Inputs come from [`Sample`]: every lane type has a list of corner values and
//! a random generator that draws a lane from the corner list with probability
//! 1/8 (so corner *combinations* across lanes and arguments are frequent in
//! the random phase), otherwise uniformly. A campaign runs
//!
//! 1. a **corner phase**: for two-argument operations whose corner lists are
//!    small, the full cartesian product of corners; otherwise every corner of
//!    every argument position with the other arguments random (4 repetitions),
//!    plus the cartesian product of the first four corners of each position;
//! 2. a **random phase** of `n` cases;
//!
//! and, for models with an immediate, both phases for **every** immediate in
//! the accepted range.
//!
//! The reference side runs behind `std::hint::black_box` on every input and
//! on its result, so release-mode campaigns really execute the instruction on
//! run-time data instead of letting LLVM fold `model == intrinsic` for the
//! intrinsics that stdarch implements as generic LLVM IR.
#![forbid(unsafe_code)]

use crate::rng::Rng;
use std::fmt::Debug;
use std::ops::RangeInclusive;

/// An optimization barrier for one reference input: the reference (the real
/// intrinsic) must execute on values the compiler cannot see, so that LLVM
/// cannot prove `model(x) == reference(x)` symbolically (e.g. by vectorizing
/// the scalar model into the same IR as a generic `simd_add` intrinsic) and
/// fold the comparison away in release builds.
#[inline(always)]
fn bb<T>(x: T) -> T {
    std::hint::black_box(x)
}

/// Run the reference behind an optimization barrier on its result as well.
#[inline(always)]
fn opaque<R>(f: impl FnOnce() -> R) -> R {
    std::hint::black_box(f())
}

/// Input types the campaigns can generate.
pub trait Sample: Copy + Debug {
    /// A random value, lanes drawn from [`Sample::corners`]-style corner
    /// values with probability 1/8 each.
    fn random(rng: &mut Rng) -> Self;
    /// Corner values, most important first (the first four are combined
    /// exhaustively across argument positions).
    fn corners() -> Vec<Self>;
}

/// Corner words for `u32` lanes: 0, ~0, 0x8000_0000, 1, 0x7fff_ffff, then the
/// remaining single-bit words and a few byte patterns.
pub const WORD_CORNERS: [u32; 42] = {
    let mut v = [0u32; 42];
    let head = [0, u32::MAX, 0x8000_0000, 1, 0x7fff_ffff];
    let tail = [
        0xffff_fffe,
        0x0000_ffff,
        0xffff_0000,
        0x00ff_00ff,
        0xff00_ff00,
        0x0123_4567,
        0x89ab_cdef,
    ];
    let mut i = 0;
    while i < 5 {
        v[i] = head[i];
        i += 1;
    }
    let mut k = 1;
    while k < 31 {
        v[4 + k] = 1 << k;
        k += 1;
    }
    let mut j = 0;
    while j < 7 {
        v[35 + j] = tail[j];
        j += 1;
    }
    v
};

/// Corner bytes: 0, 0xff, 0x80, 1, 0x7f, the other single-bit bytes and a
/// few nibble patterns.
pub const BYTE_CORNERS: [u8; 16] = [
    0, 0xff, 0x80, 1, 0x7f, 2, 4, 8, 16, 32, 64, 0x0f, 0xf0, 0xfe, 0x8f, 0x70,
];

/// [`WORD_CORNERS`] as a vector.
pub fn word_corners() -> Vec<u32> {
    WORD_CORNERS.to_vec()
}

/// [`BYTE_CORNERS`] as a vector.
pub fn byte_corners() -> Vec<u8> {
    BYTE_CORNERS.to_vec()
}

impl Sample for u32 {
    fn random(rng: &mut Rng) -> Self {
        let r = rng.next_u64();
        if r & 7 == 0 {
            WORD_CORNERS[((r >> 3) % WORD_CORNERS.len() as u64) as usize]
        } else {
            (r >> 32) as u32
        }
    }
    fn corners() -> Vec<Self> {
        word_corners()
    }
}

impl Sample for u8 {
    fn random(rng: &mut Rng) -> Self {
        let r = rng.next_u64();
        if r & 7 == 0 {
            BYTE_CORNERS[((r >> 3) % BYTE_CORNERS.len() as u64) as usize]
        } else {
            (r >> 56) as u8
        }
    }
    fn corners() -> Vec<Self> {
        byte_corners()
    }
}

impl Sample for u16 {
    fn random(rng: &mut Rng) -> Self {
        let r = rng.next_u64();
        if r & 7 == 0 {
            MASK16_CORNERS[((r >> 3) % MASK16_CORNERS.len() as u64) as usize]
        } else {
            (r >> 48) as u16
        }
    }
    fn corners() -> Vec<Self> {
        MASK16_CORNERS.to_vec()
    }
}

/// Corner values for 16-bit words and `__mmask16` opmasks: none / all / the
/// sign bit / one element, alternating elements, halves, every single bit.
pub const MASK16_CORNERS: [u16; 24] = {
    let mut v = [0u16; 24];
    let head = [0, u16::MAX, 0x8000, 1, 0x5555, 0xaaaa, 0x00ff, 0xff00];
    let mut i = 0;
    while i < 8 {
        v[i] = head[i];
        i += 1;
    }
    let mut k = 0;
    while k < 16 {
        v[8 + k] = 1 << k;
        k += 1;
    }
    v
};

impl Sample for u64 {
    fn random(rng: &mut Rng) -> Self {
        let r = rng.next_u64();
        if r & 7 == 0 {
            let c = <i64 as Sample>::corners();
            c[((r >> 3) % c.len() as u64) as usize] as u64
        } else {
            rng.next_u64()
        }
    }
    fn corners() -> Vec<Self> {
        <i64 as Sample>::corners().into_iter().map(|x| x as u64).collect()
    }
}

impl Sample for i32 {
    fn random(rng: &mut Rng) -> Self {
        u32::random(rng) as i32
    }
    fn corners() -> Vec<Self> {
        word_corners().into_iter().map(|w| w as i32).collect()
    }
}

impl Sample for i64 {
    fn random(rng: &mut Rng) -> Self {
        ((u32::random(rng) as u64) << 32 | u32::random(rng) as u64) as i64
    }
    fn corners() -> Vec<Self> {
        let mut v = vec![0i64, -1, i64::MIN, 1, i64::MAX];
        for k in 1..63 {
            v.push(1i64 << k);
        }
        v.push(0x0c0d_0e0f_0809_0a0b);
        v.push(0x0405_0607_0001_0203);
        v
    }
}

impl Sample for [u32; 4] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u32::random(rng))
    }
    fn corners() -> Vec<Self> {
        let words = word_corners();
        // The four most important corners are splats, so the exhaustive
        // combination of "first four" covers 0 / ~0 / 0x8000_0000 / 1 lanes.
        let mut v: Vec<[u32; 4]> = words.iter().map(|&w| [w; 4]).collect();
        for lane in 0..4 {
            for w in [u32::MAX, 0x8000_0000, 1, 0x7fff_ffff] {
                let mut x = [0u32; 4];
                x[lane] = w;
                v.push(x);
                let mut y = [u32::MAX; 4];
                y[lane] = !w;
                v.push(y);
            }
        }
        v.push([0, 1, 2, 3]);
        v.push([u32::MAX, 0, u32::MAX, 0]);
        v.push([0x8000_0000, 0x7fff_ffff, 0x8000_0000, 0x7fff_ffff]);
        v
    }
}

impl Sample for [u16; 8] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u16::random(rng))
    }
    fn corners() -> Vec<Self> {
        // Splats of every 16-bit corner, then single-lane patterns (the
        // nibble masks of a byte compare: 0x00ff / 0xff00 / 0xffff in one lane).
        let mut v: Vec<[u16; 8]> = MASK16_CORNERS.iter().map(|&w| [w; 8]).collect();
        for lane in 0..8 {
            for w in [0xffffu16, 0x00ff, 0xff00, 0x8000, 1] {
                let mut x = [0u16; 8];
                x[lane] = w;
                v.push(x);
            }
        }
        v.push(core::array::from_fn(|i| i as u16));
        v.push(core::array::from_fn(|i| if i % 2 == 0 { 0xffff } else { 0 }));
        v
    }
}

impl Sample for [u64; 2] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u64::random(rng))
    }
    fn corners() -> Vec<Self> {
        let words = <u64 as Sample>::corners();
        let mut v: Vec<[u64; 2]> = words.iter().map(|&w| [w; 2]).collect();
        for w in [u64::MAX, 1 << 63, 1, i64::MAX as u64, 0xffff_ffff, 0x1_0000_0000] {
            v.push([w, 0]);
            v.push([0, w]);
            v.push([w, !w]);
        }
        v
    }
}

impl Sample for [u32; 2] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u32::random(rng))
    }
    fn corners() -> Vec<Self> {
        let words = word_corners();
        let mut v: Vec<[u32; 2]> = words.iter().map(|&w| [w; 2]).collect();
        for w in [u32::MAX, 0x8000_0000, 1, 0x7fff_ffff] {
            v.push([w, 0]);
            v.push([0, w]);
            v.push([w, !w]);
        }
        v
    }
}

fn byte_vector_corners<const N: usize>() -> Vec<[u8; N]> {
    let mut v: Vec<[u8; N]> = byte_corners().iter().map(|&b| [b; N]).collect();
    v.push(core::array::from_fn(|i| i as u8));
    v.push(core::array::from_fn(|i| (N - 1 - i) as u8));
    // The byte-swap-in-32-bit-lanes pattern (vrev32 / pshufb MASK shape).
    v.push(core::array::from_fn(|i| (i ^ 3) as u8));
    // Control-byte patterns for pshufb: high bit set in alternate lanes, and
    // indices with bits 6..4 set (which PSHUFB ignores).
    v.push(core::array::from_fn(|i| {
        if i % 2 == 0 { 0x80 } else { i as u8 }
    }));
    v.push(core::array::from_fn(|i| 0x70 | i as u8));
    v.push(core::array::from_fn(|i| 0x80 | i as u8));
    for pos in 0..N {
        let mut x = [0u8; N];
        x[pos] = 0x80;
        v.push(x);
        let mut y = [0u8; N];
        y[pos] = 0xff;
        v.push(y);
    }
    v
}

/// Corner vectors for the 256/512-bit models (`[u8; 32]`, and appended to the
/// `[u8; 64]` block corners): byte splats; for every element width (16, 32,
/// 64 bits) the sign bit, the largest signed value and 1 in every element and
/// alternating all-ones / zero elements; index patterns for the permutes and
/// shuffles (identity, reversal, the table-select bit 6 of VPERMI2B, the
/// zeroing bit 7 and the ignored bits 6..4 of VPSHUFB, dword/qword lane
/// indices with junk above); and single `0x80` / `0xff` bytes at element and
/// lane boundaries.
pub fn wide_vector_corners<const N: usize>() -> Vec<[u8; N]> {
    let mut v: Vec<[u8; N]> = byte_corners().iter().map(|&b| [b; N]).collect();
    for w in [2usize, 4, 8] {
        v.push(core::array::from_fn(|i| if i % w == w - 1 { 0x80 } else { 0 }));
        v.push(core::array::from_fn(|i| if i % w == w - 1 { 0x7f } else { 0xff }));
        v.push(core::array::from_fn(|i| if i % w == 0 { 1 } else { 0 }));
        v.push(core::array::from_fn(|i| if (i / w) % 2 == 0 { 0xff } else { 0 }));
    }
    v.push(core::array::from_fn(|i| i as u8));
    v.push(core::array::from_fn(|i| (N - 1 - i) as u8));
    v.push(core::array::from_fn(|i| (i ^ 3) as u8));
    v.push(core::array::from_fn(|i| (i as u8) | 0x40));
    v.push(core::array::from_fn(|i| (i as u8) | 0x80));
    v.push(core::array::from_fn(|i| if i % 2 == 0 { 0x80 } else { i as u8 }));
    v.push(core::array::from_fn(|i| 0x70 | (i as u8 & 0x0f)));
    v.push(core::array::from_fn(|i| if i % 4 == 0 { ((i / 4) ^ 0x0f) as u8 | 0xf0 } else { 0xff }));
    v.push(core::array::from_fn(|i| if i % 8 == 0 { ((i / 8) ^ 0x0f) as u8 } else { 0 }));
    for pos in [0usize, 1, 3, 4, 7, 8, 15, 16, 31, 32, 63] {
        if pos < N {
            let mut x = [0u8; N];
            x[pos] = 0x80;
            v.push(x);
            let mut y = [0u8; N];
            y[pos] = 0xff;
            v.push(y);
        }
    }
    v
}

impl Sample for [u8; 32] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u8::random(rng))
    }
    fn corners() -> Vec<Self> {
        wide_vector_corners::<32>()
    }
}

impl Sample for [u8; 16] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u8::random(rng))
    }
    fn corners() -> Vec<Self> {
        byte_vector_corners::<16>()
    }
}

impl Sample for [u8; 8] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u8::random(rng))
    }
    fn corners() -> Vec<Self> {
        byte_vector_corners::<8>()
    }
}

impl Sample for [u32; 8] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u32::random(rng))
    }
    fn corners() -> Vec<Self> {
        let mut v: Vec<[u32; 8]> = word_corners().iter().map(|&w| [w; 8]).collect();
        v.push(crate::fips::H0);
        v
    }
}

impl Sample for [u32; 16] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u32::random(rng))
    }
    fn corners() -> Vec<Self> {
        let mut v: Vec<[u32; 16]> = word_corners().iter().map(|&w| [w; 16]).collect();
        v.push(core::array::from_fn(|i| i as u32));
        v
    }
}

impl Sample for [u8; 64] {
    fn random(rng: &mut Rng) -> Self {
        core::array::from_fn(|_| u8::random(rng))
    }
    fn corners() -> Vec<Self> {
        let mut v: Vec<[u8; 64]> = byte_corners().iter().map(|&b| [b; 64]).collect();
        v.push(core::array::from_fn(|i| i as u8));
        // The fixed padding block of a 64-byte message (QMDB's fold shape).
        let mut pad = [0u8; 64];
        pad[0] = 0x80;
        pad[62] = 0x02;
        v.push(pad);
        // The `__m512i` corners (their byte splats are already listed).
        v.extend(wide_vector_corners::<64>().into_iter().skip(byte_corners().len()));
        v
    }
}

/// The result of one campaign (one model, or one consistency property).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Model (or property) name.
    pub name: String,
    /// Random cases run (summed over immediates).
    pub random: u64,
    /// Corner cases run (summed over immediates).
    pub corner: u64,
    /// The immediate range tested exhaustively, if the model has one.
    pub immediates: Option<RangeInclusive<i32>>,
    /// Number of cases where model and reference disagreed.
    pub mismatches: u64,
    /// The first disagreement, rendered for a bug report.
    pub first_mismatch: Option<String>,
    /// Why the campaign was not run (feature absent), if it was skipped.
    pub skipped: Option<String>,
    /// The PRNG seed (reproduces the campaign exactly).
    pub seed: u64,
}

impl Outcome {
    fn new(name: &str, seed: u64) -> Self {
        Outcome {
            name: name.to_string(),
            random: 0,
            corner: 0,
            immediates: None,
            mismatches: 0,
            first_mismatch: None,
            skipped: None,
            seed,
        }
    }

    /// A campaign that was not run, with the reason.
    pub fn skipped(name: &str, reason: impl Into<String>) -> Self {
        let mut o = Outcome::new(name, 0);
        o.skipped = Some(reason.into());
        o
    }

    /// Total cases run.
    pub fn total(&self) -> u64 {
        self.random + self.corner
    }

    /// Ran, and no case disagreed.
    pub fn passed(&self) -> bool {
        self.skipped.is_none() && self.mismatches == 0 && self.total() > 0
    }

    /// Number of immediates covered (0 if the model has none).
    pub fn immediate_count(&self) -> u64 {
        self.immediates
            .as_ref()
            .map_or(0, |r| (*r.end() as i64 - *r.start() as i64 + 1) as u64)
    }

    fn record(&mut self, corner: bool, describe: impl FnOnce() -> String) {
        self.mismatches += 1;
        if self.first_mismatch.is_none() {
            let phase = if corner { "corner" } else { "random" };
            self.first_mismatch = Some(format!(
                "{} ({phase} case, seed {:#x}): {}",
                self.name,
                self.seed,
                describe()
            ));
        }
    }

    fn count(&mut self, corner: bool) {
        if corner {
            self.corner += 1;
        } else {
            self.random += 1;
        }
    }

    /// One-line human-readable summary.
    pub fn summary(&self) -> String {
        if let Some(reason) = &self.skipped {
            return format!("{:<28} SKIPPED: {reason}", self.name);
        }
        let imm = match &self.immediates {
            Some(r) => format!(", immediates {}..={} exhaustive", r.start(), r.end()),
            None => String::new(),
        };
        let verdict = if self.passed() {
            "ok".to_string()
        } else {
            format!("{} MISMATCHES", self.mismatches)
        };
        format!(
            "{:<28} {verdict}: {} random + {} corner cases{imm}",
            self.name, self.random, self.corner
        )
    }
}

/// Assert that every outcome passed (skipped outcomes are allowed and
/// printed); panics with every failure's first mismatch otherwise.
pub fn assert_all_passed(outcomes: &[Outcome]) {
    let mut failures = Vec::new();
    for o in outcomes {
        eprintln!("{}", o.summary());
        if o.skipped.is_none() && !o.passed() {
            failures.push(
                o.first_mismatch
                    .clone()
                    .unwrap_or_else(|| format!("{}: no cases run", o.name)),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "differential failures:\n{}",
        failures.join("\n")
    );
}

/// The cartesian-product size up to which two-argument corner phases are
/// exhaustive.
pub const CARTESIAN_LIMIT: usize = 1 << 16;

/// Repetitions per (position, corner) pair in the per-position corner phase.
const CORNER_REPS: usize = 4;

/// Campaign for a unary operation.
pub fn diff1<A, R>(
    name: &str,
    n: u64,
    seed: u64,
    model: impl Fn(A) -> R,
    reference: impl Fn(A) -> R,
) -> Outcome
where
    A: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let case = |o: &mut Outcome, corner: bool, a: A| {
        o.count(corner);
        let (m, h) = (model(a), opaque(|| reference(bb(a))));
        if m != h {
            o.record(corner, || {
                format!("a = {a:?}: model {m:?} != reference {h:?}")
            });
        }
    };
    for a in A::corners() {
        case(&mut o, true, a);
    }
    for _ in 0..n {
        let a = A::random(&mut rng);
        case(&mut o, false, a);
    }
    o
}

/// Campaign for a binary operation.
pub fn diff2<A, B, R>(
    name: &str,
    n: u64,
    seed: u64,
    model: impl Fn(A, B) -> R,
    reference: impl Fn(A, B) -> R,
) -> Outcome
where
    A: Sample,
    B: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let case = |o: &mut Outcome, corner: bool, a: A, b: B| {
        o.count(corner);
        let (m, h) = (model(a, b), opaque(|| reference(bb(a), bb(b))));
        if m != h {
            o.record(corner, || {
                format!("a = {a:?}, b = {b:?}: model {m:?} != reference {h:?}")
            });
        }
    };
    let (ca, cb) = (A::corners(), B::corners());
    if ca.len() * cb.len() <= CARTESIAN_LIMIT {
        for &a in &ca {
            for &b in &cb {
                case(&mut o, true, a, b);
            }
        }
    } else {
        for &a in &ca {
            for _ in 0..CORNER_REPS {
                let b = B::random(&mut rng);
                case(&mut o, true, a, b);
            }
        }
        for &b in &cb {
            for _ in 0..CORNER_REPS {
                let a = A::random(&mut rng);
                case(&mut o, true, a, b);
            }
        }
        for &a in ca.iter().take(4) {
            for &b in cb.iter().take(4) {
                case(&mut o, true, a, b);
            }
        }
    }
    for _ in 0..n {
        let a = A::random(&mut rng);
        let b = B::random(&mut rng);
        case(&mut o, false, a, b);
    }
    o
}

/// Campaign for a ternary operation.
pub fn diff3<A, B, C, R>(
    name: &str,
    n: u64,
    seed: u64,
    model: impl Fn(A, B, C) -> R,
    reference: impl Fn(A, B, C) -> R,
) -> Outcome
where
    A: Sample,
    B: Sample,
    C: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let case = |o: &mut Outcome, corner: bool, a: A, b: B, c: C| {
        o.count(corner);
        let (m, h) = (model(a, b, c), opaque(|| reference(bb(a), bb(b), bb(c))));
        if m != h {
            o.record(corner, || {
                format!("a = {a:?}, b = {b:?}, c = {c:?}: model {m:?} != reference {h:?}")
            });
        }
    };
    let (ca, cb, cc) = (A::corners(), B::corners(), C::corners());
    for &a in &ca {
        for _ in 0..CORNER_REPS {
            let (b, c) = (B::random(&mut rng), C::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
    }
    for &b in &cb {
        for _ in 0..CORNER_REPS {
            let (a, c) = (A::random(&mut rng), C::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
    }
    for &c in &cc {
        for _ in 0..CORNER_REPS {
            let (a, b) = (A::random(&mut rng), B::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
    }
    for &a in ca.iter().take(4) {
        for &b in cb.iter().take(4) {
            for &c in cc.iter().take(4) {
                case(&mut o, true, a, b, c);
            }
        }
    }
    for _ in 0..n {
        let a = A::random(&mut rng);
        let b = B::random(&mut rng);
        let c = C::random(&mut rng);
        case(&mut o, false, a, b, c);
    }
    o
}

/// Campaign for a four-argument operation (`_mm_set_epi32`).
pub fn diff4<A, R>(
    name: &str,
    n: u64,
    seed: u64,
    model: impl Fn(A, A, A, A) -> R,
    reference: impl Fn(A, A, A, A) -> R,
) -> Outcome
where
    A: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let case = |o: &mut Outcome, corner: bool, x: [A; 4]| {
        o.count(corner);
        let (m, h) = (
            model(x[0], x[1], x[2], x[3]),
            opaque(|| reference(bb(x[0]), bb(x[1]), bb(x[2]), bb(x[3]))),
        );
        if m != h {
            o.record(corner, || {
                format!("args = {x:?}: model {m:?} != reference {h:?}")
            });
        }
    };
    let corners = A::corners();
    for pos in 0..4 {
        for &c in &corners {
            let mut x: [A; 4] = core::array::from_fn(|_| A::random(&mut rng));
            x[pos] = c;
            case(&mut o, true, x);
        }
    }
    for _ in 0..n {
        let x: [A; 4] = core::array::from_fn(|_| A::random(&mut rng));
        case(&mut o, false, x);
    }
    o
}

/// Split a total random budget `n` over `k` immediates so that the sum is at
/// least `n` (§9.2: ≥ 10^7 per model, all immediates included).
pub fn per_immediate(n: u64, imms: &RangeInclusive<i32>) -> u64 {
    let k = (*imms.end() as i64 - *imms.start() as i64 + 1).max(1) as u64;
    n.div_ceil(k)
}

/// Campaign for a unary operation with an immediate, every immediate in
/// `imms` exhaustively; `n` is the total random budget.
pub fn diff_imm1<A, R>(
    name: &str,
    imms: RangeInclusive<i32>,
    n: u64,
    seed: u64,
    model: impl Fn(A, i32) -> R,
    reference: impl Fn(A, i32) -> R,
) -> Outcome
where
    A: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let per = per_immediate(n, &imms);
    let corners = A::corners();
    for imm in imms.clone() {
        let case = |o: &mut Outcome, corner: bool, a: A| {
            o.count(corner);
            let (m, h) = (model(a, imm), opaque(|| reference(bb(a), bb(imm))));
            if m != h {
                o.record(corner, || {
                    format!("imm = {imm}, a = {a:?}: model {m:?} != reference {h:?}")
                });
            }
        };
        for &a in &corners {
            case(&mut o, true, a);
        }
        for _ in 0..per {
            let a = A::random(&mut rng);
            case(&mut o, false, a);
        }
    }
    o.immediates = Some(imms);
    o
}

/// Campaign for a binary operation with an immediate, every immediate in
/// `imms` exhaustively; `n` is the total random budget.
pub fn diff_imm2<A, B, R>(
    name: &str,
    imms: RangeInclusive<i32>,
    n: u64,
    seed: u64,
    model: impl Fn(A, B, i32) -> R,
    reference: impl Fn(A, B, i32) -> R,
) -> Outcome
where
    A: Sample,
    B: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let per = per_immediate(n, &imms);
    let (ca, cb) = (A::corners(), B::corners());
    for imm in imms.clone() {
        let case = |o: &mut Outcome, corner: bool, a: A, b: B| {
            o.count(corner);
            let (m, h) = (
                model(a, b, imm),
                opaque(|| reference(bb(a), bb(b), bb(imm))),
            );
            if m != h {
                o.record(corner, || {
                    format!("imm = {imm}, a = {a:?}, b = {b:?}: model {m:?} != reference {h:?}")
                });
            }
        };
        for &a in &ca {
            let b = B::random(&mut rng);
            case(&mut o, true, a, b);
        }
        for &b in &cb {
            let a = A::random(&mut rng);
            case(&mut o, true, a, b);
        }
        for &a in ca.iter().take(4) {
            for &b in cb.iter().take(4) {
                case(&mut o, true, a, b);
            }
        }
        for _ in 0..per {
            let a = A::random(&mut rng);
            let b = B::random(&mut rng);
            case(&mut o, false, a, b);
        }
    }
    o.immediates = Some(imms);
    o
}

/// Campaign for a ternary operation with an immediate (`VPTERNLOG`), every
/// immediate in `imms` exhaustively; `n` is the total random budget. The
/// corner phase per immediate is every corner of each position with the
/// other two random, plus the product of the first three corners of each.
pub fn diff_imm3<A, B, C, R>(
    name: &str,
    imms: RangeInclusive<i32>,
    n: u64,
    seed: u64,
    model: impl Fn(A, B, C, i32) -> R,
    reference: impl Fn(A, B, C, i32) -> R,
) -> Outcome
where
    A: Sample,
    B: Sample,
    C: Sample,
    R: PartialEq + Debug,
{
    let mut o = Outcome::new(name, seed);
    let mut rng = Rng::new(seed);
    let per = per_immediate(n, &imms);
    let (ca, cb, cc) = (A::corners(), B::corners(), C::corners());
    for imm in imms.clone() {
        let case = |o: &mut Outcome, corner: bool, a: A, b: B, c: C| {
            o.count(corner);
            let (m, h) = (model(a, b, c, imm), opaque(|| reference(bb(a), bb(b), bb(c), bb(imm))));
            if m != h {
                o.record(corner, || format!("imm = {imm}, a = {a:?}, b = {b:?}, c = {c:?}: model {m:?} != reference {h:?}"));
            }
        };
        for &a in &ca {
            let (b, c) = (B::random(&mut rng), C::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
        for &b in &cb {
            let (a, c) = (A::random(&mut rng), C::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
        for &c in &cc {
            let (a, b) = (A::random(&mut rng), B::random(&mut rng));
            case(&mut o, true, a, b, c);
        }
        for &a in ca.iter().take(3) {
            for &b in cb.iter().take(3) {
                for &c in cc.iter().take(3) {
                    case(&mut o, true, a, b, c);
                }
            }
        }
        for _ in 0..per {
            let (a, b, c) = (A::random(&mut rng), B::random(&mut rng), C::random(&mut rng));
            case(&mut o, false, a, b, c);
        }
    }
    o.immediates = Some(imms);
    o
}

/// A per-model seed: the campaign seed mixed with an FNV-1a hash of the name,
/// so each model's campaign is reproducible on its own.
pub fn model_seed(base: u64, name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    base ^ h
}

/// Campaign sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Random cases per model (split over immediates for immediate models).
    pub random_per_model: u64,
    /// Base seed (mixed with the model name by [`model_seed`]).
    pub seed: u64,
}

/// The default campaign seed.
pub const DEFAULT_SEED: u64 = 0x5eed_2026_0923_0001;

impl Config {
    /// The fast default used by `cargo test` (debug build friendly).
    pub fn fast() -> Self {
        Config {
            random_per_model: 100_000,
            seed: DEFAULT_SEED,
        }
    }

    /// The §9.2 campaign: 10^7 random cases per model.
    pub fn large() -> Self {
        Config {
            random_per_model: 10_000_000,
            seed: DEFAULT_SEED,
        }
    }

    /// The seed for one model.
    pub fn seed_for(&self, name: &str) -> u64 {
        model_seed(self.seed, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corner_lists_start_with_the_required_values() {
        assert_eq!(&word_corners()[..4], &[0, u32::MAX, 0x8000_0000, 1]);
        // Every single-bit word is present.
        let w = word_corners();
        assert!((0..32).all(|k| w.contains(&(1u32 << k))));
        assert_eq!(
            &<[u32; 4]>::corners()[..3],
            &[[0; 4], [u32::MAX; 4], [0x8000_0000; 4]]
        );
    }

    #[test]
    fn campaigns_count_and_detect() {
        let ok = diff2(
            "add",
            1000,
            1,
            |a: u32, b: u32| a.wrapping_add(b),
            |a: u32, b: u32| b.wrapping_add(a),
        );
        assert!(ok.passed());
        assert_eq!(ok.random, 1000);
        assert_eq!(ok.corner as usize, word_corners().len().pow(2));
        // A reference that differs only at 0x8000_0000 must be caught by the corner phase.
        let bad = diff1(
            "neg",
            0,
            2,
            |a: u32| a.wrapping_neg(),
            |a: u32| {
                if a == 0x8000_0000 {
                    0
                } else {
                    a.wrapping_neg()
                }
            },
        );
        assert!(!bad.passed());
        assert_eq!(bad.mismatches, 1);
        let imm = diff_imm1(
            "shl",
            0..=31,
            3200,
            3,
            |a: u32, n| a << n,
            |a: u32, n| a.wrapping_shl(n as u32),
        );
        assert!(imm.passed());
        assert_eq!(imm.random, 3200);
        assert_eq!(imm.immediate_count(), 32);
        let imm_bad = diff_imm1(
            "shr",
            0..=32,
            64,
            4,
            |a: u32, n| a.checked_shr(n as u32).unwrap_or(0),
            |a: u32, n| a.wrapping_shr(n as u32),
        );
        assert!(
            !imm_bad.passed(),
            "immediate 32 differs and must be detected"
        );
    }

    #[test]
    fn per_immediate_budget_covers_total() {
        assert_eq!(per_immediate(10_000_000, &(0..=255)), 39_063);
        assert!(per_immediate(10_000_000, &(1..=32)) * 32 >= 10_000_000);
    }
}
