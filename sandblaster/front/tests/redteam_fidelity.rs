//! Red team, lens "elaboration fidelity (model vs rustc)".
//!
//! A differential fuzzer over the exec subset (the language of the
//! structured reading of lifted Rust). Every program is written once
//! (`program!`): it is compiled natively into this test binary (dev profile:
//! overflow checks and debug assertions on) and verified by sandblaster with
//! the build's prover chain. For thousands of random (edge-biased) inputs
//! the harness compares
//!
//! 1. the native result of the erased source (a panic is recorded as
//!    `PANIC`: a verified program must never panic),
//! 2. the kernel evaluation (`driver::stage::eval_in`, the reference semantics of
//!    SEMANTICS.md §17).
//!
//! (A third lens, the code the optimizer printed, went with the optimizer:
//! nothing is printed any more.)
//!
//! Tests that expose a divergence are `#[ignore]`d with a comment naming the
//! finding; run them with `--ignored`.
//!
//! ```text
//! CARGO_TARGET_DIR=target/rt-fidelity cargo test -p sandblaster-front --test redteam_fidelity -- --nocapture
//! CARGO_TARGET_DIR=target/rt-fidelity cargo test -p sandblaster-front --test redteam_fidelity -- --ignored --nocapture
//! ```

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros, dead_code)]
mod util;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use util::ToJ;

// ---------------------------------------------------------------------------
// random inputs
// ---------------------------------------------------------------------------

pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed ^ 0x9e37_79b9_7f4a_7c15)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    /// An edge-biased value of `bits` bits.
    pub fn int(&mut self, bits: u32) -> u64 {
        let max = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        match self.below(8) {
            0 | 1 => {
                let edges = [0, 1, 2, 3, max, max - 1, max / 2, max / 2 + 1, bits as u64, bits as u64 - 1, bits as u64 + 1];
                edges[self.below(edges.len() as u64) as usize] & max
            }
            2 => {
                let k = self.below(bits as u64) as u32;
                let p = 1u64 << k;
                [p, p.wrapping_sub(1), p.wrapping_add(1)][self.below(3) as usize] & max
            }
            3 | 4 => self.below(40),
            _ => self.next() & max,
        }
    }
}

pub trait Gen: Sized {
    fn draw(r: &mut Rng) -> Self;
}
macro_rules! gen_int {
    ($($t:ty => $b:expr),*) => { $(impl Gen for $t { fn draw(r: &mut Rng) -> $t { r.int($b) as $t } })* };
}
gen_int!(u8 => 8, u16 => 16, u32 => 32, u64 => 64, usize => 64);
impl Gen for bool {
    fn draw(r: &mut Rng) -> bool {
        r.below(2) == 1
    }
}
impl<T: Gen> Gen for Option<T> {
    fn draw(r: &mut Rng) -> Option<T> {
        if r.below(4) == 0 { None } else { Some(T::draw(r)) }
    }
}
impl<T: Gen> Gen for Vec<T> {
    fn draw(r: &mut Rng) -> Vec<T> {
        let n = match r.below(6) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => r.below(6),
            _ => r.below(12),
        };
        (0..n).map(|_| T::draw(r)).collect()
    }
}
impl<T: Gen, const N: usize> Gen for [T; N] {
    fn draw(r: &mut Rng) -> [T; N] {
        std::array::from_fn(|_| T::draw(r))
    }
}
impl<A: Gen, B: Gen> Gen for (A, B) {
    fn draw(r: &mut Rng) -> (A, B) {
        (A::draw(r), B::draw(r))
    }
}
impl<A: Gen, B: Gen, C: Gen> Gen for (A, B, C) {
    fn draw(r: &mut Rng) -> (A, B, C) {
        (A::draw(r), B::draw(r), C::draw(r))
    }
}

/// A by-reference array argument (`&[T; N]`).
#[derive(Clone)]
pub struct ByRef<T>(pub T);
impl<T: Gen> Gen for ByRef<T> {
    fn draw(r: &mut Rng) -> ByRef<T> {
        ByRef(T::draw(r))
    }
}

/// Rust source text of a value (for the source driver) and of its type.
pub trait Rs {
    fn rs(&self) -> String;
    fn ty() -> String;
}
macro_rules! rs_int {
    ($($t:ty),*) => { $(impl Rs for $t { fn rs(&self) -> String { format!("{}{}", self, stringify!($t)) } fn ty() -> String { stringify!($t).into() } })* };
}
rs_int!(u8, u16, u32, u64, usize);
impl Rs for bool {
    fn rs(&self) -> String {
        self.to_string()
    }
    fn ty() -> String {
        "bool".into()
    }
}
impl<T: Rs> Rs for Option<T> {
    fn rs(&self) -> String {
        match self {
            None => format!("None::<{}>", T::ty()),
            Some(x) => format!("Some({})", x.rs()),
        }
    }
    fn ty() -> String {
        format!("Option<{}>", T::ty())
    }
}
impl<T: Rs> Rs for Vec<T> {
    fn rs(&self) -> String {
        format!("&[{}]", self.iter().map(|x| x.rs()).collect::<Vec<_>>().join(", "))
    }
    fn ty() -> String {
        format!("&'static [{}]", T::ty())
    }
}
impl<T: Rs, const N: usize> Rs for [T; N] {
    fn rs(&self) -> String {
        format!("[{}]", self.iter().map(|x| x.rs()).collect::<Vec<_>>().join(", "))
    }
    fn ty() -> String {
        format!("[{}; {N}]", T::ty())
    }
}
impl<T: Rs> Rs for ByRef<T> {
    fn rs(&self) -> String {
        format!("&{}", self.0.rs())
    }
    fn ty() -> String {
        format!("&'static {}", T::ty())
    }
}
impl<A: Rs, B: Rs> Rs for (A, B) {
    fn rs(&self) -> String {
        format!("({}, {})", self.0.rs(), self.1.rs())
    }
    fn ty() -> String {
        format!("({}, {})", A::ty(), B::ty())
    }
}
impl<A: Rs, B: Rs, C: Rs> Rs for (A, B, C) {
    fn rs(&self) -> String {
        format!("({}, {}, {})", self.0.rs(), self.1.rs(), self.2.rs())
    }
    fn ty() -> String {
        format!("({}, {}, {})", A::ty(), B::ty(), C::ty())
    }
}

/// How a generated value is passed to the native function.
pub trait Arg {
    type Out<'a>
    where
        Self: 'a;
    fn arg(&self) -> Self::Out<'_>;
}
macro_rules! arg_copy {
    ($($t:ty),*) => { $(impl Arg for $t { type Out<'a> = $t; fn arg(&self) -> $t { *self } })* };
}
arg_copy!(u8, u16, u32, u64, usize, bool);
impl<T: Copy> Arg for Option<T> {
    type Out<'a>
        = Option<T>
    where
        T: 'a;
    fn arg(&self) -> Option<T> {
        *self
    }
}
impl<T> Arg for Vec<T> {
    type Out<'a>
        = &'a [T]
    where
        T: 'a;
    fn arg(&self) -> &[T] {
        &self[..]
    }
}
impl<T: Copy, const N: usize> Arg for [T; N] {
    type Out<'a>
        = [T; N]
    where
        T: 'a;
    fn arg(&self) -> [T; N] {
        *self
    }
}
impl<T> Arg for ByRef<T> {
    type Out<'a>
        = &'a T
    where
        T: 'a;
    fn arg(&self) -> &T {
        &self.0
    }
}
impl<A: Copy, B: Copy> Arg for (A, B) {
    type Out<'a>
        = (A, B)
    where
        A: 'a,
        B: 'a;
    fn arg(&self) -> (A, B) {
        *self
    }
}
impl<A: Copy, B: Copy, C: Copy> Arg for (A, B, C) {
    type Out<'a>
        = (A, B, C)
    where
        A: 'a,
        B: 'a,
        C: 'a;
    fn arg(&self) -> (A, B, C) {
        *self
    }
}

impl<A: ToJ, B: ToJ, C: ToJ, D: ToJ> ToJ for (A, B, C, D) {
    fn j(&self) -> String {
        format!("[{},{},{},{}]", self.0.j(), self.1.j(), self.2.j(), self.3.j())
    }
}
impl<A: ToJ, B: ToJ, C: ToJ, D: ToJ, E: ToJ> ToJ for (A, B, C, D, E) {
    fn j(&self) -> String {
        format!("[{},{},{},{},{}]", self.0.j(), self.1.j(), self.2.j(), self.3.j(), self.4.j())
    }
}

/// The JSON printer of the source driver (same format as `util::ToJ`).
const DRIVER_TOJ: &str = r#"
trait ToJ { fn j(&self) -> String; }
macro_rules! num_toj { ($($t:ty),*) => { $(impl ToJ for $t { fn j(&self) -> String { self.to_string() } })* }; }
num_toj!(u8, u16, u32, u64, usize);
impl ToJ for bool { fn j(&self) -> String { self.to_string() } }
impl ToJ for () { fn j(&self) -> String { "null".into() } }
impl<T: ToJ> ToJ for [T] { fn j(&self) -> String { format!("[{}]", self.iter().map(|x| x.j()).collect::<Vec<_>>().join(",")) } }
impl<T: ToJ, const N: usize> ToJ for [T; N] { fn j(&self) -> String { self[..].j() } }
impl<T: ToJ + ?Sized> ToJ for &T { fn j(&self) -> String { (**self).j() } }
impl<T: ToJ> ToJ for Option<T> { fn j(&self) -> String { match self { None => "null".into(), Some(x) => format!("{{\"Some\":{}}}", x.j()) } } }
impl<A: ToJ, B: ToJ> ToJ for (A, B) { fn j(&self) -> String { format!("[{},{}]", self.0.j(), self.1.j()) } }
impl<A: ToJ, B: ToJ, C: ToJ> ToJ for (A, B, C) { fn j(&self) -> String { format!("[{},{},{}]", self.0.j(), self.1.j(), self.2.j()) } }
impl<A: ToJ, B: ToJ, C: ToJ, D: ToJ> ToJ for (A, B, C, D) { fn j(&self) -> String { format!("[{},{},{},{}]", self.0.j(), self.1.j(), self.2.j(), self.3.j()) } }
impl<A: ToJ, B: ToJ, C: ToJ, D: ToJ, E: ToJ> ToJ for (A, B, C, D, E) { fn j(&self) -> String { format!("[{},{},{},{},{}]", self.0.j(), self.1.j(), self.2.j(), self.3.j(), self.4.j()) } }
"#;

// ---------------------------------------------------------------------------
// cases and the differential runner
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Case {
    pub f: String,
    /// JSON array of the arguments (kernel evaluation).
    pub args_j: String,
    /// Rust tuple expression of the arguments, `(a, b,)`.
    pub args_rs: String,
    /// Rust tuple type of the arguments, `(A, B,)`.
    pub tys_rs: String,
    pub arity: usize,
    /// Native result (JSON) or `PANIC`.
    pub native: String,
}

/// `fuzz!(rng, n, m::f(a: A, b: B))`: `n` random calls of `m::f`.
macro_rules! fuzz {
    ($rng:expr, $n:expr, $m:ident :: $f:ident ( $($a:ident : $t:ty),* $(,)? )) => {{
        let mut v: Vec<Case> = Vec::new();
        let rng: &mut Rng = $rng;
        for _ in 0..$n {
            $( let $a: $t = <$t as Gen>::draw(rng); )*
            let args_j = { let xs: Vec<String> = vec![$( ToJ::j(&Arg::arg(&$a)) ),*]; format!("[{}]", xs.join(",")) };
            let args_rs = { let xs: Vec<String> = vec![$( Rs::rs(&$a) ),*]; format!("({},)", xs.join(", ")) };
            let tys_rs = { let xs: Vec<String> = vec![$( <$t as Rs>::ty() ),*]; format!("({},)", xs.join(", ")) };
            let arity = { let xs: Vec<&str> = vec![$( stringify!($a) ),*]; xs.len() };
            let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ToJ::j(&$m::$f($(Arg::arg(&$a)),*)))).unwrap_or_else(|_| "PANIC".to_string());
            v.push(Case { f: stringify!($f).into(), args_j, args_rs, tys_rs, arity, native });
        }
        v
    }};
}

/// Fixed calls: `fixed!(m::f(a: A = expr, ..))`.
#[allow(unused_macros)]
macro_rules! fixed {
    ($m:ident :: $f:ident ( $($a:ident : $t:ty = $e:expr),* $(,)? )) => {{
        $( let $a: $t = $e; )*
        let args_j = { let xs: Vec<String> = vec![$( ToJ::j(&Arg::arg(&$a)) ),*]; format!("[{}]", xs.join(",")) };
        let args_rs = { let xs: Vec<String> = vec![$( Rs::rs(&$a) ),*]; format!("({},)", xs.join(", ")) };
        let tys_rs = { let xs: Vec<String> = vec![$( <$t as Rs>::ty() ),*]; format!("({},)", xs.join(", ")) };
        let arity = { let xs: Vec<&str> = vec![$( stringify!($a) ),*]; xs.len() };
        let native = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ToJ::j(&$m::$f($(Arg::arg(&$a)),*)))).unwrap_or_else(|_| "PANIC".to_string());
        Case { f: stringify!($f).into(), args_j, args_rs, tys_rs, arity, native }
    }};
}

/// A program whose DSL source has extra items with sandblaster attributes
/// (`dsl`), natively replaced by the attribute-free twins in `native`.
macro_rules! program_x {
    ($name:ident { $($src:tt)* } native { $($native:tt)* } dsl $dsl:expr) => {
        #[allow(dead_code, unused, clippy::all)]
        pub mod $name {
            $($src)*
            $($native)*
            pub const SRC: &str = concat!(stringify!($($src)*), "\n", $dsl);
        }
    };
}

/// Outcome of [`run`].
#[derive(Debug, Default)]
pub struct Report {
    pub verified: bool,
    pub why_not: String,
    pub mismatches: Vec<String>,
    pub cases: usize,
}

impl Report {
    #[track_caller]
    pub fn assert_clean(&self) {
        assert!(self.verified, "program not verified:\n{}", self.why_not);
        assert!(self.mismatches.is_empty(), "{} of {} case(s) diverge:\n{}", self.mismatches.len(), self.cases, self.mismatches.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
    }
}

fn normalize(s: &str) -> String {
    match util_parse(s) {
        Some(x) => x,
        None => s.to_string(),
    }
}

fn util_parse(s: &str) -> Option<String> {
    sandblaster_front::elab::value::J::parse(s).ok().map(|j| j.render())
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("redteam-fidelity").join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Verifies `src` (the standard provers), evaluates every case with the
/// kernel and compares with the native results.
pub fn run(name: &str, src: &str, cases: &[Case]) -> Report {
    let mut rep = Report { cases: cases.len(), ..Default::default() };
    let c = util::accepted(src);
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let t0 = std::time::Instant::now();
    let built = driver::stage::verify_checked(&c, &opts);
    eprintln!("[{name}] verify: {:?}", t0.elapsed());
    if !built.v.proofs_ok {
        rep.why_not = util::explain(&c, &built.v);
        return rep;
    }
    rep.verified = true;
    // kernel evaluation
    let t1 = std::time::Instant::now();
    let kernel: Vec<Result<String, String>> = util::with_elab(src, ProverSet::Standard, |c, out| {
        eprintln!("[{name}] elaboration: {:?}", t1.elapsed());
        let t2 = std::time::Instant::now();
        let r = cases.iter().map(|cs| driver::stage::eval_in(out, c.krate.as_ref().unwrap(), &cs.f, &cs.args_j)).collect();
        eprintln!("[{name}] kernel eval of {} case(s): {:?}", cases.len(), t2.elapsed());
        r
    });
    for (i, cs) in cases.iter().enumerate() {
        let native = normalize(&cs.native);
        let k = match &kernel[i] {
            Ok(k) => normalize(k),
            Err(e) => format!("ERR({e})"),
        };
        if native == "PANIC" || k != native {
            rep.mismatches.push(format!("{}{}: native {} | kernel {}", cs.f, cs.args_j, native, k));
        }
    }
    rep
}

fn seed() -> u64 {
    std::env::var("REDTEAM_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed)
}

fn iters(n: usize) -> usize {
    let k: usize = std::env::var("REDTEAM_SCALE").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    n * k
}

// ---------------------------------------------------------------------------
// battery 1: arithmetic, casts, shifts, integer methods, literal typing
// ---------------------------------------------------------------------------

program!(arith {
    pub fn ops(a: u32, b: u32) -> (u32, u32, u32, u32) {
        let s = a.wrapping_add(b);
        let d = if a >= b { a - b } else { b - a };
        let m = (a as u64 * b as u64 >> 16u32) as u32;
        let q = if b != 0 { (a / b).wrapping_add(a % b) } else { a };
        (s, d, m, q)
    }
    pub fn compound(a: u8, b: u8, c: u16) -> (u8, u16, u64) {
        let mut x = a;
        x ^= b;
        x &= 0xf0 | a;
        x |= b >> 3u32;
        let mut y = c;
        if y > 0 { y -= 1; }
        y %= 1000;
        y *= 3;
        y /= 2;
        y <<= 1u8;
        y >>= 2u64;
        let mut z: u64 = y as u64;
        z += x as u64;
        z <<= 40u32;
        z >>= 33u16;
        (x, y, z)
    }
    pub fn shifts(x: u64, k: u8, s: u64) -> (u64, u32, u16, u8) {
        let a = if (k as u32) < 64 { x << k } else { x };
        let b = if s < 32 { (x as u32) >> s } else { 7 };
        let c = if k < 16 { (x as u16).wrapping_shl(k as u32) } else { (x as u16).wrapping_shr(k as u32) };
        let d = (x as u8).rotate_left(s as u32) ^ (x as u8).rotate_right(k as u32);
        (a, b, c, d)
    }
    pub fn casts(x: u64, b: bool) -> (u8, u16, u32, usize) {
        let a = x as u8;
        let c = (x >> 8u32) as u16 as u8 as u16;
        let d = (b as u32) + (x as u32 as u64 >> 31u32) as u32;
        let e = x as usize as u16 as usize;
        (a, c, d, e)
    }
    pub fn methods(a: u32, b: u32) -> (u32, u32, u32, u32) {
        let x = a.saturating_add(b) ^ a.saturating_sub(b) ^ a.saturating_mul(b);
        let y = a.count_ones().wrapping_add(a.leading_zeros()).wrapping_add(a.trailing_zeros() << 8u32);
        let z = a.swap_bytes() ^ a.abs_diff(b) ^ a.min(b) ^ a.max(b);
        let w = match a.checked_mul(b) { Some(p) => p, None => match a.checked_sub(b) { Some(q) => q, None => a.wrapping_neg() } };
        (x, y, z, w)
    }
    pub fn methods64(a: u64, b: u8) -> (u64, u32, bool, u64) {
        let x = a.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(b as u32);
        let y = (a >> 3u32).leading_zeros().wrapping_add((b as u64).trailing_zeros() << 8u32);
        let z = a.is_power_of_two() || (b as u16).is_power_of_two();
        let w = a.checked_div(b as u64).unwrap_or(1u64).wrapping_sub(a.checked_add(a).unwrap_or(0u64));
        (x, y, z, w)
    }
    pub fn bytes(x: u64, y: u16) -> (u64, u16, u32) {
        let be = x.to_be_bytes();
        let le = x.to_le_bytes();
        let r = u64::from_le_bytes(be) ^ u64::from_be_bytes(le);
        let yb = y.to_le_bytes();
        let y2 = u16::from_be_bytes(yb);
        let w = u32::from_le_bytes([be[0], le[1], yb[0], yb[1]]);
        (r, y2, w)
    }
    pub fn literals(x: u8) -> (u64, u32, u16, u8) {
        let a: u64 = 1 << 40u32;
        let b: u64 = (x as u64) << 56u8;
        let c: u32 = 0xffff_ffff >> (x % 32);
        let d: u16 = !0 ^ (x as u16);
        let e: u8 = if x > 0xf0 { 0b1010_1010 } else { 0o17 };
        (a | b, c, d, e)
    }
    pub fn precedence(a: u32, b: u32, c: u32) -> (u32, bool, u32) {
        let x = a & b | c ^ a;
        let y = (a < b) == (b > a);
        let z = (a >> 1u32) + (b >> 2u32) & 0xff ^ c % 7;
        (x, y, z)
    }
});

#[test]
fn arithmetic_differential() {
    let mut r = Rng::new(seed());
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(400), arith::ops(a: u32, b: u32)));
    cases.extend(fuzz!(&mut r, iters(400), arith::compound(a: u8, b: u8, c: u16)));
    cases.extend(fuzz!(&mut r, iters(400), arith::shifts(x: u64, k: u8, s: u64)));
    cases.extend(fuzz!(&mut r, iters(300), arith::casts(x: u64, b: bool)));
    cases.extend(fuzz!(&mut r, iters(400), arith::methods(a: u32, b: u32)));
    cases.extend(fuzz!(&mut r, iters(400), arith::methods64(a: u64, b: u8)));
    cases.extend(fuzz!(&mut r, iters(300), arith::bytes(x: u64, y: u16)));
    cases.extend(fuzz!(&mut r, iters(200), arith::literals(x: u8)));
    cases.extend(fuzz!(&mut r, iters(300), arith::precedence(a: u32, b: u32, c: u32)));
    let rep = run("arith", arith::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 1b: checked arithmetic at every width, shift amounts of every
// width, compound assignments on locals, fields and elements, against
// native and kernel
// ---------------------------------------------------------------------------

program!(e0 {
    #[derive(Clone, Copy)]
    pub struct P {
        pub a: u16,
        pub b: u64,
    }
    pub fn w8(a: u8, b: u8) -> (u8, u8, u8, u8, u8) {
        let s = if a < 128 && b < 128 { a + b } else { 0 };
        let d = if a >= b { a - b } else { b - a };
        let m = if a < 16 && b < 16 { a * b } else { 1 };
        let l = if b < 8 { a << b } else { a };
        let r = if (b as u64) < 8 { a >> (b as u64) } else { a };
        (s, d, m, l, r)
    }
    pub fn w16(a: u16, b: u16) -> (u16, u16, u16, u16, u16) {
        let s = if a < 32768 && b < 32768 { a + b } else { 0 };
        let d = if a >= b { a - b } else { b - a };
        let m = if a < 256 { a * 255 } else { 1 };
        let l = if b < 16 { a << b } else { a };
        let r = if (b as usize) < 16 { a >> (b as usize) } else { a };
        (s, d, m, l, r)
    }
    pub fn w32(a: u32, b: u32, k: u8) -> (u32, u32, u32, u32, u32) {
        let s = if a < 2147483648 && b < 2147483648 { a + b } else { 0 };
        let d = if a >= b { a - b } else { b - a };
        let m = if a < 65536 { a * 65535 } else { 1 };
        let l = if k < 32 { a << k } else { a };
        let r = if b < 32 { a >> b } else { a };
        (s, d, m, l, r)
    }
    pub fn w64(a: u64, b: u64, k: u16) -> (u64, u64, u64, u64, u64) {
        let s = if a < 9223372036854775808 && b < 9223372036854775808 { a + b } else { 0 };
        let d = if a >= b { a - b } else { b - a };
        let m = if a < 4294967296 { a * 4294967295 } else { 1 };
        let l = if k < 64 { a << k } else { a };
        let r = if b < 64 { a >> b } else { a };
        (s, d, m, l, r)
    }
    pub fn wsize(a: usize, b: usize, k: u32) -> (usize, usize, usize, usize, usize) {
        let s = if a < 9223372036854775808 && b < 9223372036854775808 { a + b } else { 0 };
        let d = if a >= b { a - b } else { b - a };
        let m = if a < 4294967296 { a * 4294967295 } else { 1 };
        let l = if k < 64 { a << k } else { a };
        let r = if (k as u64) < 64 { a >> (k as u64) } else { a };
        (s, d, m, l, r)
    }
    pub fn compound(xs: [u32; 4], i: usize, v: u8, a: u16, b: u64) -> ([u32; 4], u16, u64, u8) {
        let mut ys = xs;
        let mut p = P { a, b };
        let mut n = v;
        if i < 3 && ys[i + 1] >= 5 {
            ys[i + 1] -= 5;
        }
        if i < 4 && ys[i] < 1000000 {
            ys[i] += 7;
        }
        if i < 4 {
            ys[i] <<= 2u8;
            ys[i] >>= 1u64;
        }
        if p.a < 1000 {
            p.a *= 60;
            p.a += 1;
        }
        if n < 250 {
            n += 5;
        }
        n >>= 1u16;
        if v < 64 {
            p.b <<= v;
        }
        p.b >>= 3usize;
        (ys, p.a, p.b, n)
    }
    pub fn order(a: u32) -> (u32, u32) {
        let mut x = a % 1000;
        x += { x = 5; 1u32 };
        let y = x + { x = 9; 2u32 };
        (x, y)
    }
});

#[test]
fn e0_differential() {
    let mut r = Rng::new(seed() + 11);
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(300), e0::w8(a: u8, b: u8)));
    cases.extend(fuzz!(&mut r, iters(300), e0::w16(a: u16, b: u16)));
    cases.extend(fuzz!(&mut r, iters(300), e0::w32(a: u32, b: u32, k: u8)));
    cases.extend(fuzz!(&mut r, iters(300), e0::w64(a: u64, b: u64, k: u16)));
    cases.extend(fuzz!(&mut r, iters(300), e0::wsize(a: usize, b: usize, k: u32)));
    cases.extend(fuzz!(&mut r, iters(300), e0::compound(xs: [u32; 4], i: usize, v: u8, a: u16, b: u64)));
    cases.extend(fuzz!(&mut r, iters(200), e0::order(a: u32)));
    let rep = run("e0", e0::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 2: control flow (SSA, early exits, short circuit, joins vs CPS)
// ---------------------------------------------------------------------------

program!(control {
    pub fn nested_return(a: u32, b: u32) -> u32 {
        let x = if a > 10 {
            if b == 0 {
                return 1;
            }
            a / b
        } else {
            match b {
                0 => return 2,
                1..=5 => b * 3,
                _ => a.wrapping_add(b),
            }
        };
        x.wrapping_mul(7)
    }
    pub fn try_nested(a: Option<u8>, b: Option<u8>, c: Option<u16>) -> Option<u32> {
        let s = a? as u32 + b? as u32;
        let t = if s > 100 { c? as u32 } else { s };
        Some(t.wrapping_add(match c { Some(v) => v as u32, None => 5 }))
    }
    pub fn short(xs: &[u8], i: usize) -> (bool, bool, u8) {
        let a = i < xs.len() && xs[i] > 3;
        let b = i >= xs.len() || xs[i] == 0;
        let c = if i < xs.len() && (xs[i] > 10 || i == 0) { xs[i] } else { 99 };
        (a, b, c)
    }
    pub fn block_assign(a: u32) -> (u32, u32, u32) {
        let mut x = a % 1000;
        let y = { x += 1; x * 2 };
        let z = x + { x = 5; 1u32 };
        (x, y, z)
    }
    pub fn shadowing(a: u32) -> (u32, u32) {
        let mut x = a % 100;
        {
            let mut x = 5u32;
            x += 1;
            let _ = x;
        }
        x += 1;
        let y = x;
        let x = y * 2;
        (x, y)
    }
    pub fn alias(n0: u32) -> (u32, u32) {
        let mut n = n0 % 10;
        let m = n;
        n += 1;
        let k = n;
        n = n * 3;
        (m * 100 + k, n)
    }
    pub fn assign_arms(a: u8, o: Option<u8>) -> (u32, u32) {
        let mut acc = 1u32;
        let mut other = 0u32;
        let y = match o {
            Some(v) if v > a => { acc = 2; v as u32 }
            Some(v) => { other = v as u32; 7 }
            None => { acc = 3; other = 9; 0 }
        };
        (acc + y, other)
    }
    pub fn assign_return(o: Option<u8>, t: u8) -> u32 {
        let mut acc = 10u32;
        let y = match o {
            Some(v) => { acc += v as u32; v }
            None => {
                let Some(z) = t.checked_add(1) else { return 99 };
                z
            }
        };
        acc + y as u32
    }
    pub fn many_ifs(a: u32) -> u32 {
        let mut x = 0u32;
        if a & 1 != 0 { x += 1; }
        if a & 2 != 0 { x += 2; }
        if a & 4 != 0 { x += 4; }
        if a & 8 != 0 { x += 8; }
        if a & 16 != 0 { x += 16; }
        if a & 32 != 0 { x += 32; }
        if a & 64 != 0 { x += 64; }
        if a & 128 != 0 { x += 128; }
        if a & 256 != 0 { x += 256; }
        if a & 512 != 0 { x += 512; }
        if a & 1024 != 0 { x += 1024; }
        x
    }
    pub fn many_ifs2(a: u32) -> (u32, u32) {
        let mut x = 0u32;
        let mut y = 0u32;
        if a & 1 != 0 { x += 1; } else { y += 1; }
        if a & 2 != 0 { x += 2; } else { y = x; }
        if a & 4 != 0 { x += 4; } else { y += x; }
        if a & 8 != 0 { x = y; } else { y += 8; }
        if a & 16 != 0 { x += 16; } else { y = y * 2; }
        if a & 32 != 0 { x += 32; } else { y = x ^ y; }
        if a & 64 != 0 { x ^= y; } else { y += 64; }
        if a & 128 != 0 { x += 128; } else { y = y.wrapping_mul(3); }
        if a & 256 != 0 { y = x; } else { x = y; }
        if a & 512 != 0 { x += 1; } else { y += 1; }
        (x, y)
    }
    pub fn unreach(x: u8) -> u8 {
        match x % 4 {
            0 => 10,
            1 | 2 => 20,
            3 => 30,
            _ => unreachable!(),
        }
    }
    pub fn if_let_chain(a: Option<u8>, b: Option<u8>) -> u16 {
        if let Some(x) = a {
            x as u16
        } else if let Some(y) = b {
            y as u16 + 256
        } else {
            1000
        }
    }
    pub fn bool_ops(a: bool, b: bool, c: bool) -> (bool, bool, bool, u8) {
        let x = a & b | !c;
        let y = a ^ b == c;
        let z = (a != b) & (b == c) | a && !b;
        (x, y, z, a as u8 + b as u8 * 2 + c as u8 * 4)
    }
    pub fn ret_in_let_else(xs: &[u8]) -> u32 {
        let [a, b, ..] = xs else { return xs.len() as u32 };
        let Some(c) = xs.last() else { unreachable!() };
        *a as u32 * 65536 + *b as u32 * 256 + *c as u32
    }
    pub fn early_in_arg(a: Option<u32>, b: u32) -> Option<u32> {
        Some(a?.wrapping_add(match b { 0 => return None, 1 => 7, n => n }))
    }
});

#[test]
fn control_differential() {
    let mut r = Rng::new(seed() + 1);
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(300), control::nested_return(a: u32, b: u32)));
    cases.extend(fuzz!(&mut r, iters(300), control::try_nested(a: Option<u8>, b: Option<u8>, c: Option<u16>)));
    cases.extend(fuzz!(&mut r, iters(300), control::short(xs: Vec<u8>, i: usize)));
    cases.extend(fuzz!(&mut r, iters(200), control::block_assign(a: u32)));
    cases.extend(fuzz!(&mut r, iters(200), control::shadowing(a: u32)));
    cases.extend(fuzz!(&mut r, iters(200), control::alias(n0: u32)));
    cases.extend(fuzz!(&mut r, iters(300), control::assign_arms(a: u8, o: Option<u8>)));
    cases.extend(fuzz!(&mut r, iters(300), control::assign_return(o: Option<u8>, t: u8)));
    cases.extend(fuzz!(&mut r, iters(300), control::many_ifs(a: u32)));
    cases.extend(fuzz!(&mut r, iters(300), control::many_ifs2(a: u32)));
    cases.extend(fuzz!(&mut r, iters(100), control::unreach(x: u8)));
    cases.extend(fuzz!(&mut r, iters(200), control::if_let_chain(a: Option<u8>, b: Option<u8>)));
    cases.extend(fuzz!(&mut r, iters(100), control::bool_ops(a: bool, b: bool, c: bool)));
    cases.extend(fuzz!(&mut r, iters(300), control::ret_in_let_else(xs: Vec<u8>)));
    cases.extend(fuzz!(&mut r, iters(300), control::early_in_arg(a: Option<u32>, b: u32)));
    let rep = run("control", control::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 3: patterns (slice patterns, or-patterns with guards, ranges)
// ---------------------------------------------------------------------------

program!(pats {
    pub fn ends(s: &[u8]) -> (u32, usize) {
        match s {
            [] => (0, 0),
            [x] => (*x as u32, 1),
            [init @ .., last] if *last > 128 => (*last as u32 + 1000, init.len()),
            [first, .., last] => ((*first as u32) * 256 + (*last as u32), s.len()),
        }
    }
    pub fn init_last(s: &[u16]) -> (u16, usize, u16) {
        match s {
            [init @ .., last] => {
                let f = match init { [a, ..] => *a, [] => 7 };
                (*last, init.len(), f)
            }
            [] => (0, 0, 0),
        }
    }
    pub fn middle(s: &[u8]) -> (usize, u8, u8) {
        match s {
            [a, b, mid @ .., y, z] => (mid.len(), a ^ b ^ y ^ z, match mid { [m, ..] => *m, [] => 0 }),
            [a, rest @ ..] => (rest.len() + 100, *a, 0),
            [] => (999, 0, 0),
        }
    }
    pub fn overlap(s: &[u8]) -> u32 {
        match s {
            [1, ..] => 1,
            [_, 2] => 2,
            [.., 3] => 3,
            [x, y] if x == y => 4,
            [_, _, _] => 5,
            [.., 4, _] => 6,
            _ => 7,
        }
    }
    pub fn arr_rest(a: [u8; 6]) -> (u8, usize, u8, bool) {
        let [x, mid @ .., z] = a;
        let [p, q, ..] = mid;
        (x ^ z, mid.len(), mid[3] ^ p ^ q, mid == [a[1], a[2], a[3], a[4]])
    }
    pub fn or_guard(a: Option<u32>, b: Option<u32>) -> u32 {
        match (a, b) {
            (Some(x), _) | (_, Some(x)) if x > 5 => x,
            (Some(x), Some(y)) => x.wrapping_add(y),
            _ => 0,
        }
    }
    pub fn or_cross(p: (u8, u8), q: (u8, u8)) -> u32 {
        match (p, q) {
            ((x, _) | (_, x), (y, _) | (_, y)) if x as u32 + y as u32 > 300 => x as u32 * 1000 + y as u32,
            _ => 1,
        }
    }
    pub fn or_nested(t: (Option<u8>, u8)) -> u32 {
        match t {
            (Some(1 | 2) | None, 0..=9) => 1,
            (Some(x @ (3 | 4)), y) if y > x => 2,
            (Some(x), y @ (10 | 20)) => x as u32 + y as u32,
            (_, 250..=255) => 4,
            _ => 5,
        }
    }
    pub fn ranges(x: u8, y: u16) -> u32 {
        let a = match x {
            0 => 0u32,
            1..=9 => 1,
            5..=20 => 2,
            b'a'..=b'z' => 3,
            200..=u8::MAX => 4,
            n @ 21..=40 if n % 2 == 0 => 5,
            _ => 6,
        };
        let b = match y {
            0..=0xff => 10u32,
            0x100 | 0x200 | 0x300 => 20,
            0xffff => 30,
            _ => 40,
        };
        a.wrapping_add(b)
    }
    pub fn slice_or(s: &[u8]) -> u32 {
        match s {
            [1 | 2, rest @ ..] | [rest @ .., 9] => rest.len() as u32,
            [x, y, ..] if *x > *y => 100,
            _ => 200,
        }
    }
    pub fn let_or(t: (Option<u8>, u8)) -> u8 {
        let ((Some(x), _) | (None, x)) = t;
        x
    }
    pub fn tuple_bool(t: (u8, bool, Option<bool>)) -> u8 {
        match t {
            (0, true, Some(true)) => 1,
            (0, _, None) => 2,
            (_, false, Some(b)) if b => 3,
            (1..=10, _, _) => 4,
            (_, true, _) | (_, _, Some(false)) => 5,
            _ => 6,
        }
    }
    pub fn deref_pats(s: &[(u8, u8)]) -> u32 {
        match s {
            [(a, b), rest @ ..] if a < b => (*a as u32).wrapping_add(rest.len() as u32),
            [(a, _), .., (_, z)] => *a as u32 * 256 + *z as u32,
            [(a, b)] => *a as u32 ^ *b as u32,
            [] => 77,
        }
    }
});

#[test]
fn patterns_differential() {
    let mut r = Rng::new(seed() + 2);
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(400), pats::ends(s: Vec<u8>)));
    cases.extend(fuzz!(&mut r, iters(300), pats::init_last(s: Vec<u16>)));
    cases.extend(fuzz!(&mut r, iters(400), pats::middle(s: Vec<u8>)));
    // small alphabet so the literal patterns hit
    for _ in 0..iters(600) {
        let n = r.below(5) as usize;
        let v: Vec<u8> = (0..n).map(|_| r.below(11) as u8).collect();
        cases.push(fixed!(pats::overlap(s: Vec<u8> = v.clone())));
        cases.push(fixed!(pats::slice_or(s: Vec<u8> = v.clone())));
    }
    cases.extend(fuzz!(&mut r, iters(300), pats::arr_rest(a: [u8; 6])));
    cases.extend(fuzz!(&mut r, iters(300), pats::or_guard(a: Option<u32>, b: Option<u32>)));
    cases.extend(fuzz!(&mut r, iters(400), pats::or_cross(p: (u8, u8), q: (u8, u8))));
    for _ in 0..iters(500) {
        let a = match r.below(6) { 0 => None, k => Some((r.below(8) as u8).wrapping_add(if k == 5 { 250 } else { 0 })) };
        let b = [0u8, 1, 3, 4, 5, 9, 10, 20, 250, 255][r.below(10) as usize];
        cases.push(fixed!(pats::or_nested(t: (Option<u8>, u8) = (a, b))));
        let c = match r.below(3) { 0 => None, 1 => Some(true), _ => Some(false) };
        cases.push(fixed!(pats::tuple_bool(t: (u8, bool, Option<bool>) = (r.below(12) as u8, r.below(2) == 1, c))));
    }
    cases.extend(fuzz!(&mut r, iters(600), pats::ranges(x: u8, y: u16)));
    cases.extend(fuzz!(&mut r, iters(200), pats::let_or(t: (Option<u8>, u8))));
    cases.extend(fuzz!(&mut r, iters(300), pats::deref_pats(s: Vec<(u8, u8)>)));
    let rep = run("pats", pats::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 4: loops and recursion
// ---------------------------------------------------------------------------

program_x!(loops {
    pub fn range_excl(a: u8, b: u8) -> (u32, u32) {
        let mut n = 0u32;
        let mut s = 0u32;
        for i in a..b {
            proof! { invariant(n <= i as u32 && s <= n * 255); }
            n += 1;
            s += i as u32;
        }
        (n, s)
    }
    pub fn range_incl(a: u8, b: u8) -> (u32, u8) {
        let mut n = 0u32;
        let mut last = 0u8;
        for i in a..=b {
            proof! { invariant(n <= i as u32); }
            n += 1;
            last = i;
        }
        (n, last)
    }
    pub fn incl_max(a: u8) -> u32 {
        let mut n = 0u32;
        for i in a..=u8::MAX {
            proof! { invariant((n as Int) + (a as Int) == (i as Int)); }
            n += 1;
        }
        n
    }
    pub fn shadow_loop_var(x: u32) -> (u32, u32) {
        let i = x % 7;
        let mut acc = 0u32;
        for i in 0u32..5 {
            proof! { invariant(acc <= i * 10); }
            let acc2 = acc + i;
            acc = acc2;
        }
        let mut other = 1u32;
        for _k in 0u32..3 {
            let other = 5u32;
            let _ = other;
        }
        other += i;
        (acc.wrapping_add(i), other)
    }
    pub fn alias_bound(n0: u32) -> (u32, u32) {
        let mut n = n0 % 10;
        let m = n;
        let mut c = 0u32;
        for _i in 0..m {
            proof! { invariant(c <= 10); }
            if n > 0 { n -= 1; }
            if c < 10 { c += 1; }
        }
        (c, n)
    }
    pub fn while_and(xs: &[u8]) -> (usize, u32) {
        let mut i = 0usize;
        let mut s = 0u32;
        while i < xs.len() && xs[i] != 0 {
            proof! { decreases(xs.len() - i); invariant(i <= xs.len()); }
            s = s.wrapping_add(xs[i] as u32);
            i += 1;
        }
        (i, s)
    }
    pub fn nested_arr(n: u8) -> [u8; 9] {
        let mut g = [0u8; 9];
        for i in 0usize..3 {
            for j in 0usize..3 {
                g[i * 3 + j] = (i as u8).wrapping_mul(n).wrapping_add(j as u8);
            }
        }
        g
    }
    pub fn stop_flag(xs: &[u32]) -> u32 {
        let mut acc = 0u32;
        let mut stopped = false;
        for i in 0..xs.len() {
            if xs[i] == 0 { stopped = true; }
            if !stopped { acc = acc.wrapping_add(xs[i]); }
        }
        acc
    }
    pub fn loop_index_mut(xs: &[u8]) -> [u8; 4] {
        let mut out = [0u8; 4];
        let mut k = 0usize;
        for i in 0..xs.len() {
            proof! { invariant(k < 4); }
            out[k] = out[k].wrapping_add(xs[i]);
            k = (k + 1) % 4;
        }
        out
    }
    pub fn count(n: u32, acc: u64) -> u64 {
        if n == 0 { acc } else { count(n - 1, acc.wrapping_add(n as u64)) }
    }
    pub fn start_count(n: u16) -> u64 {
        count(n as u32, 0)
    }
    pub fn sum_slice(xs: &[u8], acc: u32) -> u32 {
        match xs {
            [] => acc,
            [x, rest @ ..] => sum_slice(rest, acc.wrapping_add(*x as u32)),
        }
    }
    pub fn rev_fold(xs: &[u8], acc: u32) -> u32 {
        match xs {
            [] => acc,
            [init @ .., last] => rev_fold(init, acc.wrapping_mul(31).wrapping_add(*last as u32)),
        }
    }
    pub fn both_ends(xs: &[u8], acc: u32) -> u32 {
        match xs {
            [] => acc,
            [x] => acc ^ (*x as u32),
            [first, mid @ .., last] => both_ends(mid, acc.wrapping_mul(7).wrapping_add(*first as u32 * 256 + *last as u32)),
        }
    }
    pub fn use_pow(n: u8) -> u64 {
        if (n as u32) < 64 { pow2(n as u32) } else { 0 }
    }
} native {
    pub fn pow2(n: u32) -> u64 {
        if n == 0 { 1 } else { pow2(n - 1).wrapping_mul(2) }
    }
} dsl r#"
#[decreases(n, max = 64)]
pub(crate) fn pow2(n: u32) -> u64 {
    if n == 0 { 1 } else { pow2(n - 1).wrapping_mul(2) }
}
"#);

#[test]
fn loops_differential() {
    let mut r = Rng::new(seed() + 3);
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(200), loops::range_excl(a: u8, b: u8)));
    cases.extend(fuzz!(&mut r, iters(200), loops::range_incl(a: u8, b: u8)));
    cases.extend(fuzz!(&mut r, iters(100), loops::incl_max(a: u8)));
    cases.extend(fuzz!(&mut r, iters(100), loops::shadow_loop_var(x: u32)));
    cases.extend(fuzz!(&mut r, iters(100), loops::alias_bound(n0: u32)));
    cases.extend(fuzz!(&mut r, iters(300), loops::while_and(xs: Vec<u8>)));
    cases.extend(fuzz!(&mut r, iters(100), loops::nested_arr(n: u8)));
    cases.extend(fuzz!(&mut r, iters(300), loops::stop_flag(xs: Vec<u32>)));
    cases.extend(fuzz!(&mut r, iters(300), loops::loop_index_mut(xs: Vec<u8>)));
    cases.extend(fuzz!(&mut r, iters(100), loops::start_count(n: u16)));
    cases.extend(fuzz!(&mut r, iters(300), loops::sum_slice(xs: Vec<u8>, acc: u32)));
    cases.extend(fuzz!(&mut r, iters(300), loops::rev_fold(xs: Vec<u8>, acc: u32)));
    cases.extend(fuzz!(&mut r, iters(300), loops::both_ends(xs: Vec<u8>, acc: u32)));
    cases.extend(fuzz!(&mut r, iters(100), loops::use_pow(n: u8)));
    let rep = run("loops", loops::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 5: structs, enums, places, slices, methods of slices and arrays
// ---------------------------------------------------------------------------

program!(data {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct P {
        pub a: u8,
        pub b: u16,
        pub arr: [u8; 3],
    }
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum E {
        A,
        B(u8, u8),
        C { x: u16, p: P },
    }
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct W(pub u8, pub (u8, bool));
    impl P {
        pub fn sum(&self) -> u32 {
            self.a as u32 + self.b as u32 + self.arr[0] as u32
        }
        pub fn bump(self, k: u8) -> P {
            P { arr: [k, self.arr[1], self.arr[2]], ..self }
        }
    }
    pub const BASE: P = P { a: 1, b: 2, arr: [3, 4, 5] };
    pub const TABLE: [u16; 5] = [10, 20, 30, 40, 50];

    pub fn update(a: u8, b: u16, k: u8) -> (u8, u16, [u8; 3], u32) {
        let p = P { b, a, ..BASE };
        let q = P { arr: [a, k, a ^ k], ..p }.bump(k);
        (q.a, q.b, q.arr, q.sum())
    }
    pub fn places(a: u8, i: u8, v: u8) -> ([u8; 3], u16, [[u8; 2]; 2], (u8, u16)) {
        let mut p = BASE;
        p.arr[(i % 3) as usize] = v;
        p.b += a as u16;
        let mut m = [[0u8; 2]; 2];
        m[(i % 2) as usize][((i / 2) % 2) as usize] = v;
        m[1][0] ^= a;
        let mut t = (a, 7u16);
        t.0 = t.0.wrapping_add(v);
        t.1 *= 2;
        (p.arr, p.b, m, t)
    }
    pub fn enum_eq(x: u8, y: u8, z: u16) -> (bool, bool, bool, bool, u32) {
        let e1 = E::B(x, y);
        let e2 = E::B(y, x);
        let e3 = E::C { x: z, p: BASE };
        let e4 = E::C { p: P { a: x, ..BASE }, x: z };
        let w1 = W(x, (y, x > y));
        let w2 = W(x, (y, y < x));
        let tag = match e4 { E::A => 0u32, E::B(a, _) => a as u32, E::C { p: P { a, .. }, x } => a as u32 + x as u32 };
        (e1 == e2, e3 == e4, e1 != E::A, w1 == w2, tag)
    }
    pub fn table(i: u8) -> u32 {
        let k = (i % 5) as usize;
        TABLE[k] as u32 + TABLE.len() as u32 + TABLE[4 - k] as u32
    }
    pub fn slicing(s: &[u8], a: usize, b: usize) -> (usize, u32, usize, usize) {
        if a <= b && b <= s.len() {
            let t = &s[a..b];
            let u = &s[a..];
            let v = &s[..b];
            let w = &t[..];
            let first = match w.first() { Some(x) => *x as u32, None => 1000 };
            (t.len(), first, u.len(), v.len())
        } else {
            (0, 0, 0, 0)
        }
    }
    pub fn splits(s: &[u8], mid: usize) -> (usize, usize, u32) {
        let (x, y) = match s.split_at_checked(mid) { Some(p) => p, None => s.split_at(0) };
        let f = match s.split_first() { Some((h, t)) => (*h as u32).wrapping_add(t.len() as u32), None => 0 };
        let l = match s.split_last() { Some((h, t)) => (*h as u32) << 8u32 | t.len() as u32, None => 1 };
        (x.len(), y.len(), f ^ l)
    }
    pub fn chunks(s: &[u8]) -> (usize, usize, u32, u32) {
        let (c, r) = s.as_chunks::<3>();
        let mut acc = 0u32;
        for i in 0..c.len() {
            acc = acc.wrapping_mul(31).wrapping_add(c[i][0] as u32 + c[i][2] as u32);
        }
        let fc = match s.first_chunk::<2>() { Some(a) => u16::from_le_bytes(*a) as u32, None => 7 };
        let sfc = match s.split_first_chunk::<4>() { Some((h, t)) => u32::from_be_bytes(*h) ^ t.len() as u32, None => 9 };
        (c.len(), r.len(), acc, fc ^ sfc)
    }
    pub fn copies(src: &[u8], lo: usize) -> [u8; 8] {
        let mut out = [0xaau8; 8];
        let n = if src.len() < 4 { src.len() } else { 4 };
        if lo <= 4 {
            out[lo..lo + n].copy_from_slice(&src[..n]);
        }
        let mut two = [0u8; 2];
        if src.len() >= 2 {
            two.copy_from_slice(&src[src.len() - 2..]);
        }
        out[6] = two[0];
        out[7] = two[1];
        out
    }
    pub fn eqs(s: &[u8], a: [u8; 2], o: Option<u8>) -> (bool, bool, bool, bool) {
        let x = s == &a[..];
        let y = a == [1, 2];
        let z = o == Some(3) || o != None && a[0] == 0;
        let w = (a[0], o) == (a[1], None);
        (x, y, z, w)
    }
    pub fn gets(s: &[u16], i: usize) -> (u32, u32, u32) {
        let a = match s.get(i) { Some(v) => *v as u32, None => 70000 };
        let b = match s.last() { Some(v) => *v as u32, None => 70001 };
        let c = (s.is_empty() as u32).wrapping_add((s.len() as u32).wrapping_mul(2));
        (a, b, c)
    }
});

#[test]
fn data_differential() {
    let mut r = Rng::new(seed() + 4);
    let mut cases = Vec::new();
    cases.extend(fuzz!(&mut r, iters(200), data::update(a: u8, b: u16, k: u8)));
    cases.extend(fuzz!(&mut r, iters(300), data::places(a: u8, i: u8, v: u8)));
    cases.extend(fuzz!(&mut r, iters(300), data::enum_eq(x: u8, y: u8, z: u16)));
    cases.extend(fuzz!(&mut r, iters(100), data::table(i: u8)));
    for _ in 0..iters(400) {
        let n = r.below(10) as usize;
        let v: Vec<u8> = (0..n).map(|_| r.int(8) as u8).collect();
        let a = r.below(12) as usize;
        let b = r.below(12) as usize;
        cases.push(fixed!(data::slicing(s: Vec<u8> = v.clone(), a: usize = a, b: usize = b)));
        cases.push(fixed!(data::splits(s: Vec<u8> = v.clone(), mid: usize = a)));
        cases.push(fixed!(data::copies(src: Vec<u8> = v.clone(), lo: usize = a % 7)));
    }
    cases.extend(fuzz!(&mut r, iters(300), data::chunks(s: Vec<u8>)));
    for _ in 0..iters(300) {
        let n = r.below(4) as usize;
        let v: Vec<u8> = (0..n).map(|_| r.below(4) as u8).collect();
        let a = [r.below(4) as u8, r.below(4) as u8];
        let o = if r.below(3) == 0 { None } else { Some(r.below(5) as u8) };
        cases.push(fixed!(data::eqs(s: Vec<u8> = v.clone(), a: [u8; 2] = a, o: Option<u8> = o)));
    }
    cases.extend(fuzz!(&mut r, iters(300), data::gets(s: Vec<u16>, i: usize)));
    let rep = run("data", data::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// battery 6: tail recursion printed as loops (parallel parameter rebinding)
// ---------------------------------------------------------------------------

program_x!(tails {
    pub fn swap_rec(a: u32, b: u32, n: u8) -> (u32, u32) {
        if n == 0 { (a, b) } else { swap_rec(b, a ^ b.rotate_left(3), n - 1) }
    }
    pub fn two_calls(x: u32, n: u8) -> u32 {
        if n == 0 {
            x
        } else if x % 2 == 0 {
            two_calls(x / 2, n - 1)
        } else {
            two_calls(x.wrapping_mul(3).wrapping_add(1), n - 1)
        }
    }
    pub fn slice_state(xs: &[u8], lo: u8, hi: u8) -> (u8, u8) {
        match xs {
            [] => (lo, hi),
            [x, rest @ ..] if *x < lo => slice_state(rest, *x, hi),
            [x, rest @ ..] if *x > hi => slice_state(rest, lo, *x),
            [_, rest @ ..] => slice_state(rest, hi, lo),
        }
    }
    pub fn let_tail(xs: &[u16], acc: u32) -> u32 {
        match xs {
            [] => acc,
            [x, rest @ ..] => {
                let acc = acc.wrapping_add(*x as u32);
                let_tail(rest, acc)
            }
        }
    }
    pub fn shadow_params(a: u32, b: u32, n: u8) -> u32 {
        if n == 0 {
            a.wrapping_sub(b)
        } else {
            let b = a.wrapping_add(1);
            let a = b.wrapping_mul(3);
            shadow_params(b, a, n - 1)
        }
    }
} native {
    pub fn fib(n: u8, a: u64, b: u64) -> u64 {
        match n {
            0 => a,
            k => fib(k - 1, b, a.wrapping_add(b)),
        }
    }
    pub fn early(xs: &[u8], acc: u32) -> u32 {
        let Some((h, t)) = xs.split_first() else { return acc };
        if *h == 0 {
            return acc.wrapping_add(1000000);
        }
        early(t, acc.wrapping_add(*h as u32))
    }
    pub fn opt_tail(xs: &[u8], acc: u16) -> Option<u16> {
        let (h, t) = xs.split_first()?;
        if t.is_empty() { Some(acc ^ *h as u16) } else { opt_tail(t, acc.checked_add(*h as u16)?) }
    }
} dsl r#"
#[decreases(n)]
pub fn fib(n: u8, a: u64, b: u64) -> u64 {
    match n {
        0 => a,
        k => fib(k - 1, b, a.wrapping_add(b)),
    }
}
#[decreases(xs.len())]
pub fn early(xs: &[u8], acc: u32) -> u32 {
    let Some((h, t)) = xs.split_first() else { return acc };
    if *h == 0 {
        return acc.wrapping_add(1000000);
    }
    early(t, acc.wrapping_add(*h as u32))
}
#[decreases(xs.len())]
pub fn opt_tail(xs: &[u8], acc: u16) -> Option<u16> {
    let (h, t) = xs.split_first()?;
    if t.is_empty() { Some(acc ^ *h as u16) } else { opt_tail(t, acc.checked_add(*h as u16)?) }
}
"#);

#[test]
fn tail_recursion_differential() {
    let mut r = Rng::new(seed() + 5);
    let mut cases = Vec::new();
    for _ in 0..iters(300) {
        let n = r.below(20) as u8;
        cases.push(fixed!(tails::swap_rec(a: u32 = r.int(32) as u32, b: u32 = r.int(32) as u32, n: u8 = n)));
        cases.push(fixed!(tails::fib(n: u8 = r.below(100) as u8, a: u64 = r.int(64), b: u64 = r.int(64))));
        cases.push(fixed!(tails::two_calls(x: u32 = r.int(32) as u32, n: u8 = r.below(60) as u8)));
        cases.push(fixed!(tails::shadow_params(a: u32 = r.int(32) as u32, b: u32 = r.int(32) as u32, n: u8 = n)));
    }
    cases.extend(fuzz!(&mut r, iters(300), tails::slice_state(xs: Vec<u8>, lo: u8, hi: u8)));
    cases.extend(fuzz!(&mut r, iters(300), tails::let_tail(xs: Vec<u16>, acc: u32)));
    cases.extend(fuzz!(&mut r, iters(300), tails::early(xs: Vec<u8>, acc: u32)));
    cases.extend(fuzz!(&mut r, iters(300), tails::opt_tail(xs: Vec<u8>, acc: u16)));
    let rep = run("tails", tails::SRC, &cases);
    rep.assert_clean();
}

// ---------------------------------------------------------------------------
// random programs: a generator of well-typed, mostly provable programs over
// the subset (SSA, shadowing, compound assignment, guarded partial ops,
// integer/option/slice/array matches with guards, ranges and or-patterns,
// early returns, let-else, for/while loops, calls between functions), and a
// differential runner: native (source, debug) vs kernel.
// ---------------------------------------------------------------------------

pub mod rgen {
    use super::Rng;
    use std::fmt::Write as _;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum T {
        U8,
        U16,
        U32,
        U64,
        Usize,
        Bool,
    }
    pub const INTS: [T; 5] = [T::U8, T::U16, T::U32, T::U64, T::Usize];

    impl T {
        pub fn name(self) -> &'static str {
            match self {
                T::U8 => "u8",
                T::U16 => "u16",
                T::U32 => "u32",
                T::U64 => "u64",
                T::Usize => "usize",
                T::Bool => "bool",
            }
        }
        pub fn bits(self) -> u32 {
            match self {
                T::U8 => 8,
                T::U16 => 16,
                T::U32 => 32,
                T::U64 | T::Usize => 64,
                T::Bool => 1,
            }
        }
        pub fn max(self) -> u64 {
            if self.bits() == 64 { u64::MAX } else { (1u64 << self.bits()) - 1 }
        }
    }

    /// Parameter types.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum P {
        S(T),
        Opt(T),
        Bytes,
    }

    impl P {
        pub fn name(self) -> String {
            match self {
                P::S(t) => t.name().into(),
                P::Opt(t) => format!("Option<{}>", t.name()),
                P::Bytes => "&[u8]".into(),
            }
        }
        pub fn driver_ty(self) -> String {
            match self {
                P::Bytes => "&'static [u8]".into(),
                p => p.name(),
            }
        }
    }

    /// A random input value: (JSON, Rust expression).
    pub fn input(r: &mut Rng, p: P) -> (String, String) {
        match p {
            P::S(T::Bool) => {
                let b = r.below(2) == 1;
                (b.to_string(), b.to_string())
            }
            P::S(t) => {
                let v = r.int(t.bits());
                (v.to_string(), format!("{v}{}", t.name()))
            }
            P::Opt(t) => {
                if r.below(4) == 0 {
                    ("null".into(), format!("None::<{}>", t.name()))
                } else {
                    let (j, s) = input(r, P::S(t));
                    (format!("{{\"Some\":{j}}}"), format!("Some({s})"))
                }
            }
            P::Bytes => {
                let n = match r.below(4) {
                    0 => r.below(3),
                    _ => r.below(10),
                };
                let v: Vec<u64> = (0..n).map(|_| if r.below(3) == 0 { r.below(4) } else { r.int(8) }).collect();
                (format!("[{}]", v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")), format!("&[{}]", v.iter().map(|x| format!("{x}u8")).collect::<Vec<_>>().join(", ")))
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Local {
        name: String,
        ty: T,
        mutable: bool,
        array: bool,
    }

    /// A generated function's signature.
    #[derive(Clone, Debug)]
    pub struct Sig {
        pub name: String,
        pub params: Vec<(String, P)>,
        pub ret: Vec<T>,
    }

    impl Sig {
        pub fn ret_ty(&self) -> String {
            if self.ret.len() == 1 { self.ret[0].name().into() } else { format!("({})", self.ret.iter().map(|t| t.name()).collect::<Vec<_>>().join(", ")) }
        }
    }

    pub struct G<'r> {
        pub r: &'r mut Rng,
        locals: Vec<Local>,
        scopes: Vec<usize>,
        opts: Vec<(String, T)>,
        slice: Option<String>,
        arrays: Vec<(String, T, bool)>,
        ret: Vec<T>,
        fresh: u32,
        in_loop: u32,
        pub callees: Vec<Sig>,
        stmts_left: i32,
        /// Straight-line mode (no branching on inputs).
        pub straight: bool,
    }

    fn lit(r: &mut Rng, t: T) -> String {
        match t {
            T::Bool => (r.below(2) == 1).to_string(),
            _ => {
                let v = r.int(t.bits());
                if r.below(10) == 0 && v <= 0xffff_ffff {
                    format!("0x{v:x}{}", t.name())
                } else {
                    format!("{v}{}", t.name())
                }
            }
        }
    }

    impl<'r> G<'r> {
        pub fn new(r: &'r mut Rng) -> G<'r> {
            G { r, locals: vec![], scopes: vec![], opts: vec![], slice: None, arrays: vec![], ret: vec![], fresh: 0, in_loop: 0, callees: vec![], stmts_left: 0, straight: false }
        }

        fn pick<X: Copy>(&mut self, xs: &[X]) -> X {
            xs[self.r.below(xs.len() as u64) as usize]
        }
        fn chance(&mut self, n: u64) -> bool {
            self.r.below(n) == 0
        }
        fn fresh(&mut self, p: &str) -> String {
            self.fresh += 1;
            format!("{p}{}", self.fresh)
        }
        fn int_ty(&mut self) -> T {
            self.pick(&INTS)
        }
        fn push_scope(&mut self) {
            self.scopes.push(self.locals.len());
        }
        fn pop_scope(&mut self) {
            let n = self.scopes.pop().unwrap();
            self.locals.truncate(n);
            let na = self.arrays.len();
            let _ = na;
        }
        /// Visible locals of type `t` (innermost binding of each name).
        fn vars(&self, t: T, mutable: bool) -> Vec<String> {
            let mut seen: Vec<&str> = vec![];
            let mut out = vec![];
            for l in self.locals.iter().rev() {
                if seen.contains(&l.name.as_str()) {
                    continue;
                }
                seen.push(&l.name);
                if !l.array && l.ty == t && (!mutable || l.mutable) {
                    out.push(l.name.clone());
                }
            }
            out
        }
        fn declare(&mut self, name: &str, ty: T, mutable: bool) {
            self.locals.push(Local { name: name.into(), ty, mutable, array: false });
        }

        // ------------------------------------------------------------------
        // expressions
        // ------------------------------------------------------------------

        fn leaf(&mut self, t: T) -> String {
            let vs = self.vars(t, false);
            if !vs.is_empty() && !self.chance(4) {
                return self.pick_s(&vs);
            }
            lit(self.r, t)
        }
        fn pick_s(&mut self, xs: &[String]) -> String {
            let i = self.r.below(xs.len() as u64) as usize;
            xs[i].clone()
        }

        pub fn ex(&mut self, t: T, d: u32) -> String {
            if t == T::Bool {
                return self.bex(d);
            }
            if d == 0 || self.chance(4) {
                return self.leaf(t);
            }
            let tn = t.name();
            let d1 = d - 1;
            if self.straight {
                return self.straight_ex(t, d1);
            }
            match self.r.below(26) {
                0 => format!("({}).wrapping_add({})", self.ex(t, d1), self.ex(t, d1)),
                1 => format!("({}).wrapping_sub({})", self.ex(t, d1), self.ex(t, d1)),
                2 => format!("({}).wrapping_mul({})", self.ex(t, d1), self.ex(t, d1)),
                3 => format!("({} ^ {})", self.ex(t, d1), self.ex(t, d1)),
                4 => format!("({} & {})", self.ex(t, d1), self.ex(t, d1)),
                5 => format!("({} | {})", self.ex(t, d1), self.ex(t, d1)),
                6 => format!("(!{})", self.ex(t, d1)),
                7 => {
                    let m = self.pick(&["rotate_left", "rotate_right", "wrapping_shl", "wrapping_shr"]);
                    format!("({}).{m}({})", self.ex(t, d1), self.ex(T::U32, d1))
                }
                8 => {
                    let at = self.pick(&[T::U8, T::U32, T::U64, T::U16]);
                    let op = self.pick(&["<<", ">>"]);
                    format!("({} {op} ({} % {}{}))", self.ex(t, d1), self.ex(at, d1), t.bits(), at.name())
                }
                9 => {
                    let m = self.pick(&["min", "max", "saturating_add", "saturating_sub", "saturating_mul", "abs_diff"]);
                    format!("({}).{m}({})", self.ex(t, d1), self.ex(t, d1))
                }
                10 => {
                    let m = self.pick(&["count_ones", "leading_zeros", "trailing_zeros"]);
                    format!("(({}).{m}() as {tn})", self.ex(t, d1))
                }
                11 => format!("({}).swap_bytes()", self.ex(t, d1)),
                12 => {
                    let m = self.pick(&["checked_add", "checked_sub", "checked_mul", "checked_div"]);
                    format!("({}).{m}({}).unwrap_or({})", self.ex(t, d1), self.ex(t, d1), self.ex(t, d1))
                }
                13 | 14 => {
                    let from = self.pick(&[T::U8, T::U16, T::U32, T::U64, T::Usize, T::Bool]);
                    let e = self.ex(from, d1);
                    let e = self.no_bare_lit(e, from);
                    format!("({e} as {tn})")
                }
                15 => format!("(if {} {{ {} }} else {{ {} }})", self.bex(d1), self.ex(t, d1), self.ex(t, d1)),
                16 | 17 => self.int_match(t, d1),
                18 | 19 => self.guarded(t, d1),
                20 => self.slice_read(t, d1),
                21 => self.opt_read(t, d1),
                22 => self.array_read(t, d1),
                23 => self.call(t, d1),
                24 => {
                    let n = self.fresh("b");
                    let bt = self.int_ty();
                    let v = self.ex(bt, d1);
                    self.push_scope();
                    self.declare(&n, bt, false);
                    let body = self.ex(t, d1);
                    self.pop_scope();
                    format!("{{ let {n}: {} = {v}; {body} }}", bt.name())
                }
                _ => {
                    let e = self.bex(d1);
                    let e = self.no_bare_lit(e, T::Bool);
                    format!("({e} as {tn})")
                }
            }
        }

        /// The front end types a bare literal operand of `as` with the cast
        /// target even when it is suffixed (`245u8 as usize` is rejected);
        /// hide literals behind a block.
        fn no_bare_lit(&mut self, e: String, t: T) -> String {
            let bare = e.starts_with(|c: char| c.is_ascii_digit()) || e == "true" || e == "false";
            if bare {
                let c = self.fresh("c");
                format!("{{ let {c}: {} = {e}; {c} }}", t.name())
            } else {
                e
            }
        }

        /// Straight-line integer expressions.
        fn straight_ex(&mut self, t: T, d1: u32) -> String {
            let tn = t.name();
            match self.r.below(16) {
                0 => format!("({}).wrapping_add({})", self.ex(t, d1), self.ex(t, d1)),
                1 => format!("({}).wrapping_sub({})", self.ex(t, d1), self.ex(t, d1)),
                2 => format!("({}).wrapping_mul({})", self.ex(t, d1), self.ex(t, d1)),
                3 => {
                    let op = self.pick(&["^", "&", "|"]);
                    format!("({} {op} {})", self.ex(t, d1), self.ex(t, d1))
                }
                4 => format!("(!{})", self.ex(t, d1)),
                5 => {
                    let m = self.pick(&["rotate_left", "rotate_right", "wrapping_shl", "wrapping_shr"]);
                    format!("({}).{m}({})", self.ex(t, d1), self.ex(T::U32, d1))
                }
                6 => {
                    let k = self.r.below(t.bits() as u64);
                    let at = self.pick(&["u8", "u32", "u64", "usize"]);
                    let op = self.pick(&["<<", ">>"]);
                    format!("({} {op} {k}{at})", self.ex(t, d1))
                }
                7 => {
                    let m = self.pick(&["min", "max", "saturating_add", "saturating_sub", "saturating_mul", "abs_diff"]);
                    format!("({}).{m}({})", self.ex(t, d1), self.ex(t, d1))
                }
                8 => {
                    let m = self.pick(&["count_ones", "leading_zeros", "trailing_zeros"]);
                    format!("(({}).{m}() as {tn})", self.ex(t, d1))
                }
                9 => format!("({}).swap_bytes()", self.ex(t, d1)),
                10 | 11 => {
                    let from = self.pick(&[T::U8, T::U16, T::U32, T::U64, T::Usize, T::Bool]);
                    let e = self.ex(from, d1);
                    let e = self.no_bare_lit(e, from);
                    format!("({e} as {tn})")
                }
                12 => {
                    // byte conversions
                    let src = self.pick(&[T::U16, T::U32, T::U64]);
                    let n = src.bits() / 8;
                    let m = self.pick(&["to_le_bytes", "to_be_bytes"]);
                    let k = self.r.below(n as u64);
                    format!("(({}).{m}()[{k}] as {tn})", self.ex(src, d1))
                }
                13 if t != T::U8 && t != T::Usize => {
                    let n = t.bits() / 8;
                    let bs: Vec<String> = (0..n).map(|_| self.ex(T::U8, d1.min(1))).collect();
                    let m = self.pick(&["from_le_bytes", "from_be_bytes"]);
                    format!("{tn}::{m}([{}])", bs.join(", "))
                }
                14 => self.array_read(t, d1),
                _ => {
                    let n = self.fresh("b");
                    let bt = self.int_ty();
                    let v = self.ex(bt, d1);
                    self.push_scope();
                    self.declare(&n, bt, false);
                    let body = self.ex(t, d1);
                    self.pop_scope();
                    format!("{{ let {n}: {} = {v}; {body} }}", bt.name())
                }
            }
        }

        pub fn bex(&mut self, d: u32) -> String {
            if d == 0 || self.chance(4) {
                return self.leaf(T::Bool);
            }
            let d1 = d - 1;
            match self.r.below(12) {
                0..=3 => {
                    let t = self.int_ty();
                    let op = self.pick(&["<", "<=", "==", "!=", ">", ">="]);
                    format!("({} {op} {})", self.ex(t, d1), self.ex(t, d1))
                }
                4 => format!("(!{})", self.bex(d1)),
                5 => format!("({} && {})", self.bex(d1), self.bex(d1)),
                6 => format!("({} || {})", self.bex(d1), self.bex(d1)),
                7 => {
                    let op = self.pick(&["^", "&", "|", "==", "!="]);
                    format!("({} {op} {})", self.bex(d1), self.bex(d1))
                }
                8 => {
                    let t = self.int_ty();
                    format!("({}).is_power_of_two()", self.ex(t, d1))
                }
                9 => match (self.opts.is_empty(), self.slice.clone()) {
                    (false, _) if self.chance(2) => {
                        let i = self.r.below(self.opts.len() as u64) as usize;
                        let m = self.pick(&["is_some", "is_none"]);
                        format!("{}.{m}()", self.opts[i].0)
                    }
                    (_, Some(s)) => format!("{s}.is_empty()"),
                    _ => self.leaf(T::Bool),
                },
                10 => self.int_match(T::Bool, d1),
                _ => format!("(if {} {{ {} }} else {{ {} }})", self.bex(d1), self.bex(d1), self.bex(d1)),
            }
        }

        fn lit_in(&mut self, t: T, near: u64) -> u64 {
            let v = if self.chance(2) { near.wrapping_add(self.r.below(4)) } else { self.r.int(t.bits()) };
            v & t.max()
        }

        /// `match e { lit, range, binding @ range if g, or-pattern, _ }`.
        fn int_match(&mut self, t: T, d: u32) -> String {
            let st = self.int_ty();
            let stn = st.name();
            let scrut = self.ex(st, d);
            let mut s = format!("(match {scrut} {{ ");
            let narms = 1 + self.r.below(4);
            let base = self.r.int(st.bits());
            for _ in 0..narms {
                match self.r.below(5) {
                    0 => {
                        let v = self.lit_in(st, base);
                        let _ = write!(s, "{v}{stn} => {}, ", self.ex(t, d));
                    }
                    1 => {
                        let a = self.lit_in(st, base);
                        let b = self.lit_in(st, base);
                        let (a, b) = (a.min(b), a.max(b));
                        let _ = write!(s, "{a}{stn}..={b}{stn} => {}, ", self.ex(t, d));
                    }
                    2 => {
                        let a = self.lit_in(st, base);
                        let b = self.lit_in(st, base);
                        let (a, b) = (a.min(b), a.max(b));
                        let k = self.fresh("k");
                        self.push_scope();
                        self.declare(&k, st, false);
                        let g = self.bex(d);
                        let body = self.ex(t, d);
                        self.pop_scope();
                        let _ = write!(s, "{k} @ {a}{stn}..={b}{stn} if {g} => {body}, ");
                    }
                    3 => {
                        let a = self.lit_in(st, base);
                        let b = self.lit_in(st, base);
                        let c = self.lit_in(st, base);
                        let _ = write!(s, "{a}{stn} | {b}{stn} | {c}{stn} => {}, ", self.ex(t, d));
                    }
                    _ => {
                        let k = self.fresh("k");
                        self.push_scope();
                        self.declare(&k, st, false);
                        let g = self.bex(d);
                        let body = self.ex(t, d);
                        self.pop_scope();
                        let _ = write!(s, "{k} if {g} => {body}, ");
                    }
                }
            }
            let _ = write!(s, "_ => {} }})", self.ex(t, d));
            s
        }

        /// Partial operators under a guard that proves them.
        fn guarded(&mut self, t: T, d: u32) -> String {
            let tn = t.name();
            let a = self.fresh("g");
            let b = self.fresh("g");
            let ea = self.ex(t, d);
            let eb = self.ex(t, d);
            match self.r.below(7) {
                0 => {
                    let ec = self.ex(t, d);
                    format!("{{ let {a}: {tn} = {ea}; let {b}: {tn} = {eb}; if {b} != 0 {{ {a} / {b} }} else {{ {ec} }} }}")
                }
                1 => {
                    let ec = self.ex(t, d);
                    format!("{{ let {a}: {tn} = {ea}; let {b}: {tn} = {eb}; if {b} > 0 {{ {a} % {b} }} else {{ {ec} }} }}")
                }
                2 => format!("{{ let {a}: {tn} = {ea}; let {b}: {tn} = {eb}; if {a} >= {b} {{ {a} - {b} }} else {{ {b} - {a} }} }}"),
                3 => format!("{{ let {a}: {tn} = {ea}; if {a} < {} {{ {a} + 1 }} else {{ {a} }} }}", t.max()),
                4 => format!("{{ let {a}: {tn} = {ea} % 100; let {b}: {tn} = {eb} % 100; {a} + {b} }}"),
                5 => format!("{{ let {a}: {tn} = {ea} % 16; let {b}: {tn} = {eb} % 15; {a} * {b} + {b} }}"),
                _ => format!("{{ let {a}: {tn} = {ea}; if {a} > 0 {{ {a} - 1 }} else {{ {eb} }} }}"),
            }
        }

        fn slice_read(&mut self, t: T, d: u32) -> String {
            let Some(s) = self.slice.clone() else { return self.leaf(t) };
            let tn = t.name();
            match self.r.below(6) {
                0 => {
                    let v = self.fresh("v");
                    let i = self.ex(T::Usize, d);
                    let e = self.ex(t, d);
                    format!("(match {s}.get({i}) {{ Some({v}) => *{v} as {tn}, None => {e} }})")
                }
                1 => format!("({s}.len() as {tn})"),
                2 => {
                    let i = self.fresh("i");
                    let ei = self.ex(T::Usize, d);
                    let e = self.ex(t, d);
                    format!("{{ let {i}: usize = {ei}; if {i} < {s}.len() {{ {s}[{i}] as {tn} }} else {{ {e} }} }}")
                }
                3 => {
                    let (a, b) = (self.fresh("h"), self.fresh("h"));
                    let e0 = self.ex(t, d);
                    self.push_scope();
                    self.declare(&a, T::U8, false);
                    let e1 = self.ex(t, d);
                    self.declare(&b, T::U8, false);
                    let e2 = self.ex(t, d);
                    self.pop_scope();
                    let r = self.fresh("rest");
                    match self.r.below(3) {
                        0 => format!("(match {s} {{ [] => {e0}, [{a}] => {{ let {a}: u8 = *{a}; {e1} }}, [{a}, .., {b}] => {{ let {a}: u8 = *{a}; let {b}: u8 = *{b}; {e2} }} }})"),
                        1 => format!("(match {s} {{ [{a}, {r} @ ..] if {r}.len() > 2 => {{ let {a}: u8 = *{a}; {e1} }}, [{r} @ .., {a}, {b}] => {{ let {a}: u8 = *{a}; let {b}: u8 = *{b}; ({e2}).wrapping_add({r}.len() as {tn}) }}, _ => {e0} }})"),
                        _ => format!("(match {s} {{ [{r} @ .., {a}] => {{ let {a}: u8 = *{a}; ({e1}).wrapping_mul({r}.len() as {tn}) }}, [] => {e0} }})"),
                    }
                }
                4 => {
                    let v = self.fresh("v");
                    let e = self.ex(t, d);
                    format!("(match {s}.first() {{ Some({v}) => *{v} as {tn}, None => {e} }})")
                }
                _ => {
                    let e = self.ex(t, d);
                    let v = self.fresh("v");
                    format!("(match {s}.last() {{ Some({v}) => (*{v} as {tn}).wrapping_add({e}), None => 3{tn} }})")
                }
            }
        }

        fn opt_read(&mut self, t: T, d: u32) -> String {
            if self.opts.is_empty() {
                return self.leaf(t);
            }
            let i = self.r.below(self.opts.len() as u64) as usize;
            let (o, ot) = self.opts[i].clone();
            let tn = t.name();
            match self.r.below(3) {
                0 => {
                    let e = self.ex(ot, d);
                    format!("({o}.unwrap_or({e}) as {tn})")
                }
                _ => {
                    let v = self.fresh("v");
                    let w = self.fresh("v");
                    self.push_scope();
                    self.declare(&v, ot, false);
                    let g = self.bex(d);
                    let e1 = self.ex(t, d);
                    self.pop_scope();
                    self.push_scope();
                    self.declare(&w, ot, false);
                    let e2 = self.ex(t, d);
                    self.pop_scope();
                    let e3 = self.ex(t, d);
                    format!("(match {o} {{ Some({v}) if {g} => {e1}, Some({w}) => ({e2}).wrapping_add({w} as {tn}), None => {e3} }})")
                }
            }
        }

        fn array_read(&mut self, t: T, d: u32) -> String {
            let cands: Vec<(String, T)> = self.arrays.iter().filter(|a| self.locals.iter().rev().find(|l| l.name == a.0).is_some_and(|l| l.array)).map(|a| (a.0.clone(), a.1)).collect();
            if cands.is_empty() {
                return self.leaf(t);
            }
            let (a, _at) = cands[self.r.below(cands.len() as u64) as usize].clone();
            if self.straight {
                let k = self.r.below(4);
                return format!("({a}[{k}] as {})", t.name());
            }
            let i = self.ex(T::U32, d);
            format!("({a}[({i} % 4u32) as usize] as {})", t.name())
        }

        fn call(&mut self, t: T, d: u32) -> String {
            let cs: Vec<Sig> = self.callees.clone();
            if cs.is_empty() {
                return self.leaf(t);
            }
            let c = cs[self.r.below(cs.len() as u64) as usize].clone();
            let mut args = vec![];
            for (_, p) in &c.params {
                args.push(match p {
                    P::S(pt) => self.ex(*pt, d.min(1)),
                    P::Opt(pt) => {
                        let same: Vec<String> = self.opts.iter().filter(|o| o.1 == *pt).map(|o| o.0.clone()).collect();
                        if !same.is_empty() && self.chance(2) {
                            self.pick_s(&same)
                        } else if self.chance(3) {
                            format!("None::<{}>", pt.name())
                        } else {
                            format!("Some({})", self.ex(*pt, d.min(1)))
                        }
                    }
                    P::Bytes => match self.slice.clone() {
                        Some(s) if !self.chance(3) => s,
                        _ => "&[1u8, 200u8, 3u8]".into(),
                    },
                });
            }
            let k = self.r.below(c.ret.len() as u64) as usize;
            let call = format!("{}({})", c.name, args.join(", "));
            let proj = if c.ret.len() == 1 { call } else { format!("{call}.{k}") };
            format!("({proj} as {})", t.name())
        }

        // ------------------------------------------------------------------
        // statements
        // ------------------------------------------------------------------

        fn ret_expr(&mut self, d: u32) -> String {
            let rs: Vec<T> = self.ret.clone();
            let es: Vec<String> = rs.iter().map(|t| self.ex(*t, d)).collect();
            if es.len() == 1 { format!("({})", es[0]) } else { format!("({})", es.join(", ")) }
        }

        fn stmt(&mut self, out: &mut String, ind: usize) {
            self.stmts_left -= 1;
            let pad = " ".repeat(ind);
            let muts: Vec<(String, T)> = {
                let mut seen: Vec<String> = vec![];
                let mut v = vec![];
                for l in self.locals.iter().rev() {
                    if seen.contains(&l.name) {
                        continue;
                    }
                    seen.push(l.name.clone());
                    if l.mutable && !l.array && l.ty != T::Bool {
                        v.push((l.name.clone(), l.ty));
                    }
                }
                v
            };
            let choice = if self.straight { [0u64, 1, 2, 3, 4, 5, 6, 7, 8, 11, 17, 19][self.r.below(12) as usize] } else { self.r.below(20) };
            match choice {
                0 | 1 => {
                    let t = self.pick(&[T::U8, T::U16, T::U32, T::U64, T::Usize, T::Bool]);
                    let n = self.fresh("x");
                    let e = self.ex(t, 3);
                    let _ = writeln!(out, "{pad}let {n}: {} = {e};", t.name());
                    self.declare(&n, t, false);
                }
                2 | 3 => {
                    let t = self.int_ty();
                    let n = self.fresh("m");
                    let e = self.ex(t, 2);
                    let _ = writeln!(out, "{pad}let mut {n}: {} = {e};", t.name());
                    self.declare(&n, t, true);
                }
                4 => {
                    // shadowing (possibly with a different type)
                    let names: Vec<String> = self.locals.iter().map(|l| l.name.clone()).collect();
                    if names.is_empty() {
                        return;
                    }
                    let n = self.pick_s(&names);
                    let t = self.int_ty();
                    let e = self.ex(t, 2);
                    let m = self.chance(2);
                    let _ = writeln!(out, "{pad}let {}{n}: {} = {e};", if m { "mut " } else { "" }, t.name());
                    self.declare(&n, t, m);
                }
                5..=8 if !muts.is_empty() => {
                    let (m, t) = muts[self.r.below(muts.len() as u64) as usize].clone();
                    let tn = t.name();
                    let e = self.ex(t, 2);
                    let which = if self.straight { [0u64, 1, 2, 3, 4, 7][self.r.below(6) as usize] } else { self.r.below(9) };
                    match which {
                        0 => {
                            let _ = writeln!(out, "{pad}{m} = {e};");
                        }
                        1 => {
                            let _ = writeln!(out, "{pad}{m} ^= {e};");
                        }
                        2 => {
                            let _ = writeln!(out, "{pad}{m} |= {e};");
                        }
                        3 => {
                            let _ = writeln!(out, "{pad}{m} &= {e};");
                        }
                        4 => {
                            let _ = writeln!(out, "{pad}{m} = {m}.wrapping_add({e});");
                        }
                        5 => {
                            let _ = writeln!(out, "{pad}if {m} < {} {{ {m} += 1; }}", t.max());
                        }
                        6 => {
                            let _ = writeln!(out, "{pad}if {m} > 0 {{ {m} -= 1; }}");
                        }
                        7 => {
                            let at = self.pick(&[T::U8, T::U32]);
                            let s = self.ex(at, 1);
                            let op = self.pick(&["<<=", ">>="]);
                            let _ = writeln!(out, "{pad}{m} {op} {s} % {}{};", t.bits(), at.name());
                        }
                        _ => {
                            let _ = writeln!(out, "{pad}{m} %= {e} | 1{tn};");
                        }
                    }
                }
                9 | 10 if !muts.is_empty() => {
                    // assigning branches
                    let c = self.bex(2);
                    let (m1, t1) = muts[self.r.below(muts.len() as u64) as usize].clone();
                    let (m2, t2) = muts[self.r.below(muts.len() as u64) as usize].clone();
                    let e1 = self.ex(t1, 2);
                    let e2 = self.ex(t2, 2);
                    if self.chance(2) {
                        let _ = writeln!(out, "{pad}if {c} {{ {m1} = {e1}; }} else {{ {m2} = {e2}; }}");
                    } else {
                        let st = self.int_ty();
                        let scr = self.ex(st, 1);
                        let a = self.r.int(st.bits());
                        let b = self.r.int(st.bits());
                        let (a, b) = (a.min(b), a.max(b));
                        let e3 = self.ex(t1, 1);
                        let _ = writeln!(out, "{pad}match {scr} {{ {a}{sn}..={b}{sn} => {{ {m1} = {e1}; }} _ if {c} => {{ {m2} = {e2}; }} _ => {{ {m1} = {e3}; }} }}", sn = st.name());
                    }
                }
                11 => {
                    // arrays
                    let t = self.int_ty();
                    let n = self.fresh("a");
                    let e = self.ex(t, 1);
                    let _ = writeln!(out, "{pad}let mut {n}: [{}; 4] = [{e}; 4];", t.name());
                    for _ in 0..(1 + self.r.below(3)) {
                        let i = self.leaf(T::U32);
                        let v = self.ex(t, 2);
                        let op = self.pick(&["=", "^=", "|="]);
                        if self.straight {
                            let k = self.r.below(4);
                            let _ = writeln!(out, "{pad}{n}[{k}] {op} {v};");
                        } else {
                            let _ = writeln!(out, "{pad}{n}[({i} % 4u32) as usize] {op} {v};");
                        }
                    }
                    self.arrays.push((n.clone(), t, true));
                    self.locals.push(Local { name: n, ty: t, mutable: false, array: true });
                }
                12 => {
                    // nested block with its own scope
                    let _ = writeln!(out, "{pad}{{");
                    self.push_scope();
                    let k = 1 + self.r.below(3);
                    for _ in 0..k {
                        if self.stmts_left > 0 {
                            self.stmt(out, ind + 4);
                        }
                    }
                    self.pop_scope();
                    let _ = writeln!(out, "{pad}}}");
                }
                13 | 14 if self.in_loop == 0 && !muts.is_empty() => self.loop_stmt(out, ind, &muts),
                15 if self.in_loop == 0 => {
                    let c = self.bex(2);
                    let r = self.ret_expr(2);
                    let _ = writeln!(out, "{pad}if {c} {{ return {r}; }}");
                }
                16 if self.in_loop == 0 && !self.opts.is_empty() => {
                    let i = self.r.below(self.opts.len() as u64) as usize;
                    let (o, ot) = self.opts[i].clone();
                    let v = self.fresh("v");
                    let r = self.ret_expr(1);
                    let _ = writeln!(out, "{pad}let Some({v}) = {o} else {{ return {r}; }};");
                    self.declare(&v, ot, false);
                }
                17 => {
                    let t1 = self.int_ty();
                    let t2 = self.pick(&[T::U8, T::U16, T::U32, T::U64, T::Usize, T::Bool]);
                    let (a, b) = (self.fresh("p"), self.fresh("q"));
                    let e1 = self.ex(t1, 2);
                    let e2 = self.ex(t2, 2);
                    let _ = writeln!(out, "{pad}let ({a}, {b}): ({}, {}) = ({e1}, {e2});", t1.name(), t2.name());
                    self.declare(&a, t1, false);
                    self.declare(&b, t2, false);
                }
                18 if self.in_loop == 0 && self.slice.is_some() => {
                    let s = self.slice.clone().unwrap();
                    let (a, r) = (self.fresh("f"), self.fresh("r"));
                    let ret = self.ret_expr(1);
                    if self.chance(2) {
                        let _ = writeln!(out, "{pad}let [{a}, {r} @ ..] = {s} else {{ return {ret}; }};");
                    } else {
                        let _ = writeln!(out, "{pad}let [{r} @ .., {a}] = {s} else {{ return {ret}; }};");
                    }
                    let _ = writeln!(out, "{pad}let {a}: u8 = *{a};");
                    self.declare(&a, T::U8, false);
                    let rl = self.fresh("x");
                    let _ = writeln!(out, "{pad}let {rl}: usize = {r}.len();");
                    self.declare(&rl, T::Usize, false);
                }
                _ => {
                    let t = self.int_ty();
                    let n = self.fresh("x");
                    let e = self.ex(t, 3);
                    let _ = writeln!(out, "{pad}let {n} = {e};");
                    self.declare(&n, t, false);
                }
            }
        }

        fn loop_stmt(&mut self, out: &mut String, ind: usize, muts: &[(String, T)]) {
            let pad = " ".repeat(ind);
            self.in_loop += 1;
            let i = self.fresh("i");
            let kind = self.r.below(4);
            let muted: Vec<String> = muts.iter().map(|m| m.0.clone()).collect();
            let header = match kind {
                0 => {
                    let mut b = self.leaf(T::U32);
                    if muted.contains(&b) {
                        b = "5u32".into();
                    }
                    format!("for {i} in 0u32..({b} % 7u32)")
                }
                1 if self.slice.is_some() => {
                    let s = self.slice.clone().unwrap();
                    format!("for {i} in 0..{s}.len()")
                }
                2 => {
                    let mut a = self.leaf(T::U8);
                    let mut b = self.leaf(T::U8);
                    if muted.contains(&a) {
                        a = "1u8".into();
                    }
                    if muted.contains(&b) {
                        b = "2u8".into();
                    }
                    format!("for {i} in ({a} | 248u8)..=({b} | 250u8)")
                }
                _ => {
                    let k = self.fresh("w");
                    let b = self.leaf(T::U32);
                    let _ = writeln!(out, "{pad}let mut {k}: u32 = {b} % 6u32;");
                    self.declare(&k, T::U32, true);
                    format!("while {k} > 0 {{\n{pad}    proof! {{ decreases({k}); }}\n{pad}    {k} -= 1;\n{pad}   ")
                }
            };
            let ity = match kind {
                0 => Some(T::U32),
                1 if self.slice.is_some() => Some(T::Usize),
                2 => Some(T::U8),
                _ => None,
            };
            let is_while = ity.is_none();
            if is_while {
                let _ = write!(out, "{pad}{header}");
            } else {
                let _ = writeln!(out, "{pad}{header} {{");
            }
            self.push_scope();
            if let Some(t) = ity {
                self.declare(&i, t, false);
            }
            let n = 1 + self.r.below(3);
            for _ in 0..n {
                let (m, t) = muts[self.r.below(muts.len() as u64) as usize].clone();
                let e = if ity == Some(T::Usize) && self.chance(2) {
                    let s = self.slice.clone().unwrap();
                    format!("({s}[{i}] as {})", t.name())
                } else {
                    self.ex(t, 2)
                };
                match self.r.below(3) {
                    0 => {
                        let _ = writeln!(out, "{pad}    {m} = {m}.wrapping_add({e});");
                    }
                    1 => {
                        let _ = writeln!(out, "{pad}    {m} ^= {e};");
                    }
                    _ => {
                        let _ = writeln!(out, "{pad}    {m} = {m}.rotate_left(3).wrapping_mul(({e}) | 1);");
                    }
                }
            }
            if self.chance(3) {
                // a shadowing let inside the body must not leak out
                let (m, t) = muts[self.r.below(muts.len() as u64) as usize].clone();
                let e = self.ex(t, 1);
                let _ = writeln!(out, "{pad}    let {m}: {} = {e};", t.name());
                let _ = writeln!(out, "{pad}    let _ = {m};");
            }
            self.pop_scope();
            let _ = writeln!(out, "{pad}}}");
            self.in_loop -= 1;
        }

        /// A whole function.
        pub fn function(&mut self, name: &str) -> (Sig, String) {
            self.locals.clear();
            self.scopes.clear();
            self.opts.clear();
            self.arrays.clear();
            self.slice = None;
            self.fresh = 0;
            let np = 1 + self.r.below(4) as usize;
            let mut params = vec![];
            for k in 0..np {
                let p = if self.straight { P::S(self.int_ty()) } else { match self.r.below(8) {
                    0 => P::Opt(self.int_ty()),
                    1 => P::Bytes,
                    2 => P::S(T::Bool),
                    _ => P::S(self.int_ty()),
                } };
                let n = match p {
                    P::Bytes => {
                        if self.slice.is_some() {
                            continue;
                        }
                        "s".to_string()
                    }
                    P::Opt(_) => format!("o{k}"),
                    P::S(_) => format!("p{k}"),
                };
                match p {
                    P::S(t) => self.declare(&n, t, false),
                    P::Opt(t) => self.opts.push((n.clone(), t)),
                    P::Bytes => self.slice = Some(n.clone()),
                }
                params.push((n, p));
            }
            let nr = 1 + self.r.below(3) as usize;
            let ret: Vec<T> = (0..nr).map(|_| self.pick(&[T::U8, T::U16, T::U32, T::U64, T::Usize, T::Bool])).collect();
            self.ret = ret.clone();
            let sig = Sig { name: name.into(), params: params.clone(), ret };
            let mut body = String::new();
            self.stmts_left = 4 + self.r.below(8) as i32;
            while self.stmts_left > 0 {
                self.stmt(&mut body, 4);
            }
            let tail = self.ret_expr(3);
            let ps: Vec<String> = params.iter().map(|(n, p)| format!("{n}: {}", p.name())).collect();
            let src = format!("pub fn {name}({}) -> {} {{\n{body}    {tail}\n}}\n", ps.join(", "), sig.ret_ty());
            (sig, src)
        }
    }
}

/// Compiles and runs a driver over `module` (the plain source with a no-op
/// `proof!`), one output line per case.
fn run_driver(dir: &Path, tag: &str, module: &str, cases: &[Case], release: bool) -> Result<Vec<String>, String> {
    let modfile = format!("{tag}_module.rs");
    std::fs::write(dir.join(&modfile), module).unwrap();
    let mut main = format!("#![allow(unused)]\nmacro_rules! proof {{ ($($t:tt)*) => {{}}; }}\ninclude!(\"{modfile}\");\n");
    main.push_str(DRIVER_TOJ);
    let mut chunks = 0usize;
    let mut i = 0;
    while i < cases.len() {
        let f = &cases[i].f;
        let mut j = i;
        while j < cases.len() && j - i < 150 && &cases[j].f == f && cases[j].tys_rs == cases[i].tys_rs {
            j += 1;
        }
        let call_args: Vec<String> = (0..cases[i].arity).map(|k| format!("c.{k}")).collect();
        let _ = writeln!(main, "fn chunk{chunks}(out: &mut dyn std::io::Write) {{\n    let cases: &[{}] = &[", cases[i].tys_rs);
        for c in &cases[i..j] {
            let _ = writeln!(main, "        {},", c.args_rs);
        }
        let _ = writeln!(
            main,
            "    ];\n    for c in cases.iter() {{\n        let r = std::panic::catch_unwind(|| ToJ::j(&{f}({})));\n        let _ = writeln!(out, \"{{}}\", r.unwrap_or_else(|_| \"PANIC\".to_string()));\n        let _ = out.flush();\n    }}\n}}",
            call_args.join(", ")
        );
        chunks += 1;
        i = j;
    }
    main.push_str("fn main() {\n    std::panic::set_hook(Box::new(|_| {}));\n    let mut out = std::io::stdout().lock();\n");
    for k in 0..chunks {
        let _ = writeln!(main, "    chunk{k}(&mut out);");
    }
    main.push_str("}\n");
    let suffix = if release { "rel" } else { "dbg" };
    let main_path = dir.join(format!("{tag}_main_{suffix}.rs"));
    std::fs::write(&main_path, &main).unwrap();
    let bin = dir.join(format!("{tag}_{suffix}"));
    let mut cmd = Command::new("rustc");
    cmd.args(["--edition", "2024", "--cap-lints", "allow", "-o"]).arg(&bin);
    if release {
        cmd.args(["-C", "opt-level=3", "-C", "overflow-checks=off", "-C", "debug-assertions=off"]);
    } else {
        cmd.args(["-C", "overflow-checks=on", "-C", "debug-assertions=on"]);
    }
    let st = cmd.arg(&main_path).output().expect("rustc");
    if !st.status.success() {
        return Err(format!("{tag} does not compile ({suffix}):\n{}", String::from_utf8_lossy(&st.stderr).chars().take(4000).collect::<String>()));
    }
    let run = Command::new(&bin).output().expect("run");
    let mut lines: Vec<String> = String::from_utf8_lossy(&run.stdout).lines().map(|s| s.to_string()).collect();
    if !run.status.success() {
        let why = format!("ABORT({:?}: {})", run.status.code(), String::from_utf8_lossy(&run.stderr).lines().next().unwrap_or("").chars().take(160).collect::<String>());
        while lines.len() < cases.len() {
            lines.push(why.clone());
        }
    }
    Ok(lines)
}

/// Result of [`random_programs`].
#[derive(Debug, Default)]
pub struct RandomReport {
    pub generated: usize,
    pub accepted: usize,
    pub front_rejected: Vec<String>,
    pub unproven: Vec<String>,
    pub cases: usize,
    pub mismatches: Vec<String>,
    pub dir: PathBuf,
}

/// Generates `nprogs` random programs, keeps the verified ones, and runs
/// the differential comparison on their batch.
pub fn random_programs(tag: &str, seed: u64, nprogs: usize, inputs: usize, straight_share: usize) -> RandomReport {
    use rgen::*;
    let mut rep = RandomReport::default();
    let mut r = Rng::new(seed);
    let mut batch = String::new();
    let mut sigs: Vec<Sig> = vec![];
    for p in 0..nprogs {
        let nf = 1 + r.below(3) as usize;
        let mut prog = String::new();
        let mut psigs = vec![];
        {
            let straight = straight_share > 0 && p % straight_share == 0;
            let mut g = G::new(&mut r);
            g.straight = straight;
            for k in 0..nf {
                g.callees = psigs.clone();
                let (sig, src) = g.function(&format!("g{p}_f{k}"));
                prog.push_str(&src);
                psigs.push(sig);
            }
        }
        rep.generated += 1;
        // the program under verification (to pin down a hang)
        let _ = std::fs::write(Path::new(env!("CARGO_TARGET_TMPDIR")).join("redteam-fidelity").join(format!("{tag}-current.rs")), &prog);
        let c = util::check_src(&prog);
        if !c.ok() {
            let first = c.render().lines().next().unwrap_or("").to_string();
            rep.front_rejected.push(format!("{first}"));
            let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("redteam-fidelity").join(format!("{tag}-rejected"));
            let _ = std::fs::create_dir_all(&d);
            let _ = std::fs::write(d.join(format!("p{p}.rs")), format!("{prog}\n/*\n{}\n*/\n", c.render()));
            continue;
        }
        let built = driver::stage::verify_checked(&c, &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
        if !built.v.proofs_ok {
            let why = util::explain(&c, &built.v);
            rep.unproven.push(why.lines().find(|l| l.starts_with("unproven") || l.contains("error")).unwrap_or("").chars().take(200).collect());
            continue;
        }
        rep.accepted += 1;
        batch.push_str(&prog);
        sigs.extend(psigs);
    }
    let dir = scratch(tag);
    rep.dir = dir.clone();
    std::fs::write(dir.join("batch.rs"), &batch).unwrap();
    if sigs.is_empty() {
        return rep;
    }
    // the proofs of the batch
    let c = util::accepted(&batch);
    let built = driver::stage::verify_checked(&c, &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    if !built.v.proofs_ok {
        rep.mismatches.push(format!("batch not verified:\n{}", util::explain(&c, &built.v)));
        return rep;
    }
    // inputs
    let mut cases = vec![];
    for sig in &sigs {
        for _ in 0..inputs {
            let mut js = vec![];
            let mut rs = vec![];
            for (_, p) in &sig.params {
                let (j, s) = rgen::input(&mut r, *p);
                js.push(j);
                rs.push(s);
            }
            cases.push(Case {
                f: sig.name.clone(),
                args_j: format!("[{}]", js.join(",")),
                args_rs: format!("({},)", rs.join(", ")),
                tys_rs: format!("({},)", sig.params.iter().map(|(_, p)| p.driver_ty()).collect::<Vec<_>>().join(", ")),
                arity: sig.params.len(),
                native: String::new(),
            });
        }
    }
    rep.cases = cases.len();
    let kernel: Vec<Result<String, String>> = util::with_elab(&batch, ProverSet::Standard, |c, out| cases.iter().map(|cs| driver::stage::eval_in(out, c.krate.as_ref().unwrap(), &cs.f, &cs.args_j)).collect());
    let native = run_driver(&dir, "src", &batch, &cases, false);
    if let Err(msg) = &native {
        rep.mismatches.push(format!("[source-debug] {msg}"));
    }
    let get = |v: &Result<Vec<String>, String>, i: usize| v.as_ref().ok().and_then(|v| v.get(i)).map(|s| normalize(s)).unwrap_or_else(|| "<none>".into());
    for (i, cs) in cases.iter().enumerate() {
        let n = get(&native, i);
        let k = match &kernel[i] {
            Ok(k) => normalize(k),
            Err(e) => format!("ERR({e})"),
        };
        if n == "PANIC" || n.starts_with("ABORT") || k != n {
            rep.mismatches.push(format!("{}{}: source {} | kernel {}", cs.f, cs.args_j, n, k));
        }
    }
    rep
}

fn summarize(rep: &RandomReport) -> String {
    let mut s = format!("generated {} program(s), accepted {}, {} case(s), {} mismatch(es); dir {}\n", rep.generated, rep.accepted, rep.cases, rep.mismatches.len(), rep.dir.display());
    let mut fr = rep.front_rejected.clone();
    fr.sort();
    fr.dedup();
    for x in fr.iter().take(12) {
        let _ = writeln!(s, "  front: {x}");
    }
    let mut un = rep.unproven.clone();
    un.sort();
    un.dedup();
    for x in un.iter().take(12) {
        let _ = writeln!(s, "  unproven: {x}");
    }
    for m in rep.mismatches.iter().take(30) {
        let _ = writeln!(s, "  MISMATCH {m}");
    }
    s
}

#[test]
fn random_programs_differential() {
    let rounds: u64 = std::env::var("REDTEAM_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
    let mut all = vec![];
    for k in 0..rounds {
        let rep = random_programs(&format!("random{k}"), seed().wrapping_add(1000 + k), 25, 40, 0);
        eprintln!("[random{k}] {}", summarize(&rep));
        all.extend(rep.mismatches);
    }
    assert!(all.is_empty(), "{} mismatch(es):\n{}", all.len(), all.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}

// ---------------------------------------------------------------------------
// reproductions of findings
// ---------------------------------------------------------------------------

/// Verifies `body` with the standard provers: whether it verified, and why
/// not.
fn verify_program(body: &str) -> (bool, String) {
    let c = util::accepted(body);
    let built = driver::stage::verify_checked(&c, &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (built.v.proofs_ok, util::explain(&c, &built.v))
}

program!(cfg_stmts {
    pub fn attr_stmt(a: u32) -> u32 {
        let mut x = a % 100;
        #[cfg(target_arch = "x86_64")]
        {
            x += 1000;
        }
        #[cfg(sandblaster)]
        {
            x += 20000;
        }
        #[cfg(any())]
        if x > 0 {
            x += 300000;
        }
        x
    }
    pub fn attr_arm(a: u8) -> u8 {
        match a {
            #[cfg(target_arch = "x86_64")]
            0 => 100,
            _ => 7,
        }
    }
    pub fn guard(xs: &[u8], i: usize) -> u8 {
        #[cfg(sandblaster)]
        if i >= xs.len() {
            return 0;
        }
        xs[i]
    }
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct T2 {
        pub v: u8,
        #[cfg(any())]
        pub w: u8,
    }
    pub fn cmp(a: u8, b: u8) -> bool {
        let x = T2 { v: 1, #[cfg(any())] w: a };
        let y = T2 { v: 1, #[cfg(any())] w: b };
        x == y
    }
    pub fn arr(i: usize) -> (usize, u8) {
        let a = [1u8, #[cfg(any())] 2u8];
        (a.len(), if i < a.len() { a[i] } else { 0 })
    }
});

/// FINDING (high, fidelity): `#[cfg(..)]` on statements, expression
/// statements and match arms is silently ignored by the front end (only
/// item-level cfgs are evaluated, loader.rs; `let` statements reject
/// attributes, other statements and arms do not). The model keeps every
/// cfg'd-out statement/arm, while rustc compiling the source for the same
/// target drops them: on aarch64 `attr_stmt(5)` is 5 under rustc and 321005
/// in the kernel; `attr_arm(0)` is 7 vs 100. `#[cfg(sandblaster)]`
/// statements (the ghost marker for items) are elaborated as exec code:
/// `guard` is verified only thanks to a `#[cfg(sandblaster)]` bounds guard,
/// which rustc drops from the source (the erased source panics on
/// `guard(&[1, 2], 5)`). (Lifted Rust is read from rustc's MIR, where cfgs
/// are already applied.) All these forms
/// (block, `if`, `match`, `while`, `for` statements and match arms) are
/// accepted by stable rustc 1.98. The same holds for `#[cfg]` on struct
/// fields (definitions and literals), array/tuple elements, enum variants
/// and parameters: `cmp(1, 2)` is `true` under rustc (the `w` field does not
/// exist) and `false` in the model; `arr(1)` is `(1, 0)` vs `(2, 2)`.
#[test]
#[ignore = "finding: statement/arm-level #[cfg] ignored; the verified model differs from rustc's reading of the source"]
fn repro_statement_cfg_ignored() {
    let cases = vec![
        fixed!(cfg_stmts::attr_stmt(a: u32 = 5)),
        fixed!(cfg_stmts::attr_arm(a: u8 = 0)),
        fixed!(cfg_stmts::attr_arm(a: u8 = 1)),
        fixed!(cfg_stmts::guard(xs: Vec<u8> = vec![1, 2], i: usize = 1)),
        fixed!(cfg_stmts::guard(xs: Vec<u8> = vec![1, 2], i: usize = 5)),
        fixed!(cfg_stmts::cmp(a: u8 = 1, b: u8 = 2)),
        fixed!(cfg_stmts::arr(i: usize = 1)),
    ];
    let rep = run("cfg_stmts", cfg_stmts::SRC, &cases);
    eprintln!("{}", rep.mismatches.join("\n"));
    rep.assert_clean();
}

#[test]
fn random_straight_line_differential() {
    let rounds: u64 = std::env::var("REDTEAM_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
    let mut all = vec![];
    for k in 0..rounds {
        let rep = random_programs(&format!("straight{k}"), seed().wrapping_add(5000 + k), 25, 40, 1);
        eprintln!("[straight{k}] {}", summarize(&rep));
        all.extend(rep.mismatches);
    }
    assert!(all.is_empty(), "{} mismatch(es):\n{}", all.len(), all.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}

/// FINDING (medium, incompleteness): a path fact about the *entry* value of
/// a local that a later loop assigns is carried into the loop helper as a
/// `requires` (SEMANTICS.md §8: "every fact in scope at the loop head that
/// mentions only the parameters (renamed)") and must be re-proven at every
/// recursive call for the *new* value. After `if m == 7 { return 0; }` the
/// fact `m ≠ 7` becomes a loop invariant, so the trivially correct program
/// below is rejected (`unproven obligation [well-formed] in
/// crate::carried::loop#0`, goal `Eq(Bool, #eq_u32(m, 7u32), false)`).
#[test]
#[ignore = "finding: entry-only path facts over assigned locals become loop invariants (correct programs rejected)"]
fn repro_entry_fact_becomes_loop_invariant() {
    let src = r#"
pub fn carried(a: u32, xs: &[u8]) -> u32 {
    let mut m = a;
    if m == 7 {
        return 0;
    }
    for _i in 0..xs.len() {
        m = 7;
    }
    m
}
"#;
    let (verified, why) = verify_program(src);
    assert!(verified, "a correct program is rejected:\n{why}");
}

/// FINDING (low, false rejection): the operand of `as` that is a bare
/// literal is checked against the cast target even when it carries its own
/// suffix, so `245u8 as usize` and `true as u8` (both accepted by rustc)
/// are rejected with "mismatched types".
#[test]
#[ignore = "finding: suffixed/bool literal operands of `as` are rejected"]
fn repro_suffixed_literal_cast_rejected() {
    let c = util::check_src("pub fn f() -> (usize, u8) { (245u8 as usize, true as u8) }\n");
    assert!(c.ok(), "rustc accepts this; the front end says:\n{}", c.render());
}

/// FINDING (critical, unsoundness; **fixed**, DESIGN.md §3.1, review 4
/// R4-C2): the zero-sized-slice rule (DESIGN.md §3.2, review-1 "Slices of
/// zero-sized types") was enforced only for concrete element types. A
/// generic `&[T]` with `T: Copy` gets the model's `len ≤ ISIZE_MAX` fact
/// (SEMANTICS.md §2, `slice::ok_bound`) although a boundary function is
/// instantiated by host code with any `T: Copy`, including `()`, where rustc
/// allows `len == usize::MAX`. `f` below verified; the model proved
/// `s.len() + 1` cannot overflow and that `t[s.len()]` is in bounds in the
/// `else` branch, so the shipped code used a plain `+` and `get_unchecked`,
/// and safe host code calling `f::<()>(&[(); usize::MAX], ..)` read out of
/// bounds in release builds. The front end now rejects a `pub` generic
/// function reachable from the root in which a type parameter occurs inside
/// a slice element type.
#[test]
fn repro_generic_zst_slice_unsound() {
    let src = r#"
pub fn f<T: Copy>(s: &[T], t: [u8; 4]) -> u8 {
    let n = s.len() + 1;
    if n > 3 { 0 } else { t[s.len()] }
}
"#;
    let c = util::check_src(src);
    assert!(
        c.diags.list.iter().any(|d| d.kind == sandblaster_front::diag::DiagKind::Boundary && d.msg.contains("type parameter `T` inside a slice element type")),
        "the front end must reject the exported generic slice function:\n{}",
        c.render()
    );
    // the internal (non-boundary) generic helper is still fine
    let c = util::check_src("fn g<T: Copy>(s: &[T]) -> usize { s.len() }\npub fn f(s: &[u8]) -> usize { g(s) }\n");
    assert!(c.ok(), "{}", c.render());
}

/// Helper: one random round with an explicit seed (`REDTEAM_RSEED`).
#[test]
#[ignore = "tool"]
fn tool_random_round() {
    let Some(s) = std::env::var("REDTEAM_RSEED").ok().and_then(|s| s.parse::<u64>().ok()) else { return };
    let rep = random_programs(&format!("round{s}"), s, 25, 40, 0);
    eprintln!("[round{s}] {}", summarize(&rep));
}
