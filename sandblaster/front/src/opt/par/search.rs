//! SIMD search lowering (plan O10, corpus P12; optimizer design §13.5).
//!
//! **Scope** (fairness audit of 2026-10-02, J14): one skeleton, built for
//! corpus P12 — a byte slice, one comparison with a literal, `F` and `B` of
//! the index alone. It is keyed on structure, not names, but it is not yet a
//! general SIMD search: widening it (any byte predicate of comparisons and
//! masks, any index type) and its hit count on the held-out set (plan step
//! 8) come before any claim of generality.
//!
//! A **search site** is a tail-recursive byte search with an early exit:
//!
//! ```text
//! fn go(xs: &[u8], i: u64) -> R {
//!     match xs {
//!         [] => B(i),
//!         [h, t @ ..] => if P(*h) { F(i) } else { go(t, i.wrapping_add(1)) },
//!     }
//! }
//! ```
//!
//! with `P(h)` one unsigned comparison of `h` with a literal (`<`, `<=`,
//! `>`, `>=`, `==`, either orientation) and `F`, `B` expressions of `i`
//! alone. On aarch64 it gets a NEON variant `go__search_neon` that tests 16
//! bytes per step:
//!
//! ```text
//! match xs.split_first_chunk::<16>() {
//!     None => go(xs, i),
//!     Some((c, t)) => {
//!         let n = vshrn_n_u16::<4>(vreinterpretq_u16_u8(CMP(load_u8x16(c), vdupq_n_u8(C))));
//!         let m = vgetq_lane_u64::<0>(vreinterpretq_u64_u8(vcombine_u8(n, n)));
//!         let z = m.trailing_zeros();
//!         if z < 64 { F(i.wrapping_add((z >> 2) as u64)) } else { go__search_neon(t, i.wrapping_add(16)) }
//!     }
//! }
//! ```
//!
//! The compare gives `0xff` per matching byte; the narrowing shift keeps
//! one nibble per byte, so the first match is `trailing_zeros / 4`.
//!
//! **Proof.** The generic part is a small lemma library (checked by the
//! kernel when first loaded, [`library_text`]), stated over the skeleton's
//! parameters (`R`, `P`, `F`, `B`, the function and its unfolding equation):
//!
//! * `search::unroll1`, `search::unroll16`: sixteen unfoldings of the
//!   scalar search on a slice of length ≥ 16 give a chain of sixteen byte
//!   tests (`search::scalar16`) ending in the search of the rest;
//! * `search::pick16`: the NEON mask's `trailing_zeros` picks the same
//!   answer as that chain, by case analysis on the sixteen test results,
//!   each case closed by `bits::tz_range_u64_4k` and `bvrefl` on the mask;
//! * `search::mask_<kind>`: the vector compare equals the mask of the
//!   sixteen scalar tests (`bvrefl`);
//! * `search::neon_<kind>`: the variant equals the source for every input,
//!   by measure induction on the slice length (the variant's own recursion
//!   is the induction hypothesis).
//!
//! Each site's lemma `go__search_neon::search_equiv` is then one
//! application of `search::neon_<kind>` to both functions and their
//! `delta` unfoldings: the kernel's conversion checks that the source is
//! exactly the skeleton and that the emitted variant is exactly the NEON
//! form (no recognizer is trusted).

use std::rc::Rc;
use std::time::Instant;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use crate::builtins::{Builtin, IntMethod, SliceMethod};
use crate::elab::{Options as ElabOptions, Output, ProverChain};
use crate::hir::*;
use crate::span::Span;

/// The step budget of the library and of one site's lemma.
pub const SEARCH_PROOF_STEPS: u64 = 400_000_000;

/// Bytes per step of the NEON variant.
pub const CHUNK: u64 = 16;

/// The byte test of a search site, as elaborated: the primitive and
/// whether the byte is its first operand (`h OP C`) or its second (`C OP h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmp {
    pub op: CmpOp,
    pub byte_first: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
}

impl Cmp {
    /// The kind's name in the library (`lt_hc`: `h < C`).
    pub fn name(self) -> String {
        let op = match self.op {
            CmpOp::Lt => "lt",
            CmpOp::Le => "le",
            CmpOp::Gt => "gt",
            CmpOp::Ge => "ge",
            CmpOp::Eq => "eq",
        };
        format!("{op}_{}", if self.byte_first { "hc" } else { "ch" })
    }

    fn prim(self) -> &'static str {
        match self.op {
            CmpOp::Lt => "lt_u8",
            CmpOp::Le => "le_u8",
            CmpOp::Gt => "gt_u8",
            CmpOp::Ge => "ge_u8",
            CmpOp::Eq => "eq_u8",
        }
    }

    /// The test's core text at the byte `x`.
    fn pred(self, x: &str) -> String {
        if self.byte_first { format!("#{}({x}, C)", self.prim()) } else { format!("#{}(C, {x})", self.prim()) }
    }

    /// The NEON compare `(intrinsic, bytes first)`: `vcltq_u8(a, b)` is
    /// `a < b` lanewise, `vcgeq_u8(a, b)` is `a >= b`, `vceqq_u8` is `==`.
    fn vcmp(self) -> (&'static str, bool) {
        // the test as `byte REL C` with REL in {<, <=, >, >=, ==}
        let rel = match (self.op, self.byte_first) {
            (op, true) => op,
            (CmpOp::Lt, false) => CmpOp::Gt,
            (CmpOp::Le, false) => CmpOp::Ge,
            (CmpOp::Gt, false) => CmpOp::Lt,
            (CmpOp::Ge, false) => CmpOp::Le,
            (CmpOp::Eq, false) => CmpOp::Eq,
        };
        match rel {
            CmpOp::Lt => ("vcltq_u8", true),
            CmpOp::Gt => ("vcltq_u8", false),
            CmpOp::Ge => ("vcgeq_u8", true),
            CmpOp::Le => ("vcgeq_u8", false),
            CmpOp::Eq => ("vceqq_u8", true),
        }
    }
}

// ---------------------------------------------------------------------------
// The lemma library.
// ---------------------------------------------------------------------------

const OPT: &str = "Option(Tuple2(Array U8 16usize, Slice U8))";
const TUP: &str = "Tuple2(Array U8 16usize, Slice U8)";
const FR: &str = "(f : Slice U8 -> U64 -> R)";
const FT: &str = "Slice U8 -> U64 -> R";
const LE0: &str = "#le_usize(fst(xs), 0usize)";
const LT0: &str = "#lt_usize(0usize, fst(xs))";
const LE16: &str = "#le_usize(16usize, fst(xs))";

fn ik(k: u64) -> String {
    if k == 0 { "i".into() } else { format!("#wadd_u64(i, {k}u64)") }
}

fn bools_ty() -> String {
    (0..CHUNK).map(|k| format!("(b{k} : Bool)")).collect::<Vec<_>>().join(" -> ")
}

fn bools_bind() -> String {
    (0..CHUNK).map(|k| format!("(b{k} : Bool)")).collect::<Vec<_>>().join(" ")
}

fn bools_names() -> String {
    (0..CHUNK).map(|k| format!("b{k}")).collect::<Vec<_>>().join(" ")
}

/// The kind-independent part of the library.
pub fn library_generic() -> String {
    let mut o = String::new();
    o.push_str("-- The SIMD search lemma library (plan O10, P12; opt/par/search.rs). Generated; every\n-- lemma is checked by the kernel when loaded.\n\n");
    // the scalar skeleton's body, over its path condition `y`
    o.push_str(&format!(
        "-- one step of the scalar search (the elaborated body of the skeleton), over the value `y`\n-- of its emptiness test\n\
def[prelude] search::stepy : (R : Type) -> (P : U8 -> Bool) -> (F : U64 -> R) -> (B : U64 -> R) -> {FR} -> (xs : Slice U8) -> (i : U64) -> (y : Bool) -> (.e : Eq(Bool, {LE0}, y)) -> R :=
  fun (R : Type) (P : U8 -> Bool) (F : U64 -> R) (B : U64 -> R) {FR} (xs : Slice U8) (i : U64) (y : Bool) (.e : Eq(Bool, {LE0}, y)) =>
    (match y : Bool as y2 return (.e : Eq(Bool, {LE0}, y2)) -> R with
    | false => fun (.e : Eq(Bool, {LE0}, false)) =>
        let t : Slice U8 = slice::suffix U8 xs 1usize .linarith([eq::promote Bool {LE0} false .e : Eq(Bool, {LE0}, false)]; Eq(Bool, #le_usize(1usize, fst(xs)), true); []);
        let h : U8 = slice::index U8 xs 0usize .linarith([eq::promote Bool {LE0} false .e : Eq(Bool, {LE0}, false)]; Eq(Bool, #lt_usize(0usize, fst(xs)), true); []);
        (match P h : Bool as y3 return (.e1 : Eq(Bool, P h, y3)) -> R with
        | false => fun (.e1 : Eq(Bool, P h, false)) => f t (u64::wrapping_add i 1u64)
        | true => fun (.e1 : Eq(Bool, P h, true)) => F i
        end) .refl(Bool, P h)
    | true => fun (.e : Eq(Bool, {LE0}, true)) => B i
    end) .e

def[prelude] search::step : (R : Type) -> (P : U8 -> Bool) -> (F : U64 -> R) -> (B : U64 -> R) -> {FR} -> (xs : Slice U8) -> (i : U64) -> R :=
  fun (R : Type) (P : U8 -> Bool) (F : U64 -> R) (B : U64 -> R) {FR} (xs : Slice U8) (i : U64) =>
    search::stepy R P F B f xs i ({LE0}) .refl(Bool, {LE0})

"
    ));
    // one byte test of a non-empty slice
    o.push_str(&format!(
        "-- the step on a non-empty slice: one byte test\n\
def[prelude] search::one : (R : Type) -> (P : U8 -> Bool) -> (F : U64 -> R) -> {FR} -> (xs : Slice U8) -> (i : U64) -> (.h : Eq(Bool, {LT0}, true)) -> R :=
  fun (R : Type) (P : U8 -> Bool) (F : U64 -> R) {FR} (xs : Slice U8) (i : U64) (.h : Eq(Bool, {LT0}, true)) =>
    (match P (slice::index U8 xs 0usize .h) : Bool as y return (.e1 : Eq(Bool, P (slice::index U8 xs 0usize .h), y)) -> R with
    | false => fun (.e1 : Eq(Bool, P (slice::index U8 xs 0usize .h), false)) =>
        f (slice::suffix U8 xs 1usize .linarith([h : Eq(Bool, {LT0}, true)]; Eq(Bool, #le_usize(1usize, fst(xs)), true); [])) (u64::wrapping_add i 1u64)
    | true => fun (.e1 : Eq(Bool, P (slice::index U8 xs 0usize .h), true)) => F i
    end) .refl(Bool, P (slice::index U8 xs 0usize .h))

"
    ));
    let hf = "(hf : (xs : Slice U8) -> (i : U64) -> Eq(R, f xs i, search::step R P F B f xs i))";
    o.push_str(&format!(
        "-- a function whose unfolding is the step, on a non-empty slice, is one byte test\n\
def[lemma, opaque] search::unroll1 : (R : Type) -> (P : U8 -> Bool) -> (F : U64 -> R) -> (B : U64 -> R) -> {FR} -> {hf}
    -> (xs : Slice U8) -> (i : U64) -> (.h : Eq(Bool, {LT0}, true)) -> Eq(R, f xs i, search::one R P F f xs i .h) :=
  fun (R : Type) (P : U8 -> Bool) (F : U64 -> R) (B : U64 -> R) {FR} {hf} (xs : Slice U8) (i : U64) (.h : Eq(Bool, {LT0}, true)) =>
    eq::trans R (f xs i) (search::step R P F B f xs i) (search::one R P F f xs i .h) (hf xs i)
      ((match {LE0} : Bool as y return (.e : Eq(Bool, {LE0}, y)) -> Eq(R, search::stepy R P F B f xs i y .e, search::one R P F f xs i .h) with
        | false => fun (.e : Eq(Bool, {LE0}, false)) => refl(R, search::one R P F f xs i .h)
        | true => fun (.e : Eq(Bool, {LE0}, true)) =>
            absurd(Eq(R, B i, search::one R P F f xs i .h),
              linarith([h : Eq(Bool, {LT0}, true), eq::promote Bool {LE0} true .e : Eq(Bool, {LE0}, true)]; Empty; []))
        end) .refl(Bool, {LE0}))

"
    ));
    // the chain of sixteen tests
    fn smatch(k: u64) -> String {
        if k == CHUNK {
            return "K".into();
        }
        let b = format!("b{k}");
        format!(
            "(match {b} : Bool as y return (.e1 : Eq(Bool, {b}, y)) -> R with | false => fun (.e1 : Eq(Bool, {b}, false)) => {} | true => fun (.e1 : Eq(Bool, {b}, true)) => F ({}) end) .refl(Bool, {b})",
            smatch(k + 1),
            ik(k)
        )
    }
    let (bty, bbind, bnames) = (bools_ty(), bools_bind(), bools_names());
    o.push_str(&format!(
        "-- sixteen byte tests in order (`b_k`: the test of byte k), then `K`\n\
def[prelude] search::scalar16 : (R : Type) -> (F : U64 -> R) -> (K : R) -> (i : U64) -> {bty} -> R :=
  fun (R : Type) (F : U64 -> R) (K : R) (i : U64) {bbind} =>
    {}

",
        smatch(0)
    ));
    let lanes: Vec<String> = (0..CHUNK).map(|k| format!("(if b{k} return U8 then 255u8 else 0u8)")).collect();
    o.push_str(&format!(
        "-- the NEON mask of sixteen test results: a nibble per byte (vshrn #4 of the 0xff/0 lanes)\n\
def[prelude] search::mask16 : {bty} -> U64 :=
  fun {bbind} =>
    let n : Array U8 8usize = aarch64::vshrn_n_u16 4u32 .refl(Bool, true) .refl(Bool, true) (aarch64::vreinterpretq_u16_u8 (aarch64::u8x16 {}));
    aarch64::vgetq_lane_u64 0u32 .refl(Bool, true) (aarch64::vreinterpretq_u64_u8 (aarch64::vcombine_u8 n n))

",
        lanes.join(" ")
    ));
    let ltz = "#lt_u32(z, 64u32)";
    o.push_str(&format!(
        "-- the answer of the NEON step from the mask's trailing zeros `z` (`K`: no byte matched)\n\
def[prelude] search::pick : (R : Type) -> (F : U64 -> R) -> (K : R) -> (i : U64) -> (z : U32) -> R :=
  fun (R : Type) (F : U64 -> R) (K : R) (i : U64) (z : U32) =>
    (match {ltz} : Bool as y return (.e1 : Eq(Bool, {ltz}, y)) -> R with
    | false => fun (.e1 : Eq(Bool, {ltz}, false)) => K
    | true => fun (.e1 : Eq(Bool, {ltz}, true)) => F (u64::wrapping_add i #cast_u32_u64(#shr_u32(z, 2u32; refl(Bool, #lt_u32(2u32, 32u32)))))
    end) .refl(Bool, {ltz})

"
    ));
    // pick16: case analysis on the test results
    fn args(k: u64, y: &str) -> String {
        let mut v: Vec<String> = vec!["false".into(); k as usize];
        v.push(y.into());
        v.extend((k + 1..CHUNK).map(|j| format!("b{j}")));
        v.join(" ")
    }
    fn case(k: u64) -> String {
        if k == CHUNK {
            return "refl(R, K)".into();
        }
        let a = args(k, "y");
        let mot = format!("Eq(R, search::pick R F K i (u64::trailing_zeros (search::mask16 {a})), search::scalar16 R F K i {a})");
        let m = format!("(search::mask16 {})", args(k, "true"));
        let maskk: u128 = (1u128 << (4 * k + 1)) - 1;
        let powk: u128 = 1u128 << (4 * k);
        let tz = format!("(bits::tz_range_u64_{} {m} .bvrefl(U64, #and_u64({m}, {maskk}u64), {powk}u64))", 4 * k);
        let fk = format!("F ({})", ik(k));
        let leaf = format!(
            "transport(U32, {z}u32, u64::trailing_zeros {m}, eq::sym U32 (u64::trailing_zeros {m}) {z}u32 {tz}, z. Eq(R, search::pick R F K i z, {fk}), refl(R, {fk}))",
            z = 4 * k
        );
        format!("match b{k} : Bool as y return {mot} with\n    | false => {}\n    | true => {leaf}\n    end", case(k + 1))
    }
    o.push_str(&format!(
        "-- the mask's first set nibble is the first matching byte (a case per first match)\n\
def[lemma, opaque] search::pick16 : (R : Type) -> (F : U64 -> R) -> (K : R) -> (i : U64) -> {bty}
    -> Eq(R, search::pick R F K i (u64::trailing_zeros (search::mask16 {bnames})), search::scalar16 R F K i {bnames}) :=
  fun (R : Type) (F : U64 -> R) (K : R) (i : U64) {bbind} =>
    {}

",
        case(0)
    ));
    // unroll16
    let pa = "(slice::prefix_array U8 xs 16usize .h)";
    let bp: Vec<String> = (0..CHUNK).map(|k| format!("(P (array::index U8 16usize {pa} {k}usize .refl(Bool, true)))")).collect();
    let kx = "(f (slice::suffix U8 xs 16usize .h) (u64::wrapping_add i 16u64))";
    let lx = "fst(snd(xs))";
    let mut l: Vec<String> = vec!["let s0 : Slice U8 = xs;".into()];
    for k in 0..CHUNK {
        l.push(format!("let .p{k} : Eq(Bool, #lt_usize(0usize, fst(s{k})), true) = linarith([h : Eq(Bool, {LE16}, true)]; Eq(Bool, #lt_usize(0usize, fst(s{k})), true); []);"));
        l.push(format!(
            "let s{} : Slice U8 = slice::suffix U8 s{k} 1usize .linarith([p{k} : Eq(Bool, #lt_usize(0usize, fst(s{k})), true)]; Eq(Bool, #le_usize(1usize, fst(s{k})), true); []);",
            k + 1
        ));
    }
    l.push("let sx : Slice U8 = slice::suffix U8 xs 16usize .h;".into());
    l.push(format!("let q1 : Eq(List(U8), fst(snd(s1)), seq::drop U8 {lx} 1int) = refl(List(U8), fst(snd(s1)));"));
    for k in 1..CHUNK {
        l.push(format!(
            "let q{n} : Eq(List(U8), fst(snd(s{n})), seq::drop U8 {lx} {n}int) = eq::trans (List(U8)) fst(snd(s{n})) (seq::drop U8 (seq::drop U8 {lx} {k}int) 1int) (seq::drop U8 {lx} {n}int) \
(eq::cong (List(U8)) (List(U8)) (fun (l : List(U8)) => seq::drop U8 l 1int) fst(snd(s{k})) (seq::drop U8 {lx} {k}int) q{k}) \
(seq::drop_drop U8 {lx} {k}int 1int .refl(Bool, true) .refl(Bool, true));",
            n = k + 1
        ));
    }
    l.push("let es : Eq(Slice U8, s16, sx) = slice::ext U8 s16 sx .q16;".into());
    l.push("let t16 : R = f sx (u64::wrapping_add i 16u64);".into());
    l.push(format!("let E16 : Eq(R, f s16 ({i16}), t16) = eq::cong (Slice U8) R (fun (s : Slice U8) => f s ({i16})) s16 sx es;", i16 = ik(16)));
    let ctx = |k: u64, r: &str| {
        let sc = format!("P (slice::index U8 s{k} 0usize .p{k})");
        format!(
            "(match {sc} : Bool as y return (.e1 : Eq(Bool, {sc}, y)) -> R with | false => fun (.e1 : Eq(Bool, {sc}, false)) => {r} | true => fun (.e1 : Eq(Bool, {sc}, true)) => F ({}) end) .refl(Bool, {sc})",
            ik(k)
        )
    };
    for k in (0..CHUNK).rev() {
        l.push(format!("let t{k} : R = {};", ctx(k, &format!("t{}", k + 1))));
        l.push(format!(
            "let E{k} : Eq(R, f s{k} ({ikk}), t{k}) = eq::trans R (f s{k} ({ikk})) (search::one R P F f s{k} ({ikk}) .p{k}) t{k} (search::unroll1 R P F B f hf s{k} ({ikk}) .p{k}) \
(eq::cong R R (fun (r : R) => {c}) (f s{n} ({ikn})) t{n} E{n});",
            ikk = ik(k),
            ikn = ik(k + 1),
            n = k + 1,
            c = ctx(k, "r")
        ));
    }
    l.push("E0".into());
    o.push_str(&format!(
        "-- sixteen unfoldings of the search on a slice of length >= 16: the sixteen byte tests, then\n-- the search of the rest\n\
def[lemma, opaque] search::unroll16 : (R : Type) -> (P : U8 -> Bool) -> (F : U64 -> R) -> (B : U64 -> R) -> {FR} -> {hf}
    -> (xs : Slice U8) -> (i : U64) -> (.h : Eq(Bool, {LE16}, true)) -> Eq(R, f xs i, search::scalar16 R F {kx} i {}) :=
  fun (R : Type) (P : U8 -> Bool) (F : U64 -> R) (B : U64 -> R) {FR} {hf} (xs : Slice U8) (i : U64) (.h : Eq(Bool, {LE16}, true)) =>
    {}

",
        bp.join(" "),
        l.join("\n    ")
    ));
    o
}

/// The part of the library for one byte test.
pub fn library_kind(k: Cmp) -> String {
    let kind = k.name();
    let (vc, bytes_first) = k.vcmp();
    let (a, b) = if bytes_first { ("(aarch64::vld1q_u8 c)", "(aarch64::vdupq_n_u8 C)") } else { ("(aarch64::vdupq_n_u8 C)", "(aarch64::vld1q_u8 c)") };
    let mut o = String::new();
    o.push_str(&format!(
        "-- the NEON mask of the test `{}` on the bytes of `c`\n\
def[prelude] search::vmask_{kind} : (C : U8) -> (c : Array U8 16usize) -> U64 :=
  fun (C : U8) (c : Array U8 16usize) =>
    let n : Array U8 8usize = aarch64::vshrn_n_u16 4u32 .refl(Bool, true) .refl(Bool, true) (aarch64::vreinterpretq_u16_u8 (aarch64::{vc} {a} {b}));
    aarch64::vgetq_lane_u64 0u32 .refl(Bool, true) (aarch64::vreinterpretq_u64_u8 (aarch64::vcombine_u8 n n))

",
        k.pred("h")
    ));
    let bc: Vec<String> = (0..CHUNK).map(|j| format!("({})", k.pred(&format!("array::index U8 16usize c {j}usize .refl(Bool, true)")))).collect();
    o.push_str(&format!(
        "def[lemma, opaque] search::mask_{kind} : (C : U8) -> (c : Array U8 16usize) -> Eq(U64, search::vmask_{kind} C c, search::mask16 {bc}) :=
  fun (C : U8) (c : Array U8 16usize) => bvrefl(U64, search::vmask_{kind} C c, search::mask16 {bc})

",
        bc = bc.join(" ")
    ));
    o.push_str(&format!(
        "-- one step of the NEON search (the elaborated body of the variant), over the result `o` of\n-- the chunk split\n\
def[prelude] search::nbody_{kind} : (R : Type) -> (C : U8) -> (F : U64 -> R) -> {FR} -> (g : {FT}) -> (xs : Slice U8) -> (i : U64) -> (s : {OPT}) -> (o : {OPT}) -> (.e : Eq({OPT}, s, o)) -> R :=
  fun (R : Type) (C : U8) (F : U64 -> R) {FR} (g : {FT}) (xs : Slice U8) (i : U64) (s : {OPT}) (o : {OPT}) (.e : Eq({OPT}, s, o)) =>
    (match o : {OPT} as y return (.e : Eq({OPT}, s, y)) -> R with
    | None => fun (.e : Eq({OPT}, s, None[{TUP}])) => f xs i
    | Some(value) => fun (.e : Eq({OPT}, s, Some[{TUP}](value))) =>
        let c : Array U8 16usize = match value : {TUP} as y return Array U8 16usize with | tuple2(x, x1) => x end;
        let t : Slice U8 = match value : {TUP} as y return Slice U8 with | tuple2(x, x1) => x1 end;
        search::pick R F (g t (u64::wrapping_add i 16u64)) i (u64::trailing_zeros (search::vmask_{kind} C c))
    end) .e

"
    ));
    let sfc = "slice::split_first_chunk U8 xs 16usize";
    o.push_str(&format!(
        "def[prelude] search::nstep_{kind} : (R : Type) -> (C : U8) -> (F : U64 -> R) -> {FR} -> (g : {FT}) -> (xs : Slice U8) -> (i : U64) -> R :=
  fun (R : Type) (C : U8) (F : U64 -> R) {FR} (g : {FT}) (xs : Slice U8) (i : U64) =>
    search::nbody_{kind} R C F f g xs i ({sfc}) ({sfc}) .refl({OPT}, {sfc})

"
    ));
    let pk = format!("(fun (h : U8) => {})", k.pred("h"));
    let hfk = format!("(hf : (xs : Slice U8) -> (i : U64) -> Eq(R, f xs i, search::step R {pk} F B f xs i))");
    let hg = format!("(hg : (xs : Slice U8) -> (i : U64) -> Eq(R, g xs i, search::nstep_{kind} R C F f g xs i))");
    let sy = format!(
        "((match y : Bool as y2 return (.h : Eq(Bool, {LE16}, y2)) -> {OPT} with | false => fun (.h : Eq(Bool, {LE16}, false)) => None[{TUP}] \
| true => fun (.h : Eq(Bool, {LE16}, true)) => Some[{TUP}](tuple2[Array U8 16usize, Slice U8](slice::prefix_array U8 xs 16usize .h, slice::suffix U8 xs 16usize .h)) end) .e)"
    );
    let bs: Vec<String> = (0..CHUNK).map(|j| format!("({})", k.pred(&format!("array::index U8 16usize pa {j}usize .refl(Bool, true)")))).collect();
    let bs = bs.join(" ");
    let i16 = "(u64::wrapping_add i 16u64)";
    let av = format!("search::pick R F K i (u64::trailing_zeros (search::vmask_{kind} C pa))");
    let bm = format!("search::pick R F K i (u64::trailing_zeros (search::mask16 {bs}))");
    let sg = format!("search::scalar16 R F K i {bs}");
    let sf = format!("search::scalar16 R F Kf i {bs}");
    let dec = format!(
        "pair(Sigma (_ : Eq(Bool, #le_int(0int, #cast_usize_int(fst(sx))), true)), Eq(Bool, #lt_int(#cast_usize_int(fst(sx)), #cast_usize_int(fst(xs))), true), \
linarith([]; Eq(Bool, #le_int(0int, #cast_usize_int(fst(sx))), true); []), \
linarith([e : Eq(Bool, {LE16}, true)]; Eq(Bool, #lt_int(#cast_usize_int(fst(sx)), #cast_usize_int(fst(xs))), true); []))"
    );
    o.push_str(&format!(
        "-- the NEON search equals the scalar search (measure induction on the slice length)\n\
def[lemma, opaque] search::neon_{kind} : (R : Type) -> (C : U8) -> (F : U64 -> R) -> (B : U64 -> R) -> {FR} -> {hfk} -> (g : {FT}) -> {hg}
    -> (xs : Slice U8) -> (i : U64) -> Eq(R, g xs i, f xs i) :=
  fun (R : Type) (C : U8) (F : U64 -> R) (B : U64 -> R) {FR} {hfk} (g : {FT}) {hg} (xs : Slice U8) (i : U64) =>
    eq::trans R (g xs i) (search::nstep_{kind} R C F f g xs i) (f xs i) (hg xs i)
      ((match {LE16} : Bool as y return (.e : Eq(Bool, {LE16}, y)) -> Eq(R, search::nbody_{kind} R C F f g xs i {sy} {sy} .refl({OPT}, {sy}), f xs i) with
        | false => fun (.e : Eq(Bool, {LE16}, false)) => refl(R, f xs i)
        | true => fun (.e : Eq(Bool, {LE16}, true)) =>
            let pa : Array U8 16usize = slice::prefix_array U8 xs 16usize .e;
            let sx : Slice U8 = slice::suffix U8 xs 16usize .e;
            let K : R = g sx {i16};
            let Kf : R = f sx {i16};
            let e1 : Eq(R, {av}, {bm}) = eq::cong U64 R (fun (m : U64) => search::pick R F K i (u64::trailing_zeros m)) (search::vmask_{kind} C pa) (search::mask16 {bs}) (search::mask_{kind} C pa);
            let e2 : Eq(R, {bm}, {sg}) = search::pick16 R F K i {bs};
            let ih : Eq(R, K, Kf) = rec(R, C, F, B, f, hf, g, hg, sx, {i16}; {dec});
            let e3 : Eq(R, {sg}, {sf}) = eq::cong R R (fun (k : R) => search::scalar16 R F k i {bs}) K Kf ih;
            let e4 : Eq(R, f xs i, {sf}) = search::unroll16 R {pk} F B f hf xs i .e;
            eq::trans R ({av}) ({bm}) (f xs i) e1 (eq::trans R ({bm}) ({sg}) (f xs i) e2 (eq::trans R ({sg}) ({sf}) (f xs i) e3 (eq::sym R (f xs i) ({sf}) e4)))
        end) .refl(Bool, {LE16}))
  measure(#cast_usize_int(fst(xs)))
"
    ));
    o
}

/// The whole library for `kinds` (for the regeneration test and reports).
pub fn library_text(kinds: &[Cmp]) -> String {
    let mut o = library_generic();
    for k in kinds {
        o.push('\n');
        o.push_str(&library_kind(*k));
    }
    o
}

/// Loads the library parts `kind` needs (once per environment). Returns
/// the kernel steps spent.
pub fn ensure_library(env: &mut Env, kind: Cmp) -> Result<u64, String> {
    let mut spent = 0u64;
    if env.lookup_global("search::unroll16").is_none() {
        crate::opt::seqsum::ensure_lemmas(env)?;
        let mut b = Budget { steps: SEARCH_PROOF_STEPS };
        for k in (0..64).step_by(4) {
            crate::auto::bitlib::ensure(env, crate::auto::bitlib::Family::TzRange, Width::U64, k, &mut b).map_err(|e| format!("bits::tz_range_u64_{k}: {e}"))?;
        }
        env.load_core(&library_generic(), &mut b).map_err(|e| format!("the search library was rejected: {}", e.to_string().chars().take(900).collect::<String>()))?;
        spent += SEARCH_PROOF_STEPS - b.steps;
    }
    if env.lookup_global(&format!("search::neon_{}", kind.name())).is_none() {
        let mut b = Budget { steps: SEARCH_PROOF_STEPS };
        env.load_core(&library_kind(kind), &mut b).map_err(|e| format!("the search library ({}) was rejected: {}", kind.name(), e.to_string().chars().take(900).collect::<String>()))?;
        spent += SEARCH_PROOF_STEPS - b.steps;
    }
    Ok(spent)
}

// ---------------------------------------------------------------------------
// Sites.
// ---------------------------------------------------------------------------

/// A search site found in the HIR.
#[derive(Clone, Debug)]
pub struct Site {
    pub item: ItemId,
    /// The local of the index parameter.
    pub index: LocalId,
    /// `F`: the found branch (an expression of the index alone).
    pub found: Expr,
}

fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Block(b) if b.stmts.is_empty() => b.tail.as_deref().map(peel).unwrap_or(e),
        _ => e,
    }
}

fn param_local(p: &Param) -> Option<LocalId> {
    match &p.pat.kind {
        PatKind::Binding { local, sub: None, .. } => Some(*local),
        _ => None,
    }
}

/// Whether `e` is written only with the forms [`subst`] rewrites, and
/// mentions no local but `index`.
fn simple_of(e: &Expr, index: LocalId) -> bool {
    match &e.kind {
        ExprKind::Lit(_) | ExprKind::BuiltinConst(_) | ExprKind::Const(_) => true,
        ExprKind::Local(l) => *l == index,
        ExprKind::Adt { fields, base: None, .. } => fields.iter().all(|(_, x)| simple_of(x, index)),
        ExprKind::Tuple(xs) => xs.iter().all(|x| simple_of(x, index)),
        ExprKind::Call { callee: Callee::Builtin(..) | Callee::Item(..), args } => args.iter().all(|x| simple_of(x, index)),
        ExprKind::Binary(_, a, b) => simple_of(a, index) && simple_of(b, index),
        ExprKind::Unary(_, a) | ExprKind::Cast(a, _) | ExprKind::Coerce(_, a) => simple_of(a, index),
        ExprKind::Block(b) if b.stmts.is_empty() => b.tail.as_deref().is_some_and(|t| simple_of(t, index)),
        _ => false,
    }
}

/// `e` with the local `index` replaced by `by` (on [`simple_of`] forms).
fn subst(e: &Expr, index: LocalId, by: &Expr) -> Expr {
    let mut out = e.clone();
    out.kind = match &e.kind {
        ExprKind::Local(l) if *l == index => return by.clone(),
        ExprKind::Adt { ctor, ty_args, fields, base } => ExprKind::Adt { ctor: ctor.clone(), ty_args: ty_args.clone(), fields: fields.iter().map(|(i, x)| (*i, subst(x, index, by))).collect(), base: base.clone() },
        ExprKind::Tuple(xs) => ExprKind::Tuple(xs.iter().map(|x| subst(x, index, by)).collect()),
        ExprKind::Call { callee, args } => ExprKind::Call { callee: callee.clone(), args: args.iter().map(|x| subst(x, index, by)).collect() },
        ExprKind::Binary(op, a, b) => ExprKind::Binary(*op, Box::new(subst(a, index, by)), Box::new(subst(b, index, by))),
        ExprKind::Unary(op, a) => ExprKind::Unary(*op, Box::new(subst(a, index, by))),
        ExprKind::Cast(a, t) => ExprKind::Cast(Box::new(subst(a, index, by)), t.clone()),
        ExprKind::Coerce(c, a) => ExprKind::Coerce(*c, Box::new(subst(a, index, by))),
        ExprKind::Block(b) => ExprKind::Block(Block { stmts: vec![], tail: b.tail.as_ref().map(|t| Box::new(subst(t, index, by))), span: b.span }),
        k => k.clone(),
    };
    out
}

/// The search sites of `krate` (syntactic: source exec functions shaped
/// like the skeleton; the kernel decides later whether they are).
pub fn candidates(krate: &Crate) -> Vec<Site> {
    let mut out = Vec::new();
    for it in &krate.items {
        if it.ghost {
            continue;
        }
        let ItemKind::Fn(f) = &it.kind else { continue };
        if f.kind != FnKind::Exec || f.implements.is_some() || !f.generics.is_empty() || f.has_requires() || !f.target_features.is_empty() || f.receiver.is_some() || f.params.len() != 2 {
            continue;
        }
        if f.params[0].ty != Ty::slice_ref(Ty::u8()) || f.params[1].ty != Ty::Uint(UintTy::U64) || f.params.iter().any(|p| p.ghost) {
            continue;
        }
        let (Some(xs), Some(ix)) = (param_local(&f.params[0]), param_local(&f.params[1])) else { continue };
        let FnBody::Exec(b) = &f.body else { continue };
        let ExprKind::Match { scrut, arms, .. } = &peel(b).kind else { continue };
        if !matches!(&scrut.kind, ExprKind::Local(l) if *l == xs) || arms.len() != 2 || arms.iter().any(|a| a.guard.is_some()) {
            continue;
        }
        // arm 2: `[h, t @ ..] => if COND { F } else { go(t, i.wrapping_add(1)) }`
        let slice_pat = |p: &Pat| -> Option<(usize, Option<LocalId>)> {
            let p = match &p.kind {
                PatKind::Deref { pat, .. } => pat,
                _ => p,
            };
            match &p.kind {
                PatKind::Slice { prefix, rest, suffix } if suffix.is_empty() => {
                    let tail = match rest {
                        None => None,
                        Some(Some(t)) => match &t.kind {
                            PatKind::Binding { local, sub: None, .. } => Some(*local),
                            _ => return None,
                        },
                        Some(None) => return None,
                    };
                    Some((prefix.len(), tail))
                }
                _ => None,
            }
        };
        let (Some((0, None)), Some((1, Some(t)))) = (slice_pat(&arms[0].pat), slice_pat(&arms[1].pat)) else { continue };
        let ExprKind::If { then, els: Some(els), .. } = &peel(&arms[1].body).kind else { continue };
        let rec_ok = match &peel(els).kind {
            ExprKind::Call { callee: Callee::Item(g, targs), args } if *g == it.id && targs.is_empty() && args.len() == 2 => {
                matches!(&args[0].kind, ExprKind::Local(l) if *l == t)
                    && matches!(&args[1].kind, ExprKind::Call { callee: Callee::Builtin(Builtin::Int(IntMethod::WrappingAdd, UintTy::U64), _), args: a }
                        if a.len() == 2 && matches!(&a[0].kind, ExprKind::Local(l) if *l == ix) && matches!(&a[1].kind, ExprKind::Lit(Lit::Int(1))))
            }
            _ => false,
        };
        if !rec_ok || !simple_of(then, ix) {
            continue;
        }
        out.push(Site { item: it.id, index: ix, found: (**then).clone() });
    }
    out
}

// ---------------------------------------------------------------------------
// The elaborated skeleton.
// ---------------------------------------------------------------------------

/// What the kernel term of a site gives the lemma: the test, its literal,
/// `F` and `B` as `λ(j : U64). …` terms and the result type.
struct Skeleton {
    cmp: Cmp,
    c: u8,
    found: Tm,
    base: Tm,
    ret: Tm,
}

/// `let … ; let j = v; j` ↦ `v` (tracking the binder depth).
fn peel_lets(mut t: Tm, mut d: u32) -> (Tm, u32) {
    loop {
        let next = match &*t {
            Term::Let { val, body, .. } => {
                if matches!(&**body, Term::Var(sandblaster_kernel::term::Idx(0))) {
                    (val.clone(), d)
                } else {
                    (body.clone(), d + 1)
                }
            }
            _ => return (t, d),
        };
        t = next.0;
        d = next.1;
    }
}

/// The match of `(match … with …) proof` or of a bare match.
fn head_match(t: &Tm) -> Option<(&Tm, &[sandblaster_kernel::term::Arm])> {
    let m = match &**t {
        Term::App { fun, .. } => fun,
        _ => t,
    };
    match &**m {
        Term::Match { scrut, arms, .. } => Some((scrut, arms.as_slice())),
        _ => None,
    }
}

fn lam_body(t: &Tm) -> Option<&Tm> {
    match &**t {
        Term::Lam { body, .. } => Some(body),
        _ => None,
    }
}

/// `λ(j : U64). t` for a term `t` at depth `d` whose only free variable
/// is the index parameter (level 1).
fn of_index(t: &Tm, d: u32) -> Option<Tm> {
    if d < 2 {
        return None;
    }
    let ix = d - 2;
    if (0..d).any(|k| k != ix && sandblaster_kernel::util::occurs(t, k)) {
        return None;
    }
    Some(mk::lam("j", Rel::Rel, mk::int_ty(Width::U64), sandblaster_kernel::util::shift(t, -(ix as i64))))
}

fn lit_u8(t: &Tm) -> Option<u8> {
    match &**t {
        Term::Lit { w: Width::U8, n } => u8::try_from(n).ok(),
        _ => None,
    }
}

fn skeleton(env: &Env, g: GlobalId) -> Result<Skeleton, String> {
    let tele = crate::opt::symex::telescope(env, g).ok_or("no telescope")?;
    if tele.binders.len() != 2 || sandblaster_kernel::util::occurs(&tele.ret, 0) || sandblaster_kernel::util::occurs(&tele.ret, 1) {
        return Err("not a function of a slice and an index with a fixed result type".into());
    }
    let body = env.global_body(g).ok_or("no body")?;
    let mut t = body;
    for _ in 0..2 {
        t = lam_body(&t).ok_or("the body has fewer than two binders")?.clone();
    }
    let (t, d) = peel_lets(t, 2);
    let (scrut, arms) = head_match(&t).ok_or("the body is not a match on the slice length")?;
    let empty_test = matches!(&**scrut, Term::Prim { op: PrimOp::Le(Width::Usize), args, .. } if args.len() == 2 && matches!(&*args[1], Term::Lit { n, .. } if n == &0.into()));
    if !empty_test || arms.len() != 2 {
        return Err("the body is not a match on the slice length".into());
    }
    // `true`: B (under the idiom's equation binder)
    let base = lam_body(&arms[1].body).ok_or("the empty case is not an idiom arm")?;
    let base = of_index(base, d + 1).ok_or("the empty case depends on more than the index")?;
    let inner = lam_body(&arms[0].body).ok_or("the non-empty case is not an idiom arm")?;
    let (inner, d2) = peel_lets(inner.clone(), d + 1);
    let (scrut2, arms2) = head_match(&inner).ok_or("the non-empty case is not a byte test")?;
    let (op, args) = match &**scrut2 {
        Term::Prim { op, args, .. } if args.len() == 2 => (*op, args),
        _ => return Err("the byte test is not a comparison".into()),
    };
    let cop = match op {
        PrimOp::Lt(Width::U8) => CmpOp::Lt,
        PrimOp::Le(Width::U8) => CmpOp::Le,
        PrimOp::Gt(Width::U8) => CmpOp::Gt,
        PrimOp::Ge(Width::U8) => CmpOp::Ge,
        PrimOp::Eq(Width::U8) => CmpOp::Eq,
        _ => return Err("the byte test is not an unsigned byte comparison".into()),
    };
    let (byte_first, c) = match (lit_u8(&args[0]), lit_u8(&args[1])) {
        (None, Some(c)) => (true, c),
        (Some(c), None) => (false, c),
        _ => return Err("the byte test does not compare with a literal".into()),
    };
    if arms2.len() != 2 {
        return Err("the byte test is not a boolean match".into());
    }
    let found = lam_body(&arms2[1].body).ok_or("the found case is not an idiom arm")?;
    let found = of_index(found, d2 + 1).ok_or("the found case depends on more than the index")?;
    Ok(Skeleton { cmp: Cmp { op: cop, byte_first }, c, found, base, ret: tele.ret })
}

// ---------------------------------------------------------------------------
// The variant.
// ---------------------------------------------------------------------------

fn ex(kind: ExprKind, ty: Ty, sp: Span) -> Expr {
    Expr::new(kind, ty, sp)
}

fn intrinsic(arch: &crate::target::Arch, name: &str) -> Result<&'static crate::intrinsics::IntrinsicInfo, String> {
    crate::intrinsics::lookup(arch, name).ok_or_else(|| format!("no intrinsic `{name}`"))
}

/// The HIR of the NEON variant of `site` (see the module docs).
fn variant_def(krate: &Crate, site: &Site, cmp: Cmp, c: u8, self_id: ItemId) -> Result<FnDef, String> {
    let orig = krate.item(site.item);
    let sp = orig.span;
    let arch = krate.target.arch.clone();
    let mut f = krate.fn_def(site.item).ok_or("not a function")?.clone();
    let xs = param_local(&f.params[0]).ok_or("the slice parameter is not a binding")?;
    let ix = site.index;
    let u8t = Ty::u8();
    let u64t = Ty::Uint(UintTy::U64);
    let u32t = Ty::u32();
    let slice = Ty::slice_ref(u8t.clone());
    let chunk = Ty::Ref(Box::new(Ty::Array(Box::new(u8t.clone()), CHUNK)));
    let pair = Ty::Tuple(vec![chunk.clone(), slice.clone()]);
    let opt = Ty::Option(Box::new(pair.clone()));
    let ret = f.ret.clone();
    let v16 = Ty::Vector(crate::intrinsics::VecTy::Uint8x16);
    let v8 = Ty::Vector(crate::intrinsics::VecTy::Uint8x8);
    let local = |name: &str, ty: &Ty, f: &mut FnDef| {
        let l = LocalId(f.locals.len() as u32);
        f.locals.push(LocalDecl { name: name.into(), ty: ty.clone(), mutable: false, ghost: false, span: sp });
        l
    };
    let lc = local("c", &chunk, &mut f);
    let lt = local("t", &slice, &mut f);
    let ln = local("n", &v8, &mut f);
    let lm = local("m", &u64t, &mut f);
    let lz = local("z", &u32t, &mut f);
    let var = |l: LocalId, ty: &Ty| ex(ExprKind::Local(l), ty.clone(), sp);
    let lit = |n: u128, ty: &Ty| ex(ExprKind::Lit(Lit::Int(n)), ty.clone(), sp);
    let call_i = |name: &str, imms: Vec<i64>, args: Vec<Expr>| -> Result<Expr, String> {
        let info = intrinsic(&arch, name)?;
        Ok(ex(ExprKind::Call { callee: Callee::Intrinsic(info.id, imms), args }, info.ret.clone(), sp))
    };
    let bind = |l: LocalId, ty: &Ty| Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span: sp };
    let let_ = |l: LocalId, ty: &Ty, init: Expr| Stmt { kind: StmtKind::Let { pat: bind(l, ty), init, els: None }, span: sp };
    let block = |stmts: Vec<Stmt>, tail: Expr| {
        let ty = tail.ty.clone();
        ex(ExprKind::Block(Block { stmts, tail: Some(Box::new(tail)), span: sp }), ty, sp)
    };
    // the chunk test
    let load = crate::intrinsics::lookup_helper(&arch, "load_u8x16").ok_or("no load_u8x16 helper")?;
    let v = ex(ExprKind::Call { callee: Callee::Helper(load), args: vec![var(lc, &chunk)] }, v16.clone(), sp);
    let d = call_i("vdupq_n_u8", vec![], vec![lit(c as u128, &u8t)])?;
    let (vc, bytes_first) = cmp.vcmp();
    let cmpv = if bytes_first { call_i(vc, vec![], vec![v, d])? } else { call_i(vc, vec![], vec![d, v])? };
    let n = call_i("vshrn_n_u16", vec![4], vec![call_i("vreinterpretq_u16_u8", vec![], vec![cmpv])?])?;
    let m = call_i("vgetq_lane_u64", vec![0], vec![call_i("vreinterpretq_u64_u8", vec![], vec![call_i("vcombine_u8", vec![], vec![var(ln, &v8), var(ln, &v8)])?])?])?;
    let z = ex(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(IntMethod::TrailingZeros, UintTy::U64), vec![]), args: vec![var(lm, &u64t)] }, u32t.clone(), sp);
    let hit = ex(ExprKind::Binary(BinOp::Lt, Box::new(var(lz, &u32t)), Box::new(lit(64, &u32t))), Ty::Bool, sp);
    let shifted = ex(ExprKind::Cast(Box::new(ex(ExprKind::Binary(BinOp::Shr, Box::new(var(lz, &u32t)), Box::new(lit(2, &u32t))), u32t.clone(), sp)), u64t.clone()), u64t.clone(), sp);
    let wadd = |a: Expr, b: Expr| ex(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(IntMethod::WrappingAdd, UintTy::U64), vec![]), args: vec![a, b] }, u64t.clone(), sp);
    let found = subst(&site.found, ix, &wadd(var(ix, &u64t), shifted));
    let again = ex(ExprKind::Call { callee: Callee::Item(self_id, vec![]), args: vec![var(lt, &slice), wadd(var(ix, &u64t), lit(CHUNK as u128, &u64t))] }, ret.clone(), sp);
    let tail = ex(ExprKind::If { cond: Box::new(hit), then: Box::new(block(vec![], found)), els: Some(Box::new(block(vec![], again))) }, ret.clone(), sp);
    let some_body = block(vec![let_(ln, &v8, n), let_(lm, &u64t, m), let_(lz, &u32t, z)], tail);
    let short = ex(ExprKind::Call { callee: Callee::Item(site.item, vec![]), args: vec![var(xs, &slice), var(ix, &u64t)] }, ret.clone(), sp);
    let split = ex(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(SliceMethod::SplitFirstChunk(CHUNK)), vec![u8t.clone()]), args: vec![var(xs, &slice)] }, opt.clone(), sp);
    let none_pat = Pat { kind: PatKind::Ctor { ctor: Ctor::None, ty_args: vec![pair.clone()], fields: vec![] }, ty: opt.clone(), span: sp };
    let some_pat = Pat {
        kind: PatKind::Ctor { ctor: Ctor::Some, ty_args: vec![pair.clone()], fields: vec![(0, Pat { kind: PatKind::Tuple(vec![bind(lc, &chunk), bind(lt, &slice)]), ty: pair.clone(), span: sp })] },
        ty: opt.clone(),
        span: sp,
    };
    let body = ex(
        ExprKind::Match { scrut: Box::new(split), arms: vec![Arm { pat: none_pat, guard: None, body: short, span: sp }, Arm { pat: some_pat, guard: None, body: some_body, span: sp }], source: MatchSource::Match },
        ret.clone(),
        sp,
    );
    f.body = FnBody::Exec(block(vec![], body));
    let len = ex(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(SliceMethod::Len), vec![u8t.clone()]), args: vec![var(xs, &slice)] }, Ty::usize(), sp);
    f.decreases = Some(Decreases { measure: len, max: None });
    f.recursion = crate::hir::Recursion::Tail;
    let features = vec!["neon".to_string()];
    f.feature_set = crate::target::feature_closure(&arch, &features);
    f.target_features = features;
    f.implements = None;
    f.specialize = false;
    f.ensures = None;
    f.inline = None;
    Ok(f)
}

/// A lowered search site.
#[derive(Clone, Debug)]
pub struct Lowered {
    pub item: ItemId,
    pub global: GlobalId,
    pub lemma: GlobalId,
    pub kind: Cmp,
    pub literal: u8,
    /// Kernel steps of the library (the first site of a crate only).
    pub library_steps: u64,
    /// Kernel steps of this site's `search_equiv` (the library instance).
    pub instance_steps: u64,
    pub millis: u128,
}

/// Lowers `site` (aarch64): builds the variant, elaborates it and proves
/// `<variant>::search_equiv : Π xs i. Eq(R, variant xs i, go xs i)`.
pub fn lower(out: &mut Output, ext: &mut Crate, chain: &mut ProverChain, eopts: &ElabOptions, site: &Site) -> Result<Lowered, String> {
    let t0 = Instant::now();
    let g = *out.fn_globals.get(&site.item).ok_or("the site is not elaborated")?;
    let sk = skeleton(&out.env, g)?;
    let library_steps = ensure_library(&mut out.env, sk.cmp)?;
    let orig = ext.item(site.item).clone();
    let rid = ItemId(ext.items.len() as u32);
    let f = variant_def(ext, site, sk.cmp, sk.c, rid)?;
    let name = format!("{}__search_neon", orig.name);
    let mut path = orig.path.clone();
    if let Some(l) = path.0.last_mut() {
        *l = name.clone();
    }
    let docs = vec![format!(" NEON search of `{}` (16 bytes per step; plan O10): equal to it by `{name}::search_equiv`.", orig.path)];
    ext.items.push(Item { id: rid, name: name.clone(), path, module: orig.module, vis: Vis::Crate, ghost: false, span: orig.span, docs, allow: orig.allow.clone(), cfg: Some("all(target_arch = \"aarch64\", target_endian = \"little\")".into()), kind: ItemKind::Fn(f) });
    ext.modules[orig.module.0 as usize].items.push(rid);
    let diags_before = out.diags.list.len();
    let failed = crate::elab::generated::resume(out, ext, &[rid], chain, eopts, None);
    let pop = |out: &mut Output, ext: &mut Crate| {
        out.diags.list.truncate(diags_before);
        ext.modules[orig.module.0 as usize].items.retain(|i| *i != rid);
        if ext.items.len() == rid.0 as usize + 1 {
            ext.items.pop();
        }
    };
    match failed {
        Ok(f) if f.is_empty() => {}
        Ok(_) => {
            let why = out.diags.list.get(diags_before..).and_then(|d| d.first()).map(|d| d.msg.clone()).unwrap_or_default();
            pop(out, ext);
            return Err(format!("the search variant did not elaborate: {why}"));
        }
        Err(e) => {
            pop(out, ext);
            return Err(format!("the search variant did not elaborate: {e}"));
        }
    }
    let vg = *out.fn_globals.get(&rid).ok_or("the search variant has no global")?;
    let gname = out.env.global_name(vg).map(|n| n.to_string()).unwrap_or(name);
    let (lemma, instance_steps) = match prove_link_counted(&mut out.env, g, vg, &format!("{gname}::search_equiv")) {
        Ok(l) => l,
        Err(e) => {
            ext.items[rid.0 as usize].ghost = true;
            return Err(e);
        }
    };
    Ok(Lowered { item: rid, global: vg, lemma, kind: sk.cmp, literal: sk.c, library_steps, instance_steps, millis: t0.elapsed().as_millis() })
}

/// Proves `name : Π xs i. Eq(R, variant xs i, source xs i)` as the
/// instance `search::neon_<test> R C F B source (λxs i. δ source) variant
/// (λxs i. δ variant) xs i` of the search library: the kernel checks that
/// `source` unfolds to the scalar skeleton and `variant` to the NEON step.
pub fn prove_link(env: &mut Env, source: GlobalId, variant: GlobalId, name: &str) -> Result<GlobalId, String> {
    prove_link_counted(env, source, variant, name).map(|(g, _)| g)
}

/// [`prove_link`], also returning the kernel steps of the instance (the
/// library's own steps are not counted: [`Lowered::library_steps`]).
pub fn prove_link_counted(env: &mut Env, source: GlobalId, variant: GlobalId, name: &str) -> Result<(GlobalId, u64), String> {
    let sk = skeleton(env, source)?;
    ensure_library(env, sk.cmp)?;
    let lib = env.lookup_global(&format!("search::neon_{}", sk.cmp.name())).ok_or("the search library is not loaded")?;
    let slice_ty = crate::opt::symex::telescope(env, source).ok_or("no telescope")?.binders[0].2.clone();
    let unfold = |def: GlobalId| {
        let body = Rc::new(Term::Delta { def, args: vec![mk::var(1), mk::var(0)] });
        mk::lam("xs", Rel::Rel, slice_ty.clone(), mk::lam("i", Rel::Rel, mk::int_ty(Width::U64), body))
    };
    let r = |t: Tm| (Rel::Rel, t);
    let body = mk::apps(
        mk::global(lib),
        [r(sk.ret.clone()), r(mk::lit(Width::U8, sk.c)), r(sk.found.clone()), r(sk.base.clone()), r(mk::global(source)), r(unfold(source)), r(mk::global(variant)), r(unfold(variant)), r(mk::var(1)), r(mk::var(0))],
    );
    crate::opt::proof::commit_counted(env, variant, source, body, &Recursion::None, name, SEARCH_PROOF_STEPS).map_err(|e| format!("the search variant's lemma was rejected by the kernel: {e}"))
}

/// The skeleton's per-step costs `(variant step, source step)` under
/// `model` (one step each, calls not counted): the variant tests
/// [`CHUNK`] bytes per step, the source one.
pub fn step_costs(model: &crate::opt::cost::model::SetModel, k: &Crate, variant: ItemId, source: ItemId) -> (u64, u64) {
    let c = |id: ItemId| k.fn_def(id).map(|f| model.fn_cost(k, f, &|_| None)).unwrap_or(0);
    (c(variant), c(source))
}

