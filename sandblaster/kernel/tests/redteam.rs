//! Red-team reproductions against the kernel (lens: KERNEL EXPLOITS).
//!
//! Tests that demonstrate an unsoundness assert what a SOUND kernel must do
//! (reject). R1 (below) was fixed by Pfenning-style resurrection in the
//! checker and the proposition requirement on irrelevant Σ components and
//! constructor fields (see AUDIT.md §4); its reproductions are no longer
//! ignored and are also part of the adversarial suite.

mod common;

use common::*;
use sandblaster_kernel::api::*;

fn must_reject(src: &str, what: &str) {
    let mut env = prelude();
    if let Ok(names) = load(&mut env, src) {
        panic!("UNSOUND: kernel accepted {what}: {names:?}");
    }
}

// ---------------------------------------------------------------------------
// R1 (critical, FIXED): closed proof of Empty. Root cause (before the fix):
// `Checker` carried one boolean `irr`; once an irrelevant position is entered, every `Irr`
// variable / `snd` of an Irr Σ / Irr constructor field / Irr let becomes
// usable relevantly — including binders introduced *inside* that position.
// Irrelevant positions may hold data (e.g. `.h : Bool`), conversion skips
// them, and `absurd` turns an irrelevant proof of Empty into a relevant term.
// ---------------------------------------------------------------------------

#[test]
fn r1a_irr_lambda_in_irrelevant_mode_proves_empty() {
    must_reject(include_str!("redteam/irr_mode_empty.core"), "boom : Empty (Irr λ in irr mode)");
}

#[test]
fn r1b_snd_of_irr_sigma_in_irrelevant_mode_proves_empty() {
    must_reject(
        "def[lemma] boom : Empty :=
           absurd(Empty,
             let L : (G : (Sigma (b : Bool), .Bool) -> Bool)
                   -> Eq(Bool, G pair(Sigma (b : Bool), .Bool, true, false), G pair(Sigma (b : Bool), .Bool, true, true)) =
               fun (G : (Sigma (b : Bool), .Bool) -> Bool) => refl(Bool, G pair(Sigma (b : Bool), .Bool, true, false));
             bool::false_ne_true (L (fun (p : Sigma (b : Bool), .Bool) => snd(p))))",
        "boom : Empty (snd of Irr Σ in irr mode)",
    );
}

#[test]
fn r1c_irr_ctor_field_in_irrelevant_mode_proves_empty() {
    must_reject(
        "inductive IBox { | ibox(.x : Bool) }
         def[lemma] boom : Empty :=
           absurd(Empty,
             bool::false_ne_true
               (eq::cong IBox Bool (fun (b : IBox) => match b : IBox as _ return Bool with | ibox(.x) => x end)
                  ibox(.false) ibox(.true) (refl(IBox, ibox(.false)))))",
        "boom : Empty (Irr ctor field in irr mode)",
    );
}

#[test]
fn r1d_irr_let_in_irrelevant_mode_proves_empty() {
    must_reject(
        "def[lemma] boom : Empty :=
           absurd(Empty,
             let L : (G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false) =
               fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true);
             bool::false_ne_true (L (fun (.h : Bool) => let .y : Bool = h; bool::not y)))",
        "boom : Empty (Irr let in irr mode)",
    );
}

/// Consequence: a checked `exec` definition whose bounds proof comes from
/// `boom` — the kind of index codegen emits as `get_unchecked` (UB).
#[test]
fn r1e_exec_out_of_bounds_index_typechecks() {
    must_reject(
        concat!(
            include_str!("redteam/irr_mode_empty.core"),
            "\ndef[exec] oob : (s : Slice U8) -> U8 :=
               fun (s : Slice U8) =>
                 slice::index U8 s 1000usize .absurd(Eq(Bool, #lt_usize(1000usize, fst(s)), true), boom)"
        ),
        "exec out-of-bounds index justified by boom",
    );
}

// ---------------------------------------------------------------------------
// Prelude fidelity: every whitelisted integer / byte method evaluated by the
// kernel on literals, compared with native Rust (boundary grids, all widths).
// ---------------------------------------------------------------------------

fn opt(ty: &str, v: Option<String>) -> String {
    match v {
        Some(x) => format!("Some[{ty}]({x})"),
        None => format!("None[{ty}]"),
    }
}

macro_rules! fidelity {
    ($name:ident, $t:ty, $w:literal, $W:literal, $n:literal) => {
        #[test]
        fn $name() {
            let env = prelude();
            let m = <$t>::MAX;
            let vals: Vec<$t> = vec![0, 1, 2, 3, 7, 8, m, m - 1, m / 2, m / 2 + 1, m / 3, (m / 255).wrapping_mul(0x5a), 1 << ($n * 8 - 1)];
            let shs: Vec<u32> = vec![0, 1, 7, 8, 9, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, u32::MAX];
            let lit = |x: $t| format!("{}{}", x, $w);
            let mut bad = Vec::new();
            let mut chk = |src: String, want: String| {
                let got = norm(&env, &src);
                if got != want {
                    bad.push(format!("{src}: kernel {got}, rust {want}"));
                }
            };
            for &a in &vals {
                chk(format!("{}::wrapping_neg {}", $w, lit(a)), lit(a.wrapping_neg()));
                chk(format!("{}::count_ones {}", $w, lit(a)), format!("{}u32", a.count_ones()));
                chk(format!("{}::leading_zeros {}", $w, lit(a)), format!("{}u32", a.leading_zeros()));
                chk(format!("{}::trailing_zeros {}", $w, lit(a)), format!("{}u32", a.trailing_zeros()));
                chk(format!("{}::swap_bytes {}", $w, lit(a)), lit(a.swap_bytes()));
                chk(format!("{}::is_power_of_two {}", $w, lit(a)), format!("{}", a.is_power_of_two()));
                for &s in &shs {
                    let sl = format!("{s}u32");
                    chk(format!("{}::wrapping_shl {} {}", $w, lit(a), sl), lit(a.wrapping_shl(s)));
                    chk(format!("{}::wrapping_shr {} {}", $w, lit(a), sl), lit(a.wrapping_shr(s)));
                    chk(format!("{}::rotate_left {} {}", $w, lit(a), sl), lit(a.rotate_left(s)));
                    chk(format!("{}::rotate_right {} {}", $w, lit(a), sl), lit(a.rotate_right(s)));
                }
                for &b in &vals {
                    let (la, lb) = (lit(a), lit(b));
                    chk(format!("{}::wrapping_add {la} {lb}", $w), lit(a.wrapping_add(b)));
                    chk(format!("{}::wrapping_sub {la} {lb}", $w), lit(a.wrapping_sub(b)));
                    chk(format!("{}::wrapping_mul {la} {lb}", $w), lit(a.wrapping_mul(b)));
                    chk(format!("{}::min {la} {lb}", $w), lit(a.min(b)));
                    chk(format!("{}::max {la} {lb}", $w), lit(a.max(b)));
                    chk(format!("{}::saturating_add {la} {lb}", $w), lit(a.saturating_add(b)));
                    chk(format!("{}::saturating_sub {la} {lb}", $w), lit(a.saturating_sub(b)));
                    chk(format!("{}::saturating_mul {la} {lb}", $w), lit(a.saturating_mul(b)));
                    chk(format!("{}::abs_diff {la} {lb}", $w), lit(a.abs_diff(b)));
                    chk(format!("{}::checked_add {la} {lb}", $w), opt($W, a.checked_add(b).map(lit)));
                    chk(format!("{}::checked_sub {la} {lb}", $w), opt($W, a.checked_sub(b).map(lit)));
                    chk(format!("{}::checked_mul {la} {lb}", $w), opt($W, a.checked_mul(b).map(lit)));
                    chk(format!("{}::checked_div {la} {lb}", $w), opt($W, a.checked_div(b).map(lit)));
                    chk(format!("{}::checked_rem {la} {lb}", $w), opt($W, a.checked_rem(b).map(lit)));
                }
            }
            assert!(bad.is_empty(), "{} mismatches, first: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
        }
    };
}

fidelity!(prelude_int_methods_u8, u8, "u8", "U8", 1);
fidelity!(prelude_int_methods_u16, u16, "u16", "U16", 2);
fidelity!(prelude_int_methods_u32, u32, "u32", "U32", 4);
fidelity!(prelude_int_methods_u64, u64, "u64", "U64", 8);
fidelity!(prelude_int_methods_usize, u64, "usize", "Usize", 8);

fn list_of(bytes: &[u8]) -> String {
    let mut s = "Nil[U8]".to_string();
    for b in bytes.iter().rev() {
        s = format!("Cons[U8]({b}u8, {s})");
    }
    s
}

macro_rules! bytes_fidelity {
    ($name:ident, $t:ty, $w:literal, $n:literal) => {
        #[test]
        fn $name() {
            let env = prelude();
            let m = <$t>::MAX;
            let vals: Vec<$t> = vec![0, 1, 0x7f, 0x80, 0xff, m, m - 1, m / 3, (m / 255).wrapping_mul(0x5a), 1 << ($n * 8 - 1)];
            let mut bad = Vec::new();
            for &x in &vals {
                let lit = format!("{x}{}", $w);
                for (f, want) in [("to_le_bytes", x.to_le_bytes()), ("to_be_bytes", x.to_be_bytes())] {
                    let src = format!("fst({}::{f} {lit})", $w);
                    let got = norm(&env, &src);
                    if got != list_of(&want) {
                        bad.push(format!("{src}: {got}"));
                    }
                }
                let bytes = x.to_le_bytes();
                let arr = format!("pair(Array U8 {}usize, {}, refl(Int, {}int))", $n, list_of(&bytes), $n);
                for (f, want) in [("from_le_bytes", <$t>::from_le_bytes(bytes)), ("from_be_bytes", <$t>::from_be_bytes(bytes))] {
                    let src = format!("{}::{f} ({arr})", $w);
                    let got = norm(&env, &src);
                    if got != format!("{want}{}", $w) {
                        bad.push(format!("{src}: {got}"));
                    }
                }
            }
            assert!(bad.is_empty(), "{:#?}", bad);
        }
    };
}

bytes_fidelity!(prelude_bytes_u16, u16, "u16", 2);
bytes_fidelity!(prelude_bytes_u32, u32, "u32", 4);
bytes_fidelity!(prelude_bytes_u64, u64, "u64", 8);

#[test]
fn harness_sanity_detects_mismatch() {
    let env = prelude();
    assert_eq!(norm(&env, "u64::rotate_right 1u64 1u32"), "9223372036854775808u64");
    assert_ne!(norm(&env, "u64::rotate_right 1u64 1u32"), "1u64");
    assert_eq!(norm(&env, "u64::saturating_mul 4294967296u64 4294967296u64"), format!("{}u64", u64::MAX));
}

// ---------------------------------------------------------------------------
// bvnorm / linarith / axiom must-reject probes (false statements, many true
// on almost every input; width boundaries). Each must be rejected.
// ---------------------------------------------------------------------------

#[test]
fn false_word_and_arith_statements_are_rejected() {
    let env = prelude();
    let cases: &[(&str, &str, &str)] = &[
        ("shl-then-shr drops top byte", "U32", "fun (x : U32) => bvrefl(U32, #wshr_u32(#wshl_u32(x, 8u32), 8u32), x)"),
        ("shr not over not", "U8", "fun (x : U8) => bvrefl(U8, #wshr_u8(#not_u8(x), 1u32), #not_u8(#wshr_u8(x, 1u32)))"),
        (
            "or vs xor overlap",
            "U32",
            "fun (b : U8) (c : U8) => bvrefl(U32, #or_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32)), #xor_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32)))",
        ),
        (
            "zext not over wadd",
            "U32",
            "fun (a : U8) (b : U8) => bvrefl(U32, #cast_u8_u32(#wadd_u8(a, b)), #wadd_u32(#cast_u8_u32(a), #cast_u8_u32(b)))",
        ),
        ("rotr by 64 is id at u64 but rotr 32 is not", "U64", "fun (x : U64) => bvrefl(U64, #rotr_u64(x, 32u32), x)"),
        ("shift amount 64 masks to 0 at u64 (true) vs 63", "U64", "fun (x : U64) => bvrefl(U64, #wshl_u64(x, 64u32), #wshl_u64(x, 63u32))"),
        (
            "sum split by carry",
            "U16",
            "fun (a : U16) (b : U16) => bvrefl(U16, #wshr_u16(#wadd_u16(a, b), 1u32), #wadd_u16(#wshr_u16(a, 1u32), #wshr_u16(b, 1u32)))",
        ),
        ("absorption vs or (false)", "U32", "fun (x : U32) (y : U32) => bvrefl(U32, #and_u32(x, #or_u32(x, y)), #or_u32(x, y))"),
        (
            "5-var majority mismatch",
            "U8",
            "fun (a : U8) (b : U8) (c : U8) (d : U8) (e : U8) => bvrefl(U8, #xor_u8(#and_u8(a, b), #and_u8(#and_u8(c, d), e)), #xor_u8(#and_u8(a, b), #and_u8(c, #and_u8(d, a))))",
        ),
        (
            "mul by 3 vs shl+add wrong const",
            "U64",
            "fun (x : U64) => bvrefl(U64, #wmul_u64(x, 3u64), #wadd_u64(#wshl_u64(x, 1u32), #wadd_u64(x, 1u64)))",
        ),
        ("swap_bytes twice vs once", "U32", "fun (x : U32) => bvrefl(U32, #swap_bytes_u32(x), #swap_bytes_u32(#swap_bytes_u32(x)))"),
        ("count_ones of not", "U32", "fun (x : U32) => bvrefl(U32, #count_ones_u32(#not_u32(x)), #wsub_u32(31u32, #count_ones_u32(x)))"),
        (
            "linarith u64 bound off by one",
            "",
            "fun (x : U64) => linarith([]; Eq(Bool, #lt_int(#cast_u64_int(x), 18446744073709551615int), true); [])",
        ),
        (
            "linarith usize bound off by one",
            "",
            "fun (x : Usize) => linarith([]; Eq(Bool, #le_int(#cast_usize_int(x), 18446744073709551614int), true); [])",
        ),
        ("linarith wadd no carry", "", "fun (a : U8) (b : U8) => linarith([]; Eq(Bool, #le_u8(a, #wadd_u8(a, b)), true); [])"),
        (
            "linarith rem bound wrong",
            "",
            "fun (x : U64) => linarith([]; Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 7u64), true); [])",
        ),
        (
            "linarith wshr by 1 halves exactly",
            "",
            "fun (x : U32) => linarith([]; Eq(Int, #iadd(#cast_u32_int(#wshr_u32(x, 1u32)), #cast_u32_int(#wshr_u32(x, 1u32))), #cast_u32_int(x)); [])",
        ),
        ("linarith mask 2^k-1 wrong k", "", "fun (x : U32) => linarith([]; Eq(Bool, #le_u32(#and_u32(x, 255u32), 127u32), true); [])"),
        ("linarith trunc cast", "", "fun (x : U32) => linarith([]; Eq(Int, #cast_u8_int(#cast_u32_u8(x)), #cast_u32_int(x)); [])"),
        ("linarith idiv by 0", "", "fun (x : Int) => linarith([]; Eq(Int, #idiv(x, 0int), 1int); [])"),
        ("linarith imod neg divisor", "", "fun (x : Int) => linarith([]; Eq(Bool, #lt_int(#imod(x, -3int), 0int), true); [])"),
        ("linarith wmul carry", "", "fun (a : U8) => linarith([]; Eq(Bool, #le_u8(a, #wmul_u8(a, 2u8)), true); [])"),
        (
            "linarith cast u64->usize->u32",
            "",
            "fun (x : U64) => linarith([]; Eq(Int, #cast_u32_int(#cast_u64_u32(x)), #cast_u64_int(x)); [])",
        ),
        (
            "linarith of_int top",
            "",
            "fun (i : Int) (.h0 : Eq(Bool, #le_int(0int, i), true)) (.h1 : Eq(Bool, #le_int(i, 255int), true)) => linarith([]; Eq(Bool, #lt_u8(#of_int_u8(i; h0, h1), 255u8), true); [])",
        ),
    ];
    let mut accepted = Vec::new();
    for (what, _ty, src) in cases {
        let t = env.parse_term(&[], src).unwrap_or_else(|e| panic!("parse {what}: {e}"));
        if env.infer(&Ctx::default(), &t, &mut budget()).is_ok() {
            accepted.push(*what);
        }
    }
    assert!(accepted.is_empty(), "UNSOUND: accepted {accepted:?}");
}
