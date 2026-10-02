//! Four prover gaps that bloated the proof of the MMR's
//! `parent_heights_are_the_appended_parents` and of `chunk_peaks`'s contract
//! (storage/sandblaster/mmr), each fixed generally, as a minimal repro that
//! failed and a negative twin that must keep failing (an unproven
//! obligation, never a kernel rejection):
//!
//! * bit runs and multiples: a word's trailing zeros and trailing ones, for
//!   every count at once (`stdlib::bits::trailing_zeros_u64`,
//!   `trailing_ones_u64`, on the bit-library steps `bits::tz_shr1_<w>` and
//!   `bits::not_val_<w>`), and multiples of powers of two below a lowest set
//!   bit (`aligned_below_low_bit`, `aligned_down`) — no lemma per count;
//! * nonlinear monotonicity: `0 ≤ a·b`, `b ≤ a·b` for `1 ≤ a`, `a·b ≤ U·b`
//!   for `a ≤ U` (instances of the kernel's `mul_mono`), and the exponent of
//!   a power bounded through the power (`nat::pow2_lt_rev`);
//! * a constructor's value inside a contract (`ret.v == Some((Position::new(n),
//!   g))`): the goal's constructor equation is split through layers of
//!   different types (an option of a pair of a newtype); a contract that
//!   names an opaque function (a constructor callers know by its contract)
//!   has the callee's contract as a fact of its proof; and closing a proof
//!   under the facts a search derived is linear (`auto::state`), so a large
//!   proof no longer exhausts the goal's budget after it was found;
//! * a match-shaped hypothesis (an irrelevant `use_hyp` instance) passed to a
//!   lemma: the elaborator promotes the proof by cases instead of handing the
//!   kernel an irrelevant variable in a relevant position.

#[path = "spec15_util.rs"]
mod util;

use util::*;

const STDLIB_MOD: &str = include_str!("../stdlib/mod.rs");
const STDLIB_BITS: &str = include_str!("../stdlib/bits.rs");
const STDLIB_SEQS: &str = include_str!("../stdlib/seqs.rs");
const STDLIB_BRIDGES: &str = include_str!("../stdlib/bridges.rs");
const STDLIB_FOLDS: &str = include_str!("../stdlib/folds.rs");

const EXEC_STUB: &str = "//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub.\npub fn probe(x: u8) -> u8 { x }\n";

/// A probe crate: a stub boundary, the standard library and `proof`.
fn run_with_stdlib(proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\nmod stdlib;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let proof = format!("//! Probe.\nuse sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse crate::stdlib::bits::aligned;\n{proof}");
    run_files(&[
        ("r/mod.rs", root),
        ("r/exec.rs", EXEC_STUB),
        ("r/stdlib/mod.rs", STDLIB_MOD),
        ("r/stdlib/bits.rs", STDLIB_BITS),
        ("r/stdlib/seqs.rs", STDLIB_SEQS),
        ("r/stdlib/bridges.rs", STDLIB_BRIDGES),
        ("r/stdlib/folds.rs", STDLIB_FOLDS),
        ("r/PROOF.rs", &proof),
    ])
}

/// A probe crate without the standard library.
fn run_plain(proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let proof = format!("//! Probe.\nuse sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", EXEC_STUB), ("r/PROOF.rs", &proof)])
}

/// No kernel rejection anywhere (a refuted goal is an unproven obligation).
#[track_caller]
fn no_rejection(r: &Run) {
    for needle in ["rejected by the kernel", "the kernel rejected", "kernel rejects", "Relevance:"] {
        assert!(!r.rendered.contains(needle), "a kernel rejection ({needle}):\n{}", r.explain());
    }
}

/// `crate::proof::<name>` checked, with every obligation proven.
#[track_caller]
fn proven(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let bad: Vec<String> = r.unproven.iter().filter(|(d, _, _)| *d == full).map(|(_, k, g)| format!("[{k}] {g}")).collect();
    assert!(bad.is_empty(), "`{full}` has unproven obligations:\n{}\n{}", bad.join("\n"), r.rendered);
    assert!(r.checked_defs.contains(&full), "`{full}` was not checked:\n{}", r.explain());
    no_rejection(r);
}

/// `crate::proof::<name>` not proven, and nothing rejected by the kernel.
#[track_caller]
fn refuted(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    assert!(!r.checked_defs.contains(&full), "`{full}` was proven, but its goal does not follow:\n{}", r.explain());
    no_rejection(r);
}

// ---------------------------------------------------------------------------
// 1. Bit runs and multiples
// ---------------------------------------------------------------------------

#[test]
fn trailing_zeros_and_ones_for_every_count() {
    let r = run_with_stdlib(
        r#"
/// A nonzero word is 2^z times an odd number, `z` its trailing zeros.
#[lemma]
fn tz(x: u64) {
    requires(x != 0u64);
    ensures(aligned(x as Int, x.trailing_zeros() as Int)
        && aligned((x as Int) - pow2(x.trailing_zeros() as Int), (x.trailing_zeros() as Int) + 1));
    crate::stdlib::bits::trailing_zeros_u64(x);
    follows();
}
/// Negative twin: not a multiple of the next power.
#[lemma]
fn tz_bad(x: u64) {
    requires(x != 0u64);
    ensures(aligned(x as Int, (x.trailing_zeros() as Int) + 1));
    crate::stdlib::bits::trailing_zeros_u64(x);
    follows();
}
/// The trailing ones `t` of a word below the maximum: `n + 1 - 2^t` is a
/// multiple of 2^(t+1).
#[lemma]
fn tones(n: u64) {
    requires(n != 18446744073709551615u64);
    ensures(pow2((!n).trailing_zeros() as Int) <= (n as Int) + 1
        && aligned((n as Int) + 1 - pow2((!n).trailing_zeros() as Int), ((!n).trailing_zeros() as Int) + 1));
    crate::stdlib::bits::trailing_ones_u64(n);
    follows();
}
/// Negative twin: `n + 1` is not a multiple of 2^(t+1).
#[lemma]
fn tones_bad(n: u64) {
    requires(n != 18446744073709551615u64);
    ensures(aligned((n as Int) + 1, ((!n).trailing_zeros() as Int) + 1));
    crate::stdlib::bits::trailing_ones_u64(n);
    follows();
}
/// Below `2^62` a word has at most 62 trailing ones (the exponent read off
/// `2^t <= n + 1 <= 2^62`).
#[lemma]
fn tones_bound(n: u64) {
    requires((n as Int) < pow2(62));
    ensures(((!n).trailing_zeros() as Int) <= 62);
    crate::stdlib::bits::trailing_ones_u64(n);
    follows();
}
/// Negative twin: 61 is too few (`2^62 - 1` has 62).
#[lemma]
fn tones_bound_bad(n: u64) {
    requires((n as Int) < pow2(62));
    ensures(((!n).trailing_zeros() as Int) <= 61);
    crate::stdlib::bits::trailing_ones_u64(n);
    follows();
}
/// Below the lowest set bit `t` of `x`, `x - 2^i` is a multiple of 2^i.
#[lemma]
fn low(x: Nat, t: Int, i: Int) {
    requires(0 <= i && i <= t && pow2(t) <= x && aligned(x - pow2(t), t + 1));
    ensures(pow2(i) <= x && aligned(x - pow2(i), i) && aligned(x - pow2(t), i));
    crate::stdlib::bits::aligned_below_low_bit(x, t, i);
    crate::stdlib::bits::aligned_down((x - pow2(t)) as Nat, t + 1, i);
    follows();
}
/// Negative twin: `x - 2^i` is not a multiple of 2^(i+1).
#[lemma]
fn low_bad(x: Nat, t: Int, i: Int) {
    requires(0 <= i && i <= t && pow2(t) <= x && aligned(x - pow2(t), t + 1));
    ensures(pow2(i) <= x && aligned(x - pow2(i), i + 1));
    crate::stdlib::bits::aligned_below_low_bit(x, t, i);
    follows();
}
"#,
    );
    proven(&r, "tz");
    refuted(&r, "tz_bad");
    proven(&r, "tones");
    refuted(&r, "tones_bad");
    proven(&r, "tones_bound");
    refuted(&r, "tones_bound_bad");
    proven(&r, "low");
    refuted(&r, "low_bad");
}

#[test]
fn a_complement_is_exact() {
    let r = run_plain(
        r#"
/// `!x` is `MAX - x`, for linear arithmetic (`bits::not_val_<w>`).
#[lemma]
fn not64(x: u64) {
    ensures((!x) as Int + (x as Int) == 18446744073709551615);
    by_arithmetic();
}
/// At another width.
#[lemma]
fn not8(x: u8) {
    ensures((!x) as Int == 255 - (x as Int));
    by_arithmetic();
}
/// Negative twin.
#[lemma]
fn not8_bad(x: u8) {
    ensures((!x) as Int == 256 - (x as Int));
    by_arithmetic();
}
"#,
    );
    proven(&r, "not64");
    proven(&r, "not8");
    refuted(&r, "not8_bad");
}

// ---------------------------------------------------------------------------
// 2. Nonlinear monotonicity
// ---------------------------------------------------------------------------

#[test]
fn products_of_nonnegative_factors() {
    let r = run_plain(
        r#"
/// A product of nonnegative factors is nonnegative.
#[lemma]
fn nonneg(c: Int, x: Int) {
    requires(c >= 0 && x >= 0);
    ensures(c * x >= 0);
    by_arithmetic();
}
/// Negative twin: not positive (`x` may be 0).
#[lemma]
fn nonneg_bad(c: Int, x: Int) {
    requires(c >= 0 && x >= 0);
    ensures(c * x >= 1);
    by_arithmetic();
}
/// A factor of at least 1 does not decrease the other.
#[lemma]
fn grows(c: Int, x: Int) {
    requires(c >= 0 && x >= 0);
    ensures((c + 1) * x >= x);
    by_arithmetic();
}
/// Negative twin: not strictly (`x` may be 0).
#[lemma]
fn grows_bad(c: Int, x: Int) {
    requires(c >= 0 && x >= 0);
    ensures((c + 1) * x >= x + 1);
    by_arithmetic();
}
/// A factor bounded by a literal bounds the product by the other times it.
#[lemma]
fn bounded(a: Int, b: Int) {
    requires(0 <= a && a <= 5 && b >= 0);
    ensures(a * b <= 5 * b);
    by_arithmetic();
}
/// Negative twin.
#[lemma]
fn bounded_bad(a: Int, b: Int) {
    requires(0 <= a && a <= 5 && b >= 0);
    ensures(a * b <= 4 * b);
    by_arithmetic();
}
/// The exponent of a power, through a product (`chunk_peaks`'s `g <= 62`).
#[lemma]
fn exponent(c: u64, g: u32) {
    requires(((c as Int) + 1) * pow2(g as Int) <= pow2(62));
    ensures(g <= 62u32);
    by_arithmetic();
}
/// Negative twin: `c = 0, g = 62` is allowed.
#[lemma]
fn exponent_bad(c: u64, g: u32) {
    requires(((c as Int) + 1) * pow2(g as Int) <= pow2(62));
    ensures(g <= 61u32);
    by_arithmetic();
}
"#,
    );
    proven(&r, "nonneg");
    refuted(&r, "nonneg_bad");
    proven(&r, "grows");
    refuted(&r, "grows_bad");
    proven(&r, "bounded");
    refuted(&r, "bounded_bad");
    proven(&r, "exponent");
    refuted(&r, "exponent_bad");
}

// ---------------------------------------------------------------------------
// 3. A contract that names an opaque function
// ---------------------------------------------------------------------------

const OPAQUE_NEW: &str = r#"//! A newtype built by an opaque constructor.
use sandblaster::prelude::*;

/// A value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P(u64);

/// The value `v`. Opaque in proofs (it has a loop): callers know it by its
/// contract.
#[ensures(|ret: P| ret == P(v))]
pub fn mk(v: u64) -> P {
    for _ in 0..2u32 {}
    P(v)
}

/// The pair of `a + b` and 7, its position named through `mk`.
#[ensures(|ret: Option<(P, u32)>| ret == Some((mk((a as u64) + (b as u64)), 7u32)))]
pub fn pair(a: u32, b: u32) -> Option<(P, u32)> {
    Some((P((b as u64) + (a as u64)), 7))
}
"#;

fn run_opaque(exec: &str) -> Run {
    run_files(&[("r/mod.rs", "mod p;\npub use p::{P, mk, pair};\n"), ("r/p.rs", exec)])
}

const NESTED_NEW: &str = r#"//! A newtype built by a transparent constructor (`Position::new`) around a
//! helper's value.
use sandblaster::prelude::*;

/// A value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P(u64);

impl P {
    /// The value `v`.
    #[ensures(|ret: P| ret == P(v))]
    pub fn new(v: u64) -> P {
        P(v)
    }
}

/// Twice `a + 1`. Opaque in proofs (it has a loop): callers know it by its
/// contract.
#[ensures(|ret: u64| (ret as Int) == crate::proof::tw((a as Int) + 1))]
pub fn helper(a: u32) -> u64 {
    proof! { crate::proof::tw_is((a as Int) + 1); }
    for _ in 0..2u32 {}
    ((a as u64) + 1) * 2
}

/// The pair of `tw(succ(a))` and 7, its value named through `P::new` three
/// constructors deep (an option of a pair of the newtype). `succ(a)` is
/// `a + 1` by a fact, so the two values are equal by congruence: the
/// innermost equation needs the whole search, not a rewrite of the integer
/// arguments.
#[ensures(|ret: Option<(P, u32)>| ret == Some((P::new(crate::proof::tw(crate::proof::succ(a as Int)) as u64), 7u32)))]
pub fn pair(a: u32) -> Option<(P, u32)> {
    proof! { crate::proof::succ_is(a as Int); }
    let p = P::new(helper(a));
    Some((p, 7))
}
"#;

const NESTED_PROOF: &str = r#"//! Vocabulary.
use sandblaster::prelude::*;

/// Twice (opaque: its value is `tw_is`).
#[spec]
#[opaque]
#[example(tw(3) == 6)]
pub fn tw(x: Int) -> Int {
    2 * x
}

/// The value of `tw`.
#[lemma]
pub fn tw_is(x: Int) {
    ensures(tw(x) == 2 * x);
    unfold(tw);
    follows();
}

/// The successor (opaque: its value is `succ_is`).
#[spec]
#[opaque]
#[example(succ(3) == 4)]
pub fn succ(x: Int) -> Int {
    x + 1
}

/// The value of `succ`.
#[lemma]
pub fn succ_is(x: Int) {
    ensures(succ(x) == x + 1);
    unfold(succ);
    follows();
}
"#;

#[test]
fn a_contract_names_a_transparent_constructor() {
    let run = |exec: &str| {
        run_files(&[
            ("r/mod.rs", "mod p;\npub use p::{P, helper, pair};\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n"),
            ("r/p.rs", exec),
            ("r/PROOF.rs", NESTED_PROOF),
        ])
    };
    let r = run(NESTED_NEW);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(!r.unproven.iter().any(|(d, _, _)| d.contains("pair")), "`pair`'s contract did not prove:\n{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::p::pair::ensures"), "{}", r.explain());
    no_rejection(&r);
    // negative twin: another value
    let r = run(&NESTED_NEW.replace("crate::proof::tw(crate::proof::succ(a as Int))", "crate::proof::tw(crate::proof::succ(a as Int) + 1)"));
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::p::pair::ensures" && k == "ensures"), "the wrong contract proved:\n{}", r.explain());
    no_rejection(&r);
}

#[test]
fn a_contract_names_an_opaque_constructor() {
    let r = run_opaque(OPAQUE_NEW);
    assert!(r.front_ok, "{}", r.rendered);
    let bad: Vec<_> = r.unproven.iter().filter(|(d, _, _)| d.contains("pair")).collect();
    assert!(bad.is_empty(), "`pair`'s contract did not prove:\n{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::p::pair::ensures"), "{}", r.explain());
    no_rejection(&r);
    // negative twin: another position
    let r = run_opaque(&OPAQUE_NEW.replace("Some((mk((a as u64) + (b as u64)), 7u32))", "Some((mk((a as u64) + (b as u64) + 1u64), 7u32))"));
    assert!(r.unproven.iter().any(|(d, k, _)| d == "crate::p::pair::ensures" && k == "ensures"), "the wrong contract proved:\n{}", r.explain());
    no_rejection(&r);
}

// ---------------------------------------------------------------------------
// 4. A match-shaped hypothesis passed to a lemma
// ---------------------------------------------------------------------------

const PICK_ROOT: &str = r#"
/// The small numbers.
pub fn pick(x: u32) -> Option<u32> {
    if x < 10 { Some(x) } else { None }
}

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const PICK_LAWS: &str = r#"use sandblaster::prelude::*;
use super::pick;

/// `pick` keeps a small number (a statement by cases on the answer).
#[law]
fn pick_keeps(x: u32) {
    requires(x < 10u32);
    ensures(match pick(x) { Some(v) => v == x, None => false });
}

/// `pick` drops the others.
#[law]
fn pick_drops(x: u32) {
    requires(x >= 10u32);
    ensures(pick(x) == None);
}
"#;

fn pick_proof(lemma_requires: &str, lemma_value: &str, real_use: &str) -> String {
    format!(
        r#"use sandblaster::prelude::*;
#[allow(unused_imports)]
use super::pick;

#[proof]
fn pick_keeps(x: u32) {{
    follows();
}}

#[proof]
fn pick_drops(x: u32) {{
    follows();
}}

/// An answer that holds a value is `Some` of it.
#[lemma]
fn holds(o: Option<u32>, x: u32) {{
    requires(x < 10u32);
    requires({lemma_requires});
    ensures(o == Some({lemma_value}));
    match o {{
        Some(v) => follows(),
        None => by_contradiction(),
    }}
}}

/// Pinned by its laws. The real `pick`'s statement (a `use_real`
/// instance: irrelevant, and by cases) is the lemma's `requires` for the
/// real answer (`apply` reads it off that fact, or the call's obligation
/// is proved from it); `pick'`'s from `use_hyp`.
#[proof(complete = super::pick)]
fn pick_determined(x: u32) {{
    if x < 10u32 {{
        use_real(0, x);
        {real_use}
        use_hyp(0, x);
        holds(pick(x), x);
        follows();
    }} else {{
        use_hyp(1, x);
        follows();
    }}
}}
"#
    )
}

#[test]
fn a_match_shaped_hypothesis_reaches_a_lemma() {
    let run = |req: &str, val: &str, real_use: &str| run_files(&[("r/mod.rs", PICK_ROOT), ("r/LAWS.rs", PICK_LAWS), ("r/PROOF.rs", &pick_proof(req, val, real_use))]);
    let r = run("match o { Some(v) => v == x, None => false }", "x", "let r = apply(holds);");
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.unproven.is_empty() && r.failed_defs.is_empty(), "not verified:\n{}", r.explain());
    no_rejection(&r);
    // negative twin: a requires the hypothesis does not give (the lemma
    // called with its arguments: `apply` finds no fact to read them off)
    let r = run("match o { Some(v) => v == x + 1u32, None => false }", "x + 1u32", "holds(crate::pick(x), x);");
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.unproven.iter().any(|(d, k, _)| d.contains("pick::complete") && k == "callee-requires"), "the wrong requires proved:\n{}", r.explain());
    no_rejection(&r);
}
