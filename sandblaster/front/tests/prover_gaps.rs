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
//!
//! Three more, from the verifier's laws (storage/sandblaster/verifier: the
//! first two were worked around there with case lemmas, the third had kept
//! a law to walks that collect nothing):
//!
//! * one stuck term given three constructor values: the second equation
//!   joined from them was built at the depth before the first one's
//!   saturation pushed its facts, its variables pointing at later binders
//!   (`elems` read as `sibs`), and the kernel rejected the proof ("mixing
//!   list types");
//! * `unfold(f)` of a recursive `f` unfolded, in its later rounds, a call
//!   the unfolded body brings in wherever else the goal names it (the other
//!   side of `f(s) == match f(left(s)).3 { .. }`), copying the body into
//!   every occurrence until the goal could not be read back — auto then
//!   reported the body's `if` scrutinee as absent ("does not occur
//!   relevantly"). The calls a recursive body brings in stay folded, and
//!   a copy of a call the goal also writes is given that written call's
//!   term: its own proofs come from the body's path equation (`&xs[1..]`
//!   in the arm `Some(head)` of `match xs.first()`), which a later
//!   `rewrite` of that scrutinee could not generalize;
//! * a script `rewrite(e == C(v))` of a goal that matches on `e`: the
//!   rewrite's motive kept the match's path-equation argument `refl(e)`
//!   (an irrelevant proof the abstraction does not touch) where the match,
//!   now on the motive variable `y`, takes a proof of `y == y`, and the
//!   kernel rejected the proof. That argument is now `refl(y)`.
//!
//! Two more, from the MMR's and the verifier's panic contracts (C1: a
//! no-panic clause `!(p)` is a function's last precondition):
//!
//! * a negated disjunction `!(a || b)` gave auto neither side as a fact,
//!   and as a goal it was not split;
//! * a call's precondition proof, proven for the call's irrelevant slot
//!   from an irrelevant fact (the statement's no-panic clause in a
//!   `#[proof(complete = ..)]` script), went unchanged into the callee's
//!   `ensures` fact, a relevant `let` in proof mode, and the kernel
//!   rejected the proof ("irrelevant variable `h_req0` used in a relevant
//!   position"). Such a proof is now promoted where the precondition
//!   carries no information (`Elab::contract_args`);
//! * a domain written `implies(a <= b, q)` with the no-panic clause
//!   `!(a > b)` did not give `q`: the implication was used only by backward
//!   chaining on its conclusion as written, which the target, its spec
//!   function unfolded, no longer matched, and the clause's comparison is
//!   not the premise's. An implication whose premise is a comparison now
//!   gives its conclusion when a fact compares the same operands and
//!   linear arithmetic proves the premise (`auto::facts`,
//!   `implication_units`).

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

// ---------------------------------------------------------------------------
// 5. One stuck term, three constructor values
// ---------------------------------------------------------------------------

#[test]
fn a_term_with_three_values_joins_at_the_current_depth() {
    // saturating `o == Some(z)` joins it with the two other values: the
    // first join pushes `Some(z) == Some(x)` and its injectivity before the
    // second builds `Some(z) == Some(y)` (the claim), whose proof must be at
    // that later depth; the parameters after them have other types, so a
    // proof built at the earlier depth is rejected by the kernel
    let r = run_plain(
        r#"
/// The second joined equation is the claim.
#[lemma]
fn three_values(o: Option<Seq<u8>>, x: Seq<u8>, y: Seq<u8>, z: Seq<u8>, pad: u64, q: Seq<u64>) {
    requires(o == Some(x) && o == Some(y) && o == Some(z));
    ensures(Some(z) == Some(y));
    follows();
}
/// Negative twin: another value.
#[lemma]
fn three_values_bad(o: Option<Seq<u8>>, x: Seq<u8>, y: Seq<u8>, z: Seq<u8>, pad: u64, q: Seq<u64>) {
    requires(o == Some(x) && o == Some(y) && o == Some(z));
    ensures(Some(z) == Some(seq![1u8]));
    follows();
}
"#,
    );
    proven(&r, "three_values");
    refuted(&r, "three_values_bad");
}

// ---------------------------------------------------------------------------
// 6. `unfold` of a recursive function: the body's calls stay folded
// ---------------------------------------------------------------------------

const TRI: &str = r#"
/// A recursive spec function whose body calls itself once.
#[spec]
#[decreases(n)]
#[example(tri(3) == 6)]
pub fn tri(n: Nat) -> Nat {
    if n == 0 { 0 } else { tri(n - 1) + n }
}
"#;

#[test]
fn unfold_leaves_the_bodys_calls_folded() {
    // the right side names `tri(n - 1)`, the call `tri(n)`'s body brings
    // in: after `unfold(tri)` both sides still show it folded (a later
    // round would unfold it, with every copy in the body, into the
    // grandchild call `tri(n - 1 - 1)`)
    let r = run_plain(&format!(
        r#"{TRI}
/// One step.
#[lemma]
fn tri_step(n: Nat, k: Nat) {{
    requires(n > 0 && tri(n - 1) == k);
    ensures(tri(n) == tri(n - 1) + n);
    unfold(tri);
    show();
    rewrite(tri(n - 1) == k);
    follows();
}}
/// Negative twin.
#[lemma]
fn tri_step_bad(n: Nat, k: Nat) {{
    requires(n > 0 && tri(n - 1) == k);
    ensures(tri(n) == tri(n - 1) + n + 1);
    unfold(tri);
    rewrite(tri(n - 1) == k);
    follows();
}}
"#
    ));
    proven(&r, "tri_step");
    refuted(&r, "tri_step_bad");
    let shown = r.rendered.split("warning[script]: show()").nth(1).unwrap_or_else(|| panic!("no show() output:\n{}", r.rendered));
    let goal = shown.lines().find(|l| l.contains("| goal:")).unwrap_or_else(|| panic!("no goal line:\n{shown}"));
    assert!(goal.contains("#iadd(crate::proof::tri #isub(n, 1int), n))"), "the right side's call was unfolded:\n{goal}");
    assert!(!goal.contains("#isub(#isub(n, 1int), 1int)"), "a call the body brought in was unfolded:\n{goal}");
}

#[test]
fn unfold_of_a_walk_over_both_halves_states_one_step() {
    // the shape of a subtree walk (the verifier's `rebuild`): the left
    // half's result, reused, and the right half from where it stopped
    let r = run_plain(
        r#"
/// A recursive function returning a pair, its recursive results reused.
#[spec]
#[decreases(n)]
#[example(walk(1, 0) == (2, 1))]
pub fn walk(n: Nat, x: Int) -> (Int, Int) {
    if n == 0 {
        (x, x + 1)
    } else {
        let l = walk(n - 1, x);
        let r = walk(n - 1, l.0 + l.1);
        (l.0 + r.1, r.0)
    }
}
/// One step of `walk`, stated over its recursive calls.
#[lemma]
fn walk_node(n: Nat, x: Int) {
    requires(n > 0);
    ensures(walk(n, x) == (walk(n - 1, x).0 + walk(n - 1, walk(n - 1, x).0 + walk(n - 1, x).1).1, walk(n - 1, walk(n - 1, x).0 + walk(n - 1, x).1).0));
    unfold(walk);
    follows();
}
/// Negative twin: a component swapped.
#[lemma]
fn walk_node_bad(n: Nat, x: Int) {
    requires(n > 0);
    ensures(walk(n, x) == (walk(n - 1, x).0 + walk(n - 1, walk(n - 1, x).0 + walk(n - 1, x).1).0, walk(n - 1, walk(n - 1, x).0 + walk(n - 1, x).1).0));
    unfold(walk);
    follows();
}
"#,
    );
    proven(&r, "walk_node");
    refuted(&r, "walk_node_bad");
}

const FOLD_ROOT: &str = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::join;\n";

/// QMDB's `fold_back` shape: a non-tail recursion over a slice whose
/// recursive call carries proofs (its precondition, its depth bound and the
/// bound of `&xs[1..]`, which the arm `Some(head)` of `match xs.first()`
/// knows from its path equation).
const FOLD_EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;

/// Attach `head` in front of an optional fold.
pub fn join(head: &u8, tail: Option<u8>) -> Option<u8> {
    match tail {
        None => Some(*head),
        Some(t) => Some(if t < *head { t } else { *head }),
    }
}

/// The least element, from the right.
#[requires(xs.len() <= 64usize)]
#[decreases(xs.len(), max = 64)]
pub(crate) fn fold_back(xs: &[u8]) -> Option<u8> {
    match xs.first() {
        None => None,
        Some(head) => join(head, fold_back(&xs[1..])),
    }
}
"#;

#[test]
fn unfold_then_rewrite_the_bodys_scrutinee() {
    // after `unfold(fold_back)` the arm `Some(head)` holds a copy of the
    // right side's `fold_back(&xs[1..])` whose proofs come from the arm's
    // equation; it is given the right side's term, so rewriting
    // `xs.first()` generalizes that equation (QMDB's `fold_back_is`)
    let run = |claim: &str| {
        let proof = format!(
            r#"//! Probe.
use sandblaster::prelude::*;
/// One step of the fold.
#[lemma]
fn step(xs: &[u8], y: u8) {{
    requires(xs.len() >= 1usize && xs.len() <= 64usize && xs.first() == Some(&y));
    ensures({claim});
    unfold(crate::exec::fold_back);
    rewrite(xs.first() == Some(&y));
    follows();
}}
"#
        );
        run_files(&[("r/mod.rs", FOLD_ROOT), ("r/exec.rs", FOLD_EXEC), ("r/PROOF.rs", &proof)])
    };
    let r = run("crate::exec::fold_back(xs) == crate::exec::join(&y, crate::exec::fold_back(&xs[1..]))");
    proven(&r, "step");
    // negative twin: the head left out
    let r = run("crate::exec::fold_back(xs) == crate::exec::fold_back(&xs[1..])");
    refuted(&r, "step");
}

// ---------------------------------------------------------------------------
// 7. A script rewrite of a match's scrutinee
// ---------------------------------------------------------------------------

#[test]
fn rewriting_a_matched_term_keeps_the_match_well_typed() {
    // the goal is the dependent-match idiom `match walk(x).1 as z return
    // Π(e : walk(x).1 == z). .. end refl(walk(x).1)`; rewriting `walk(x).1`
    // to `Some(v)` must give the path-equation argument the motive
    // variable's `refl` too (the kernel rejected `refl(walk(x).1)` there)
    let r = run_plain(
        r#"
/// A walk: what is left, and the answer (opaque: its value is unknown).
#[spec]
#[opaque]
#[example(walk(3) == (3, Some(3)))]
pub fn walk(x: u8) -> (u8, Option<u8>) {
    (x, Some(x))
}
/// The answer's value, by rewriting the match's scrutinee.
#[lemma]
fn rw_scrut(x: u8, v: u8) {
    requires(walk(x).1 == Some(v));
    ensures(match walk(x).1 { Some(y) => y == v, None => false });
    rewrite(walk(x).1 == Some(v));
    follows();
}
/// Negative twin: another value.
#[lemma]
fn rw_scrut_bad(x: u8, v: u8) {
    requires(walk(x).1 == Some(v));
    ensures(match walk(x).1 { Some(y) => y != v, None => false });
    rewrite(walk(x).1 == Some(v));
    follows();
}
"#,
    );
    proven(&r, "rw_scrut");
    refuted(&r, "rw_scrut_bad");
}

// ---------------------------------------------------------------------------
// 8. A negated disjunction (a panic contract's no-panic clause)
// ---------------------------------------------------------------------------

/// A panic contract `panics_when(a || b)` makes `!(a || b)` a precondition
/// (its no-panic clause, DESIGN.md §16.5): the function's body needs each
/// side's comparison from it (`children`'s shift needs `height < 64` from
/// `!(height >= 64 || pos < 2^height)`), and its callers prove it. As a
/// fact it gives `!a` and `!b`, each as the comparison's other value, which
/// linear arithmetic reads; as a goal it is the goals `!a` and `!b`.
/// Negative twins: a negated conjunction gives neither side, and the goal
/// fails when one side may hold.
#[test]
fn a_negated_disjunction_gives_each_side_negated() {
    let r = run_plain(
        r#"
/// Both sides of a negated disjunction, as comparisons.
#[lemma]
fn no_panic_sides(h: u32, p: u64, q: u64) {
    requires(!(h >= 64u32 || (p as Int) < (q as Int)));
    ensures(h < 64u32 && q <= p);
    follows();
}
/// Negative twin: a negated conjunction says neither.
#[lemma]
fn no_panic_conj(h: u32, p: u64, q: u64) {
    requires(!(h >= 64u32 && (p as Int) < (q as Int)));
    ensures(h < 64u32);
    follows();
}
/// The clause as a goal: each side refuted.
#[lemma]
fn no_panic_goal(h: u32, p: u64, q: u64) {
    requires(h <= 62u32 && q <= p);
    ensures(!(h >= 64u32 || (p as Int) < (q as Int)));
    follows();
}
/// Negative twin: one side may hold.
#[lemma]
fn no_panic_goal_open(h: u32, p: u64, q: u64) {
    requires(h <= 62u32);
    ensures(!(h >= 64u32 || (p as Int) < (q as Int)));
    follows();
}
/// The clause as a callee's hypothesis, proven at the call (the goal keeps
/// the prelude's `Not(Or(..))` unexpanded).
#[lemma]
fn calls_with_clause(h: u32, p: u64, q: u64) {
    requires(h <= 62u32 && q <= p);
    ensures(h < 64u32);
    no_panic_sides(h, p, q);
    follows();
}
/// Negative twin: the call's clause may fail.
#[lemma]
fn calls_without_clause(h: u32, p: u64, q: u64) {
    requires(h <= 62u32);
    ensures(h < 64u32);
    no_panic_sides(h, p, q);
    follows();
}
"#,
    );
    proven(&r, "no_panic_sides");
    refuted(&r, "no_panic_conj");
    proven(&r, "no_panic_goal");
    refuted(&r, "no_panic_goal_open");
    proven(&r, "calls_with_clause");
    refuted(&r, "calls_without_clause");
}

// ---------------------------------------------------------------------------
// 9. A call's precondition proof in a relevant contract fact
// ---------------------------------------------------------------------------

const DOWN_ROOT: &str = r#"
/// Rounds down to an even number; its precondition is a no-panic clause.
#[requires(!(x > 1000u32))]
pub(crate) fn down(x: u32) -> u32 { x - x % 2 }

/// `down` by another name: its contract reads the real `down`.
#[requires(!(x > 1000u32))]
#[ensures(|r: u32| r == down(x))]
pub(crate) fn down_too(x: u32) -> u32 { down(x) }

/// The total boundary.
#[ensures(|r: u32| r == down_too(x as u32))]
pub fn api(x: u8) -> u32 { down_too(x as u32) }

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const DOWN_LAWS: &str = r#"use sandblaster::prelude::*;
use super::down;

/// `down` clears the lowest bit.
#[law]
fn down_value(x: u32) {
    requires(x <= 1000u32);
    ensures(down(x) == x - x % 2u32);
}
"#;

fn down_proof(arg: &str) -> String {
    format!(
        r#"use sandblaster::prelude::*;
#[allow(unused_imports)]
use super::{{down, down_too}};

#[proof]
fn down_value(x: u32) {{
    follows();
}}

/// Pinned by its law. The call of `down_too` (outside the section) needs
/// its precondition, which the statement's irrelevant no-panic clause
/// proves; its `ensures` fact is a relevant `let`.
#[proof(complete = super::down)]
fn down_determined(x: u32) {{
    let b = down_too({arg});
    use_hyp(0, x);
    use_real(0, x);
    follows();
}}
"#
    )
}

/// A `#[proof(complete = ..)]` script calls a function whose precondition
/// is a negation, proven from the statement's irrelevant precondition: the
/// callee's `ensures` fact takes the proof relevantly, promoted. Negative
/// twin: a precondition that does not follow stays an unproven obligation,
/// never a kernel rejection.
#[test]
fn a_calls_precondition_proof_is_promoted_for_its_contract_fact() {
    let run = |arg: &str| run_files(&[("r/mod.rs", DOWN_ROOT), ("r/LAWS.rs", DOWN_LAWS), ("r/PROOF.rs", &down_proof(arg))]);
    let r = run("x");
    assert!(r.front_ok, "{}", r.rendered);
    no_rejection(&r);
    assert!(r.unproven.is_empty() && r.failed_defs.is_empty(), "not verified:\n{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::down::complete"), "`down::complete` not checked:\n{}", r.explain());
    let r = run("x + 1u32");
    assert!(r.front_ok, "{}", r.rendered);
    no_rejection(&r);
    assert!(r.unproven.iter().any(|(d, k, _)| d.contains("down::complete") && k == "callee-requires"), "the call's precondition proved:\n{}", r.explain());
}

// ---------------------------------------------------------------------------
// 10. An implication whose premise follows by arithmetic
// ---------------------------------------------------------------------------

/// `PeakIterator::new`'s domain, `implies(size <= MAX_NODES,
/// valid_size(size))`, and its no-panic clause `!(size > MAX_NODES)` give
/// `valid_size(size)` (the code needs it): modus ponens, the premise proven
/// by linear arithmetic from the clause. Negative twins: without the
/// clause the premise may fail, and a clause about other operands proves
/// nothing.
#[test]
fn an_implication_whose_premise_follows_by_arithmetic_gives_its_conclusion() {
    let r = run_plain(
        r#"
/// Whether `r` is even below `2^h` (a stand-in for `valid_size`: a
/// recursive predicate the search unfolds).
#[spec]
#[decreases(h + 1)]
#[example(evenish(4, 3) && !evenish(5, 3))]
pub fn evenish(r: Int, h: Int) -> bool {
    if h < 0 { r == 0 } else if r >= pow2(h) { evenish(r - pow2(h), h - 1) } else { evenish(r, h - 1) }
}

/// The domain and the clause give the predicate.
#[lemma]
fn domain_mp(s: u64, m: u64) {
    requires(implies((s as Int) <= (m as Int), evenish(s as Int, 8)));
    requires(!((s as Int) > (m as Int)));
    ensures(evenish(s as Int, 8));
    follows();
}
/// Negative twin: without the clause the premise may fail.
#[lemma]
fn domain_mp_open(s: u64, m: u64) {
    requires(implies((s as Int) <= (m as Int), evenish(s as Int, 8)));
    ensures(evenish(s as Int, 8));
    follows();
}
/// Negative twin: a clause about other operands.
#[lemma]
fn domain_mp_other(s: u64, m: u64, t: u64) {
    requires(implies((s as Int) <= (m as Int), evenish(s as Int, 8)));
    requires(!((t as Int) > (m as Int)));
    ensures(evenish(s as Int, 8));
    follows();
}
"#,
    );
    proven(&r, "domain_mp");
    refuted(&r, "domain_mp_open");
    refuted(&r, "domain_mp_other");
}

// ---------------------------------------------------------------------------
// 11. Shifts by a variable amount (C4)
// ---------------------------------------------------------------------------

/// A shift by a non-literal amount `s` below the width: `1 << s` is `2^s`,
/// `x << s` (checked or wrapping) is `x · 2^s` when that fits, `MAX >> s`
/// is `2^(w − s) − 1` and its complement has `w − s` trailing zeros, a
/// power `2^e` has `e` trailing zeros, `(a + b) · 2^e` distributes, and
/// shifts of ordered values are ordered (`a ≤ b` gives `a >> s ≤ b >> s`,
/// and `a << s ≤ b << s` when `b << s` fits).
/// Each is one lemma of `lemmas/bits_shift.core` (the amount enumerated
/// once, in the library), instantiated by `auto` at the shift atoms; the
/// storage proofs' 64-case ladders (`shl_one`, `wshl_one`, `wshl_exact`,
/// `mask_facts`, `tz_pow2`, `chunk_facts`) are gone. Negative twins: a
/// product that may not fit, an off-by-one power, a mask one bit short,
/// a strict order of shifts of equal values, a larger shift that
/// overflows.
#[test]
fn shifts_by_a_variable_amount() {
    let r = run_plain(
        r#"
/// `1 << s`.
#[lemma]
fn shl_one(s: u32) {
    requires(s < 64u32);
    ensures((1u64 << s) as Int == pow2(s as Int));
    follows();
}
/// The wrapping form (the literal reading's `<<`).
#[lemma]
fn wshl_one(s: u32) {
    requires(s < 64u32);
    ensures(1u64.wrapping_shl(s) as Int == pow2(s as Int));
    follows();
}
/// A product that fits.
#[lemma]
fn shl_mul(x: u64, s: u32) {
    requires(s < 64u32 && (x as Int) * pow2(s as Int) < pow2(64));
    ensures((x << s) as Int == (x as Int) * pow2(s as Int));
    follows();
}
/// At another width, wrapping.
#[lemma]
fn wshl_mul8(x: u8, s: u32) {
    requires(s < 8u32 && (x as Int) * pow2(s as Int) < 256);
    ensures(x.wrapping_shl(s) as Int == (x as Int) * pow2(s as Int));
    follows();
}
/// The mask of `64 - k` ones and its complement's trailing zeros.
#[lemma]
fn mask(k: u32) {
    requires(k < 64u32);
    ensures((u64::MAX >> k) as Int == pow2(64 - (k as Int)) - 1 && ((!(u64::MAX >> k)).trailing_zeros() as Int) == 64 - (k as Int));
    follows();
}
/// `chunk_peaks`'s bounds: a sum times a power (linked to the code's
/// `(c + 1) << g`), and the next power.
#[lemma]
fn chunk(c: u64, g: u32) {
    requires(g <= 62u32 && ((c as Int) + 1) * pow2(g as Int) <= pow2(62));
    ensures((c as Int) + 1 <= pow2(62)
        && ((c as Int) + 1) * pow2(g as Int) == (c as Int) * pow2(g as Int) + pow2(g as Int)
        && ((c + 1u64) << g) as Int == ((c as Int) + 1) * pow2(g as Int)
        && (c << g) as Int == (c as Int) * pow2(g as Int)
        && ((1u64 << (g + 1u32)) as Int) == 2 * pow2(g as Int));
    follows();
}
/// A power's trailing zeros (the library lemma by name).
#[lemma]
fn tz(t: u64, e: Int) {
    requires(0 <= e && e < 64 && (t as Int) == pow2(e));
    ensures((t.trailing_zeros() as Int) == e);
    sandblaster::lemmas::bits::tz_pow2_u64(t, e);
    follows();
}
/// Ordered values, ordered shifts.
#[lemma]
fn shr_mono(a: u64, b: u64, s: u32) {
    requires(s < 64u32 && a <= b);
    ensures((a >> s) <= (b >> s));
    follows();
}
/// The same for `<<`, when the larger one fits.
#[lemma]
fn shl_mono(a: u32, b: u32, s: u32) {
    requires(s < 32u32 && a <= b && (b as Int) * pow2(s as Int) < pow2(32));
    ensures((a << s) <= (b << s));
    follows();
}
/// Negative twin: equal values shift to equal values.
#[lemma]
fn shr_mono_strict(a: u64, b: u64, s: u32) {
    requires(s < 64u32 && a <= b);
    ensures((a >> s) < (b >> s));
    follows();
}
/// Negative twin: the larger one may overflow.
#[lemma]
fn shl_mono_nofit(a: u32, b: u32, s: u32) {
    requires(s < 32u32 && a <= b);
    ensures((a << s) <= (b << s));
    follows();
}
/// Negative twin: the product may not fit.
#[lemma]
fn shl_mul_nofit(x: u64, s: u32) {
    requires(s < 64u32);
    ensures((x << s) as Int == (x as Int) * pow2(s as Int));
    follows();
}
/// Negative twin: off by one.
#[lemma]
fn shl_one_off(s: u32) {
    requires(s < 64u32);
    ensures((1u64 << s) as Int == pow2(s as Int) + 1);
    follows();
}
/// Negative twin: a mask one bit short.
#[lemma]
fn mask_short(k: u32) {
    requires(k < 64u32);
    ensures((u64::MAX >> k) as Int == pow2(63 - (k as Int)) - 1);
    follows();
}
"#,
    );
    for name in ["shl_one", "wshl_one", "shl_mul", "wshl_mul8", "mask", "chunk", "tz", "shr_mono", "shl_mono"] {
        proven(&r, name);
    }
    for name in ["shl_mul_nofit", "shl_one_off", "mask_short", "shr_mono_strict", "shl_mono_nofit"] {
        refuted(&r, name);
    }
}
