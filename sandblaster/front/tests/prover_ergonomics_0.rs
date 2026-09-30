//! Prover ergonomics, package P1 (auto core): minimal repros of the §15 S5
//! QMDB proof-bloat defects in facts, rewriting, motives and repair, each
//! with a negative twin (the closer must still fail when the goal does not
//! follow).
//!
//! Every crate is a probe crate (`mod.rs` + `exec.rs` + `PROOF.rs`) run
//! through the stage pipeline; a test looks at the named lemmas only.

#[path = "spec15_util.rs"]
mod util;

use util::*;

const MOD: &str = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
const EXEC_STUB: &str = "//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub.\npub fn probe(x: u8) -> u8 { x }\n";

fn run_probe(exec: &str, proof: &str) -> Run {
    let proof = format!("//! Probe.\nuse sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", MOD), ("r/exec.rs", exec), ("r/PROOF.rs", &proof)])
}

/// The lemma `crate::proof::<name>` checked, with every obligation proven.
#[track_caller]
fn proven(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let bad: Vec<String> = r.unproven.iter().filter(|(d, _, _)| *d == full).map(|(_, k, g)| format!("[{k}] {g}")).collect();
    assert!(bad.is_empty(), "`{full}` has unproven obligations:\n{}\n{}", bad.join("\n"), r.rendered);
    assert!(r.checked_defs.iter().any(|d| *d == full), "`{full}` was not checked:\n{}", r.explain());
}

/// The lemma `crate::proof::<name>` is not proven (an obligation failed or
/// the definition did not check).
#[track_caller]
fn refuted(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    assert!(!r.checked_defs.iter().any(|d| *d == full), "`{full}` was proven, but its goal does not follow:\n{}", r.explain());
}

// ---------------------------------------------------------------------------
// A3: a proof read back from its value (`refl(Bool, c)` for `c == true`)
// ---------------------------------------------------------------------------

const S21_EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;
/// A stub boundary.
pub fn probe(x: u8) -> u8 { x }
/// A callee with a dependent conjunction as its requirement.
#[requires(start <= i && !(i - start < width))]
pub fn past(start: u64, i: u64, width: u64) -> u64 { i - start }
"#;

/// s21: the dependent conjunction `a && b[a]` (the `u64` subtraction of the
/// second conjunct needs the first) was proven by the basic prover with the
/// first conjunct's proof bound as a *value*; its read-back
/// `refl(Bool, start <= i)` stood where `start <= i == true` is needed and
/// the kernel rejected the proof.
#[test]
fn a3_dependent_conjunction_keeps_the_first_proof() {
    let r = run_probe(
        S21_EXEC,
        r#"
/// The callee's requirement from `Prop` facts.
#[lemma]
fn call_past(start: u64, i: u64, width: u64) {
    requires(start <= 500u64 && width <= 500u64);
    requires(!(i < start));
    requires(i >= start + width);
    ensures(crate::exec::past(start, i, width) == i - start);
    by_unfolding(crate::exec::past);
}

/// The conjunction itself as the goal.
#[lemma]
fn conj_goal(start: u64, i: u64, width: u64) {
    requires(start <= 500u64 && width <= 500u64);
    requires(!(i < start));
    requires(i >= start + width);
    ensures(start <= i && !(i - start < width));
    by_arithmetic();
}

/// Negative: the second conjunct does not follow.
#[lemma]
fn conj_goal_bad(start: u64, i: u64, width: u64) {
    requires(start <= 500u64 && width <= 500u64);
    requires(!(i < start));
    requires(i + 1u64 >= start + width);
    ensures(start <= i && !(i - start < width));
    by_arithmetic();
}
"#,
    );
    proven(&r, "call_past");
    proven(&r, "conj_goal");
    refuted(&r, "conj_goal_bad");
}

// ---------------------------------------------------------------------------
// B4: a `Prop` disequality `a != b` as a usable fact
// ---------------------------------------------------------------------------

const CNT_EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;
/// A stub boundary.
pub fn probe(x: u8) -> u8 { x }
/// Count down over a slice (tail recursive).
pub fn cnt(n: usize, xs: &[u8], acc: usize) -> usize {
    if n == 0 {
        return acc;
    }
    match xs.first() {
        None => acc,
        Some(_h) => cnt(n - 1, &xs[1..], acc.saturating_add(1)),
    }
}
"#;

/// `requires(h != g)` decides the unfolded `if h == g` (c_nat::b8_ne), and
/// `requires(n != 0)` gives `1 <= n` for the underflow check of `n - 1`
/// (a_kernel::a3_guard); both were unusable before (the fact is a `Prop`
/// negation, the rest of auto reads the boolean `eq(a, b) == false`).
#[test]
fn b4_prop_disequality_decides_branches_and_arithmetic() {
    let r = run_probe(
        CNT_EXEC,
        r#"
/// A branch on equality.
#[spec]
fn pick(h: Nat, g: Nat) -> Nat { if h == g { 0 } else { h } }

/// The `Prop` negation decides the unfolded test.
#[lemma]
fn b8_ne(h: Nat, g: Nat) {
    requires(h != g);
    ensures(pick(h, g) == h);
    by_unfolding(pick);
}

/// Negative: the other branch's value.
#[lemma]
fn b8_ne_bad(h: Nat, g: Nat) {
    requires(h != g);
    ensures(pick(h, g) == 0);
    by_unfolding(pick);
}

/// `n != 0` gives `1 <= n` (the subtraction's underflow check).
#[lemma]
fn a3_guard_sub(n: usize, m: usize) {
    requires(n != 0usize && m < 10usize);
    ensures(n - 1usize < n);
    by_arithmetic();
}

/// Negative: `n != 1` does not give `1 <= n`.
#[lemma]
fn a3_guard_sub_bad(n: usize) {
    requires(n != 1usize);
    ensures(n - 1usize < n);
    by_arithmetic();
}

/// A signed disequality: linarith splits it.
#[lemma]
fn ne_split(a: Int, b: Int) {
    requires(a != b && a <= b);
    ensures(a < b);
    by_arithmetic();
}

/// Negative: `a != b` alone does not order them.
#[lemma]
fn ne_split_bad(a: Int, b: Int) {
    requires(a != b);
    ensures(a < b);
    by_arithmetic();
}
"#,
    );
    proven(&r, "b8_ne");
    refuted(&r, "b8_ne_bad");
    proven(&r, "a3_guard_sub");
    refuted(&r, "a3_guard_sub_bad");
    proven(&r, "ne_split");
    refuted(&r, "ne_split_bad");
}

// ---------------------------------------------------------------------------
// B5: determination of a right-nested `&&` chain cascades
// ---------------------------------------------------------------------------

/// A fact `a && (b && (… && g))` gives every conjunct: each determined
/// conjunct rewrote the chain once per rule *and* once per fact, so the
/// facts doubled at every level and the search ran out at the fifth
/// (e_chain2::e1_right_int, e_chain::e1_right).
#[test]
fn b5_right_nested_chain_cascades() {
    let r = run_probe(
        EXEC_STUB,
        r#"
/// Seven checks over Int, right nested.
#[spec]
fn right7i(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int) -> bool {
    a < 10 && (b < 10 && (c < 10 && (d < 10 && (e < 10 && (f < 10 && g < 10)))))
}

/// Seven checks over Nat, right nested.
#[spec]
fn right7(a: Nat, b: Nat, c: Nat, d: Nat, e: Nat, f: Nat, g: Nat) -> bool {
    a < 10 && (b < 10 && (c < 10 && (d < 10 && (e < 10 && (f < 10 && g < 10)))))
}

/// The last conjunct, Int.
#[lemma]
fn e1_right_int(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int) {
    requires(right7i(a, b, c, d, e, f, g));
    ensures(g < 10);
    unfold(right7i);
    follows();
}

/// The last conjunct, Nat.
#[lemma]
fn e1_right(a: Nat, b: Nat, c: Nat, d: Nat, e: Nat, f: Nat, g: Nat) {
    requires(right7(a, b, c, d, e, f, g));
    ensures(g < 10);
    unfold(right7);
    follows();
}

/// Negative: a stronger bound does not follow.
#[lemma]
fn e1_right_bad(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int) {
    requires(right7i(a, b, c, d, e, f, g));
    ensures(g < 9);
    unfold(right7i);
    follows();
}
"#,
    );
    proven(&r, "e1_right_int");
    proven(&r, "e1_right");
    refuted(&r, "e1_right_bad");
}

// ---------------------------------------------------------------------------
// B3: congruence modulo arithmetic
// ---------------------------------------------------------------------------

/// A fact `r(y) == 4` proves `r(x - 1) == 4` when `y + 1 == x`
/// (b_norm::b14_congr_arith2): the arguments are equal by linear arithmetic.
#[test]
fn b3_fact_congruence_modulo_arithmetic() {
    let r = run_probe(
        EXEC_STUB,
        r#"
/// A recursive spec function.
#[spec]
#[decreases(n)]
fn r(n: Nat) -> Nat { if n == 0 { 0 } else { r(n - 1) + 2 } }

/// The argument equation needs arithmetic.
#[lemma]
fn b14_congr_arith2(x: Nat, y: Nat) {
    requires(y + 1 == x && r(y) == 4);
    ensures(r(x - 1) == 4);
    by_arithmetic();
}

/// The fact on the other side, the application on the right.
#[lemma]
fn b14_congr_flipped(x: Nat, y: Nat) {
    requires(y + 1 == x && 4 == r(y));
    ensures(4 == r(x - 1));
    by_arithmetic();
}

/// Negative: the arguments differ.
#[lemma]
fn b14_congr_bad(x: Nat, y: Nat) {
    requires(y + 2 == x && r(y) == 4);
    ensures(r(x - 1) == 4);
    by_arithmetic();
}
"#,
    );
    proven(&r, "b14_congr_arith2");
    proven(&r, "b14_congr_flipped");
    refuted(&r, "b14_congr_bad");
}

// ---------------------------------------------------------------------------
// B6: a proposition-valued `match` on an exec call, rewritten by the call's
// equation
// ---------------------------------------------------------------------------

const GET_EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;
/// A stub boundary.
pub fn probe(x: u8) -> u8 { x }
/// Drop `i` (truncating).
pub fn drop_(xs: &[u8], i: usize) -> &[u8] {
    match xs.split_at_checked(i) {
        Some((_a, b)) => b,
        None => &xs[xs.len()..],
    }
}
/// Get via drop.
pub fn get_(xs: &[u8], i: usize) -> Option<&u8> {
    drop_(xs, i).first()
}
"#;

/// The goal `match get_(xs, i) { Some(w) => *w == v, None => false }` (a
/// `Type`-valued dependent match, whose path equation is bound relevantly)
/// with the fact `get_(xs, i) == Some(&v)` (b1_norm::b1_fact_in_context):
/// the rewrite motive abstracted the path equation's `refl` like a value,
/// so every motive was ill-typed.
#[test]
fn b6_prop_match_rewritten_by_the_scrutinee_fact() {
    let r = run_probe(
        GET_EXEC,
        r#"
/// The folded form.
#[lemma]
fn get_some(xs: &[u8], i: usize, v: u8) {
    requires(crate::exec::drop_(xs, i).first() == Some(&v));
    ensures(crate::exec::get_(xs, i) == Some(&v));
    by_unfolding(crate::exec::get_);
}

/// The fact against a goal that matches on the call.
#[lemma]
fn b1_fact_in_context(xs: &[u8], i: usize, v: u8) {
    requires(crate::exec::drop_(xs, i).first() == Some(&v));
    ensures(match crate::exec::get_(xs, i) { Some(w) => *w == v, None => false });
    get_some(xs, i, v);
    follows();
}

/// Negative: the arm's claim is false.
#[lemma]
fn b1_fact_in_context_bad(xs: &[u8], i: usize, v: u8) {
    requires(crate::exec::drop_(xs, i).first() == Some(&v));
    ensures(match crate::exec::get_(xs, i) { Some(w) => *w != v, None => false });
    get_some(xs, i, v);
    follows();
}
"#,
    );
    proven(&r, "get_some");
    proven(&r, "b1_fact_in_context");
    refuted(&r, "b1_fact_in_context_bad");
}

// ---------------------------------------------------------------------------
// A8: finite enumeration over a one-value range
// ---------------------------------------------------------------------------

/// A fact that fixes `x` to one value sends the enumeration straight to its
/// leaf, which pushed the value's equation as a `let` of a frame nobody
/// closed: the proof referred to an unbound variable ("IllFormed: unbound
/// variable index", logged s1 in `count_ones_is_popcount`).
#[test]
fn a8_one_value_enumeration_is_closed() {
    let r = run_probe(
        EXEC_STUB,
        r#"
/// A boolean fact fixes `x` to 0.
#[lemma]
fn enum_one(x: u64) {
    requires((x == 0u64) == true);
    ensures(x.count_ones() as Int == popcount(x as Int));
    follows();
}

/// With a branch.
#[lemma]
fn enum_branch(x: u64) {
    ensures(x != 0u64 || x.count_ones() as Int == popcount(x as Int));
    if x == 0u64 { follows(); } else { follows(); }
}

/// Negative: a false claim about the single value.
#[lemma]
fn enum_one_bad(x: u64) {
    requires((x == 0u64) == true);
    ensures(x.count_ones() as Int == popcount(x as Int) + 1);
    follows();
}
"#,
    );
    proven(&r, "enum_one");
    proven(&r, "enum_branch");
    refuted(&r, "enum_one_bad");
}

// ---------------------------------------------------------------------------
// B10: one view link between an exec record and a spec record
// ---------------------------------------------------------------------------

const REC_EXEC: &str = r#"//! Exec part.
use sandblaster::prelude::*;
/// A stub boundary.
pub fn probe(x: u8) -> u8 { x }
/// An exec record.
#[derive(Clone, Copy)]
pub struct E<'a> { pub leaves: u64, pub inactive: u64, pub digests: &'a [u8] }
/// A verdict on the exec record.
pub fn ok(e: &E) -> bool { e.inactive <= e.leaves && e.digests.len() as u64 == e.leaves }
"#;

/// `requires(view(e) == s)` (the record's view is a constructor) gives
/// every field: the proof needs no field-by-field links (the QMDB 86b/86c
/// `@LINKS@` template).
#[test]
fn b10_one_view_link_gives_the_fields() {
    let r = run_probe(
        REC_EXEC,
        r#"
/// The spec record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct S { pub leaves: Nat, pub inactive: Nat, pub digests: Seq<u8> }

/// The spec verdict.
#[spec]
fn sok(s: S) -> bool { s.inactive <= s.leaves && s.digests.len() == s.leaves }

/// The view.
#[spec]
fn view(e: crate::exec::E) -> S { S { leaves: e.leaves as Nat, inactive: e.inactive as Nat, digests: e.digests } }

/// One link: facts about the exec fields are facts about the spec fields.
#[lemma]
fn ok_is(e: crate::exec::E, s: S) {
    requires(view(e) == s);
    requires(e.inactive <= e.leaves);
    ensures(s.inactive <= s.leaves);
    follows();
}

/// A field from the link.
#[lemma]
fn field(e: crate::exec::E, s: S) {
    requires(s == view(e));
    ensures(s.leaves == e.leaves as Nat);
    follows();
}

/// Negative: a field the link does not give.
#[lemma]
fn field_bad(e: crate::exec::E, s: S) {
    requires(s == view(e));
    ensures(s.leaves == e.inactive as Nat);
    follows();
}
"#,
    );
    proven(&r, "ok_is");
    proven(&r, "field");
    refuted(&r, "field_bad");
}

// ---------------------------------------------------------------------------
// B11: a `∨` fact with one side refuted
// ---------------------------------------------------------------------------

const TREE_SPEC: &str = r#"//! Spec.
use sandblaster::prelude::*;
/// A tree.
#[derive(Clone, Copy)]
pub enum T { Leaf(u8), Node(T, T) }
/// An opaque judgement.
#[opaque]
pub fn bad(x: Seq<u8>) -> bool { x.len() == 3 }
/// Walk two trees.
pub fn clash(a: T, b: T) -> Seq<u8> {
    match (a, b) {
        (T::Leaf(x), T::Leaf(y)) => seq![x, y],
        (T::Node(a1, _a2), T::Node(b1, _b2)) => clash(a1, b1),
        _ => seq![],
    }
}
/// Agree.
pub fn agree(a: T, b: T) -> bool {
    match (a, b) {
        (T::Leaf(x), T::Leaf(y)) => x == y,
        (T::Node(a1, a2), T::Node(b1, b2)) => agree(a1, b1) && agree(a2, b2),
        _ => false,
    }
}
"#;

/// `agree(a, b) || bad(clash(a, b))` and `!bad(clash(a, b))` give
/// `agree(a, b)` (the QMDB tree law `equal_roots_agree`: the induction
/// hypothesis `agree ∨ collision(clash(..))` with `!collision(clash(..))`).
/// The disjunction waited for a case split, the search's last step, and the
/// budget ran out on the recursive `agree` first.
#[test]
fn b11_disjunction_with_a_refuted_side() {
    let proof = r#"//! Probe.
use sandblaster::prelude::*;
use super::spec::{T, agree, bad, clash};

/// The disjunction and the negation of its right side.
#[lemma]
fn b11_either(a: T, b: T) {
    requires(agree(a, b) || bad(clash(a, b)));
    requires(!bad(clash(a, b)));
    ensures(agree(a, b));
    follows();
}

/// On constructors (the calls unfold on both facts alike).
#[lemma]
fn b11_either_nodes(a1: T, a2: T, b1: T, b2: T) {
    requires(agree(T::Node(a1, a2), T::Node(b1, b2)) || bad(clash(T::Node(a1, a2), T::Node(b1, b2))));
    requires(!bad(clash(a1, b1)));
    ensures(agree(a1, b1) && agree(a2, b2));
    follows();
}

/// Negative: the refuted call has other arguments.
#[lemma]
fn b11_either_bad(a: T, b: T) {
    requires(agree(a, b) || bad(clash(a, b)));
    requires(!bad(clash(b, a)));
    ensures(agree(a, b));
    follows();
}
"#;
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[spec]\nmod spec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let r = run_files(&[("r/mod.rs", root), ("r/exec.rs", EXEC_STUB), ("r/spec.rs", TREE_SPEC), ("r/PROOF.rs", proof)]);
    proven(&r, "b11_either");
    proven(&r, "b11_either_nodes");
    refuted(&r, "b11_either_bad");
}
