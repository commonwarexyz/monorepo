//! Prover ergonomics, round 4 (Track B of the proof plan, Phase 2): the
//! prover defects found by the proof-form prototypes (D1–D3) and the
//! automation the plan adds (A2 one-step unfold lemmas, A3 the simplifier's
//! cast normal form, A5 `Nat` guards on compound arguments, A6 a `match` on
//! a recursive call), and the dependency order of a self-recursive
//! function's own refinement proof. Each test is a minimal repro; every
//! strengthened step has a negative twin (a false or non-following goal)
//! that must still fail, without a kernel rejection.

#[path = "spec15_util.rs"]
mod util;

use util::*;

/// A probe crate: `exec.rs` (exec code) and `PROOF.rs` (ghost items).
fn probe(proof: &str, exec: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let exec = format!("//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub boundary.\npub fn probe(x: u8) -> u8 {{ x }}\n{exec}");
    let proof = format!("//! Ghost part.\nuse sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", &exec), ("r/PROOF.rs", &proof)])
}

/// The unproven or unchecked items of `PROOF.rs` (by short name).
fn failed(r: &Run) -> Vec<String> {
    let mut v: Vec<String> = r.unproven.iter().map(|(d, _, _)| d.clone()).chain(r.failed_defs.iter().map(|(d, _)| d.clone())).collect();
    v.sort();
    v.dedup();
    v.into_iter().filter_map(|d| d.strip_prefix("crate::proof::").map(str::to_string)).collect()
}

/// Asserts that exactly the items `bad` of `PROOF.rs` fail (the negative
/// twins), that every other item checks, and that nothing was rejected by
/// the kernel.
#[track_caller]
fn only_twins_fail(proof: &str, exec: &str, bad: &[&str]) -> Run {
    let r = probe(proof, exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    let mut want: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(failed(&r), want, "unexpected set of failing items:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "a kernel rejection:\n{}", r.explain());
    r
}

#[test]
fn lemma_arguments_that_bind_facts_keep_their_scope() {
    // D2 (refsrc's 3 open `path_is` obligations): an exec call with an
    // `ensures` in a lemma's argument (`pos(0, i)`) binds its fact around the
    // rest; the lemma's conclusion was pushed one binder off (`i` read as
    // `s`, the array `op` as `i`: "`fst` of a non-pair" in the kernel)
    only_twins_fail(
        r#"
/// The spec leaf.
#[spec]
fn leaf(i: Nat, op: Seq<u8>) -> Int { if op.len() > 0 { i + op[0] as Int } else { 0 } }
/// The code's leaf is the spec's.
#[lemma]
fn leaf_root(position: u64, i: Nat, op: [u8; 4]) {
    requires(position as Nat == i && i < 1000);
    ensures(crate::exec::leaf_digest(position, &op) as Int == leaf(i, seq![..op]));
    by_unfolding(crate::exec::leaf_digest, leaf);
}
/// The lemma at an exec call's result (whose `ensures` is a fact of the argument).
#[lemma]
fn user(s: u64, i: u64, op: [u8; 4], inat: Nat) {
    requires(i < 1000 && s < 1000 && i as Nat == inat);
    ensures(crate::exec::leaf_digest(crate::exec::pos(0u32, i), &op) as Int == leaf(inat, seq![..op]));
    leaf_root(crate::exec::pos(0u32, i), inat, op);
}
/// Negative twin: a different leaf.
#[lemma]
fn user_bad(s: u64, i: u64, op: [u8; 4], inat: Nat) {
    requires(i < 1000 && s < 1000 && i as Nat == inat);
    ensures(crate::exec::leaf_digest(crate::exec::pos(0u32, s), &op) as Int == leaf(inat, seq![..op]));
    leaf_root(crate::exec::pos(0u32, i), inat, op);
}
"#,
        r#"
/// A position.
#[requires(h <= 3 && s < 1000)]
#[ensures(|ret| ret as Int == s as Int + h as Int)]
pub fn pos(h: u32, s: u64) -> u64 { s + h as u64 }
/// A leaf digest.
#[requires(p < 2000)]
pub fn leaf_digest(p: u64, op: &[u8; 4]) -> u64 { p + op[0] as u64 }
"#,
        &["user_bad"],
    );
}

#[test]
fn lemma_arguments_that_bind_facts_keep_their_scope_scalars() {
    // the same without arrays: before, `user`'s conclusion talked about `s`
    only_twins_fail(
        r#"
/// A fact about a position and a leaf.
#[lemma]
fn at_leaf(position: u64, i: Nat) {
    requires(position as Nat == i);
    ensures(position as Int + 1 == i + 1);
    by_arithmetic();
}
/// The lemma's argument is an exec call with an `ensures`: its conclusion is about `i` and `inat`.
#[lemma]
fn user(s: u64, i: u64, inat: Nat) {
    requires(i < 1000 && s < 1000 && i as Nat == inat);
    ensures(crate::exec::pos(0u32, i) as Int + 1 == inat + 1);
    at_leaf(crate::exec::pos(0u32, i), inat);
    by_arithmetic();
}
/// Negative twin: the same step does not say anything about `s`.
#[lemma]
fn user_bad(s: u64, i: u64, inat: Nat) {
    requires(i < 1000 && s < 1000 && i as Nat == inat);
    ensures(crate::exec::pos(0u32, s) as Int + 1 == inat + 1);
    at_leaf(crate::exec::pos(0u32, i), inat);
    by_arithmetic();
}
"#,
        r#"
/// A position.
#[requires(h <= 3 && s < 1000)]
#[ensures(|ret| ret as Int == s as Int + h as Int)]
pub fn pos(h: u32, s: u64) -> u64 {
    s + h as u64
}
"#,
        &["user_bad"],
    );
}

#[test]
fn fact_proofs_are_not_evaluated() {
    // D1: a proof-mode fact is a variable for evaluation; before, its value
    // (the lemma's body unfolded, with stuck transports that store no
    // equation) was read back into the next state's proof slots (`fuel - 1`)
    // as `Erased`, and the callee's `requires` failed ("`Erased` placeholder")
    only_twins_fail(
        r#"
/// An alignment test.
#[spec]
fn al(s: Int, e: Int) -> bool { s >= 0 && e >= 0 }
/// Alignment weakens.
#[lemma]
fn al_weaken(s: Int, e: Int) {
    requires(al(s, e) && e >= 1);
    ensures(al(s, e - 1));
    follows();
}
/// A scan state (the widths from 2^e up are done).
#[spec]
fn sc(n: Int, e: Int, w: Int, s: Int, r: Int, b: Int) -> Prop {
    e >= 0 && 0 <= s && 0 <= r && w == pow2(e) / 2 && al(s, e) && s + r == n && r < pow2(e) && b == popcount(s)
}
/// A width not left: the next width, nothing else changes (proven by cases).
#[lemma]
fn sc_skip(n: Int, e: Int, w: Int, s: Int, r: Int, b: Int) {
    requires(sc(n, e, w, s, r, b) && e >= 1 && r < w);
    ensures(sc(n, e - 1, w / 2, s, r, b));
    sandblaster::lemmas::nat::pow2_step(e - 1, e);
    sandblaster::lemmas::nat::pow2_pos(e - 1);
    al_weaken(s, e);
    if e - 1 >= 1 { sandblaster::lemmas::nat::pow2_step(e - 2, e - 1); follows(); } else { follows(); }
}
/// What the loop found so far.
#[spec]
fn found_ok(found: Option<u64>, i: u64, start: u64) -> Prop {
    match found { None => start <= i, Some(v) => i < start && v <= i }
}
/// The loop's invariant, as its recursive lemma states it.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn inv(fuel: u32, i: u64, remaining: u64, width: u64, start: u64, before: u32, found: Option<u64>, n: u64) {
    requires(fuel <= 63 && (before as Int) + (fuel as Int) <= 63 && (n as Int) <= 4611686018427387904);
    requires(sc(n as Int, fuel as Int, width as Int, start as Int, remaining as Int, before as Int));
    requires(found_ok(found, i, start));
    ensures(true);
    follows();
}
/// D1: the skip step at the code's own next state (`fuel - 1`, `width / 2`).
#[lemma]
#[allow(clippy::too_many_arguments)]
fn skip(fuel: u32, i: u64, remaining: u64, width: u64, start: u64, before: u32, found: Option<u64>, n: u64) {
    requires(fuel <= 63 && (before as Int) + (fuel as Int) <= 63 && (n as Int) <= 4611686018427387904);
    requires(sc(n as Int, fuel as Int, width as Int, start as Int, remaining as Int, before as Int));
    requires(found_ok(found, i, start));
    requires(fuel != 0u32 && remaining < width);
    ensures(true);
    sc_skip(n as Int, fuel as Int, width as Int, start as Int, remaining as Int, before as Int);
    inv(fuel - 1, i, remaining, width / 2, start, before, found, n);
    follows();
}
/// Negative twin: the step does not give a width of a quarter.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn skip_bad(fuel: u32, i: u64, remaining: u64, width: u64, start: u64, before: u32, found: Option<u64>, n: u64) {
    requires(fuel <= 63 && (before as Int) + (fuel as Int) <= 63 && (n as Int) <= 4611686018427387904);
    requires(sc(n as Int, fuel as Int, width as Int, start as Int, remaining as Int, before as Int));
    requires(found_ok(found, i, start));
    requires(fuel != 0u32 && remaining < width && width >= 8);
    ensures(true);
    sc_skip(n as Int, fuel as Int, width as Int, start as Int, remaining as Int, before as Int);
    inv(fuel - 1, i, remaining, width / 4, start, before, found, n);
    follows();
}
"#,
        r#"
"#,
        &["skip_bad"],
    );
}

#[test]
fn generated_one_step_unfolding() {
    // A2: `f::step(args)` is `f(args) == body[args]` by `delta` (the kernel
    // checks it); with the branch's facts the simplifier picks the arm —
    // one lemma per function instead of a lemma per branch
    only_twins_fail(
        r#"
/// Triangular numbers.
#[spec]
#[decreases(n)]
fn tri(n: Nat) -> Nat {
    if n == 0 { 0 } else { n + tri(n - 1) }
}
/// A branch: left or right half.
#[spec]
#[decreases(h)]
fn walk(h: Nat, w: Nat, x: Nat) -> Nat {
    if h == 0 { x } else if x < w / 2 { 2 * walk(h - 1, w / 2, x) } else { 1 + walk(h - 1, w / 2, x - w / 2) }
}
/// An opaque helper.
#[spec]
#[opaque]
fn twice(x: Int) -> Int { 2 * x }
/// One step of `tri`.
#[lemma]
fn tri_one(n: Nat) {
    requires(n >= 1);
    ensures(tri(n) == n + tri(n - 1));
    tri::step(n);
    follows();
}
/// The left branch of `walk`, from its one step.
#[lemma]
fn walk_left(h: Nat, w: Nat, x: Nat) {
    requires(h >= 1 && x < w / 2);
    ensures(walk(h, w, x) == 2 * walk(h - 1, w / 2, x));
    walk::step(h, w, x);
    follows();
}
/// The right branch.
#[lemma]
fn walk_right(h: Nat, w: Nat, x: Nat) {
    requires(h >= 1 && x >= w / 2);
    ensures(walk(h, w, x) == 1 + walk(h - 1, w / 2, x - w / 2));
    walk::step(h, w, x);
    follows();
}
/// The opaque helper's step.
#[lemma]
fn twice_is(x: Int) {
    ensures(twice(x) == x + x);
    twice::step(x);
    by_arithmetic();
}
/// Negative twin: the step does not say this.
#[lemma]
fn tri_bad(n: Nat) {
    requires(n >= 2);
    ensures(tri(n) == n + tri(n - 2));
    tri::step(n);
    follows();
}
/// Negative twin: the wrong branch.
#[lemma]
fn walk_bad(h: Nat, w: Nat, x: Nat) {
    requires(h >= 1 && x >= w / 2 && w >= 2);
    ensures(walk(h, w, x) == 2 * walk(h - 1, w / 2, x));
    walk::step(h, w, x);
    follows();
}
/// Negative twin: without the step, the opaque helper stays unknown.
#[lemma]
fn twice_bad(x: Int) {
    ensures(twice(x) == x + x);
    by_arithmetic();
}
"#,
        r#"
"#,
        &["tri_bad", "walk_bad", "twice_bad"],
    );
}

#[test]
fn casts_have_one_normal_form() {
    // D3/A3: `(x / 2) as Nat` and `(x as Nat) / 2` are one term for the
    // simplifier (a cast pushed into a checked operation, by a `linarith`
    // equation), so a lemma about the `Int` form rewrites the code's form
    only_twins_fail(
        r#"
/// An opaque predicate.
#[spec]
#[opaque]
fn good(x: Int) -> bool { x >= 0 }
/// An opaque function.
#[spec]
#[opaque]
fn f(x: Int, y: Int) -> Int { x + y }
/// D3: the cast of a halving is the halving of the cast.
#[lemma]
fn d3a(n: u64) {
    requires(good((n as Int) / 2));
    ensures(good((n / 2) as Int));
    follows();
}
/// D3: a difference and a sum under casts.
#[lemma]
fn d3b(n: u64, m: u32, z: Int) {
    requires(m >= 1 && n < 1000 && z == f((m as Int) - 1, (n as Int) + (n as Int)));
    ensures(z == f((m - 1) as Int, (n + n) as Int));
    follows();
}
/// D3 negative twin: an off-by-one halving.
#[lemma]
fn d3a_bad(n: u64) {
    requires(good((n as Int) / 2));
    ensures(good((n / 2 + 1) as Int));
    follows();
}
/// D3 negative twin: a different argument.
#[lemma]
fn d3b_bad(n: u64, m: u32, z: Int) {
    requires(m >= 1 && n < 1000 && z == f((m as Int) - 1, (n as Int) + (n as Int)));
    ensures(z == f((m - 1) as Int, (n + 1) as Int));
    follows();
}
/// A recursive function of a halving.
#[spec]
#[decreases(n)]
fn lg(n: Nat) -> Nat { if n <= 1 { 0 } else { 1 + lg(n / 2) } }
/// The recursion's one step, as a lemma about `Int` halving.
#[lemma]
fn lg_step(n: Nat) {
    requires(n >= 2);
    ensures(lg(n) == 1 + lg(n / 2));
    lg::step(n);
    follows();
}
/// D3 through rewriting: the goal names `(x / 2) as Nat`.
#[lemma]
fn d3c(x: u64) {
    requires(x >= 2);
    ensures(lg(x as Nat) == 1 + lg((x / 2) as Nat));
    lg_step(x as Nat);
    by_arithmetic();
}
/// D3 negative twin through rewriting.
#[lemma]
fn d3c_bad(x: u64) {
    requires(x >= 2);
    ensures(lg(x as Nat) == 1 + lg((x / 4) as Nat));
    lg_step(x as Nat);
    by_arithmetic();
}
/// D3 in a narrow closer.
#[lemma]
fn d3d(n: u64) {
    requires(good((n as Int) / 2));
    ensures(good((n / 2) as Int));
    by_arithmetic();
}
"#,
        r#"
"#,
        &["d3a_bad", "d3b_bad", "d3c_bad"],
    );
}

#[test]
fn nat_guards_on_compound_arguments() {
    // A5: the `0 <= a + 1` guard of a `Nat` field of a struct literal, in a
    // fact unfolded by `by_unfolding`, is decided (before: the fact stayed
    // behind the guard)
    only_twins_fail(
        r#"
/// Half of a Nat.
#[spec]
#[opaque]
fn half(n: Nat) -> Nat { n / 2 }
/// Nested guards.
#[spec]
fn quarter(a: Nat, b: Nat) -> Nat { half(half(a + b) + a) }
/// A pair of sizes.
#[derive(PartialEq, Eq, Clone, Copy)]
struct Sz { n: Nat, k: Nat }
/// Sizes of the next level.
#[spec]
fn next(s: Sz) -> Sz { Sz { n: s.n / 2, k: s.k - s.k / 2 } }
/// A predicate over sizes.
#[spec]
fn fits(s: Sz, m: Nat) -> bool { s.n + s.k <= m }
/// v1: by_unfolding with a compound argument.
#[lemma]
fn v1(a: Nat, b: Nat) {
    ensures(half(a + b) == (a + b) / 2);
    by_unfolding(half);
}
/// v2: nested guards, by_unfolding.
#[lemma]
fn v2(a: Nat, b: Nat) {
    ensures(quarter(a, b) == ((a + b) / 2 + a) / 2);
    by_unfolding(quarter, half);
}
/// v3: a fact with a compound argument decides the goal.
#[lemma]
fn v3(a: Nat, b: Nat, m: Nat) {
    requires(fits(next(Sz { n: a, k: b }), m));
    ensures(a / 2 + (b - b / 2) <= m);
    follows();
}
/// v4: struct literal with compound Nat fields, by_unfolding.
#[lemma]
fn v4(a: Nat, b: Nat, m: Nat) {
    requires(fits(next(Sz { n: a + 1, k: b }), m));
    ensures((a + 1) / 2 + (b - b / 2) <= m);
    by_unfolding(fits, next);
}
/// v5: negative twin of v4 (off by one).
#[lemma]
fn v5(a: Nat, b: Nat, m: Nat) {
    requires(fits(next(Sz { n: a + 1, k: b }), m));
    ensures((a + 1) / 2 + (b - b / 2) + 1 <= m);
    by_unfolding(fits, next);
}
/// v6: the guard in the goal.
#[lemma]
fn v6(a: Nat, b: Nat, m: Nat) {
    requires((a + 1) / 2 + (b - b / 2) <= m);
    ensures(fits(next(Sz { n: a + 1, k: b }), m));
    by_unfolding(fits, next);
}
/// v7: negative twin of v6.
#[lemma]
fn v7(a: Nat, b: Nat, m: Nat) {
    requires((a + 1) / 2 + (b - b / 2) <= m + 1);
    ensures(fits(next(Sz { n: a + 1, k: b }), m));
    by_unfolding(fits, next);
}
"#,
        r#"
"#,
        &["v5", "v7"],
    );
}

#[test]
fn match_on_a_recursive_call() {
    // A6: a goal `match cnt(n) { .. }` against the induction hypothesis
    // `match cnt(n - 1) { .. }`: one unfolding, then a split on the shared
    // recursive call (before: the search unfolded deeper and ran out of
    // nodes)
    only_twins_fail(
        r#"
/// Half of a Nat.
#[spec]
fn half(n: Nat) -> Nat { n / 2 }
/// Half of a sum (a Nat guard on a compound argument).
#[spec]
fn half_sum(a: Nat, b: Nat) -> Nat { half(a + b) }
/// Half of a difference.
#[spec]
fn half_diff(a: Nat, b: Nat) -> Nat { if a >= b { half(a - b) } else { 0 } }
/// A count that may be absent.
#[spec]
#[decreases(n)]
fn cnt(n: Nat) -> Option<Nat> {
    if n == 0 { Some(0) } else {
        match cnt(n - 1) { Some(k) => Some(k + 1), None => None }
    }
}
/// A5: the guard `0 <= a + b` of `half` is decided.
#[lemma]
fn a5_sum(a: Nat, b: Nat) {
    ensures(half_sum(a, b) == (a + b) / 2);
    follows();
}
/// A5: the guard `0 <= a - b` under `a >= b`.
#[lemma]
fn a5_diff(a: Nat, b: Nat) {
    requires(a >= b);
    ensures(half_diff(a, b) == (a - b) / 2);
    follows();
}
/// A5 negative twin: without `a >= b` the value is not the half.
#[lemma]
fn a5_diff_bad(a: Nat, b: Nat) {
    ensures(half_diff(a, b) == (a - b) / 2);
    follows();
}
/// A6: a goal that is a match on a recursive call.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn a6_cnt(n: Nat) {
    ensures(match cnt(n) { Some(k) => k == n, None => false });
    if n == 0 {
        follows();
    } else {
        ih(n - 1);
        follows();
    }
}
/// A6 negative twin: the count is not `n + 1`.
#[lemma]
#[induction(n)]
#[decreases(n)]
fn a6_cnt_bad(n: Nat) {
    ensures(match cnt(n) { Some(k) => k == n + 1, None => false });
    if n == 0 {
        follows();
    } else {
        ih(n - 1);
        follows();
    }
}
"#,
        r#"
"#,
        &["a5_diff_bad", "a6_cnt_bad"],
    );
}

#[test]
fn step_needs_a_function_with_a_value() {
    // a predicate unfolds with `unfold(f)`; `f::step` says so
    let r = probe("/// A predicate.\n#[spec]\nfn big(x: Int) -> Prop { x > 10 }\n/// .\n#[lemma]\nfn p(x: Int) {\n    requires(x > 11);\n    ensures(big(x));\n    big::step(x);\n    follows();\n}\n", "");
    assert!(r.rendered.contains("`f::step(args)` needs a function with a value"), "{}", r.rendered);
}

#[test]
fn a_recursive_function_is_ordered_before_its_own_refinement_proof() {
    // refsrc's `elab/order.rs` fix: the recursive call of `is_even` no
    // longer makes its `#[proof(refines = ..)]` item a dependency of
    // `is_even` itself (before: "has not been elaborated (dependency order)")
    only_twins_fail(
        r#"
/// Parity.
#[spec]
#[decreases(n)]
pub(crate) fn even(n: Nat) -> bool { if n == 0 { true } else { !even(n - 1) } }
/// The code's recursion is the spec's, by its own proof item (the
/// recursive call is the induction hypothesis).
#[proof(refines = crate::exec::is_even)]
#[decreases(n)]
fn is_even(n: u64) {
    unfold(crate::exec::is_even);
    if n == 0u64 {
        follows();
    } else {
        is_even(n - 1);
        follows();
    }
}
"#,
        r#"
/// Parity by recursion.
#[refines(crate::proof::even)]
#[decreases(n, max = 100)]
#[requires(n <= 100)]
pub fn is_even(n: u64) -> bool { if n == 0 { true } else { !is_even(n - 1) } }
"#,
        &[],
    );
}

#[test]
fn a_recursive_function_is_ordered_before_its_own_refinement_proof_negative() {
    // a wrong recursion (`!` dropped) does not refine `even`
    let r = probe(
        r#"
/// Parity.
#[spec]
#[decreases(n)]
pub(crate) fn even(n: Nat) -> bool { if n == 0 { true } else { !even(n - 1) } }
/// The code's recursion is the spec's, by its own proof item (the
/// recursive call is the induction hypothesis).
#[proof(refines = crate::exec::is_even)]
#[decreases(n)]
fn is_even(n: u64) {
    unfold(crate::exec::is_even);
    if n == 0u64 {
        follows();
    } else {
        is_even(n - 1);
        follows();
    }
}
"#,
        r#"
/// Parity by recursion.
#[refines(crate::proof::even)]
#[decreases(n, max = 100)]
#[requires(n <= 100)]
pub fn is_even(n: u64) -> bool { if n == 0 { true } else { is_even(n - 1) } }
"#,
    );
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.refs.iter().any(|x| x.item == "crate::exec::is_even" && !x.checked) || !r.failed_defs.is_empty(), "the wrong recursion was proven:\n{}", r.explain());
    assert!(!r.rendered.contains("dependency order") && !r.rendered.contains("rejected by the kernel"), "{}", r.explain());
}
