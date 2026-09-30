//! Post-loop facts (DESIGN.md §7.4, SEMANTICS.md §12.1): the helper of a
//! loop has the lemma `f::loop#k::ensures`, proven by walking the helper
//! body (`invariant-exit` at the exits, the induction hypothesis at the
//! recursive calls), and the call site binds it as an irrelevant fact: the
//! invariants hold after the loop at the exit index (`i := b` for `a..b`;
//! `i := b + 1` for `a..=b`, exactly over `i as Int`, else when `b < MAX`;
//! and `c == false` for `while`). Nothing is asserted about the bounds: a
//! loop that may run zero times with `a > b` gives `a <= b ==> …`.
//!
//! A post-loop fact never comes for free: it is a kernel-checked lemma
//! applied to the entry proofs, so an unproven invariant (entry,
//! preservation or exit) fails the build.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use sandblaster_front::opt::OptOptions;
use util::{assert_verified, explain, kinds_of, status_of, unproven, verify_src};

/// Verifies `src` and asserts it verified.
#[track_caller]
fn accepts(src: &str) -> sandblaster_front::driver::Verification {
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    v
}

/// [`accepts`] with the build's prover chain (basic, then auto): for claims
/// that use an implication fact (`a <= b ==> …`, `b < MAX ==> …`), which
/// only auto instantiates (SEMANTICS.md §18).
#[track_caller]
fn accepts_std(src: &str) -> sandblaster_front::driver::Verification {
    let (c, v) = verify_src(src, ProverSet::Standard);
    assert_verified(&c, &v);
    v
}

/// Asserts `def` has an unproven obligation of `kind` and is not checked
/// (the program is not verified).
#[track_caller]
fn rejects(src: &str, def: &str, kind: &str) -> sandblaster_front::driver::Verification {
    let (c, v) = verify_src(src, ProverSet::Basic);
    let bad = unproven(&v);
    assert!(bad.iter().any(|(d, k)| d == def && k == kind), "expected an unproven `{kind}` obligation in `{def}`; got:\n{}", explain(&c, &v));
    assert_ne!(status_of(&v, def), &DefStatus::Checked, "{def} must not be checked");
    v
}

fn count(ks: &[String], k: &str) -> usize {
    ks.iter().filter(|x| *x == k).count()
}

// ---------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------

#[test]
fn invariant_after_a_for_loop() {
    let v = accepts(
        r#"
pub fn count(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c == i); }
        c += 1;
    }
    proof! { assert(c == n); }
    c
}
"#,
    );
    assert_eq!(status_of(&v, "crate::count::loop#0::ensures"), &DefStatus::Checked);
    let ks = kinds_of(&v, "crate::count::loop#0::ensures");
    assert!(count(&ks, "invariant-exit") >= 1, "the exit is proven in the lemma: {ks:?}");
    // the empty range at the call site (`0 = n`)
    assert!(count(&kinds_of(&v, "crate::count"), "invariant-exit") >= 1);
}

#[test]
fn invariant_after_a_loop_from_a_variable_lower_bound() {
    // `k..n` runs zero times when `k > n`: the fact is `k <= n ==> …`
    accepts_std(
        r#"
#[requires(k <= n)]
fn span(k: u32, n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in k..n {
        proof! { invariant((c as Int) == (i as Int) - (k as Int)); }
        c += 1;
    }
    proof! { assert((c as Int) == (n as Int) - (k as Int)); }
    c
}
pub fn use_span(n: u32) -> u32 { if n >= 3 { span(3, n) } else { 0 } }
"#,
    );
}

#[test]
fn post_loop_fact_feeds_ensures() {
    accepts(
        r#"
#[ensures(|r: u64| (r as Int) == 2 * (n as Int))]
pub fn double(n: u32) -> u64 {
    let mut acc: u64 = 0;
    for i in 0..n {
        proof! { invariant((acc as Int) == 2 * (i as Int)); }
        acc += 2;
    }
    acc
}
"#,
    );
}

#[test]
fn invariant_after_inclusive_range_at_max() {
    // `250..=u8::MAX` does not overflow; an invariant that does not mention
    // the loop variable holds after the loop
    accepts(
        r#"
pub fn capped() -> u8 {
    let mut m: u8 = 0;
    for _j in 250u8..=u8::MAX {
        proof! { invariant(m <= 100); }
        if m < 100 { m += 1; }
    }
    proof! { assert(m <= 100); }
    m
}
"#,
    );
}

#[test]
fn exact_invariant_after_inclusive_range_at_max() {
    // an invariant over `j as Int` is stated exactly at `b + 1` (here 256,
    // one past `u8::MAX`)
    let v = accepts(
        r#"
pub fn count_to_max() -> u32 {
    let mut c: u32 = 0;
    for j in 250u8..=u8::MAX {
        proof! { invariant((c as Int) == (j as Int) - 250); }
        c += 1;
    }
    proof! { assert(c == 6); }
    c
}
"#,
    );
    assert_eq!(status_of(&v, "crate::count_to_max::loop#0::ensures"), &DefStatus::Checked);
}

#[test]
fn invariant_after_inclusive_range_below_max() {
    // over the loop variable as a machine integer, the invariants hold at
    // `b + 1` when `b < MAX`
    accepts_std(
        r#"
pub fn count_incl(n: u8) -> u32 {
    let mut c: u32 = 0;
    for j in 0u8..=n {
        proof! { invariant(c == j as u32); }
        c += 1;
    }
    proof! { assert(implies(n < 255, c == (n as u32) + 1)); }
    c
}
"#,
    );
}

#[test]
fn condition_and_invariant_after_a_while_loop() {
    let v = accepts(
        r#"
pub fn countdown(n: u32) -> u32 {
    let mut i = n;
    let mut steps: u32 = 0;
    while i > 0 {
        proof! {
            decreases(i);
            invariant((steps as Int) + (i as Int) == (n as Int));
        }
        i -= 1;
        steps += 1;
    }
    proof! { assert(i == 0); assert(steps == n); }
    steps
}
"#,
    );
    assert_eq!(status_of(&v, "crate::countdown::loop#0::ensures"), &DefStatus::Checked);
}

#[test]
fn condition_after_a_while_loop_without_invariants() {
    accepts(
        r#"
pub fn drain(n: u32) -> u32 {
    let mut i = n;
    while i > 0 {
        proof! { decreases(i); }
        i -= 1;
    }
    proof! { assert(i == 0); }
    i
}
"#,
    );
}

#[test]
fn nested_loops() {
    let v = accepts(
        r#"
pub fn grid() -> u64 {
    let mut total: u64 = 0;
    for i in 0u32..4 {
        proof! { invariant(total == (i as u64) * 3); }
        let mut row: u64 = 0;
        for j in 0u32..3 {
            proof! { invariant(row == j as u64); }
            row += 1;
        }
        total += row;
    }
    proof! { assert(total == 12); }
    total
}
"#,
    );
    assert_eq!(status_of(&v, "crate::grid::loop#0::ensures"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::grid::loop#1::ensures"), &DefStatus::Checked);
}

#[test]
fn loop_in_a_generic_function() {
    accepts(
        r#"
fn count_items<T: Copy>(xs: &[T]) -> usize {
    let mut c: usize = 0;
    for i in 0..xs.len() {
        proof! { invariant(c == i); }
        c += 1;
    }
    proof! { assert(c == xs.len()); }
    c
}
pub fn count_bytes(xs: &[u8]) -> usize { count_items(xs) }
fn last_of<T: Copy>(xs: &[T], d: T) -> T {
    let mut r = d;
    let mut k: usize = 0;
    for i in 0..xs.len() {
        proof! { invariant(k == i); }
        r = xs[i];
        k += 1;
    }
    proof! { assert(k == xs.len()); }
    r
}
pub fn last_byte(xs: &[u8]) -> u8 { last_of(xs, 0u8) }
"#,
    );
}

#[test]
fn loops_without_invariants_get_no_lemma() {
    let v = accepts(
        r#"
pub fn xor_all(xs: &[u8]) -> u8 {
    let mut x = 0u8;
    for i in 0..xs.len() {
        x ^= xs[i];
    }
    x
}
"#,
    );
    assert!(v.defs.iter().all(|d| !d.name.ends_with("::ensures")), "{:?}", v.defs.iter().map(|d| &d.name).collect::<Vec<_>>());
}

/// The whole pipeline: the helpers' exec bodies are unchanged, so the
/// optimizer (strict) and the round trip (the printed code read back and
/// compared with the optimized core, DESIGN.md §8.3) are unaffected; the
/// lemmas are never printed and are recorded unchanged in generated mode.
#[test]
fn optimizer_and_round_trip_are_unaffected() {
    let src = r#"
pub fn count(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c == i); }
        c += 1;
    }
    proof! { assert(c == n); }
    c
}
pub fn sum4(a: [u32; 4]) -> u64 {
    let mut s: u64 = 0;
    for i in 0usize..4 {
        proof! { invariant((s as Int) <= (i as Int) * 4294967295); }
        s += a[i] as u64;
    }
    proof! { assert((s as Int) <= 4 * 4294967295); }
    s
}
pub fn drain(n: u32) -> u32 {
    let mut i = n;
    let mut k: u32 = 0;
    while i > 0 {
        proof! { decreases(i); invariant((k as Int) + (i as Int) == (n as Int)); }
        i -= 1;
        k += 1;
    }
    proof! { assert(k == n); }
    k
}
pub fn grid() -> u64 {
    let mut total: u64 = 0;
    for i in 0u32..4 {
        proof! { invariant(total == (i as u64) * 3); }
        let mut row: u64 = 0;
        for j in 0u32..3 {
            proof! { invariant(row == j as u64); }
            row += 1;
        }
        total += row;
    }
    proof! { assert(total == 12); }
    total
}
pub fn to_max(a: u8) -> u32 {
    let mut c: u32 = 0;
    for j in a..=u8::MAX {
        proof! { invariant((c as Int) == (j as Int) - (a as Int)); }
        c += 1;
    }
    proof! { assert((c as Int) == 256 - (a as Int)); }
    c
}
"#;
    let c = util::accepted(src);
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &opts, &OptOptions { strict: true, ..Default::default() }, "r/mod.rs");
    assert!(built.v.proofs_ok, "not verified:\n{}", util::explain(&c, &built.v));
    for f in ["count", "sum4", "drain", "grid", "to_max"] {
        assert_eq!(status_of(&built.v, &format!("crate::{f}::loop#0::ensures")), &DefStatus::Checked, "{f}");
    }
    let em = built.emit.expect("optimized").expect("optimizer ran");
    assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "round trip failed:\n{}\n{}", em.roundtrip.join("\n"), em.code);
    assert!(!em.code.contains("ensures"), "lemmas are never printed:\n{}", em.code);
}

// ---------------------------------------------------------------------
// must reject
// ---------------------------------------------------------------------

#[test]
fn no_fact_from_an_invariant_false_at_entry() {
    // the lemma is conditional on the invariant at entry: the entry
    // obligation fails, so the function is not verified
    rejects(
        r#"
pub fn f(n: u32) -> u32 {
    let mut c: u32 = 5;
    for i in 0..n {
        proof! { invariant(c == i); }
        c += 1;
    }
    proof! { assert(c == n); }
    c
}
"#,
        "crate::f",
        "invariant-entry",
    );
}

#[test]
fn no_fact_from_an_invariant_not_preserved() {
    // the helper does not check: no lemma, so no fact, and the claim after
    // the loop is unproven too
    let v = rejects(
        r#"
pub fn f(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant((c as Int) == (i as Int)); }
        c = c.wrapping_add(2);
    }
    proof! { assert(c == n); }
    c
}
"#,
        "crate::f::loop#0",
        "invariant-preserve",
    );
    assert!(v.defs.iter().all(|d| d.name != "crate::f::loop#0::ensures" || d.status != DefStatus::Checked));
    assert!(unproven(&v).iter().any(|(d, k)| d == "crate::f" && k == "assert"), "the claim after the loop has no fact to use");
}

#[test]
fn invariant_false_at_the_exit() {
    // `i < n` holds in every iteration but not after the last one: the
    // exit obligation of the lemma fails
    rejects(
        r#"
pub fn f(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(i < n); }
        c = c.wrapping_add(1);
    }
    c
}
"#,
        "crate::f::loop#0::ensures",
        "invariant-exit",
    );
}

#[test]
fn off_by_one_claim_after_the_loop() {
    rejects(
        r#"
pub fn f(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c == i); }
        c += 1;
    }
    proof! { assert((c as Int) == (n as Int) + 1); }
    c
}
"#,
        "crate::f",
        "assert",
    );
    // `a..=b`: the invariant holds at `b + 1`, not at `b`
    rejects(
        r#"
pub fn f() -> u32 {
    let mut c: u32 = 0;
    for j in 250u8..=u8::MAX {
        proof! { invariant((c as Int) == (j as Int) - 250); }
        c += 1;
    }
    proof! { assert(c == 5); }
    c
}
"#,
        "crate::f",
        "assert",
    );
}

#[test]
fn nothing_about_the_bounds_after_the_loop() {
    // `k..n` may run zero times with `k > n`: the loop gives no `k <= n`
    rejects(
        r#"
pub fn f(k: u32, n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in k..n {
        proof! { invariant(c <= i); }
        c = i;
    }
    n - k
}
"#,
        "crate::f",
        "underflow",
    );
}

#[test]
fn inclusive_range_at_max_gives_nothing_over_the_loop_variable_as_a_machine_integer() {
    // after `250..=u8::MAX` the loop variable would be 256, which a `u8`
    // cannot hold: an invariant over `j as u32` is stated under `b < MAX`,
    // which is false here (stated over `j as Int`, it would be exact)
    rejects(
        r#"
pub fn f() -> u32 {
    let mut c: u32 = 0;
    for j in 250u8..=u8::MAX {
        proof! { invariant(c == (j as u32) - 250); }
        c += 1;
    }
    proof! { assert(c == 6); }
    c
}
"#,
        "crate::f",
        "assert",
    );
}

// ---------------------------------------------------------------------
// review S0 regressions
// ---------------------------------------------------------------------

/// Obligations of `def` proven by reusing a proof the helper already has.
fn reused(v: &sandblaster_front::driver::Verification, def: &str) -> usize {
    v.obligations.iter().filter(|o| o.def == def && matches!(&o.status, sandblaster_front::elab::OblStatus::Proven { by } if by == "reuse")).count()
}

#[test]
fn disjunctive_invariants_after_a_for_loop() {
    // `||` invariants verified before the post-loop lemmas, and must still:
    // a disjunction is stated after the loop in implication form (`found
    // == true → ..`), which a proof after the loop can use
    accepts_std(
        r#"
pub fn find(xs: &[u8; 8], key: u8) -> (bool, usize) {
    let mut found = false;
    let mut pos: usize = 0;
    for i in 0usize..8 {
        proof! { invariant(pos < 8); invariant(found == false || xs[pos] == key); }
        if xs[i] == key { found = true; pos = i; }
    }
    proof! { assert(implies(found == true, xs[pos] == key)); }
    (found, pos)
}
"#,
    );
    accepts_std(
        r#"
pub fn all_small(xs: &[u8; 8]) -> bool {
    let mut ok = true;
    for i in 0usize..8 {
        proof! { invariant(ok == true || ok == false); }
        if xs[i] >= 128 { ok = false; }
    }
    ok
}
"#,
    );
}

#[test]
fn disjunctive_invariants_after_a_while_loop() {
    accepts_std(
        r#"
pub fn find(xs: &[u8; 8], key: u8) -> (bool, usize) {
    let mut found = false;
    let mut pos: usize = 0;
    let mut i: usize = 0;
    while i < 8 {
        proof! { invariant(i <= 8); invariant(pos < 8); invariant(found == false || xs[pos] == key); decreases(8 - i); }
        if xs[i] == key { found = true; pos = i; }
        i += 1;
    }
    proof! { assert(i == 8); assert(implies(found == true, xs[pos] == key)); }
    (found, pos)
}
"#,
    );
}

#[test]
fn several_mutated_locals_feed_ensures() {
    // the fact is stated over the locals after the loop (not the loop's
    // join value), so goals stay small: every obligation in its scope,
    // including the `ensures` clause's own overflow checks, is proven
    accepts(
        r#"
#[ensures(|r: u32| r == (n as u32))]
pub fn two(n: u16) -> u32 {
    let n = n as u32;
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    for i in 0..n {
        proof! { invariant(a == i); invariant(b == 2 * i); }
        a += 1;
        b += 2;
    }
    a
}
"#,
    );
    accepts(
        r#"
#[ensures(|r: u32| r == 3 * (n as u32))]
pub fn three(n: u16) -> u32 {
    let n = n as u32;
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    for i in 0..n {
        proof! { invariant(a == i); invariant(b == 2 * i); }
        a += 1;
        b += 2;
    }
    a + b
}
"#,
    );
    // a conjunction in the ensures: proven from the irrelevant fact and
    // promoted
    accepts(
        r#"
#[ensures(|r: (u32, u32)| r.0 == (n as u32) && r.1 == 2 * (n as u32))]
pub fn pair(n: u16) -> (u32, u32) {
    let n = n as u32;
    let mut a: u32 = 0;
    let mut b: u32 = 0;
    for i in 0..n {
        proof! { invariant(a == i); invariant(b == 2 * i); }
        a += 1;
        b += 2;
    }
    (a, b)
}
"#,
    );
}

#[test]
fn post_loop_fact_reaches_a_later_loop() {
    // §7.4: the facts in scope at a loop head about the variables it reads
    // are requires of its helper — a post-loop fact included
    accepts(
        r#"
#[requires(n < 8)]
fn g(n: u32, xs: &[u8; 8]) -> u64 {
    let mut total: u32 = 0;
    for i in 0..n {
        proof! { invariant(total == i); }
        total += 1;
    }
    let mut s: u64 = 0;
    for j in 0..n {
        proof! { invariant((s as Int) <= 255 * (j as Int)); }
        s += xs[total as usize] as u64;
    }
    s
}
pub fn api(xs: &[u8; 8]) -> u64 { g(3, xs) }
"#,
    );
}

#[test]
fn compound_while_conditions_after_the_loop() {
    // `!(a && b)` is stated as `a == true → b == false` (`b` runs only when
    // `a` holds, so its operations are defined), `!(a || b)` as `a == false
    // ∧ b == false`
    accepts_std(
        r#"
pub fn scan(xs: &[u8; 16]) -> usize {
    let mut i: usize = 0;
    while i < 16 && xs[i] != 0 {
        proof! { invariant(i <= 16); decreases(16 - i); }
        i += 1;
    }
    proof! { assert(implies(i < 16, xs[i] == 0)); }
    i
}
"#,
    );
    accepts_std(
        r#"
pub fn scan2(lim: usize) -> usize {
    let mut i: usize = 0;
    while i < 16 && i < lim {
        proof! { invariant(i <= 16); decreases(16 - i); }
        i += 1;
    }
    proof! { assert(implies(i < 16, i >= lim)); }
    i
}
"#,
    );
    accepts_std(
        r#"
pub fn both(a: u32, b: u32) -> u32 {
    let mut x: u32 = a % 100;
    let mut y: u32 = b % 100;
    while x < 50 || y < 50 {
        proof! { invariant(x <= 100); invariant(y <= 100); decreases(200 - x - y); }
        if x < 50 { x += 1; } else { y += 1; }
    }
    proof! { assert(x >= 50 && y >= 50); }
    x + y
}
"#,
    );
}

#[test]
fn many_invariants_are_proven_once() {
    // the invariants at `i + 1` are proven once, before the branch on `i +
    // 1 < b`: the recursive call and the lemma's exit reuse them (no second
    // linear search per invariant), so the cost stays that of the loop's
    // own preservation proofs
    let t0 = std::time::Instant::now();
    let v = accepts(
        r#"
pub fn f(n: u16) -> u32 {
    let n = n as u32;
    let mut a: u32 = 0;
    for i in 0..n {
        proof! { invariant(a == i); invariant(a <= 1 * i + 0); invariant(a <= 2 * i + 1); invariant(a <= 3 * i + 2); invariant(a <= 4 * i + 3); }
        a += 1;
    }
    a
}
"#,
    );
    let exits = count(&kinds_of(&v, "crate::f::loop#0::ensures"), "invariant-exit");
    assert!(exits >= 5, "{exits}");
    assert_eq!(reused(&v, "crate::f::loop#0::ensures"), exits, "every exit conjunct reuses a preservation proof");
    assert_eq!(count(&kinds_of(&v, "crate::f::loop#0"), "invariant-preserve"), 5, "one preservation proof per invariant");
    // generous: before the fix this took about ten times the pre-lemma cost
    assert!(t0.elapsed() < std::time::Duration::from_secs(120), "{:?}", t0.elapsed());
}

#[test]
fn exit_failures_explain_the_rule() {
    let (c, v) = verify_src(
        r#"
pub fn sum(xs: &[u8; 8]) -> u32 {
    let mut s: u32 = 0;
    for i in 0usize..8 {
        proof! { invariant(i < 8); invariant((s as Int) <= 255 * (i as Int)); }
        s += xs[i] as u32;
    }
    s
}
"#,
        ProverSet::Basic,
    );
    let d = v.diags.list.iter().find(|d| d.msg.contains("[invariant-exit]")).unwrap_or_else(|| panic!("{}", explain(&c, &v)));
    assert!(d.notes.iter().any(|(_, n)| n.contains("must also hold when the loop exits") && n.contains("i <= b")), "{:?}", d.notes);
    assert!(d.goal.as_deref().unwrap_or("").contains("i_exit"), "the exit index prints under the loop variable's name: {:?}", d.goal);
    // an operation of the invariant undefined at the exit index is an exit
    // failure too, not a bare index-bounds one
    let (c, v) = verify_src(
        r#"
pub fn sum(xs: &[u8; 8]) -> u32 {
    let mut s: u32 = 0;
    for i in 0usize..8 {
        proof! { invariant(xs[i] == xs[i]); invariant((s as Int) <= 255 * (i as Int)); }
        s += xs[i] as u32;
    }
    s
}
"#,
        ProverSet::Basic,
    );
    let bad = unproven(&v);
    assert!(bad.iter().any(|(d, k)| d == "crate::sum::loop#0::ensures" && k == "invariant-exit"), "{}", explain(&c, &v));
    assert!(!bad.iter().any(|(_, k)| k == "index-bounds"), "{bad:?}");
    let d = v.diags.list.iter().find(|d| d.msg.contains("[invariant-exit]")).unwrap();
    assert!(d.notes.iter().any(|(_, n)| n.contains("must be defined when the loop exits")), "{:?}", d.notes);
}

// ---------------------------------------------------------------------
// facts from before the loop
// ---------------------------------------------------------------------

#[test]
fn a_fact_about_a_mutated_local_does_not_block_the_loop() {
    // `v == 5` holds on entry only; it is not carried into the helper (it
    // would have to hold at every recursive call, where `v` has changed)
    accepts(
        r#"
pub fn f() -> u32 {
    let mut v: u32 = 5;
    proof! { assert(v == 5); }
    while v > 0 {
        proof! { decreases(v); }
        v -= 1;
    }
    v
}
"#,
    );
    // nor one about a read-only value a mutated local aliases on entry
    accepts(
        r#"
pub fn g(n: u32) -> u32 {
    let mut v = n;
    proof! { assert(v == n); }
    while v > 0 {
        proof! { decreases(v); }
        v -= 1;
    }
    v
}
"#,
    );
}

#[test]
fn a_fact_about_a_mutated_local_is_not_available_inside_the_loop() {
    rejects(
        r#"
pub fn f() -> u32 {
    let mut v: u32 = 5;
    proof! { assert(v == 5); }
    while v > 0 {
        proof! { decreases(v); assert(v == 5); }
        v -= 1;
    }
    v
}
"#,
        "crate::f::loop#0",
        "assert",
    );
}

#[test]
fn a_fact_about_a_read_only_parameter_is_still_carried() {
    accepts(
        r#"
#[requires(n < 100)]
fn f(n: u32) -> u32 {
    let mut v: u32 = 0;
    let mut i: u32 = 0;
    while i < n {
        proof! { decreases((n as Int) - (i as Int)); invariant(v == i); }
        v += 1;
        i += 1;
    }
    v
}

pub fn g() -> u32 {
    f(50)
}
"#,
    );
}
