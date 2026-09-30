//! The engineer-facing proof statements (DESIGN.md §4.4,
//! docs/PROOF-GUIDE.md): the closing statements `follows()`,
//! `by_computation()`, `by_arithmetic()`, `by_unfolding(..)` and
//! `by_contradiction()` (each checks the reason it states), the warning at
//! a block end without one, `by_cases(..)`, `#[induction(x)]` + `ih(..)`,
//! `apply(lemma)` and `calc! { .. }`, each with positive and negative tests,
//! plus the old forms they replace (still accepted) and the removed
//! `by_auto()` / `follows_from_facts()`.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::diag::Severity;
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use util::explain;

/// Front end + verification (ghost items included, the build's provers).
fn verify(src: &str) -> (Checked, Verification) {
    let c = util::check_src(src);
    assert!(c.ok(), "front end rejected:\n{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (c, v)
}

#[track_caller]
fn verified(src: &str) -> (Checked, Verification) {
    let (c, v) = verify(src);
    assert!(v.proofs_ok, "not verified:\n{}", explain(&c, &v));
    (c, v)
}

/// Verification must fail; returns the rendered error diagnostics.
#[track_caller]
fn fails(src: &str) -> String {
    let (c, v) = verify(src);
    assert!(!v.proofs_ok, "unexpectedly verified:\n{src}");
    v.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n")
}

/// The front end must reject; returns the rendered errors.
#[track_caller]
fn rejected(src: &str) -> String {
    let c = util::check_src(src);
    assert!(!c.ok(), "front end accepted:\n{src}");
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n")
}

fn warnings(c: &Checked) -> Vec<String> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| d.render(&c.sm)).collect()
}

// ---------------------------------------------------------------------------
// follows, and the removed by_auto / follows_from_facts
// ---------------------------------------------------------------------------

const TWICE: &str = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn twice(x: u8) -> Int { 2 * (x as Int) }
"#;

#[test]
fn follows_closes_and_empty_bodies_warn() {
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); follows(); }}\n");
    let (c, v) = verified(&src);
    assert!(warnings(&c).is_empty() && !v.diags.list.iter().any(|d| d.severity == Severity::Warning), "{:?}", warnings(&c));
    // the same lemma with an empty body: accepted, with a warning (that no
    // longer mentions the removed `by_auto()`)
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); }}\n");
    let (c, _) = verified(&src);
    let w = warnings(&c);
    assert!(w.iter().any(|m| m.contains("empty `#[lemma]` body") && m.contains("write `follows();`")), "{w:?}");
    assert!(!w.iter().any(|m| m.contains("by_auto")), "{w:?}");
    // empty case arms and branches warn too, and so does a missing `else`
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(b: bool, x: u8) {{ ensures(twice(x) <= 510); if b {{ }} else {{ follows(); }} }}\n");
    let (c, _) = verified(&src);
    assert!(warnings(&c).iter().any(|m| m.contains("empty branch") && m.contains("follows();")), "{:?}", warnings(&c));
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(b: bool, x: u8) {{ ensures(twice(x) <= 510); if b {{ follows(); }} }}\n");
    let (c, _) = verified(&src);
    assert!(warnings(&c).iter().any(|m| m.contains("script `if` without `else`")), "{:?}", warnings(&c));
}

#[test]
fn follows_fails_when_the_goal_does_not_follow() {
    // `x < 10` does not follow from anything in scope: the build fails
    let e = fails("pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(x: u8) { requires(x < 20); ensures(x < 10); follows(); }\n");
    assert!(e.contains("unproven obligation"), "{e}");
    verified("pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(x: u8) { requires(x < 5); ensures(x < 10); follows(); }\n");
}

#[test]
fn follows_from_facts_is_spelled_follows() {
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); follows_from_facts(); }}\n"));
    assert!(e.contains("`follows_from_facts()` is spelled `follows()`"), "{e}");
}

#[test]
fn closing_statements_must_be_last() {
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(twice(x) <= 510); follows(); assert(x <= 255); }}\n"));
    assert!(e.contains("unreachable proof step") && e.contains("`follows()` already closes the goal"), "{e}");
    for (closer, shown) in [("by_arithmetic()", "by_arithmetic()"), ("by_contradiction()", "by_contradiction()"), ("by_unfolding(twice)", "by_unfolding(..)"), ("by_computation()", "by_computation()")] {
        let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(twice(x) <= 510); {closer}; assert(x <= 255); }}\n"));
        assert!(e.contains("unreachable proof step") && e.contains(&format!("`{shown}` already closes the goal")), "{closer}: {e}");
    }
}

#[test]
fn by_auto_is_removed() {
    // an error that says what to write instead
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); by_auto(); }}\n"));
    assert!(e.contains("`by_auto()` was removed"), "{e}");
    for s in ["by_computation()", "by_arithmetic()", "by_unfolding(f, ..)", "by_contradiction()", "`follows()` (the automation's general reasoning: what `by_auto()` did)"] {
        assert!(e.contains(s), "{s}: {e}");
    }
    // also as a match arm
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(o: Option<u8>) {{ ensures(true); match o {{ None => by_auto(), Some(_) => follows() }} }}\n"));
    assert!(e.contains("`by_auto()` was removed"), "{e}");
}

// ---------------------------------------------------------------------------
// by_computation
// ---------------------------------------------------------------------------

const CODE: &str = r#"
#[derive(Clone, Copy)]
pub enum Color { Red, Green, Blue }
pub fn code(c: Color) -> u8 { match c { Color::Red => 1, Color::Green => 2, Color::Blue => 3 } }
pub fn get(o: Option<u8>) -> u8 { match o { None => 0, Some(v) => v } }
"#;

#[test]
fn by_computation_proves_by_evaluation() {
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn green(v: u8) {{ ensures(code(Color::Green) + get(Some(v)) - v == 2); by_computation(); }}\n");
    // `code(Green) = 2` and `get(Some(v)) = v` compute; `2 + v - v` does not
    // convert to `2` without arithmetic, so this one must fail ...
    let e = fails(&src);
    assert!(e.contains("left side evaluates to") && e.contains("right side evaluates to"), "{e}");
    // ... while a goal whose sides compute to the same value holds
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn green(v: u8) {{ ensures(get(Some(v)) == v && code(Color::Blue) == 3); by_computation(); }}\n");
    // a conjunction is not an equation: rejected with an explanation
    let e = fails(&src);
    assert!(e.contains("by_computation()"), "{e}");
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn green(v: u8) {{ ensures(get(Some(v)) == v); by_computation(); }}\n#[cfg(sandblaster)] #[lemma] fn blue() {{ ensures(code(Color::Blue) == 3); by_computation(); }}\n");
    verified(&src);
}

#[test]
fn by_computation_does_not_search() {
    // provable from the hypothesis (auto closes it), but not by evaluation
    let src = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(a: u8, b: u8) { requires(a < b); ensures(a <= b); by_computation(); }\n";
    let e = fails(src);
    assert!(e.contains("left side evaluates to") && e.contains("right side evaluates to: true"), "{e}");
    let ok = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(a: u8, b: u8) { requires(a < b); ensures(a <= b); by_arithmetic(); }\n";
    verified(ok);
}

// ---------------------------------------------------------------------------
// by_arithmetic
// ---------------------------------------------------------------------------

#[test]
fn by_arithmetic_accepts_arithmetic_on_the_facts() {
    let src = format!(
        r#"{TWICE}
pub fn g(x: u8) -> u8 {{ x / 2 }}
#[cfg(sandblaster)] #[lemma] fn lt_le(a: u8, b: u8) {{ requires(a < b); ensures(a <= b); by_arithmetic(); }}
#[cfg(sandblaster)] #[lemma] fn sum(a: u8, b: u8) {{ requires(a <= 10); requires(b <= 20); ensures((a as Int) + (b as Int) <= 30); by_arithmetic(); }}
// facts about a user function: used without knowing what it computes
#[cfg(sandblaster)] #[lemma] fn unknown_fn(x: u8) {{ requires(twice(x) <= 100); ensures(twice(x) + 1 <= 101); by_arithmetic(); }}
// equal arguments, equal results (congruence)
#[cfg(sandblaster)] #[lemma] fn congr(x: u8, y: u8) {{ requires(x == y); ensures(g(x) == g(y)); by_arithmetic(); }}
// the built-in axioms of `min`/`saturating_sub`
#[cfg(sandblaster)] #[lemma] fn min_le(a: u8, b: u8) {{ ensures(a.min(b) <= a); by_arithmetic(); }}
#[cfg(sandblaster)] #[lemma] fn sat_le(a: u8, b: u8) {{ ensures(a.saturating_sub(b) <= a); by_arithmetic(); }}
// constructor clash between facts
#[cfg(sandblaster)] #[lemma] fn clash(o: Option<u8>, v: u8) {{ requires(o == Some(v)); ensures(o != None); by_arithmetic(); }}
"#
    );
    let (_, v) = verified(&src);
    assert!(v.obligations.iter().any(|o| matches!(&o.status, sandblaster_front::elab::OblStatus::Proven { by } if by == "script(by_arithmetic)")), "{:?}", v.obligations.iter().map(|o| &o.status).collect::<Vec<_>>());
}

#[test]
fn by_arithmetic_with_proofs_inside_statements() {
    // the overflow proof of `tw(x) + 1` (inside the statements) uses what
    // `tw` computes; the claim is still checked with `tw` unknown
    let src = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn tw(x: u8) -> u16 { (x as u16) * 2 }
#[cfg(sandblaster)] #[lemma] fn l(x: u8) { requires(tw(x) + 1 <= 300); ensures(tw(x) + 1 <= 301); by_arithmetic(); }
"#;
    verified(src);
    let src = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn tw(x: u8) -> u16 { (x as u16) * 2 }
#[cfg(sandblaster)] #[lemma] fn l(x: u8) { requires(tw(x) + 1 <= 600); ensures(tw(x) <= 510); by_arithmetic(); }
"#;
    let e = fails(src);
    assert!(e.contains("treated as unknown functions: `tw`"), "{e}");
    verified(&src.replace("by_arithmetic()", "by_unfolding(tw)"));
}

#[test]
fn by_arithmetic_rejects_a_goal_that_needs_unfolding() {
    // `twice(x) <= 510` holds, but only by what `twice` computes
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); by_arithmetic(); }}\n");
    let e = fails(&src);
    assert!(e.contains("`by_arithmetic()`: the goal does not follow from the facts in scope by arithmetic"), "{e}");
    assert!(e.contains("treated as unknown functions: `twice`") && e.contains("by_unfolding(twice)"), "{e}");
    // the same through a `let` of the lemma
    let src = format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); let t = twice(x); assert(t <= 510, {{ by_arithmetic(); }}); }}\n");
    let e = fails(&src);
    assert!(e.contains("treated as unknown functions: `twice`"), "{e}");
    // an evaluation that is not arithmetic: `code(Blue)` is 3 only by `code`'s definition
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn blue() {{ ensures(code(Color::Blue) == 3); by_arithmetic(); }}\n");
    let e = fails(&src);
    assert!(e.contains("`code`"), "{e}");
}

#[test]
fn by_arithmetic_rejects_case_splits_and_lemmas() {
    // true by cases on `b` (auto splits; `by_arithmetic()` does not)
    let src = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(b: bool) { ensures(b || !b); by_arithmetic(); }\n";
    let e = fails(src);
    assert!(e.contains("case split"), "{e}");
    let ok = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(b: bool) { ensures(b || !b); by_cases(b); }\n";
    verified(ok);
}

// ---------------------------------------------------------------------------
// by_unfolding
// ---------------------------------------------------------------------------

const INC: &str = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn inc(x: u8) -> Int { (x as Int) + 1 }
#[cfg(sandblaster)] #[spec] fn dec(x: u8) -> Int { (x as Int) - 1 }
#[cfg(sandblaster)] #[spec] fn tri(n: u32) -> Int { if n == 0 { 0 } else { (n as Int) + tri(n - 1) } }
"#;

#[test]
fn by_unfolding_unfolds_exactly_the_named_definitions() {
    let src = format!(
        r#"{INC}
#[cfg(sandblaster)] #[spec] fn twice(x: u8) -> Int {{ 2 * (x as Int) }}
#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) {{ ensures(twice(x) <= 510); by_unfolding(twice); }}
#[cfg(sandblaster)] #[lemma] fn both(x: u8) {{ ensures(inc(x) + dec(x) == 2 * (x as Int)); by_unfolding(inc, dec); }}
// a recursive definition: one step
#[cfg(sandblaster)] #[lemma] fn tri_step(n: u32) {{ requires(n > 0); ensures(tri(n) == (n as Int) + tri(n - 1)); by_unfolding(tri); }}
"#
    );
    let (_, v) = verified(&src);
    assert!(v.obligations.iter().any(|o| matches!(&o.status, sandblaster_front::elab::OblStatus::Proven { by } if by == "script(by_unfolding)")), "{:?}", v.obligations.iter().map(|o| &o.status).collect::<Vec<_>>());
}

#[test]
fn by_unfolding_rejects_when_another_definition_is_needed() {
    // `dec` must be unfolded too
    let src = format!("{INC}#[cfg(sandblaster)] #[lemma] fn both(x: u8) {{ ensures(inc(x) + dec(x) == 2 * (x as Int)); by_unfolding(inc); }}\n");
    let e = fails(&src);
    assert!(e.contains("`by_unfolding(inc)`: the goal does not follow"), "{e}");
    assert!(e.contains("treated as unknown functions: `dec`") && e.contains("by_unfolding(inc, dec)"), "{e}");
}

#[test]
fn by_unfolding_names_functions() {
    let e = rejected(&format!("{INC}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(inc(x) >= 1); by_unfolding(); }}\n"));
    assert!(e.contains("`by_unfolding` names the definitions") && e.contains("by_arithmetic();"), "{e}");
    let e = rejected(&format!("{INC}#[cfg(sandblaster)] #[lemma] fn helper(x: u8) {{ ensures(inc(x) >= 1); by_unfolding(inc); }}\n#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(inc(x) >= 1); by_unfolding(helper); }}\n"));
    assert!(e.contains("`by_unfolding` takes a function definition, not a lemma or law"), "{e}");
    // a name the goal does not mention: a warning
    let src = format!("{INC}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(inc(x) >= 1); by_unfolding(inc, dec); }}\n");
    let (_, v) = verified(&src);
    assert!(v.diags.list.iter().any(|d| d.severity == Severity::Warning && d.msg.contains("`dec` does not occur in the goal")), "{:?}", v.diags.list.iter().map(|d| &d.msg).collect::<Vec<_>>());
}

// ---------------------------------------------------------------------------
// by_contradiction
// ---------------------------------------------------------------------------

#[test]
fn by_contradiction_needs_contradictory_facts() {
    let src = format!(
        r#"{CODE}
#[cfg(sandblaster)] #[lemma] fn impossible(a: u8) {{ requires(a > 10); requires(a < 5); ensures(a == 7); by_contradiction(); }}
// a case that cannot happen: `get(None) == 0`, not 5
#[cfg(sandblaster)] #[lemma] fn arm(o: Option<u8>) {{
    requires(get(o) == 5);
    ensures(o != None);
    match o {{
        None => by_contradiction(),
        Some(_) => follows(),
    }}
}}
"#
    );
    verified(&src);
    // consistent facts: rejected even though the goal itself is provable
    let src = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(a: u8) { requires(a > 10); ensures(a > 5); by_contradiction(); }\n";
    let e = fails(src);
    assert!(e.contains("`by_contradiction()`: the facts in scope must contradict each other"), "{e}");
    assert!(e.contains("the goal (not used)"), "{e}");
}

// ---------------------------------------------------------------------------
// by_cases
// ---------------------------------------------------------------------------

#[test]
fn by_cases_on_bools_options_enums_and_ranges() {
    let src = format!(
        r#"{CODE}
#[cfg(sandblaster)] #[lemma] fn and_left(a: bool, b: bool) {{ requires((a && b) == true); ensures(a); by_cases(a); }}
#[cfg(sandblaster)] #[lemma] fn and_comm(a: bool, b: bool) {{ ensures((a && b) == (b && a)); by_cases(a, b); }}
#[cfg(sandblaster)] #[lemma] fn code_range(c: Color) {{ ensures(code(c) >= 1 && code(c) <= 3); by_cases(c); }}
#[cfg(sandblaster)] #[lemma] fn get_none(o: Option<u8>) {{ requires(o == None); ensures(get(o) == 0); by_cases(o); }}
#[cfg(sandblaster)] #[lemma] fn get_bound(o: Option<u8>, k: u8) {{ requires(get(o) < k); ensures(get(o) <= 254); by_cases(o); assert(get(o) < k); }}
#[cfg(sandblaster)] #[lemma] fn small_square(k: u8) {{ requires(k < 4); ensures((k as Int) * (k as Int) <= 9); by_cases(k, 0..4); }}
"#
    );
    verified(&src);
}

#[test]
fn by_cases_inside_proof_blocks() {
    // the token form `by_cases(k in lo..hi)` inside `proof! { .. }`; the
    // call form in an `assert` block of exec code
    let src = r#"
#[cfg(sandblaster)] #[spec] fn sq(k: u8) -> Int { (k as Int) * (k as Int) }
#[cfg(sandblaster)] #[lemma] fn sq_small(k: u8) { requires(k < 3); ensures(sq(k) <= 4); proof! { by_cases(k in 0..3); } }
pub fn f(k: u8) -> u8 {
    if k < 3 {
        proof! { assert(sq(k) <= 4, { by_cases(k, 0..3); }); }
        k
    } else {
        0
    }
}
"#;
    verified(src);
}

#[test]
fn by_cases_rejects_what_it_cannot_split() {
    let e = rejected("pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(xs: &[u8]) { ensures(xs.len() >= 0); by_cases(xs); }\n");
    assert!(e.contains("`by_cases` splits a `bool`, an `Option` or an enum"), "{e}");
    let e = rejected("pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn l(k: u8) { ensures(k >= 0); by_cases(k); }\n");
    assert!(e.contains("by_cases(k, lo..hi)"), "{e}");
}

// ---------------------------------------------------------------------------
// #[induction(x)] and ih(..)
// ---------------------------------------------------------------------------

const TOTAL: &str = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn total(xs: &[u8]) -> Int { match xs { [] => 0, [h, t @ ..] => (*h as Int) + total(t) } }
#[cfg(sandblaster)] #[spec] fn tri(n: u32) -> Int { if n == 0 { 0 } else { (n as Int) + tri(n - 1) } }
"#;

#[test]
fn induction_with_ih() {
    let src = format!(
        r#"{TOTAL}
#[cfg(sandblaster)]
#[lemma]
#[induction(n)]
fn tri_bound(n: u32) {{
    ensures(tri(n) >= (n as Int));
    if n == 0 {{
        // `tri(0) = 0`
        by_unfolding(tri);
    }} else {{
        ih(n - 1);
    }}
}}
"#
    );
    verified(&src);
    // the old form (a recursive call by name) still works
    let src = format!(
        r#"{TOTAL}
#[cfg(sandblaster)]
#[lemma]
fn tri_bound(n: u32) {{
    ensures(tri(n) >= (n as Int));
    if n == 0 {{
    }} else {{
        tri_bound(n - 1);
    }}
}}
"#
    );
    verified(&src);
}

#[test]
fn ih_outside_an_inductive_proof() {
    let e = rejected(&format!("{TOTAL}#[cfg(sandblaster)] #[lemma] fn l(xs: &[u8]) {{ ensures(total(xs) >= 0); match xs {{ [] => by_computation(), [_h, t @ ..] => {{ ih(t); }} }} }}\n"));
    assert!(e.contains("`ih(..)` outside an inductive proof") && e.contains("#[induction(x)]"), "{e}");
    let e = rejected("pub fn g(x: u8) -> u8 { proof! { ih(x); } x }\n");
    assert!(e.contains("`ih(..)` outside an inductive proof"), "{e}");
}

#[test]
fn induction_must_recurse_on_a_smaller_argument() {
    let e = rejected(&format!("{TOTAL}#[cfg(sandblaster)] #[lemma] #[induction(xs)] fn l(xs: &[u8]) {{ ensures(total(xs) >= 0); match xs {{ [] => by_computation(), [_h, _t @ ..] => {{ ih(xs); }} }} }}\n"));
    assert!(e.contains("structurally smaller `xs`"), "{e}");
    let e = rejected(&format!("{TOTAL}#[cfg(sandblaster)] #[lemma] #[induction(xs)] fn l(xs: &[u8]) {{ ensures(total(xs) >= 0); follows(); }}\n"));
    assert!(e.contains("never applies its induction hypothesis"), "{e}");
    let e = rejected(&format!("{TOTAL}#[cfg(sandblaster)] #[lemma] #[induction(ys)] fn l(xs: &[u8]) {{ ensures(total(xs) >= 0); follows(); }}\n"));
    assert!(e.contains("`ys` is not a parameter"), "{e}");
}

// ---------------------------------------------------------------------------
// apply(lemma)
// ---------------------------------------------------------------------------

const PICK: &str = r#"
pub fn pick(x: u32) -> Option<u32> {
    if x > 10 { Some(x - 10) } else { None }
}
pub fn wrap(x: u32) -> bool {
    match pick(x) {
        None => false,
        Some(v) => v > 3,
    }
}
#[cfg(sandblaster)]
#[lemma]
fn pick_small(x: u32, v: u32) {
    requires(x <= 13);
    requires(pick(x) == Some(v));
    ensures(v <= 3);
    by_cases(x > 10);
}
"#;

#[test]
fn apply_infers_arguments_from_facts() {
    // `pick_small(x, v)` from `x <= 13` and the arm's path equation
    let src = format!(
        r#"{PICK}
#[cfg(sandblaster)]
#[lemma]
fn wrap_small(x: u32) {{
    requires(x <= 13);
    ensures(wrap(x) == false);
    unfold(wrap);
    match pick(x) {{
        // `wrap` returns `false` when `pick` finds nothing
        None => by_computation(),
        Some(_) => apply(pick_small),
    }}
}}
"#
    );
    verified(&src);
    // through a transparent function: `twice_mono`'s `a <= b` against `le(x, y)`
    let src = format!(
        r#"{TWICE}
pub fn le(a: u8, b: u8) -> bool {{ a <= b }}
#[cfg(sandblaster)] #[lemma] fn twice_mono(a: u8, b: u8) {{ requires(a <= b); ensures(twice(a) <= twice(b)); by_unfolding(twice); }}
#[cfg(sandblaster)] #[lemma] fn use_mono(x: u8, y: u8) {{ requires(le(x, y)); ensures(twice(x) <= twice(y)); apply(twice_mono); }}
#[cfg(sandblaster)] #[lemma] fn bind_mono(x: u8, y: u8) {{ requires(x <= y); ensures(twice(x) + 1 <= twice(y) + 1); let h = apply(twice_mono); by_arithmetic(); }}
"#
    );
    verified(&src);
}

#[test]
fn apply_with_no_matching_fact_lists_the_candidates() {
    let src = format!(
        r#"{TWICE}
#[cfg(sandblaster)] #[lemma] fn twice_mono(a: u8, b: u8) {{ requires(a <= b); ensures(twice(a) <= twice(b)); by_unfolding(twice); }}
#[cfg(sandblaster)] #[lemma] fn l(x: u8, y: u8) {{ requires(x != y); ensures(x == x); apply(twice_mono); }}
"#
    );
    let e = fails(&src);
    assert!(e.contains("`apply(twice_mono)`: cannot infer its arguments (a, b)"), "{e}");
    assert!(e.contains("requires: a <= b") || e.contains("requires:"), "{e}");
    assert!(e.contains("no fact in scope matches") && e.contains("fact in scope:"), "{e}");
}

#[test]
fn apply_ambiguity_lists_the_candidates() {
    let src = format!(
        r#"{TWICE}
#[cfg(sandblaster)] #[lemma] fn pos(a: u8) {{ requires(a > 0); ensures(a >= 1); by_arithmetic(); }}
#[cfg(sandblaster)] #[lemma] fn l(x: u8, y: u8) {{ requires(x > 0); requires(y > 0); ensures((x as Int) + (y as Int) >= 2); apply(pos); }}
"#
    );
    let e = fails(&src);
    assert!(e.contains("is ambiguous") && e.contains("candidate 1: a = x") && e.contains("candidate 2: a = y"), "{e}");
}

#[test]
fn apply_rejects_non_lemmas_and_self() {
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(twice(x) >= 0); apply(twice); }}\n"));
    assert!(e.contains("`twice` is not a lemma or law"), "{e}");
    let e = rejected(&format!("{TWICE}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ ensures(twice(x) >= 0); apply(l); }}\n"));
    assert!(e.contains("`apply` of the enclosing proof"), "{e}");
}

// ---------------------------------------------------------------------------
// calc!
// ---------------------------------------------------------------------------

const CALC: &str = r#"
pub fn f(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn double(x: u8) -> Int { 2 * (x as Int) }
#[cfg(sandblaster)] #[lemma] fn double_eq(a: u8, b: u8) { requires(a == b); ensures(double(a) == double(b)); by_arithmetic(); }
"#;

#[test]
fn calc_equational_chain() {
    let src = format!(
        r#"{CALC}
#[cfg(sandblaster)]
#[lemma]
fn chain(x: u8, y: u8) {{
    requires(x == y);
    ensures(double(x) + 1 == 2 * (y as Int) + 1);
    calc! {{
        double(x) + 1
            == double(y) + 1 by {{ double_eq(x, y); }};
            == 2 * (y as Int) + 1 by {{ by_computation(); }};
    }}
}}
#[cfg(sandblaster)]
#[lemma]
fn chain_le(a: u8, b: u8, c: u8) {{
    requires(a <= b);
    requires(b < c);
    ensures(a < c);
    calc! {{ a <= b; < c; }}
}}
#[cfg(sandblaster)]
#[lemma]
fn chain_fact(x: u8, y: u8) {{
    requires(x == y);
    ensures(double(x) <= 510);
    // in the middle of a proof, the chain's conclusion is a fact
    calc! {{ double(x) == double(y) by {{ apply(double_eq); }}; }}
    by_unfolding(double);
}}
"#
    );
    verified(&src);
}

#[test]
fn calc_wrong_step_fails_at_that_step() {
    let src = format!(
        r#"{CALC}
#[cfg(sandblaster)]
#[lemma]
fn chain(x: u8, y: u8) {{
    requires(x == y);
    ensures(double(x) + 1 == 2 * (y as Int) + 2);
    calc! {{
        double(x) + 1
            == double(y) + 1 by {{ double_eq(x, y); }};
            == 2 * (y as Int) + 2;
    }}
}}
"#
    );
    let (c, v) = verify(&src);
    assert!(!v.proofs_ok);
    let failed: Vec<_> = v.diags.list.iter().filter(|d| d.severity == Severity::Error && d.msg.starts_with("unproven obligation")).collect();
    // exactly one failure: the second link (`double(y) + 1 == 2 * y + 2`),
    // reported on its line (the first link and the goal check hold)
    assert_eq!(failed.len(), 1, "{}", explain(&c, &v));
    let r = failed[0].render(&c.sm);
    assert!(r.contains("[assert]") && r.contains("== 2 * (y as Int) + 2;"), "{r}");
    let line = src.lines().position(|l| l.contains("== 2 * (y as Int) + 2;")).unwrap() as u32 + 1 + 2; // + the HEADER lines
    assert_eq!(failed[0].span.lo.0, line, "{r}");
}

#[test]
fn calc_and_apply_in_exec_proof_blocks() {
    // in exec code a chain (and an `apply`) only adds facts
    let src = format!(
        r#"{CALC}
pub fn g(x: u8, y: u8) -> u8 {{
    if x == y {{
        proof! {{
            calc! {{ double(x) == double(y) by {{ double_eq(x, y); }}; == 2 * (y as Int); }}
            apply(double_eq);
            assert(double(x) == double(y));
        }}
    }}
    x
}}
"#
    );
    verified(&src);
}

#[test]
fn calc_must_prove_the_goal() {
    let src = format!("{CALC}#[cfg(sandblaster)] #[lemma] fn chain(x: u8, y: u8) {{ requires(x == y); ensures(double(x) == double(y) + 0); calc! {{ double(y) == double(x) by {{ double_eq(y, x); }}; }} }}\n");
    let e = fails(&src);
    assert!(e.contains("`calc!` proves") && e.contains("first and last terms"), "{e}");
    let e = rejected(&format!("{CALC}#[cfg(sandblaster)] #[lemma] fn chain(x: u8) {{ ensures(double(x) >= 0); calc! {{ double(x) }} }}\n"));
    assert!(e.contains("cannot parse `calc!`"), "{e}");
}

// ---------------------------------------------------------------------------
// review fixes: what the restricted closers may use, and block ends
// ---------------------------------------------------------------------------

/// The elaborator's warnings (the front end's are in [`warnings`]).
fn elab_warnings(c: &Checked, v: &Verification) -> Vec<String> {
    v.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| d.render(&c.sm)).collect()
}

const CALLS: &str = r#"
pub fn f0(x: u8) -> u8 { x }
#[cfg(sandblaster)] #[spec] fn g(x: u8) -> Int { 2 * (x as Int) }
#[cfg(sandblaster)] #[spec] fn f(x: u8) -> Int { g(x) + 1 }
pub fn join(h: u8, t: Option<u8>) -> Option<u8> { match t { None => Some(h), Some(d) => Some(d) } }
pub fn back(xs: &[u8]) -> Option<u8> { match xs { [] => None, [h, ..] => Some(*h) } }
pub fn mix(a: u8, b: u8) -> u8 { a ^ b }
pub fn top(n: usize, xs: &[u8], acc: u8) -> Option<u8> {
    if n == 0 {
        return join(acc, back(xs));
    }
    match xs {
        [] => None,
        [h, tail @ ..] => top(n - 1, tail, mix(acc, *h)),
    }
}
"#;

#[test]
fn by_unfolding_keeps_what_the_named_definitions_call_unknown() {
    // `f` calls `g`: unfolding `f` exposes `g(x)`, which stays unknown
    let e = fails(&format!("{CALLS}#[cfg(sandblaster)] #[lemma] fn a(x: u8) {{ ensures(f(x) == 2 * (x as Int) + 1); by_unfolding(f); }}\n"));
    assert!(e.contains("treated as unknown functions: `g`") && e.contains("name them: `by_unfolding(f, g)`"), "{e}");
    verified(&format!("{CALLS}#[cfg(sandblaster)] #[lemma] fn a(x: u8) {{ ensures(f(x) == 2 * (x as Int) + 1); by_unfolding(f, g); }}\n"));
    // a goal about `g` alone: naming `f` does not unfold `g` (and `f` is
    // reported as not needed)
    let (c, v) = verify(&format!("{CALLS}#[cfg(sandblaster)] #[lemma] fn b(x: u8) {{ ensures(g(x) == 2 * (x as Int)); by_unfolding(f); }}\n"));
    assert!(!v.proofs_ok);
    assert!(elab_warnings(&c, &v).iter().any(|m| m.contains("`f` does not occur in the goal")), "{:?}", elab_warnings(&c, &v));
    // a recursive definition: the functions it calls stay unknown as well
    let e = fails(&format!("{CALLS}#[cfg(sandblaster)] #[lemma] fn base(acc: u8) {{ ensures(top(0, &[], acc) == Some(acc)); by_unfolding(top); }}\n"));
    // (the candidates: every function the step sees, `mix` included)
    assert!(e.contains("treated as unknown functions: `join`, `back`, `mix`") && e.contains("by_unfolding(top, join, back, mix)"), "{e}");
    verified(&format!("{CALLS}#[cfg(sandblaster)] #[lemma] fn base(acc: u8) {{ ensures(top(0, &[], acc) == Some(acc)); by_unfolding(top, join, back); }}\n"));
    // one step of `top`: `mix` is unknown, the same on both sides
    let (_, v) = verified(&format!(
        "{CALLS}#[cfg(sandblaster)] #[lemma] fn order(n: usize, h: u8, t: &[u8], acc: u8) {{ requires(n < usize::MAX && (t.len() as Int) < ISIZE_MAX); ensures(top(n + 1, seq::cons(h, t), acc) == top(n, t, mix(acc, h))); by_unfolding(top); }}\n"
    ));
    assert!(v.obligations.iter().any(|o| matches!(&o.status, sandblaster_front::elab::OblStatus::Proven { by } if by == "script(by_unfolding)")));
}

#[test]
fn restricted_closers_treat_functions_without_parameters_as_unknown() {
    // exec code: `seven()` is unknown to `by_arithmetic()`
    let src = "pub fn seven() -> u8 { 7 }\npub fn k7(x: u8) -> u8 { let s = seven(); proof! { assert(s == 7, { by_arithmetic(); }); } x }\n";
    let e = fails(src);
    assert!(e.contains("treated as unknown functions: `seven`"), "{e}");
    verified(&src.replace("by_arithmetic()", "by_unfolding(seven)"));
    // a spec constant: unknown, and so is what it calls
    let src = format!("{TWICE}#[cfg(sandblaster)] #[spec] fn k() -> Int {{ twice(100) }}\n#[cfg(sandblaster)] #[lemma] fn a() {{ ensures(k() == 200); by_arithmetic(); }}\n");
    let e = fails(&src);
    assert!(e.contains("treated as unknown functions: `k`"), "{e}");
    let e = fails(&src.replace("by_arithmetic()", "by_unfolding(k)"));
    assert!(e.contains("treated as unknown functions: `twice`"), "{e}");
    verified(&src.replace("by_arithmetic()", "by_unfolding(k, twice)"));
}

#[test]
fn unfold_changes_only_the_calls_it_names() {
    let defs = r#"
pub fn rd(xs: &[u8]) -> Option<(u8, &[u8])> { match xs { [] => None, [h, t @ ..] => Some((*h, t)) } }
pub fn dbl(x: u8) -> u16 { (x as u16) * 2 }
#[cfg(sandblaster)] #[spec] fn tri(n: u32) -> Int { if n == 0 { 0 } else { (n as Int) + tri(n - 1) } }
"#;
    // an opaque reader and a recursive function that the goal does not
    // mention: `unfold` leaves the goal as it is (and says so), so
    // `by_arithmetic()` still treats `dbl` as unknown
    for f in ["rd", "tri"] {
        let (c, v) = verify(&format!("{defs}#[cfg(sandblaster)] #[lemma] fn b(x: u8) {{ ensures(dbl(x) <= 510); unfold({f}); by_arithmetic(); }}\n"));
        assert!(!v.proofs_ok, "{f}");
        assert!(elab_warnings(&c, &v).iter().any(|m| m.contains("`unfold`: no application of this function in the goal")), "{f}: {:?}", elab_warnings(&c, &v));
        let e: Vec<String> = v.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| d.render(&c.sm)).collect();
        assert!(e.iter().any(|m| m.contains("treated as unknown functions: `dbl`")), "{f}: {e:?}");
    }
    // an opaque reader applied in the goal: one `delta` step on the goal term
    verified(&format!("{defs}#[cfg(sandblaster)] #[lemma] fn r() {{ ensures(rd(&[]) == None); unfold(rd); by_computation(); }}\n"));
}

#[test]
fn block_ends_without_a_closing_statement_warn() {
    let lemmas = r#"
#[cfg(sandblaster)] #[lemma] fn mono(a: u8, b: u8) { requires(a <= b); ensures(twice(a) <= twice(b)); by_unfolding(twice); }
"#;
    // the lemma's conclusion is the goal: no warning
    let src = format!("{TWICE}{lemmas}#[cfg(sandblaster)] #[lemma] fn m(x: u8, y: u8) {{ requires(x <= y); ensures(twice(x) <= twice(y)); apply(mono); }}\n");
    let (c, v) = verified(&src);
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
    // one more step of reasoning after it: a warning, until the block says why
    let src = format!("{TWICE}{lemmas}#[cfg(sandblaster)] #[lemma] fn m(x: u8, y: u8) {{ requires(x <= y); ensures(twice(x) + 1 <= twice(y) + 1); apply(mono); }}\n");
    let (c, v) = verified(&src);
    let w = elab_warnings(&c, &v);
    assert!(w.iter().any(|m| m.contains("the block ends without a closing statement") && m.contains("write `follows();`")), "{w:?}");
    let (c, v) = verified(&src.replace("apply(mono); }", "apply(mono); by_arithmetic(); }"));
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
    // after `witness`
    let src = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn w(x: u8) { requires(x < 10); ensures(exists(|y: u8| y < 20 && y > x)); witness(x + 1); }\n";
    let (c, v) = verified(src);
    assert!(elab_warnings(&c, &v).iter().any(|m| m.contains("the block ends without a closing statement")), "{:?}", elab_warnings(&c, &v));
    let (c, v) = verified(&src.replace("witness(x + 1); }", "witness(x + 1); by_arithmetic(); }"));
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
    // a goal closed by evaluation after a `rewrite`: no warning
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn n(o: Option<u8>) {{ requires(o == None); ensures(get(o) == 0); rewrite(o == None); }}\n");
    let (c, v) = verified(&src);
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
    // `calc!` links without `by`: a link given by a fact is fine, one that
    // needs reasoning warns
    let src = "pub fn f(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] fn ch(a: u8, b: u8, c: u8) { requires(a <= b); requires(b < c); ensures((a as Int) + 1 <= (c as Int)); calc! { (a as Int) + 1 <= (b as Int) + 1; <= (c as Int); } }\n";
    let (c, v) = verified(src);
    let w = elab_warnings(&c, &v);
    assert!(w.iter().filter(|m| m.contains("`calc!` link without `by`") && m.contains("by { follows(); }")).count() == 2, "{w:?}");
    let (c, v) = verified(&src.replace("(b as Int) + 1; <= (c as Int);", "(b as Int) + 1 by { by_arithmetic(); }; <= (c as Int) by { by_arithmetic(); };"));
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
    // `by_cases` names the split; its cases are closed by the automation
    let src = format!("{CODE}#[cfg(sandblaster)] #[lemma] fn and_left(a: bool, b: bool) {{ requires((a && b) == true); ensures(a); by_cases(a); }}\n");
    let (c, v) = verified(&src);
    assert!(elab_warnings(&c, &v).is_empty(), "{:?}", elab_warnings(&c, &v));
}

#[test]
fn a_user_lemma_named_eq_sound_is_not_a_built_in_rule() {
    // `c || !c` needs a case split: `by_arithmetic()` rejects it, whatever
    // the crate's lemmas are called
    for name in ["eq_sound", "excluded_middle"] {
        let src = format!("pub fn f0(x: u8) -> u8 {{ x }}\n#[cfg(sandblaster)] #[lemma] fn {name}(b: bool) {{ ensures(b || !b); by_cases(b); }}\n#[cfg(sandblaster)] #[lemma] fn use_it(c: bool) {{ ensures(c || !c); by_arithmetic(); }}\n");
        let e = fails(&src);
        assert!(e.contains("case split"), "{name}: {e}");
    }
}

#[test]
fn by_arithmetic_substitutes_equal_arguments_into_predicates() {
    // `small` is unknown, but `x == y` makes `small(x)` and `small(y)` the same
    let src = "pub fn f0(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[spec] fn small(x: u8) -> Prop { x < 10 }\n#[cfg(sandblaster)] #[lemma] fn p(x: u8, y: u8) { requires(small(x)); requires(x == y); ensures(small(y)); by_arithmetic(); }\n";
    verified(src);
}

// ---------------------------------------------------------------------------
// old forms
// ---------------------------------------------------------------------------

#[test]
fn old_forms_still_work() {
    let src = format!(
        r#"{CODE}
#[cfg(sandblaster)] #[lemma] fn and_left(a: bool, b: bool) {{ requires((a && b) == true); ensures(a); if a {{ }} else {{ }} }}
#[cfg(sandblaster)] #[lemma] fn get_none(o: Option<u8>) {{ requires(o == None); ensures(get(o) == 0); match o {{ None => {{}} Some(_) => {{}} }} }}
#[cfg(sandblaster)] #[lemma] fn small_square(k: u8) {{ requires(k < 4); ensures((k as Int) * (k as Int) <= 9); cases(k, 0..4, {{}}); }}
"#
    );
    let (c, _) = verified(&src);
    // accepted, with warnings that point to the new statements
    let w = warnings(&c);
    assert!(w.iter().any(|m| m.contains("follows();")), "{w:?}");
    assert!(w.iter().any(|m| m.contains("by_cases(k, ..)")), "{w:?}");
}
