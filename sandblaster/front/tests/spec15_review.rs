//! §15 S1 review fixes (regressions): the automation that composes
//! refinements (Nat parameters, `%` and truncation, symbolic indices into
//! slices and arrays, callee refinements under path equations, facts of an
//! unfolded body in proof items), the `error[refines-unproven]` shape,
//! placeholders of failed definitions never judged by examples or
//! refinement goals, fuel detection under `#[decreases]`, vector-file
//! parsing and diagnostics.

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::elab::examples::ClosureKind;
use util::*;

// ---------------------------------------------------------------------
// a spec fn with a `Nat` parameter does not block automation
// ---------------------------------------------------------------------

#[test]
fn a_nat_parameter_guard_is_transparent_to_automation() {
    // the `Nat` guard of `pick` is `0 ≤ i`, the same term as the side
    // condition of `s[i]`: a case split on the guard keeps that proof
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn pick(s: Seq<u8>, i: Nat) -> Nat { if i < s.len() { s[i] as Nat } else { 0 } }
#[cfg(sandblaster)] #[spec] fn pick_int(s: Seq<u8>, i: Int) -> Nat { if 0 <= i && i < s.len() as Int { s[i as Nat] as Nat } else { 0 } }

#[cfg(sandblaster)]
#[lemma]
fn pick_is_index(xs: Seq<u8>, i: Nat) {
    requires(i < xs.len());
    ensures(pick(xs, i) == xs[i] as Nat);
    follows();
}

#[cfg(sandblaster)]
#[lemma]
fn pick_int_is_index(xs: Seq<u8>, i: Nat) {
    requires(i < xs.len());
    ensures(pick_int(xs, i as Int) == xs[i] as Nat);
    follows();
}
"#,
    );
    assert!(r.checked_defs.iter().any(|d| d == "crate::pick_is_index"), "{}", r.explain());
}

#[test]
fn byte_at_a_symbolic_index_refines_over_nat_and_int() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn at_nat(xs: Seq<u8>, i: Nat) -> Option<Nat> { if i < xs.len() { Some(xs[i] as Nat) } else { None } }
#[cfg(sandblaster)] #[spec] fn at_int(xs: Seq<u8>, i: Int) -> Option<Nat> { if 0 <= i && i < xs.len() as Int { Some(xs[i as Nat] as Nat) } else { None } }

#[refines(at_nat)]
pub fn byte_nat(xs: &[u8], i: usize) -> Option<u8> { if i < xs.len() { Some(xs[i]) } else { None } }

#[refines(at_int(xs, i as Int))]
pub fn byte_int(xs: &[u8], i: usize) -> Option<u8> { if i < xs.len() { Some(xs[i]) } else { None } }
"#,
    );
    for f in ["crate::byte_nat", "crate::byte_int"] {
        let x = r.refinement(f);
        assert!(x.checked && x.proof == "walk", "{f}: {}", r.explain());
    }
}

// ---------------------------------------------------------------------
// `%` and truncation relate machine words to `Nat`/`Int`
// ---------------------------------------------------------------------

#[test]
fn remainder_and_truncation_refine_nat_specs() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn mod2(x: Nat) -> Nat { x % 2 }
#[cfg(sandblaster)] #[spec] fn lo_byte(x: Nat) -> Nat { x % 256 }
#[cfg(sandblaster)] #[spec] fn div2(x: Nat) -> Nat { x / 2 }

#[refines(mod2)]
pub fn m2(x: u32) -> u32 { x % 2 }

#[refines(lo_byte)]
pub fn lb(x: u32) -> u8 { (x & 0xff) as u8 }

#[refines(lo_byte)]
pub fn lb_cast(x: u32) -> u8 { x as u8 }

#[refines(div2)]
pub fn d2(x: u32) -> u32 { x / 2 }

#[cfg(sandblaster)]
#[lemma]
fn rem_cast(x: u32) {
    ensures(((x % 10u32) as Int) == (x as Int) % 10);
    follows();
}
"#,
    );
    for f in ["crate::m2", "crate::lb", "crate::lb_cast", "crate::d2"] {
        assert!(r.refinement(f).checked, "{f}: {}", r.explain());
    }
    assert!(r.checked_defs.iter().any(|d| d == "crate::rem_cast"));
}

// ---------------------------------------------------------------------
// loops over slices and arrays refining recursive `Seq` specs
// ---------------------------------------------------------------------

const SUM_SPEC: &str = r#"
#[cfg(sandblaster)]
#[spec]
#[decreases(n)]
#[example(sum_to(seq![1u8, 2u8, 3u8], 2) == 3)]
fn sum_to(xs: Seq<u8>, n: Nat) -> Nat {
    if n == 0 || n > xs.len() { 0 } else { sum_to(xs, n - 1) + (xs[n - 1] as Nat) }
}
"#;

#[test]
fn a_loop_over_a_slice_refines_a_recursive_seq_spec() {
    // the invariant at `i + 1` reads `sum_to(xs, (i +ᵤ 1) as Nat)`, the
    // unfolding fact `sum_to(xs, (i as Nat) + 1)`: joined by atom congruence
    let r = verifies(&format!(
        "{SUM_SPEC}{}",
        r#"
#[refines(sum_to(xs, n as Nat))]
#[requires(n <= xs.len() && n <= 1000)]
fn sum_slice(xs: &[u8], n: usize) -> u32 {
    let mut s: u32 = 0;
    for i in 0..n {
        proof! { invariant((s as Int) == sum_to(xs, i as Nat)); invariant((s as Int) <= 255 * (i as Int)); }
        proof! { assert(sum_to(xs, (i as Nat) + 1) == sum_to(xs, i as Nat) + (xs[i] as Nat)); }
        s += xs[i] as u32;
    }
    s
}

pub fn total(xs: &[u8; 16]) -> u32 { sum_slice(xs, 16) }
"#
    ));
    assert!(r.refinement("crate::sum_slice").checked, "{}", r.explain());
}

#[test]
fn a_loop_over_an_array_refines_a_recursive_seq_spec() {
    let r = verifies(&format!(
        "{SUM_SPEC}{}",
        r#"
#[refines(sum_to(xs, n as Nat))]
#[requires(n <= 16)]
fn sum_array(xs: &[u8; 16], n: usize) -> u32 {
    let mut s: u32 = 0;
    for i in 0..n {
        proof! { invariant((s as Int) == sum_to(xs, i as Nat)); invariant((s as Int) <= 255 * (i as Int)); invariant(i <= 16); }
        proof! { assert(sum_to(xs, (i as Nat) + 1) == sum_to(xs, i as Nat) + (xs[i] as Nat)); }
        s += xs[i] as u32;
    }
    s
}

pub fn total(xs: &[u8; 16]) -> u32 { sum_array(xs, 16) }
"#
    ));
    assert!(r.refinement("crate::sum_array").checked, "{}", r.explain());
}

// ---------------------------------------------------------------------
// refinements compose
// ---------------------------------------------------------------------

#[test]
fn a_function_composing_refined_callees_refines_by_the_walk() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn half(x: Nat) -> Option<Nat> { if x % 2 == 0 { Some(x / 2) } else { None } }
#[cfg(sandblaster)] #[spec] fn quarter(x: Nat) -> Option<Nat> { match half(x) { None => None, Some(y) => half(y) } }
#[cfg(sandblaster)] #[spec] fn first(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> { if xs.len() == 0 { None } else { Some((xs[0] as Nat, xs.skip(1))) } }
#[cfg(sandblaster)] #[spec] fn second(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> { match first(xs) { None => None, Some((_, rest)) => first(rest) } }

#[refines(half)]
pub fn half_x(x: u32) -> Option<u32> { if x % 2 == 0 { Some(x / 2) } else { None } }

#[refines(quarter)]
pub fn quarter_x(x: u32) -> Option<u32> { match half_x(x) { None => None, Some(y) => half_x(y) } }

#[refines(first)]
pub fn first_x(xs: &[u8]) -> Option<(u8, &[u8])> { if xs.is_empty() { None } else { Some((xs[0], &xs[1..])) } }

#[refines(second)]
pub fn second_x(xs: &[u8]) -> Option<(u8, &[u8])> { match first_x(xs) { None => None, Some((_, rest)) => first_x(rest) } }
"#,
    );
    for f in ["crate::quarter_x", "crate::second_x"] {
        assert!(r.refinement(f).checked, "{f}: {}", r.explain());
    }
}

const CODEC_SPEC: &str = r#"
#[cfg(sandblaster)]
#[spec]
fn read_u16(xs: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    if xs.len() < 2 { None } else { Some(((xs[0] as Nat) * 256 + (xs[1] as Nat), xs.skip(2))) }
}

#[cfg(sandblaster)]
#[spec]
fn read_bytes(xs: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> {
    match read_u16(xs) {
        None => None,
        Some((n, rest)) => if rest.len() < n { None } else { Some((rest.take(n), rest.skip(n))) },
    }
}

/// A big-endian u16 and the rest (a codec reader: opaque in proofs).
#[refines(read_u16)]
pub fn read_u16_x(xs: &[u8]) -> Option<(u16, &[u8])> {
    if xs.len() < 2 { None } else { Some((u16::from_be_bytes([xs[0], xs[1]]), &xs[2..])) }
}

/// A length-prefixed byte string and the rest.
#[refines(read_bytes)]
pub fn read_bytes_x(xs: &[u8]) -> Option<(&[u8], &[u8])> {
    match read_u16_x(xs) {
        None => None,
        Some((n, rest)) => {
            let n = n as usize;
            if rest.len() < n {
                None
            } else {
                let (body, tail) = rest.split_at(n);
                Some((body, tail))
            }
        }
    }
}

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const CODEC_PROOF: &str = r#"use sandblaster::prelude::*;

#[lemma]
fn be16(a: u8, b: u8) {
    ensures(u16::from_be_bytes([a, b]) == (a as u16) * 256u16 + (b as u16));
    bv();
}

#[proof(refines = crate::read_u16_x)]
fn read_u16_x(xs: &[u8]) {
    unfold(crate::read_u16_x);
    if xs.len() < 2 {
        follows();
    } else {
        be16(xs[0], xs[1]);
        follows();
    }
}
"#;

#[test]
fn a_decoder_composing_a_refined_sub_decoder_refines_by_the_walk() {
    // the walk derives `spec::read_u16(xs) = α(C(v̄))` from the callee's
    // refinement under each path equation, and selects the arm of the
    // `split_at` tuple (its fields are the prefix and suffix)
    let r = verifies_files(&[("r/mod.rs", CODEC_SPEC), ("r/PROOF.rs", CODEC_PROOF)]);
    let f = r.refinement("crate::read_bytes_x");
    assert!(f.checked && f.proof == "walk", "{}", r.explain());
}

#[test]
fn unfold_in_a_proof_item_brings_the_body_facts_into_scope() {
    // after `unfold(f)` the call-site facts of `f`'s body (the callee's
    // refinement `h_ref`) are facts of the script, not hidden in the goal
    let proof = format!(
        "{CODEC_PROOF}{}",
        r#"
#[proof(refines = crate::read_bytes_x)]
fn read_bytes_x(xs: &[u8]) {
    unfold(crate::read_bytes_x);
    if xs.len() < 2 {
        assert(crate::read_u16_x(xs) == None);
        follows();
    } else {
        follows();
    }
}
"#
    );
    let r = run_files(&[("r/mod.rs", CODEC_SPEC), ("r/PROOF.rs", &proof)]);
    // the assert is proven from the hoisted `h_ref` (and `unfold` warns
    // about nothing: the unfolded body is in the goal)
    assert!(!r.unproven.iter().any(|(d, k, _)| d == "crate::read_bytes_x::refines" && k == "assert"), "{}", r.explain());
    assert!(!r.warnings.iter().any(|(k, m)| *k == K::Script && m.contains("no application")), "{:?}", r.warnings);
}

// ---------------------------------------------------------------------
// error[refines-unproven]
// ---------------------------------------------------------------------

#[test]
fn an_unproven_refinement_is_one_refines_unproven_error_in_surface_syntax() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn at(xs: Seq<u8>, i: Nat) -> Option<Nat> { if i < xs.len() { Some(xs[i] as Nat) } else { None } }
#[cfg(sandblaster)] #[spec] fn mix(a: u32, b: u32) -> u32 { a.rotate_left(5) ^ b }

#[refines(at)]
pub fn at_x(xs: &[u8], i: usize) -> Option<u8> {
    if i < xs.len() { Some(xs[i]) } else if i == xs.len() { Some(0) } else { None }
}

#[refines(mix)]
pub fn mix_x(a: u32, b: u32) -> u32 { a.rotate_left(3) ^ b }
"#,
    );
    let errs: Vec<&String> = r.errors.iter().filter(|(k, _)| *k == K::RefinesUnproven).map(|(_, m)| m).collect();
    assert_eq!(errs.len(), 2, "one error per refinement lemma:\n{}", r.rendered);
    assert!(r.has_error(K::RefinesUnproven, "`crate::at_x` is not proven to refine `crate::at`: 1 of 3 branch(es) unproven"), "{}", r.rendered);
    assert!(!r.errors.iter().any(|(k, m)| *k == K::Obligation && m.contains("[refines]")), "the branch errors are folded into it:\n{}", r.rendered);
    // the goal and the branch's path conditions in surface syntax
    assert!(r.rendered.contains("goal: match Some(0u8) {") && r.rendered.contains("crate::at(xs, (i as Int))"), "{}", r.rendered);
    assert!(r.rendered.contains("(i == xs.len()) (path)"), "{}", r.rendered);
    assert!(r.rendered.contains("add `#[proof(refines = crate::at_x)]` in PROOF.rs"), "{}", r.rendered);
    // word arithmetic suggests `bv()`
    assert!(r.rendered.contains("u32::rotate_left(a, 3u32) ^ b") && r.rendered.contains("ending in `bv()`"), "{}", r.rendered);
}

#[test]
fn a_false_bv_step_names_the_first_differing_element() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn two(a: u32, b: u32) -> [u32; 3] { [a ^ b, a.rotate_left(7), b] }

#[refines(two)]
pub fn two_x(a: u32, b: u32) -> [u32; 3] { [a ^ b, a.rotate_left(8), b] }

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#,
        ),
        ("r/PROOF.rs", "use sandblaster::prelude::*;\n#[proof(refines = crate::two_x)]\nfn two_x(a: u32, b: u32) { unfold(crate::two_x); bv(); }\n"),
    ]);
    assert!(!r.verified);
    assert!(r.rendered.contains("`bv()`: result element 1 (of 3) differs"), "{}", r.rendered);
}

// ---------------------------------------------------------------------
// placeholders of failed definitions are never judged
// ---------------------------------------------------------------------

#[test]
fn an_example_through_a_failed_definition_is_not_checked_not_false() {
    let r = fails(
        r#"
#[cfg(sandblaster)]
#[spec]
#[example(first_plus7(seq![1u8, 2u8]) == 8)]
fn first_plus7(xs: Seq<u8>) -> Nat { (xs[0] as Nat) + 7 }
"#,
    );
    assert!(r.has_error(K::Example, "example #0 of `crate::first_plus7` was not checked: it depends on `crate::first_plus7`, which did not verify"), "{}", r.rendered);
    assert!(!r.errors.iter().any(|(k, m)| *k == K::Example && m.contains("is false")), "{}", r.rendered);
    assert!(!r.rendered.contains("evaluates to: 0"), "{}", r.rendered);
}

#[test]
fn a_refinement_through_a_failed_function_is_not_checked() {
    let r = fails(
        r#"
#[cfg(sandblaster)] #[spec] fn count(n: Nat) -> Nat { n }

#[refines(count)]
pub fn count_x(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c == i + 1); }
        c += 1;
    }
    c
}
"#,
    );
    assert!(r.has_error(K::Elab, "`crate::count_x::refines` was not checked: it depends on"), "{}", r.rendered);
    assert!(!r.errors.iter().any(|(k, _)| *k == K::RefinesUnproven), "no goal about the placeholder:\n{}", r.rendered);
}

// ---------------------------------------------------------------------
// fuel under `#[decreases]`
// ---------------------------------------------------------------------

#[test]
fn a_decreases_on_the_fuel_does_not_hide_a_fuel_bounded_spec() {
    let bounded = run(
        r#"
#[cfg(sandblaster)]
#[spec]
#[decreases(fuel)]
fn peaks(fuel: Nat, size: Nat) -> Nat {
    if fuel == 0 { 0 } else if size == 0 { 0 } else { 1 + peaks(fuel - 1, size / 2) }
}
"#,
    );
    // (a legacy `#[spec] fn` outside a `#[spec]` module: recorded for the
    // §15.8 examples gate, an error inside a spec module)
    let fuel = |r: &Run| r.errors.iter().any(|(k, m)| *k == K::FuelSufficient && m.contains("fuel-bounded (parameter `fuel`)")) || r.closure.iter().any(|(i, k, m)| i == "crate::peaks" && *k == ClosureKind::Fuel && m.contains("fuel-bounded (parameter `fuel`)"));
    assert!(fuel(&bounded), "{}", bounded.explain());
    // a real measure: the countdown parameter is not fuel
    let measured = run(
        r#"
#[cfg(sandblaster)]
#[spec]
#[decreases(xs.len())]
fn nth(xs: Seq<u8>, i: Nat) -> Nat {
    if xs.len() == 0 { 0 } else if i == 0 { xs[0] as Nat } else { nth(xs.skip(1), i - 1) }
}
"#,
    );
    assert!(!measured.errors.iter().any(|(k, _)| *k == K::FuelSufficient), "{}", measured.rendered);
    assert!(!measured.closure.iter().any(|(_, k, _)| *k == ClosureKind::Fuel), "{:?}", measured.closure);
}

// ---------------------------------------------------------------------
// vector files
// ---------------------------------------------------------------------

const KAT_CHECKER: &str = r#"
#[cfg(sandblaster)] #[spec] fn double(x: Nat) -> Nat { 2 * x }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "kat.rsp", format = "cavp", provenance = independent)]
fn double_kat(x: Nat, y: Nat) -> bool { double(x) == y }
"#;

#[test]
fn records_without_a_blank_line_are_an_error_not_merged() {
    let r = run_files(&[("r/mod.rs", KAT_CHECKER), ("r/kat.rsp", "X = 1\nY = 2\n# ----\nX = 2\nY = 999\n# ----\nX = 3\nY = 12345\n")]);
    assert!(r.has_error(K::Example, "vector file `kat.rsp` is malformed: line 4: the key `X` repeats in the record that starts on line 1"), "{}", r.rendered);
}

#[test]
fn case_colliding_json_keys_are_an_error() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn double(x: Nat) -> Nat { 2 * x }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "kat.json", format = "json", provenance = independent)]
fn double_kat(x: Nat, y: Nat) -> bool { double(x) == y }
"#,
        ),
        ("r/kat.json", r#"[ { "x": 1, "y": 2 }, { "x": 2, "X": 3, "y": 4 } ]"#),
    ]);
    assert!(r.has_error(K::Example, "record 1: the keys `x` and `X` collide"), "{}", r.rendered);
}

#[test]
fn a_false_byte_record_shows_its_fields_and_the_first_differing_byte() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn rev(m: Seq<u8>) -> Seq<u8> { m.rev() }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "rev.rsp", format = "cavp", provenance = independent)]
fn rev_kat(msg: Seq<u8>, out: Seq<u8>) -> bool { rev(msg) == out }
"#,
        ),
        ("r/rev.rsp", "Msg = 0102\nOut = 0201\n\nMsg = 0a0b0c\nOut = 0c0a0b\n"),
    ]);
    assert!(r.has_error(K::Example, "vector file `rev.rsp` of `crate::rev_kat`: 1 of 2 record(s) is false (line 4)"), "{}", r.rendered);
    assert!(r.rendered.contains("r/rev.rsp:4:1: error[example]"), "{}", r.rendered);
    assert!(r.rendered.contains("line 4: msg = 0a0b0c, out = 0c0a0b (is false)") || r.rendered.contains("line 4: msg = 0a0b0c, out = 0c0a0b"), "{}", r.rendered);
    assert!(r.rendered.contains("left side evaluates to: hex!(\"0c0b0a\") (3 bytes)"), "{}", r.rendered);
    assert!(r.rendered.contains("first difference: at `[1]`: 11u8 vs 10u8"), "{}", r.rendered);
}

// ---------------------------------------------------------------------
// known-answer evaluation scales linearly
// ---------------------------------------------------------------------

#[test]
fn chunking_a_long_sequence_is_linear_in_the_kernel_evaluator() {
    // 64 KiB in chunks of 64 within a step budget a quadratic chunking
    // (a length test on the rest at every chunk) exceeds many times over
    let opts = sandblaster_front::elab::Options { example_budget: 150_000_000, ..Default::default() };
    let r = run_files_with(
        &[(
            "r/mod.rs",
            r#"
#[cfg(sandblaster)]
#[spec]
#[example(nchunks(Seq::repeat(0u8, 65536)) == 1024)]
#[example(nchunks(Seq::repeat(7u8, 65600)) == 1025)]
fn nchunks(m: Seq<u8>) -> Nat { m.chunks_exact::<64>().len() }
"#,
        )],
        opts,
    );
    let ex: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::nchunks").collect();
    assert_eq!(ex.len(), 2, "{}", r.explain());
    assert!(ex.iter().all(|e| e.checked), "{}", r.explain());
}
