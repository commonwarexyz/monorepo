//! Ghost code (DESIGN.md §4, SEMANTICS.md §12–§13): spec functions,
//! lemmas, laws with proof items, `ensures`, `proof!` asserts and script
//! steps, through the verified pipeline (ghost items included, as in the
//! build).

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use util::{explain, status_of};

fn full(files: &[(&str, &str)]) -> (Checked, Verification) {
    let c = util::check_files(files);
    assert!(c.ok(), "front end rejected:\n{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Basic, exec_only: false });
    (c, v)
}

fn single(src: &str) -> (Checked, Verification) {
    full(&[("r/mod.rs", src)])
}

#[track_caller]
fn assert_all_verified(c: &Checked, v: &Verification) {
    assert!(v.proofs_ok, "not verified:\n{}", explain(c, v));
}

#[test]
fn spec_functions_and_lemmas() {
    let (c, v) = single(
        r#"
#[cfg(sandblaster)] #[spec] fn twice(x: u8) -> Int { 2 * (x as Int) }
#[cfg(sandblaster)] #[lemma] fn twice_le(x: u8) { ensures(twice(x) <= 510); }
#[cfg(sandblaster)] #[lemma] fn twice_mono(a: u8, b: u8) { requires(a <= b); ensures(twice(a) <= twice(b)); }
pub fn f(x: u8) -> u8 { x }
"#,
    );
    assert_all_verified(&c, &v);
    assert_eq!(status_of(&v, "crate::twice"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::twice_le"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::twice_mono"), &DefStatus::Checked);
}

#[test]
fn spec_function_in_a_requires() {
    let (c, v) = single(
        r#"
#[cfg(sandblaster)] #[spec] fn room(x: u32) -> Int { 100 - (x as Int) }
#[requires(room(x) > 0)]
fn inc(x: u32) -> u32 { x + 1 }
pub fn g(y: u32) -> u32 { if y < 50 { inc(y) } else { 0 } }
"#,
    );
    assert_all_verified(&c, &v);
}

#[test]
fn laws_with_proof_items() {
    let root = "pub fn double(x: u8) -> u16 { x as u16 * 2 }\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n";
    let laws = "use sandblaster::prelude::*;\nuse super::double;\n#[law] fn double_exact(x: u8) { ensures((double(x) as Int) == 2 * (x as Int)); }\n#[law] fn double_mono(a: u8, b: u8) { requires(a <= b); ensures(double(a) <= double(b)); }\n";
    let proofs = "use sandblaster::prelude::*;\nuse super::double;\n#[proof] fn double_exact(x: u8) { }\n#[proof] fn double_mono(a: u8, b: u8) { double_exact(a); double_exact(b); }\n";
    let (c, v) = full(&[("r/mod.rs", root), ("r/LAWS.rs", laws), ("r/PROOF.rs", proofs)]);
    assert_all_verified(&c, &v);
    assert_eq!(v.laws.len(), 2, "{:?}", v.laws);
    assert!(v.laws.iter().all(|l| l.status == DefStatus::Checked), "{:?}", v.laws);
}

#[test]
fn ensures_of_exec_functions() {
    let (c, v) = single(
        r#"
#[ensures(|r: u16| (r as Int) == (x as Int) + 1)]
pub fn inc(x: u8) -> u16 { x as u16 + 1 }
"#,
    );
    assert_all_verified(&c, &v);
    assert_eq!(status_of(&v, "crate::inc::ensures"), &DefStatus::Checked);
}

#[test]
fn proof_blocks_add_facts() {
    let (c, v) = single(
        r#"
pub fn f(x: u8, y: u8) -> u16 {
    let s = x as u16 + y as u16;
    proof! { assert(s <= 510); }
    s + 1
}
"#,
    );
    assert_all_verified(&c, &v);
}

#[test]
fn script_case_analysis() {
    let (c, v) = single(
        r#"
#[cfg(sandblaster)] #[lemma] fn cases_small(x: u8) {
    requires(x < 3);
    ensures((x as Int) * (x as Int) <= 4);
    cases(x, 0u8..3, { });
}
#[cfg(sandblaster)] #[lemma] fn split(b: bool, x: u8) {
    ensures((if b { x } else { 0 }) <= x);
    if b { } else { }
}
pub fn f(x: u8) -> u8 { x }
"#,
    );
    assert_all_verified(&c, &v);
}

#[test]
fn ensures_through_branches_and_at_call_sites() {
    let (c, v) = single(
        r#"
#[ensures(|r: u8| r <= 10)]
fn clamp(x: u8) -> u8 { if x > 10 { 10 } else { x } }
#[ensures(|r: u8| r <= 20)]
fn pick(o: Option<u8>) -> u8 {
    match o {
        Some(x) if x < 20 => x,
        Some(_) => 20,
        None => return 0,
    }
}
pub fn use_it(x: u8, o: Option<u8>) -> u8 { clamp(x) + pick(o) + 200 }
"#,
    );
    assert_all_verified(&c, &v);
    assert_eq!(status_of(&v, "crate::clamp::ensures"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::pick::ensures"), &DefStatus::Checked);
}

#[test]
fn ensures_of_recursive_functions_by_induction() {
    let (c, v) = single(
        r#"
#[ensures(|r: u32| (r as Int) <= (acc as Int) + (n as Int))]
pub fn cnt(n: u32, acc: u32) -> u32 { if n == 0 { acc } else { cnt(n - 1, acc.saturating_add(1)) } }
#[requires(n <= 20)]
#[decreases(n, max = 20)]
#[ensures(|r: u64| (r as Int) <= 2 * (n as Int))]
fn twice(n: u32) -> u64 { if n == 0 { 0 } else { twice(n - 1).wrapping_add(2) } }
pub fn use_twice(n: u32) -> u64 { if n <= 20 { twice(n) + 1 } else { 0 } }
"#,
    );
    assert_all_verified(&c, &v);
    assert_eq!(status_of(&v, "crate::cnt::ensures"), &DefStatus::Checked);
    assert_eq!(status_of(&v, "crate::twice::ensures"), &DefStatus::Checked);
}

#[test]
fn derived_partial_eq_is_sound_and_complete() {
    let (c, v) = single(
        r#"
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P { pub x: u32, pub y: bool, pub d: [u8; 4] }
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum E { A, B(u16, P), C { k: u8 } }
pub fn same(a: E, b: E) -> bool { a == b }
"#,
    );
    assert_all_verified(&c, &v);
    for name in ["crate::P::eq", "crate::P::eq_sound", "crate::P::eq_complete", "crate::E::eq", "crate::E::eq_sound", "crate::E::eq_complete"] {
        assert_eq!(status_of(&v, name), &DefStatus::Checked, "{name}");
    }
}
