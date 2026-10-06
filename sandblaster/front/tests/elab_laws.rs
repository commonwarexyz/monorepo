//! The script machinery law proofs rely on, on small programs (the
//! features the former QMDB fixture's proofs used): prelude lemma paths
//! (`sandblaster::lemmas::..`, glob imports), refinement of a slice
//! variable, term-level `unfold`/`rewrite(a == b)`, a `match` on a
//! non-variable scrutinee that occurs in the goal, codec readers opaque in
//! proofs. (A large crate whose laws verify, and a false law that does
//! not: `tests/verified_roots.rs` on the MMR; a wrong implementation that
//! breaks its refinement: `tests/spec15_refines.rs`,
//! `tests/spec15_worked.rs`.)

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use util::explain;

// ---------------------------------------------------------------------------
// the proof features, on small programs
// ---------------------------------------------------------------------------

fn full(files: &[(&str, &str)]) -> (Checked, Verification) {
    let c = util::check_files(files);
    assert!(c.ok(), "front end rejected:\n{}", c.render());
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (c, v)
}

#[track_caller]
fn assert_all_verified(c: &Checked, v: &Verification) {
    assert!(v.proofs_ok, "not verified:\n{}", explain(c, v));
}

#[test]
fn prelude_lemmas_by_path_and_glob_import() {
    let root = "pub fn same(a: [u8; 4], b: [u8; 4]) -> bool { a == b }\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n";
    let laws = "use sandblaster::prelude::*;\nuse super::same;\n#[law] fn same_sound(a: [u8; 4], b: [u8; 4]) { requires(same(a, b)); ensures(a == b); }\n#[law] fn same_sound2(a: [u8; 4], b: [u8; 4]) { requires(same(a, b)); ensures(b == a); }\n";
    let proofs = "use sandblaster::prelude::*;\nuse sandblaster::lemmas::array::*;\n#[proof] fn same_sound(a: [u8; 4], b: [u8; 4]) { sandblaster::lemmas::array::eq_sound_u8(4, a, b); }\n#[proof] fn same_sound2(a: [u8; 4], b: [u8; 4]) { eq_sound_u8(4, a, b); }\n";
    let (c, v) = full(&[("r/mod.rs", root), ("r/LAWS.rs", laws), ("r/PROOF.rs", proofs)]);
    assert_all_verified(&c, &v);
    assert!(v.laws.iter().all(|l| l.status == DefStatus::Checked), "{:?}", v.laws);
}

#[test]
fn slice_refinement_in_lemmas() {
    let src = r#"
pub fn first_or_zero(xs: &[u8]) -> u8 {
    match xs {
        [] => 0,
        [h, ..] => *h,
    }
}
#[cfg(sandblaster)]
#[lemma]
fn empty_is_zero(xs: &[u8]) {
    requires(xs.len() == 0);
    ensures(first_or_zero(xs) == 0);
    match xs {
        [] => {}
        [h, t @ ..] => {}
    }
}
#[cfg(sandblaster)]
#[lemma]
fn cons_is_head(h: u8, t: &[u8]) {
    requires((t.len() as Int) < ISIZE_MAX);
    ensures(first_or_zero(seq::cons(h, t)) == h);
}
"#;
    let (c, v) = full(&[("r/mod.rs", src)]);
    assert_all_verified(&c, &v);
}

#[test]
fn term_level_unfold_rewrite_and_match() {
    // `wrap` is transparent; its goal is handled on the term: `unfold`
    // exposes the match on `pick(x)`, `rewrite(pick(x) == None)` replaces
    // it, and a `match pick(x)` generalizes its occurrence in the goal
    let src = r#"
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
fn wrap_none(x: u32) {
    requires(pick(x) == None);
    ensures(wrap(x) == false);
    unfold(wrap);
    rewrite(pick(x) == None);
}
#[cfg(sandblaster)]
#[lemma]
fn pick_small(x: u32, v: u32) {
    requires(x <= 13);
    requires(pick(x) == Some(v));
    ensures(v <= 3);
    if x > 10 {
    } else {
    }
}
#[cfg(sandblaster)]
#[lemma]
fn wrap_small(x: u32) {
    requires(x <= 13);
    ensures(wrap(x) == false);
    unfold(wrap);
    match pick(x) {
        None => {}
        Some(v) => {
            pick_small(x, v);
        }
    }
}
"#;
    let (c, v) = full(&[("r/mod.rs", src)]);
    assert_all_verified(&c, &v);
}

#[test]
fn codec_readers_are_opaque_in_proofs() {
    let src = r#"
pub fn byte(xs: &[u8]) -> Option<(u8, &[u8])> {
    match xs {
        [] => None,
        [h, t @ ..] => Some((*h, t)),
    }
}
pub fn head_or(xs: &[u8], d: u8) -> u8 {
    match byte(xs) {
        None => d,
        Some((b, _)) => b,
    }
}
"#;
    let c = util::accepted(src);
    let k = c.krate.as_ref().unwrap();
    let opaque = driver::stage::with_elaboration(k, &VerifyOptions { provers: ProverSet::Basic, exec_only: true }, |out| {
        let g = |n: &str| out.env.global_opaque(out.env.lookup_global(n).unwrap_or_else(|| panic!("no {n}"))).unwrap();
        (g("crate::byte"), g("crate::head_or"))
    });
    assert_eq!(opaque, (true, false), "`byte` is a reader (opaque), `head_or` is not");
}
