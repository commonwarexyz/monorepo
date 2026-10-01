//! The lift pass (`#[lift(mir = "m.sbmir")] mod m;`, `crate::lift`): plain
//! Rust files checked as written, their bodies read from rustc's MIR (the
//! fixture `mir_fixtures/lift_w`). Sealed-trait generics become one
//! instance per impl type, `&mut self` becomes state passing (`mut self`
//! returning the new state), attachments (`#[lift_attach]`) add contracts
//! from a proof file, `#[lift(unverified = "..")]` leaves named instances
//! out, visibly, and a lifted module without its MIR is refused. Each
//! feature has a positive test and a negative twin.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked, ProverSet, Verification};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::{explain, opts, unproven};

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// A small module in the shape of codec's varint: a sealed trait over two
/// widths, a generic wrapper, a `&mut self` method, `size_of`, `div_ceil`
/// (the MIR fixture `mir_fixtures/lift_w`: its bodies are rustc's MIR).
const W: &str = include_str!("mir_fixtures/lift_w/w.rs");
/// rustc's MIR of `W` (`mir_fixtures/extract.py`).
const W_MIR: &str = include_str!("mir_fixtures/lift_w/w.sbmir");

/// The files and `r/w.sbmir` (the MIR of `W`, which every lifted `w` reads).
fn check(files: &[(&str, &str)]) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)).chain([("r/w.sbmir", W_MIR)]));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn root(decls: &str) -> String {
    format!("{ROOT}{decls}")
}

fn errors(c: &Checked) -> Vec<(DiagKind, String)> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect()
}

fn warnings(c: &Checked) -> Vec<String> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| d.msg.clone()).collect()
}

#[track_caller]
fn rejects(c: &Checked, kind: DiagKind, needle: &str) {
    assert!(errors(c).iter().any(|(k, m)| *k == kind && m.contains(needle)), "expected error[{}] containing {needle:?}; got:\n{}", kind.code(), c.render());
}

#[track_caller]
fn front_ok(files: &[(&str, &str)]) -> Checked {
    let c = check(files);
    assert!(c.ok(), "front end rejected the lifted crate:\n{}", c.render());
    c
}

fn verify(c: &Checked) -> Verification {
    driver::stage::verify(c.krate.as_ref().unwrap(), &opts(ProverSet::Standard))
}

fn def_names(v: &Verification) -> Vec<String> {
    v.defs.iter().map(|d| d.name.clone()).collect()
}

// ---------------------------------------------------------------------
// monomorphization and state passing
// ---------------------------------------------------------------------

#[test]
fn sealed_generics_become_instances_and_mut_self_becomes_state_passing() {
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", W)]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
    let names = def_names(&v);
    for d in ["crate::w::Wrap__u16::bits", "crate::w::Wrap__u32::bits", "crate::w::Wrap__u16::low", "crate::w::Counter::bump", "crate::w::Counter::chunks"] {
        assert!(names.iter().any(|n| n == d), "missing instance `{d}`; have {names:?}");
    }
}

#[test]
fn a_lifted_module_without_its_mir_is_refused() {
    // the bodies are read only from rustc's MIR: the error names the extractor
    let r = root("#[lift]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", W)]);
    rejects(&c, DiagKind::Unsupported, "has no `mir = \"..\"`");
    assert!(c.render().contains("sandblaster/mirx/extract.sh"), "{}", c.render());
    // twin: a ghost module (laws, proofs) and a host model need no MIR
    let ok = root("#[lift(mir = \"w.sbmir\")]\nmod w;\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use w::{Counter, Wrap};\n");
    front_ok(&[("r/mod.rs", &ok), ("r/w.rs", W), ("r/PROOF.rs", "use sandblaster::prelude::*;\n")]);
}

/// Ghost code the expression reading shares with the deleted body reading
/// (`docs/mir-lift.md` §20): each reads as it did before the source's body
/// reading was deleted.
const GHOST_SHARED: &str = r#"use sandblaster::prelude::*;
use crate::w::{Prim, Wrap};

#[spec]
fn eight<T: Prim>() -> usize { 8 }
#[spec]
fn halved(x: u32) -> u32 { x >> 1 }
#[spec]
fn first(s: &[u8]) -> u8 { let i = 0; s[i] }
#[spec]
fn same(x: u32) -> u32 { let y = x.checked_add(0).unwrap(); y }
#[spec]
fn got(o: Option<u32>) -> u32 { let x = o.unwrap(); x }
#[lemma]
fn generic_call<T: Prim>(w: Wrap<T>) { ensures(eight() == 8usize); }
#[lemma]
fn unwrap_max(x: u32) { ensures(Some(x).unwrap() == x && u32::max(x, 3) >= 3u32); }
#[lemma]
fn slices(s: &[u8], i: usize) { requires(i < s.len()); ensures((&s[..=i]).len() == i + 1 && s.as_ref().len() == s.len()); }
#[lemma]
fn ctor(x: u32) { ensures(Wrap(x).low() == (x as u8)); }
#[lemma]
fn signed_shift_not(x: u32) { ensures(((x as i32) >> 1) == ((x as i32) >> 1u32) && (!(x as i32)) == (!(x as i32))); }
#[lemma]
fn signed_xor(x: u32, y: u32) { ensures(((x as i32) ^ (y as i32)) == ((y as i32) ^ (x as i32))); }
#[lemma]
fn signed_narrow(x: u32) { ensures((((x as i32) as i16) as Int) == (((x as i32) as i16) as Int)); }
"#;

#[test]
fn the_ghost_language_keeps_the_readings_it_shared_with_the_body_reading() {
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use w::{Counter, Wrap};\n");
    front_ok(&[("r/mod.rs", &r), ("r/w.rs", W), ("r/PROOF.rs", GHOST_SHARED)]);
    // twin: a signed operation the reading does not translate is refused
    let bad = GHOST_SHARED.replace("((x as i32) ^ (y as i32)) == ((y as i32) ^ (x as i32))", "((x as i32) + (y as i32)) == ((y as i32) + (x as i32))");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", W), ("r/PROOF.rs", &bad)]);
    rejects(&c, DiagKind::Unsupported, "the signed operation `+` is not lifted");
}

#[test]
fn a_generic_without_a_sealed_bound_is_not_lifted() {
    let w = format!("{W}\npub fn same<T: Copy>(x: T) -> T {{ x }}\n");
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", &w)]);
    rejects(&c, DiagKind::Unsupported, "cannot monomorphize `same`");
}

#[test]
fn an_associated_const_in_a_sealed_trait_is_reported_not_dropped() {
    let w = W.replace("fn low(self) -> u8;", "const SIZE: usize;\n        fn low(self) -> u8;");
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", &w)]);
    rejects(&c, DiagKind::Unsupported, "only methods and associated types are lifted in traits");
}

#[test]
fn mut_self_is_state_passing_only_in_lifted_modules() {
    // the same method written by value in a plain module is rejected: the
    // `mut self` receiver is the lift's encoding of `&mut self`, not DSL
    let plain = "#[derive(Clone, Copy)]\npub struct C { n: u32 }\nimpl C {\n    pub fn bump(mut self) -> (C, u32) { self.n = self.n.wrapping_add(1); (self, self.n) }\n}\n";
    let c = check(&[("r/mod.rs", &root(plain))]);
    rejects(&c, DiagKind::MutRef, "`mut self` / `&mut self` receivers are not supported");
}

#[test]
fn ghost_types_in_exec_signatures_only_in_lifted_modules() {
    // lifted code models buffers as `Seq<u8>`; a plain module may not
    let plain = "pub fn put(s: Seq<u8>, b: u8) -> Seq<u8> { s }\n";
    let c = check(&[("r/mod.rs", &root(plain))]);
    rejects(&c, DiagKind::Ghost, "ghost type");
}

// ---------------------------------------------------------------------
// #[lift(unverified = "..")]
// ---------------------------------------------------------------------

#[test]
fn unverified_instances_are_left_out_and_reported() {
    let r = root("#[lift(mir = \"w.sbmir\", unverified = \"u32\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", W)]);
    assert!(warnings(&c).iter().any(|m| m.contains("the `u32` instances of `w` are declared unverified")), "{}", c.render());
    let v = verify(&c);
    util::assert_verified(&c, &v);
    let names = def_names(&v);
    assert!(names.iter().any(|n| n == "crate::w::Wrap__u16::bits"), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("__u32")), "a declared-unverified instance must not be lifted: {names:?}");
}

#[test]
fn a_malformed_lift_attribute_is_an_error() {
    let r = root("#[lift(mir = \"w.sbmir\", skip = \"u32\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", W)]);
    rejects(&c, DiagKind::Load, "expected `#[lift]`, `#[lift(host)]`, `#[lift(opt)]` or `#[lift(unverified");
}

#[test]
fn without_the_declaration_every_instance_is_lifted() {
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n");
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", W)]);
    assert!(!warnings(&c).iter().any(|m| m.contains("declared unverified")), "{}", c.render());
}

// ---------------------------------------------------------------------
// attachments
// ---------------------------------------------------------------------

const ATTACH_ROOT: &str = "#[lift(mir = \"w.sbmir\")]\nmod w;\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use w::{Counter, Wrap};\n";

#[test]
fn an_attached_summary_is_proven_on_every_instance() {
    let proof = "use sandblaster::prelude::*;\nuse crate::w::Prim;\n\n#[lift_attach(crate::w::Wrap::bits)]\nfn bits_summary<T: Prim>() {\n    ensures(|ret: usize| ret >= 16usize && ret <= 32usize);\n}\n";
    let r = root(ATTACH_ROOT);
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", W), ("r/PROOF.rs", proof)]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn a_false_attached_summary_fails_on_the_instance_it_is_false_for() {
    // 16 bits for `u16`: `ret >= 17` holds for `u32` only
    let proof = "use sandblaster::prelude::*;\nuse crate::w::Prim;\n\n#[lift_attach(crate::w::Wrap::bits)]\nfn bits_summary<T: Prim>() {\n    ensures(|ret: usize| ret >= 17usize);\n}\n";
    let r = root(ATTACH_ROOT);
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", W), ("r/PROOF.rs", proof)]);
    let v = verify(&c);
    let bad = unproven(&v);
    assert!(bad.iter().any(|(d, _)| d.starts_with("crate::w::Wrap__u16::bits")), "{}", explain(&c, &v));
    assert!(!bad.iter().any(|(d, _)| d.starts_with("crate::w::Wrap__u32::bits")), "{}", explain(&c, &v));
}

#[test]
fn an_attachment_to_a_missing_item_is_an_error() {
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::w::Wrap::nope)]\nfn s() {\n    ensures(|ret: usize| ret >= 0usize);\n}\n";
    let r = root(ATTACH_ROOT);
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", W), ("r/PROOF.rs", proof)]);
    rejects(&c, DiagKind::Unsupported, "attachment to `Wrap::nope` matches no lifted item");
}

// ---------------------------------------------------------------------
// div_ceil (elab/lift.core)
// ---------------------------------------------------------------------

program!(dc {
    pub fn dc8(a: u8) -> u8 {
        a.div_ceil(7u8)
    }
    pub fn dc16(a: u16, b: u16) -> u16 {
        if b == 0 { 0 } else { a.div_ceil(b) }
    }
    pub fn dcus(a: usize) -> usize {
        a.div_ceil(7usize)
    }
});

#[test]
fn div_ceil_agrees_with_rustc() {
    let cases = calls!(dc;
        dc8(0u8); dc8(1u8); dc8(7u8); dc8(8u8); dc8(254u8); dc8(255u8);
        dc16(0u16, 1u16); dc16(65535u16, 1u16); dc16(65535u16, 2u16); dc16(65535u16, 65535u16); dc16(5u16, 0u16); dc16(1u16, 65535u16);
        dcus(0usize); dcus(64usize); dcus(63usize); dcus(usize::MAX);
    );
    util::differential(dc::SRC, ProverSet::Basic, &cases);
}

#[test]
fn div_ceil_by_a_possible_zero_is_unproven() {
    let (c, v) = util::verify_src("pub fn f(a: u32, b: u32) -> u32 { a.div_ceil(b) }\n", ProverSet::Basic);
    assert!(unproven(&v).iter().any(|(d, k)| d == "crate::f" && k == "div-zero"), "{}", explain(&c, &v));
}

// ---------------------------------------------------------------------
// per-literal bit-family lemmas by name (auto/bitlib.rs, kernel-checked)
// ---------------------------------------------------------------------

const LZ: &str = r#"
#[requires(x.leading_zeros() >= 7u32)]
fn small(x: u16) -> bool {
    proof! {
        sandblaster::lemmas::bits::lz_ge_u16_9(x);
        assert(x < 512u16);
    }
    true
}

pub fn g(x: u16) -> bool {
    if x.leading_zeros() >= 7u32 { small(x) } else { false }
}
"#;

/// Prelude lemmas are ghost items: verify with ghost code (not exec-only).
fn verify_full(body: &str) -> (Checked, Verification) {
    let c = front_ok(&[("r/mod.rs", &root(body))]);
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &sandblaster_front::driver::VerifyOptions { provers: ProverSet::Standard, exec_only: false });
    (c, v)
}

#[test]
fn a_bit_family_lemma_is_generated_when_a_proof_names_it() {
    let (c, v) = verify_full(LZ);
    util::assert_verified(&c, &v);
}

#[test]
fn a_bit_family_lemma_outside_its_range_does_not_exist() {
    // `lz_ge_u16_k` exists for k < 16 only
    let c = check(&[("r/mod.rs", &root(&LZ.replace("lz_ge_u16_9", "lz_ge_u16_16")))]);
    rejects(&c, DiagKind::Resolve, "lz_ge_u16_16");
}

#[test]
fn a_bit_family_lemma_does_not_prove_more_than_it_states() {
    // lz ≥ 7 gives x < 2^9, not x < 2^8
    let (c, v) = verify_full(&LZ.replace("x < 512u16", "x < 256u16"));
    assert!(unproven(&v).iter().any(|(d, k)| d == "crate::small" && k == "assert"), "{}", explain(&c, &v));
}
