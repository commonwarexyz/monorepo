//! The generated crate's public API is the source's (DESIGN.md §2): every
//! public path — `pub mod`s, items, fields, variants, inherent functions,
//! and `pub use` re-exports inside modules and at the root, renames (`as`)
//! included — with the same kind and naming the same definition. Both sides
//! are read by an independent `syn` walker (`common/api.rs`), not by the
//! front end. Regression test for the generated `config` modules of QMDB,
//! which dropped the `hash_chunk` / `hash_graft` re-exports that the source
//! and the rustc baseline have. (The x86_64 production instance is compared
//! in `opt_x86.rs`.)

mod common;
#[path = "common/api.rs"]
mod api;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

use common::*;
use sandblaster_front::canon::ReExportTarget;
use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

/// One QMDB elaboration at a time in this process (each needs a few GB).
static HEAVY: Mutex<()> = Mutex::new(());

/// Every form of re-export: module-level (plain, renamed, of the module's
/// own item, of a re-export, of a module, of an item of a private module,
/// of a type, of a variant, of `::core`), root-level (a variant, an item
/// through a re-export chain, a private module's public submodule), and an
/// inherent function reached through a renamed type.
const FIXTURE: &[(&str, &str)] = &[
    (
        "r/mod.rs",
        "#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub mod a;
pub mod b;
mod hidden;

pub use a::Kind::Two as Second;
pub use b::renamed as root_alias;
pub use hidden::inner as exposed;
",
    ),
    (
        "r/a.rs",
        "use sandblaster::prelude::*;

/// A two-valued kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    One,
    Two,
}

/// Two numbers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pair {
    pub left: u32,
    pub right: u32,
}

impl Pair {
    pub fn sum(self) -> u32 {
        self.left.wrapping_add(self.right)
    }
}

pub const C: u32 = 3;

pub fn f(x: u32) -> u32 {
    x
}

pub fn pick(k: Kind) -> u32 {
    match k {
        Kind::One => 1,
        Kind::Two => 2,
    }
}

pub use super::b::g;
pub use super::b::g as g_alias;
pub use self::f as f_again;
pub use super::hidden::inner as nested;
pub use super::hidden::inner::h as h2;
",
    ),
    (
        "r/b.rs",
        "use sandblaster::prelude::*;

pub fn g(x: u32) -> u32 {
    x.wrapping_add(1)
}

pub use super::a::f as renamed;
pub use super::a::Kind;
pub use super::a::Kind::One;
pub use super::a::Pair as Couple;
pub use core::option::Option as Maybe;
",
    ),
    ("r/hidden.rs", "pub mod inner;\n"),
    (
        "r/hidden/inner.rs",
        "use sandblaster::prelude::*;

pub fn h(x: u32) -> u32 {
    x ^ 1
}
",
    ),
];

fn fixture_read(p: &Path) -> Option<String> {
    FIXTURE.iter().find(|(q, _)| Path::new(q) == p).map(|(_, t)| t.to_string())
}

#[test]
fn every_reexport_is_printed_and_the_public_api_is_the_sources() {
    let target = TargetInfo::aarch64_apple_darwin();
    let c = check_files(FIXTURE);
    assert!(c.ok(), "{}", c.render());
    // the re-exports outside the boundary, as the driver collects them
    let mut got: Vec<String> = c.reexports.iter().map(|r| format!("{}::{}", c.krate.as_ref().unwrap().module(r.module).path, r.name)).collect();
    got.sort();
    let want = ["crate::Second", "crate::a::f_again", "crate::a::g", "crate::a::g_alias", "crate::a::h2", "crate::a::nested", "crate::b::Couple", "crate::b::Kind", "crate::b::Maybe", "crate::b::One", "crate::b::renamed"];
    assert_eq!(got, want);
    assert!(c.reexports.iter().all(|r| !matches!(r.target, ReExportTarget::Unsupported(_))), "{:?}", c.reexports);
    let want_api = api::source_api(Path::new("r/mod.rs"), &fixture_read, &target);
    // the walker's view of the source (spot checks)
    for (path, def) in [("a::g_alias", "b::g"), ("a::nested::h", "hidden::inner::h"), ("b::Couple::sum", "a::Pair::sum"), ("Second", "a::Kind::Two"), ("root_alias", "a::f"), ("b::Maybe", "core::option::Option"), ("exposed::h", "hidden::inner::h")] {
        assert!(want_api.iter().any(|e| e.path == path && e.def == def), "walker: {path} = {def} missing:\n{want_api:#?}");
    }

    // phase 1 (unverified printer) and phase 3 (the build's output, round-tripped)
    let phase1 = driver::stage::emit(&c, "r/mod.rs").unwrap();
    let a1 = api::generated_api(&phase1, &target);
    assert_eq!(want_api, a1, "phase-1 output: public API differs from the source:\n{}", api::diff(&want_api, &a1));
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions { strict: true, ..Default::default() }, "r/mod.rs");
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let em = built.emit.expect("emitted").expect("optimized");
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "round trip: {:?}\n{}", em.roundtrip, em.code);
    assert_eq!(em.roundtrip_stats.reexports, want.len(), "{:?}", em.roundtrip_stats);
    assert!(em.roundtrip_stats.api_differences.is_empty(), "{:?}", em.roundtrip_stats.api_differences);
    for line in ["pub use crate::__sandblaster::b::g as g_alias;", "pub use crate::__sandblaster::a::f as renamed;", "pub use crate::__sandblaster::hidden::inner as nested;", "pub use ::core::option::Option as Maybe;", "pub use __sandblaster::a::Kind::Two as Second;"] {
        assert!(em.code.contains(line), "`{line}` not printed:\n{}", em.code);
    }
    let a3 = api::generated_api(&em.code, &target);
    assert_eq!(want_api, a3, "public API differs from the source:\n{}", api::diff(&want_api, &a3));

    // rustc accepts the re-exports, and they name the right definitions
    let dir = tmp("api-fidelity");
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    let main = format!(
        r#"include!({gen:?});
fn main() {{
    let p = b::Couple {{ left: 2, right: 3 }};
    let maybe: b::Maybe<u32> = Some(a::C);
    let s = [a::g_alias(1), a::g(1), b::renamed(7), a::f_again(7), root_alias(7), a::nested::h(4), a::h2(4), exposed::h(4), p.sum(), a::pick(Second), a::pick(b::One), maybe.unwrap(), (b::Kind::One == a::Kind::One) as u32];
    println!("{{s:?}}");
}}
"#,
        gen = dir.join("sandblaster.rs")
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let out = rustc_run(&dir.join("main.rs"), &dir.join("api"), &[]);
    assert_eq!(out.trim(), "[2, 2, 7, 7, 7, 5, 5, 5, 5, 2, 1, 3, 1]");
}

/// A re-export the generated crate cannot have is not dropped silently: the
/// round trip reports it (and the build fails).
#[test]
fn a_reexport_the_generated_crate_cannot_have_is_reported() {
    let files: &[(&str, &str)] = &[
        ("r/mod.rs", "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub mod m;\npub mod n;\n"),
        ("r/m.rs", "use sandblaster::prelude::*;\n#[derive(Clone, Copy, PartialEq, Eq, Debug)]\npub struct Pair {\n    pub left: u32,\n}\npub fn f(x: u32) -> u32 { x }\n"),
        ("r/n.rs", "use sandblaster::prelude::*;\npub use super::m::f as u16;\npub use super::m::Pair as u8;\n"),
    ];
    let c = check_files(files);
    assert!(c.ok(), "{}", c.render());
    // a type named `u8` would change what `u8` means in the module's code; a
    // function named `u16` does not (it is in the value namespace)
    assert!(c.reexports.iter().any(|r| r.name == "u8" && matches!(r.target, ReExportTarget::Unsupported(_))), "{:?}", c.reexports);
    assert!(c.reexports.iter().any(|r| r.name == "u16" && matches!(r.target, ReExportTarget::Item(_))), "{:?}", c.reexports);
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions { strict: true, ..Default::default() }, "r/mod.rs");
    assert!(built.v.proofs_ok, "{}", built.v.diags.render(&c.sm));
    let em = built.emit.expect("emitted").expect("optimized");
    assert!(em.roundtrip.iter().any(|f| f.contains("public API") && f.contains("crate::n::u8")), "{:?}", em.roundtrip);
    assert!(!em.code.contains("as u8;") && em.code.contains("pub use crate::__sandblaster::m::f as u16;"), "{}", em.code);
}

/// The public API of a QMDB instance's optimized output (the exec-only
/// test path; the printer and the round trip are the build's).
fn qmdb_apis(root: &str, target: &TargetInfo) -> (BTreeSet<api::Entry>, String, Vec<(String, String)>) {
    let _g = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let rel = format!("sandblaster/fixtures/qmdb/sandblaster/{root}");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(&rel);
    let c = driver::check(&path, &RealFs, target);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        driver::stage::optimize_emit_mode(&c, &mut out, &rel, "", &OptOptions { strict: true, ..Default::default() }, true).unwrap()
    });
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "round trip: {:?}", em.roundtrip);
    let src = api::source_api(&path, &api::disk, target);
    (src, em.code, em.opt.not_emitted.clone())
}

/// The fully specified QMDB's public API is its root's `pub use` list
/// (§15.8: the modules are private), the same for both instances:
/// `Digest`, `verify` and `verify_fixed`. (Until §15 S5 the modules were
/// `pub`, and the instance's `config::hash_chunk` / `config::hash_graft`
/// re-exports were public paths too.)
fn assert_same_api(root: &str) {
    let target = TargetInfo::aarch64_apple_darwin();
    let (src, code, not_emitted) = qmdb_apis(root, &target);
    assert!(not_emitted.is_empty(), "{not_emitted:?}");
    let out = api::generated_api(&code, &target);
    assert_eq!(src, out, "{root}: the generated public API differs from the source's:\n{}", api::diff(&src, &out));
    assert!(out.iter().any(|e| e.path == "verify" && e.def == "verifier::verify" && e.kind == "fn/4"), "{root}: {out:?}");
    assert!(out.iter().any(|e| e.path == "verify_fixed" && e.def == "verifier::verify_fixed" && e.kind == "fn/4"), "{root}: {out:?}");
    assert!(out.iter().any(|e| e.path == "Digest" && e.def == "sha256::Digest"), "{root}: {out:?}");
    // nothing of the private modules is public
    assert!(!out.iter().any(|e| e.path.contains("::")), "{root}: a module path is public: {out:?}");
    // the comparison catches the regression: without its `pub use` line,
    // `verify_fixed` is missing from the generated API
    let dropped: String = code.lines().filter(|l| !l.ends_with(" as verify_fixed;")).map(|l| format!("{l}\n")).collect();
    assert_ne!(dropped, code);
    let d = api::generated_api(&dropped, &target);
    let missing: Vec<&str> = src.difference(&d).map(|e| e.path.as_str()).collect();
    assert_eq!(missing, vec!["verify_fixed"], "{root}");
}

#[test]
fn qmdb_n32_public_api_is_the_sources() {
    assert_same_api("mod.rs");
}

#[test]
fn qmdb_n1_public_api_is_the_sources() {
    // `config` is `config_n1` imported at the root (`use self::config_n1
    // as config;`, not `pub`): the API is the N = 32 instance's
    assert_same_api("n1.rs");
}
