//! The lift conformance check (`sandblaster_front::conform`, DESIGN.md §1.1
//! item 8): the lifted model, evaluated by the kernel, against the source
//! compiled by rustc, on generated inputs. A small module in the shape of
//! commonware-codec's varint (sealed-trait generics over signed widths,
//! `&mut self` with an attached invariant, `BufMut`/`Buf` state passing,
//! `?`/`map_err`, `&a[..=n]`, a host model; its bodies read from rustc's MIR,
//! the fixture `mir_fixtures/conf_w`) passes; each deliberately wrong reading
//! of the MIR (the lift's test hook) is caught with the input that shows it;
//! a pass is cached by its key and a failure is not; a check that cannot
//! run fails.
//!
//! These tests run `rustc` (the one on `PATH`, or `$RUSTC`).

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::{Path, PathBuf};

use sandblaster_front::conform::{self, Config, Report};
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::elab::DefStatus;
use sandblaster_front::lift::{test_hook, ConformCallee, ParamPass};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

const ROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[lift(mir = "w.sbmir")]
mod w;

#[lift(host)]
mod error;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

pub use error::Error;
pub use crate::__lift::Result;
pub use w::{Acc, put_pair, take2, zigzag};
"#;

const ERROR: &str = "//! Host model: `crate::Error`.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Error {\n    EndOfBuffer,\n    InvalidVarint(usize),\n}\n";

/// The lifted source (existing Rust, as written: `mir_fixtures/conf_w`).
const W: &str = include_str!("mir_fixtures/conf_w/w.rs");
/// rustc's MIR of `W` (`mir_fixtures/extract.py`).
const W_MIR: &str = include_str!("mir_fixtures/conf_w/w.sbmir");

const PROOF: &str = r#"use sandblaster::prelude::*;

#[lift_attach(crate::w::Acc)]
fn acc_state() {
    invariant(self.count <= 100u8);
}
"#;

fn files() -> Vec<(&'static str, String)> {
    vec![("/r/mod.rs", ROOT.to_string()), ("/r/w.rs", W.to_string()), ("/r/w.sbmir", W_MIR.to_string()), ("/r/error.rs", ERROR.to_string()), ("/r/PROOF.rs", PROOF.to_string())]
}

fn check(files: &[(&str, String)], hook: Option<test_hook::WrongRule>) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, c.as_str())));
    test_hook::set(hook);
    let c = driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin());
    test_hook::set(None);
    assert!(c.ok(), "front end rejected the lifted crate:\n{}", c.render());
    c
}

fn work_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandblaster-conform-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn config(name: &str) -> Config {
    Config::new(PathBuf::from(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into())), work_dir(name), "2021", "tests/lift_conformance.rs")
}

/// Elaborates the crate (every definition must check) and runs the check.
fn conformance(c: &Checked, cfg: &Config) -> Report {
    let info = driver::lifted::emitted_module(&c.lifted).expect("one lifted module").expect("a lifted module").clone();
    let k = c.krate.as_ref().unwrap();
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    driver::stage::with_elaboration_mut(k, &opts, |out| {
        let bad: Vec<String> = out.defs.iter().filter(|d| !matches!(d.status, DefStatus::Checked | DefStatus::Deferred(_))).map(|d| d.name.clone()).collect();
        assert!(bad.is_empty(), "definitions not checked: {bad:?}");
        conform::check(out, k, c, &info, cfg)
    })
}

fn entry<'r>(r: &'r Report, lifted: &str) -> &'r conform::EntryReport {
    r.entries.iter().find(|e| e.lifted == lifted).unwrap_or_else(|| panic!("no entry `{lifted}` in {:?}", r.entries.iter().map(|e| &e.lifted).collect::<Vec<_>>()))
}

#[test]
fn the_lift_records_how_to_call_each_original() {
    let c = check(&files(), None);
    let find = |l: &str| c.lift_facts.conform.iter().find(|e| e.lifted == l).unwrap_or_else(|| panic!("no conformance entry `{l}`: {:?}", c.lift_facts.conform));
    let add = find("crate::w::Acc::add");
    assert_eq!(add.params, vec![ParamPass::MutRef, ParamPass::Value]);
    assert!(matches!(&add.callee, ConformCallee::Inherent { base, method, .. } if base == "Acc" && method == "add"));
    assert_eq!(find("crate::w::put_pair").params, vec![ParamPass::Value, ParamPass::Value, ParamPass::BufMut]);
    assert!(!find("crate::w::put_pair").has_ret);
    assert_eq!(find("crate::w::take2").params, vec![ParamPass::Buf]);
    assert!(matches!(&find("crate::w::zigzag__i16").callee, ConformCallee::Free { name, generics, .. } if name == "zigzag" && generics == &vec!["i16".to_string()]));
    // a sealed-trait method in its inline module
    assert!(matches!(&find("crate::w::SPrim__i32__zz").callee, ConformCallee::Trait { modpath, trait_path, self_ty, .. } if modpath == &vec!["sealed".to_string()] && trait_path == "SPrim" && self_ty == "i32"));
    // ghost code and the host model have no entries
    assert!(c.lift_facts.conform.iter().all(|e| e.module == "w"), "{:?}", c.lift_facts.conform);
}

#[test]
fn the_lift_agrees_with_rustc_on_a_small_codec() {
    let c = check(&files(), None);
    let cfg = config("pass");
    let r = conformance(&c, &cfg);
    assert!(r.passed(), "{:#?}", r.failures());
    assert!(!r.cached);
    eprintln!("{}\n{}", r.summary(), r.json().render());
    for l in ["crate::w::Acc::new", "crate::w::Acc::add", "crate::w::put_pair", "crate::w::take2", "crate::w::zigzag__i16", "crate::w::zigzag__i32", "crate::w::SPrim__i16__zz", "crate::w::SPrim__i32__zz"] {
        let e = entry(&r, l);
        assert!(e.skipped.is_none(), "{l} skipped: {:?}", e.skipped);
        assert!(e.cases > 0, "{l}: no inputs");
    }
    // the invariant-carrying state: candidates that break it are rejected by
    // the kernel, the others (and the states reached) are compared
    let add = entry(&r, "crate::w::Acc::add");
    assert!(add.rejected > 0 && add.reference > 0 && add.cases > 50, "{add:?}");
    // every outcome of take2 (both errors, `Ok`) and of add (`true`, `false`)
    assert!(entry(&r, "crate::w::take2").classes >= 3, "{:?}", entry(&r, "crate::w::take2"));
    assert!(entry(&r, "crate::w::Acc::add").classes >= 2);
    assert!(r.cases > 500, "{}", r.summary());
    // the literal reading of every function read from MIR is compared with
    // rustc too (amendment (f) of `docs/checked-structuring.md`), on the
    // first inputs of each, the invariant-carrying state's included
    for l in ["crate::w::Acc::add", "crate::w::put_pair", "crate::w::take2", "crate::w::SPrim__i32__zz"] {
        let e = entry(&r, l);
        assert!(e.literal > 0 && e.literal <= conform::LITERAL_CASES, "{l}: {e:?}");
    }
    assert!(r.literal_cases > 100, "{}", r.summary());
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

/// The literal reading against rustc: a misreading of L alone (one operator
/// of `put_pair`'s MIR as L reads it; S, read before, is unchanged) is a
/// mismatch of the check, which names the literal reading, and only that.
#[test]
fn a_misreading_of_the_literal_reading_is_caught_against_rustc() {
    let mut c = check(&files(), None);
    let mut loaded = (*c.lift_facts.mir_loaded[0].loaded).clone();
    let f = loaded.m.fns.get_mut("fx_conf_w::w::put_pair::<&mut [u8]>").expect("put_pair's MIR");
    match &mut f.blocks[0].stmts[0] {
        sandblaster_front::mir::ir::Stmt::Assign(_, sandblaster_front::mir::ir::Rvalue::Bin(op, _, _), _) if op == "xor" => *op = "or".into(),
        other => panic!("{other:?}"),
    }
    c.lift_facts.mir_loaded[0].loaded = std::sync::Arc::new(loaded);
    let cfg = config("literal");
    let r = conformance(&c, &cfg);
    assert!(!r.passed(), "the misread literal reading went unnoticed: {}", r.summary());
    assert!(r.mismatches.iter().all(|m| m.lifted == "crate::w::put_pair" && m.model.starts_with("the literal reading of rustc's MIR gives")), "{:#?}", r.mismatches);
    assert!(!cfg.work_dir.join("conformance.key").exists(), "a failure left a cache key");
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn a_wrong_signed_shift_rule_is_caught() {
    let c = check(&files(), Some(test_hook::WrongRule::SignedShrLogical));
    let cfg = config("shr");
    let r = conformance(&c, &cfg);
    assert!(!r.passed(), "the wrong rule went unnoticed: {}", r.summary());
    assert!(r.notes.iter().any(|n| n.contains("SignedShrLogical")), "{:?}", r.notes);
    // the negative inputs of the ZigZag functions show it
    let f = r.failures();
    assert!(f.iter().any(|m| m.contains("SPrim__i32__zz") && m.contains("rustc's build gives")), "{f:#?}");
    assert!(r.mismatches.iter().any(|m| m.lifted == "crate::w::zigzag__i16"), "{:#?}", r.mismatches);
    assert!(r.mismatches.iter().all(|m| m.lifted.contains("zz") || m.lifted.contains("zigzag")), "{:#?}", r.mismatches);
    assert!(!cfg.work_dir.join("conformance.key").exists(), "a failure left a cache key");
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn a_wrong_inclusive_range_rule_is_caught() {
    let c = check(&files(), Some(test_hook::WrongRule::InclusiveRangeAsExclusive));
    let cfg = config("range");
    let r = conformance(&c, &cfg);
    assert!(!r.passed(), "the wrong rule went unnoticed: {}", r.summary());
    assert!(r.mismatches.iter().any(|m| m.lifted == "crate::w::put_pair"), "{:#?}", r.mismatches);
    assert!(r.mismatches.iter().all(|m| m.lifted == "crate::w::put_pair"), "{:#?}", r.mismatches);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn a_pass_is_cached_by_its_key() {
    let c = check(&files(), None);
    let cfg = config("cache");
    let r1 = conformance(&c, &cfg);
    assert!(r1.passed() && !r1.cached, "{:#?}", r1.failures());
    let r2 = conformance(&c, &cfg);
    assert!(r2.passed() && r2.cached && r2.key == r1.key, "{}", r2.summary());
    assert_eq!(r1.header_line(), r2.header_line(), "the emitted header must not depend on the cache");
    // the replayed report is the report of the run: the build's report and
    // summary do not depend on the cache either
    assert_eq!(r1.summary(), r2.summary());
    assert_eq!(r1.json().render(), r2.json().render());
    // twin: a malformed or foreign record is a miss (the check runs again)
    let key_file = cfg.work_dir.join("conformance.key");
    let good = std::fs::read_to_string(&key_file).unwrap();
    for bad in [good.replacen("\ncases ", "\ncases x", 1), good.replacen(&r1.key, &"0".repeat(64), 1), good.replace(conform::VERSION, "sandblaster-lift-conformance/2"), format!("{good}garbage\n")] {
        std::fs::write(&key_file, &bad).unwrap();
        let r = conformance(&c, &cfg);
        assert!(r.passed() && !r.cached, "{bad}");
        assert_eq!(r.json().render(), r1.json().render());
    }
    // a changed source changes the key: checked again (the fixture
    // `conf_w64`: `W` with `a < 64` for `a < 128`, and its MIR)
    let mut fs2 = files();
    fs2[1].1 = include_str!("mir_fixtures/conf_w64/w.rs").to_string();
    fs2[2].1 = include_str!("mir_fixtures/conf_w64/w.sbmir").to_string();
    assert_eq!(fs2[1].1, W.replace("if a < 128 { 1 } else { 2 }", "if a < 64 { 1 } else { 2 }"));
    let c2 = check(&fs2, None);
    let r3 = conformance(&c2, &cfg);
    assert!(r3.passed() && !r3.cached && r3.key != r1.key, "{}", r3.summary());
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn a_check_that_cannot_run_fails() {
    let c = check(&files(), None);
    let mut cfg = config("norustc");
    cfg.rustc = PathBuf::from("/nonexistent/rustc");
    let r = conformance(&c, &cfg);
    assert!(!r.passed() && r.errors.iter().any(|e| e.contains("cannot run")), "{:#?}", r.errors);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn a_harness_that_does_not_compile_fails() {
    // rustc refuses the harness (here: an edition it does not know): the
    // check fails, it is never skipped
    let c = check(&files(), None);
    let mut cfg = config("nocompile");
    cfg.edition = "1999".into();
    let r = conformance(&c, &cfg);
    assert!(!r.passed() && r.errors.iter().any(|e| e.contains("rustc failed on the harness")), "{:#?}", r.errors);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

#[test]
fn the_edition_follows_the_manifest() {
    let fs = MemFs::from_files([("/ws/Cargo.toml", "[workspace]\nmembers = [\"a\"]\n\n[workspace.package]\nedition = \"2024\"\n"), ("/ws/a/Cargo.toml", "[package]\nname = \"a\"\nedition.workspace = true\n"), ("/ws/b/Cargo.toml", "[package]\nname = \"b\"\nedition = \"2018\"\n")]);
    assert_eq!(conform::edition_of(&fs, Path::new("/ws/a")).as_deref(), Some("2024"));
    assert_eq!(conform::edition_of(&fs, Path::new("/ws/b")).as_deref(), Some("2018"));
    assert_eq!(conform::edition_of(&fs, Path::new("/ws/c")), None);
}

// ---------------------------------------------------------------------
// the MMR track's lift features: every function they lift is compared, or
// excluded with a reason the check reports
// ---------------------------------------------------------------------

const MROOT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[lift(mir = "m.sbmir")]
mod m;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;
"#;

/// Operator, comparison, `Deref` and `Iterator` impls (on a struct and on a
/// primitive), a derived `Default`, core combinators with closures, an
/// assertion macro, an `impl Iterator` return and a `for` loop helper.
/// (`mir_fixtures/conf_m`; its bodies are rustc's MIR.)
const M: &str = include_str!("mir_fixtures/conf_m/m.rs");
const M_MIR: &str = include_str!("mir_fixtures/conf_m/m.sbmir");

const MPROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::m::count, loop_nr = 0)]\nfn count_loop() {\n    invariant((acc as Int) + (iter.n as Int) == (n as Int));\n    decreases(iter.n);\n}\n";

fn mfiles() -> Vec<(&'static str, String)> {
    vec![("/q/mod.rs", MROOT.to_string()), ("/q/m.rs", M.to_string()), ("/q/m.sbmir", M_MIR.to_string()), ("/q/PROOF.rs", MPROOF.to_string())]
}

#[test]
fn the_lift_records_the_mmr_features_for_the_check() {
    let c = check(&mfiles(), None);
    let find = |l: &str| c.lift_facts.conform.iter().find(|e| e.lifted == l).unwrap_or_else(|| panic!("no conformance entry `{l}`: {:#?}", c.lift_facts.conform));
    // an operator impl: the lifted method is renamed, the harness calls the trait's
    assert!(matches!(&find("crate::m::Pos::add__u64").callee, ConformCallee::Trait { trait_path, method, self_ty, .. } if trait_path == "core::ops::Add<u64>" && method == "add" && self_ty == "Pos"));
    assert!(matches!(&find("crate::m::Pos::eq__u64").callee, ConformCallee::Trait { trait_path, method, .. } if trait_path == "PartialEq<u64>" && method == "eq"));
    assert!(matches!(&find("crate::m::Pos::deref").callee, ConformCallee::Trait { method, .. } if method == "deref"));
    // an operator impl on a primitive: a free function, called through the impl
    assert!(matches!(&find("crate::m::u64__eq__Pos").callee, ConformCallee::Trait { self_ty, trait_path, method, .. } if self_ty == "u64" && trait_path == "PartialEq<Pos>" && method == "eq"));
    // a derived `Default` and a custom `Iterator`
    assert!(matches!(&find("crate::m::Pos::default").callee, ConformCallee::Trait { trait_path, method, .. } if trait_path == "Default" && method == "default"));
    assert_eq!(find("crate::m::Down::next").params, vec![ParamPass::MutRef]);
    // excluded with a reason: the `impl Iterator` return and the loop helper
    let skipped: Vec<(&str, &str)> = c.lift_facts.conform_skipped.iter().map(|s| (s.lifted.as_str(), s.why.as_str())).collect();
    assert!(skipped.iter().any(|(l, w)| *l == "crate::m::down" && w.contains("impl Trait")), "{skipped:#?}");
    assert!(skipped.iter().any(|(l, w)| l.starts_with("crate::m::count__") && w.contains("loop helper")), "{skipped:#?}");
    // nothing lifted is left unaccounted for
    for f in ["next", "is_at", "at_is", "zero", "dec2", "half_or_zero", "shl_or_zero", "ones", "tripled", "halved", "count", "Pos::new", "Down::new"] {
        find(&format!("crate::m::{f}"));
    }
}

#[test]
fn the_lift_of_the_mmr_features_agrees_with_rustc() {
    let c = check(&mfiles(), None);
    let cfg = config("mmr");
    let r = conformance(&c, &cfg);
    eprintln!("{}\n{}", r.summary(), r.json().render());
    assert!(r.passed(), "{:#?}", r.failures());
    for l in ["crate::m::Pos::add__u64", "crate::m::Pos::eq__u64", "crate::m::Pos::deref", "crate::m::u64__eq__Pos", "crate::m::Pos::default", "crate::m::Down::next", "crate::m::next", "crate::m::is_at", "crate::m::at_is", "crate::m::zero", "crate::m::dec2", "crate::m::half_or_zero", "crate::m::shl_or_zero", "crate::m::ones", "crate::m::tripled", "crate::m::halved", "crate::m::count"] {
        let e = entry(&r, l);
        assert!(e.skipped.is_none(), "{l} skipped: {:?}", e.skipped);
        assert!(e.cases > 0, "{l}: no inputs");
    }
    // the exclusions are in the report, with their reasons
    assert!(entry(&r, "crate::m::down").skipped.as_deref().is_some_and(|w| w.contains("impl Trait")));
    assert!(r.entries.iter().any(|e| e.lifted.starts_with("crate::m::count__") && e.skipped.as_deref().is_some_and(|w| w.contains("loop helper"))), "{:#?}", r.entries);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
}

/// The check on a lifted crate on disk (`LIFT_CONFORM_CRATE`: its DSL
/// root; `LIFT_CONFORM_EDITION`, default 2024), on one elaboration
/// without the §15 gates: the fast way to rerun the check on a pilot (`cargo test --test lift_conformance -- --ignored
/// --nocapture pilot`).
#[test]
#[ignore]
fn pilot() {
    let root = std::env::var("LIFT_CONFORM_CRATE").expect("LIFT_CONFORM_CRATE");
    // `LIFT_CONFORM_HOOK=shr|range`: lift with a deliberately wrong rule (the
    // check must then fail)
    let hook = match std::env::var("LIFT_CONFORM_HOOK").as_deref() {
        Ok("shr") => Some(test_hook::WrongRule::SignedShrLogical),
        Ok("range") => Some(test_hook::WrongRule::InclusiveRangeAsExclusive),
        _ => None,
    };
    test_hook::set(hook);
    let c = driver::check(Path::new(&root), &sandblaster_front::loader::RealFs, &TargetInfo::aarch64_apple_darwin());
    test_hook::set(None);
    assert!(c.ok(), "{}", c.render());
    let info = driver::lifted::emitted_module(&c.lifted).expect("one lifted module").expect("a lifted module").clone();
    let k = c.krate.as_ref().unwrap();
    let mut cfg = config("pilot");
    cfg.edition = std::env::var("LIFT_CONFORM_EDITION").unwrap_or_else(|_| "2024".into());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let t = std::time::Instant::now();
    let r = driver::stage::with_elaboration_mut(k, &opts, |out| {
        eprintln!("elaboration: {:?}", t.elapsed());
        conform::check(out, k, &c, &info, &cfg)
    });
    eprintln!("{}\n{}", r.summary(), r.json().render());
    if hook.is_some() {
        assert!(!r.passed(), "the wrong rule {hook:?} went unnoticed");
        eprintln!("caught: {} mismatch(es); first: {:?}", r.mismatches.len(), r.failures().first());
    } else {
        assert!(r.passed(), "{:#?}", r.failures());
    }
}

// ---------------------------------------------------------------------
// in-place modules: the harness is a copy of the host crate
// ---------------------------------------------------------------------

/// A host crate (no dependencies) whose `src/a.rs` is lifted in place: a
/// private-field state, a function with an attached precondition, a
/// signed shift.
/// (`mir_fixtures/conf_inplace`; its bodies are rustc's MIR.)
const IN_PLACE_A: &str = include_str!("mir_fixtures/conf_inplace/src/a.rs");
const IN_PLACE_MIR: &str = include_str!("mir_fixtures/conf_inplace/a.sbmir");

const IN_PLACE_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\npub mod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n";

const IN_PLACE_PROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::Acc)]\nfn acc_state() {\n    invariant(self.count <= 100u8);\n}\n\n#[lift_attach(crate::a::inc)]\nfn inc_pre() {\n    requires((x as Int) < 1000);\n}\n";

/// Writes the host crate under a fresh directory; returns it.
fn in_place_crate(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandblaster-inplace-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    for (p, t) in [
        ("Cargo.toml", "[package]\nname = \"inplace-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n"),
        ("src/lib.rs", "mod a;\npub use a::{half, inc, Acc};\n"),
        ("src/a.rs", IN_PLACE_A),
        ("sandblaster/m/mod.rs", IN_PLACE_ROOT),
        ("sandblaster/m/a.sbmir", IN_PLACE_MIR),
        ("sandblaster/m/PROOF.rs", IN_PLACE_PROOF),
    ] {
        let f = d.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, t).unwrap();
    }
    d
}

fn in_place_conformance(dir: &Path, hook: Option<test_hook::WrongRule>, cfg: &Config) -> Report {
    test_hook::set(hook);
    let c = driver::check(&dir.join("sandblaster/m/mod.rs"), &sandblaster_front::loader::RealFs, &TargetInfo::aarch64_apple_darwin());
    test_hook::set(None);
    assert!(c.ok(), "front end rejected the in-place crate:\n{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let infos: Vec<&sandblaster_front::lift::LiftedInfo> = c.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    driver::stage::with_elaboration_mut(k, &opts, |out| conform::check_in_place(out, k, &c, &infos, cfg))
}

fn in_place_config(dir: &Path, name: &str) -> Config {
    let mut cfg = config(&format!("inplace-{name}"));
    cfg.manifest_dir = Some(dir.to_path_buf());
    cfg.cargo = PathBuf::from(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cfg
}

#[test]
fn an_in_place_module_agrees_with_rustc_through_a_copy_of_its_crate() {
    let dir = in_place_crate("pass");
    let cfg = in_place_config(&dir, "pass");
    let r = in_place_conformance(&dir, None, &cfg);
    assert!(r.passed(), "{:#?}\n{}", r.failures(), r.json().render());
    for l in ["crate::a::Acc::new", "crate::a::Acc::add", "crate::a::inc", "crate::a::half"] {
        let e = entry(&r, l);
        assert!(e.skipped.is_none() && e.cases > 0, "{l}: {e:?}");
        // in place too, the literal reading is compared with rustc
        assert!(e.literal > 0, "{l}: {e:?}");
    }
    // the precondition is decided by its checker: inputs that break it are
    // not compared (the original would overflow on `u32::MAX`)
    assert!(entry(&r, "crate::a::inc").rejected > 0, "{:?}", entry(&r, "crate::a::inc"));
    // the private-field state is built in its own file (invariant kept)
    assert!(entry(&r, "crate::a::Acc::add").rejected > 0);
    // the host's own source is not changed
    assert_eq!(std::fs::read_to_string(dir.join("src/a.rs")).unwrap(), IN_PLACE_A);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_in_place_harness_catches_a_wrong_lift_rule_and_needs_its_crate() {
    let dir = in_place_crate("hook");
    let cfg = in_place_config(&dir, "hook");
    let r = in_place_conformance(&dir, Some(test_hook::WrongRule::SignedShrLogical), &cfg);
    assert!(!r.passed(), "the wrong rule went unnoticed: {}", r.summary());
    assert!(r.mismatches.iter().any(|m| m.lifted == "crate::a::half"), "{:#?}", r.mismatches);
    assert!(r.mismatches.iter().all(|m| m.lifted == "crate::a::half"), "{:#?}", r.mismatches);
    assert!(!cfg.work_dir.join("conformance.key").exists(), "a failure left a cache key");
    // without the host crate's directory the check cannot run: it fails
    let mut no_crate = in_place_config(&dir, "nocrate");
    no_crate.manifest_dir = None;
    let r = in_place_conformance(&dir, None, &no_crate);
    assert!(!r.passed() && r.errors.iter().any(|e| e.contains("copy of the host crate")), "{:#?}", r.errors);
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
    let _ = std::fs::remove_dir_all(&dir);
}
