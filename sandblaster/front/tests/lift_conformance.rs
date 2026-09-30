//! The lift conformance check (`sandblaster_front::conform`, DESIGN.md §1.1
//! item 8): the lifted model, evaluated by the kernel, against the source
//! compiled by rustc, on generated inputs. A small module in the shape of
//! commonware-codec's varint (sealed-trait generics over signed widths,
//! `&mut self` with an attached invariant, `BufMut`/`Buf` state passing,
//! `?`/`map_err`, `&a[..=n]`, a host model) passes; each deliberately wrong
//! lift rule (the lift's test hook) is caught with the input that shows it;
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

#[lift]
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

/// The lifted source (existing Rust, as written).
const W: &str = r#"//! A small codec in the shape of commonware-codec's varint.

use crate::{Buf, Error};
use bytes::BufMut;
use sealed::SPrim;

mod sealed {
    pub trait SPrim: Copy {
        fn zz(self) -> u32;
    }
    impl SPrim for i32 {
        fn zz(self) -> u32 {
            ((self << 1) ^ (self >> 31)) as u32
        }
    }
    impl SPrim for i16 {
        fn zz(self) -> u32 {
            (((self << 1) ^ (self >> 15)) as u16) as u32
        }
    }
}

/// An accumulator of at most 100 bytes.
#[derive(Debug, Clone)]
pub struct Acc {
    total: u32,
    count: u8,
}

impl Acc {
    pub fn new() -> Self {
        Self { total: 0, count: 0 }
    }

    pub fn add(&mut self, b: u8) -> bool {
        if self.count >= 100 {
            return false;
        }
        self.total = self.total.wrapping_add(b as u32);
        self.count += 1;
        true
    }
}

/// Writes `a`, `b` and, when `a` has its top bit set, `a ^ b`.
pub fn put_pair(a: u8, b: u8, buf: &mut impl BufMut) {
    let bytes = [a, b, a ^ b];
    let n: usize = if a < 128 { 1 } else { 2 };
    buf.put_slice(&bytes[..=n]);
}

/// Reads a big-endian `u16`.
pub fn take2(buf: &mut impl Buf) -> Result<u16, Error> {
    let hi = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
    let lo = buf.try_get_u8().map_err(|_| Error::EndOfBuffer)?;
    Ok(((hi as u16) << 8) | lo as u16)
}

/// ZigZag of a signed value.
pub fn zigzag<S: SPrim>(x: S) -> u32 {
    x.zz()
}
"#;

const PROOF: &str = r#"use sandblaster::prelude::*;

#[lift_attach(crate::w::Acc)]
fn acc_state() {
    invariant(self.count <= 100u8);
}
"#;

fn files() -> Vec<(&'static str, String)> {
    vec![("/r/mod.rs", ROOT.to_string()), ("/r/w.rs", W.to_string()), ("/r/error.rs", ERROR.to_string()), ("/r/PROOF.rs", PROOF.to_string())]
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
    Config { rustc: PathBuf::from(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into())), work_dir: work_dir(name), edition: "2021".into(), toolchain_id: "tests/lift_conformance.rs".into() }
}

/// Elaborates the crate (every definition must check) and runs the check.
fn conformance(c: &Checked, cfg: &Config) -> Report {
    let info = driver::lifted::emitted_module(&c.lifted).expect("one lifted module").expect("a lifted module").clone();
    let k = c.krate.as_ref().unwrap();
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    driver::stage::with_elaboration(k, &opts, |out| {
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
    for bad in [good.replacen("\ncases ", "\ncases x", 1), good.replacen(&r1.key, &"0".repeat(64), 1), good.replace("sandblaster-lift-conformance/3", "sandblaster-lift-conformance/2"), format!("{good}garbage\n")] {
        std::fs::write(&key_file, &bad).unwrap();
        let r = conformance(&c, &cfg);
        assert!(r.passed() && !r.cached, "{bad}");
        assert_eq!(r.json().render(), r1.json().render());
    }
    // a changed source changes the key: checked again
    let mut fs2 = files();
    fs2[1].1 = W.replace("if a < 128 { 1 } else { 2 }", "if a < 64 { 1 } else { 2 }");
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

#[lift]
mod m;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;
"#;

/// Operator, comparison, `Deref` and `Iterator` impls (on a struct and on a
/// primitive), a derived `Default`, core combinators with closures, an
/// assertion macro, an `impl Iterator` return and a `for` loop helper.
const M: &str = r#"//! The MMR track's lift features in one module.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl core::ops::Add<u64> for Pos {
    type Output = Self;
    fn add(self, r: u64) -> Self {
        Self(self.0.wrapping_add(r))
    }
}

impl core::ops::Deref for Pos {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl PartialEq<u64> for Pos {
    fn eq(&self, o: &u64) -> bool {
        self.0 == *o
    }
}

impl PartialEq<Pos> for u64 {
    fn eq(&self, o: &Pos) -> bool {
        *self == o.0
    }
}

pub fn next(p: Pos) -> u64 {
    let q = p + 1;
    *q
}

pub fn is_at(p: Pos, x: u64) -> bool {
    p == x
}

pub fn at_is(x: u64, p: Pos) -> bool {
    x == p
}

pub fn zero() -> u64 {
    let z = Pos::default();
    *z
}

pub fn dec2(x: Option<u64>) -> Option<u64> {
    x.and_then(|v| v.checked_sub(2))
}

pub fn half_or_zero(x: Option<u64>) -> u64 {
    x.map_or(0u64, |v| v / 2)
}

pub fn shl_or_zero(x: u64, s: u32) -> u64 {
    match x.checked_shl(s) {
        Some(v) => v,
        None => 0,
    }
}

pub fn ones(x: u64) -> u32 {
    x.trailing_ones()
}

pub fn tripled(n: u32) -> u64 {
    let f = |k: u64| k * 3;
    f(n as u64)
}

pub fn halved(x: u64) -> u64 {
    assert!(x / 2 <= x, "halving never grows");
    x / 2
}

pub struct Down {
    n: u32,
}

impl Iterator for Down {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.n == 0 {
            return None;
        }
        self.n -= 1;
        Some(self.n)
    }
}

impl Down {
    pub fn new(n: u32) -> Self {
        Self { n }
    }
}

pub fn down(n: u16) -> impl Iterator<Item = u32> {
    Down::new(n as u32)
}

pub fn count(n: u16) -> u64 {
    let mut acc = 0u64;
    for _i in down(n) {
        acc += 1;
    }
    acc
}
"#;

const MPROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::m::count, loop_nr = 0)]\nfn count_loop() {\n    invariant((acc as Int) + (iter.n as Int) == (n as Int));\n    decreases(iter.n);\n}\n";

fn mfiles() -> Vec<(&'static str, String)> {
    vec![("/q/mod.rs", MROOT.to_string()), ("/q/m.rs", M.to_string()), ("/q/PROOF.rs", MPROOF.to_string())]
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
    let r = driver::stage::with_elaboration(k, &opts, |out| {
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
