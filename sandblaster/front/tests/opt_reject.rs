//! The optimizer's soundness must-reject suite (design §20;
//! docs/optimizer-plan.md O1 items 2 and 6, gate G4).
//!
//! Each test injects an unsound candidate, proof, cache entry or decision
//! through `OptTestHooks` (`opt::hooks`, compiled for this crate's tests only)
//! and asserts three things:
//! 1. what rejects it, and the kernel's error kind where the kernel does;
//! 2. the fallback: `Unspecialized { failure: true }` with the source printed
//!    (for a function), or the portable code (for a variant set), or no
//!    emitted code at all (the evidence gate fails closed);
//! 3. a build error under `SANDBLASTER_STRICT_OPT=1` (strict options: the
//!    optimizer's errors are what `build_verified` refuses to emit on).
//!
//! One exception to 2: a forged entry *on disk* is a hint, never a
//! candidate (optimizer design §17: a miss recomputes the identical
//! result). The kernel rejects it, the optimizer reports it (a warning; a
//! build error under strict options), removes it and builds the proof as on
//! a miss: the build emits the cold build's code, and the next build is
//! clean.
//!
//! Every fault has a control: the same injection, untampered, is accepted.
//! Without it a rejection may come from something other than the fault (a
//! route that refuses the candidate's whole shape), and proves nothing.
//!
//! | Test | Injected fault | Control (accepted) | Rejected by |
//! | --- | --- | --- | --- |
//! | R25 | forged cache entry (tampered proof skeleton; and on disk, entries of the hints-only cache swapped — a driven lemma's, or helper lemmas' next to an admitted straight-line residual) | the untampered skeleton / warm cache | `add_def` |
//! | R2 | varint: the range check after the ninth byte claimed dead (`DriveFault::RangeCheckDead`) | `location` driven without the fault | `add_def`: Linarith |
//! | R10 | fold with a non-decreasing measure (`DriveFault::FoldBadMeasure`: the fold helper's lemma recursive on its accumulator) | `sum_small` folded without the fault | the kernel's termination check (`add_def`: Linarith, the `rec` decrease proof) |
//! | R26 | unvalidated intrinsic in a dispatched variant | the same dispatch with evidence | evidence gate |
//! | R16 | lane-lifted SHA-256 (the lane functor, plan O10) with lanes 3 and 4 swapped in the pack, in the kernel and in the proof builder's lane arrays (`LaneFault::SwapLanes`) | the same lifting without the fault | the kernel's check of `lane_equiv` (the site keeps its code) |
//! | R26 (lanes) | a lane kernel dispatched without a host run of the kernel; a NEON lane kernel dispatched with a model's evidence withheld; a lane kernel whose load/store helper template changed after its host run | the same dispatch with the host run granted / the evidence restored / the unchanged template | the lane evidence gate / the model evidence gate / the lane evidence gate (the record is named by the emitted text) |
//! | R27 | clone residual reused without `clone_equiv` (claimed, or a tampered proof) | the optimizer's own lemma | emission-chain check / `add_def` (the set falls back) |
//! | R1, R3, R4, R11–R15 | driven-route faults (`opt::DriveFault`, plan O4) | the same function driven without the fault | kernel (`add_def`: Linarith, TypeMismatch) / residual or helper elaboration |
//! | R24 | `word::eq8` "proven" by linarith | the shipped lemma library | kernel linarith check (the library does not load) |
//! | R21 | feature-only clone on a CPU where `lzcnt` executes as `bsr` (simulated in the machine code: the emitted detection forced true with `hooks::KatFault::ForceDetect`, the release binary's `lzcnt`/`tzcnt` encodings patched to `bsr`/`bsf`; x86_64 binary run under Rosetta 2) | the same binary unpatched: the self-test passes and the clone runs | the dispatch's known-answer self-test at run time: the process is pinned to the portable code (plan O8) |
//! | corpus conv | per program, a one-token mutation of a candidate today's route admits (`opt_corpus/conv_pairs.rs`) | the unmutated candidate | `check_residual_equal: TypeMismatch` (not convertible), pinned per program |
//! | corpus route | per program, the frozen variant for its eventual route (`opt_corpus/must_reject.rs`) | the variant with its bug fixed (`must_reject_controls.rs`) | rejected, reason pinned; not evidence while the control is rejected too (`pending`) |
//!
//! Later milestones add the remaining R-tests here as their paths appear
//! (plan §4.3).
//!
//! Run: `cargo test -p sandblaster-front --test opt_reject -- --nocapture`.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sandblaster_front::driver::{self, Checked, OptimizedEmit};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::hooks::{self, CacheEntry, OptTestHooks, ProofSkeleton};
use sandblaster_front::opt::{OptOptions, Outcome};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::term::{GlobalId, Rel, Tm};
use sandblaster_kernel::util::mk;

#[path = "opt_corpus/manifest.rs"]
mod manifest;

/// One test at a time: R26 withholds hardware evidence process-wide.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn check_files(files: &[(&str, &str)], root: &str) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, s)| (*p, *s)));
    let c = driver::check(Path::new(root), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// Elaborates (exec code) and optimizes `c` with `hooks`, strict or not.
fn optimize(c: &Checked, root: &str, hooks: &OptTestHooks, strict: bool) -> OptimizedEmit {
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        driver::stage::optimize_emit_mode(c, &mut out, root, "", &OptOptions { strict, hooks: Some(Arc::new(hooks.clone())), ..Default::default() }, true).unwrap()
    })
}

/// [`optimize`] with a loop-summary configuration.
fn optimize_with_loops(c: &Checked, root: &str, hooks: &OptTestHooks, strict: bool, loops: sandblaster_front::opt::loopsum::LoopConfig) -> OptimizedEmit {
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        driver::stage::optimize_emit_mode(c, &mut out, root, "", &OptOptions { strict, loops, hooks: Some(Arc::new(hooks.clone())), ..Default::default() }, true).unwrap()
    })
}

fn report<'a>(em: &'a OptimizedEmit, name: &str) -> &'a sandblaster_front::opt::FnReport {
    em.opt.fns.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no report for {name}"))
}

/// Whether the printed item `name` is printed from its source (the proven
/// fallback) rather than from a residual.
fn prints_source(em: &OptimizedEmit, name: &str) -> bool {
    let f = report(em, name);
    let (g, compare) = em.opt.targets[&f.item];
    g == compare
}

/// `λ x̄. refl(R, h x̄)` for a global `h` with the same telescope as `b`:
/// a well-formed proof term of the wrong statement unless `h x̄ ≡ b x̄`.
fn refl_of(h: &'static str) -> ProofSkeleton {
    Arc::new(move |env, _a: GlobalId, b: GlobalId| {
        let hg = env.lookup_global(h).ok_or("no such global")?;
        let tele = sandblaster_front::opt::symex::telescope(env, b).ok_or("no telescope")?;
        let n = tele.binders.len();
        let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
        let mut body = mk::refl(tele.ret.clone(), mk::apps(mk::global(hg), args));
        for (nm, rel, dom) in tele.binders.iter().rev() {
            body = mk::lam(nm, *rel, dom.clone(), body);
        }
        Ok(body)
    })
}

// ---------------------------------------------------------------------------
// R25: forged cache entry (tampered proof skeleton) — rejected by `add_def`
// ---------------------------------------------------------------------------

const SRC_R25: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

fn add1(x: u32) -> u32 {
    x.wrapping_add(1)
}

fn flip(x: u32) -> u32 {
    x ^ 1
}

pub fn twice(x: u32) -> u32 {
    add1(add1(x))
}

pub fn thrice(x: u32) -> u32 {
    add1(twice(x)) ^ flip(x)
}
"#;

#[test]
fn r25_forged_cache_entry_is_rejected_by_add_def() {
    let _g = serial();
    let c = check_files(&[("r/mod.rs", SRC_R25)], "r/mod.rs");
    // control: the untampered skeleton (conversion link) is accepted
    let good = OptTestHooks { cache: BTreeMap::from([("crate::twice".to_string(), CacheEntry { candidate: None, proof: hooks::refl_skeleton() })]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &good, true);
    let f = report(&em, "crate::twice");
    assert!(matches!(f.outcome, Outcome::Specialized { .. }), "the untampered cache entry must be admitted: {:?}", f.outcome);
    assert!(f.candidates.iter().any(|c| c.chosen && c.injected), "{:?}", f.candidates);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(!prints_source(&em, "crate::twice"));
    // the tampered skeleton: `refl(u32, flip x)` offered for
    // `Eq(u32, twice__residual x, twice x)` (it proves `flip x = flip x`)
    let bad = OptTestHooks { cache: BTreeMap::from([("crate::twice".to_string(), CacheEntry { candidate: None, proof: refl_of("crate::flip") })]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &bad, false);
    let f = report(&em, "crate::twice");
    println!("R25: {:?}\n     {:?}", f.outcome, f.candidates);
    // 1. rejected by add_def, a kernel type error
    let cand = f.candidates.first().expect("a candidate");
    assert_eq!(cand.rejected_by.as_deref(), Some("add_def: TypeMismatch"), "{cand:?}");
    // 2. Unspecialized { failure: true }, the source printed, a warning
    assert!(matches!(&f.outcome, Outcome::Unspecialized { failure: true, reason } if reason.contains("cache entry rejected by the kernel")), "{:?}", f.outcome);
    assert!(prints_source(&em, "crate::twice"));
    assert!(em.code.contains("add1(crate::__sandblaster::add1(") || em.code.contains("add1(add1("), "the source body of `twice` must be printed:\n{}", em.code);
    assert!(em.opt.warnings.iter().any(|w| w.contains("crate::twice") && w.contains("cache entry rejected")), "{:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    // 3. a build error under strict
    let em = optimize(&c, "r/mod.rs", &bad, true);
    assert!(em.opt.errors.iter().any(|e| e.contains("crate::twice") && e.contains("cache entry rejected")), "{:?}", em.opt.errors);
}

// ---------------------------------------------------------------------------
// R25 on disk: the hints-only proof cache (`opt::cache`,
// `target/sandblaster/opt-cache/`) with two entries swapped
// ---------------------------------------------------------------------------

const SRC_R25_DISK: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn small(x: u32) -> Option<u32> {
    if x < 100 {
        if x < 1000 { Some(x + 1) } else { None }
    } else {
        None
    }
}

pub fn nested(x: u64) -> u64 {
    if x < 10 {
        if x < 20 { x } else { 99 }
    } else {
        0
    }
}
"#;

/// Elaborates and optimizes `c` with the proof cache in `dir`.
fn optimize_cached(c: &Checked, root: &str, dir: &Path, strict: bool) -> OptimizedEmit {
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        driver::stage::optimize_emit_mode(c, &mut out, root, "", &OptOptions { strict, cache_dir: Some(dir.to_path_buf()), ..Default::default() }, true).unwrap()
    })
}

/// The `.proof` entries of the cache in `dir`, sorted.
fn cache_entries(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir).expect("the cache directory").filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "proof")).collect();
    entries.sort();
    entries
}

fn mentions(b: &[u8], s: &str) -> bool {
    b.windows(s.len()).any(|w| w == s.as_bytes())
}

/// The messages (warnings or errors) reporting a rejected cache entry of
/// function `f` with the kernel's error `kind`.
fn cache_rejections<'a>(msgs: &'a [String], f: &str, kind: &str) -> Vec<&'a String> {
    msgs.iter().filter(|m| m.contains(&format!("`{f}`")) && m.contains("cache entry rejected") && m.contains(&format!("add_def: {kind}"))).collect()
}

/// R25 with the real cache: a cold build stores the two driven functions'
/// proofs; `nested`'s entry is overwritten with `small`'s (a well-formed
/// proof of another lemma whose dependencies are unchanged, so the cache
/// offers it); the next build commits the hint with `add_def`, which
/// rejects it (a kernel type error). The rejection is reported — a warning,
/// a build error under strict options — and the entry is removed and its
/// proof rebuilt: the build emits the cold build's code, the entry is the
/// cold build's again, and the next build is clean. The untampered warm
/// build (the control) admits both hits and emits exactly the cold build's
/// code.
#[test]
fn r25_forged_on_disk_cache_entry_is_rejected_by_add_def() {
    let _g = serial();
    let c = check_files(&[("r/mod.rs", SRC_R25_DISK)], "r/mod.rs");
    let dir = std::env::temp_dir().join(format!("sandblaster-r25-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // cold, then the control: warm and untampered
    let cold = optimize_cached(&c, "r/mod.rs", &dir, true);
    let entries = cache_entries(&dir);
    assert_eq!(entries.len(), 2, "two driven functions, two cached proofs: {entries:?}");
    for f in ["crate::small", "crate::nested"] {
        assert!(matches!(report(&cold, f).outcome, Outcome::Specialized { .. }) && !prints_source(&cold, f), "{f}: {:?}", report(&cold, f).outcome);
    }
    let warm = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert!(warm.opt.errors.is_empty() && warm.opt.warnings.is_empty() && warm.roundtrip.is_empty(), "{:?} {:?} {:?}", warm.opt.errors, warm.opt.warnings, warm.roundtrip);
    assert_eq!(warm.code, cold.code, "a warm build emits the cold build's code");
    // the forgery: `nested`'s entry replaced by `small`'s (entries name
    // the globals their proofs mention; `small` is optimized first, so
    // everything its proof mentions exists when `nested`'s entry is read)
    let bytes: Vec<Vec<u8>> = entries.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let small_ix = (0..2).find(|&i| mentions(&bytes[i], "crate::small__residual")).expect("small's entry");
    let nested_ix = 1 - small_ix;
    assert!(mentions(&bytes[nested_ix], "crate::nested__residual"));
    let forge = || std::fs::write(&entries[nested_ix], &bytes[small_ix]).unwrap();
    forge();
    let em = optimize_cached(&c, "r/mod.rs", &dir, false);
    for f in ["crate::small", "crate::nested"] {
        let r = report(&em, f);
        println!("R25 (disk) {f}: {:?}\n     {:?}", r.outcome, r.candidates);
        // the hint costs nothing but its rebuild: both admitted as in the
        // cold build
        assert!(matches!(r.outcome, Outcome::Specialized { .. }) && r.rung == Some(Rung::Driven) && !prints_source(&em, f), "{f}: {:?}", r.outcome);
    }
    // 1. rejected by add_def, a kernel type error, and reported (a warning)
    assert_eq!(cache_rejections(&em.opt.warnings, "crate::nested", "TypeMismatch").len(), 1, "{:?}", em.opt.warnings);
    assert!(!em.opt.warnings.iter().any(|w| w.contains("`crate::small`")), "{:?}", em.opt.warnings);
    assert!(report(&em, "crate::nested").candidates.iter().any(|c| c.rung == Rung::Driven && c.chosen && c.reason.contains("rejected entries removed and rebuilt")), "{:?}", report(&em, "crate::nested").candidates);
    // 2. the cold build's code; the forged entry replaced by the rebuilt
    // proof (the cold build's entry, byte for byte)
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert_eq!(em.code, cold.code, "a rejected hint must not change the emitted code");
    assert_eq!(std::fs::read(&entries[nested_ix]).unwrap(), bytes[nested_ix], "the rejected entry is rebuilt");
    // 3. a build error under strict options
    forge();
    let em = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert_eq!(cache_rejections(&em.opt.errors, "crate::nested", "TypeMismatch").len(), 1, "{:?}", em.opt.errors);
    assert!(!em.opt.errors.iter().any(|e| e.contains("`crate::small`")), "{:?}", em.opt.errors);
    assert_eq!(em.code, cold.code);
    // and the next build is clean: the rejected entry did not survive
    let em = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty(), "{:?} {:?}", em.opt.errors, em.opt.warnings);
    assert_eq!(em.code, cold.code);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A static recursion (the varint reader) specialized into per-level
/// helpers `leb128_go__<fuel>_<shift>` (design §6.5) by the driver on
/// `leb128`, whose straight-line residual (tier 0, linked by conversion) is
/// admitted too: its drive replaces it only because it keeps the static
/// recursion. `location` calls `leb128`.
const SRC_R25_HELPERS: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub const MAX_LEAVES: u64 = 1u64 << 62u32;

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn leb128_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        if (fuel != 1 || h < 2) && (shift == 0 || h != 0) { Some((value, t)) } else { None }
    } else {
        leb128_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn leb128(xs: &[u8]) -> Option<(u64, &[u8])> {
    leb128_go(10, xs, 0, 0)
}

pub fn location(xs: &[u8]) -> Option<(u64, &[u8])> {
    let (value, rest) = leb128(xs)?;
    if value <= MAX_LEAVES { Some((value, rest)) } else { None }
}
"#;

/// R25 on disk, next to an admitted straight-line residual: the cached
/// proofs of `leb128`'s helper lemmas rotated among themselves (well-formed
/// proofs of other lemmas, dependencies unchanged). Every one is rejected
/// by `add_def`. Formerly the driven candidate then failed silently (its
/// tier-0 residual stood in, no warning, no strict error) and every later
/// build repeated it, with different code (`location` no longer driven
/// through `leb128`'s summary). Now: each rejection is reported (a
/// warning; a build error under strict options), each entry is removed and
/// rebuilt, the build emits the cold build's code, and the next build is
/// clean.
#[test]
fn r25_forged_helper_entries_next_to_a_straight_line_residual_are_reported() {
    let _g = serial();
    let c = check_files(&[("r/mod.rs", SRC_R25_HELPERS)], "r/mod.rs");
    let dir = std::env::temp_dir().join(format!("sandblaster-r25-helpers-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cold = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert!(cold.opt.errors.is_empty() && cold.opt.warnings.is_empty() && cold.roundtrip.is_empty(), "{:?} {:?} {:?}", cold.opt.errors, cold.opt.warnings, cold.roundtrip);
    // the shape this test is about: tier 0 admitted, the driven residual
    // chosen over it
    let f = report(&cold, "crate::leb128");
    assert!(f.rung == Some(Rung::Driven) && f.candidates.iter().any(|c| c.rung == Rung::StraightLine && !c.chosen && c.reason.starts_with("admitted")), "{:?} {:?}", f.rung, f.candidates);
    let entries = cache_entries(&dir);
    let bytes: Vec<Vec<u8>> = entries.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let helpers: Vec<usize> = (0..entries.len()).filter(|&i| mentions(&bytes[i], "crate::leb128_go__") && !mentions(&bytes[i], "crate::leb128__residual") && !mentions(&bytes[i], "crate::location__residual")).collect();
    assert!(helpers.len() >= 2, "the helper lemmas' entries: {} of {}", helpers.len(), entries.len());
    let rotate = || {
        for (k, &i) in helpers.iter().enumerate() {
            std::fs::write(&entries[i], &bytes[helpers[(k + 1) % helpers.len()]]).unwrap();
        }
    };
    // non-strict: warnings, the cold build's code, the entries rebuilt
    rotate();
    let em = optimize_cached(&c, "r/mod.rs", &dir, false);
    let f = report(&em, "crate::leb128");
    println!("R25 (helpers) leb128: {:?} {:?}\n     {:?}\n     warnings {:?}", f.outcome, f.rung, f.candidates, em.opt.warnings);
    // (a rotated entry whose proof names a helper not yet committed when it
    // is read is a plain miss; the others reach the kernel)
    let rejected = |msgs: &[String]| msgs.iter().filter(|m| m.contains("`crate::leb128`") && m.contains("cache entry rejected by the kernel (add_def: ")).count();
    let n = rejected(&em.opt.warnings);
    assert!((2..=helpers.len()).contains(&n) && !cache_rejections(&em.opt.warnings, "crate::leb128", "TypeMismatch").is_empty(), "a warning per rejected entry: {:?}", em.opt.warnings);
    assert_eq!(em.opt.warnings.len(), n, "only the rejections: {:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_))), "{:?} {:?}", f.rung, f.candidates);
    assert_eq!(em.code, cold.code, "a rejected hint must not change the emitted code");
    for &i in &helpers {
        assert_eq!(std::fs::read(&entries[i]).unwrap(), bytes[i], "the rejected entry {:?} is rebuilt", entries[i]);
    }
    // strict: build errors
    rotate();
    let em = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert_eq!(rejected(&em.opt.errors), n, "{:?}", em.opt.errors);
    assert_eq!(em.code, cold.code);
    // then clean
    let em = optimize_cached(&c, "r/mod.rs", &dir, true);
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty(), "{:?} {:?}", em.opt.errors, em.opt.warnings);
    assert_eq!(em.code, cold.code);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// R26 / R27: a portable `add4` with a (private) NEON variant, a caller `top`
// (cloned into the variant set as `top__neon`) — the multiversioning sample
// of tests/redteam_opt.rs without the method. The variant is not exported, so
// without evidence it is simply left out of the emitted code (§9.2).
// ---------------------------------------------------------------------------

const SRC_MV: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::vaddq_u32;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u32x4, store_u32x4};

pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "neon")]
#[implements(crate::add4)]
fn add4_neon(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

pub fn top(x: [u32; 4]) -> [u32; 4] {
    add4(add4(x, [1, 2, 3, 4]), x)
}
"#;

#[test]
fn r26_unvalidated_intrinsic_in_a_dispatched_variant_is_rejected_by_the_evidence_gate() {
    use sandblaster_targets::evidence;
    use sandblaster_targets::registry::Arch;
    const MODEL: &str = "vaddq_u32";
    let _g = serial();
    let c = check_files(&[("r/mod.rs", SRC_MV)], "r/mod.rs");
    let withheld = evidence::withhold(Arch::Aarch64, &[MODEL]);
    assert!(!evidence::is_validated(Arch::Aarch64, MODEL));
    // control: without evidence the optimizer does not dispatch the variant
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    let v = em.opt.variants.iter().find(|v| v.variant == "crate::add4_neon").expect("variant report");
    assert!(!v.dispatched, "{v:?}");
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    // the fault: the variant dispatched anyway (a simulated optimizer bug)
    let forced = OptTestHooks { force_dispatch: ["crate::add4_neon".to_string()].into(), ..Default::default() };
    for strict in [false, true] {
        let em = optimize(&c, "r/mod.rs", &forced, strict);
        let v = em.opt.variants.iter().find(|v| v.variant == "crate::add4_neon").unwrap();
        println!("R26 (strict={strict}): {} | errors {:?}", v.note, em.opt.errors);
        assert!(v.dispatched, "the hook must have forced the dispatch: {v:?}");
        // 1. rejected by the evidence gate, naming the model
        // 2. fails closed: the gate's error means nothing is emitted (strict
        //    or not; `build_verified` refuses any optimizer error)
        // 3. so a build error under strict too
        assert!(em.opt.errors.iter().any(|e| e.contains(MODEL) && e.contains("without hardware evidence")), "{:?}", em.opt.errors);
    }
    drop(withheld);
    // with the evidence restored the same (forced) dispatch is legitimate
    let em = optimize(&c, "r/mod.rs", &forced, true);
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
}

#[test]
fn r27_clone_residual_without_clone_equiv_is_rejected_by_the_emission_chain_check() {
    let _g = serial();
    let c = check_files(&[("r/mod.rs", SRC_MV)], "r/mod.rs");
    // control: the set is dispatched, every clone has its kernel-checked lemma
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert_eq!(em.opt.sets.len(), 1, "one variant set");
    let cl = em.opt.clones.iter().find(|r| r.clone == "crate::top__neon").expect("clone of top");
    assert_eq!(cl.lemma.as_deref(), Some("crate::top__neon::clone_equiv"));
    assert!(em.code.contains("top__neon"), "the clone is emitted");
    assert!(matches!(report(&em, "crate::top__neon").outcome, Outcome::Specialized { .. }), "the clone's residual is emitted");

    // (a) the clone's lemma skipped but claimed
    let forged = OptTestHooks { forge_clone_lemma: ["crate::top__neon".to_string()].into(), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &forged, false);
    println!("R27a warnings: {:?}", em.opt.warnings);
    // 1. the emission-chain check finds no such lemma in the kernel
    assert!(em.opt.warnings.iter().any(|w| w.contains("emission chain") && w.contains("crate::top__neon") && w.contains("not in the kernel environment")), "{:?}", em.opt.warnings);
    // 2. fallback: the set is not dispatched, the portable code is emitted
    assert!(em.opt.sets.is_empty() && em.opt.dispatchers.is_empty(), "the set must fall back");
    assert!(!em.code.contains("top__neon") && !em.code.contains("add4__portable"), "no clone or dispatcher may be emitted:\n{}", em.code);
    assert!(em.opt.clones.iter().all(|r| r.lemma.as_deref() != Some("crate::top__neon::clone_equiv")), "the forged claim must not survive in the report");
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    // 3. a build error under strict
    let em = optimize(&c, "r/mod.rs", &forged, true);
    assert!(em.opt.errors.iter().any(|e| e.contains("emission chain") && e.contains("crate::top__neon")), "{:?}", em.opt.errors);

    // (b) a tampered proof of the clone lemma (`refl` of the wrong function)
    let tampered = OptTestHooks { proofs: BTreeMap::from([("crate::top__neon::clone_equiv".to_string(), refl_of("crate::add4_neon"))]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &tampered, false);
    println!("R27b warnings: {:?}", em.opt.warnings);
    // 1. add_def refuses it (a kernel type error)
    assert!(em.opt.warnings.iter().any(|w| w.contains("crate::top__neon") && w.contains("no kernel-checked equality lemma") && w.contains("TypeMismatch")), "{:?}", em.opt.warnings);
    // 2. no lemma is recorded, and a clone without its lemma is not admitted
    //    (plan O4 retired the renaming argument): the set falls back to the
    //    portable code
    let cl = em.opt.clones.iter().find(|r| r.clone == "crate::top__neon").unwrap();
    assert!(cl.lemma.is_none(), "{cl:?}");
    assert!(em.opt.sets.is_empty() && em.opt.dispatchers.is_empty(), "the set must fall back");
    assert!(!em.code.contains("top__neon"), "no clone may be emitted:\n{}", em.code);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    // 3. a build error under strict
    let em = optimize(&c, "r/mod.rs", &tampered, true);
    assert!(em.opt.errors.iter().any(|e| e.contains("crate::top__neon") && e.contains("no kernel-checked equality lemma")), "{:?}", em.opt.errors);
}

// ---------------------------------------------------------------------------
// The corpus's must-reject pairs (corpus.toml; opt_corpus/conv_pairs.rs,
// must_reject.rs, must_reject_controls.rs)
//
// A rejected candidate is evidence only when a correct candidate of the same
// shape is admitted: today's route (tier-0 conversion) refuses whole shapes
// (any relevant `match`, loops, helpers defined after the entry, closed forms
// that are not convertible) whether the candidate is right or wrong. So every
// wrong candidate comes with a control, and each pair is classified:
// `attributable` (the control is admitted, the mutant rejected: the verdicts
// differ because of the mutation alone) or not (both rejected: `pending` the
// milestone whose route admits the shape). The classification and each
// rejection's reason are pinned in corpus.toml and asserted here.
// ---------------------------------------------------------------------------

/// The files proposed as candidates, mounted as modules of the corpus.
const CANDIDATE_FILES: [&str; 3] = ["conv_pairs", "must_reject", "must_reject_controls"];

/// The corpus files plus the candidate files, mounted as `c/`.
fn corpus_with_candidates() -> Vec<(String, String)> {
    let dir = manifest::corpus_dir();
    let mut files = Vec::new();
    for e in std::fs::read_dir(dir.join("dsl")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        let mut text = std::fs::read_to_string(&p).unwrap();
        if name == "mod.rs" {
            for m in CANDIDATE_FILES {
                text.push_str(&format!("\npub mod {m};\n"));
            }
        }
        files.push((format!("c/{name}"), text));
    }
    for m in CANDIDATE_FILES {
        files.push((format!("c/{m}.rs"), std::fs::read_to_string(dir.join(format!("{m}.rs"))).unwrap()));
    }
    files.sort();
    files
}

/// Which pair of a program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PairKind {
    /// `conv_*`: a control of the shape today's route (tier-0 conversion)
    /// admits and its one-token mutation (opt_corpus/conv_pairs.rs).
    Conv,
    /// `must_reject*`: the frozen variant for the program's eventual route
    /// (must_reject.rs) and the variant with its bug fixed
    /// (must_reject_controls.rs).
    Route,
}

/// One must-reject pair: a correct control and a wrong mutant of the same
/// shape, proposed in turn as the program's candidate.
struct Pair<'a> {
    p: &'a manifest::Program,
    entry: &'a str,
    control: &'a str,
    mutant: &'a str,
    /// An input on which the mutant differs from the program.
    witness: &'a str,
    /// `attributable`, or why the pair is not evidence yet (`pending <milestone>: …`,
    /// `unattributable: …`).
    status: &'a str,
    /// The mutant's rejection: `<rejected_by> | <fragment of the kernel's message>`.
    reason: &'a str,
    /// The control's rejection when the pair is not attributable (same format).
    control_reason: Option<&'a str>,
}

impl Pair<'_> {
    fn attributable(&self) -> bool {
        self.status == "attributable"
    }
}

fn pairs(programs: &[manifest::Program], kind: PairKind) -> Vec<Pair<'_>> {
    let key = |k: &str| match kind {
        PairKind::Conv => format!("conv_{k}"),
        PairKind::Route => format!("must_reject_{k}"),
    };
    programs
        .iter()
        .map(|p| {
            let pair = Pair {
                p,
                entry: p.get("entry"),
                control: p.get(&key("control")),
                mutant: match kind {
                    PairKind::Conv => p.get("conv_mutant"),
                    PairKind::Route => p.get("must_reject"),
                },
                witness: match kind {
                    PairKind::Conv => p.get("conv_witness"),
                    PairKind::Route => p.get("witness"),
                },
                status: p.get(&key("status")),
                reason: p.get(&key("reason")),
                control_reason: p.fields.get(&key("control_reason")).map(|s| s.as_str()),
            };
            assert!(
                pair.status == "attributable" || pair.status.starts_with("pending O") || pair.status.starts_with("unattributable: "),
                "{} {kind:?}: status `{}` is not `attributable`, `pending O<n>: …` or `unattributable: …`",
                p.id(),
                pair.status
            );
            assert_eq!(pair.attributable(), pair.control_reason.is_none(), "{} {kind:?}: a control reason is pinned exactly when the pair is not attributable", p.id());
            pair
        })
        .collect()
}

/// What the admission route did with the candidate injected for a function.
#[derive(Debug, PartialEq)]
enum Verdict {
    Admitted,
    Rejected { by: String, why: String },
}

impl Verdict {
    fn is(&self, pinned: &str) -> bool {
        let (by, frag) = pinned.split_once(" | ").unwrap_or((pinned, ""));
        matches!(self, Verdict::Rejected { by: b, why } if b == by && why.contains(frag))
    }
    fn show(&self) -> String {
        match self {
            Verdict::Admitted => "admitted".into(),
            Verdict::Rejected { by, why } => format!("{by} | {}", why.trim_start_matches("the kernel rejected the residual: ").chars().take(110).collect::<String>()),
        }
    }
}

fn verdict(em: &OptimizedEmit, entry: &str) -> Verdict {
    let f = report(em, entry);
    let cand = f.candidates.first().unwrap_or_else(|| panic!("{entry}: no candidate"));
    assert!(cand.injected, "{entry}: the candidate must be the injected one: {cand:?}");
    match &f.outcome {
        Outcome::Specialized { .. } => {
            assert!(cand.chosen && cand.rejected_by.is_none(), "{entry}: {cand:?}");
            assert!(!prints_source(em, entry), "{entry}: an admitted candidate is printed");
            Verdict::Admitted
        }
        Outcome::Unspecialized { failure: true, reason } => {
            assert!(!cand.chosen, "{entry}: {cand:?}");
            // the fallback: the source printed, a warning (an error under strict)
            assert!(prints_source(em, entry), "{entry}: the source must be printed");
            Verdict::Rejected { by: cand.rejected_by.clone().unwrap_or_else(|| "-".into()), why: reason.clone() }
        }
        o => panic!("{entry}: unexpected outcome for an injected candidate: {o:?}"),
    }
}

/// Classifies a pair from its verdicts against its pins: `Ok(true)` when it
/// is evidence (the control admitted, the mutant rejected as pinned: the
/// verdicts differ because of the mutation alone), `Ok(false)` when it is not
/// evidence yet (both rejected, each as pinned), else what contradicts the
/// pins. A wrong candidate must never be admitted, whatever the status.
fn classify(control: &Verdict, mutant: &Verdict, reason: &str, control_reason: Option<&str>) -> Result<bool, Vec<String>> {
    let mut bad = Vec::new();
    match mutant {
        Verdict::Admitted => bad.push("the WRONG candidate was admitted".to_string()),
        m if !m.is(reason) => bad.push(format!("the mutant's rejection is `{}`, pinned `{reason}`", m.show())),
        _ => {}
    }
    let attributable = match (control, control_reason) {
        (Verdict::Admitted, None) => true,
        (Verdict::Admitted, Some(_)) => {
            bad.push("the control is now admitted, so the pair is evidence: set its status to `attributable` and drop its control reason".into());
            true
        }
        (Verdict::Rejected { .. }, None) => {
            bad.push(format!("the control was rejected (`{}`), so the mutant's rejection is not attributable to its mutation", control.show()));
            false
        }
        (Verdict::Rejected { .. }, Some(r)) => {
            if !control.is(r) {
                bad.push(format!("the control's rejection is `{}`, pinned `{r}`", control.show()));
            }
            false
        }
    };
    if bad.is_empty() { Ok(attributable) } else { Err(bad) }
}

/// `classify` refuses the evidence the corpus test used to accept: a
/// rejection "for either kernel reason" says nothing when the correct control
/// is rejected for the same reason (the kernel refused the shape).
#[test]
fn pair_classification_needs_an_admitted_control() {
    let rej = |by: &str, why: &str| Verdict::Rejected { by: by.into(), why: format!("the kernel rejected the residual: {why}") };
    let conv = "check_residual_equal: TypeMismatch | candidate is not convertible";
    let shape = "check_residual_equal: IllFormed | candidate contains a relevant `match`";
    let not_conv = || rej("check_residual_equal: TypeMismatch", "TypeMismatch: candidate is not convertible with `crate::f`");
    let ill = || rej("check_residual_equal: IllFormed", "IllFormed: candidate contains a relevant `match`");
    // evidence: the control admitted, the mutant rejected as pinned
    assert_eq!(classify(&Verdict::Admitted, &not_conv(), conv, None), Ok(true));
    // the old acceptance criterion: both rejected for a kernel reason; claimed as evidence, refused
    let e = classify(&not_conv(), &not_conv(), conv, None).unwrap_err();
    assert!(e[0].contains("not attributable"), "{e:?}");
    let e = classify(&ill(), &ill(), shape, None).unwrap_err();
    assert!(e[0].contains("not attributable"), "{e:?}");
    // the same pair, declared not attributable with both reasons pinned: accepted, not counted
    assert_eq!(classify(&ill(), &ill(), shape, Some(shape)), Ok(false));
    // pins are exact: another kernel reason is a mismatch, for the mutant and the control
    assert!(classify(&Verdict::Admitted, &ill(), conv, None).is_err());
    assert!(classify(&not_conv(), &ill(), shape, Some(shape)).is_err());
    // a wrong candidate admitted is always an error; a pending pair whose control is now admitted must be re-pinned
    assert!(classify(&Verdict::Admitted, &Verdict::Admitted, conv, None).unwrap_err()[0].contains("WRONG"));
    assert!(classify(&Verdict::Admitted, &not_conv(), conv, Some(conv)).unwrap_err()[0].contains("now admitted"));
}

/// The tokens of the body of `pub fn <name>(` in `src` (the lines after its
/// signature line, up to the closing `}` at column 0).
fn body_tokens(src: &str, name: &str) -> Vec<String> {
    let head = format!("pub fn {name}(");
    let start = src.lines().position(|l| l.starts_with(&head)).unwrap_or_else(|| panic!("no `{head}`"));
    let body: Vec<&str> = src.lines().skip(start + 1).take_while(|l| *l != "}").collect();
    let text = body.join("\n");
    let (mut out, mut it) = (Vec::new(), text.chars().peekable());
    while let Some(c) = it.next() {
        if c.is_whitespace() {
            continue;
        }
        let mut t = c.to_string();
        if c.is_alphanumeric() || c == '_' {
            while let Some(&d) = it.peek().filter(|d| d.is_alphanumeric() || **d == '_') {
                t.push(d);
                it.next();
            }
        } else if let Some(&d) = it.peek() {
            if ["<=", ">=", "==", "!=", "<<", ">>", "&&", "||", "->", "::", ".."].contains(&format!("{c}{d}").as_str()) {
                t.push(d);
                it.next();
            }
        }
        out.push(t);
    }
    out
}

/// Each conversion mutant is its control with exactly one token changed.
#[test]
fn conversion_mutants_are_one_token_mutations() {
    let src = std::fs::read_to_string(manifest::corpus_dir().join("conv_pairs.rs")).unwrap();
    for p in manifest::load() {
        let name = |k: &str| p.get(k).rsplit("::").next().unwrap().to_string();
        let (c, m) = (body_tokens(&src, &name("conv_control")), body_tokens(&src, &name("conv_mutant")));
        let diff: Vec<(&String, &String)> = c.iter().zip(&m).filter(|(a, b)| a != b).collect();
        assert!(c.len() == m.len() && diff.len() == 1, "{}: the mutant is not a one-token mutation of the control: {} vs {} tokens, differing at {diff:?}", p.id(), c.len(), m.len());
        println!("{:4} {} -> {}  ({})", p.id(), diff[0].0, diff[0].1, p.get("conv_mutation"));
    }
}

/// Checks and classifies one kind of pair over the whole corpus.
fn corpus_pairs(kind: PairKind) {
    let _g = serial();
    let programs = manifest::load();
    let pairs = pairs(&programs, kind);
    let files = corpus_with_candidates();
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, s)| (p.as_str(), s.as_str())).collect();
    let c = check_files(&refs, "c/mod.rs");
    // 1. kernel evaluation: the mutant differs from the program on its
    //    witness, the control agrees with it on every input of the program
    //    (its probes and both witnesses)
    {
        let k = c.krate.as_ref().unwrap();
        elab::with_big_stack(|| {
            let mut chain = ProverChain::standard();
            let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            assert!(out.obligations.iter().all(|o| o.proven()), "the corpus and its candidates must verify");
            let ev = |f: &str, x: &str, id: &str| driver::stage::eval_in(&out, k, f, x).unwrap_or_else(|e| panic!("{id} {f}{x}: {e}"));
            for q in &pairs {
                let id = q.p.id();
                let (a, b) = (ev(q.entry, q.witness, id), ev(q.mutant, q.witness, id));
                println!("{id:4} {kind:?} {}{:.40} = {a:.50} | mutant = {b:.50}", q.entry, q.witness);
                assert_ne!(a, b, "{id} {kind:?}: the mutant `{}` agrees with the program on its witness", q.mutant);
                let mut inputs: Vec<&str> = q.p.fields.get("probes").map(|s| s.split('\u{1f}').collect()).unwrap_or_default();
                inputs.extend([q.p.get("witness"), q.p.get("conv_witness")]);
                for x in inputs {
                    assert_eq!(ev(q.control, x, id), ev(q.entry, x, id), "{id} {kind:?}: the control `{}` differs from the program on {x}", q.control);
                }
            }
        });
    }
    // 2. the verdicts: every control, then every mutant, proposed at once
    let controls = OptTestHooks { candidates: pairs.iter().map(|q| (q.entry.to_string(), q.control.to_string())).collect(), ..Default::default() };
    let mutants = OptTestHooks { candidates: pairs.iter().map(|q| (q.entry.to_string(), q.mutant.to_string())).collect(), ..Default::default() };
    let em_c = optimize(&c, "c/mod.rs", &controls, true);
    let em_m = optimize(&c, "c/mod.rs", &mutants, false);
    let mut bad = Vec::new();
    let (mut attributable, mut pending) = (Vec::new(), Vec::new());
    println!("\n{kind:?} pairs: control verdict | mutant verdict");
    for q in &pairs {
        let (id, entry) = (q.p.id(), q.entry);
        let (vc, vm) = (verdict(&em_c, entry), verdict(&em_m, entry));
        println!("{id:4} {:9} control: {}\n{:14} mutant:  {}", if q.attributable() { "attrib." } else { "pending" }, vc.show(), "", vm.show());
        match classify(&vc, &vm, q.reason, q.control_reason) {
            Ok(true) => attributable.push(id),
            Ok(false) => pending.push(format!("{id} ({})", q.status)),
            Err(e) => bad.extend(e.into_iter().map(|e| format!("{id} {kind:?} (control `{}`, mutant `{}`): {e}", q.control, q.mutant))),
        }
        // strict: an error exactly for each rejected candidate
        let err = |em: &OptimizedEmit| em.opt.errors.iter().any(|e| e.contains(&format!("`{entry}`")) && e.contains("specialization failed"));
        if err(&em_c) != matches!(vc, Verdict::Rejected { .. }) {
            bad.push(format!("{id} {kind:?}: strict errors do not match the control's verdict: {:?}", em_c.opt.errors));
        }
        if !em_m.opt.warnings.iter().any(|w| w.contains(&format!("`{entry}`"))) {
            bad.push(format!("{id} {kind:?}: no warning for the rejected mutant"));
        }
        // today's route admits a candidate for a function exactly when the
        // optimizer specializes it: every specialized entry has conversion
        // evidence, and no other entry claims it
        if kind == PairKind::Conv {
            // (the straight-line rung admits the entry: chosen, or superseded
            // by the driven residual)
            let spec = q.p.today.get(entry).is_some_and(|t| t == "Specialized" || t.ends_with("straight-line superseded)"));
            if spec != q.attributable() {
                bad.push(format!("{id} Conv: the entry is {} today, but the pair is {}", if spec { "Specialized" } else { "not specialized" }, q.status));
            }
        }
    }
    assert!(em_m.opt.errors.is_empty() && em_m.roundtrip.is_empty(), "the fallbacks must build: {:?} {:?}", em_m.opt.errors, em_m.roundtrip);
    assert!(em_c.roundtrip.is_empty(), "the admitted controls must round-trip: {:?}", em_c.roundtrip);
    println!("\n{kind:?}: {} attributable ({}), {} not attributable: {}", attributable.len(), attributable.join(" "), pending.len(), pending.join("; "));
    assert!(bad.is_empty(), "{} must-reject pair mismatch(es):\n{}", bad.len(), bad.join("\n"));
    // 3. build errors under strict, one per mutant
    let em = optimize(&c, "c/mod.rs", &mutants, true);
    for q in &pairs {
        assert!(em.opt.errors.iter().any(|e| e.contains(&format!("`{}`", q.entry)) && e.contains("specialization failed")), "{}: {:?}", q.p.id(), em.opt.errors);
    }
}

/// The conversion pairs: today's must-reject evidence. Every specialized
/// entry's control is admitted and its one-token mutant rejected as not
/// convertible; the other entries' pairs are pending O4.
#[test]
fn corpus_conversion_pairs_are_attributable() {
    corpus_pairs(PairKind::Conv);
}

/// The frozen route variants: each is rejected (a wrong candidate is never
/// admitted) with the source printed, but none is attributable yet — each
/// control is rejected for the same shape — so they are pending the
/// milestones whose routes admit their shapes.
#[test]
fn corpus_route_variants_are_rejected_and_classified() {
    corpus_pairs(PairKind::Route);
}

// ---------------------------------------------------------------------------
// O4, the driven route (design §20 R1, R3, R4, R11–R15, R24). Each fault is
// injected with `OptTestHooks::drive_faults` (`opt::DriveFault`): the
// driver, the residual printer or the helper builder proposes something
// wrong and the proof builder trusts it (closes leaves by `refl`, emits the
// claimed decisions), so the rejection comes from the kernel or from
// elaboration. Control: the same function without the fault is driven and
// admitted by its kernel-checked lemma (`Link::Lemma`).
// ---------------------------------------------------------------------------

use sandblaster_front::opt::{DriveFault, Link, Rung};

/// Runs the control and the fault for `name` of `src`: the control is
/// admitted as driven; the fault is rejected by `rejected_by` (a prefix of
/// the driven candidate's `rejected_by`) with the source printed and a
/// warning, and is a build error under strict options.
fn drive_fault_case(tag: &str, src: &str, name: &str, fault: DriveFault, rejected_by: &str) {
    let _g = serial();
    let c = check_files(&[("r/mod.rs", src)], "r/mod.rs");
    // control
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    let f = report(&em, name);
    assert!(matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_))), "{tag} control: `{name}` must be driven and admitted: {:?} {:?}", f.outcome, f.candidates);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag} control: {:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(!prints_source(&em, name), "{tag} control: the residual must be printed");
    // the fault
    let hooks = OptTestHooks { drive_faults: BTreeMap::from([(name.to_string(), fault)]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, false);
    let f = report(&em, name);
    println!("{tag}: {:?}\n     {:?}", f.outcome, f.candidates);
    // 1. rejected by the expected check
    let cand = f.candidates.iter().find(|c| c.rung == Rung::Driven).expect("a driven candidate");
    assert!(!cand.chosen, "{tag}: the faulty residual must not be admitted: {cand:?}");
    assert!(cand.rejected_by.as_deref().is_some_and(|r| r.starts_with(rejected_by)), "{tag}: expected a rejection by `{rejected_by}`: {cand:?}");
    // 2. Unspecialized { failure: true }, the source printed, a warning
    assert!(matches!(&f.outcome, Outcome::Unspecialized { failure: true, .. }), "{tag}: {:?}", f.outcome);
    assert!(prints_source(&em, name), "{tag}: the source must be printed");
    assert!(em.opt.warnings.iter().any(|w| w.contains(name)), "{tag}: {:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag}: the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    // 3. a build error under strict
    let em = optimize(&c, "r/mod.rs", &hooks, true);
    assert!(em.opt.errors.iter().any(|e| e.contains(name)), "{tag}: {:?}", em.opt.errors);
}

/// R1: the prune of a live arm. `x < 20` is dead-false only in the driver's
/// imagination: under `x < 10` it is true; the certificate-free claim
/// `Eq(Bool, x < 20, false)` fails the kernel's linarith check.
#[test]
fn r1_prune_of_a_live_arm_is_rejected_by_linarith() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn nested(x: u64) -> u64 {
    if x < 10 {
        if x < 20 { x } else { 99 }
    } else {
        0
    }
}
"#;
    drive_fault_case("R1", SRC, "crate::nested", DriveFault::FlipPrune, "add_def: Linarith");
}

/// R2: the varint's range check after the ninth byte claimed dead. In
/// `location` (the QMDB reader, `sandblaster/fixtures/qmdb/sandblaster/codec.rs` verbatim) the
/// check `value <= MAX_LEAVES` is decided in the leaves of the first eight
/// bytes, but after nine bytes the value may exceed `2^62` (bits 56–62):
/// the certificate-free claim `Eq(Bool, value <= MAX_LEAVES, true)` fails
/// the kernel's linarith check.
#[test]
fn r2_varint_ninth_byte_range_check_claimed_dead_is_rejected_by_linarith() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub const MAX_LEAVES: u64 = 1u64 << 62u32;

fn uint64_finish(ok: bool, value: u64, rest: &[u8]) -> Option<(u64, &[u8])> {
    if ok { Some((value, rest)) } else { None }
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn uint64_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        let ok = (fuel != 1 || h < 2) && (shift == 0 || h != 0);
        uint64_finish(ok, value, t)
    } else {
        uint64_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> {
    uint64_go(10, xs, 0, 0)
}

pub fn location(xs: &[u8]) -> Option<(u64, &[u8])> {
    let (value, rest) = uint64(xs)?;
    if value <= MAX_LEAVES { Some((value, rest)) } else { None }
}
"#;
    drive_fault_case("R2", SRC, "crate::location", DriveFault::RangeCheckDead, "add_def: Linarith");
}

/// R10: a fold with a non-decreasing measure. `sum_small`'s checked sum
/// (corpus P10) is folded into a loop helper with the bound invariant
/// `acc <= (65536 - xs.len()) * (2^32 - 1)` (plan O5); the fault declares
/// the helper's lemma measure-recursive on the accumulator, which grows at
/// the back-edge, and claims the decrease with a certificate-free
/// `linarith`: the kernel's termination check (the `rec`'s decrease proof)
/// refuses it.
#[test]
fn r10_fold_with_a_non_decreasing_measure_is_rejected_by_the_kernel() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(xs.len() <= 65536)]
#[decreases(xs.len())]
fn sum_checked_go(xs: &[u32], acc: u64) -> Option<u64> {
    match xs {
        [] => Some(acc),
        [h, t @ ..] => match acc.checked_add(*h as u64) {
            None => None,
            Some(a) => sum_checked_go(t, a),
        },
    }
}

pub fn sum_small(xs: &[u32]) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    sum_checked_go(xs, 0)
}
"#;
    drive_fault_case("R10", SRC, "crate::sum_small", DriveFault::FoldBadMeasure, "add_def: Linarith");
}

/// R3: a partial read hoisted out of its guard: `xs[i]` printed (as an
/// unchecked read) above `if i < xs.len()`; its bound obligation no longer
/// has the guard's fact, and the residual does not elaborate.
#[test]
fn r3_partial_read_hoisted_out_of_its_guard_is_rejected_by_elaboration() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn get_or_zero(xs: &[u8], i: usize) -> u8 {
    if i < xs.len() { xs[i] } else { 0 }
}
"#;
    drive_fault_case("R3", SRC, "crate::get_or_zero", DriveFault::HoistPartial, "elaboration");
}

/// R4: the residual's arms differ from the driven source (`Some`/`None`
/// swapped): the lemma's leaves do not convert.
#[test]
fn r4_residual_arm_swapped_is_rejected_by_the_lemma_type_check() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn half(x: u64) -> Option<u64> {
    if x % 2 == 0 { Some(x / 2) } else { None }
}
"#;
    drive_fault_case("R4", SRC, "crate::half", DriveFault::SwapArms, "add_def: TypeMismatch");
}

/// A static recursion (literal fuel) that the driver specializes into
/// per-level helpers `go__3`, `go__2`, … (design §6.5), called from a
/// function tier 0 cannot specialize (stuck on `on`).
const SRC_HELPERS: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(fuel <= 3)]
#[decreases(fuel)]
fn go(fuel: u32, xs: &[u8], acc: u64) -> u64 {
    if fuel == 0 {
        return acc;
    }
    let [h, t @ ..] = xs else {
        return acc;
    };
    go(fuel - 1, t, acc.wrapping_add(*h as u64))
}

pub fn sum3(xs: &[u8], acc: u64, on: bool) -> u64 {
    if on { go(3, xs, acc) } else { acc }
}
"#;

/// R11: helpers calling each other (a helper calling itself in place of the
/// next level): recursion without a termination measure is refused.
#[test]
fn r11_recursive_helpers_are_rejected_by_elaboration() {
    drive_fault_case("R11", SRC_HELPERS, "crate::sum3", DriveFault::SelfHelper, "elaboration");
}

/// R12: a helper whose `requires` (`acc == 0`) is not implied at its call
/// sites: the call's obligation is not proven.
#[test]
fn r12_helper_requires_not_implied_is_rejected_by_elaboration() {
    drive_fault_case("R12", SRC_HELPERS, "crate::sum3", DriveFault::HelperRequires, "elaboration");
}

/// R5 (Σ3): a segment rewrite off by one. The buffer slice
/// `buf[0..na + 2 + nb]` reaches one element into the zero padding, where
/// the segment normal form stops (a `take` ending inside a replicated piece:
/// the control is not rewritten). The fault claims the `take` ends before
/// the padding (`take(C, na+2+nb) = A ++ mid :: B`), the side condition
/// `k ≤ 0` (`k = 1`) with a certificate-free `linarith`: the residual folds
/// one element too few and the kernel's linarith check refuses the lemma.
#[test]
fn r5_segment_take_off_by_one_is_rejected_by_linarith() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub const CAP: usize = 64;

pub fn concat_fold_pad(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP - 1 {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + 2 + nb], 0))
}
"#;
    let _g = serial();
    let name = "crate::concat_fold_pad";
    let c = check_files(&[("r/mod.rs", SRC)], "r/mod.rs");
    // control: not rewritten (the normal form stops at the padding), no failure
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    let f = report(&em, name);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "R5 control: {:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(!matches!(f.outcome, Outcome::Unspecialized { failure: true, .. }), "R5 control: {:?}", f.outcome);
    assert!(f.rung != Some(Rung::Driven), "R5 control: the padded slice is not rewritten: {:?}", f.candidates);
    // the fault
    let hooks = OptTestHooks { drive_faults: BTreeMap::from([(name.to_string(), DriveFault::SegTakeShort)]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, false);
    let f = report(&em, name);
    println!("R5: {:?}\n     {:?}", f.outcome, f.candidates);
    let cand = f.candidates.iter().find(|c| c.rung == Rung::Driven).expect("a driven candidate");
    assert!(!cand.chosen, "R5: the faulty residual must not be admitted: {cand:?}");
    assert!(cand.rejected_by.as_deref().is_some_and(|r| r.starts_with("add_def: Linarith")), "R5: expected a rejection by the kernel's linarith: {cand:?}");
    assert!(matches!(&f.outcome, Outcome::Unspecialized { failure: true, .. }), "R5: {:?}", f.outcome);
    assert!(prints_source(&em, name), "R5: the source must be printed");
    assert!(em.opt.warnings.iter().any(|w| w.contains(name)), "R5: {:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "R5: the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    let em = optimize(&c, "r/mod.rs", &hooks, true);
    assert!(em.opt.errors.iter().any(|e| e.contains(name)), "R5: {:?}", em.opt.errors);
}

/// R9 (Σ3): the fold's order over the pieces swapped. The buffer of P7 is
/// fused (control: `concat_fold` driven over `a ‖ [mid] ‖ b` through the
/// segment helper `fold_mix__seg0`); the fault continues the helper's loop
/// with its first and last segments swapped (`fold(X ++ Y)` as
/// `fold(Y ++ X)`) and claims the back-edge's induction step: the helper's
/// measure-recursive lemma does not check.
#[test]
fn r9_segment_fold_order_swapped_is_rejected_at_the_induction_step() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub const CAP: usize = 256;

pub fn concat_fold(a: &[u64], mid: u64, b: &[u64]) -> Option<u64> {
    let na = a.len();
    let nb = b.len();
    if na + nb >= CAP {
        return None;
    }
    let mut buf = [0u64; CAP];
    buf[0..na].copy_from_slice(a);
    buf[na] = mid;
    buf[na + 1..na + 1 + nb].copy_from_slice(b);
    Some(fold_mix(&buf[0..na + 1 + nb], 0))
}
"#;
    drive_fault_case("R9", SRC, "crate::concat_fold", DriveFault::SegFoldSwap, "add_def: TypeMismatch");
}

/// A driven candidate rejected by a check the optimizer relies on, next to
/// an admitted straight-line residual (tier 0, linked by conversion; the
/// driver runs only because it keeps the static recursion `go`): the
/// tier-0 residual stays, and the fault is reported all the same — a
/// warning, a build error under strict options. (Formerly only a fault
/// without a tier-0 residual was reported; this one was silent.)
#[test]
fn driven_fault_next_to_a_straight_line_residual_is_reported() {
    let _g = serial();
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(fuel <= 3)]
#[decreases(fuel)]
fn go(fuel: u32, xs: &[u8], acc: u64) -> u64 {
    if fuel == 0 {
        return acc;
    }
    let [h, t @ ..] = xs else {
        return acc;
    };
    go(fuel - 1, t, acc.wrapping_add(*h as u64))
}

pub fn sum3(xs: &[u8], acc: u64) -> u64 {
    go(3, xs, acc)
}
"#;
    let name = "crate::sum3";
    let c = check_files(&[("r/mod.rs", SRC)], "r/mod.rs");
    // control: driven, its straight-line residual admitted and superseded
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    let f = report(&em, name);
    assert!(f.rung == Some(Rung::Driven) && f.candidates.iter().any(|c| c.rung == Rung::StraightLine && !c.chosen && c.reason.starts_with("admitted")), "control: {:?} {:?}", f.rung, f.candidates);
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty() && em.roundtrip.is_empty(), "control: {:?} {:?} {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    // the fault (R11's recursive helpers): rejected by elaboration
    let hooks = OptTestHooks { drive_faults: BTreeMap::from([(name.to_string(), DriveFault::SelfHelper)]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, false);
    let f = report(&em, name);
    println!("driven fault next to tier 0: {:?} {:?}\n     {:?}\n     {:?}", f.outcome, f.rung, f.candidates, em.opt.warnings);
    let cand = f.candidates.iter().find(|c| c.rung == Rung::Driven).expect("a driven candidate");
    assert!(!cand.chosen && cand.rejected_by.as_deref() == Some("elaboration"), "{cand:?}");
    // the straight-line residual stays (kernel-checked by conversion)
    assert!(matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::StraightLine) && matches!(f.link, Some(Link::Conversion)), "{:?} {:?} {:?}", f.outcome, f.rung, f.link);
    assert!(!prints_source(&em, name));
    // reported: a warning
    assert!(em.opt.warnings.iter().any(|w| w.contains(&format!("`{name}`")) && w.contains("driven candidate was rejected (elaboration)")), "{:?}", em.opt.warnings);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    // a build error under strict options
    let em = optimize(&c, "r/mod.rs", &hooks, true);
    assert!(em.opt.errors.iter().any(|e| e.contains(&format!("`{name}`")) && e.contains("driven candidate was rejected")), "{:?}", em.opt.errors);
}

/// R13: a fact from arm A used in arm B: the reused decision of `x < 10` in
/// its `true` arm claims `false`, proven by the arm's own path equation
/// `Eq(Bool, x < 10, true)` — the transport's motive does not type-check.
#[test]
fn r13_fact_from_the_sibling_arm_is_rejected_by_motive_typing() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn twice(x: u64) -> u64 {
    if x < 10 {
        if x < 10 { 1 } else { 2 }
    } else {
        if x < 10 { 3 } else { 4 }
    }
}
"#;
    drive_fault_case("R13", SRC, "crate::twice", DriveFault::CrossArmReuse, "add_def: TypeMismatch");
}

/// R14: a select-converted arm containing a partial operation: `a / b`
/// evaluated before `if b != 0` has no divisor fact.
#[test]
fn r14_select_arm_with_a_partial_operation_is_rejected_by_elaboration() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn safe_div(a: u32, b: u32) -> Option<u32> {
    Some(if b != 0 { a / b } else { 0 })
}
"#;
    drive_fault_case("R14", SRC, "crate::safe_div", DriveFault::SelectPartial, "elaboration");
}

/// R16: a checked constructor's invariant proof under a split on its own
/// test. `Idx::new(x & 15)` is linked by its lemma; the proof builder
/// abstracts the scrutinee `s2 <= 7` (`s2 = x & 15`) in the source, where
/// the constructor `Idx(x & 15, p)` carries `p : (x & 15) <= 7 == true`.
/// The field's expected type does not mention the scrutinee (it is the
/// invariant at the field `x & 15`), so `p` is kept as it is; the
/// abstraction used to transport it to `y == true`, an ill-typed motive,
/// and the candidate was refused as if the builder had merely given up
/// (no warning). The control is admitted; the fault (the old behavior,
/// `DriveFault::TransportKeptProof`) is an ill-typed term of the proof
/// builder, an optimizer fault.
#[test]
fn r16_transported_constructor_invariant_is_rejected_by_the_proof_builder() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub const MAXI: u32 = 7;

#[derive(Clone, Copy, PartialEq, Eq)]
#[invariant(self.0 <= MAXI)]
pub struct Idx(u32);

impl Idx {
    pub fn new(x: u32) -> Option<Idx> {
        if x <= MAXI { Some(Idx(x)) } else { None }
    }
}

pub fn pick(i: Idx, a: &[u8; 8]) -> u8 {
    if i.0 <= 7 { a[i.0 as usize] } else { 0 }
}

pub fn loc_small(x: u32) -> u32 {
    match Idx::new(x & 15) {
        Some(i) => pick(i, &[1, 2, 3, 4, 5, 6, 7, 8]) as u32,
        None => 100,
    }
}
"#;
    drive_fault_case("R16", SRC, "crate::loc_small", DriveFault::TransportKeptProof, sandblaster_front::opt::PROOF_ILL_TYPED);
}

// R3 and R14 behind a `requires`: the counterexample lies outside the
// search's fixed value pool (slices of at most four elements; a few
// boundary integers), so the search takes its values from the hypotheses'
// literals (`opt::refute`). Without them the fault was classified as an
// incompleteness (`not re-proven`, no warning, no strict error).

/// R3 behind `#[requires(xs.len() >= 8)]`: the counterexample needs a slice
/// of at least eight elements.
#[test]
fn r3_hoisted_read_behind_a_length_requires_is_rejected_by_elaboration() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(xs.len() >= 8)]
fn get_or_zero(xs: &[u8], i: usize) -> u8 {
    if i < xs.len() { xs[i] } else { 0 }
}

pub fn wrap(xs: &[u8], i: usize) -> u8 {
    if xs.len() >= 8 { get_or_zero(xs, i) } else { 0 }
}
"#;
    drive_fault_case("R3 (len requires)", SRC, "crate::get_or_zero", DriveFault::HoistPartial, "elaboration");
}

/// R3 behind `#[requires(k == 12345)]`: the only models of the hypothesis
/// lie outside the fixed pool.
#[test]
fn r3_hoisted_read_behind_a_scalar_requires_is_rejected_by_elaboration() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(k == 12345)]
fn get_or_zero(xs: &[u8], i: usize, k: u32) -> u8 {
    if i < xs.len() { xs[i] } else { 0 }
}

pub fn wrap(xs: &[u8], i: usize, k: u32) -> u8 {
    if k == 12345 { get_or_zero(xs, i, k) } else { 0 }
}
"#;
    drive_fault_case("R3 (scalar requires)", SRC, "crate::get_or_zero", DriveFault::HoistPartial, "elaboration");
}

/// R14 behind `#[requires(a == 12345)]`: a division hoisted out of its
/// `b != 0` guard in a helper whose dividend is fixed by its `requires`.
#[test]
fn r14_select_arm_behind_a_requires_is_rejected_by_elaboration() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(a == 12345)]
fn safe_div(a: u32, b: u32) -> u32 {
    if b != 0 { a / b } else { 0 }
}

pub fn wrap(a: u32, b: u32) -> u32 {
    if a == 12345 { safe_div(a, b) } else { 0 }
}
"#;
    drive_fault_case("R14 (requires)", SRC, "crate::safe_div", DriveFault::SelectPartial, "elaboration");
}

/// R15: a wrapping operation on a path where the source value overflows:
/// `x.saturating_add(1)` printed as `x.wrapping_add(1)` (they differ at
/// `x = 255`); the equality lemma is not provable.
#[test]
fn r15_wrapping_op_where_the_source_saturates_is_rejected_by_the_lemma() {
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn bump(x: u8, c: bool) -> u8 {
    if c { x.saturating_add(1) } else { x }
}
"#;
    drive_fault_case("R15", SRC, "crate::bump", DriveFault::WrapOps, "add_def: TypeMismatch");
}

/// R24: `eq8_word` "proven" by linarith. The lemma library with the word
/// lemma's case analysis replaced by a linarith claim does not load: the
/// kernel's linarith check refuses it (base-256 uniqueness is not linear
/// arithmetic), so the library build fails.
#[test]
fn r24_eq8_word_by_linarith_is_rejected_by_the_kernel() {
    use sandblaster_front::auto::lemmas;
    let _g = serial();
    let words = lemmas::FILES.iter().find(|(f, _)| *f == "words.core").expect("the word lemmas").1;
    // `word::eq8`: its statement, with the body replaced by one linarith claim
    let start = words.find("def[lemma] word::eq8 :").expect("word::eq8");
    let end = start + words[start..].find("\n\n").expect("end of word::eq8");
    let def = &words[start..end];
    let (head, _) = def.split_once(":=").expect("a definition");
    let stmt = head.trim_start_matches("def[lemma] word::eq8 :").trim();
    // binders `(a0 : U8) -> … -> (k : Bool) -> GOAL`: the λ over the same
    // binders, the goal proven by linarith
    let goal = stmt.rsplit_once("-> Eq(").map(|(_, g)| format!("Eq({g}")).expect("the goal");
    let binders: Vec<&str> = stmt.split(" -> ").filter(|b| b.starts_with('(')).collect();
    let forged = format!("def[lemma] word::eq8 : {stmt} :=\n  fun {} =>\n    linarith([]; {goal}; [])", binders.join(" "));
    let text = words.replacen(def, &forged, 1);
    let r = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            let mut env = sandblaster_kernel::api::Env::with_prelude();
            let mut b = sandblaster_kernel::value::Budget { steps: 4_000_000_000 };
            // the library in its load order (`lemmas::load`: the ghost
            // library before `nat.core`), the forged `words.core` in its place
            for (file, src) in lemmas::FILES.iter() {
                if *file == "words.core" {
                    return env.load_core(&text, &mut b).map(|_| ()).map_err(|e| (e.kind, e.message.chars().take(300).collect::<String>()));
                }
                if *file == "nat.core" {
                    sandblaster_front::elab::semantics::load_ghost_library(&mut env).unwrap();
                }
                let t = lemmas::expand_n_templates(src).and_then(|t| sandblaster_kernel::expand_templates(&t)).unwrap();
                env.load_core(&t, &mut b).unwrap_or_else(|e| panic!("{file}: {e}"));
            }
            unreachable!("words.core is in the library")
        })
        .unwrap()
        .join()
        .unwrap();
    println!("R24: {r:?}");
    let Err((kind, _)) = r else { panic!("R24: the lemma library with `word::eq8` proven by linarith must not load") };
    assert_eq!(kind, sandblaster_kernel::api::KernelErrorKind::Linarith, "R24: rejected by the kernel's linarith check");
    // control: the library as shipped loads (`auto_lemmas::lemma_files_load`)
}

// ---------------------------------------------------------------------------
// O6, Σ2 loop summaries (design §20 R7, R8). Each fault is injected with
// `OptTestHooks::loop_faults` (`opt::loopsum::LoopFault`): the summarizer
// proposes a wrong closed form or invariant, skips its trace validation,
// and the lemma builder claims every obligation it cannot prove, so what
// rejects the summary is the kernel (its linarith check). Control: the
// same loop is summarized and `shape` is emitted as its closed form. The
// fallback of a rejected summary is the next rung: `shape` keeps its loop
// (the driven residual calling `shape_go`), with a warning (a build error
// under strict options).
// ---------------------------------------------------------------------------

use sandblaster_front::opt::loopsum::LoopFault;

/// QMDB's `shape` and `shape_go`, read from `sandblaster/fixtures/qmdb/sandblaster/merkle.rs`.
fn shape_program() -> String {
    let merkle = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/merkle.rs")).unwrap();
    let item = |marker: &str| -> String {
        let lines: Vec<&str> = merkle.lines().collect();
        let i = lines.iter().position(|l| l.starts_with(marker)).unwrap_or_else(|| panic!("no item `{marker}`"));
        let mut start = i;
        while start > 0 && (lines[start - 1].starts_with("///") || lines[start - 1].starts_with("#[")) {
            start -= 1;
        }
        let (mut depth, mut end, mut opened) = (0i32, i, false);
        for (j, l) in lines.iter().enumerate().skip(i) {
            for c in l.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        opened = true
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            end = j;
            if (opened && depth == 0) || (!opened && l.trim_end().ends_with(';')) {
                break;
            }
        }
        lines[start..=end].join("\n")
    };
    format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n{}\n\n{}\n\n{}\n\n{}\n", item("pub const MAX_LEAVES"), item("pub struct Shape"), item("pub fn shape("), item("pub(crate) fn shape_go("))
}

fn loop_fault_case(tag: &str, fault: LoopFault) {
    let _g = serial();
    let src = shape_program();
    let c = check_files(&[("r/mod.rs", &src)], "r/mod.rs");
    // control: the closed form
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    let f = report(&em, "crate::shape");
    assert_eq!(f.rung, Some(Rung::ClosedForm), "{tag} control: {:?}", f.candidates);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag} control: {:?} {:?}", em.opt.errors, em.roundtrip);
    // the fault
    let hooks = OptTestHooks { loop_faults: BTreeMap::from([("crate::shape_go".to_string(), fault)]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, false);
    let f = report(&em, "crate::shape");
    println!("{tag}: {:?} {:?}\n     warnings {:?}", f.outcome, f.rung, em.opt.warnings);
    // 1. rejected by the kernel's linarith check
    assert!(em.opt.warnings.iter().any(|w| w.contains("shape_go") && w.contains("kernel rejected") && w.contains("Linarith")), "{tag}: {:?}", em.opt.warnings);
    // 2. the fallback: no closed form, the loop kept, the build fine
    assert_ne!(f.rung, Some(Rung::ClosedForm), "{tag}: {:?}", f.candidates);
    assert!(!em.code.contains("shape_go__closed"), "{tag}: no helper may be emitted");
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag}: the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    // 3. a build error under strict
    let em = optimize(&c, "r/mod.rs", &hooks, true);
    assert!(em.opt.errors.iter().any(|e| e.contains("shape_go") && e.contains("kernel rejected")), "{tag}: {:?}", em.opt.errors);
}

/// R7: the closed form off by one (`h = 64 − lz(L ⊕ t)`): the per-literal
/// lemmas' pinning obligations are false and their claims fail the
/// kernel's linarith check at `lemma_k`.
#[test]
fn r7_closed_form_off_by_one_is_rejected_by_lemma_k() {
    loop_fault_case("R7", LoopFault::WitnessPlusOne);
}

/// R8: a wrong invariant (`before = popcnt(L >> (f − 1))`): a step
/// obligation is false and its claim fails the kernel's linarith check.
#[test]
fn r8_wrong_invariant_is_rejected_by_a_step_obligation() {
    loop_fault_case("R8", LoopFault::GuardCountShift);
}

/// R6: an early exit on a find-*last* variant of `shape_go` (the payload is
/// set at every peak that starts at or before the target, so the last one
/// wins). With its stop test forced to "the payload is set", the rest of
/// the run is not stable once the payload is set: the stability lemma's
/// induction step (invariant preservation) does not typecheck and the
/// kernel rejects it. Control: the early exit the planner proposes itself
/// (stop test `target < start`, final on this variant too) is admitted.
#[test]
fn r6_early_exit_on_find_last_is_rejected_by_invariant_preservation() {
    let _g = serial();
    let src = shape_program();
    let find_first = "        let found = if target < start {\n            found\n        } else if target - start < width {\n            Some(Shape {";
    assert!(src.contains(find_first), "the shape_go source changed");
    let src = src.replace(find_first, "        let found = if target < start {\n            found\n        } else {\n            Some(Shape {");
    let src = src.replacen("            })\n        } else {\n            found\n        };", "            })\n        };", 1);
    let c = check_files(&[("r/mod.rs", &src)], "r/mod.rs");
    // control: synthesis off, the planner's own stop test
    let loops = sandblaster_front::opt::loopsum::LoopConfig { synthesis: false, ..Default::default() };
    let em = optimize_with_loops(&c, "r/mod.rs", &OptTestHooks::default(), true, loops.clone());
    let f = report(&em, "crate::shape");
    assert_eq!(f.rung, Some(Rung::EarlyExit), "R6 control: {:?}", f.candidates);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "R6 control: {:?} {:?}", em.opt.errors, em.roundtrip);
    // the fault: the stop test "the payload is set"
    let hooks = OptTestHooks { loop_faults: BTreeMap::from([("crate::shape_go".to_string(), LoopFault::EarlyExitPayloadSet)]), ..Default::default() };
    let em = optimize_with_loops(&c, "r/mod.rs", &hooks, false, loops.clone());
    let f = report(&em, "crate::shape");
    println!("R6: {:?} {:?}\n     warnings {:?}\n     candidates {:?}", f.outcome, f.rung, em.opt.warnings, f.candidates);
    assert!(em.opt.warnings.iter().any(|w| w.contains("shape_go") && w.contains("kernel rejected") && w.contains("early::final")), "R6: {:?}", em.opt.warnings);
    assert_ne!(f.rung, Some(Rung::EarlyExit), "R6: {:?}", f.candidates);
    assert!(!em.code.contains("shape_go__early"), "R6: no helper may be emitted");
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "R6: the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    let em = optimize_with_loops(&c, "r/mod.rs", &hooks, true, loops);
    assert!(em.opt.errors.iter().any(|e| e.contains("shape_go") && e.contains("kernel rejected")), "R6 strict: {:?}", em.opt.errors);
}

/// The set-bit rung's faults (design §20, plan O6): the control is the rung
/// itself (synthesis off, the set-bit iteration preferred), admitted; the
/// fault's lemma is claimed where it does not hold and the kernel rejects
/// it (a warning, a build error under strict options), the fallback builds.
fn set_bits_fault_case(tag: &str, fault: LoopFault, lemma: &str) {
    let _g = serial();
    let src = shape_program();
    let c = check_files(&[("r/mod.rs", &src)], "r/mod.rs");
    let loops = sandblaster_front::opt::loopsum::LoopConfig { synthesis: false, prefer_set_bits: true, ..Default::default() };
    // control: the set-bit iteration
    let em = optimize_with_loops(&c, "r/mod.rs", &OptTestHooks::default(), true, loops.clone());
    let f = report(&em, "crate::shape");
    assert_eq!(f.rung, Some(Rung::SetBits), "{tag} control: {:?}", f.candidates);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag} control: {:?} {:?}", em.opt.errors, em.roundtrip);
    // the fault
    let hooks = OptTestHooks { loop_faults: BTreeMap::from([("crate::shape_go".to_string(), fault)]), ..Default::default() };
    let em = optimize_with_loops(&c, "r/mod.rs", &hooks, false, loops.clone());
    let f = report(&em, "crate::shape");
    println!("{tag}: {:?} {:?}\n     warnings {:?}", f.outcome, f.rung, em.opt.warnings);
    assert!(em.opt.warnings.iter().any(|w| w.contains("shape_go") && w.contains("kernel rejected") && w.contains(lemma)), "{tag}: {:?}", em.opt.warnings);
    assert_ne!(f.rung, Some(Rung::SetBits), "{tag}: {:?}", f.candidates);
    assert!(!em.code.contains("shape_go__bits"), "{tag}: no helper may be emitted");
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{tag}: the fallback must build: {:?} {:?}", em.opt.errors, em.roundtrip);
    let em = optimize_with_loops(&c, "r/mod.rs", &hooks, true, loops);
    assert!(em.opt.errors.iter().any(|e| e.contains("shape_go") && e.contains("kernel rejected")), "{tag} strict: {:?}", em.opt.errors);
}

/// R28: a symbolic-fuel enumeration lemma (the set-bit rung's idle run)
/// whose arm `c` claims the fuel is `c + 1`: the arm's claim fails the
/// kernel's linarith check.
#[test]
fn r28_misstated_enumeration_arm_is_rejected() {
    set_bits_fault_case("R28", LoopFault::EnumArmMisstated, "bits::idle");
}

/// R29: a set-bit iteration that jumps one fuel too far down (past the
/// set bit): the idle run's hypothesis at the jump is false and its claim
/// fails the kernel's linarith check in the helper's lemma.
#[test]
fn r29_wrong_set_bit_step_is_rejected() {
    set_bits_fault_case("R29", LoopFault::SetBitsWrongJump, "bits::equiv");
}

// ---------------------------------------------------------------------------
// Residuals whose obligations do not re-prove: a proven fallback, or a fault
// when a counterexample shows the residual is wrong (`opt::refute`)
// ---------------------------------------------------------------------------

/// A residual's obligation that the provers do not re-prove is either true
/// (the driver decided a test by its own procedure) or false (the residual
/// is wrong). A counterexample tells them apart:
///
/// * the varint reader into a checked `Loc` constructor: the driver prunes
///   `value <= MAX` in the leaves of the shorter varints, and in three of
///   them the elaborator does not re-prove the invariant obligation of
///   `Loc(value)` from the path. No counterexample exists: a proven
///   fallback (the source is printed, the reason is in the report), not an
///   optimizer fault, so a strict build has no error;
/// * R3 (a partial read hoisted out of its guard): the bound obligation is
///   false at `xs = []`, `i = 0`; the counterexample makes it a fault (a
///   warning; an error under strict options), as R3 itself asserts.
#[test]
fn reproof_failures_are_classified_by_counterexample() {
    let _g = serial();
    const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub const MAX: u64 = 1u64 << 62u32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[invariant(self.0 <= MAX)]
pub struct Loc(u64);

fn uint64_finish(ok: bool, value: u64, rest: &[u8]) -> Option<(u64, &[u8])> {
    if ok { Some((value, rest)) } else { None }
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn uint64_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        let ok = (fuel != 1 || h < 2) && (shift == 0 || h != 0);
        uint64_finish(ok, value, t)
    } else {
        uint64_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> {
    uint64_go(10, xs, 0, 0)
}

pub fn location(xs: &[u8]) -> Option<Loc> {
    let (v, _rest) = uint64(xs)?;
    if v <= MAX { Some(Loc(v)) } else { None }
}
"#;
    let c = check_files(&[("r/mod.rs", SRC)], "r/mod.rs");
    for strict in [false, true] {
        let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), strict);
        let f = report(&em, "crate::location");
        println!("location (strict={strict}): {:?}\n     {:?}", f.outcome, f.candidates);
        let cand = f.candidates.iter().find(|c| c.rung == Rung::Driven).expect("a driven candidate");
        if !cand.chosen {
            // not re-proven: a proven fallback, recorded, never a fault
            assert_eq!(cand.rejected_by.as_deref(), Some("not re-proven"), "{cand:?}");
            assert!(cand.reason.contains("no counterexample found") && cand.reason.contains("type-invariant"), "{cand:?}");
            assert!(matches!(f.outcome, Outcome::Unspecialized { failure: false, .. }), "{:?}", f.outcome);
            assert!(prints_source(&em, "crate::location"));
        }
        assert!(!em.opt.warnings.iter().any(|w| w.contains("crate::location")), "{:?}", em.opt.warnings);
        assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "strict={strict}: {:?} {:?}", em.opt.errors, em.roundtrip);
    }
    // R3's residual: refuted by a counterexample, a fault
    const R3: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn get_or_zero(xs: &[u8], i: usize) -> u8 {
    if i < xs.len() { xs[i] } else { 0 }
}
"#;
    let c = check_files(&[("r/mod.rs", R3)], "r/mod.rs");
    let hooks = OptTestHooks { drive_faults: BTreeMap::from([("crate::get_or_zero".to_string(), DriveFault::HoistPartial)]), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, false);
    let f = report(&em, "crate::get_or_zero");
    let cand = f.candidates.iter().find(|c| c.rung == Rung::Driven).expect("a driven candidate");
    assert_eq!(cand.rejected_by.as_deref(), Some("elaboration"), "{cand:?}");
    assert!(cand.reason.contains("refuted: the goal is false at") && cand.reason.contains("i = 0usize"), "{cand:?}");
    assert!(matches!(f.outcome, Outcome::Unspecialized { failure: true, .. }), "{:?}", f.outcome);
}

/// R21's sample: bit counts, so the x86 feature-only sets (`v4`,
/// `v3_scalar`, plan O8) clone both functions.
const SRC_KAT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn bit_len(x: u64) -> u32 {
    64 - x.leading_zeros()
}

pub fn ones(x: u64) -> u32 {
    x.count_ones()
}
"#;

/// Builds R21's emitted crate for `x86_64-apple-darwin` with the
/// detection of `v3_scalar` forced true (the self-test is the production
/// template), and compiles it in release mode (`-O`, where LLVM folds any
/// check it can see through) with a driver that checks every result
/// against the Rust reference, prints the dispatch decision, and calls the
/// clone `bit_len__v3_scalar` directly. Returns the emitted code and the
/// binary.
fn r21_build() -> (String, std::path::PathBuf) {
    let fs = MemFs::from_files([("r/mod.rs", SRC_KAT)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    // (the feature-only sets' host evidence granted: no host has run them)
    let hooks = OptTestHooks { kat_faults: BTreeMap::from([("v3_scalar".to_string(), hooks::KatFault::ForceDetect)]), set_evidence: ["v4", "v3_scalar"].iter().map(|s| s.to_string()).collect(), ..Default::default() };
    let em = optimize(&c, "r/mod.rs", &hooks, true);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    let names: Vec<&str> = em.opt.sets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["v4", "v3_scalar"], "the feature-only sets");
    assert!(em.opt.clones.iter().any(|cl| cl.clone == "crate::bit_len__v3_scalar" && cl.lemma.is_some()), "{:?}", em.opt.clones);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("r21");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("gen.rs"), &em.code).unwrap();
    let main = format!(
        r#"include!({gen:?});
fn main() {{
    let mut xs: Vec<u64> = vec![0, 1, 2, 3, u64::MAX, 1 << 63, (1 << 63) - 1, 0x0123_4567_89ab_cdef];
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..1000 {{ s ^= s << 13; s ^= s >> 7; s ^= s << 17; xs.push(s >> (s % 64)); }}
    for x in &xs {{
        assert_eq!(bit_len(*x), 64 - x.leading_zeros(), "bit_len({{x}})");
        assert_eq!(ones(*x), x.count_ones(), "ones({{x}})");
    }}
    println!("checked {{}} inputs", xs.len());
    println!("dispatch v3_scalar {{}}", crate::__sandblaster::__dispatch::has_v3_scalar());
    println!("dispatch v4 {{}}", crate::__sandblaster::__dispatch::has_v4());
    // the clone itself, bypassing the dispatch (Rosetta 2 implements the
    // instructions it does not report)
    println!("direct bit_len__v3_scalar(1) = {{}}", unsafe {{ crate::__sandblaster::bit_len__v3_scalar(::core::hint::black_box(1u64)) }});
}}
"#,
        gen = dir.join("gen.rs")
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let st = std::process::Command::new("rustc")
        .args(["--edition", "2024", "--target", "x86_64-apple-darwin", "-O", "-C", "overflow-checks=on", "--cap-lints", "warn", "-o"])
        .arg(dir.join("r21"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    (em.code, dir.join("r21"))
}

/// Simulates a CPU without LZCNT/BMI1 in the machine code: every `lzcnt`
/// and `tzcnt` of `bin` (`F3 [REX] 0F BD/BC`) gets its `F3` prefix
/// replaced by `3E`, which decodes as `bsr`/`bsf` — what such a CPU
/// executes (the `F3` prefix is ignored there). Returns the patched binary
/// and the patched sites per function, or `None` when no disassembler is
/// available.
fn r21_patch_bsr(bin: &Path) -> Option<(std::path::PathBuf, BTreeMap<String, usize>)> {
    let od = std::process::Command::new("objdump").args(["-d", "--no-show-raw-insn"]).arg(bin).output().ok()?;
    if !od.status.success() {
        return None;
    }
    let mut data = std::fs::read(bin).unwrap();
    // x86_64 Mach-O executables: `__TEXT` maps file offset 0 at 0x1_0000_0000
    const TEXT_VM: u64 = 0x1_0000_0000;
    let mut sites: BTreeMap<String, usize> = BTreeMap::new();
    let mut func = String::new();
    for line in String::from_utf8_lossy(&od.stdout).lines() {
        if let Some(l) = line.strip_suffix(">:") {
            func = l.split_once(" <").map(|(_, f)| f.to_string()).unwrap_or_default();
            continue;
        }
        let Some((addr, insn)) = line.split_once(':') else { continue };
        let insn = insn.trim_start();
        if !(insn.starts_with("lzcnt") || insn.starts_with("tzcnt")) {
            continue;
        }
        let Ok(addr) = u64::from_str_radix(addr.trim(), 16) else { continue };
        let off = (addr - TEXT_VM) as usize;
        let rex = usize::from((0x40..=0x4f).contains(&data[off + 1]));
        assert!(data[off] == 0xf3 && data[off + 1 + rex] == 0x0f && matches!(data[off + 2 + rex], 0xbd | 0xbc), "{func}: not an lzcnt/tzcnt encoding at {addr:#x}");
        data[off] = 0x3e;
        *sites.entry(func.clone()).or_default() += 1;
    }
    let out = bin.with_extension("bsr");
    std::fs::write(&out, &data).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Some((out, sites))
}

/// Runs an x86_64 binary (under Rosetta 2 on this Mac); `None` when the
/// host cannot run it.
fn r21_run(bin: &Path) -> Option<String> {
    match std::process::Command::new(bin).output() {
        Ok(r) => {
            assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
            Some(String::from_utf8_lossy(&r.stdout).to_string())
        }
        Err(e) => {
            eprintln!("cannot run x86_64 binaries here ({e}); compiled only");
            None
        }
    }
}

/// R21 (design §20, §13.2): a feature-only clone on a CPU where `lzcnt`
/// executes as `bsr`. Simulated in the machine code: the emitted detection
/// claims the features (`KatFault::ForceDetect`; the self-test is the
/// production template) and the release binary's `lzcnt`/`tzcnt`
/// encodings are patched to `bsr`/`bsf`, in the clones and in the
/// self-test alike. Rejected by the dispatch's known-answer self-test: the
/// process is pinned to the portable code, whose results are correct,
/// although the patched clone itself computes a wrong answer. Control: the
/// unpatched binary (Rosetta 2 executes LZCNT, TZCNT, POPCNT, BZHI and
/// SHLX correctly although it does not report them) — the self-test passes
/// and the clone runs, with correct results.
///
/// This checks the part a source-level simulation cannot: that the
/// self-test still executes `lzcnt`/`tzcnt` after LLVM's optimizations
/// (without `black_box` it folded every check into a compare of the
/// constant inputs, and a `bsr` CPU passed it).
///
/// Unlike the kernel-rejected faults, this one is decided when the program
/// runs: the emitted code is sound either way (the clone is kernel-proven
/// equal to the source), and the self-test is what keeps a detection bug on
/// a CPU that decodes these encodings as `bsr`/`bsf` from producing wrong
/// answers. No build error is involved.
#[test]
fn r21_lzcnt_as_bsr_is_rejected_by_the_dispatch_self_test() {
    let _g = serial();
    let (code, bin) = r21_build();
    // the emitted self-test claims the features and is the production template
    assert!(code.contains("let yes: bool = true && unsafe { kat_v3_scalar() };"), "the simulated detection");
    assert!(code.contains("::core::hint::black_box(::core::arch::x86_64::_lzcnt_u64(one)) == 63u64"), "the self-test's results are opaque to the compiler");
    // the machine code of the self-test runs the instructions
    let (bsr, sites) = match r21_patch_bsr(&bin) {
        Some(x) => x,
        None => {
            eprintln!("no objdump here: the fault is not simulated");
            return;
        }
    };
    // (std's `rep bsf` — the `tzcnt` encoding LLVM uses where a zero input
    // is undefined — is patched too, as on the real CPU; it is harmless)
    let ours: BTreeMap<&String, &usize> = sites.iter().filter(|(f, _)| f.contains("___sandblaster")).collect();
    println!("R21 patched lzcnt/tzcnt sites: {} in all, in the emitted crate {ours:?}", sites.values().sum::<usize>());
    let kat = sites.iter().filter(|(f, _)| f.contains("kat_v3_scalar")).map(|(_, n)| *n).sum::<usize>();
    assert!(kat >= 8, "the release self-test must execute lzcnt and tzcnt (4 each), found {kat}: {sites:?}");
    assert!(sites.iter().any(|(f, _)| f.contains("bit_len__v3_scalar")), "the clone uses lzcnt: {sites:?}");
    // the control: the unpatched binary, real instructions
    if let Some(out) = r21_run(&bin) {
        println!("R21 control run:\n{out}");
        assert!(out.contains("checked 1008 inputs"), "{out}");
        assert!(out.contains("dispatch v3_scalar true"), "the control's self-test passes and the clone runs: {out}");
        assert!(out.contains("direct bit_len__v3_scalar(1) = 1\n"), "{out}");
    }
    // the fault: lzcnt/tzcnt run as bsr/bsf
    if let Some(out) = r21_run(&bsr) {
        println!("R21 fault run:\n{out}");
        // the clone alone is wrong on this CPU: 64 - bsr(1) = 64
        assert!(out.contains("direct bit_len__v3_scalar(1) = 64\n"), "the simulated CPU computes bsr: {out}");
        // rejected: the self-test fails, the process uses the portable code
        assert!(out.contains("checked 1008 inputs"), "{out}");
        assert!(out.contains("dispatch v3_scalar false"), "the self-test must pin the process to portable code: {out}");
        assert!(out.contains("dispatch v4 false"), "{out}");
    }
    // a production emission (no hook): no host has run the feature-only
    // sets, so neither is generated (fail closed, like an intrinsic without
    // hardware evidence) ...
    let fs = MemFs::from_files([("r/mod.rs", SRC_KAT)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::x86_64_apple_darwin());
    let em = optimize(&c, "r/mod.rs", &OptTestHooks::default(), true);
    assert!(em.opt.sets.is_empty() && !em.code.contains("kat_v3_scalar") && !em.code.contains("__v3_scalar"), "a feature-only set without host evidence: {:?}", em.opt.sets.iter().map(|s| &s.name).collect::<Vec<_>>());
    for st in ["v4", "v3_scalar"] {
        assert!(em.opt.not_cloned.iter().any(|(f, set, why)| f == "*" && set == st && why.contains("no host evidence")), "{st}: {:?}", em.opt.not_cloned);
    }
    // ... and with the sets' host evidence (granted here) the production
    // detection runs the self-test inside the cached detection
    let em = optimize(&c, "r/mod.rs", &OptTestHooks { set_evidence: ["v4", "v3_scalar"].iter().map(|s| s.to_string()).collect(), ..Default::default() }, true);
    assert!(em.code.contains("::std::arch::is_x86_feature_detected!(\"popcnt\") && ::std::arch::is_x86_feature_detected!(\"lzcnt\") && ::std::arch::is_x86_feature_detected!(\"bmi1\") && ::std::arch::is_x86_feature_detected!(\"bmi2\") && unsafe { kat_v3_scalar() }"), "the production detection runs the self-test");
    let prod_kat = &em.code[em.code.find("unsafe fn kat_v3_scalar()").unwrap()..];
    let forced_kat = &code[code.find("unsafe fn kat_v3_scalar()").unwrap()..];
    let end = |s: &str| s.find("\n    }\n").unwrap_or(s.len());
    assert_eq!(&prod_kat[..end(prod_kat)], &forced_kat[..end(forced_kat)], "R21's self-test is the production one");
}

// ---------------------------------------------------------------------------
// R16 / R26 on lane kernels (plan O10): QMDB's SHA-256 `compress` at a lane
// site of 16 (x86_64, AVX-512) or 4 (aarch64, NEON) calls.
// ---------------------------------------------------------------------------

fn lane_site(n: usize, target: &TargetInfo) -> Checked {
    let sha = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/sha256.rs")).unwrap();
    let calls = (0..n).map(|i| format!("compress(states[{i}], &blocks[{i}])")).collect::<Vec<_>>().join(", ");
    let site = format!("use sandblaster::prelude::*;\nuse crate::sha256::compress;\n\npub fn compress_x{n}(states: &[[u32; 8]; {n}], blocks: &[[u8; 64]; {n}]) -> [[u32; 8]; {n}] {{\n    [{calls}]\n}}\n");
    let fs = MemFs::from_files([("q/mod.rs", "#![forbid(unsafe_code)]\npub mod sha256;\npub mod lanes;\n"), ("q/sha256.rs", sha.as_str()), ("q/lanes.rs", site.as_str())]);
    let c = driver::check(Path::new("q/mod.rs"), &fs, target);
    assert!(c.ok(), "{}", c.render());
    c
}

fn lane_report<'a>(em: &'a OptimizedEmit, kernel: &str) -> &'a sandblaster_front::opt::par::LaneReport {
    em.opt.lanes.iter().find(|l| l.kernel == kernel).unwrap_or_else(|| panic!("no lane report for {kernel}"))
}

#[test]
fn r16_lane_lifted_sha_with_lanes_3_and_4_swapped_is_rejected_by_the_lane_functor_lemma() {
    use sandblaster_front::opt::par::lift::LaneFault;
    let _g = serial();
    const K: &str = "crate::lanes::compress_x16__avx512_x16";
    let c = lane_site(16, &TargetInfo::x86_64_apple_darwin());
    // control: the lifting is admitted (proven; not dispatched: no host run)
    let em = optimize(&c, "q/mod.rs", &OptTestHooks::default(), false);
    let l = lane_report(&em, K);
    assert!(l.proof.is_ok(), "{:?}", l.proof);
    // the fault: lanes 3 and 4 swapped, the proof builder trusting it
    let faulty = OptTestHooks { lane_faults: [(K.to_string(), LaneFault::SwapLanes(3, 4))].into(), set_evidence: ["lanes:avx512_x16".to_string()].into(), ..Default::default() };
    for strict in [false, true] {
        let em = optimize(&c, "q/mod.rs", &faulty, strict);
        let l = lane_report(&em, K);
        println!("R16 (strict={strict}): {}", l.note.chars().take(300).collect::<String>());
        // 1. rejected by the kernel's check of lane_equiv (a type mismatch)
        let e = l.proof.as_ref().expect_err("the swapped lanes must be rejected");
        assert!(e.contains("lane_equiv rejected by the kernel") && e.contains("TypeMismatch"), "{e}");
        // 2. the fallback: nothing dispatched, the kernel not emitted
        assert!(!l.dispatched);
        assert!(!em.code.contains("compress_x16__avx512_x16"));
        // 3. an optimizer fault: a build error under strict options
        let msgs: &Vec<String> = if strict { &em.opt.errors } else { &em.opt.warnings };
        assert!(msgs.iter().any(|m| m.contains(K) && m.contains("rejected by the kernel")), "{msgs:?}");
    }
}

#[test]
fn r26_lane_kernel_dispatched_without_a_host_run_is_rejected_by_the_lane_evidence_gate() {
    let _g = serial();
    const K: &str = "crate::lanes::compress_x16__avx512_x16";
    let c = lane_site(16, &TargetInfo::x86_64_apple_darwin());
    // control: without a host run the kernel is not dispatched, no error
    let em = optimize(&c, "q/mod.rs", &OptTestHooks::default(), false);
    assert!(!lane_report(&em, K).dispatched);
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    // the fault: dispatched anyway
    let forced = OptTestHooks { force_dispatch: [K.to_string()].into(), ..Default::default() };
    for strict in [false, true] {
        let em = optimize(&c, "q/mod.rs", &forced, strict);
        println!("R26 lanes (strict={strict}): errors {:?}", em.opt.errors);
        assert!(lane_report(&em, K).dispatched, "the hook must have forced the dispatch");
        assert!(em.opt.errors.iter().any(|e| e.contains(K) && e.contains("without host evidence of the kernel")), "{:?}", em.opt.errors);
    }
    // with the host run granted the same dispatch is legitimate
    let granted = OptTestHooks { force_dispatch: [K.to_string()].into(), set_evidence: ["lanes:avx512_x16".to_string()].into(), ..Default::default() };
    let em = optimize(&c, "q/mod.rs", &granted, false);
    assert!(!em.opt.errors.iter().any(|e| e.contains("lane kernel")), "{:?}", em.opt.errors);
}

/// [`optimize`] with the load/store helper `helper` printed from
/// `template` (a changed trusted template, `hooks::with_helper_template`).
fn optimize_with_template(c: &Checked, root: &str, hooks: &OptTestHooks, strict: bool, arch: sandblaster_front::target::Arch, helper: &str, template: &'static str) -> OptimizedEmit {
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        hooks::with_helper_template(&arch, helper, template, || {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            driver::stage::optimize_emit_mode(c, &mut out, root, "", &OptOptions { strict, hooks: Some(Arc::new(hooks.clone())), ..Default::default() }, true).unwrap()
        })
    })
}

/// R26 (lanes, emitted text): a lane kernel's host run covers the code the
/// host compiled — the kernel as printed and the helpers it calls. After a
/// helper template changes (here `store_u32x16` swaps lanes 3 and 4 on the
/// way out, which the round trip cannot see: it reads a helper back as its
/// core model), the kernel's evidence record has a new name, the old run
/// does not count, and the kernel is not dispatched; forced anyway, the
/// lane evidence gate refuses it.
#[test]
fn r26_lane_kernel_whose_helper_template_changed_is_not_covered_by_the_old_host_run() {
    use sandblaster_front::target::Arch;
    const K: &str = "crate::lanes::compress_x16__avx512_x16";
    const STORE: &str = "store_u32x16";
    const SWAPPED: &str = "let mut out = [0u32; 16]; unsafe { ::core::arch::x86_64::_mm512_storeu_si512(out.as_mut_ptr().cast(), a) }; out.swap(3, 4); out";
    let _g = serial();
    let c = lane_site(16, &TargetInfo::x86_64_apple_darwin());
    // the kernel as emitted today, and a host run of exactly that
    let em = optimize(&c, "q/mod.rs", &OptTestHooks::default(), false);
    let old = lane_report(&em, K).lane_set.clone();
    assert!(old.starts_with("lanes:avx512_x16:") && old.len() == "lanes:avx512_x16:".len() + 32, "{old}");
    let run = OptTestHooks { set_evidence: [old.clone()].into(), ..Default::default() };
    // control: with that run the kernel is dispatched, and the emission
    // calls the trusted store helper
    let em = optimize(&c, "q/mod.rs", &run, false);
    let l = lane_report(&em, K);
    assert!(l.dispatched && l.host_evidence.is_ok(), "{}", l.note);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(em.code.contains("fn compress_x16__avx512_x16") && em.code.contains(&format!("fn {STORE}(")), "the kernel and its store helper are emitted");
    // the fault: the helper template changed, the old run kept
    for strict in [false, true] {
        let em = optimize_with_template(&c, "q/mod.rs", &run, strict, Arch::X86_64, STORE, SWAPPED);
        let l = lane_report(&em, K);
        println!("R26 lanes, changed helper (strict={strict}): {} -> {}: {:?}", old, l.lane_set, l.host_evidence);
        // 1. a new name: the old run says nothing about this code
        assert_ne!(l.lane_set, old, "the helper change must rename the kernel's evidence record");
        assert!(l.proof.is_ok(), "the kernel itself is still proven: {:?}", l.proof);
        // 2. not dispatched, nothing of it emitted, no error (fail closed)
        assert!(!l.dispatched && l.host_evidence.is_err(), "{}", l.note);
        assert!(!em.code.contains("compress_x16__avx512_x16") && !em.code.contains("out.swap(3, 4)"), "the changed kernel must not be emitted");
        assert!(!em.opt.errors.iter().any(|e| e.contains("lane kernel")) && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    }
    // forced past the gate with the old run: the lane evidence gate refuses
    let forced = OptTestHooks { force_dispatch: [K.to_string()].into(), set_evidence: [old.clone()].into(), ..Default::default() };
    let em = optimize_with_template(&c, "q/mod.rs", &forced, true, Arch::X86_64, STORE, SWAPPED);
    assert!(lane_report(&em, K).dispatched, "the hook must have forced the dispatch");
    assert!(em.opt.errors.iter().any(|e| e.contains(K) && e.contains("without host evidence of the kernel")), "{:?}", em.opt.errors);
    // and the template override is gone after the call: the old name again
    let em = optimize(&c, "q/mod.rs", &OptTestHooks::default(), false);
    assert_eq!(lane_report(&em, K).lane_set, old);
}

#[test]
fn r26_neon_lane_kernel_with_withheld_model_evidence_is_rejected_by_the_evidence_gate() {
    use sandblaster_targets::evidence;
    use sandblaster_targets::registry::Arch;
    const MODEL: &str = "vaddq_u32";
    const K: &str = "crate::lanes::compress_x4__neon_x4";
    let _g = serial();
    let c = lane_site(4, &TargetInfo::aarch64_apple_darwin());
    let withheld = evidence::withhold(Arch::Aarch64, &[MODEL]);
    // forced past the cost model and the missing host run
    let forced = OptTestHooks { force_dispatch: [K.to_string()].into(), set_evidence: ["lanes:neon_x4".to_string()].into(), ..Default::default() };
    for strict in [false, true] {
        let em = optimize(&c, "q/mod.rs", &forced, strict);
        println!("R26 NEON lanes (strict={strict}): errors {:?}", em.opt.errors);
        assert!(lane_report(&em, K).dispatched);
        assert!(em.opt.errors.iter().any(|e| e.contains(MODEL) && e.contains("without hardware evidence")), "{:?}", em.opt.errors);
    }
    drop(withheld);
    let em = optimize(&c, "q/mod.rs", &forced, false);
    assert!(!em.opt.errors.iter().any(|e| e.contains("without hardware evidence")), "{:?}", em.opt.errors);
}
