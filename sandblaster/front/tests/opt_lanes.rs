//! The lane functor (optimizer design §13.3; plan O10): QMDB's SHA-256
//! `compress` lifted to AVX-512 ×16, AVX2 ×8 and NEON ×4, and the
//! shape-specialized ×16 of `hash_64` (constant second block), each linked
//! to its lane site by a kernel-checked `lane_equiv` lemma within the plan's
//! budgets (≤ 2·10⁹ steps, ≤ 1 GiB).
//!
//! Run: `cargo test -p sandblaster-front --features opt-test-hooks --test opt_lanes -- --nocapture --test-threads=1`.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Mutex;

use sandblaster_front::driver::{self, Checked, OptimizedEmit};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::hir::{ItemId, ItemKind};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::par::lift::{self, LANE_PROOF_STEPS, LaneFault, Lifted};
use sandblaster_front::opt::par::tiles::{self, LaneTarget};
use sandblaster_front::opt::hooks::OptTestHooks;
use sandblaster_front::opt::par::LaneReport;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

/// One elaboration at a time (the heap is measured per process).
static SERIAL: Mutex<()> = Mutex::new(());

fn sha256_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/sha256.rs")).unwrap()
}

/// A lane site of `n` calls of `f` (`compress` or `hash_64`).
fn site_src(n: usize) -> String {
    let calls = |f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<Vec<_>>().join(", ");
    format!(
        "use sandblaster::prelude::*;\nuse crate::sha256::{{compress, hash_64, Digest}};\n\n\
         /// {n} independent compressions (a lane site).\n\
         pub fn compress_x{n}(states: &[[u32; 8]; {n}], blocks: &[[u8; 64]; {n}]) -> [[u32; 8]; {n}] {{\n    [{}]\n}}\n\n\
         /// {n} independent 64-byte hashes (the second block is constant padding).\n\
         pub fn hash64_x{n}(msgs: &[[u8; 64]; {n}]) -> [Digest; {n}] {{\n    [{}]\n}}\n",
        calls(&|i| format!("compress(states[{i}], &blocks[{i}])")),
        calls(&|i| format!("hash_64(&msgs[{i}])")),
    )
}

fn check(n: usize, target: &TargetInfo, sha: &str) -> Checked {
    let mut fs = MemFs::new();
    fs.insert("q/mod.rs", "#![forbid(unsafe_code)]\npub mod sha256;\npub mod lanes;\n");
    fs.insert("q/sha256.rs", sha);
    fs.insert("q/lanes.rs", &site_src(n));
    let c = driver::check(Path::new("q/mod.rs"), &fs, target);
    assert!(c.ok(), "{}", c.render());
    c
}

fn item(c: &Checked, path: &str) -> ItemId {
    let k = c.krate.as_ref().unwrap();
    k.items.iter().find(|it| it.path.to_string() == path && matches!(it.kind, ItemKind::Fn(_))).map(|it| it.id).unwrap_or_else(|| panic!("no function {path}"))
}

/// Elaborates and lifts `site` on `target`.
fn lift(c: &Checked, site: &str, target: &'static LaneTarget) -> Result<Lifted, String> {
    lift_with(c, site, target, None)
}

fn lift_with(c: &Checked, site: &str, target: &'static LaneTarget, fault: Option<LaneFault>) -> Result<Lifted, String> {
    let k = c.krate.as_ref().unwrap();
    let id = item(c, site);
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        let users: HashSet<_> = out.fn_globals.values().copied().collect();
        let mut ext = k.clone();
        let r = lift::lift_site_with(&mut out, &mut ext, &mut chain, &elab::Options::default(), id, target, &|g| users.contains(&g), fault);
        if let Ok(l) = &r {
            println!(
                "{site} on {}: {} scalar ops -> {} vector ops ({} tiles, {} leaves, {} constants); lane_equiv: {} steps, peak heap {}, {} ms, proof {} KiB; whole lift (site to lane_equiv): peak heap {}, {} ms",
                target.name,
                l.stats.scalar_ops,
                l.stats.vector_ops,
                l.stats.tiles,
                l.stats.leaves,
                l.stats.consts,
                l.stats.steps,
                l.stats.peak_bytes.map(|b| format!("+{} MiB", b >> 20)).unwrap_or_else(|| "below an earlier peak of this process".into()),
                l.stats.millis,
                l.stats.proof_bytes >> 10,
                l.stats.lift_peak_bytes.map(|b| format!("+{} MiB", b >> 20)).unwrap_or_else(|| "below an earlier peak of this process".into()),
                l.stats.lift_millis
            );
        }
        r
    })
}

/// Plan O10's budgets: ≤ 2·10⁹ steps, ≤ 1 GiB (the heap growth is exact
/// when the proof set the process's peak: run a test alone to measure it).
fn within_budget(l: &Lifted) {
    assert!(l.stats.steps <= LANE_PROOF_STEPS, "{} steps", l.stats.steps);
    if let Some(b) = l.stats.peak_bytes {
        assert!(b <= 1 << 30, "peak heap +{} MiB", b >> 20);
    }
    // the whole lift too (symbolic execution, evaluation, printing,
    // elaboration and the proof)
    if let Some(b) = l.stats.lift_peak_bytes {
        assert!(b <= 1 << 30, "whole-lift peak heap +{} MiB", b >> 20);
    }
}

#[test]
fn compress_x16_on_avx512() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let l = lift(&c, "crate::lanes::compress_x16", &tiles::AVX512_X16).unwrap_or_else(|e| panic!("{e}"));
    within_budget(&l);
}

#[test]
fn compress_x8_on_avx2() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(8, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let l = lift(&c, "crate::lanes::compress_x8", &tiles::AVX2_X8).unwrap_or_else(|e| panic!("{e}"));
    within_budget(&l);
}

#[test]
fn compress_x4_on_neon() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(4, &TargetInfo::aarch64_apple_darwin(), &sha256_src());
    let l = lift(&c, "crate::lanes::compress_x4", &tiles::NEON_X4).unwrap_or_else(|e| panic!("{e}"));
    within_budget(&l);
}

/// The shape-specialized ×16: `hash_64`'s second block is constant
/// padding, so its schedule and `W + K` fold to vector constants.
#[test]
fn hash64_x16_on_avx512_has_a_constant_second_block() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let l = lift(&c, "crate::lanes::hash64_x16", &tiles::AVX512_X16).unwrap_or_else(|e| panic!("{e}"));
    within_budget(&l);
    // the first block's 16 message words and 8 initial-state words are the
    // only lane inputs; everything of the second block is constant
    assert!(l.stats.leaves <= 16 + 8, "{} leaves", l.stats.leaves);
    assert!(l.stats.consts > 64, "{} constants", l.stats.consts);
}

/// R16 (design §20): a lane-lifted SHA with lanes 3 and 4 swapped in the
/// pack — in the kernel and in the proof builder's lane arrays — is
/// rejected by the kernel's check of `lane_equiv`.
#[test]
fn r16_swapped_lanes_are_rejected_by_the_lane_functor_lemma() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let e = lift_with(&c, "crate::lanes::compress_x16", &tiles::AVX512_X16, Some(LaneFault::SwapLanes(3, 4))).expect_err("swapped lanes must be rejected");
    println!("R16: {}", e.chars().take(400).collect::<String>());
    assert!(e.contains("lane_equiv rejected by the kernel"), "{e}");
    // control: the same lifting without the fault is admitted
    lift(&c, "crate::lanes::compress_x16", &tiles::AVX512_X16).unwrap_or_else(|e| panic!("{e}"));
}

// ---------------------------------------------------------------------------
// The optimizer's lane phase (a lane site in a whole build)

fn optimize(c: &Checked, hooks: Option<OptTestHooks>, strict: bool) -> OptimizedEmit {
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        let opts = OptOptions { strict, hooks: hooks.map(std::sync::Arc::new), ..Default::default() };
        driver::stage::optimize_emit_mode(c, &mut out, "q/mod.rs", "", &opts, true).unwrap()
    })
}

/// The build's only warnings are the site clones' specializations (see
/// the callers), and it has no error.
fn site_clone_warnings_only(em: &OptimizedEmit) {
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    for w in &em.opt.warnings {
        assert!(w.contains("__sha2`: specialization failed") || w.contains("__sha_sse2_ssse3_sse4_1`: specialization failed"), "unexpected warning: {w}");
    }
}

fn lane<'a>(em: &'a OptimizedEmit, kernel: &str) -> &'a LaneReport {
    em.opt.lanes.iter().find(|l| l.kernel == kernel).unwrap_or_else(|| panic!("no lane report for {kernel}: {:?}", em.opt.lanes.iter().map(|l| &l.kernel).collect::<Vec<_>>()))
}

/// Plan O10: the NEON ×4 SHA-256 kernel is proven, then rejected by the M5
/// cost model (the SHA2 instructions are cheaper per message); nothing of
/// it is emitted.
#[test]
fn neon_x4_sha_is_proven_then_rejected_by_the_m5_cost_model() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(4, &TargetInfo::aarch64_apple_darwin(), &sha256_src());
    // not strict: the site's clone into the {sha2} set cannot be
    // specialized (its inlined `compress_sha2` reads the lanes' blocks as
    // elements of an array parameter, which the residual printer does not
    // print; unrelated to lanes, see `site_clone_warnings_only`)
    let em = optimize(&c, None, false);
    site_clone_warnings_only(&em);
    let l = lane(&em, "crate::lanes::compress_x4__neon_x4");
    println!("{}", l.note);
    let st = l.proof.as_ref().unwrap_or_else(|e| panic!("{e}"));
    assert!(st.steps <= LANE_PROOF_STEPS);
    assert!(!l.chosen && !l.dispatched, "{}", l.note);
    assert!(l.note.contains("rejected by the cost model"), "{}", l.note);
    assert!(l.site_best.contains("sha2"), "the site's best code is the SHA2 variant: {}", l.site_best);
    assert!(l.lifted_cost > l.site_cost);
    assert!(!em.code.contains("compress_x4__neon_x4"), "a rejected kernel is not emitted");
}

/// Plan O10: the AVX-512 ×16 kernel is proven and compiles for x86_64, but
/// is not dispatched: no host has run it (the evidence gate holds).
#[test]
fn avx512_x16_is_proven_but_not_dispatched_without_host_evidence() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let em = optimize(&c, None, false);
    site_clone_warnings_only(&em);
    for kernel in ["crate::lanes::compress_x16__avx512_x16", "crate::lanes::hash64_x16__avx512_x16"] {
        let l = lane(&em, kernel);
        println!("{}", l.note);
        l.proof.as_ref().unwrap_or_else(|e| panic!("{e}"));
        assert!(!l.dispatched, "{}", l.note);
        assert!(l.host_evidence.is_err(), "{:?}", l.host_evidence);
        assert!(!em.code.contains(kernel.rsplit("::").next().unwrap()), "an undispatched kernel is not emitted");
    }
}

/// With a host run granted (a test hook), the ×16 kernel is dispatched at
/// the site's boundary like any variant: the emitted code has the kernel
/// and a dispatcher, and the build has no error.
#[test]
fn granted_host_evidence_dispatches_the_x16_kernel() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let hooks = OptTestHooks { set_evidence: ["lanes:avx512_x16".to_string()].into_iter().collect(), ..Default::default() };
    let em = optimize(&c, Some(hooks), false);
    site_clone_warnings_only(&em);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    let l = lane(&em, "crate::lanes::compress_x16__avx512_x16");
    println!("{}", l.note);
    assert!(l.chosen && l.dispatched, "{}", l.note);
    assert!(em.code.contains("fn compress_x16__avx512_x16"), "the kernel is emitted");
    assert!(em.code.contains("_mm512_ternarylogic_epi32") && em.code.contains("_mm512_ror_epi32"), "vpternlogd / vprord");
}

/// The evidence record of a lane kernel is named by the code a host runs
/// (plan O10, §9.2), and the round trip holds every printed lane kernel to
/// the tokens its record names: a kernel printed otherwise (a printer that
/// disagreed with the fingerprint) is a build error. Doc comments are not
/// code and do not count.
#[test]
fn the_round_trip_holds_a_printed_lane_kernel_to_the_text_its_record_names() {
    use sandblaster_front::roundtrip::lane_kernel_check;
    const K: &str = "crate::lanes::compress_x16__avx512_x16";
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = check(16, &TargetInfo::x86_64_apple_darwin(), &sha256_src());
    let hooks = OptTestHooks { set_evidence: ["lanes:avx512_x16".to_string()].into_iter().collect(), ..Default::default() };
    let mut em = optimize(&c, Some(hooks), false);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    let l = lane(&em, K).clone();
    assert!(l.dispatched, "{}", l.note);
    assert!(l.lane_set.starts_with("lanes:avx512_x16:") && l.kernel_tokens.len() == 64 && l.core_hash.len() == 64, "{l:?}");
    assert!(l.note.contains(&format!("evidence record `{}`", l.lane_set)) && l.note.contains(sandblaster_targets::evidence::BUILD_RUSTC), "{}", l.note);
    assert_eq!(lane_kernel_check(&em.code, &em.opt).unwrap(), Vec::<String>::new());
    // a doc comment changed: same code, no failure
    let docs = em.code.replacen("Lane kernel of `crate::lanes::compress_x16`", "Lane kernel (edited doc) of `crate::lanes::compress_x16`", 1);
    assert_ne!(docs, em.code);
    assert_eq!(lane_kernel_check(&docs, &em.opt).unwrap(), Vec::<String>::new());
    // the kernel's code changed after its record was named: refused
    let head = "-> [[u32; 8usize]; 16usize] {\n";
    let at = em.code.find("fn compress_x16__avx512_x16(").and_then(|i| em.code[i..].find(head).map(|j| i + j + head.len())).expect("the kernel's body");
    let mut changed = em.code.clone();
    changed.insert_str(at, "            let _extra: u32 = 0u32;\n");
    let f = lane_kernel_check(&changed, &em.opt).unwrap();
    assert!(f.len() == 1 && f[0].contains(K) && f[0].contains("printed differently") && f[0].contains(&l.lane_set), "{f:?}");
    // the record names other tokens: refused
    em.opt.lanes.iter_mut().find(|x| x.kernel == K).unwrap().kernel_tokens = "0".repeat(64);
    let f = lane_kernel_check(&em.code, &em.opt).unwrap();
    assert!(f.len() == 1 && f[0].contains(K), "{f:?}");
}

// ---------------------------------------------------------------------------
// The generated lanewise-lemma libraries (`lemmas/lanes/<target>.core`)

fn lanes_sample(target: &TargetInfo) -> Checked {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/lanes");
    let mut fs = MemFs::new();
    for f in ["mod.rs", "sha256.rs", "sites.rs"] {
        fs.insert(&format!("l/{f}"), &std::fs::read_to_string(dir.join(f)).unwrap());
    }
    let c = driver::check(Path::new("l/mod.rs"), &fs, target);
    assert!(c.ok(), "{}", c.render());
    c
}

/// The non-SHA lane sample (`tests/samples/lanes_arx`, fairness audit J17).
fn arx_sample(target: &TargetInfo) -> Checked {
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/lanes_arx/mod.rs")).unwrap();
    let mut fs = MemFs::new();
    fs.insert("a/mod.rs", &src);
    let c = driver::check(Path::new("a/mod.rs"), &fs, target);
    assert!(c.ok(), "{}", c.render());
    c
}

/// The library of a target: every lemma the lane kernels of the samples
/// use — the SHA-256 sites of `tests/samples/lanes` (`sha_sites`), then the
/// ARX sites of `tests/samples/lanes_arx` (`arx_sites`): boundary lemmas,
/// lane maps, one triple per cone shape, in first-use order.
/// `lemmas/lanes/<target>.core` is this text
/// (`SANDBLASTER_REGENERATE_LANES=1` rewrites it), and the kernel checks
/// every lemma of it when it loads. A test golden file: no optimizer code
/// loads it (fairness audit J17).
fn library(target: &'static LaneTarget, info: &TargetInfo, sha_sites: &[&str], arx_sites: &[&str]) -> String {
    let mut seen = HashSet::new();
    let mut text = format!(
        "-- GENERATED by `sandblaster/front/tests/opt_lanes.rs` (lane_lemma_libraries_are_generated);\n\
         -- do not edit. The lanewise lemmas of the lane target `{}` (plan O10, the lane\n\
         -- functor): the boundary lemmas, the lane maps and one lemma triple per cone\n\
         -- shape of the SHA-256 lane kernels of `tests/samples/lanes` and the ARX\n\
         -- quarter rounds of `tests/samples/lanes_arx`. A test golden file, never an\n\
         -- optimizer input: `front/src` does not load it, and the optimizer generates\n\
         -- the same text for the cones a build needs; the kernel checks every lemma\n\
         -- when it is loaded.\n",
        target.name
    );
    for (c, sites) in [(lanes_sample(info), sha_sites), (arx_sample(info), arx_sites)] {
        let k = c.krate.as_ref().unwrap();
        let more = elab::with_big_stack(|| {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            lift::ensure_core(&mut out.env, target).unwrap();
            let users: HashSet<_> = out.fn_globals.values().copied().collect();
            let mut texts = Vec::new();
            for site in sites {
                let sg = out.fn_globals[&item(&c, site)];
                let s = lift::find_site(&out.env, sg, &|g| users.contains(&g)).unwrap_or_else(|e| panic!("{site}: {e}"));
                let p = lift::plan(&out.env, &s, target).unwrap_or_else(|e| panic!("{site}: {e}"));
                texts.extend(p.lemma_texts());
            }
            texts
        });
        for (name, t) in more {
            if seen.insert(name) {
                text.push('\n');
                text.push_str(&t);
            }
        }
    }
    text
}

/// The committed aarch64 record holds a native M5 run of the NEON ×4
/// kernel of `tests/samples/lanes` (host kit stage `lanes`, the harness
/// `tests/host_lanes.rs`; 10⁶ inputs, no mismatch). The record is named by
/// the kernel's emitted text, so it must still name what the optimizer
/// emits today: when this fails after a printer, helper or lane-functor
/// change, re-run the harness on the M5 and record the new name (see
/// `tools/host-kit/README.md`, "Lane kernels"). The kernel stays
/// undispatched on the M5: its cost model picks the SHA2 instructions.
#[test]
fn the_m5_record_of_the_neon_x4_kernel_names_the_emitted_kernel() {
    /// The compiler the record was made with (the set name includes it).
    const RECORDED_WITH: &str = "rustc 1.98.1 (48a229cea 2026-09-01)";
    if sandblaster_targets::evidence::BUILD_RUSTC != RECORDED_WITH {
        println!("skipped: built by {}, the record was made with {RECORDED_WITH} (re-record on the M5)", sandblaster_targets::evidence::BUILD_RUSTC);
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let c = lanes_sample(&TargetInfo::aarch64_apple_darwin());
    let em = optimize(&c, None, true);
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    let l = lane(&em, "crate::sites::compress_x4__neon_x4");
    println!("{}", l.note);
    let v = l.host_evidence.as_ref().unwrap_or_else(|e| panic!("the committed record does not name the emitted kernel `{}` ({e}): re-record it", l.lane_set));
    assert!(v.contains("Apple M5"), "{v}");
    assert!(!l.dispatched && l.note.contains("rejected by the cost model"), "{}", l.note);
}

#[test]
fn lane_lemma_libraries_are_generated() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("lemmas/lanes");
    let cases: [(&'static LaneTarget, TargetInfo, &[&str], &[&str]); 3] = [
        (&tiles::AVX512_X16, TargetInfo::x86_64_apple_darwin(), &["crate::sites::compress_x16", "crate::sites::hash64_x16"], &["crate::quarter_x16"]),
        (&tiles::AVX2_X8, TargetInfo::x86_64_apple_darwin(), &["crate::sites::compress_x8"], &["crate::quarter_x8"]),
        (&tiles::NEON_X4, TargetInfo::aarch64_apple_darwin(), &["crate::sites::compress_x4"], &["crate::quarter_x4"]),
    ];
    for (target, info, sites, arx) in cases {
        let text = library(target, &info, sites, arx);
        let path = dir.join(format!("{}.core", target.name));
        if std::env::var_os("SANDBLASTER_REGENERATE_LANES").is_some() {
            std::fs::write(&path, &text).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(committed == text, "{} is stale; regenerate with SANDBLASTER_REGENERATE_LANES=1", path.display());
        // the kernel re-checks every lemma of the library
        let c = lanes_sample(&info);
        let k = c.krate.as_ref().unwrap();
        let (n, steps) = elab::with_big_stack(move || {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            lift::ensure_core(&mut out.env, target).unwrap();
            let mut b = sandblaster_kernel::value::Budget { steps: LANE_PROOF_STEPS };
            let names = out.env.load_core(&text, &mut b).unwrap_or_else(|e| panic!("{}: {e}", target.name));
            (names.len(), LANE_PROOF_STEPS - b.steps)
        });
        println!("{}: {n} definitions checked, {steps} steps", target.name);
    }
}
