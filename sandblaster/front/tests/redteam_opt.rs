//! RED TEAM (phase 4) — optimizer / codegen / round-trip lens.
//!
//! Each test below asserts the behaviour the design promises (DESIGN.md
//! §8.3: "hoisting an unchecked read out of its guard, dropping or
//! duplicating an operation, or any evaluation-level rewrite fails [the
//! round trip]"; §3.7 stack safety; §9.2 evidence gating). They were the
//! red team's failing reproductions (docs/review-3-redteam.md) and are now
//! regression tests. Mutation tests also compile the original (and any
//! accepted mutant) with rustc and print both outputs.
//!
//! Run: `cargo test -p sandblaster-front --test redteam_opt -- --nocapture`.

use std::path::Path;
use std::process::Command;

use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::roundtrip;
use sandblaster_front::target::TargetInfo;

fn check(src: &str) -> Checked {
    let fs = MemFs::from_files([("r/mod.rs", src)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

fn mutate(code: &str, from: &str, to: &str) -> String {
    assert_eq!(code.matches(from).count(), 1, "mutation site `{from}` must occur exactly once in:\n{code}");
    code.replacen(from, to, 1)
}

/// Compiles `code` (the generated file) with a `main` printing `calls`,
/// runs it and returns its stdout lines (or the compiler error).
fn run_rustc(tag: &str, code: &str, calls: &[&str], release: bool) -> Result<Vec<String>, String> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("redteam-opt").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
    let mut main = String::from("include!(\"sandblaster.rs\");\nfn main() {\n");
    for call in calls {
        main.push_str(&format!("    println!(\"{{:?}}\", {call});\n"));
    }
    main.push_str("}\n");
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let mut cmd = Command::new("rustc");
    cmd.args(["--edition", "2024", "--cap-lints", "allow", "-o"]).arg(dir.join("gen")).arg(dir.join("main.rs"));
    if release {
        cmd.args(["-C", "opt-level=3", "-C", "debug-assertions=off", "-C", "overflow-checks=off"]);
    } else {
        cmd.args(["-C", "overflow-checks=on", "-C", "debug-assertions=on"]);
    }
    let st = cmd.output().expect("rustc");
    if !st.status.success() {
        return Err(String::from_utf8_lossy(&st.stderr).to_string());
    }
    let run = Command::new(dir.join("gen")).output().unwrap();
    if !run.status.success() {
        return Err(format!("run failed ({}): stdout {:?} stderr {}", run.status, String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr)));
    }
    Ok(String::from_utf8_lossy(&run.stdout).lines().map(|s| s.to_string()).collect())
}

/// One mutation of the printed file.
struct Mutation {
    label: &'static str,
    from: &'static str,
    to: &'static str,
}

/// Outcome of one mutation.
#[derive(Debug)]
struct Verdict {
    label: &'static str,
    /// Round-trip failures (empty = accepted).
    failures: Vec<String>,
    original: Result<Vec<String>, String>,
    mutated: Result<Vec<String>, String>,
}

/// Verifies + optimizes `src` (strict), checks the unmutated output passes,
/// then applies each mutation, runs the round trip on it and (for accepted
/// ones) compiles/runs original and mutated code with rustc.
fn run_mutations(tag: &str, src: &str, calls: &[&str], muts: &[Mutation]) -> (String, Vec<Verdict>) {
    let c = check(src);
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "the unmutated output must pass the round trip: {:?}\n{}", em.roundtrip, em.code);
        let code = em.code.clone();
        let original = run_rustc(&format!("{tag}-orig"), &code, calls, false);
        let mut verdicts = Vec::new();
        for (i, m) in muts.iter().enumerate() {
            let mutated = mutate(&code, m.from, m.to);
            let failures = match roundtrip::check(&mutated, &em.opt, &mut out, &c.sm, &c.reexports) {
                Ok(s) => s.failures,
                Err(e) => vec![e],
            };
            let mrun = if failures.is_empty() { run_rustc(&format!("{tag}-m{i}"), &mutated, calls, false) } else { Err("(not compiled: rejected)".into()) };
            println!("=== mutation `{}`: round trip {}", m.label, if failures.is_empty() { "ACCEPTED".to_string() } else { format!("rejected: {}", failures[0].lines().next().unwrap_or("")) });
            if failures.is_empty() {
                println!("    original rustc output: {:?}", original);
                println!("    mutated  rustc output: {:?}", mrun);
            }
            verdicts.push(Verdict { label: m.label, failures, original: original.clone(), mutated: mrun });
        }
        (code, verdicts)
    })
}

/// Asserts the design's promise: every mutation below changes what rustc
/// computes, so the round trip must reject each of them.
fn assert_all_rejected(verdicts: &[Verdict]) {
    let accepted: Vec<String> = verdicts
        .iter()
        .filter(|v| v.failures.is_empty())
        .map(|v| format!("`{}` (original {:?} vs mutated {:?})", v.label, v.original, v.mutated))
        .collect();
    assert!(accepted.is_empty(), "the round trip ACCEPTED semantics-changing mutations:\n  {}", accepted.join("\n  "));
}

// ---------------------------------------------------------------------------
// F1: `#[cfg(..)]` attributes on statements / match arms / struct-literal
// fields are ignored by the round-trip lowering (it never looks at
// `syn::Local::attrs`, `syn::Arm::attrs`, `syn::FieldValue::attrs` or the
// attributes of expression statements), but rustc removes the annotated
// syntax before type checking.
// ---------------------------------------------------------------------------

const SRC_CFG: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P {
    pub x: u32,
    pub y: u32,
}

pub fn classify(x: u32) -> u32 {
    match x {
        0 => 100,
        _ => 200,
    }
}

pub fn upd(a: u32, b: u32) -> u32 {
    let mut s = a;
    if b > 3 {
        s = s ^ b;
    }
    s
}

pub fn with_base(p: P, v: u32) -> P {
    if v > 5 { P { x: v, ..p } } else { p }
}

pub fn fill(v: u8) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[2] = v;
    out
}

pub fn copy_in(src: &[u8; 2]) -> [u8; 4] {
    let mut out = [9u8; 4];
    out[1..3].copy_from_slice(src);
    out
}

pub fn put(i: usize, v: u8) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[i & 3] = v;
    out
}

pub fn copy_at(src: &[u8; 2], hi: bool) -> [u8; 4] {
    let mut out = [9u8; 4];
    if hi {
        out[2..4].copy_from_slice(src);
    } else {
        out[0..2].copy_from_slice(src);
    }
    out
}

pub fn is_origin(p: P) -> u32 {
    match p {
        P { x: 0, y: 0 } => 1,
        _ => 2,
    }
}

pub fn total(xs: &[u8]) -> u64 {
    let mut s: u64 = 0;
    for i in 0..xs.len() {
        s = s.wrapping_add(xs[i] as u64);
    }
    s
}

// The same constructs inside loop bodies, which are printed from the source
// (the Σ1 driver keeps loops for Σ2, and re-prints the loop-free functions
// above as its residuals: `if` chains instead of matches and patterns).

pub fn classify_all(xs: &[u32]) -> u32 {
    let mut s: u32 = 0;
    for a in 0..xs.len() {
        let c: u32 = match xs[a] {
            0 => 100,
            _ => 200,
        };
        s = s ^ c;
    }
    s
}

pub fn upd_all(xs: &[u32], c: u32) -> u32 {
    let mut s: u32 = 0;
    for b in 0..xs.len() {
        s = xs[b];
        if c > 3 {
            s = s ^ c;
        }
    }
    s
}

pub fn with_base_all(p: P, vs: &[u32]) -> P {
    let mut q = p;
    for d in 0..vs.len() {
        let w = vs[d];
        q = P { x: w, ..p };
    }
    q
}

pub fn copy_all(src: &[u8; 2], n: usize) -> [u8; 4] {
    let mut out = [9u8; 4];
    for e in 0..n {
        out[1..3].copy_from_slice(src);
    }
    out
}

pub fn origins(ps: &[P]) -> u32 {
    let mut n: u32 = 0;
    for f in 0..ps.len() {
        let hit: u32 = match ps[f] {
            P { x: 0, y: 0 } => 1,
            _ => 0,
        };
        n = n.wrapping_add(hit);
    }
    n
}
"#;

const CALLS_CFG: &[&str] = &["classify(0)", "classify(7)", "upd(1, 9)", "with_base(P { x: 1, y: 2 }, 9)", "put(1, 7)", "copy_at(&[1, 2], true)", "total(&[1, 2, 3])", "is_origin(P { x: 5, y: 0 })", "classify_all(&[0, 7])", "upd_all(&[1], 9)", "with_base_all(P { x: 1, y: 2 }, &[9])", "copy_all(&[1, 2], 1)", "origins(&[P { x: 0, y: 0 }, P { x: 5, y: 0 }])"];

#[test]
fn f1_cfg_attributes_inside_bodies_are_ignored_by_the_round_trip() {
    let muts = [
        Mutation { label: "cfg(any()) on a match arm", from: "0u32 => 100u32,", to: "#[cfg(any())] 0u32 => 100u32," },
        Mutation { label: "cfg(any()) on an `if` statement", from: "if l1_c > 3u32 {", to: "#[cfg(any())] if l1_c > 3u32 {" },
        Mutation { label: "cfg(any()) on a struct-literal field (taken from `..base` instead)", from: "P { x: l4_w, ..l0_p }", to: "P { #[cfg(any())] x: l4_w, ..l0_p }" },
        Mutation { label: "cfg(any()) on an unchecked indexed store", from: "        unsafe { /* SAFETY: every index of the place is in bounds", to: "        #[cfg(any())] unsafe { /* SAFETY: every index of the place is in bounds" },
        Mutation { label: "cfg(any()) on a copy_from_slice statement", from: "            <[u8]>::copy_from_slice(unsafe { /* SAFETY: the range is in bounds and as long as the source: slice-range obligations #", to: "            #[cfg(any())] <[u8]>::copy_from_slice(unsafe { /* SAFETY: the range is in bounds and as long as the source: slice-range obligations #" },
        Mutation { label: "cfg(any()) on a `for` loop", from: "for l2_i in 0usize..", to: "#[cfg(any())] for l2_i in 0usize.." },
        Mutation { label: "cfg(any()) on a struct-pattern field (plus `..`)", from: "P { x: 0u32, y: 0u32 } =>", to: "P { #[cfg(any())] x: 0u32, y: 0u32, .. } =>" },
    ];
    let (code, v) = run_mutations("f1", SRC_CFG, CALLS_CFG, &muts);
    println!("{code}");
    assert_all_rejected(&v);
}

// F1b: the same gap turns into an out-of-bounds `get_unchecked`: the
// proof of `i < 4` in the second arm comes from the first arm's failure
// (its path condition); dropping the first arm with `#[cfg]` leaves the
// unchecked read reachable for every `i`.
const SRC_CFG_UB: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn lookup(t: &[u8; 4], i: usize) -> u8 {
    match i {
        4..=18446744073709551615 => 0,
        _ => t[i],
    }
}
"#;

#[test]
fn f1b_cfg_on_an_arm_makes_an_unchecked_read_out_of_bounds() {
    let muts = [Mutation { label: "cfg(any()) on the arm whose exclusion proves the index", from: "4usize..=18446744073709551615usize => 0u8,", to: "#[cfg(any())] 4usize..=18446744073709551615usize => 0u8," }];
    let (code, v) = run_mutations("f1b", SRC_CFG_UB, &["lookup(&[1, 2, 3, 4], 2)", "lookup(&[1, 2, 3, 4], 1000)"], &muts);
    println!("{code}");
    // release build of the accepted mutant: no UB check, an out-of-bounds read
    if v[0].failures.is_empty() {
        let mutated = mutate(&code, muts[0].from, muts[0].to);
        println!("    mutated, release: {:?}", run_rustc("f1b-rel", &mutated, &["lookup(&[1, 2, 3, 4], 2)", "lookup(&[1, 2, 3, 4], 5)", "lookup(&[1, 2, 3, 4], 64)", "lookup(&[1, 2, 3, 4], 1 << 40)"], true));
    }
    assert_all_rejected(&v);
}

// ---------------------------------------------------------------------------
// F2: the lowering of a tail-loop self-call (`{ let tN__next = v; …;
// aK__arg = tN__next; …; continue; }`) never checks that the temporaries
// are distinct. With a repeated name, rustc's shadowing passes the LAST
// value to both parameters, while the lowering records the call with the
// original argument list.
// ---------------------------------------------------------------------------

const SRC_TAIL: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn walk(xs: &[u8], a: u32, b: u32) -> u32 {
    match xs {
        [] => a ^ (b << 1u32),
        [h, t @ ..] => walk(t, b, a.wrapping_add(*h as u32)),
    }
}
"#;

#[test]
fn f2_duplicate_continue_temporaries_are_accepted() {
    let muts = [Mutation {
        label: "second temporary renamed to the first (shadowing)",
        from: "let t2__next = l2_b; let t3__next = <u32>::wrapping_add(l1_a, (*l3_h) as u32); a0__arg = t1__next; a1__arg = t2__next; a2__arg = t3__next;",
        to: "let t2__next = l2_b; let t2__next = <u32>::wrapping_add(l1_a, (*l3_h) as u32); a0__arg = t1__next; a1__arg = t2__next; a2__arg = t2__next;",
    }];
    let (code, v) = run_mutations("f2", SRC_TAIL, &["walk(&[1, 2, 3], 10, 20)", "walk(&[7], 1, 2)"], &muts);
    println!("{code}");
    assert_all_rejected(&v);
}

// ---------------------------------------------------------------------------
// R1 (robustness): verified programs whose printed output the round trip
// rejects, so `cargo build` fails although every obligation is proven.
// ---------------------------------------------------------------------------

/// Verifies + optimizes `src` and returns the round-trip failures of the
/// unmutated output.
fn unmutated_roundtrip(src: &str) -> (String, Vec<String>, Vec<String>) {
    let c = check(src);
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let unproven: Vec<String> = out.obligations.iter().filter(|o| !o.proven()).map(|o| format!("{} {:?}", o.def, o.kind)).collect();
        assert!(unproven.is_empty(), "unproven: {unproven:?}");
        let failed: Vec<String> = out.defs.iter().filter(|d| d.status != elab::DefStatus::Checked).map(|d| format!("{} {:?}", d.name, d.status)).collect();
        assert!(failed.is_empty(), "definitions not kernel-checked: {failed:?}");
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: false, ..Default::default() }).unwrap();
        (em.code, em.roundtrip, em.opt.warnings)
    })
}

/// R1a: an indexed assignment that is the last statement of a block is
/// printed `unsafe { *get_unchecked_mut(..) = v; }` without a trailing `;`,
/// so syn parses it as the block's tail expression; the lowering's
/// expression path (`Lower::unchecked`) only accepts `unsafe { e }` without
/// a `;` and rejects the printed form.
const SRC_R1A: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

pub fn put(i: usize, v: u8) -> [u8; 4] {
    let mut out = [0u8; 4];
    if i < 4 {
        out[i] = v;
    }
    out
}
"#;

#[test]
fn r1a_guarded_indexed_store_fails_the_round_trip() {
    let (code, rt, warnings) = unmutated_roundtrip(SRC_R1A);
    println!("{code}\nround trip: {rt:?}\nwarnings: {warnings:?}");
    assert!(rt.is_empty(), "verified program rejected by the round trip: {rt:?}");
}

/// R1b: two types in one module with a method of the same name: the round
/// trip keys expected items by bare name (`expect_items`), so one of the
/// two printed methods is "unexpected".
const SRC_R1B: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct A {
    pub v: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct B {
    pub v: u64,
}

impl A {
    pub fn get(self) -> u32 {
        self.v
    }
}

impl B {
    pub fn get(self) -> u64 {
        self.v
    }
}

pub fn both(a: A, b: B) -> u64 {
    a.get() as u64 + (b.get() & 0xffff)
}
"#;

#[test]
fn r1b_same_named_methods_fail_the_round_trip() {
    let (code, rt, warnings) = unmutated_roundtrip(SRC_R1B);
    println!("{code}\nround trip: {rt:?}\nwarnings: {warnings:?}");
    assert!(rt.is_empty(), "verified program rejected by the round trip: {rt:?}");
}

// ---------------------------------------------------------------------------
// F4: the lowering resolves a canonical local name `l{id}_{name}` by its
// number (accepting any number of trailing `_`), but rustc resolves the
// exact identifier. The printer appends `_` when `l{id}_{name}` is also an
// item name; a printed use without the `_` then means the ITEM to rustc and
// the local to the round trip.
// ---------------------------------------------------------------------------

const SRC_NAMES: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[allow(non_upper_case_globals)]
pub const l0_q: u32 = 7;

pub fn g(q: u32) -> u32 {
    q ^ 1u32
}
"#;

#[test]
fn f4_local_name_resolving_to_an_item_is_accepted() {
    let muts = [Mutation { label: "use of `l0_q_` re-spelled `l0_q` (the const)", from: "l0_q_ ^ 1u32", to: "l0_q ^ 1u32" }];
    let (code, v) = run_mutations("f4", SRC_NAMES, &["g(100)", "g(0)"], &muts);
    println!("{code}");
    assert_all_rejected(&v);
}

// ---------------------------------------------------------------------------
// E1 (evidence gating): hardware evidence (DESIGN.md §9.2 "only
// instructions that remain in emitted code need evidence"; the dispatcher
// "never selects a variant whose models lack evidence") is checked ONLY for
// `#[implements]` variants. An exported `#[target_feature]` function that
// calls an intrinsic whose model lacks hardware evidence is verified
// against the unvalidated model and emitted into the boundary; the host
// calls it directly (statically enabled features make the call safe).
//
// The SHA-NI models were `pending-hardware` when this was found; they are
// validated natively now (AVX-512 host round 0, Zen 5), so the test
// withholds `_mm_sha256rnds2_epu32`'s evidence (`evidence::withhold`,
// downgrade only; no other test of this binary builds for x86_64) and, as a
// control, checks that the same function is accepted with the evidence.
// ---------------------------------------------------------------------------

const SRC_EVIDENCE: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;
use core::arch::x86_64::{__m128i, _mm_sha256rnds2_epu32};
use sandblaster::arch::x86_64::{load_u32x4, store_u32x4};

/// Two SHA-256 rounds through SHA-NI (model evidence withheld by the test).
#[target_feature(enable = "sha,sse2")]
pub fn two_rounds(cdgh: &[u32; 4], abef: &[u32; 4], wk: &[u32; 4]) -> [u32; 4] {
    let r: __m128i = _mm_sha256rnds2_epu32(load_u32x4(cdgh), load_u32x4(abef), load_u32x4(wk));
    store_u32x4(r)
}
"#;

/// `(code, round trip, errors, warnings, unproven)` of the exec-only build
/// of `SRC_EVIDENCE` for x86_64.
fn e1_build() -> (String, Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let fs = MemFs::from_files([("r/mod.rs", SRC_EVIDENCE)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let unproven: Vec<String> = out.obligations.iter().filter(|o| !o.proven()).map(|o| o.def.clone()).collect();
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        (em.code, em.roundtrip, em.opt.errors, em.opt.warnings, unproven)
    })
}

#[test]
fn e1_unvalidated_intrinsic_reaches_the_boundary_without_evidence() {
    const MODEL: &str = "_mm_sha256rnds2_epu32";
    let withheld = evidence::withhold(evidence::Arch::X86_64, &[MODEL]);
    println!("evidence of {MODEL}: {:?}", evidence::validation(evidence::Arch::X86_64, MODEL));
    assert!(!evidence::is_validated(evidence::Arch::X86_64, MODEL));
    let (code, rt, errors, warnings, unproven) = e1_build();
    println!("{code}\nround trip {rt:?}\nerrors {errors:?}\nwarnings {warnings:?}\nunproven {unproven:?}");
    let emitted = unproven.is_empty() && errors.is_empty() && rt.is_empty() && code.contains(MODEL) && code.contains("pub use __sandblaster::two_rounds");
    assert!(!emitted, "a verified, round-tripped build exports a function executing an instruction without hardware evidence");
    // the build fails with the evidence diagnostic
    assert!(errors.iter().any(|e| e.contains("two_rounds") && e.contains(MODEL) && e.contains("without hardware evidence")), "{errors:?}");
    // control: with the (native) evidence the same function is not refused
    drop(withheld);
    assert!(evidence::is_validated(evidence::Arch::X86_64, MODEL), "{:?}", evidence::validation(evidence::Arch::X86_64, MODEL));
    let (_, _, errors, _, _) = e1_build();
    assert!(!errors.iter().any(|e| e.contains("without hardware evidence")), "{errors:?}");
}

/// The evidence verdicts (`sandblaster-targets`, a dependency of the front end).
mod evidence {
    pub use sandblaster_targets::evidence::{is_validated, validation, withhold};
    pub use sandblaster_targets::registry::Arch;
}

// ---------------------------------------------------------------------------
// Multiversioning on a small sample: a portable `add4` with a NEON variant
// (evidence: vaddq_u32 / vld1q_u32 / vst1q_u32 validated), called from a
// free function and from a METHOD. R2: the boundary dispatcher template
// prints a free `pub fn` named like the method next to the impl and calls
// the clone by a free-function path, so the emitted crate does not compile
// (the round trip compares the dispatcher against the same template).
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
pub fn add4_neon(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct S {
    pub a: [u32; 4],
}

impl S {
    pub fn twice(&self) -> [u32; 4] {
        add4(self.a, self.a)
    }
}

pub fn top(x: [u32; 4]) -> [u32; 4] {
    add4(x, [1, 2, 3, 4])
}
"#;

#[test]
fn r2_method_in_call_tree_breaks_the_emitted_crate() {
    let c = check(SRC_MV);
    let k = c.krate.as_ref().unwrap();
    let (code, rt, errors, warnings, variants) = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        let vs: Vec<String> = em.opt.variants.iter().map(|v| format!("{} dispatched={} {:?} {}", v.variant, v.dispatched, v.equivalence.as_ref().map(|x| &x.0), v.note)).collect();
        (em.code, em.roundtrip, em.opt.errors, em.opt.warnings, vs)
    });
    println!("{code}\nround trip {rt:?}\nerrors {errors:?}\nwarnings {warnings:?}\nvariants {variants:?}");
    assert!(errors.is_empty() && rt.is_empty(), "optimizer/round trip failed: {errors:?} {rt:?}");
    let r = run_rustc("r2", &code, &["top([1, 2, 3, u32::MAX])", "S { a: [1, 2, 3, 4] }.twice()"], false);
    println!("rustc: {r:?}");
    assert!(r.is_ok(), "the verified, round-tripped output does not compile: {r:?}");
}

// ---------------------------------------------------------------------------
// S1 (stack depth, DESIGN.md §3.7): a depth-bounded non-tail recursion was
// accepted with `max = C ≤ 65536` regardless of its frame size; the emitted
// code is ordinary Rust recursion, so a verified function overflowed the
// 8 MiB main-thread stack (process abort) on an input its contract allows.
// Stack safety is now an obligation of the subset (`validate::check_stack`):
// `max ≤ 4096` and `depth × frame` within the 1 MiB budget.
// ---------------------------------------------------------------------------

const SRC_STACK: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[requires(d <= 65536)]
#[decreases(d, max = 65536)]
fn deep(d: u32, pad: [u64; 64]) -> u64 {
    if d == 0 {
        pad[0]
    } else {
        let mut buf = pad;
        buf[(d % 64) as usize] = d as u64;
        let r = deep(d - 1, buf).rotate_left(1);
        r ^ buf[((d / 3) % 64) as usize] ^ buf[((d / 5) % 64) as usize]
    }
}

pub fn run(d: u32) -> u64 {
    if d <= 65536 { deep(d, [3u64; 64]) } else { 0 }
}
"#;

fn front_end_errors(src: &str) -> String {
    let fs = MemFs::from_files([("r/mod.rs", src)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(!c.ok(), "the front end must reject:\n{src}");
    c.render()
}

#[test]
fn s1_depth_bounded_recursion_overflows_the_stack() {
    // the red team's program: the depth bound itself is over the cap
    let r = front_end_errors(SRC_STACK);
    assert!(r.contains("recursion depth bound 65536 exceeds 4096"), "{r}");
    // within the cap, the 512-byte frame still breaks the stack budget
    let within = SRC_STACK.replace("65536", "4096");
    let r = front_end_errors(&within);
    assert!(r.contains("may overflow the stack"), "{r}");
    // …and with a depth bound it does fit, it verifies and runs (debug and release)
    let small = SRC_STACK.replace("65536", "64");
    let (code, rt, warnings) = unmutated_roundtrip(&small);
    assert!(rt.is_empty(), "{rt:?}");
    println!("warnings {warnings:?}");
    for release in [false, true] {
        let r = run_rustc(&format!("s1-small-{release}"), &code, &["run(64)", "run(65)"], release);
        assert!(r.is_ok(), "{r:?}");
    }
}

/// R2b: a GENERIC exported function in a multiversioned call tree: the
/// dispatcher template declares only lifetimes, so `T` is unbound.
const SRC_MV_GENERIC: &str = r#"#![forbid(unsafe_code)]
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

pub fn tag<T: Copy>(x: [u32; 4], t: T) -> ([u32; 4], T) {
    (add4(x, x), t)
}
"#;

#[test]
fn r2b_generic_in_call_tree_breaks_the_emitted_crate() {
    let c = check(SRC_MV_GENERIC);
    let k = c.krate.as_ref().unwrap();
    let (code, rt, errors, warnings) = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        (em.code, em.roundtrip, em.opt.errors, em.opt.warnings)
    });
    println!("{code}\nround trip {rt:?}\nerrors {errors:?}\nwarnings {warnings:?}");
    assert!(errors.is_empty() && rt.is_empty(), "optimizer/round trip failed: {errors:?} {rt:?}");
    let r = run_rustc("r2b", &code, &["tag([1, 2, 3, u32::MAX], 7u8)"], false);
    println!("rustc: {r:?}");
    assert!(r.is_ok(), "the verified, round-tripped output does not compile: {r:?}");
}

// ---------------------------------------------------------------------------
// L1: the round trip compares visibility, `cfg` on every item, impl blocks
// (inherent, self type) and rejects every attribute below the item level
// (`cfg_attr` too).
// ---------------------------------------------------------------------------

#[test]
fn l1_item_headers_and_attributes_are_compared() {
    let muts = [
        Mutation { label: "visibility of an exported function", from: "pub fn classify(", to: "pub(crate) fn classify(" },
        Mutation { label: "`#[cfg]` on a struct", from: "pub struct P {", to: "#[cfg(any())]\n    pub struct P {" },
        Mutation { label: "visibility of a field", from: "pub x: u32,", to: "x: u32," },
        Mutation { label: "`cfg_attr` on a statement", from: "if l1_b > 3u32 {", to: "#[cfg_attr(any(), cfg(any()))] if l1_b > 3u32 {" },
        Mutation { label: "attribute on a parameter", from: "pub fn classify(l0_x: u32)", to: "pub fn classify(#[cfg(all())] l0_x: u32)" },
    ];
    let (_code, v) = run_mutations("l1", SRC_CFG, CALLS_CFG, &muts);
    assert_all_rejected(&v);
    let muts = [
        Mutation { label: "impl self type swapped", from: "impl crate::__sandblaster::A {", to: "impl crate::__sandblaster::B {" },
        Mutation { label: "`unsafe impl`", from: "impl crate::__sandblaster::A {", to: "unsafe impl crate::__sandblaster::A {" },
    ];
    let (_code, v) = run_mutations("l1b", SRC_R1B, &["both(A { v: 1 }, B { v: 2 })"], &muts);
    assert_all_rejected(&v);
}

/// L1: every `SAFETY:` comment of an unchecked operation names the kernel
/// obligation(s) that justify it: an obligation of the right kind, in the
/// printed function's kernel definition (its residual when specialized, or
/// a loop helper), and no two operations cite the same obligation.
#[test]
fn l1_safety_comments_name_the_right_obligations() {
    let c = check(SRC_CFG);
    let k = c.krate.as_ref().unwrap();
    let (code, obls) = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
        let obls: Vec<(u32, String, String)> = out.obligations.iter().map(|o| (o.id, sandblaster_front::elab::obl::kind_name(&o.kind).to_string(), o.def.clone())).collect();
        (em.code, obls)
    });
    let mut seen: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut n = 0;
    for (lineno, line) in code.lines().enumerate() {
        let mut rest = line;
        while let Some(i) = rest.find("/* SAFETY: ") {
            let tail = &rest[i..];
            let end = tail.find("*/").expect("closed comment");
            let comment = &tail[..end];
            rest = &tail[end..];
            let kind = ["index-bounds", "slice-range"].into_iter().find(|k| comment.contains(&format!(": {k} obligation")));
            let Some(kind) = kind else { continue };
            n += 1;
            // "#<id>[, #<id>..] of `<def>`"
            let seg = comment.split(" obligation").nth(1).and_then(|r| r.split(" of `").next()).unwrap_or("");
            let ids: Vec<u32> = seg.split('#').skip(1).filter_map(|p| p.split(|ch: char| !ch.is_ascii_digit()).next()?.parse().ok()).collect();
            assert!(!ids.is_empty(), "line {}: SAFETY comment without an obligation id: {comment}", lineno + 1);
            let def = comment.split('`').nth(1).expect("definition name");
            for id in ids {
                let o = obls.iter().find(|o| o.0 == id).unwrap_or_else(|| panic!("no obligation #{id}"));
                assert_eq!(o.1, kind, "line {}: #{id} is a {} obligation: {comment}", lineno + 1, o.1);
                assert_eq!(o.2, def, "line {}: #{id} belongs to {}: {comment}", lineno + 1, o.2);
                if let Some(prev) = seen.insert(id, comment.to_string()) {
                    panic!("obligation #{id} cited twice:\n  {prev}\n  {comment}");
                }
            }
        }
    }
    assert!(n >= 6, "expected unchecked operations with SAFETY comments, found {n}:\n{code}");
}
