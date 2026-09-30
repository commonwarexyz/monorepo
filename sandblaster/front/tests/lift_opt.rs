//! The optimizer on lifted code (DESIGN.md §2.1 "lifted modules",
//! `driver::lowered`): a cheaper residual of a lifted function is lowered
//! into the source file, in the source's dialect, and accepted only after
//! the lifted round trip (read back by the same lift, elaborated in
//! generated mode, compared with the kernel-checked residual). Each
//! feature has a positive test and a must-reject twin.
//!
//! `cargo test --release -p sandblaster-front --test lift_opt -- --test-threads=1`

use std::path::Path;

use sandblaster_front::driver::lowered::{LowerFault, LowerOutcome, LoweredModule};
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

const ROOT: &str = "//! A lifted example.\n#![forbid(unsafe_code)]\n#[lift]\nmod bits;\npub use bits::{EXPORTS};\n";

/// Plain Rust, written the obvious way: two loops with known closed forms
/// (Σ2 and the aegraph's `count_ones` rule) and a function the optimizer
/// cannot improve.
const BITS: &str = r#"//! Bit counting, written the obvious way.

/// Set bits of `n` above position `k`.
pub fn rank_above(n: u64, k: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        if i > k && (n >> i) & 1 == 1 {
            c = c.wrapping_add(1);
        }
    }
    c
}

/// Set bits of `x`, one bit per iteration.
pub fn popcount_loop(x: u64) -> u32 {
    let mut c: u32 = 0;
    for i in 0..64u32 {
        c = c.wrapping_add(((x >> i) & 1) as u32);
    }
    c
}

/// Already as cheap as it gets.
pub fn low_byte(x: u64) -> u8 {
    x as u8
}
"#;

fn check_files(files: &[(&str, &str)]) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn root(exports: &str) -> String {
    ROOT.replace("EXPORTS", exports)
}

fn lower(files: &[(&str, &str)]) -> LoweredModule {
    let c = check_files(files);
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: true };
    let (_, _, low) = driver::stage::lower_lifted(&c, Path::new(files[0].0), &opts, &OptOptions::default()).unwrap();
    low
}

fn outcome<'a>(low: &'a LoweredModule, f: &str) -> &'a LowerOutcome {
    &low.records.iter().find(|r| r.function == f).unwrap_or_else(|| panic!("no record for {f}: {:?}", low.records)).outcome
}

#[test]
fn closed_forms_are_lowered_into_the_source() {
    let r = root("rank_above, popcount_loop, low_byte");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", BITS)]);
    println!("{}", low.body);
    println!("{:?}", low.records);
    if let Ok(p) = std::env::var("LIFT_OPT_DUMP") {
        std::fs::write(p, &low.body).unwrap();
    }
    assert!(low.note.is_none(), "{:?}", low.note);
    assert!(matches!(outcome(&low, "crate::bits::rank_above"), LowerOutcome::Lowered { rung, .. } if rung == "ClosedForm"));
    assert!(matches!(outcome(&low, "crate::bits::popcount_loop"), LowerOutcome::Lowered { rung, .. } if rung == "Rewritten"));
    assert!(matches!(outcome(&low, "crate::bits::low_byte"), LowerOutcome::Kept(_)));
    assert_eq!(low.lowered(), 2);
    // two entries, the closed-form helper, two rewritten bodies
    assert_eq!(low.compared, 5);
    // the source text stays around the rewritten bodies
    assert!(low.body.contains("/// Set bits of `n` above position `k`.\npub fn rank_above(n: u64, k: u32) -> u32 {\n    __sandblaster_opt_rank_above(n, k)\n}"));
    assert!(low.body.contains("pub fn low_byte(x: u64) -> u8 {\n    x as u8\n}"));
    assert!(low.body.contains("count_ones()"));
    assert!(!low.body.contains("for i in"));
}

fn lower_faulty(files: &[(&str, &str)], fault: LowerFault) -> LoweredModule {
    let c = check_files(files);
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: true };
    let (_, _, low) = driver::stage::lower_lifted_with_fault(&c, Path::new(files[0].0), &opts, &OptOptions::default(), fault).unwrap();
    low
}

#[track_caller]
fn kept(low: &LoweredModule, f: &str, needle: &str) {
    match outcome(low, f) {
        LowerOutcome::Kept(why) => assert!(why.contains(needle), "`{f}` kept for another reason: {why}"),
        other => panic!("`{f}` was lowered: {other:?}\n{}", low.body),
    }
}

/// Must-reject twins of the lowering printer: a wrong comparison, constant
/// or argument order, a dropped operation, a body that calls another
/// function's residual. The lifted round trip rejects each; the function
/// keeps its source text (the rest is lowered when it passes the round
/// trip on its own).
#[test]
fn printer_faults_are_rejected_by_the_lifted_round_trip() {
    let r = root("rank_above, popcount_loop, low_byte");
    let files = [("r/mod.rs", r.as_str()), ("r/bits.rs", BITS)];
    for (fault, victim) in [
        (LowerFault::FlipComparison, "crate::bits::rank_above"),
        (LowerFault::WrongConstant, "crate::bits::rank_above"),
        (LowerFault::DropOperation, "crate::bits::rank_above"),
        (LowerFault::SwapArgs, "crate::bits::rank_above"),
        (LowerFault::CrossEntry, "crate::bits::popcount_loop"),
    ] {
        let low = lower_faulty(&files, fault);
        println!("{fault:?}: {:?} {:?}", low.note, low.records);
        match (&low.note, outcome(&low, victim)) {
            // rejected per function by the comparison
            (_, LowerOutcome::Kept(why)) => assert!(why.contains("round trip"), "{fault:?}: {why}"),
            (_, LowerOutcome::Lowered { .. }) => panic!("{fault:?}: `{victim}` was lowered with a faulty printer:\n{}", low.body),
        }
        // the victim's source body is untouched
        let src_body = if victim.ends_with("rank_above") { "        if i > k && (n >> i) & 1 == 1 {" } else { "        c = c.wrapping_add(((x >> i) & 1) as u32);" };
        assert!(low.body.contains(src_body), "{fault:?}: the source body of `{victim}` is gone:\n{}", low.body);
    }
}

/// What the lowering refuses, each kept as written with its reason: a
/// `BufMut` state beside a result, a helper name the source already uses, a
/// residual that is not cheaper. (A generic function over a sealed trait is
/// lowered through a per-type dispatch: `generic_functions_*` below.)
#[test]
fn what_is_not_lowered_keeps_its_source_text() {
    let extra = r#"
mod sealed {
    pub trait Prim: Copy {
        fn low(self) -> u8;
    }
    impl Prim for u16 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u32 {
        fn low(self) -> u8 { self as u8 }
    }
}
pub use sealed::Prim;

/// Generic: one instance per impl type.
pub fn popcount_generic<T: Prim>(x: T) -> u32 {
    let b = x.low();
    let mut c: u32 = 0;
    for i in 0..8u32 {
        c = c.wrapping_add(((b >> i) & 1) as u32);
    }
    c
}
"#;
    let state = "\nuse bytes::BufMut;\n\n/// A state and a result: not lowered yet.\npub fn put_counted(x: u8, buf: &mut impl BufMut) -> u32 {\n    buf.put_u8(x & 7);\n    1\n}\n";
    let bits = format!("{BITS}{extra}{state}");
    let r = root("rank_above, popcount_loop, low_byte, popcount_generic, put_counted");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", &bits)]);
    assert!(matches!(outcome(&low, "crate::bits::popcount_generic"), LowerOutcome::Lowered { via, .. } if via.contains("per-type dispatch")), "{:?}", low.records);
    kept(&low, "crate::bits::put_counted", "one `&mut impl BufMut` of a function without a result");
    kept(&low, "crate::bits::low_byte", "not 3% cheaper");
    assert_eq!(low.lowered(), 3);
    // a source that already uses a helper's name
    let taken = format!("{BITS}\n/// Taken.\npub fn __sandblaster_opt_popcount_loop() -> u32 {{ 0 }}\n");
    let r = root("rank_above, popcount_loop, low_byte, __sandblaster_opt_popcount_loop");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", &taken)]);
    kept(&low, "crate::bits::popcount_loop", "already uses the name");
    assert!(matches!(outcome(&low, "crate::bits::rank_above"), LowerOutcome::Lowered { .. }));
}

/// Compiles `main.rs` with the original source as `mod orig` and the
/// lowered source as `mod opt` in one binary (rustc `-O`, overflow checks
/// and debug assertions on, `-D warnings` on the lowered module's lints)
/// and runs it.
fn run_ab(dir: &Path, orig: &str, opt: &str, main: &str) -> String {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("orig.rs"), orig).unwrap();
    std::fs::write(dir.join("opt.rs"), opt).unwrap();
    std::fs::write(dir.join("main.rs"), format!("#![deny(warnings)]\n#[allow(dead_code)]\nmod orig;\n#[allow(dead_code)]\nmod opt;\n{main}")).unwrap();
    let o = std::process::Command::new("rustc")
        .args(["--edition", "2024", "-O", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "-o"])
        .arg(dir.join("ab"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(o.status.success(), "rustc rejects the lowered module:\n{}", String::from_utf8_lossy(&o.stderr));
    let r = std::process::Command::new(dir.join("ab")).output().expect("run");
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    String::from_utf8_lossy(&r.stdout).to_string()
}

/// The emitted module compiles with rustc (lint-clean under
/// `deny(warnings)`) and agrees with the source on every value tried:
/// the edges of `k` (0..=70) and `n`, and a pseudo-random sweep.
#[test]
fn the_lowered_module_compiles_and_agrees_with_the_source() {
    let r = root("rank_above, popcount_loop, low_byte");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", BITS)]);
    assert_eq!(low.lowered(), 2);
    let (docs, body) = BITS.split_at(BITS.find("\n\n").unwrap());
    let _ = docs;
    let main = r#"
fn main() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut n = 0u64;
    let edges = [0u64, 1, 2, 3, u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) - 1, 0xFF, 0x8000_0000];
    for &v in &edges {
        for k in 0..=70u32 {
            assert_eq!(orig::rank_above(v, k), opt::rank_above(v, k), "rank_above({v}, {k})");
        }
        assert_eq!(orig::popcount_loop(v), opt::popcount_loop(v));
    }
    for _ in 0..200_000 {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let k = (x >> 58) as u32 + (x & 7) as u32;
        assert_eq!(orig::rank_above(x, k), opt::rank_above(x, k));
        assert_eq!(orig::popcount_loop(x), opt::popcount_loop(x));
        assert_eq!(orig::low_byte(x), opt::low_byte(x));
        n += 1;
    }
    println!("agree {n}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-ab-{}", std::process::id()));
    let out = run_ab(&dir, body, &low.body, main);
    assert!(out.contains("agree 200000"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// module mode (`sandblaster::build::compile_module`): the whole crate path
// ---------------------------------------------------------------------

#[path = "gated_util.rs"]
mod gated;

const M_ROOT: &str = "sandblaster/bits/mod.rs";
const M_MODULE: &str = "src/bits.rs";

const M_DSL_ROOT: &str = r#"//! A lifted module: `bits.rs` as written.
#![forbid(unsafe_code)]

#[lift]
mod bits;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

pub use bits::{clamp7, low_byte};
"#;

const M_BITS: &str = r#"//! Bits of a byte, the obvious way.

/// The low three bits of `x`, clamped to 7.
pub fn clamp7(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// The low byte of `x`.
pub fn low_byte(x: u32) -> u8 {
    x as u8
}
"#;

const M_LAWS: &str = r#"//! What `bits.rs` guarantees.
use sandblaster::prelude::*;
use crate::bits::{clamp7, low_byte};

/// `clamp7` is the value modulo 8.
#[law]
fn clamp7_low_bits(x: u8) {
    ensures(clamp7(x) as Nat == (x as Nat) % 8);
}

/// `low_byte` is the value modulo 256.
#[law]
fn low_byte_mod(x: u32) {
    ensures(low_byte(x) as Nat == (x as Nat) % 256);
}
"#;

const M_PROOF: &str = r#"//! Proofs of LAWS.rs.
use sandblaster::prelude::*;
#[allow(unused_imports)]
use crate::bits::{clamp7, low_byte};

/// By the 256 cases.
#[proof]
fn clamp7_low_bits(x: u8) {
    by_cases(x, 0..=255);
}

/// A cast truncates.
#[proof]
fn low_byte_mod(x: u32) {
    follows();
}
"#;

fn m_env() -> std::collections::HashMap<String, String> {
    // a real, writable OUT_DIR: the lift conformance check compiles and
    // runs its harness under `OUT_DIR/<out>-conformance/`
    let out = std::env::temp_dir().join(format!("sandblaster-lift-opt-out-{}", std::process::id()));
    let out = out.display().to_string();
    [
        ("CARGO_MANIFEST_DIR", "/host"),
        ("OUT_DIR", out.as_str()),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

fn m_files(bits: &str) -> Vec<(String, String)> {
    let dsl = vec![
        (format!("/host/{M_ROOT}"), M_DSL_ROOT.to_string()),
        ("/host/sandblaster/bits/bits.rs".to_string(), bits.to_string()),
        ("/host/sandblaster/bits/LAWS.rs".to_string(), M_LAWS.to_string()),
        ("/host/sandblaster/bits/PROOF.rs".to_string(), M_PROOF.to_string()),
    ];
    let mut files = gated::with_accepted_lock(&dsl, &format!("/host/{M_ROOT}"), &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"));
    let (docs, _) = driver::lifted::split_docs(bits);
    files.push(("/host/src/lib.rs".into(), "//! A host crate.\nmod bits;\npub fn both(x: u32) -> u8 { bits::clamp7(bits::low_byte(x)) }\n".into()));
    files.push((format!("/host/{M_MODULE}"), format!("{docs}{}\n", driver::module_include_line("bits"))));
    files
}

fn m_build(files: &[(String, String)]) -> driver::BuildOutcome {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = m_env();
    driver::build_module(M_ROOT, M_MODULE, None, &|k| e.get(k).cloned(), &fs)
}

/// The whole module-mode path on a lifted crate with a law: every proof
/// and gate, then the optimizer, the lowering and the lifted round trip;
/// the emitted file is the source with the rewritten body and its checked
/// helper, and says so in its header.
#[test]
fn module_mode_emits_the_lowered_source() {
    let o = m_build(&m_files(M_BITS));
    assert!(o.ok, "the build failed:\n{}", o.stderr);
    let code = o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == "bits.rs")).map(|(_, c)| c.clone()).expect("bits.rs");
    println!("{code}");
    assert!(code.contains("// STATUS: VERIFIED + LIFTED + OPTIMIZED (module mode):"), "{code}");
    assert!(code.contains("//   rewritten: `crate::bits::clamp7` (rung Driven"), "{code}");
    assert!(code.contains("pub fn clamp7(x: u8) -> u8 {\n    __sandblaster_opt_clamp7(x)\n}"), "{code}");
    assert!(code.contains("pub fn low_byte(x: u32) -> u8 {\n    x as u8\n}"), "{code}");
    assert!(code.contains("fn __sandblaster_opt_clamp7(l0_x: u8) -> u8 {\n    l0_x & 7u8\n}"), "{code}");
    assert!(!code.contains("if y > 7"), "{code}");
    // the report records every source function's outcome; the timing file
    // the optimizer's and the lowering's time
    let file = |n: &str| o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == n)).map(|(_, c)| c.clone()).unwrap_or_else(|| panic!("no {n}"));
    let report = file("bits-report.json");
    assert!(report.contains("\"lifted_optimizer\": {") && report.contains("\"outcome\": \"rewritten\"") && report.contains("\"outcome\": \"source kept\""), "{report}");
    let timing = file("bits-timing.json");
    assert!(timing.contains("\"lifted_optimizer_ms\"") && timing.contains("\"lifted_lowering_ms\""), "{timing}");
    // the emitted file compiles in a host that denies warnings, and agrees
    // with the source on every input
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-host-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("bits.rs"), &code).unwrap();
    std::fs::write(dir.join("orig.rs"), M_BITS).unwrap();
    std::fs::write(
        dir.join("main.rs"),
        "#![deny(warnings)]\n#[allow(dead_code)]\nmod bits { include!(\"bits.rs\"); }\n#[allow(dead_code)]\nmod orig;\nfn main() {\n    for x in 0..=255u8 { assert_eq!(bits::clamp7(x), orig::clamp7(x)); }\n    for x in [0u32, 1, 255, 256, u32::MAX] { assert_eq!(bits::low_byte(x), orig::low_byte(x)); }\n    println!(\"agree\");\n}\n",
    )
    .unwrap();
    let o = std::process::Command::new("rustc").args(["--edition", "2024", "-O", "-o"]).arg(dir.join("host")).arg(dir.join("main.rs")).output().expect("rustc");
    assert!(o.status.success(), "rustc rejects the emitted module:\n{}", String::from_utf8_lossy(&o.stderr));
    let r = std::process::Command::new(dir.join("host")).output().expect("run");
    assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "agree");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Twin: the same crate written with the cheap form already — no residual
/// is cheaper, so the emitted file is the source as-is (status `VERIFIED +
/// LIFTED AS-IS`, body byte for byte).
#[test]
fn module_mode_without_a_cheaper_residual_emits_the_source_as_is() {
    let bits = M_BITS.replace("    let y = x & 7;\n    if y > 7 { 7 } else { y }\n", "    x & 7\n");
    let o = m_build(&m_files(&bits));
    assert!(o.ok, "the build failed:\n{}", o.stderr);
    let code = o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == "bits.rs")).map(|(_, c)| c.clone()).expect("bits.rs");
    assert!(code.contains("// STATUS: VERIFIED + LIFTED AS-IS (module mode):"), "{code}");
    assert!(code.contains("optimized: no residual of the 2 lifted function(s) is cheaper and printable, the source is emitted as-is"), "{code}");
    let (_, body) = driver::lifted::split_docs(&bits);
    assert!(code.contains(body), "{code}");
    assert!(!code.contains("__sandblaster_opt_"), "{code}");
}

// ---------------------------------------------------------------------
// buffer state (`buf: &mut impl BufMut`): lowered back to `BufMut` calls
// ---------------------------------------------------------------------

const BUF: &str = r#"//! Buffer writes, the obvious way.
use bytes::BufMut;

/// The low three bits, clamped to 7.
fn low3(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// `low3(x)`, then a marker.
pub fn put_low3(x: u8, buf: &mut impl BufMut) {
    buf.put_u8(low3(x));
    buf.put_u8(0xFF);
}

/// A byte and a masked byte (nothing cheaper).
pub fn put_pair(a: u8, b: u8, buf: &mut impl BufMut) {
    buf.put_u8(a);
    buf.put_u8(b & 15);
}
"#;

fn lower_buf(fault: Option<LowerFault>) -> LoweredModule {
    let r = root("put_low3, put_pair");
    let c = check_files(&[("r/mod.rs", &r), ("r/bits.rs", BUF)]);
    assert!(c.ok(), "{}", c.render());
    // the buffer model is ghost code: a full elaboration
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let (_, _, low) = match fault {
        None => driver::stage::lower_lifted(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default()),
        Some(f) => driver::stage::lower_lifted_with_fault(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default(), f),
    }
    .unwrap();
    low
}

/// A function with a `BufMut` state: its residual (the callee's branch
/// pruned, the buffer operations kept as calls) is lowered as `BufMut`
/// calls on the original `&mut impl BufMut` parameter, and the lifted round
/// trip reads it back as the same state passing.
#[test]
fn buffer_state_is_lowered_to_bufmut_calls() {
    let low = lower_buf(None);
    println!("{}\n{:?}", low.body, low.records);
    assert!(matches!(outcome(&low, "crate::bits::put_low3"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    assert!(matches!(outcome(&low, "crate::bits::low3"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    kept(&low, "crate::bits::put_pair", "not 3% cheaper");
    assert!(low.body.contains("pub fn put_low3(x: u8, buf: &mut impl BufMut) {\n    __sandblaster_opt_put_low3(x, buf)\n}"), "{}", low.body);
    assert!(low.body.contains("fn __sandblaster_opt_put_low3(l0_x: u8, l1_buf: &mut impl BufMut) {\n    let l2_s2: u8 = low3(l0_x);\n    l1_buf.put_u8(l2_s2);\n    l1_buf.put_u8(255u8);\n}"), "{}", low.body);
    // rustc: the rewritten file against the source, on a `Vec<u8>` buffer
    // (a local `BufMut` stands in for the `bytes` crate)
    let fix = |t: &str| t.replace("use bytes::BufMut;", "use crate::bytes::BufMut;");
    let (_, body) = driver::lifted::split_docs(BUF);
    let main = r#"
mod bytes {
    pub trait BufMut {
        fn put_u8(&mut self, n: u8);
    }
    impl BufMut for Vec<u8> {
        fn put_u8(&mut self, n: u8) {
            self.push(n);
        }
    }
}
fn main() {
    let mut n = 0;
    for x in 0..=255u8 {
        for b in 0..=255u8 {
            let (mut v1, mut v2) = (vec![b], vec![b]);
            orig::put_low3(x, &mut v1);
            opt::put_low3(x, &mut v2);
            orig::put_pair(x, b, &mut v1);
            opt::put_pair(x, b, &mut v2);
            assert_eq!(v1, v2);
            n += 1;
        }
    }
    println!("agree {n}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-buf-{}", std::process::id()));
    let out = run_ab(&dir, &fix(body), &fix(&low.body), main);
    assert!(out.contains("agree 65536"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-reject twins in state mode: the buffer calls swapped (other byte
/// order) or one dropped. The lifted round trip rejects both; the
/// function keeps its source text.
#[test]
fn buffer_printer_faults_are_rejected() {
    for fault in [LowerFault::SwapBufferCalls, LowerFault::DropBufferCall] {
        let low = lower_buf(Some(fault));
        println!("{fault:?}: {:?}", low.records);
        kept(&low, "crate::bits::put_low3", "round trip");
        assert!(low.body.contains("    buf.put_u8(low3(x));\n    buf.put_u8(0xFF);"), "{fault:?}: {}", low.body);
    }
}

/// Scratch probe (`#[ignore]`d): the optimizer and the lowering on a real
/// lifted crate at `LIFT_OPT_ROOT` (with `SANDBLASTER_LOWER_PROBE=1`, every
/// lifted function's residual cost and lowered text is printed).
#[test]
#[ignore]
fn probe_real_root() {
    let root = std::env::var("LIFT_OPT_ROOT").expect("LIFT_OPT_ROOT");
    let c = driver::check(Path::new(&root), &sandblaster_front::loader::RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: std::env::var_os("LIFT_OPT_EXEC_ONLY").is_some() };
    let t = std::time::Instant::now();
    let lows = if c.lifted.iter().any(|l| l.in_place) {
        let (v, lows) = driver::stage::lower_in_place(&c, Path::new(&root), &opts, &OptOptions::default()).unwrap();
        println!("verified: {:?}", v.stats());
        lows
    } else {
        vec![driver::stage::lower_lifted(&c, Path::new(&root), &opts, &OptOptions::default()).unwrap().2]
    };
    println!("elapsed {:?}", t.elapsed());
    for low in &lows {
        println!("{}", low.json().render());
        if let Ok(p) = std::env::var("LIFT_OPT_DUMP") {
            let name = std::path::Path::new(&low.file).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(std::path::Path::new(&p).join(name), low.text()).unwrap();
        }
    }
}

// ---------------------------------------------------------------------
// generic functions over a sealed trait: a per-type dispatch the lift reads
// ---------------------------------------------------------------------

/// A generic function over a sealed trait with three impl types; the
/// root declares `u64` unverified.
const GEN: &str = r#"//! Generic bit counting over a sealed trait.
mod sealed {
    /// The primitive types the counter takes.
    pub trait Prim: Copy {
        fn low(self) -> u8;
    }
    impl Prim for u16 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u32 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u64 {
        fn low(self) -> u8 { self as u8 }
    }
}
pub use sealed::Prim;

/// Set bits of the low byte, one bit per iteration.
pub fn popcount_low<T: Prim>(x: T) -> u32 {
    let b = x.low();
    let mut c: u32 = 0;
    for i in 0..8u32 {
        c = c.wrapping_add(((b >> i) & 1) as u32);
    }
    c
}

/// Set bits of the low byte of `x`, plus `k`.
pub fn popcount_low_plus<T: Prim>(x: T, k: u32) -> u32 {
    popcount_low(x).wrapping_add(k)
}
"#;

fn gen_root() -> String {
    "//! A lifted generic example.\n#![forbid(unsafe_code)]\n#[lift(unverified = \"u64\")]\nmod bits;\npub use bits::{popcount_low, popcount_low_plus};\n".to_string()
}

fn lower_gen(fault: Option<LowerFault>) -> LoweredModule {
    let r = gen_root();
    let files = [("r/mod.rs", r.as_str()), ("r/bits.rs", GEN)];
    match fault {
        None => lower(&files),
        Some(f) => lower_faulty(&files, f),
    }
}

/// Every verified instance (`u16`, `u32`) of a generic function has a
/// cheaper residual: the function is lowered through the per-type dispatch
/// — a sealed dispatch trait made a supertrait of `Prim`, implemented for
/// every impl type (`u64`, declared unverified, calls a copy of the
/// original generic code) —, read back by the lift and compared per
/// instance. The emitted module compiles with rustc and agrees with the
/// source on every `u16`, every `u32` low byte and sampled `u64`s.
#[test]
fn generic_functions_are_lowered_through_a_per_type_dispatch() {
    let low = lower_gen(None);
    println!("{}\n{:?}", low.body, low.records);
    assert!(low.note.is_none(), "{:?}", low.note);
    for f in ["crate::bits::popcount_low", "crate::bits::popcount_low_plus"] {
        match outcome(&low, f) {
            LowerOutcome::Lowered { via, .. } => assert!(via.contains("per-type dispatch `__sandblaster_dispatch_Prim` over u16, u32"), "{via}"),
            other => panic!("`{f}`: {other:?}"),
        }
    }
    let b = &low.body;
    assert!(b.contains("pub trait Prim: Copy + __sandblaster_dispatch_Prim {"), "{b}");
    assert!(b.contains("pub trait __sandblaster_dispatch_Prim: Sized {\n        fn __sandblaster_opt_popcount_low(self) -> u32;\n        fn __sandblaster_opt_popcount_low_plus(self, k: u32) -> u32;\n    }"), "{b}");
    assert!(b.contains("pub fn popcount_low<T: Prim>(x: T) -> u32 {\n    x.__sandblaster_opt_popcount_low()\n}"), "{b}");
    assert!(b.contains("pub fn popcount_low_plus<T: Prim>(x: T, k: u32) -> u32 {\n    x.__sandblaster_opt_popcount_low_plus(k)\n}"), "{b}");
    assert!(b.contains("impl sealed::__sandblaster_dispatch_Prim for u16 {"), "{b}");
    assert!(b.contains("__sandblaster_opt_popcount_low_for_u16(self)"), "{b}");
    // the unverified instance keeps the original code
    assert!(b.contains("impl sealed::__sandblaster_dispatch_Prim for u64 {"), "{b}");
    assert!(b.contains("__sandblaster_orig_popcount_low::<u64>(self)"), "{b}");
    assert!(b.contains("fn __sandblaster_orig_popcount_low<T: Prim>(x: T) -> u32 {\n    let b = x.low();"), "{b}");
    assert!(!b.contains("__sandblaster_opt_popcount_low_for_u64"), "{b}");
    let (_, body) = driver::lifted::split_docs(GEN);
    let main = r#"
fn main() {
    let mut n = 0u64;
    for x in 0..=u16::MAX {
        assert_eq!(orig::popcount_low(x), opt::popcount_low(x));
        assert_eq!(orig::popcount_low_plus(x, 7), opt::popcount_low_plus(x, 7));
        n += 1;
    }
    let mut y: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..100_000 {
        y ^= y << 13; y ^= y >> 7; y ^= y << 17;
        assert_eq!(orig::popcount_low(y as u32), opt::popcount_low(y as u32));
        assert_eq!(orig::popcount_low(y), opt::popcount_low(y));
        assert_eq!(orig::popcount_low_plus(y, u32::MAX), opt::popcount_low_plus(y, u32::MAX));
        n += 1;
    }
    println!("agree {n}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-gen-{}", std::process::id()));
    let out = run_ab(&dir, body, &low.body, main);
    assert!(out.contains("agree 165536"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-reject twins of the dispatch: two instance types calling each
/// other's helper, an instance calling the original code instead of its
/// checked residual, an impl type left out. The lifted round trip rejects
/// each; the generic function keeps its source text.
#[test]
fn dispatch_faults_are_rejected() {
    for fault in [LowerFault::SwapDispatch, LowerFault::DispatchToOrig, LowerFault::DropDispatchImpl] {
        let low = lower_gen(Some(fault));
        println!("{fault:?}: {:?} {:?}", low.note, low.records);
        kept(&low, "crate::bits::popcount_low", "round trip");
        assert!(low.body.contains("pub fn popcount_low<T: Prim>(x: T) -> u32 {\n    let b = x.low();"), "{fault:?}: {}", low.body);
        assert!(!low.body.contains("__sandblaster_dispatch_Prim"), "{fault:?}: {}", low.body);
    }
}

/// What the dispatch refuses (each keeps its source text): a generic
/// function with buffer state (FRICTION: the dispatch call does not thread
/// the state yet); and the all-or-nothing rule — an instance whose residual
/// is not cheaper keeps every instance on the source. (A generic function
/// without a by-value parameter of its type is refused by the source scan:
/// the unit tests of `driver::lowered`.)
#[test]
fn what_the_dispatch_refuses() {
    let extra = "\nuse bytes::BufMut;\n\n/// A generic writer.\npub fn put_low<T: Prim>(x: T, buf: &mut impl BufMut) {\n    buf.put_u8(x.low());\n}\n\n/// Already cheap at every instance.\npub fn low_byte<T: Prim>(x: T) -> u8 {\n    x.low()\n}\n";
    let src = format!("{GEN}{extra}");
    let r = gen_root().replace("popcount_low_plus}", "popcount_low_plus, put_low, low_byte}");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", &src)]);
    println!("{:?}", low.records);
    kept(&low, "crate::bits::put_low", "a generic function with buffer state");
    kept(&low, "crate::bits::low_byte", "instance `u16`: the residual is not 3% cheaper");
    assert!(matches!(outcome(&low, "crate::bits::popcount_low"), LowerOutcome::Lowered { .. }));
}

// ---------------------------------------------------------------------
// readers: `buf: &mut impl Buf` with a result, lowered to `try_get_u8`
// ---------------------------------------------------------------------

const RD: &str = r#"//! Buffer reads, the obvious way.
use bytes::Buf;

/// The low three bits, clamped to 7.
fn low3(x: u8) -> u8 {
    let y = x & 7;
    if y > 7 { 7 } else { y }
}

/// One byte's low three bits, clamped to 7, or `None` at the end of the
/// buffer.
pub fn get_low3(buf: &mut impl Buf) -> Option<u8> {
    match buf.try_get_u8() {
        Ok(b) => {
            let y = b & 7;
            Some(if y > 7 { 7 } else { y })
        }
        Err(_) => None,
    }
}

/// Two bytes' low three bits added (`None` when fewer are left).
pub fn get_two(buf: &mut impl Buf) -> Option<u8> {
    let a = match buf.try_get_u8() {
        Ok(a) => low3(a),
        Err(_) => return None,
    };
    let b = match buf.try_get_u8() {
        Ok(b) => low3(b),
        Err(_) => return None,
    };
    Some(a + b)
}

/// A byte as it is (nothing cheaper).
pub fn get_raw(buf: &mut impl Buf) -> Option<u8> {
    match buf.try_get_u8() {
        Ok(b) => Some(b),
        Err(_) => None,
    }
}
"#;

fn lower_rd(fault: Option<LowerFault>) -> LoweredModule {
    let r = root("get_low3, get_two, get_raw");
    let c = check_files(&[("r/mod.rs", &r), ("r/bits.rs", RD)]);
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let (_, _, low) = match fault {
        None => driver::stage::lower_lifted(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default()),
        Some(f) => driver::stage::lower_lifted_with_fault(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default(), f),
    }
    .unwrap();
    low
}

/// A reader (`buf: &mut impl Buf` with a result): its residual — the
/// callee's branch pruned, the buffer model's `try_get_u8` kept — is lowered
/// as `try_get_u8()` calls on the original parameter with the result as
/// the value, read back by the lift as the same state passing, and agrees
/// with the source (rustc, every buffer of up to two bytes).
#[test]
fn readers_are_lowered_to_try_get_calls() {
    let low = lower_rd(None);
    println!("{}\n{:?}", low.body, low.records);
    assert!(low.note.is_none(), "{:?}", low.note);
    assert!(matches!(outcome(&low, "crate::bits::get_two"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    kept(&low, "crate::bits::get_raw", "not 3% cheaper");
    // OPEN (optimizer): the driven residual of `get_low3` does not
    // elaborate (a `Result` arm binding typed as the error payload), so it
    // keeps its source text: a sound fallback, recorded
    kept(&low, "crate::bits::get_low3", "did not elaborate");
    assert!(low.body.contains("pub fn get_two(buf: &mut impl Buf) -> Option<u8> {\n    __sandblaster_opt_get_two(buf)\n}"), "{}", low.body);
    assert!(low.body.contains("l0_buf.try_get_u8();"), "{}", low.body);
    let fix = |t: &str| t.replace("use bytes::Buf;", "use crate::bytes::Buf;");
    let (_, body) = driver::lifted::split_docs(RD);
    let main = r#"
mod bytes {
    pub struct TryGetError;
    pub trait Buf {
        fn try_get_u8(&mut self) -> Result<u8, TryGetError>;
    }
    impl Buf for &[u8] {
        fn try_get_u8(&mut self) -> Result<u8, TryGetError> {
            match self.split_first() {
                Some((h, t)) => { *self = t; Ok(*h) }
                None => Err(TryGetError),
            }
        }
    }
}
fn main() {
    let mut n = 0;
    let mut bufs: Vec<Vec<u8>> = vec![vec![]];
    for a in 0..=255u8 { bufs.push(vec![a]); for b in [0u8, 1, 7, 8, 200, 255] { bufs.push(vec![a, b]); bufs.push(vec![b, a, 9]); } }
    for v in &bufs {
        let (mut p, mut q) = (&v[..], &v[..]);
        assert_eq!(orig::get_low3(&mut p), opt::get_low3(&mut q));
        assert_eq!(p.len(), q.len());
        let (mut p, mut q) = (&v[..], &v[..]);
        assert_eq!(orig::get_two(&mut p), opt::get_two(&mut q));
        assert_eq!(p.len(), q.len());
        assert_eq!(orig::get_raw(&mut p), opt::get_raw(&mut q));
        n += 1;
    }
    println!("agree {n}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-rd-{}", std::process::id()));
    let out = run_ab(&dir, &fix(body), &fix(&low.body), main);
    assert!(out.contains("agree"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-reject twins in reader mode: one more byte read, or the last
/// read dropped. The lifted round trip rejects both; the reader keeps its
/// source text.
#[test]
fn reader_faults_are_rejected() {
    for fault in [LowerFault::ReadTwice, LowerFault::DropBufferCall] {
        let low = lower_rd(Some(fault));
        println!("{fault:?}: {:?}\n{}", low.records, low.body);
        kept(&low, "crate::bits::get_two", "round trip");
        assert!(low.body.contains("    let a = match buf.try_get_u8() {"), "{fault:?}: {}", low.body);
    }
}

// ---------------------------------------------------------------------
// `#[rewrite]` optimization lemmas and in-place modules
// ---------------------------------------------------------------------

const IP_BITS: &str = r#"//! Bit tests of a byte, the obvious way.

/// Whether at most one bit of `x` is set.
pub fn at_most_one_bit(x: u8) -> bool {
    x.count_ones() <= 1
}

/// The number of set bits, plus one.
pub fn ones_plus_one(x: u8) -> u32 {
    x.count_ones() + 1
}
"#;

const IP_OPT: &str = r#"//! Faster alternatives, each tied to a source function by a `#[rewrite]`
//! lemma in PROOF.rs.

/// `x` has at most one bit set: clearing its lowest set bit leaves zero.
pub fn at_most_one_bit_fast(x: u8) -> bool {
    x & x.wrapping_sub(1) == 0
}

/// Slower than the source (a multiply, a mask and a remainder).
pub fn ones_plus_one_slow(x: u8) -> u32 {
    let v = ((x as u64) * 0x0804_0201 >> 3) & 0x1111_1111;
    (v % 15) as u32 + 1
}
"#;

const IP_PROOF: &str = r#"//! Optimization lemmas (proven, so they need no human review).
use sandblaster::prelude::*;
use crate::bits::{at_most_one_bit, ones_plus_one};
use crate::opt::{at_most_one_bit_fast, ones_plus_one_slow};

/// The alternative is the source function (by the 256 cases).
#[lemma]
#[rewrite]
fn at_most_one_bit_is_fast(x: u8) {
    ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));
    by_cases(x, 0..=255);
}

/// Equal, but not cheaper.
#[lemma]
#[rewrite]
fn ones_plus_one_is_slow(x: u8) {
    ensures(ones_plus_one(x) == ones_plus_one_slow(x));
    by_cases(x, 0..=255);
}
"#;

fn ip_root(in_place: bool, extra: &str) -> String {
    let decl = if in_place { "#[lift(in_place)]\n#[path = \"../../src/bits.rs\"]" } else { "#[lift]" };
    format!("//! Bit tests, with optimization alternatives.\n#![forbid(unsafe_code)]\n\n{decl}\npub mod bits;\n\n#[lift(opt)]\nmod opt;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n{extra}\npub use bits::{{at_most_one_bit, ones_plus_one}};\n")
}

fn ip_files(in_place: bool, proof: &str, opt: &str) -> Vec<(String, String)> {
    let root = ip_root(in_place, "");
    let mut v = vec![
        ("/host/sandblaster/bits/mod.rs".to_string(), root),
        ("/host/sandblaster/bits/opt.rs".to_string(), opt.to_string()),
        ("/host/sandblaster/bits/PROOF.rs".to_string(), proof.to_string()),
    ];
    if in_place {
        v.push(("/host/src/lib.rs".into(), "//! A host crate.\nmod bits;\npub fn f(x: u8) -> bool { bits::at_most_one_bit(x) }\n".into()));
        v.push(("/host/src/bits.rs".into(), IP_BITS.to_string()));
    } else {
        v.push(("/host/sandblaster/bits/bits.rs".into(), IP_BITS.to_string()));
    }
    v
}

fn lower_ip(in_place: bool, proof: &str, opt: &str, fault: Option<LowerFault>) -> Vec<LoweredModule> {
    let files = ip_files(in_place, proof, opt);
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let root = Path::new("/host/sandblaster/bits/mod.rs");
    let c = driver::check(root, &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    if in_place {
        assert!(fault.is_none());
        let (_, lows) = driver::stage::lower_in_place(&c, root, &opts, &OptOptions::default()).unwrap();
        lows
    } else {
        let (_, _, low) = match fault {
            None => driver::stage::lower_lifted(&c, root, &opts, &OptOptions::default()),
            Some(f) => driver::stage::lower_lifted_with_fault(&c, root, &opts, &OptOptions::default(), f),
        }
        .unwrap();
        vec![low]
    }
}

/// A `#[rewrite]` lemma `f(x) == g(x)` with `g` an optimization
/// alternative (`#[lift(opt)]`, host Rust over the original API): `g`'s own
/// text replaces `f`'s body when it is cheaper, linked by the new
/// kernel-checked `<f>::rewrite_equiv` and checked by the lifted round trip;
/// an alternative that is not cheaper is not used. In place, the host's own
/// file is lowered (the file rustc compiles stays as it is; the lowered
/// copy is written beside the record). Both agree with the source on every
/// byte (rustc).
#[test]
fn rewrite_lemmas_replace_source_functions_in_place_and_in_module_mode() {
    for in_place in [true, false] {
        let lows = lower_ip(in_place, IP_PROOF, IP_OPT, None);
        assert_eq!(lows.len(), 1);
        let low = &lows[0];
        println!("in place {in_place}: {}\n{:?}", low.body, low.records);
        assert!(low.note.is_none(), "{:?}", low.note);
        match outcome(low, "crate::bits::at_most_one_bit") {
            LowerOutcome::Lowered { rung, via, .. } => {
                assert_eq!(rung, "Rewrite");
                assert!(via.contains("`crate::proof::at_most_one_bit_is_fast`") && via.contains("crate::bits::at_most_one_bit::rewrite_equiv"), "{via}");
            }
            other => panic!("{other:?}"),
        }
        kept(low, "crate::bits::ones_plus_one", "is not 3% cheaper");
        assert!(low.body.contains("pub fn at_most_one_bit(x: u8) -> bool {\n    __sandblaster_opt_at_most_one_bit_fast(x)\n}"), "{}", low.body);
        assert!(low.body.contains("/// `x` has at most one bit set: clearing its lowest set bit leaves zero.\nfn __sandblaster_opt_at_most_one_bit_fast(x: u8) -> bool {\n    x & x.wrapping_sub(1) == 0\n}"), "{}", low.body);
        assert!(!low.body.contains("ones_plus_one_slow"), "{}", low.body);
        if in_place {
            assert_eq!(low.file, "/host/src/bits.rs");
        }
        let (_, body) = driver::lifted::split_docs(IP_BITS);
        let main = "fn main() {\n    for x in 0..=255u8 {\n        assert_eq!(orig::at_most_one_bit(x), opt::at_most_one_bit(x));\n        assert_eq!(orig::ones_plus_one(x), opt::ones_plus_one(x));\n    }\n    println!(\"agree\");\n}\n";
        let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-rw-{}-{in_place}", std::process::id()));
        let out = run_ab(&dir, body, &low.body, main);
        assert!(out.contains("agree"), "{out}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Must-reject twins of rewrites: a wrong copy of the alternative (the
/// lifted round trip compares it with the verified alternative); a lemma
/// with a precondition the source function does not have (the link's
/// statement is not the lemma's: the kernel-checked link is refused); a
/// `#[rewrite]` lemma whose right side is not an alternative (not used).
#[test]
fn rewrite_faults_are_rejected() {
    let lows = lower_ip(false, IP_PROOF, IP_OPT, Some(LowerFault::WrongAlternative));
    println!("{:?}", lows[0].records);
    kept(&lows[0], "crate::bits::at_most_one_bit", "round trip");
    assert!(lows[0].body.contains("pub fn at_most_one_bit(x: u8) -> bool {\n    x.count_ones() <= 1\n}"), "{}", lows[0].body);
    // a precondition of the lemma only
    let pre = IP_PROOF.replace("    ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));\n    by_cases(x, 0..=255);", "    requires(x < 128u8);\n    ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));\n    by_cases(x, 0..=255);");
    let lows = lower_ip(false, &pre, IP_OPT, None);
    println!("{:?}", lows[0].records);
    kept(&lows[0], "crate::bits::at_most_one_bit", "do not have the same parameters and preconditions");
    // the right side is a source function, not an alternative: the lemma
    // is not used, and the residual (not cheaper) is not either
    let not_alt = format!("{IP_PROOF}\n/// A rewrite to another source function.\n#[lemma]\n#[rewrite]\nfn ones_twice(x: u8) {{\n    ensures(ones_plus_one(x) == ones_plus_one(x));\n}}\n");
    let lows = lower_ip(false, &not_alt, IP_OPT, None);
    kept(&lows[0], "crate::bits::ones_plus_one", "not 3% cheaper");
    assert!(lows[0].unused_rewrites.iter().any(|n| n.contains("`crate::proof::ones_twice` is not used") && n.contains("is not a function of a `#[lift(opt)]` module")), "{:?}", lows[0].unused_rewrites);
    assert!(lows[0].json().render().contains("unused_rewrite_lemmas"));
}

/// `#[lift(opt)]` is lifted like any module and never emitted; combined
/// with `host` or `in_place` it is refused (negative twins).
#[test]
fn the_opt_option_and_its_twins() {
    let files = ip_files(false, IP_PROOF, IP_OPT);
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("/host/sandblaster/bits/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    assert!(c.lifted.iter().any(|l| l.opt && l.name == "opt"));
    // the emitted module is the source, never the alternatives
    assert_eq!(driver::lifted::emitted_module(&c.lifted).unwrap().map(|l| l.name.as_str()), Some("bits"));
    for bad in ["#[lift(opt, host)]", "#[lift(opt, in_place)]"] {
        let mut files = ip_files(false, IP_PROOF, IP_OPT);
        files[0].1 = files[0].1.replace("#[lift(opt)]", bad);
        let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        let c = driver::check(Path::new("/host/sandblaster/bits/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(!c.ok() && c.render().contains("`opt` (optimization alternatives) cannot be combined"), "{bad}: {}", c.render());
    }
}
