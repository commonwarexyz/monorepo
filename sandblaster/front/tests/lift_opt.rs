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
/// generic function (FRICTION: its instances would need a type dispatch),
/// a function with buffer state, a helper name the source already uses, a
/// residual that is not cheaper.
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
    kept(&low, "crate::bits::popcount_generic", "generic source function");
    kept(&low, "crate::bits::put_counted", "a parameter with state other than one `&mut impl BufMut` of a function without a result");
    kept(&low, "crate::bits::low_byte", "not 3% cheaper");
    assert_eq!(low.lowered(), 2);
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
    // the summary says why each function kept its source text
    assert!(code.contains("optimized: none of the 2 source function(s) rewritten, the source is emitted as-is; source kept: "), "{code}");
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
