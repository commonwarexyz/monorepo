//! The optimizer on lifted code (DESIGN.md §2.1 "lifted modules",
//! `driver::lowered`): a cheaper residual of a lifted function is lowered
//! into the source file, in the source's dialect, and accepted only after
//! the lifted round trip (read back by the same lift, elaborated in
//! generated mode, compared with the kernel-checked residual). Each
//! feature has a positive test and a must-reject twin.
//!
//! The lifted bodies are rustc's MIR (the fixtures `mir_fixtures/opt_*`), and
//! so are the bodies the lifted round trip reads back: the MIR of the round
//! trip's copy of each scenario (`rt*.sbmir`, extracted from the copy
//! `rt*.rs` the lowering wrote; `SANDBLASTER_DUMP_ROUNDTRIP_COPIES=1` writes
//! the copies into the fixtures, `mir_fixtures/extract.py` extracts them).
//!
//! `cargo test --release -p sandblaster-front --test lift_opt -- --test-threads=1`

use std::path::Path;

use sandblaster_front::driver::lowered::{LowerFault, LowerOrigin, LowerOutcome, LoweredModule};
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

const ROOT: &str = "//! A lifted example.\n#![forbid(unsafe_code)]\n#[lift(mir = \"bits.sbmir\")]\nmod bits;\npub use bits::{EXPORTS};\n";

/// Plain Rust, written the obvious way: two loops with known closed forms
/// (Σ2 and the aegraph's `count_ones` rule) and a function the optimizer
/// cannot improve.
const BITS: &str = include_str!("mir_fixtures/opt_bits/bits.rs");

/// Straight-line functions with a clamp the bit mask already bounds (the
/// optimizer's residual drops it; rustc's MIR keeps it), a generic one, and
/// a `BufMut` writer with a result.
const DRIVEN_MORE: &str = include_str!("mir_fixtures/opt_driven_more/bits.rs");
/// The same with a function named like a helper of the lowering.
const DRIVEN_TAKEN: &str = include_str!("mir_fixtures/opt_driven_taken/bits.rs");

/// The MIR fixtures of this file: the lifted `bits.rs` of each.
const FIXTURES: &[(&str, &str)] = &[
    ("opt_bits", include_str!("mir_fixtures/opt_bits/bits.rs")),
    ("opt_driven_more", include_str!("mir_fixtures/opt_driven_more/bits.rs")),
    ("opt_driven_taken", include_str!("mir_fixtures/opt_driven_taken/bits.rs")),
    ("opt_mbits", include_str!("mir_fixtures/opt_mbits/bits.rs")),
    ("opt_mbits_cheap", include_str!("mir_fixtures/opt_mbits_cheap/bits.rs")),
    ("opt_buf", include_str!("mir_fixtures/opt_buf/bits.rs")),
    ("opt_gen2", include_str!("mir_fixtures/opt_gen2/bits.rs")),
    ("opt_gen2_more", include_str!("mir_fixtures/opt_gen2_more/bits.rs")),
    ("opt_rd", include_str!("mir_fixtures/opt_rd/bits.rs")),
    ("opt_panics", include_str!("mir_fixtures/opt_panics/bits.rs")),
    ("opt_shipped", include_str!("mir_fixtures/opt_shipped/bits.rs")),
];

/// Arithmetic with nothing to rule out its panics (exec-only code: each
/// function's elaboration leaves an obligation unproven), and a `const fn`.
const PANICS: &str = include_str!("mir_fixtures/opt_panics/bits.rs");

/// Functions whose cheaper residuals rustc compiles to MIR of another shape
/// than the residuals' own: temporaries bound by `let`, a checked
/// operation's `Option` tested with `is_none`, sub-slices of a slice.
const SHIPPED: &str = include_str!("mir_fixtures/opt_shipped/bits.rs");

/// A fixture file (`tests/mir_fixtures/<path>`), when it exists.
fn fixture(path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures").join(path)).ok()
}

/// The fixture whose lifted `bits.rs` the files hold (`dir` names it
/// directly when its source is not a file of `files`).
fn fixture_of(files: &[(String, String)]) -> Option<&'static str> {
    files.iter().find(|(p, _)| p.ends_with("bits.rs")).and_then(|(_, c)| FIXTURES.iter().find(|(_, s)| s == c)).map(|(d, _)| *d)
}

/// `files` with rustc's MIR of fixture `dir` beside the DSL root
/// (`bits.sbmir`), and the MIR of the round trip's copy of scenario `rt`
/// (`bits.roundtrip__bits.sbmir`) when it is extracted.
fn with_mir(files: &[(String, String)], dir: Option<&str>, rt: &str) -> Vec<(String, String)> {
    let mut v = files.to_vec();
    let Some(dir) = dir.or_else(|| fixture_of(files)) else { return v };
    let base = Path::new(&files[0].0).parent().unwrap().to_path_buf();
    v.push((base.join("bits.sbmir").display().to_string(), fixture(&format!("{dir}/bits.sbmir")).expect("the fixture's MIR")));
    if let Some(m) = fixture(&format!("{dir}/{rt}.sbmir")) {
        v.push((base.join("bits.roundtrip__bits.sbmir").display().to_string(), m));
    }
    v
}

/// With `SANDBLASTER_DUMP_ROUNDTRIP_COPIES` set: writes the round trip's
/// copy of scenario `rt` into its fixture (`rt*.rs`, the input of
/// `mir_fixtures/extract.py`).
fn dump_copy(dir: Option<&str>, rt: &str, copy: Option<&str>) {
    if std::env::var_os("SANDBLASTER_DUMP_ROUNDTRIP_COPIES").is_none() {
        return;
    }
    if let (Some(dir), Some(copy)) = (dir, copy) {
        std::fs::write(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures").join(dir).join(format!("{rt}.rs")), copy).unwrap();
    }
}

fn owned(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect()
}

fn check_owned(files: &[(String, String)]) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    driver::check(Path::new(&files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn check_files(files: &[(&str, &str)]) -> Checked {
    check_owned(&with_mir(&owned(files), None, "rt"))
}

fn root(exports: &str) -> String {
    ROOT.replace("EXPORTS", exports)
}

fn lower(files: &[(&str, &str)]) -> LoweredModule {
    let c = check_files(files);
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: true };
    let (_, _, low) = driver::stage::lower_lifted(&c, Path::new(files[0].0), &opts, &OptOptions::default()).unwrap();
    dump_copy(fixture_of(&owned(files)), "rt", low.roundtrip_copy.as_ref().map(|(_, t)| t.as_str()));
    low
}

fn outcome<'a>(low: &'a LoweredModule, f: &str) -> &'a LowerOutcome {
    &low.records.iter().find(|r| r.function == f).unwrap_or_else(|| panic!("no record for {f}: {:?}", low.records)).outcome
}

#[test]
#[ignore = "OPEN (optimizer on MIR loops): a `for` over a range is a tail-recursive helper over `core::ops::Range` in rustc's MIR; with its loop attachment it verifies, but its residual keeps the helper and the lowering printer does not print generic structs (`crate::__lift::Range<u32>`): no closed form, nothing lowered"]
fn closed_forms_are_lowered_into_the_source() {
    // (rustc's MIR reads each `for` as a loop helper over `core::ops::Range`:
    // its invariant and measure are attached)
    let r = format!("{}#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n", root("rank_above, popcount_loop, low_byte"));
    let pf = "use sandblaster::prelude::*;\n#[lift_attach(crate::bits::rank_above, loop_nr = 0)]\nfn rank_loop() {\n    invariant(iter.start <= iter.end && iter.end == 64u32);\n    decreases(iter.end - iter.start);\n}\n#[lift_attach(crate::bits::popcount_loop, loop_nr = 0)]\nfn pop_loop() {\n    invariant(iter.start <= iter.end && iter.end == 64u32);\n    decreases(iter.end - iter.start);\n}\n";
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", BITS), ("r/PROOF.rs", pf)]);
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
    let rt = format!("rt_{fault:?}");
    let c = check_owned(&with_mir(&owned(files), None, &rt));
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: true };
    let (_, _, low) = driver::stage::lower_lifted_with_fault(&c, Path::new(files[0].0), &opts, &OptOptions::default(), fault).unwrap();
    dump_copy(fixture_of(&owned(files)), &rt, low.roundtrip_copy.as_ref().map(|(_, t)| t.as_str()));
    low
}

/// The victim of a faulty printer is kept because the lifted round trip,
/// reading the copy's MIR back, rejected it (its comparison, the front end
/// or the generated-mode elaboration) — not because the round trip had no
/// MIR of the copy to read.
#[track_caller]
fn rejected_by_round_trip(low: &LoweredModule, f: &str) {
    match outcome(low, f) {
        LowerOutcome::Kept(why) => assert!(why.starts_with("the lifted round trip") && !why.contains("no MIR of the round trip's copy") && !why.contains("changed since the MIR was extracted"), "`{f}` kept for another reason: {why}"),
        other => panic!("`{f}` was lowered: {other:?}\n{}", low.body),
    }
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
#[ignore = "OPEN (optimizer on MIR loops): the faults target the closed-form helpers of `closed_forms_are_lowered_into_the_source`, which are not lowered from rustc's MIR yet"]
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
        // rejected per function by the comparison (the copy's MIR read back)
        rejected_by_round_trip(&low, victim);
        // the victim's source body is untouched
        let src_body = if victim.ends_with("rank_above") { "        if i > k && (n >> i) & 1 == 1 {" } else { "        c = c.wrapping_add(((x >> i) & 1) as u32);" };
        assert!(low.body.contains(src_body), "{fault:?}: the source body of `{victim}` is gone:\n{}", low.body);
    }
}

/// What the lowering refuses, each kept as written with its reason: a
/// `BufMut` state beside a result, a helper name the source already uses, a
/// residual that is not cheaper. (A generic function over a sealed trait is
/// lowered through a per-type dispatch: `generic_functions_*` below.) The
/// fixtures `opt_driven*`: straight-line code whose residuals rustc's MIR
/// leaves room for (a clamp the bit mask already bounds).
#[test]
fn what_is_not_lowered_keeps_its_source_text() {
    let r = root("bump_low, clamp7, low_byte, clamp_generic, put_counted");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", DRIVEN_MORE)]);
    println!("{}\n{:?}", low.body, low.records);
    assert!(matches!(outcome(&low, "crate::bits::clamp_generic"), LowerOutcome::Lowered { via, .. } if via.contains("per-type dispatch")), "{:?}", low.records);
    kept(&low, "crate::bits::put_counted", "one `&mut impl BufMut` of a function without a result");
    kept(&low, "crate::bits::low_byte", "not 3% cheaper");
    assert!(matches!(outcome(&low, "crate::bits::clamp7"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    assert_eq!(low.lowered(), 2);
    // a source that already uses a helper's name
    let r = root("bump_low, clamp7, low_byte, __sandblaster_opt_clamp7");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", DRIVEN_TAKEN)]);
    kept(&low, "crate::bits::clamp7", "already uses the name");
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
#[ignore = "OPEN (optimizer on MIR loops): it compiles the lowering of `closed_forms_are_lowered_into_the_source`, which is not lowered from rustc's MIR yet"]
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

/// A function that can panic (exec-only code: `b == 0`, an overflowing
/// sum; nothing rules them out) is optimized through its panic-explicit
/// reading (DESIGN.md §8.2 item 12) and lowered when the reading's residual
/// is cheaper: `twice_quot`'s second division is the first one's value, so
/// its residual divides once. It replaces the source only with the round
/// trip's two panic theorems: the source's MIR and the copy's, each against
/// the reading, accepted by the trusted gate. Functions whose readings'
/// residuals are no cheaper keep their text, and a `const fn` whose residual
/// is cheaper is lowered with `const fn` helpers.
#[test]
fn a_function_that_can_panic_is_lowered_through_its_panic_explicit_reading() {
    let r = root("twice_quot, ceil_div, inc, clamp7c");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", PANICS)]);
    println!("{}\n{:?}\n{:?}", low.body, low.note, low.records);
    match outcome(&low, "crate::bits::twice_quot") {
        LowerOutcome::Lowered { via, origin, .. } => {
            assert!(via.contains("panic-explicit reading") && via.contains("twice_quot__panics"), "{via}");
            assert_eq!(*origin, LowerOrigin::Optimizer);
        }
        other => panic!("`twice_quot` was not lowered: {other:?}"),
    }
    // its helper divides once, by Rust's own operator (which panics on `b == 0`):
    // the reading's guard `b == 0` is that division's own test, so it is not
    // printed (`lower::guards_next`), and neither is any explicit panic
    let helper = low.body.split("fn __sandblaster_opt_twice_quot").nth(1).expect("the helper");
    let helper = &helper[..helper.find("\n}\n").unwrap_or(helper.len())];
    assert_eq!(helper.matches(" / ").count(), 1, "{helper}");
    assert!(!helper.contains("panic!"), "{helper}");
    // the readings of the others are as costly as the source
    kept(&low, "crate::bits::ceil_div", "not 3% cheaper");
    kept(&low, "crate::bits::inc", "not 3% cheaper");
    // a `const fn` keeps its constness: its helper is a `const fn`
    assert!(matches!(outcome(&low, "crate::bits::clamp7c"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    assert!(low.body.contains("const fn __sandblaster_opt_clamp7c("), "{}", low.body);
    // the round trip proved the shipped code's panic theorems
    assert!(low.shipped.iter().any(|n| n.contains("twice_quot")), "{:?}", low.shipped);
}

/// The lowered module panics exactly where the source panics: both
/// compiled by rustc (overflow checks and debug assertions on) and run on
/// every input class, panics caught and compared.
#[test]
fn the_lowered_code_panics_where_the_source_panics() {
    let r = root("twice_quot, ceil_div, inc, clamp7c");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", PANICS)]);
    assert!(matches!(outcome(&low, "crate::bits::twice_quot"), LowerOutcome::Lowered { .. }), "{:?}", low.records);
    let (_, body) = PANICS.split_at(PANICS.find("\n\n").unwrap());
    let main = r#"
fn outcome<T: std::fmt::Debug>(f: impl FnOnce() -> T + std::panic::UnwindSafe) -> String {
    match std::panic::catch_unwind(f) {
        Ok(v) => format!("{v:?}"),
        Err(_) => "panic".to_string(),
    }
}
fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let vals = [0u32, 1, 2, 3, 7, 1 << 31, (1 << 31) + 1, u32::MAX - 1, u32::MAX];
    let mut n = 0u64;
    let mut panics = 0u64;
    for &a in &vals {
        for &b in &vals {
            let (x, y) = (outcome(move || orig::twice_quot(a, b)), outcome(move || opt::twice_quot(a, b)));
            assert_eq!(x, y, "twice_quot({a}, {b})");
            panics += (x == "panic") as u64;
            assert_eq!(outcome(move || orig::ceil_div(a, b)), outcome(move || opt::ceil_div(a, b)), "ceil_div({a}, {b})");
            n += 1;
        }
        assert_eq!(orig::clamp7c(a), opt::clamp7c(a));
    }
    for x in 0..=255u8 {
        assert_eq!(outcome(move || orig::inc(x)), outcome(move || opt::inc(x)));
    }
    const C: u32 = opt::clamp7c(13);
    assert_eq!(C, 5);
    println!("agree {n} panics {panics}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-panics-{}", std::process::id()));
    let out = run_ab(&dir, body, &low.body, main);
    assert!(out.contains("agree 81") && !out.contains("panics 0"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-reject twin: the copy's MIR read with one constant off (the
/// shipped code is not the code compared) fails the shipped code's panic
/// theorem, so the function keeps its source text.
#[test]
fn a_shipped_mir_that_is_not_the_lowered_code_fails_the_panic_theorem() {
    let r = root("twice_quot");
    let low = lower_faulty(&[("r/mod.rs", &r), ("r/bits.rs", PANICS)], LowerFault::ShippedMir);
    println!("{:?}\n{:?}", low.note, low.records);
    match outcome(&low, "crate::bits::twice_quot") {
        LowerOutcome::Kept(why) => assert!(why.contains("shipped code's theorem"), "{why}"),
        other => panic!("`twice_quot` was lowered: {other:?}"),
    }
}

/// A module read from MIR is decided by its shipped code's theorems, not by
/// a syntactic comparison (DESIGN.md §2.1, docs/mir-lift.md §20.7). Each
/// residual of `opt_shipped` is cheaper and reads back from rustc's MIR of
/// the copy in another form than the residual's own (temporaries bound by
/// `let`, `checked_add`'s `Option` tested with `is_none`, sub-slices of a
/// slice): the syntactic comparison, run beside the theorems by the test
/// hook `CompareStructurally` (it decides nothing there), refuses every one.
/// The kernel holds `L::shipped::<id>` of each copy — its MIR returns
/// exactly the source function's value — so each is lowered, nothing is
/// compared structurally, and the lowered module agrees with the source
/// under rustc on every input class.
#[test]
fn a_rewrite_whose_shipped_mir_differs_only_syntactically_is_accepted() {
    let r = root("pow2_ceil, read_u16_be, mix32");
    let files = [("r/mod.rs", r.as_str()), ("r/bits.rs", SHIPPED)];
    let low = lower(&files);
    println!("{}\n{:?}\n{:?}\n{:?}", low.body, low.note, low.records, low.shipped);
    let fns = ["pow2_ceil", "read_u16_be", "mix32"];
    for f in fns {
        let path = format!("crate::bits::{f}");
        assert!(matches!(outcome(&low, &path), LowerOutcome::Lowered { origin: LowerOrigin::Optimizer, .. }), "`{f}` was not lowered: {:?}", low.records);
        assert!(low.shipped.iter().any(|n| n.contains(&format!("`{path}`")) && n.contains("1 against the source function")), "`{f}`: {:?}", low.shipped);
    }
    // the theorems decided: nothing was compared structurally
    assert_eq!(low.compared, 0);
    assert!(low.structural.is_empty());
    // what the syntactic comparison would have said: each read back
    // differently from its residual
    let hooked = lower_faulty(&files, LowerFault::CompareStructurally);
    println!("{:?}", hooked.structural);
    for f in fns {
        assert!(matches!(outcome(&hooked, &format!("crate::bits::{f}")), LowerOutcome::Lowered { .. }), "`{f}` (hooked): {:?}", hooked.records);
        assert!(hooked.structural.iter().any(|s| s.starts_with(&format!("`{f}`:")) && s.contains(&format!("__sandblaster_opt_{f}` does not match its replacement"))), "`{f}`: {:?}", hooked.structural);
    }
    let (_, body) = driver::lifted::split_docs(SHIPPED);
    let main = r#"
fn main() {
    let mut n = 0u64;
    let edges = [0u64, 1, 2, 3, 4, 5, 1 << 62, (1 << 62) + 1, 1 << 63, (1 << 63) + 1, u64::MAX - 1, u64::MAX];
    for &v in &edges {
        assert_eq!(orig::pow2_ceil(v), opt::pow2_ceil(v), "pow2_ceil({v})");
        n += 1;
    }
    let data: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(37).wrapping_add(11)).collect();
    for len in 0..=data.len() {
        for at in (0..=len + 2).chain([usize::MAX - 1, usize::MAX]) {
            assert_eq!(orig::read_u16_be(&data[..len], at), opt::read_u16_be(&data[..len], at), "read_u16_be(len {len}, {at})");
            n += 1;
        }
    }
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..100_000 {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        assert_eq!(orig::pow2_ceil(x >> (x & 63)), opt::pow2_ceil(x >> (x & 63)));
        assert_eq!(orig::mix32(x as u32), opt::mix32(x as u32));
        n += 1;
    }
    const C: u32 = opt::mix32(7);
    assert_eq!(C, orig::mix32(7));
    println!("agree {n}");
}
"#;
    let dir = std::env::temp_dir().join(format!("sandblaster-lift-opt-shipped-{}", std::process::id()));
    let out = run_ab(&dir, body, &low.body, main);
    assert!(out.contains("agree"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Must-reject twin: the copy's MIR read with one constant off (the shipped
/// code is not the code the residual is) fails the shipped code's theorem —
/// which now decides alone — so the function keeps its source text.
#[test]
fn a_wrong_shipped_copy_is_refused_by_the_theorem() {
    let r = root("pow2_ceil");
    let low = lower_faulty(&[("r/mod.rs", &r), ("r/bits.rs", SHIPPED)], LowerFault::ShippedMir);
    println!("{:?}\n{:?}", low.note, low.records);
    match outcome(&low, "crate::bits::pow2_ceil") {
        LowerOutcome::Kept(why) => assert!(why.starts_with("the lifted round trip") && why.contains("shipped code's theorem"), "{why}"),
        other => panic!("`pow2_ceil` was lowered: {other:?}"),
    }
    assert!(low.body.contains("pub fn pow2_ceil(n: u64) -> Option<u64> {\n    if n <= 1 {"), "{}", low.body);
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

#[lift(mir = "bits.sbmir")]
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

const M_BITS: &str = include_str!("mir_fixtures/opt_mbits/bits.rs");

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
    // runs its harness under `OUT_DIR/<out>-conformance/` (one per build:
    // two tests building `bits` at once must not share the harness)
    static BUILDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let out = std::env::temp_dir().join(format!("sandblaster-lift-opt-out-{}-{n}", std::process::id()));
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
    let dsl = with_mir(
        &[
            (format!("/host/{M_ROOT}"), M_DSL_ROOT.to_string()),
            ("/host/sandblaster/bits/bits.rs".to_string(), bits.to_string()),
            ("/host/sandblaster/bits/LAWS.rs".to_string(), M_LAWS.to_string()),
            ("/host/sandblaster/bits/PROOF.rs".to_string(), M_PROOF.to_string()),
        ],
        None,
        "rt",
    );
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
    // (module mode writes the round trip's copy for its extraction)
    dump_copy(Some("opt_mbits"), "rt", o.outputs.iter().find(|(p, _)| p.ends_with("bits-roundtrip__bits.rs")).map(|(_, c)| c.as_str()));
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
    assert_eq!(bits, include_str!("mir_fixtures/opt_mbits_cheap/bits.rs"));
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

const BUF: &str = include_str!("mir_fixtures/opt_buf/bits.rs");

fn lower_buf(fault: Option<LowerFault>) -> LoweredModule {
    let r = root("put_low3, put_pair");
    let rt = fault.map(|f| format!("rt_{f:?}")).unwrap_or_else(|| "rt".into());
    let c = check_owned(&with_mir(&owned(&[("r/mod.rs", &r), ("r/bits.rs", BUF)]), None, &rt));
    assert!(c.ok(), "{}", c.render());
    // the buffer model is ghost code: a full elaboration
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let (_, _, low) = match fault {
        None => driver::stage::lower_lifted(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default()),
        Some(f) => driver::stage::lower_lifted_with_fault(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default(), f),
    }
    .unwrap();
    dump_copy(Some("opt_buf"), &rt, low.roundtrip_copy.as_ref().map(|(_, t)| t.as_str()));
    low
}

/// A function with a `BufMut` state: its residual (the callee's branch
/// pruned, the buffer operations kept as calls) is lowered as `BufMut`
/// calls on the original `&mut impl BufMut` parameter, and the lifted round
/// trip reads it back as the same state passing.
#[test]
#[ignore = "OPEN (optimizer on MIR bodies): rustc's MIR of these writers leaves the optimizer nothing cheaper (`put_low3`: 4618 vs 4736 milli-cycles, under the 3% bar; the source lift's reading was costlier), so no function with buffer state is lowered"]
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
#[ignore = "OPEN (optimizer on MIR bodies): rustc's MIR of these writers leaves the optimizer nothing cheaper (`put_low3`: 4618 vs 4736 milli-cycles, under the 3% bar; the source lift's reading was costlier), so no function with buffer state is lowered"]
fn buffer_printer_faults_are_rejected() {
    for fault in [LowerFault::SwapBufferCalls, LowerFault::DropBufferCall] {
        let low = lower_buf(Some(fault));
        println!("{fault:?}: {:?}", low.records);
        rejected_by_round_trip(&low, "crate::bits::put_low3");
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
/// root declares `u64` unverified. (Straight-line: a clamp the bit mask
/// already bounds, which the residual drops and rustc's MIR keeps.)
const GEN: &str = include_str!("mir_fixtures/opt_gen2/bits.rs");

fn gen_root() -> String {
    "//! A lifted generic example.\n#![forbid(unsafe_code)]\n#[lift(mir = \"bits.sbmir\", unverified = \"u64\")]\nmod bits;\npub use bits::{clamp_low, clamp_low_plus};\n".to_string()
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
    match outcome(&low, "crate::bits::clamp_low") {
        LowerOutcome::Lowered { via, .. } => assert!(via.contains("per-type dispatch `__sandblaster_dispatch_Prim` over u16, u32"), "{via}"),
        other => panic!("`clamp_low`: {other:?}"),
    }
    // the shipped code's theorems, per verified instance: the helper's, the
    // dispatch impl method's, the copy's and the one against the source
    // instance (docs/checked-structuring.md step 8)
    assert!(low.shipped.iter().any(|n| n.contains("`crate::bits::clamp_low`") && n.contains("(2 against the source function)")), "{:?}", low.shipped);
    // (the twice-clamped one: rustc's MIR leaves nothing cheaper)
    kept(&low, "crate::bits::clamp_low_plus", "not 3% cheaper");
    let b = &low.body;
    assert!(b.contains("pub trait Prim: Copy + __sandblaster_dispatch_Prim {"), "{b}");
    assert!(b.contains("pub trait __sandblaster_dispatch_Prim: Sized {\n        fn __sandblaster_opt_clamp_low(self) -> u8;\n    }"), "{b}");
    assert!(b.contains("pub fn clamp_low<T: Prim>(x: T) -> u8 {\n    x.__sandblaster_opt_clamp_low()\n}"), "{b}");
    assert!(b.contains("impl sealed::__sandblaster_dispatch_Prim for u16 {"), "{b}");
    assert!(b.contains("__sandblaster_opt_clamp_low_for_u16(self)"), "{b}");
    // the unverified instance keeps the original code
    assert!(b.contains("impl sealed::__sandblaster_dispatch_Prim for u64 {"), "{b}");
    assert!(b.contains("__sandblaster_orig_clamp_low::<u64>(self)"), "{b}");
    assert!(b.contains("fn __sandblaster_orig_clamp_low<T: Prim>(x: T) -> u8 {\n    let b = x.low() & 7;"), "{b}");
    assert!(!b.contains("__sandblaster_opt_clamp_low_for_u64"), "{b}");
    let (_, body) = driver::lifted::split_docs(GEN);
    let main = r#"
fn main() {
    let mut n = 0u64;
    for x in 0..=u16::MAX {
        assert_eq!(orig::clamp_low(x), opt::clamp_low(x));
        assert_eq!(orig::clamp_low_plus(x, 7), opt::clamp_low_plus(x, 7));
        n += 1;
    }
    let mut y: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..100_000 {
        y ^= y << 13; y ^= y >> 7; y ^= y << 17;
        assert_eq!(orig::clamp_low(y as u32), opt::clamp_low(y as u32));
        assert_eq!(orig::clamp_low(y), opt::clamp_low(y));
        assert_eq!(orig::clamp_low_plus(y, u8::MAX), opt::clamp_low_plus(y, u8::MAX));
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
        if matches!(fault, LowerFault::SwapDispatch | LowerFault::DropDispatchImpl) {
            // a `u16` passed where the `u32` helper wants a `u32`, or an impl
            // type without its dispatch impl: rustc refuses the copy, so it has
            // no MIR and the round trip cannot read it back
            // (`mir_fixtures/extract.py`: not extracted); it is kept
            kept(&low, "crate::bits::clamp_low", "no MIR of the round trip's copy");
        } else {
            rejected_by_round_trip(&low, "crate::bits::clamp_low");
        }
        assert!(low.body.contains("pub fn clamp_low<T: Prim>(x: T) -> u8 {\n    let b = x.low() & 7;"), "{fault:?}: {}", low.body);
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
    let src = include_str!("mir_fixtures/opt_gen2_more/bits.rs");
    let r = gen_root().replace("clamp_low_plus}", "clamp_low_plus, put_low, low_byte}");
    let low = lower(&[("r/mod.rs", &r), ("r/bits.rs", src)]);
    println!("{:?}", low.records);
    kept(&low, "crate::bits::put_low", "a generic function with buffer state");
    kept(&low, "crate::bits::low_byte", "instance `u16`: the residual is not 3% cheaper");
    assert!(matches!(outcome(&low, "crate::bits::clamp_low"), LowerOutcome::Lowered { .. }));
}

// ---------------------------------------------------------------------
// readers: `buf: &mut impl Buf` with a result, lowered to `try_get_u8`
// ---------------------------------------------------------------------

const RD: &str = include_str!("mir_fixtures/opt_rd/bits.rs");

fn lower_rd(fault: Option<LowerFault>) -> LoweredModule {
    let r = root("get_low3, get_two, get_raw");
    let rt = fault.map(|f| format!("rt_{f:?}")).unwrap_or_else(|| "rt".into());
    let c = check_owned(&with_mir(&owned(&[("r/mod.rs", &r), ("r/bits.rs", RD)]), None, &rt));
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let (_, _, low) = match fault {
        None => driver::stage::lower_lifted(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default()),
        Some(f) => driver::stage::lower_lifted_with_fault(&c, Path::new("r/mod.rs"), &opts, &OptOptions::default(), f),
    }
    .unwrap();
    dump_copy(Some("opt_rd"), &rt, low.roundtrip_copy.as_ref().map(|(_, t)| t.as_str()));
    low
}

/// A reader (`buf: &mut impl Buf` with a result): its residual — the
/// callee's branch pruned, the buffer model's `try_get_u8` kept — is lowered
/// as `try_get_u8()` calls on the original parameter with the result as
/// the value, read back by the lift as the same state passing, and agrees
/// with the source (rustc, every buffer of up to two bytes).
#[test]
#[ignore = "OPEN (lifted round trip on MIR): the lowered reader `get_two` is read back from rustc's MIR of the copy with another structure than the optimizer's residual (the comparison is structural: relevant structure differs), so it is rejected and kept"]
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
#[ignore = "OPEN (lifted round trip on MIR): the lowered reader `get_two` is read back from rustc's MIR of the copy with another structure than the optimizer's residual (the comparison is structural: relevant structure differs), so it is rejected and kept"]
fn reader_faults_are_rejected() {
    for fault in [LowerFault::ReadTwice, LowerFault::DropBufferCall] {
        let low = lower_rd(Some(fault));
        println!("{fault:?}: {:?}\n{}", low.records, low.body);
        rejected_by_round_trip(&low, "crate::bits::get_two");
        assert!(low.body.contains("    let a = match buf.try_get_u8() {"), "{fault:?}: {}", low.body);
    }
}

// ---------------------------------------------------------------------
// `#[rewrite]` optimization lemmas and in-place modules
// ---------------------------------------------------------------------

const IP_BITS: &str = include_str!("mir_fixtures/opt_ip_mod/bits.rs");

const IP_OPT: &str = include_str!("mir_fixtures/opt_ip_mod/opt.rs");

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
    let decl = if in_place { "#[lift(in_place, mir = \"bits.sbmir\")]\n#[path = \"../../src/bits.rs\"]" } else { "#[lift(mir = \"bits.sbmir\")]" };
    format!("//! Bit tests, with optimization alternatives.\n#![forbid(unsafe_code)]\n\n{decl}\npub mod bits;\n\n#[lift(opt, mir = \"bits.sbmir\")]\nmod opt;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n{extra}\npub use bits::{{at_most_one_bit, ones_plus_one}};\n")
}

fn ip_files(in_place: bool, proof: &str, opt: &str) -> Vec<(String, String)> {
    ip_files_rt(in_place, proof, opt, "rt")
}

/// The fixture of [`ip_files`]: `bits.rs` lifted in place or as a module.
fn ip_fixture(in_place: bool) -> &'static str {
    if in_place { "opt_ip_inplace" } else { "opt_ip_mod" }
}

fn ip_files_rt(in_place: bool, proof: &str, opt: &str, rt: &str) -> Vec<(String, String)> {
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
    with_mir(&v, Some(ip_fixture(in_place)), rt)
}

fn lower_ip(in_place: bool, proof: &str, opt: &str, fault: Option<LowerFault>) -> Vec<LoweredModule> {
    lower_ip_with(in_place, proof, opt, fault, &OptOptions::default())
}

fn lower_ip_with(in_place: bool, proof: &str, opt: &str, fault: Option<LowerFault>, oopts: &OptOptions) -> Vec<LoweredModule> {
    let rt = fault.map(|f| format!("rt_{f:?}")).unwrap_or_else(|| "rt".into());
    let files = ip_files_rt(in_place, proof, opt, &rt);
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let root = Path::new("/host/sandblaster/bits/mod.rs");
    let c = driver::check(root, &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let lows = if in_place {
        assert!(fault.is_none());
        let (_, lows) = driver::stage::lower_in_place(&c, root, &opts, oopts).unwrap();
        lows
    } else {
        let (_, _, low) = match fault {
            None => driver::stage::lower_lifted(&c, root, &opts, oopts),
            Some(f) => driver::stage::lower_lifted_with_fault(&c, root, &opts, oopts, f),
        }
        .unwrap();
        vec![low]
    };
    if proof == IP_PROOF && !oopts.exclude_user_rewrites {
        dump_copy(Some(ip_fixture(in_place)), &rt, lows.first().and_then(|l| l.roundtrip_copy.as_ref()).map(|(_, t)| t.as_str()));
    }
    lows
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
            LowerOutcome::Lowered { origin, rung, via, .. } => {
                // user code, never counted as the optimizer's
                assert_eq!(*origin, LowerOrigin::UserRewrite);
                assert_eq!(rung, "Rewrite");
                assert!(via.contains("user-supplied alternative") && via.contains("`crate::proof::at_most_one_bit_is_fast`") && via.contains("crate::bits::at_most_one_bit::rewrite_equiv"), "{via}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!((low.lowered_by(LowerOrigin::Optimizer), low.lowered_by(LowerOrigin::UserRewrite)), (0, 1));
        // the optimizer's own residual is still built and recorded
        let rec = low.records.iter().find(|r| r.function == "crate::bits::at_most_one_bit").unwrap();
        assert!(rec.optimizer_residual.is_some(), "{rec:?}");
        assert!(low.records.iter().filter(|r| r.function != "crate::bits::at_most_one_bit" && r.function != "crate::bits::ones_plus_one").all(|r| r.optimizer_residual.is_none()), "{:?}", low.records);
        let j = low.json().render();
        assert!(j.contains("\"rewritten_by_optimizer\": 0") && j.contains("\"rewritten_by_user_rewrite\": 1") && j.contains("\"origin\": \"user_rewrite\"") && j.contains("\"optimizer_residual\": "), "{j}");
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

/// The evaluation-only option (`OptOptions::exclude_user_rewrites`) builds
/// the optimizer's own output: no user alternative is used, the residual's
/// outcome is still recorded, and the optimizer still runs (its results are
/// there for every function).
#[test]
fn the_evaluation_build_excludes_user_alternatives_but_not_the_optimizer() {
    let oopts = OptOptions { exclude_user_rewrites: true, ..Default::default() };
    for in_place in [true, false] {
        let lows = lower_ip_with(in_place, IP_PROOF, IP_OPT, None, &oopts);
        let low = &lows[0];
        println!("in place {in_place}: {:?}", low.records);
        assert!(low.user_rewrites_excluded);
        assert_eq!(low.lowered_by(LowerOrigin::UserRewrite), 0, "{:?}", low.records);
        assert!(!low.body.contains("at_most_one_bit_fast"), "{}", low.body);
        let rec = low.records.iter().find(|r| r.function == "crate::bits::at_most_one_bit").unwrap();
        assert!(!matches!(rec.outcome, LowerOutcome::Lowered { origin: LowerOrigin::UserRewrite, .. }), "{rec:?}");
        assert!(rec.optimizer_residual.is_some(), "{rec:?}");
        assert!(low.json().render().contains("\"user_rewrites\": \"excluded"));
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
    rejected_by_round_trip(&lows[0], "crate::bits::at_most_one_bit");
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
    for bad in ["#[lift(opt, host, mir = \"bits.sbmir\")]", "#[lift(opt, in_place, mir = \"bits.sbmir\")]"] {
        let mut files = ip_files(false, IP_PROOF, IP_OPT);
        files[0].1 = files[0].1.replace("#[lift(opt, mir = \"bits.sbmir\")]", bad);
        let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        let c = driver::check(Path::new("/host/sandblaster/bits/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(!c.ok() && c.render().contains("`opt` (optimization alternatives) cannot be combined"), "{bad}: {}", c.render());
    }
}
