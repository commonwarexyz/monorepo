//! Compiling the optimized output: the **lowered declaration** of an
//! in-place module (DESIGN.md §2.1, `driver::in_place`,
//! `lift::open::lowered_include`). The host declares
//!
//! ```text
//! pub mod bits {
//!     //! (the leading `//!` lines of bits.rs)
//!     include!(concat!(env!("OUT_DIR"), "/bits-lowered__outer__bits.rs"));
//! }
//! ```
//!
//! and rustc compiles the build's lowered copy of `bits.rs` — exactly the
//! text the lifted round trip checked — while the lift keeps reading
//! `bits.rs` as written. Each property has a positive test and a negative
//! twin: a copy is written for every in-place file on every build; a
//! failed build writes `compile_error!` stubs (never a stale or missing
//! copy); an include of anything else, a wrong copy name, other docs, a
//! source that cannot be included, a stale declaration and a copy included
//! elsewhere are refused; a rewrite the lifted round trip rejects fails the
//! build when the host compiles the copy (and only then); the copies are
//! guarded against edits (watched, written read-only with an old time).
//!
//! Every build that must get past the declaration checks is the real one
//! (`compile_lifted`'s `driver::build_lifted`): the crate is written to a
//! scratch directory with the lock its own gates accepted (`gated_util`),
//! every proof, law and §15 gate is enforced and the lift conformance check
//! compiles a copy of it, so a passing build carries the verdict. A build
//! refused by the declaration checks (which run before any gate) is the
//! same call on an in-memory copy without a lock ([`declared`]).
//!
//! The lifted bodies are rustc's MIR (the fixtures `mir_fixtures/lu_*`); the
//! lifted round trip reads the MIR of its copy (`rt*.sbmir`, extracted from
//! the copy the build wrote, `rt*.rs`: `SANDBLASTER_DUMP_ROUNDTRIP_COPIES=1`
//! writes the copies, `mir_fixtures/extract.py` extracts them). `outer/mod.rs`
//! holds no function, so the tests vary its declaration of `bits` freely.
//!
//! `cargo test --release -p sandblaster-front --test lowered_use`

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use sandblaster_front::driver::lowered::{in_place_fault, LowerFault};
use sandblaster_front::driver::{self, BuildOutcome};
use sandblaster_front::loader::{MemFs, RealFs};
use sandblaster_front::target::TargetInfo;

#[path = "gated_util.rs"]
mod gated;

/// The in-place fault hook is process-wide: every build of this file
/// holds this lock.
static SERIAL: Mutex<()> = Mutex::new(());

const BITS: &str = include_str!("mir_fixtures/lu_nested/src/outer/bits.rs");

const BITS_DOCS: &str = "    //! Bit tests of a byte, the obvious way.\n    //!\n    //! (A second paragraph of docs.)\n";

const OPT: &str = include_str!("mir_fixtures/lu_nested/opt.rs");

const PROOF: &str = r#"//! Optimization lemmas (proven, so they need no human review).
use sandblaster::prelude::*;
use crate::outer::bits::at_most_one_bit;
#[allow(unused_imports)]
use crate::outer::bits::{ones_plus_one, Byte};
use crate::opt::at_most_one_bit_fast;

/// The alternative is the source function (by the 256 cases).
#[lemma]
#[rewrite]
fn at_most_one_bit_is_fast(x: u8) {
    ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));
    by_cases(x, 0..=255);
}

/// By the 256 cases.
#[proof]
fn at_most_one_bit_counts(x: u8) {
    by_cases(x, 0..=255);
}

/// By the 256 cases.
#[proof]
fn ones_plus_one_counts(x: u8) {
    by_cases(x, 0..=255);
}
"#;

/// The laws: each function of `bits.rs` pinned down (the crate is fully
/// specified, so its gates accept a lock and a build carries a verdict).
const LAWS: &str = r#"use sandblaster::prelude::*;
use crate::outer::bits::{at_most_one_bit, ones_plus_one};
#[allow(unused_imports)]
use crate::outer::bits::Byte;

/// `at_most_one_bit` holds exactly when at most one bit of `x` is set.
#[law]
fn at_most_one_bit_counts(x: u8) {
    ensures(at_most_one_bit(x) == (popcount(x as Nat) <= 1));
}

/// `ones_plus_one` is one more than the number of set bits.
#[law]
fn ones_plus_one_counts(x: u8) {
    ensures(ones_plus_one(x) as Nat == popcount(x as Nat) + 1);
}

/// `Byte::new` (internal) wraps its argument.
#[lift_attach(crate::outer::bits::Byte::new)]
fn new_wraps() {
    ensures(|ret: Byte| ret.0 == x);
}
"#;

const ROOT: &str = r#"//! Bit tests verified in place, with an optimization alternative.
#![forbid(unsafe_code)]

#[lift(in_place, children = "bits", mir = "bits.sbmir")]
#[path = "../../src/outer/mod.rs"]
mod outer;

#[lift(opt, mir = "bits.sbmir")]
mod opt;

#[cfg(sandblaster)]
#[lift]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[lift]
#[path = "PROOF.rs"]
mod proof;

pub use outer::bits::{at_most_one_bit, ones_plus_one};
"#;

const COPY: &str = "bits-lowered__outer__bits.rs";

/// The lowered declaration of `bits` (with `docs` inside the block and
/// the copy `file`).
fn lowered_decl(docs: &str, file: &str) -> String {
    format!("pub mod bits {{\n{docs}    include!(concat!(env!(\"OUT_DIR\"), \"/{file}\"));\n}}\n")
}

/// The lowered declaration with its IDE twin: rust-analyzer (which sets
/// `cfg(rust_analyzer)`) analyzes `bits.rs` itself, rustc compiles the copy.
fn with_ide_twin(docs: &str, file: &str) -> String {
    format!("#[cfg(rust_analyzer)]\npub mod bits;\n#[cfg(not(rust_analyzer))]\n{}", lowered_decl(docs, file))
}

/// `src/outer/mod.rs` declaring `bits` by `decl` (no function: its text is
/// not in the MIR's sources).
fn outer(decl: &str) -> String {
    format!("//! The outer module.\n\n{decl}\n/// One.\npub const ONE: u8 = 1;\n")
}

/// The MIR fixtures of this file: the lifted `bits.rs` of each.
const FIXTURES: &[(&str, &str)] = &[
    ("lu_nested", include_str!("mir_fixtures/lu_nested/src/outer/bits.rs")),
    ("lu_nested_line", include_str!("mir_fixtures/lu_nested_line/src/outer/bits.rs")),
    ("lu_nested_mod", include_str!("mir_fixtures/lu_nested_mod/src/outer/bits.rs")),
];

/// A fixture file (`tests/mir_fixtures/<path>`), when it exists.
fn fixture(path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures").join(path)).ok()
}

/// `files` with rustc's MIR of fixture `dir` beside the DSL root
/// (`bits.sbmir`) and the MIR of the round trip's copy of scenario `rt`
/// (`bits.roundtrip__<module>.sbmir`) when it is extracted.
fn with_mir(mut files: Vec<(String, String)>, dir: &str, module: &str, rt: &str) -> Vec<(String, String)> {
    files.push(("/host/sandblaster/bits/bits.sbmir".into(), fixture(&format!("{dir}/bits.sbmir")).expect("the fixture's MIR")));
    if let Some(m) = fixture(&format!("{dir}/{rt}.sbmir")) {
        files.push((format!("/host/sandblaster/bits/bits.roundtrip__{module}.sbmir"), m));
    }
    files
}

/// With `SANDBLASTER_DUMP_ROUNDTRIP_COPIES` set: writes the round trip's
/// copy a build wrote (`OUT_DIR/bits-roundtrip__<module>.rs`) into fixture
/// `dir` as `<rt>.rs`.
fn dump_copy(o: &BuildOutcome, dir: &str, module: &str, rt: &str) {
    if std::env::var_os("SANDBLASTER_DUMP_ROUNDTRIP_COPIES").is_none() {
        return;
    }
    let want = format!("bits-roundtrip__{module}.rs");
    if let Some((_, t)) = o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == want.as_str())) {
        std::fs::write(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/mir_fixtures").join(dir).join(format!("{rt}.rs")), t).unwrap();
    }
}

fn files(outer_text: &str, bits: &str) -> Vec<(String, String)> {
    files_rt(outer_text, bits, "rt")
}

/// [`files`] with the round trip's MIR of scenario `rt`.
fn files_rt(outer_text: &str, bits: &str, rt: &str) -> Vec<(String, String)> {
    let dir = FIXTURES.iter().find(|(_, s)| *s == bits).map(|(d, _)| *d).expect("a fixture of this `bits.rs`");
    let f = vec![
        ("/host/sandblaster/bits/mod.rs".into(), ROOT.into()),
        ("/host/sandblaster/bits/opt.rs".into(), OPT.into()),
        ("/host/sandblaster/bits/PROOF.rs".into(), PROOF.into()),
        ("/host/src/lib.rs".into(), "//! A host crate.\nmod outer;\npub fn f(x: u8) -> bool { outer::bits::at_most_one_bit(x) }\n".into()),
        ("/host/src/outer/mod.rs".into(), outer_text.into()),
        ("/host/src/outer/bits.rs".into(), bits.into()),
        ("/host/sandblaster/bits/LAWS.rs".into(), LAWS.into()),
    ];
    with_mir(f, dir, "outer__bits", rt)
}

/// The build environment of a host crate at `manifest` writing to `out`
/// (`RUSTC` and `CARGO` passed through for the lift conformance check).
fn env_of(manifest: &str, out: &str) -> impl Fn(&str) -> Option<String> + use<> {
    let (manifest, out) = (manifest.to_string(), out.to_string());
    move |k: &str| match k {
        "CARGO_MANIFEST_DIR" => Some(manifest.clone()),
        "OUT_DIR" => Some(out.clone()),
        "CARGO_CFG_TARGET_ARCH" => Some("aarch64".into()),
        "CARGO_CFG_TARGET_FEATURE" => Some("neon".into()),
        "CARGO_CFG_TARGET_ENDIAN" => Some("little".into()),
        "CARGO_CFG_TARGET_POINTER_WIDTH" => Some("64".into()),
        "RUSTC" | "CARGO" => std::env::var(k).ok(),
        _ => None,
    }
}

/// The host crate's manifest (its own workspace, no dependencies).
const MANIFEST: &str = "[package]\nname = \"lu-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n";

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

/// The real in-place build (module docs) of `files` (paths under
/// `/host/`), with the printer fault `fault` injected into its lowering:
/// the crate is written to a fresh scratch directory with the lock its own
/// gates accept and built from disk. When the gates do not accept a lock
/// (a proof that fails), it is built without one, so it fails and writes
/// its stubs; the reason is at the start of `stderr`.
fn build_with(files: &[(String, String)], fault: Option<LowerFault>) -> BuildOutcome {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("sandblaster-lowered-use-build-{}-{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&dir);
    let host = dir.join("host");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let mut abs: Vec<(String, String)> = files.iter().map(|(p, t)| (dir.join(p.trim_start_matches('/')).display().to_string(), t.clone())).collect();
    abs.push((host.join("Cargo.toml").display().to_string(), MANIFEST.into()));
    let env = env_of(&host.display().to_string(), &out.display().to_string());
    let target = TargetInfo::from_cargo_env(&env).expect("target");
    let root = host.join("sandblaster/bits/mod.rs").display().to_string();
    let (abs, refused_lock) = match gated::with_accepted_lock(&abs, &root, &target) {
        Ok(with_lock) => (with_lock, String::new()),
        Err(e) => (abs, format!("the gates accept no lock:\n{e}\n")),
    };
    for (p, t) in &abs {
        let f = Path::new(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, t).unwrap();
    }
    in_place_fault::set(fault);
    let mut o = driver::build_lifted("sandblaster/bits/mod.rs", "bits", None, &env, &RealFs);
    in_place_fault::set(None);
    o.stderr.insert_str(0, &refused_lock);
    let _ = std::fs::remove_dir_all(&dir);
    o
}

fn build(files: &[(String, String)]) -> BuildOutcome {
    build_with(files, None)
}

/// The same build of an in-memory copy without a lock, for a crate the
/// declaration checks refuse (they run before any gate).
fn declared(files: &[(String, String)]) -> BuildOutcome {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let o = driver::build_lifted("sandblaster/bits/mod.rs", "bits", None, &env_of("/host", "/out"), &fs);
    assert!(!o.cargo.iter().any(|l| l.contains("verified in place")), "a declaration refusal never reaches a verdict");
    o
}

/// The output file `name` of a build (`OUT_DIR/<name>`).
fn output<'a>(o: &'a BuildOutcome, name: &str) -> &'a str {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, t)| t.as_str()).unwrap_or_else(|| panic!("no output `{name}`: {:?}", o.outputs.iter().map(|(p, _)| p).collect::<Vec<_>>()))
}

#[track_caller]
fn refused(o: &BuildOutcome, needle: &str) {
    assert!(!o.ok, "the build must fail ({needle})");
    assert!(o.stderr.contains(needle), "expected {needle:?} in:\n{}", o.stderr);
}

/// Compiles the copy exactly as the host does — `include!(concat!(env!(
/// "OUT_DIR"), ..))` with `OUT_DIR` set — beside the original source, and
/// runs both on every byte.
fn rustc_ab(copy: &str) -> String {
    let dir = std::env::temp_dir().join(format!("sandblaster-lowered-use-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out")).unwrap();
    std::fs::write(dir.join("out").join(COPY), copy).unwrap();
    std::fs::write(dir.join("orig.rs"), BITS).unwrap();
    let main = format!(
        "#![deny(warnings)]\n#[allow(dead_code)]\nmod orig;\n#[allow(dead_code)]\n{}fn main() {{\n    for x in 0..=255u8 {{\n        assert_eq!(orig::at_most_one_bit(x), bits::at_most_one_bit(x));\n        assert_eq!(orig::ones_plus_one(x), bits::ones_plus_one(x));\n    }}\n    println!(\"agree\");\n}}\n",
        with_ide_twin(BITS_DOCS, COPY)
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    // the IDE's view (`--cfg rust_analyzer`) is the source itself
    std::fs::write(dir.join("bits.rs"), BITS).unwrap();
    let ide = std::process::Command::new("rustc").env("OUT_DIR", dir.join("missing")).args(["--edition", "2024", "--cfg", "rust_analyzer", "-o"]).arg(dir.join("ab-ide")).arg(dir.join("main.rs")).output().expect("rustc");
    assert!(ide.status.success(), "the IDE twin compiles bits.rs:\n{}", String::from_utf8_lossy(&ide.stderr));
    let o = std::process::Command::new("rustc")
        .env("OUT_DIR", dir.join("out"))
        .args(["--edition", "2024", "-O", "-C", "overflow-checks=on", "-o"])
        .arg(dir.join("ab"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(o.status.success(), "rustc rejects the lowered declaration:\n{}", String::from_utf8_lossy(&o.stderr));
    let r = std::process::Command::new(dir.join("ab")).output().expect("run");
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    // a missing copy does not compile (the include never falls back)
    std::fs::remove_file(dir.join("out").join(COPY)).unwrap();
    let missing = std::process::Command::new("rustc").env("OUT_DIR", dir.join("out")).args(["--edition", "2024", "-o"]).arg(dir.join("ab2")).arg(dir.join("main.rs")).output().expect("rustc");
    assert!(!missing.status.success(), "a missing copy must not compile");
    let _ = std::fs::remove_dir_all(&dir);
    String::from_utf8_lossy(&r.stdout).to_string()
}

/// The positive test: the build writes the checked copy with an honest
/// header, rustc compiles it through the lowered declaration, and it
/// agrees with the source on every byte. The other in-place file
/// (`outer/mod.rs`, declared plainly) gets its copy too — the source as
/// is, marked not compiled — so any in-place file can switch.
#[test]
fn the_lowered_declaration_compiles_the_checked_copy() {
    let o = build(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS));
    dump_copy(&o, "lu_nested", "outer__bits", "rt");
    assert!(o.ok, "{}", o.stderr);
    let copy = output(&o, COPY);
    println!("{copy}");
    assert!(copy.starts_with("// @generated by sandblaster from `") && copy.lines().next().unwrap().ends_with("/host/sandblaster/bits/mod.rs`. Do not edit: edit `src/outer/bits.rs`, the verified source (the build rewrites this file)."), "{copy}");
    assert!(copy.contains("// STATUS: VERIFIED + LIFTED IN PLACE + USER REWRITES\n"), "{copy}");
    assert!(copy.contains("// COMPILED: rustc compiles this file as the module declared in `src/outer/mod.rs`, in place of `src/outer/bits.rs`."), "{copy}");
    assert!(copy.contains("//   rewritten by user code: `crate::outer::bits::at_most_one_bit` (not optimizer output;"), "{copy}");
    assert!(copy.contains("pub fn at_most_one_bit(x: u8) -> bool {\n    __sandblaster_opt_at_most_one_bit_fast(x)\n}"), "{copy}");
    assert!(copy.contains("fn __sandblaster_opt_at_most_one_bit_fast(x: u8) -> bool {\n    x & x.wrapping_sub(1) == 0\n}"), "{copy}");
    assert!(!copy.lines().any(|l| l.starts_with("//!")), "the declaration carries the docs: {copy}");
    // the shipped code's theorems (docs/checked-structuring.md step 8): the
    // helper's and the copy's MIR against the definitions the round trip
    // compared them with, and the copy's against the source function
    assert!(output(&o, "bits-report.json").contains("`crate::outer::bits::at_most_one_bit`: 3 theorem(s) of the shipped MIR (1 against the source function)"), "{}", output(&o, "bits-report.json"));
    // a kept function whose reason mentions the round trip without being
    // its rejection does not fail the build
    assert!(output(&o, "bits-report.json").contains("its signature names `Self` (the round trip's copy is a free function)"));
    // the other in-place file has its copy too, not compiled (it carries
    // the lowered declaration of `bits` as written)
    let other = output(&o, "bits-lowered__outer__mod.rs");
    assert!(other.contains("// NOT COMPILED: the host compiles `src/outer/mod.rs` as written") && other.contains(&lowered_decl(BITS_DOCS, COPY)), "{other}");
    // the index, the verified record, the guard
    let index = output(&o, "bits-lowered.txt");
    assert!(index.starts_with("VERIFIED + LIFTED IN PLACE + USER REWRITES\n") && index.contains(&format!("{COPY} sha256 ")) && index.contains("compiled by rustc"), "{index}");
    let record = output(&o, "bits-verified.txt");
    assert!(record.contains("// Lowered copies (`OUT_DIR/bits-lowered.txt`):\n//   VERIFIED + LIFTED IN PLACE + USER REWRITES"), "{record}");
    for f in [COPY, "bits-lowered__outer__mod.rs"] {
        let p = o.guarded.iter().find(|p| p.ends_with(f)).unwrap_or_else(|| panic!("{f} is guarded"));
        assert!(o.cargo.contains(&format!("cargo::rerun-if-changed={}", p.display())), "{f} is watched: {:?}", o.cargo);
    }
    assert!(!o.guarded.iter().any(|p| p.ends_with("bits-lowered.txt") || p.ends_with("bits-verified.txt")), "only the copies are guarded");
    assert!(rustc_ab(copy).contains("agree"));
}

/// Attribution (DESIGN.md principle 3, §2.1): the rewrite of
/// `at_most_one_bit` comes from a user-supplied `#[rewrite]` alternative
/// (`at_most_one_bit_fast`), so the build summary, the lowered-copy index
/// header and the report JSON count it as user code — never as an optimizer
/// residual — and the optimizer's own residual for it is still built and
/// recorded. The negative twin: the evaluation-only build
/// (`SANDBLASTER_EVAL_EXCLUDE_USER_REWRITES=1`) leaves the alternative out
/// while the optimizer still runs.
#[test]
fn user_alternatives_are_attributed_apart_from_the_optimizer() {
    let o = build(&files(&outer("pub mod bits;\n"), BITS));
    assert!(o.ok, "{}", o.stderr);
    let counts = "rewritten functions: optimizer residuals: 0; user-supplied `#[rewrite]` alternatives (user code, not optimizer output): 1 (`crate::outer::bits::at_most_one_bit`)";
    // the build summary
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::warning=sandblaster: `bits` verified in place") && l.contains(&counts.replace("rewritten functions:", "rewritten functions in the lowered copies:"))), "{:?}", o.cargo);
    // the lowered-copy index header, and the copy's own header
    let index = output(&o, "bits-lowered.txt");
    assert!(index.contains(&format!("\n{counts}\n")), "{index}");
    assert!(index.contains("rewritten by user code: `crate::outer::bits::at_most_one_bit` (not optimizer output;") && !index.contains("rewritten: `crate::outer::bits::at_most_one_bit`"), "{index}");
    assert!(!index.contains("rewritten to their optimizer replacements") && !index.contains("rewritten to their residuals"), "{index}");
    let copy = output(&o, COPY);
    assert!(copy.contains("//   rewritten by user code: `crate::outer::bits::at_most_one_bit`") && !copy.contains("//   rewritten: `"), "{copy}");
    // the report JSON, with the residual's own outcome
    let report = output(&o, "bits-report.json");
    assert!(report.contains("\"rewritten_by_optimizer\": 0") && report.contains("\"rewritten_by_user_rewrite\": 1") && report.contains("\"origin\": \"user_rewrite\""), "{report}");
    assert!(report.contains("\"optimizer_residual\": \""), "the optimizer's residual for the function is recorded: {report}");
    assert!(!report.contains("\"origin\": \"optimizer\""), "{report}");
}

/// The IDE twin (`#[cfg(rust_analyzer)] pub mod bits;` beside the lowered
/// declaration under `#[cfg(not(rust_analyzer))]`) is the same declaration
/// to the lift and the build; one without the other is refused.
#[test]
fn the_ide_twin_is_the_same_declaration() {
    let o = build(&files(&outer(&with_ide_twin(BITS_DOCS, COPY)), BITS));
    assert!(o.ok, "{}", o.stderr);
    assert!(output(&o, COPY).contains("// COMPILED: rustc compiles this file"));
    assert!(o.cargo.contains(&"cargo::rustc-check-cfg=cfg(rust_analyzer)".to_string()), "{:?}", o.cargo);
    let no_cfg = format!("#[cfg(rust_analyzer)]\npub mod bits;\n{}", lowered_decl(BITS_DOCS, COPY));
    refused(&declared(&files(&outer(&no_cfg), BITS)), "only the IDE twin `#[cfg(rust_analyzer)] mod bits;` may accompany it");
    let no_twin = format!("#[cfg(not(rust_analyzer))]\n{}", lowered_decl(BITS_DOCS, COPY));
    refused(&declared(&files(&outer(&no_twin), BITS)), "it needs its IDE twin");
}

/// Negative twin of fail-closed: the same rewrite rejected by the lifted
/// round trip (a wrong copy of the alternative) fails the build when the
/// host compiles the copy, and every copy is a `compile_error!` stub; with
/// the plain declaration the build passes and the function keeps its
/// source text (the verified source, not a fallback).
#[test]
fn a_rewrite_the_round_trip_rejects_fails_the_build_that_compiles_the_copy() {
    let o = build_with(&files_rt(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS, "rt_WrongAlternative"), Some(LowerFault::WrongAlternative));
    dump_copy(&o, "lu_nested", "outer__bits", "rt_WrongAlternative");
    refused(&o, "compiles `src/outer/bits.rs` from its lowered copy, but the lifted round trip rejected the rewrite of `crate::outer::bits::at_most_one_bit`");
    for f in [COPY, "bits-lowered__outer__mod.rs"] {
        let t = output(&o, f);
        assert!(t.contains("::core::compile_error!(\"sandblaster: the build of `bits` failed") && !t.contains("pub fn"), "{t}");
    }
    assert!(!o.outputs.iter().any(|(p, c)| p.ends_with("bits-verified.txt") && c.contains("VERIFIED +")), "no verified record");
    assert!(o.outputs.iter().any(|(p, c)| p.ends_with("bits-verdict.key") && c.is_empty()), "the verdict key is cleared");
    let plain = build_with(&files_rt(&outer("pub mod bits;\n"), BITS, "rt_WrongAlternative"), Some(LowerFault::WrongAlternative));
    assert!(plain.ok, "{}", plain.stderr);
    let copy = output(&plain, COPY);
    assert!(copy.contains("// NOT COMPILED") && copy.contains("nothing was cheaper") && !copy.contains("rewritten:"), "{copy}");
    // nothing rewritten: the source byte for byte after its docs
    assert!(copy.ends_with(driver::lifted::split_docs(BITS).1), "{copy}");
}

/// Negative twin of the shipped code's theorem: when the MIR the build
/// ships is not the code the round trip compared (one constant of the
/// helper's MIR, in the literal reading only), its theorem fails and the
/// rewrite is rejected, so the build that compiles the copy fails.
#[test]
fn a_shipped_mir_that_is_not_the_compared_code_fails_its_theorem() {
    let o = build_with(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS), Some(LowerFault::ShippedMir));
    refused(&o, "the lifted round trip rejected the rewrite of `crate::outer::bits::at_most_one_bit`");
    assert!(o.stderr.contains("the shipped code's theorem"), "{}", o.stderr);
}

/// A failed proof fails the build and writes stubs: rustc never compiles a
/// copy of a failed build, and the include never dangles or finds a stale
/// copy. (The proof that fails: the rewrite lemma, stated wrongly.)
#[test]
fn a_failed_proof_writes_compile_error_stubs() {
    let mut f = files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS);
    f[2].1 = PROOF.replace("ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));", "ensures(at_most_one_bit(x) != at_most_one_bit_fast(x));");
    let o = build(&f);
    assert!(!o.ok, "a failed proof fails the build");
    assert!(o.stderr.starts_with("the gates accept no lock") && o.stderr.contains("at_most_one_bit_is_fast"), "{}", o.stderr);
    let t = output(&o, COPY);
    assert!(t.contains("::core::compile_error!("), "{t}");
    assert!(output(&o, "bits-lowered.txt").contains(&format!("{COPY}: FAILED BUILD")));
}

/// An include of anything but the lowered copy is refused: an arbitrary
/// file for the lifted child, the copy of another file, an extra item or
/// attribute, and an include in any other inline module of a lifted file.
#[test]
fn an_include_of_anything_else_is_refused() {
    let arbitrary = "pub mod bits {\n    include!(\"fast_bits.rs\");\n}\n";
    refused(&declared(&files(&outer(arbitrary), BITS)), "declared inline with an `include!` that is not its lowered declaration");
    let from_src = "pub mod bits {\n    include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/outer/fast.rs\"));\n}\n";
    refused(&declared(&files(&outer(from_src), BITS)), "not its lowered declaration");
    refused(&declared(&files(&outer(&lowered_decl(BITS_DOCS, "bits-lowered__outer__mod.rs")), BITS)), "which is not the lowered copy of");
    let extra = format!("pub mod bits {{\n{BITS_DOCS}    include!(concat!(env!(\"OUT_DIR\"), \"/{COPY}\"));\n    pub fn evil() {{}}\n}}\n");
    refused(&declared(&files(&outer(&extra), BITS)), "only item is the `include!` of the copy");
    let attr = format!("#[cfg(any())]\n{}", lowered_decl(BITS_DOCS, COPY));
    refused(&declared(&files(&outer(&attr), BITS)), "carries only doc comments");
    let inline_body = "pub mod bits {\n    pub fn at_most_one_bit(x: u8) -> bool { true }\n}\n";
    refused(&declared(&files(&outer(inline_body), BITS)), "is declared inline");
    let other_module = format!("{}\nmod extra {{\n    include!(concat!(env!(\"OUT_DIR\"), \"/evil.rs\"));\n}}\n", lowered_decl(BITS_DOCS, COPY));
    refused(&declared(&files(&outer(&other_module), BITS)), "macro `include!` is not defined");
}

/// The copy's name is this build's (another record's copy with the right
/// path is refused by the build), and the docs are the source's.
#[test]
fn the_name_and_the_docs_are_checked() {
    refused(&declared(&files(&outer(&lowered_decl(BITS_DOCS, "other-lowered__outer__bits.rs")), BITS)), "that this build (`bits`) writes is `OUT_DIR/bits-lowered__outer__bits.rs`");
    let fewer = "    //! Bit tests of a byte, the obvious way.\n";
    refused(&declared(&files(&outer(&lowered_decl(fewer, COPY)), BITS)), "must carry exactly the leading `//!` lines of `src/outer/bits.rs`");
    let changed = BITS_DOCS.replace("obvious", "fast");
    refused(&declared(&files(&outer(&lowered_decl(&changed, COPY)), BITS)), "the first difference is at line 1");
    refused(&declared(&files(&outer(&lowered_decl("", COPY)), BITS)), "expected 3 doc line(s), found 0");
}

/// A source whose meaning depends on the file it is in cannot be compiled
/// from a copy: `line!` (even in a test item the lift drops), an
/// out-of-line module.
#[test]
fn a_source_that_cannot_be_included_is_refused() {
    let with_line = format!("{BITS}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn l() {{\n        assert!(line!() > 0);\n    }}\n}}\n");
    assert_eq!(with_line, include_str!("mir_fixtures/lu_nested_line/src/outer/bits.rs"));
    refused(&declared(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), &with_line)), "it uses `line!`");
    let with_mod = format!("{BITS}\n#[cfg(test)]\nmod tests;\n");
    assert_eq!(with_mod, include_str!("mir_fixtures/lu_nested_mod/src/outer/bits.rs"));
    refused(&declared(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), &with_mod)), "out-of-line module `mod tests;`");
    // the twin: the same sources declared plainly build
    assert!(build(&files(&outer("pub mod bits;\n"), &with_line)).ok);
}

/// Only the declaring file includes a copy, once: a stale declaration (a
/// file this build does not lift, whose copy would be an old build's) and
/// a copy included elsewhere are refused.
#[test]
fn stale_and_extra_mentions_are_refused() {
    let mut f = files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS);
    f[3].1.push_str("mod gone {\n    include!(concat!(env!(\"OUT_DIR\"), \"/bits-lowered__gone.rs\"));\n}\n");
    refused(&declared(&f), "`src/lib.rs` mentions a lowered copy of `bits`");
    let mut f = files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS);
    f.push(("/host/src/again.rs".into(), format!("include!(concat!(env!(\"OUT_DIR\"), \"/{COPY}\"));\n")));
    refused(&declared(&f), "`src/again.rs` mentions a lowered copy of `bits`");
}

/// A top-level in-place file (declared in host code the lift does not
/// read) uses the same declaration, checked by the build.
#[test]
fn a_top_level_in_place_file_uses_the_same_declaration() {
    let root = ROOT.replace("#[lift(in_place, children = \"bits\", mir = \"bits.sbmir\")]\n#[path = \"../../src/outer/mod.rs\"]\nmod outer;", "#[lift(in_place, mir = \"bits.sbmir\")]\n#[path = \"../../src/bits.rs\"]\nmod bits;").replace("pub use outer::bits::", "pub use bits::");
    let proof = PROOF.replace("crate::outer::bits::", "crate::bits::");
    let laws = LAWS.replace("crate::outer::bits::", "crate::bits::");
    let lib = |decl: &str| format!("//! A host crate.\n{decl}pub fn f(x: u8) -> bool {{ bits::at_most_one_bit(x) }}\n");
    let mk = |lib_text: String| -> Vec<(String, String)> {
        with_mir(
            vec![
                ("/host/sandblaster/bits/mod.rs".into(), root.clone()),
                ("/host/sandblaster/bits/opt.rs".into(), OPT.into()),
                ("/host/sandblaster/bits/PROOF.rs".into(), proof.clone()),
                ("/host/src/lib.rs".into(), lib_text),
                ("/host/src/bits.rs".into(), BITS.into()),
                ("/host/sandblaster/bits/LAWS.rs".into(), laws.clone()),
            ],
            "lu_top",
            "bits",
            "rt",
        )
    };
    let o = build(&mk(lib(&lowered_decl(BITS_DOCS, "bits-lowered__bits.rs"))));
    dump_copy(&o, "lu_top", "bits", "rt");
    assert!(o.ok, "{}", o.stderr);
    let copy = output(&o, "bits-lowered__bits.rs");
    assert!(copy.contains("// COMPILED: rustc compiles this file as the module declared in `src/lib.rs`") && copy.contains("__sandblaster_opt_at_most_one_bit_fast(x)"), "{copy}");
    refused(&declared(&mk(lib("pub mod bits {\n    include!(\"bits_fast.rs\");\n}\n"))), "includes something other than its lowered copy");
    refused(&declared(&mk(lib(&lowered_decl(BITS_DOCS, "bits-lowered__outer__bits.rs")))), "that this build (`bits`) writes is `OUT_DIR/bits-lowered__bits.rs`");
}

/// The lowered declaration outside a lifted child's parent: a host module
/// of a lifted file (as `mod x;` would be), listed, not an error.
#[test]
fn a_lowered_declaration_of_a_host_module_is_a_host_module() {
    let root = ROOT.replace(", children = \"bits\"", "").replace("pub use outer::bits::{at_most_one_bit, ones_plus_one};", "pub use outer::ONE;");
    let f: Vec<(String, String)> = with_mir(
        vec![
            ("/host/sandblaster/bits/mod.rs".into(), root.replace("#[lift(opt, mir = \"bits.sbmir\")]\nmod opt;\n", "").replace("#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n", "").replace("#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n", "")),
            ("/host/src/lib.rs".into(), "mod outer;\n".into()),
            ("/host/src/outer/mod.rs".into(), outer(&lowered_decl(BITS_DOCS, "other-lowered__outer__bits.rs"))),
            ("/host/src/outer/bits.rs".into(), BITS.into()),
        ],
        "lu_hostmod",
        "outer",
        "rt",
    );
    let fs = MemFs::from_files(f.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("/host/sandblaster/bits/mod.rs"), &fs, &sandblaster_front::target::TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    assert!(c.lift_facts.dropped.iter().any(|d| d.what == "module `bits`"), "{:?}", c.lift_facts.dropped.iter().map(|d| &d.what).collect::<Vec<_>>());
}
