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
//! The lifted bodies are rustc's MIR (the fixtures `mir_fixtures/lu_*`); the
//! lifted round trip reads the MIR of its copy (`rt*.sbmir`, extracted from
//! the copy the build wrote, `rt*.rs`: `SANDBLASTER_DUMP_ROUNDTRIP_COPIES=1`
//! writes the copies, `mir_fixtures/extract.py` extracts them). `outer/mod.rs`
//! holds no function, so the tests vary its declaration of `bits` freely.
//!
//! `cargo test --release -p sandblaster-front --test lowered_use`

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sandblaster_front::driver::lowered::{in_place_fault, LowerFault};
use sandblaster_front::driver::{self, BuildOutcome, GateUse};
use sandblaster_front::loader::MemFs;

/// The in-place fault hook is process-wide: every build of this file
/// holds this lock.
static SERIAL: Mutex<()> = Mutex::new(());

const BITS: &str = include_str!("mir_fixtures/lu_nested/src/outer/bits.rs");

const BITS_DOCS: &str = "    //! Bit tests of a byte, the obvious way.\n    //!\n    //! (A second paragraph of docs.)\n";

const OPT: &str = include_str!("mir_fixtures/lu_nested/opt.rs");

const PROOF: &str = r#"//! Optimization lemmas (proven, so they need no human review).
use sandblaster::prelude::*;
use crate::outer::bits::at_most_one_bit;
use crate::opt::at_most_one_bit_fast;

/// The alternative is the source function (by the 256 cases).
#[lemma]
#[rewrite]
fn at_most_one_bit_is_fast(x: u8) {
    ensures(at_most_one_bit(x) == at_most_one_bit_fast(x));
    by_cases(x, 0..=255);
}
"#;

const ROOT: &str = r#"//! Bit tests verified in place, with an optimization alternative.
#![forbid(unsafe_code)]

#[lift(in_place, children = "bits", mir = "bits.sbmir")]
#[path = "../../src/outer/mod.rs"]
pub mod outer;

#[lift(opt, mir = "bits.sbmir")]
mod opt;

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
    if let Some((_, t)) = o.outputs.iter().find(|(p, _)| p == &PathBuf::from("/out").join(format!("bits-roundtrip__{module}.rs"))) {
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
    ];
    with_mir(f, dir, "outer__bits", rt)
}

fn env(k: &str) -> Option<String> {
    match k {
        "CARGO_MANIFEST_DIR" => Some("/host".into()),
        "OUT_DIR" => Some("/out".into()),
        "CARGO_CFG_TARGET_ARCH" => Some("aarch64".into()),
        "CARGO_CFG_TARGET_FEATURE" => Some("neon".into()),
        "CARGO_CFG_TARGET_ENDIAN" => Some("little".into()),
        "CARGO_CFG_TARGET_POINTER_WIDTH" => Some("64".into()),
        _ => None,
    }
}

fn build_with(files: &[(String, String)], fault: Option<LowerFault>) -> BuildOutcome {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    in_place_fault::set(fault);
    let o = driver::build_lifted_with("sandblaster/bits/mod.rs", "bits", None, &env, &fs, GateUse::Pending);
    in_place_fault::set(None);
    o
}

fn build(files: &[(String, String)]) -> BuildOutcome {
    build_with(files, None)
}

fn output<'a>(o: &'a BuildOutcome, name: &str) -> &'a str {
    o.outputs.iter().find(|(p, _)| p == &PathBuf::from("/out").join(name)).map(|(_, t)| t.as_str()).unwrap_or_else(|| panic!("no output `{name}`: {:?}", o.outputs.iter().map(|(p, _)| p).collect::<Vec<_>>()))
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
    assert!(copy.starts_with("// @generated by sandblaster from `/host/sandblaster/bits/mod.rs`. Do not edit: edit `src/outer/bits.rs`"), "{copy}");
    assert!(copy.contains("// STATUS: NOT VERIFIED — DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING\n"), "{copy}");
    assert!(copy.contains("each rests on a kernel-checked link to the source\n//   function and on the lifted round trip, which ran in this build"), "{copy}");
    assert!(copy.contains("// COMPILED: rustc compiles this file as the module declared in `src/outer/mod.rs`, in place of `src/outer/bits.rs`."), "{copy}");
    assert!(copy.contains("//   rewritten: `crate::outer::bits::at_most_one_bit` (rung Rewrite;"), "{copy}");
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
    // the index, the pending record, the guard
    let index = output(&o, "bits-lowered.txt");
    assert!(index.starts_with("NOT VERIFIED — DEVELOPMENT BUILD") && index.contains(&format!("{COPY} sha256 ")) && index.contains("compiled by rustc"), "{index}");
    assert!(output(&o, "bits-pending.txt").contains("lowered copies (OUT_DIR/bits-lowered.txt):"));
    for f in [COPY, "bits-lowered__outer__mod.rs"] {
        let p = PathBuf::from("/out").join(f);
        assert!(o.guarded.contains(&p), "{f} is guarded");
        assert!(o.cargo.contains(&format!("cargo::rerun-if-changed={}", p.display())), "{f} is watched: {:?}", o.cargo);
    }
    assert!(!o.guarded.iter().any(|p| p.ends_with("bits-lowered.txt") || p.ends_with("bits-pending.txt")), "only the copies are guarded");
    assert!(rustc_ab(copy).contains("agree"));
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
    refused(&build(&files(&outer(&no_cfg), BITS)), "only the IDE twin `#[cfg(rust_analyzer)] mod bits;` may accompany it");
    let no_twin = format!("#[cfg(not(rust_analyzer))]\n{}", lowered_decl(BITS_DOCS, COPY));
    refused(&build(&files(&outer(&no_twin), BITS)), "it needs its IDE twin");
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
    assert!(output(&o, "bits-pending.txt").contains("BUILD FAILED:"));
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
    assert!(!o.ok, "an unproven overflow fails the build");
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
    refused(&build(&files(&outer(arbitrary), BITS)), "declared inline with an `include!` that is not its lowered declaration");
    let from_src = "pub mod bits {\n    include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/outer/fast.rs\"));\n}\n";
    refused(&build(&files(&outer(from_src), BITS)), "not its lowered declaration");
    refused(&build(&files(&outer(&lowered_decl(BITS_DOCS, "bits-lowered__outer__mod.rs")), BITS)), "which is not the lowered copy of");
    let extra = format!("pub mod bits {{\n{BITS_DOCS}    include!(concat!(env!(\"OUT_DIR\"), \"/{COPY}\"));\n    pub fn evil() {{}}\n}}\n");
    refused(&build(&files(&outer(&extra), BITS)), "only item is the `include!` of the copy");
    let attr = format!("#[cfg(any())]\n{}", lowered_decl(BITS_DOCS, COPY));
    refused(&build(&files(&outer(&attr), BITS)), "carries only doc comments");
    let inline_body = "pub mod bits {\n    pub fn at_most_one_bit(x: u8) -> bool { true }\n}\n";
    refused(&build(&files(&outer(inline_body), BITS)), "is declared inline");
    let other_module = format!("{}\nmod extra {{\n    include!(concat!(env!(\"OUT_DIR\"), \"/evil.rs\"));\n}}\n", lowered_decl(BITS_DOCS, COPY));
    refused(&build(&files(&outer(&other_module), BITS)), "macro `include!` is not defined");
}

/// The copy's name is this build's (another record's copy with the right
/// path is refused by the build), and the docs are the source's.
#[test]
fn the_name_and_the_docs_are_checked() {
    refused(&build(&files(&outer(&lowered_decl(BITS_DOCS, "other-lowered__outer__bits.rs")), BITS)), "that this build (`bits`) writes is `OUT_DIR/bits-lowered__outer__bits.rs`");
    let fewer = "    //! Bit tests of a byte, the obvious way.\n";
    refused(&build(&files(&outer(&lowered_decl(fewer, COPY)), BITS)), "must carry exactly the leading `//!` lines of `src/outer/bits.rs`");
    let changed = BITS_DOCS.replace("obvious", "fast");
    refused(&build(&files(&outer(&lowered_decl(&changed, COPY)), BITS)), "the first difference is at line 1");
    refused(&build(&files(&outer(&lowered_decl("", COPY)), BITS)), "expected 3 doc line(s), found 0");
}

/// A source whose meaning depends on the file it is in cannot be compiled
/// from a copy: `line!` (even in a test item the lift drops), an
/// out-of-line module.
#[test]
fn a_source_that_cannot_be_included_is_refused() {
    let with_line = format!("{BITS}\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn l() {{\n        assert!(line!() > 0);\n    }}\n}}\n");
    assert_eq!(with_line, include_str!("mir_fixtures/lu_nested_line/src/outer/bits.rs"));
    refused(&build(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), &with_line)), "it uses `line!`");
    let with_mod = format!("{BITS}\n#[cfg(test)]\nmod tests;\n");
    assert_eq!(with_mod, include_str!("mir_fixtures/lu_nested_mod/src/outer/bits.rs"));
    refused(&build(&files(&outer(&lowered_decl(BITS_DOCS, COPY)), &with_mod)), "out-of-line module `mod tests;`");
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
    refused(&build(&f), "`src/lib.rs` mentions a lowered copy of `bits`");
    let mut f = files(&outer(&lowered_decl(BITS_DOCS, COPY)), BITS);
    f.push(("/host/src/again.rs".into(), format!("include!(concat!(env!(\"OUT_DIR\"), \"/{COPY}\"));\n")));
    refused(&build(&f), "`src/again.rs` mentions a lowered copy of `bits`");
}

/// A top-level in-place file (declared in host code the lift does not
/// read) uses the same declaration, checked by the build.
#[test]
fn a_top_level_in_place_file_uses_the_same_declaration() {
    let root = ROOT.replace("#[lift(in_place, children = \"bits\", mir = \"bits.sbmir\")]\n#[path = \"../../src/outer/mod.rs\"]\npub mod outer;", "#[lift(in_place, mir = \"bits.sbmir\")]\n#[path = \"../../src/bits.rs\"]\npub mod bits;").replace("pub use outer::bits::", "pub use bits::");
    let proof = PROOF.replace("crate::outer::bits::", "crate::bits::");
    let lib = |decl: &str| format!("//! A host crate.\n{decl}pub fn f(x: u8) -> bool {{ bits::at_most_one_bit(x) }}\n");
    let mk = |lib_text: String| -> Vec<(String, String)> {
        with_mir(
            vec![
                ("/host/sandblaster/bits/mod.rs".into(), root.clone()),
                ("/host/sandblaster/bits/opt.rs".into(), OPT.into()),
                ("/host/sandblaster/bits/PROOF.rs".into(), proof.clone()),
                ("/host/src/lib.rs".into(), lib_text),
                ("/host/src/bits.rs".into(), BITS.into()),
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
    refused(&build(&mk(lib("pub mod bits {\n    include!(\"bits_fast.rs\");\n}\n"))), "includes something other than its lowered copy");
    refused(&build(&mk(lib(&lowered_decl(BITS_DOCS, "bits-lowered__outer__bits.rs")))), "that this build (`bits`) writes is `OUT_DIR/bits-lowered__bits.rs`");
}

/// The lowered declaration outside a lifted child's parent: a host module
/// of a lifted file (as `mod x;` would be), listed, not an error.
#[test]
fn a_lowered_declaration_of_a_host_module_is_a_host_module() {
    let root = ROOT.replace(", children = \"bits\"", "").replace("pub use outer::bits::{at_most_one_bit, ones_plus_one};", "pub use outer::ONE;");
    let f: Vec<(String, String)> = with_mir(
        vec![
            ("/host/sandblaster/bits/mod.rs".into(), root.replace("#[lift(opt, mir = \"bits.sbmir\")]\nmod opt;\n", "").replace("#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n", "")),
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
