//! Module mode (DESIGN.md §2.1): a verified module inside an ordinary host
//! crate, through `driver::build_module` (the logic of
//! `sandblaster::build::compile_module`) on an in-memory host crate.
//!
//! * the fully specified test crate of `elab_pipeline` (three boundary
//!   functions refining a reference specification with known answers, an
//!   accepted lock) builds as the module `src/verified/prog.rs`: the same
//!   gates as crate mode, the relocated file (no `crate::` path, no
//!   `pub(crate)`), and the relocation equals the one of the crate-mode
//!   verdict;
//! * the emitted module compiles with rustc inside a host crate — mounted at
//!   a depth the file cannot know, next to host decoys named like the
//!   generated glue (`mod __sandblaster`, `mod __rt`) and host `macro_rules!`
//!   named like the dialect's macros — and computes what the source does;
//!   host code that reaches for an internal item does not compile (E0603);
//! * negative twins: a module file with extra content, one that includes an
//!   unverified file or another output, a second file including the output,
//!   a failing proof, a failing gate, a DSL root under `src/` and bad module
//!   file names all fail the host build and emit no code — and no
//!   environment variable changes that;
//! * verdict reuse: an unchanged input set reuses the verdict; a changed
//!   source, context or emitted file re-verifies.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;
#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use sandblaster_front::driver::{build_module, build_verified, module_file_ok, module_include_line, module_out_name, BuildOutcome, LIB_RS_LINE};
use sandblaster_front::loader::MemFs;
use sandblaster_front::relocate::{self, Tok};
use sandblaster_front::target::TargetInfo;
use util::HEADER;

const ROOT: &str = "sandblaster/prog/mod.rs";
const MODULE: &str = "src/verified/prog.rs";

fn env(extra: &[(&str, &str)]) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = [
        ("CARGO_MANIFEST_DIR", "/host"),
        ("OUT_DIR", "/out"),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in extra {
        m.insert(k.to_string(), v.to_string());
    }
    m
}

program!(prog {
    pub fn clamp_add(a: u8, b: u8) -> u8 {
        let s = a as u16 + b as u16;
        if s > 255 { 255 } else { s as u8 }
    }
    pub fn classify(x: u32) -> u32 {
        match x {
            0 => 0,
            1..=9 => 1,
            _ if x % 2 == 0 => 2,
            _ => 3,
        }
    }
    pub fn first(xs: &[u16]) -> Option<u16> {
        if xs.is_empty() { None } else { Some(xs[0]) }
    }
});

const SPEC: &str = r#"//! What the three functions compute, over unbounded numbers and sequences.

/// `a + b`, capped at 255.
#[example(saturating_sum(1, 2) == 3)]
#[example(saturating_sum(200, 100) == 255)]
#[example(saturating_sum(255, 0) == 255)]
pub fn saturating_sum(a: Nat, b: Nat) -> Nat {
    (a + b).min(255)
}

/// 0 for zero, 1 for one digit, else 2 for even and 3 for odd numbers.
#[example(classify(0) == 0)]
#[example(classify(9) == 1)]
#[example(classify(10) == 2)]
#[example(classify(13) == 3)]
pub fn classify(x: Nat) -> Nat {
    if x == 0 { 0 } else if x < 10 { 1 } else if x % 2 == 0 { 2 } else { 3 }
}

/// The first element, if any.
#[example(first(seq![]) == None)]
#[example(first(seq![7u16, 9u16]) == Some(7u16))]
pub fn first(xs: Seq<u16>) -> Option<u16> {
    if xs.len() == 0 { None } else { Some(xs[0]) }
}
"#;

/// The host crate's own (unverified) files.
fn host_files() -> Vec<(String, String)> {
    vec![
        ("/host/src/lib.rs".into(), "//! A host crate: ordinary Rust.\nmod verified;\npub mod host;\n".into()),
        ("/host/src/host.rs".into(), "pub fn twice(a: u8) -> u8 { crate::verified::prog::clamp_add(a, a) }\n".into()),
        ("/host/src/verified/mod.rs".into(), "pub mod prog;\n".into()),
        (format!("/host/{MODULE}"), format!("// the verified module (DESIGN.md §2.1)\n{}\n", module_include_line("prog"))),
    ]
}

/// The DSL crate (the root re-exports the three functions of a private
/// module, each refining its reference) with its accepted lock.
fn dsl_files() -> Vec<(String, String)> {
    let mut code = prog::SRC.replace("pub fn\n", "pub fn ");
    for (f, spec) in [("clamp_add", "saturating_sum"), ("classify", "classify"), ("first", "first")] {
        let at = code.find(&format!("pub fn {f}")).unwrap_or_else(|| panic!("no `{f}` in {code}"));
        code.insert_str(at, &format!("#[refines(crate::spec::{spec})] "));
    }
    let files = vec![
        (format!("/host/{ROOT}"), format!("{HEADER}mod m;\npub use m::{{clamp_add, classify, first}};\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec.rs\"]\nmod spec;\n")),
        ("/host/sandblaster/prog/m.rs".to_string(), format!("use sandblaster::prelude::*;\n{code}\n")),
        ("/host/sandblaster/prog/spec.rs".to_string(), SPEC.to_string()),
    ];
    gated::with_accepted_lock(&files, &format!("/host/{ROOT}"), &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"))
}

fn all_files() -> Vec<(String, String)> {
    let mut v = host_files();
    v.extend(dsl_files());
    v
}

/// `files` with `path` replaced by (or set to) `text`.
fn with(files: &[(String, String)], path: &str, text: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = files.iter().filter(|(p, _)| p != path).cloned().collect();
    v.push((path.to_string(), text.to_string()));
    v
}

fn build_ctx(files: &[(String, String)], module: &str, context: Option<&str>, extra: &[(&str, &str)]) -> BuildOutcome {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = env(extra);
    build_module(ROOT, module, context, &|k| e.get(k).cloned(), &fs)
}

fn build(files: &[(String, String)]) -> BuildOutcome {
    build_ctx(files, MODULE, None, &[])
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

#[track_caller]
fn assert_fails(o: &BuildOutcome, needle: &str) {
    assert!(!o.ok, "the build succeeded:\n{}", o.stderr);
    assert!(output(o, "prog.rs").is_none(), "code was emitted");
    assert!(o.stderr.contains(needle), "expected `{needle}` in:\n{}", o.stderr);
}

#[test]
fn module_mode_emits_the_relocated_verdict() {
    let files = all_files();
    let o = build(&files);
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "prog.rs").expect("OUT_DIR/prog.rs");
    assert!(code.lines().nth(1).is_some_and(|l| l.starts_with("// STATUS: VERIFIED + OPTIMIZED (phase 3)")), "{code}");
    assert!(code.contains("// MODULE MODE (DESIGN.md §2.1): the body of the host crate's module file `src/verified/prog.rs`"), "{code}");
    assert!(code.contains("This module's report is `prog-report.json`."), "{code}");
    assert!(code.contains("every §15 gate passed"), "{code}");
    // no absolute path and no crate-wide visibility survive
    let toks = relocate::tokens(code).unwrap();
    assert!(!toks.iter().any(|t| matches!(t, Tok::Ident(s) if s == "crate")), "{code}");
    assert!(!code.contains("pub(crate)"), "{code}");
    assert!(code.contains("super::super::__rt::chk::"), "the checked arithmetic of `m` is reached relatively:\n{code}");
    assert!(code.contains("::core::compile_error!("), "{code}");
    // the boundary: exactly the root's `pub use` list (and the spec root)
    let top_pub: Vec<&str> = code.lines().filter(|l| l.starts_with("pub ")).collect();
    assert_eq!(top_pub.len(), 4, "{top_pub:?}");
    for f in ["clamp_add", "classify", "first"] {
        assert!(top_pub.iter().any(|l| l.starts_with("pub use __sandblaster::") && l.ends_with(&format!(" as {f};"))), "{f}: {top_pub:?}");
    }
    assert!(top_pub.iter().any(|l| l.starts_with("pub const SANDBLASTER_SPEC_ROOT")), "{top_pub:?}");
    // every gate ran; the report names the module's file and its hash
    let report = output(&o, "prog-report.json").expect("report");
    for g in ["boundary", "examples", "sections", "law-rules", "lock", "mutation"] {
        assert!(report.contains(&format!("\"gate\": \"{g}\"")), "{g}: {report}");
    }
    assert!(!report.contains("\"ran\": false"), "{report}");
    let digest = sandblaster_front::surface::hex(&sandblaster_front::surface::sha256(code.as_bytes()));
    assert!(report.contains(&format!("\"file\": \"prog.rs\"")) && report.contains(&format!("\"sha256\": \"{digest}\"")), "{report}");
    assert!(output(&o, "prog-timing.json").is_some());
    // the build re-runs on any host source change (the scan of `src/`) and
    // on every DSL input
    for f in ["/host/src", "/host/sandblaster/prog/mod.rs", "/host/sandblaster/prog/m.rs", "/host/sandblaster/prog/SPEC.lock"] {
        assert!(o.cargo.iter().any(|l| l == &format!("cargo::rerun-if-changed={f}")), "{f}: {:?}", o.cargo);
    }
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::warning=sandblaster: verified module `prog`") && l.contains(&digest)), "{:?}", o.cargo);
    // crate mode on the same DSL crate: the module file is exactly the
    // relocation of the crate verdict (same gates, same print)
    let crate_files = with(&files, "/host/src/lib.rs", LIB_RS_LINE);
    let fs = MemFs::from_files(crate_files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = env(&[]);
    let c = build_verified(ROOT, &|k| e.get(k).cloned(), &fs);
    assert!(c.ok, "{}", c.stderr);
    let crate_code = output(&c, "sandblaster.rs").unwrap();
    assert_eq!(relocate::relocate(crate_code, &relocate::module_note(MODULE, "`prog-report.json`")).unwrap(), code);
}

/// Writes `files` to `dir` and compiles `main` with rustc (edition 2024,
/// debug assertions and overflow checks on).
fn rustc(dir: &Path, files: &[(&str, String)], main: &str) -> std::process::Output {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    for (p, c) in files {
        let path = dir.join(p);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, c).unwrap();
    }
    Command::new("rustc")
        .args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(dir.join("host"))
        .arg(dir.join(main))
        .output()
        .expect("rustc")
}

/// The emitted module inside a host crate: mounted two levels deep, next
/// to decoys named like the glue and host macros named like the dialect's
/// — none of it changes what the verified code calls — and the boundary
/// agrees with the natively compiled source.
#[test]
fn the_module_compiles_inside_a_host_crate_and_agrees_with_the_source() {
    let o = build(&all_files());
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "prog.rs").unwrap().to_string();
    let inputs: Vec<(u8, u8)> = vec![(0, 0), (200, 100), (255, 255), (7, 8)];
    let words: Vec<u32> = vec![0, 5, 10, 11, u32::MAX];
    let halves: Vec<Vec<u16>> = vec![vec![], vec![9], vec![1, 2, 65535]];
    let mut native = String::new();
    let mut body = String::new();
    for (a, b) in &inputs {
        native.push_str(&format!("{:?}\n", prog::clamp_add(*a, *b)));
        body.push_str(&format!("    println!(\"{{:?}}\", v::clamp_add({a}u8, {b}u8));\n"));
    }
    for w in &words {
        native.push_str(&format!("{:?}\n", prog::classify(*w)));
        body.push_str(&format!("    println!(\"{{:?}}\", v::classify({w}u32));\n"));
    }
    for h in &halves {
        native.push_str(&format!("{:?}\n", prog::first(h)));
        body.push_str(&format!("    println!(\"{{:?}}\", v::first(&[{}] as &[u16]));\n", h.iter().map(|x| format!("{x}u16")).collect::<Vec<_>>().join(", ")));
    }
    native.push_str(&format!("{}\n", prog::clamp_add(9, 9)));
    // host decoys: an absolute `crate::__sandblaster::m::clamp_add` or
    // `crate::__rt::chk::add_u16` would reach these; relative paths cannot
    let main = format!(
        "#![allow(dead_code, unused_macros)]\n\
         macro_rules! compile_error {{ ($($t:tt)*) => {{}} }}\n\
         macro_rules! unreachable {{ () => {{ 0 }} }}\n\
         mod __sandblaster {{ pub mod m {{ pub fn clamp_add(_: u8, _: u8) -> u8 {{ 42 }} pub fn classify(_: u32) -> u32 {{ 42 }} }} }}\n\
         mod __rt {{ pub mod chk {{ pub fn add_u16(_: u16, _: u16) -> u16 {{ 42 }} }} }}\n\
         mod outer {{ pub mod verified {{ #[path = \"prog.rs\"] pub mod prog; }} }}\n\
         mod host {{ pub fn twice(a: u8) -> u8 {{ crate::outer::verified::prog::clamp_add(a, a) }} }}\n\
         use outer::verified::prog as v;\n\
         fn main() {{\n{body}    println!(\"{{}}\", host::twice(9));\n}}\n"
    );
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("module-mode-host");
    let module_file = format!("{}\n", module_include_line("prog"));
    std::fs::create_dir_all(&dir).unwrap();
    // the generated module is `include!`d exactly as a host crate does it
    // (OUT_DIR set for rustc's `env!`)
    let out_dir = dir.join("out");
    let st = {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("outer/verified")).unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(out_dir.join("prog.rs"), &code).unwrap();
        std::fs::write(dir.join("outer/verified/prog.rs"), &module_file).unwrap();
        std::fs::write(dir.join("main.rs"), &main).unwrap();
        Command::new("rustc")
            .env("OUT_DIR", &out_dir)
            .args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
            .arg(dir.join("host"))
            .arg(dir.join("main.rs"))
            .output()
            .expect("rustc")
    };
    assert!(st.status.success(), "the host crate does not compile:\n{}", String::from_utf8_lossy(&st.stderr));
    let run = Command::new(dir.join("host")).output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(String::from_utf8_lossy(&run.stdout), native);
}

/// Host code reaches only the boundary: the generated glue module, the
/// source's private module and the checked-arithmetic helpers are private
/// to the module file (rustc E0603), however the host names them.
#[test]
fn host_code_cannot_reach_internals() {
    let o = build(&all_files());
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "prog.rs").unwrap().to_string();
    for (i, reach) in ["v::__sandblaster::m::clamp_add(1, 2)", "v::__rt::chk::add_u16(1, 2) as u8", "{ use v::__sandblaster::m; m::clamp_add(1, 2) }"].iter().enumerate() {
        let main = format!("mod v {{ include!(\"prog.rs\"); }}\nfn main() {{ let _x: u8 = {reach}; }}\n");
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("module-mode-reach-{i}"));
        let st = rustc(&dir, &[("prog.rs", code.clone()), ("main.rs", main)], "main.rs");
        let err = String::from_utf8_lossy(&st.stderr);
        assert!(!st.status.success(), "{reach}: the host reached an internal item");
        assert!(err.contains("E0603"), "{reach}: {err}");
    }
    // the twin: the boundary itself is reachable
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("module-mode-reach-ok");
    let st = rustc(&dir, &[("prog.rs", code), ("main.rs", "mod v { include!(\"prog.rs\"); }\nfn main() { assert_eq!(v::clamp_add(200, 100), 255); }\n".into())], "main.rs");
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
}

/// The host's lint levels apply to the included file: a host that denies
/// every warning (like the Commonware workspace, `warnings = "deny"`,
/// `rust-2018-idioms = "deny"`) and uses only part of the boundary still
/// compiles (the lint attribute of module mode).
#[test]
fn a_host_that_denies_warnings_may_use_part_of_the_boundary() {
    let o = build(&all_files());
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "prog.rs").unwrap().to_string();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("module-mode-lints");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("prog.rs"), &code).unwrap();
    std::fs::write(dir.join("lib.rs"), "#![deny(warnings, rust_2018_idioms, missing_docs, unused_qualifications, trivial_numeric_casts, unreachable_pub)]\n//! A host library.\nmod v { include!(\"prog.rs\"); }\n/// Doubles, saturating.\npub fn twice(a: u8) -> u8 { v::clamp_add(a, a) }\n").unwrap();
    for profile in [&["-C", "debug-assertions=on"][..], &["-C", "opt-level=2"][..]] {
        let st = Command::new("rustc").args(["--edition", "2024", "--crate-type", "lib", "--out-dir"]).arg(&dir).args(profile).arg(dir.join("lib.rs")).output().expect("rustc");
        assert!(st.status.success(), "{profile:?}: {}", String::from_utf8_lossy(&st.stderr));
    }
}

#[test]
fn the_module_file_is_exactly_the_include_line() {
    let line = module_include_line("prog");
    assert_eq!(line, "include!(concat!(env!(\"OUT_DIR\"), \"/prog.rs\"));");
    assert!(module_file_ok(&line, "prog"));
    assert!(module_file_ok("//! docs\n// c\ninclude!( concat!( env!( \"OUT_DIR\" ), \"/prog.rs\" ) ); /* t */\n", "prog"));
    assert!(!module_file_ok(&line, "other"));
    assert!(!module_file_ok(&format!("{line}\npub fn host() {{}}\n"), "prog"));
    assert!(!module_file_ok(&format!("use std::*;\n{line}"), "prog"));
    assert!(!module_file_ok(&format!("#[allow(unsafe_code)]\n{line}"), "prog"));
    assert!(!module_file_ok("include!(\"../unverified/prog.rs\");", "prog"));
    assert!(!module_file_ok(LIB_RS_LINE, "prog"));
}

#[test]
fn module_file_names() {
    assert_eq!(module_out_name("src/verified/varint.rs").unwrap(), "varint");
    assert_eq!(module_out_name("src/varint.rs").unwrap(), "varint");
    assert_eq!(module_out_name("src/verified/varint/mod.rs").unwrap(), "varint");
    for (bad, needle) in [
        ("src/lib.rs", "crate root"),
        ("src/main.rs", "crate root"),
        ("src/mod.rs", "not a module file"),
        ("/abs/src/v.rs", "relative path under `src/`"),
        ("verified/v.rs", "relative path under `src/`"),
        ("src/../x/v.rs", "relative path under `src/`"),
        ("src/v.txt", "`.rs` file"),
        ("src/Varint.rs", "lowercase identifier"),
        ("src/var-int.rs", "lowercase identifier"),
        ("src/sandblaster.rs", "crate mode"),
    ] {
        let e = module_out_name(bad).expect_err(bad);
        assert!(e.contains(needle), "{bad}: {e}");
    }
}

/// Negative twins: host code that includes an unverified file in the
/// verified module's place, adds content next to the include, includes the
/// output a second time or includes another output; the build fails and
/// emits nothing.
#[test]
fn the_host_cannot_replace_or_extend_the_verified_module() {
    let files = all_files();
    let m = format!("/host/{MODULE}");
    let line = module_include_line("prog");
    for (path, text, needle) in [
        (m.as_str(), "include!(\"../unverified/prog.rs\");\n".to_string(), "must contain exactly"),
        (m.as_str(), "pub fn clamp_add(a: u8, b: u8) -> u8 { a.wrapping_add(b) }\n".to_string(), "must contain exactly"),
        (m.as_str(), format!("{line}\npub fn host() {{}}\n"), "must contain exactly"),
        (m.as_str(), format!("use crate::host::*;\n{line}\n"), "must contain exactly"),
        (m.as_str(), module_include_line("other"), "must contain exactly"),
        ("/host/src/lib.rs", format!("mod verified;\npub mod host;\nmod shadow {{ use crate::host::*; {line} }}\n"), "also mentions `OUT_DIR/prog.rs`"),
        ("/host/src/deep/x.rs", format!("// {line}\n/* {line} */\npub fn f() -> &'static str {{ include_str!(concat!(env!(\"OUT_DIR\"), \"/prog.rs\")) }}\n"), "also mentions `OUT_DIR/prog.rs`"),
    ] {
        let o = build(&with(&files, path, &text));
        assert_fails(&o, needle);
        assert!(!o.outputs.iter().any(|(p, _)| p.extension().is_some_and(|x| x == "rs")), "{path}");
    }
    // a missing module file
    let gone: Vec<(String, String)> = files.iter().filter(|(p, _)| p != &m).cloned().collect();
    assert_fails(&build(&gone), "cannot read the module file");
    // comments that mention the output elsewhere are fine
    let o = build(&with(&files, "/host/src/host.rs", &format!("// the generated `{line}` lives in verified/prog.rs\npub fn twice(a: u8) -> u8 {{ crate::verified::prog::clamp_add(a, a) }}\n")));
    assert!(o.ok, "{}", o.stderr);
}

/// Negative twins: a failing proof and a failing gate fail the host build
/// like crate mode, and no environment variable emits code.
#[test]
fn failing_proofs_and_gates_fail_the_host_build() {
    let files = all_files();
    // an unprovable overflow
    let m = files.iter().find(|(p, _)| p.ends_with("prog/m.rs")).unwrap().1.clone();
    let bad = m.replace("let s = a as u16 + b as u16;", "let s = (a + b) as u16;");
    assert_ne!(bad, m);
    let o = build(&with(&files, "/host/sandblaster/prog/m.rs", &bad));
    assert_fails(&o, "error[obligation]: unproven obligation [overflow]");
    assert!(output(&o, "prog-report.json").is_some_and(|r| r.contains("\"status\": \"NOT VERIFIED\"")), "the report explains the failure");
    // a known answer that does not hold
    let s = files.iter().find(|(p, _)| p.ends_with("prog/spec.rs")).unwrap().1.clone();
    let o = build(&with(&files, "/host/sandblaster/prog/spec.rs", &s.replace("classify(13) == 3", "classify(13) == 2")));
    assert_fails(&o, "is false");
    // no lock
    let no_lock: Vec<(String, String)> = files.iter().filter(|(p, _)| !p.ends_with("SPEC.lock")).cloned().collect();
    for extra in [vec![], vec![("SANDBLASTER_PHASE1_UNVERIFIED", "1")], vec![("SANDBLASTER_MUTANTS_MAX", "0")], vec![("SANDBLASTER_STRICT_OPT", "0")]] {
        let o = build_ctx(&no_lock, MODULE, None, &extra);
        assert_fails(&o, "error[spec-lock]");
    }
    // a front-end error
    let o = build(&with(&files, "/host/sandblaster/prog/m.rs", "pub fn f(x: u32) -> u32 { x + }\n"));
    assert_fails(&o, "error");
    assert!(o.outputs.is_empty());
}

#[test]
fn the_dsl_root_is_not_host_source() {
    let mut files: Vec<(String, String)> = all_files().into_iter().map(|(p, c)| (p.replace("/host/sandblaster/prog/", "/host/src/dsl/"), c)).collect();
    files.retain(|(p, _)| !p.ends_with("SPEC.lock"));
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = env(&[]);
    let o = build_module("src/dsl/mod.rs", MODULE, None, &|k| e.get(k).cloned(), &fs);
    assert!(!o.ok && o.stderr.contains("is under `src/`"), "{}", o.stderr);
    // bad module file names fail before anything is read
    let o = build_ctx(&all_files(), "src/lib.rs", None, &[]);
    assert!(!o.ok && o.stderr.contains("crate root"), "{}", o.stderr);
}

/// Verdict reuse: the same inputs and emitted file reuse the verdict
/// (nothing re-verified, nothing written); a changed source, context or
/// emitted file re-verifies.
#[test]
fn an_unchanged_module_reuses_its_verdict() {
    let files = all_files();
    let o = build_ctx(&files, MODULE, Some("ctx-1"), &[]);
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "prog.rs").unwrap().to_string();
    let key = output(&o, "prog-verdict.key").expect("the key is written with a verdict").to_string();
    assert!(key.contains(&format!("sha256 {}", sandblaster_front::surface::hex(&sandblaster_front::surface::sha256(code.as_bytes())))), "{key}");
    let mut done = files.clone();
    done.push(("/out/prog.rs".into(), code.clone()));
    done.push(("/out/prog-verdict.key".into(), key.clone()));
    // reused: a host-only edit re-runs the scan, not the proofs
    let host_edit = with(&done, "/host/src/host.rs", "pub fn twice(a: u8) -> u8 { crate::verified::prog::clamp_add(a, 1) }\n");
    let r = build_ctx(&host_edit, MODULE, Some("ctx-1"), &[]);
    assert!(r.ok && r.outputs.is_empty(), "{}", r.stderr);
    assert!(r.cargo.iter().any(|l| l.contains("verified module `prog` unchanged")), "{:?}", r.cargo);
    assert!(r.cargo.iter().any(|l| l == "cargo::rerun-if-changed=/host/src"), "every run prints the directives: {:?}", r.cargo);
    // the module checks still run on a reused verdict
    let r = build_ctx(&with(&done, &format!("/host/{MODULE}"), "pub fn f() {}\n"), MODULE, Some("ctx-1"), &[]);
    assert!(!r.ok && r.stderr.contains("must contain exactly"), "{}", r.stderr);
    // not reused: another context, a tampered file, a changed source
    for (what, fs_files, ctx) in [
        ("context", done.clone(), "ctx-2"),
        ("emitted file", with(&done, "/out/prog.rs", &code.replace("MODULE MODE", "MODULE  MODE")), "ctx-1"),
        ("key", with(&done, "/out/prog-verdict.key", &key.replace("sha256 ", "sha256 0")), "ctx-1"),
        ("source", with(&done, "/host/sandblaster/prog/spec.rs", &format!("{SPEC}// an edit\n")), "ctx-1"),
    ] {
        let r = build_ctx(&fs_files, MODULE, Some(ctx), &[]);
        assert!(r.ok, "{what}: {}", r.stderr);
        assert!(output(&r, "prog.rs").is_some(), "{what}: the verdict was reused");
        assert!(!r.cargo.iter().any(|l| l.contains("unchanged")), "{what}");
    }
    // without a context nothing is reused and no key is written
    let r = build_ctx(&done, MODULE, None, &[]);
    assert!(r.ok && output(&r, "prog.rs").is_some() && output(&r, "prog-verdict.key").is_none(), "{}", r.stderr);
}
