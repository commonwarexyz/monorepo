//! Module mode (DESIGN.md §2.1): a verified lifted module inside an
//! ordinary host crate, through `driver::build_module` (the logic of
//! `sandblaster::build::compile_module`) on an in-memory host crate: the
//! checks that run before any proof.
//!
//! * the module file is exactly the include line, its name is a lowercase
//!   identifier under `src/`;
//! * negative twins: a module file with extra content, one that includes an
//!   unverified file or another output, a second file including the output,
//!   a DSL root under `src/` and bad module file names all fail the host
//!   build and emit no code;
//! * a crate written in sandblaster's own dialect (no `#[lift]` module) has
//!   no code to emit: module mode refuses it.
//!
//! A lifted module that verifies, its determinism, its watched paths and
//! its verdict reuse: `tests/build_loop.rs` (and codec's varint, built in
//! module mode by `codec/build.rs`).

use std::collections::HashMap;

use sandblaster_front::driver::{build_module, module_file_ok, module_include_line, module_out_name, BuildOutcome};
use sandblaster_front::loader::MemFs;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";
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

/// The host crate's own (unverified) files.
fn host_files() -> Vec<(String, String)> {
    vec![
        ("/host/src/lib.rs".into(), "//! A host crate: ordinary Rust.\nmod verified;\npub mod host;\n".into()),
        ("/host/src/host.rs".into(), "pub fn twice(a: u8) -> u8 { crate::verified::prog::clamp_add(a, a) }\n".into()),
        ("/host/src/verified/mod.rs".into(), "pub mod prog;\n".into()),
        (format!("/host/{MODULE}"), format!("// the verified module (DESIGN.md §2.1)\n{}\n", module_include_line("prog"))),
    ]
}

/// A DSL crate in sandblaster's own dialect (no `#[lift]` module).
fn dsl_files() -> Vec<(String, String)> {
    vec![
        (format!("/host/{ROOT}"), format!("{HEADER}mod m;\npub use m::clamp_add;\n")),
        ("/host/sandblaster/prog/m.rs".to_string(), "use sandblaster::prelude::*;\n/// `a + b`, capped at 255.\npub fn clamp_add(a: u8, b: u8) -> u8 {\n    let s = a as u16 + b as u16;\n    if s > 255 { 255 } else { s as u8 }\n}\n".to_string()),
    ]
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
        ("src/sandblaster.rs", "reserved"),
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
    // comments that mention the output elsewhere are fine: the module
    // checks pass (and the crate, written in sandblaster's own dialect, has
    // nothing to emit)
    let o = build(&with(&files, "/host/src/host.rs", &format!("// the generated `{line}` lives in verified/prog.rs\npub fn twice(a: u8) -> u8 {{ crate::verified::prog::clamp_add(a, a) }}\n")));
    assert_fails(&o, "lifts no Rust module");
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

/// A crate in sandblaster's own dialect passes the module checks and is
/// refused before any proof: it has no code to emit.
#[test]
fn a_crate_in_the_dialect_is_refused() {
    let o = build(&all_files());
    assert_fails(&o, "lifts no Rust module");
    assert!(o.outputs.is_empty(), "nothing is written");
}
