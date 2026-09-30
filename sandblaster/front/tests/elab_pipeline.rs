//! The crate path of the build (`driver::build_verified`, the logic of
//! `sandblaster::build::compile`, DESIGN.md §10.1, §15.8): a fully specified
//! crate with an accepted lock emits `sandblaster.rs` marked
//! `VERIFIED + OPTIMIZED` plus the report; any unproven obligation, open
//! law, front-end error or failed §15 gate emits no code. The emitted code
//! compiles with rustc and computes what the source computes.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;
#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use sandblaster_front::driver::{build_verified, BuildOutcome, LIB_RS_LINE};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::HEADER;

fn env() -> HashMap<String, String> {
    [
        ("CARGO_MANIFEST_DIR", "/crate"),
        ("OUT_DIR", "/out"),
        ("CARGO_CFG_TARGET_ARCH", "aarch64"),
        ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes"),
        ("CARGO_CFG_TARGET_ENDIAN", "little"),
        ("CARGO_CFG_TARGET_POINTER_WIDTH", "64"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

fn build(lib: &str, files: &[(&str, &str)]) -> BuildOutcome {
    let mut all: Vec<(String, String)> = vec![("/crate/src/lib.rs".into(), lib.into())];
    for (p, c) in files {
        all.push((format!("/crate/sandblaster/{p}"), c.to_string()));
    }
    build_files(&all)
}

fn build_files(all: &[(String, String)]) -> BuildOutcome {
    let fs = MemFs::from_files(all.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let e = env();
    build_verified("sandblaster/mod.rs", &|k| e.get(k).cloned(), &fs)
}

/// The fully specified crate of [`prog`]: the functions in a private
/// module, re-exported by the root, each refining a reference
/// specification with known answers; plus the lock its gates accepted.
fn prog_crate() -> Vec<(String, String)> {
    let mut code = prog::SRC.replace("pub fn\n", "pub fn ");
    for (f, spec) in [("clamp_add", "saturating_sum"), ("classify", "classify"), ("first", "first")] {
        let at = code.find(&format!("pub fn {f}")).unwrap_or_else(|| panic!("no `{f}` in {code}"));
        code.insert_str(at, &format!("#[refines(crate::spec::{spec})] "));
    }
    let files = vec![
        ("/crate/src/lib.rs".to_string(), LIB_RS_LINE.to_string()),
        ("/crate/sandblaster/mod.rs".to_string(), format!("{HEADER}mod m;\npub use m::{{clamp_add, classify, first}};\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec.rs\"]\nmod spec;\n")),
        ("/crate/sandblaster/m.rs".to_string(), format!("use sandblaster::prelude::*;\n{code}\n")),
        ("/crate/sandblaster/spec.rs".to_string(), SPEC.to_string()),
    ];
    gated::with_accepted_lock(&files, "/crate/sandblaster/mod.rs", &TargetInfo::aarch64_apple_darwin()).unwrap_or_else(|e| panic!("the gates reject the test crate:\n{e}"))
}

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

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.ends_with(name)).map(|(_, c)| c.as_str())
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

#[test]
fn verified_build_emits_code_and_report() {
    let o = build_files(&prog_crate());
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "sandblaster.rs").expect("sandblaster.rs");
    assert!(code.lines().nth(1).is_some_and(|l| l.starts_with("// STATUS: VERIFIED + OPTIMIZED (phase 3)")), "{code}");
    assert!(code.contains("every §15 gate passed"), "{code}");
    assert!(!code.contains("UNVERIFIED") && !code.contains("STAGE OUTPUT"));
    let report = output(&o, "sandblaster-report.json").expect("report");
    assert!(report.contains("\"status\": \"VERIFIED + OPTIMIZED (phase 3)\""), "{report}");
    // every gate ran and passed; the report records the emitted file's hash
    for g in ["boundary", "examples", "sections", "law-rules", "lock", "mutation"] {
        assert!(report.contains(&format!("\"gate\": \"{g}\"")), "{g}: {report}");
    }
    assert!(!report.contains("\"ran\": false"), "{report}");
    let digest = sandblaster_front::surface::hex(&sandblaster_front::surface::sha256(code.as_bytes()));
    assert!(report.contains(&format!("\"sha256\": \"{digest}\"")), "{report}");
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::rerun-if-changed=") && l.ends_with("sandblaster/mod.rs")));
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::warning=sandblaster: verified") && l.contains(&digest)));
}

/// Every gate applies to the test crate too: without its lock it fails,
/// and a known answer that does not hold fails its example.
#[test]
fn the_gates_apply_to_the_test_crate() {
    let files = prog_crate();
    let no_lock: Vec<(String, String)> = files.iter().filter(|(p, _)| !p.ends_with("SPEC.lock")).cloned().collect();
    let o = build_files(&no_lock);
    assert!(!o.ok && output(&o, "sandblaster.rs").is_none());
    assert!(o.stderr.contains("error[spec-lock]"), "{}", o.stderr);
    let wrong: Vec<(String, String)> = files.iter().map(|(p, c)| (p.clone(), if p.ends_with("spec.rs") { c.replace("classify(13) == 3", "classify(13) == 2") } else { c.clone() })).collect();
    let o = build_files(&wrong);
    assert!(!o.ok && output(&o, "sandblaster.rs").is_none());
    assert!(o.stderr.contains("is false"), "{}", o.stderr);
}

#[test]
fn unproven_obligations_emit_no_code() {
    let src = format!("{HEADER}pub fn f(a: u32, b: u32) -> u32 {{ a + b }}\n");
    let o = build(LIB_RS_LINE, &[("mod.rs", &src)]);
    assert!(!o.ok);
    assert!(output(&o, "sandblaster.rs").is_none(), "no code for an unverified crate");
    assert!(output(&o, "sandblaster-report.json").is_some_and(|r| r.contains("\"status\": \"NOT VERIFIED\"")), "the report explains the failure");
    assert!(o.stderr.contains("error[obligation]: unproven obligation [overflow] in `crate::f`"), "{}", o.stderr);
    assert!(o.stderr.contains("verification of"), "{}", o.stderr);
}

#[test]
fn front_end_errors_and_lib_rs_are_still_checked() {
    let o = build("pub fn host() {}\n", &[("mod.rs", &format!("{HEADER}pub fn f() {{}}\n"))]);
    assert!(!o.ok && o.stderr.contains("must contain exactly"), "{}", o.stderr);
    let o = build(LIB_RS_LINE, &[("mod.rs", "pub fn f(x: u32) -> u32 { x + }\n")]);
    assert!(!o.ok && o.outputs.is_empty(), "{}", o.stderr);
}

#[test]
fn open_laws_emit_no_code() {
    let root = format!("{HEADER}pub fn double(x: u8) -> u16 {{ x as u16 * 2 }}\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n");
    let laws = "use sandblaster::prelude::*;\nuse super::double;\n#[law] fn double_exact(x: u8) { ensures((double(x) as Int) == 2 * (x as Int)); }\n";
    let o = build(LIB_RS_LINE, &[("mod.rs", &root), ("LAWS.rs", laws)]);
    assert!(!o.ok, "an open claim fails the build");
    assert!(output(&o, "sandblaster.rs").is_none());
    assert!(o.stderr.contains("double_exact"), "{}", o.stderr);
}

/// The emitted verified code, compiled by rustc (debug assertions and
/// overflow checks on), computes what the natively compiled source does.
#[test]
fn emitted_code_agrees_with_the_source() {
    let o = build_files(&prog_crate());
    assert!(o.ok, "{}", o.stderr);
    let code = output(&o, "sandblaster.rs").unwrap();
    let inputs: Vec<(u8, u8)> = vec![(0, 0), (200, 100), (255, 255), (7, 8)];
    let words: Vec<u32> = vec![0, 5, 10, 11, u32::MAX];
    let halves: Vec<Vec<u16>> = vec![vec![], vec![9], vec![1, 2, 65535]];
    let mut native = String::new();
    let mut main = String::from("fn main() {\n");
    for (a, b) in &inputs {
        native.push_str(&format!("{:?}\n", prog::clamp_add(*a, *b)));
        main.push_str(&format!("    println!(\"{{:?}}\", clamp_add({a}u8, {b}u8));\n"));
    }
    for w in &words {
        native.push_str(&format!("{:?}\n", prog::classify(*w)));
        main.push_str(&format!("    println!(\"{{:?}}\", classify({w}u32));\n"));
    }
    for h in &halves {
        native.push_str(&format!("{:?}\n", prog::first(h)));
        main.push_str(&format!("    println!(\"{{:?}}\", first(&[{}] as &[u16]));\n", h.iter().map(|x| format!("{x}u16")).collect::<Vec<_>>().join(", ")));
    }
    main.push_str("}\n");
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("elab-pipeline");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
    std::fs::write(dir.join("main.rs"), format!("include!(\"sandblaster.rs\");\n{main}")).unwrap();
    let st = Command::new("rustc")
        .args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(dir.join("gen"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(st.status.success(), "the emitted code does not compile:\n{}", String::from_utf8_lossy(&st.stderr));
    let run = Command::new(dir.join("gen")).output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    assert_eq!(String::from_utf8_lossy(&run.stdout), native);
}
