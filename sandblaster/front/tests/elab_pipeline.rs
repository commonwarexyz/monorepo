//! The crate path of the build (`driver::build_crate`, DESIGN.md §10.1,
//! §15.8) on a crate written in sandblaster's own dialect: a fully
//! specified crate with an accepted lock gets a verdict (with no code: the
//! dialect is not compiled by rustc) and a report; any unproven
//! obligation, open law, front-end error or failed §15 gate gets none.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;
#[path = "gated_util.rs"]
mod gated;

use std::path::Path;

use sandblaster_front::driver::{self, LockUse};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::HEADER;

/// What the crate path made of a crate.
struct Built {
    verdict: bool,
    status: String,
    report: String,
    /// The diagnostics and the failure's closing line.
    stderr: String,
    code: Option<String>,
}

fn build(files: &[(&str, &str)]) -> Built {
    let all: Vec<(String, String)> = files.iter().map(|(p, c)| (format!("/crate/sandblaster/{p}"), c.to_string())).collect();
    build_files(&all)
}

fn build_files(all: &[(String, String)]) -> Built {
    let fs = MemFs::from_files(all.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let root = "/crate/sandblaster/mod.rs";
    let c = driver::check(Path::new(root), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        return Built { verdict: false, status: "front-end errors".into(), report: String::new(), stderr: c.render(), code: None };
    }
    let b = driver::build_crate(&c, LockUse::Enforce, root);
    let stderr = if b.verdict.is_some() { b.diagnostics().render(&c.sm) } else { b.render_failure(&c, root) };
    Built { verdict: b.verdict.is_some(), status: b.status(), report: b.report.clone(), stderr, code: b.verdict.as_ref().map(|v| v.code().to_string()) }
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
fn a_verified_crate_gets_a_verdict_and_a_report() {
    let o = build_files(&prog_crate());
    assert!(o.verdict, "{}", o.stderr);
    assert_eq!(o.status, driver::gates::DIALECT_VERIFIED);
    assert_eq!(o.code.as_deref(), Some(""), "the dialect is not compiled by rustc: no code");
    assert!(o.report.contains(&format!("\"status\": \"{}\"", driver::gates::DIALECT_VERIFIED)), "{}", o.report);
    // every gate ran and passed; spec mutation is not a gate (the
    // on-demand tool `sandblaster mutate`)
    for g in ["boundary", "examples", "sections", "law-rules", "lock"] {
        assert!(o.report.contains(&format!("\"gate\": \"{g}\"")), "{g}: {}", o.report);
    }
    assert!(!o.report.contains("\"gate\": \"mutation\"") && !o.report.contains("\"mutation\": {"), "{}", o.report);
    assert!(!o.report.contains("\"ran\": false"), "{}", o.report);
}

/// Every gate applies to the test crate too: without its lock it fails,
/// and a known answer that does not hold fails its example.
#[test]
fn the_gates_apply_to_the_test_crate() {
    let files = prog_crate();
    let no_lock: Vec<(String, String)> = files.iter().filter(|(p, _)| !p.ends_with("SPEC.lock")).cloned().collect();
    let o = build_files(&no_lock);
    assert!(!o.verdict && o.code.is_none());
    assert!(o.stderr.contains("error[spec-lock]"), "{}", o.stderr);
    let wrong: Vec<(String, String)> = files.iter().map(|(p, c)| (p.clone(), if p.ends_with("spec.rs") { c.replace("classify(13) == 3", "classify(13) == 2") } else { c.clone() })).collect();
    let o = build_files(&wrong);
    assert!(!o.verdict && o.code.is_none());
    assert!(o.stderr.contains("is false"), "{}", o.stderr);
}

#[test]
fn unproven_obligations_get_no_verdict() {
    let src = format!("{HEADER}pub fn f(a: u32, b: u32) -> u32 {{ a + b }}\n");
    let o = build(&[("mod.rs", &src)]);
    assert!(!o.verdict);
    assert!(o.report.contains("\"status\": \"NOT VERIFIED\""), "the report explains the failure: {}", o.report);
    assert!(o.stderr.contains("error[obligation]: unproven obligation [overflow] in `crate::f`"), "{}", o.stderr);
    assert!(o.stderr.contains("verification of"), "{}", o.stderr);
}

#[test]
fn front_end_errors_get_no_verdict() {
    let o = build(&[("mod.rs", "pub fn f(x: u32) -> u32 { x + }\n")]);
    assert!(!o.verdict && o.report.is_empty(), "{}", o.stderr);
}

#[test]
fn open_laws_get_no_verdict() {
    let root = format!("{HEADER}pub fn double(x: u8) -> u16 {{ x as u16 * 2 }}\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n");
    let laws = "use sandblaster::prelude::*;\nuse super::double;\n#[law] fn double_exact(x: u8) { ensures((double(x) as Int) == 2 * (x as Int)); }\n";
    let o = build(&[("mod.rs", &root), ("LAWS.rs", laws)]);
    assert!(!o.verdict, "an open claim fails the build");
    assert!(o.stderr.contains("double_exact"), "{}", o.stderr);
}
