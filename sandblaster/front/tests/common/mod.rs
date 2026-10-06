//! Shared helpers for the front-end integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked};
use sandblaster_front::loader::{MemFs, RealFs};
use sandblaster_front::target::TargetInfo;

/// The standard header of test roots.
pub const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// Checks an in-memory crate; `files[0]` is the root (`r/mod.rs`).
pub fn check_files(files: &[(&str, &str)]) -> Checked {
    check_files_target(files, &TargetInfo::aarch64_apple_darwin())
}

pub fn check_files_target(files: &[(&str, &str)], target: &TargetInfo) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)));
    driver::check(Path::new(files[0].0), &fs, target)
}

/// Checks a single-module crate made of `HEADER` + `body`.
pub fn check(body: &str) -> Checked {
    let src = format!("{HEADER}{body}");
    check_files(&[("r/mod.rs", &src)])
}

/// Checks a single-module crate on x86_64.
pub fn check_x86(body: &str) -> Checked {
    let src = format!("{HEADER}{body}");
    check_files_target(&[("r/mod.rs", &src)], &TargetInfo::x86_64_apple_darwin())
}

/// Error diagnostics as `(kind, message)`.
pub fn errors(c: &Checked) -> Vec<(DiagKind, String)> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect()
}

/// Asserts the crate is accepted without errors.
#[track_caller]
pub fn accepts(body: &str) -> Checked {
    let c = check(body);
    assert!(c.ok(), "expected no errors, got:\n{}", c.render());
    c
}

/// Asserts a refused native-dialect hardware form (`#[implements]`, the
/// `sandblaster::arch` helpers; removed with the optimizer,
/// `sandblaster_front::target::{NO_VARIANTS, NO_ARCH_HELPERS}`): some error
/// is a `... is not supported` refusal, and every other error is a resolve
/// error that follows from it (a name the refused import would have
/// brought).
#[track_caller]
pub fn refused_hardware(body: &str) -> Checked {
    let c = check(body);
    refused_hardware_checked(&c);
    c
}

#[track_caller]
pub fn refused_hardware_checked(c: &Checked) {
    let errs = errors(c);
    let refusal = |k: &DiagKind, m: &str| *k == DiagKind::Feature && m.ends_with("not supported");
    assert!(errs.iter().any(|(k, m)| refusal(k, m)) && errs.iter().all(|(k, m)| refusal(k, m) || *k == DiagKind::Resolve), "expected the hardware refusal; got:\n{}", c.render());
}

/// Asserts some error of `kind` whose message contains `needle`.
#[track_caller]
pub fn rejects(body: &str, kind: DiagKind, needle: &str) -> Checked {
    let c = check(body);
    rejects_checked(&c, kind, needle);
    c
}

#[track_caller]
pub fn rejects_checked(c: &Checked, kind: DiagKind, needle: &str) {
    let errs = errors(c);
    assert!(errs.iter().any(|(k, m)| *k == kind && m.contains(needle)), "expected error[{}] containing {:?}; got:\n{}", kind.code(), needle, c.render());
}

/// Checks a crate directory on disk.
pub fn check_dir(root: &Path) -> Checked {
    driver::check(root, &RealFs, &TargetInfo::aarch64_apple_darwin())
}

pub fn samples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples")
}

pub fn tmp(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Compiles `main` with rustc (edition 2024, debug assertions and overflow
/// checks on) and runs it, returning stdout.
pub fn rustc_run(main: &Path, out: &Path, extra: &[String]) -> String {
    let st = Command::new("rustc")
        .args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(out)
        .args(extra)
        .arg(main)
        .output()
        .expect("rustc");
    assert!(st.status.success(), "rustc failed on {}:\n{}", main.display(), String::from_utf8_lossy(&st.stderr));
    let run = Command::new(out).output().expect("run");
    assert!(run.status.success(), "{} failed:\n{}", out.display(), String::from_utf8_lossy(&run.stderr));
    String::from_utf8(run.stdout).unwrap()
}

/// Copies a DSL sample directory, erasing sandblaster annotations so the raw
/// sources compile as plain Rust (the role of the erasing macros in baseline
/// builds). Annotations must be on their own line in samples.
pub fn erase_copy(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if p.is_dir() {
            erase_copy(&p, &dst.join(e.file_name()));
            continue;
        }
        let text = std::fs::read_to_string(&p).unwrap();
        let mut out = String::new();
        for line in text.lines() {
            let t = line.trim_start();
            let erased = t.starts_with("use sandblaster::prelude::*;")
                || t.starts_with("#[requires(")
                || t.starts_with("#[ensures(")
                || t.starts_with("#[decreases(")
                || t.starts_with("#[implements(")
                || t.starts_with("proof! {");
            if !erased {
                out.push_str(line);
            }
            out.push('\n');
        }
        std::fs::write(dst.join(e.file_name()), out).unwrap();
    }
}
