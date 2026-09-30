//! Golden tests of the canonical printer (DESIGN.md §2, §8.3): the emitted
//! code for each sample is compared with `tests/golden/<sample>.<arch>.rs`
//! and compiled with rustc. Run with `SANDBLASTER_BLESS=1` to update.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;
use sandblaster_front::driver;
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn golden(sample: &str, target: &TargetInfo, triple: &str) {
    let root = samples().join(sample).join("mod.rs");
    let c = driver::check(&root, &RealFs, target);
    assert!(c.ok(), "{}", c.render());
    let code = driver::stage::emit(&c, &format!("samples/{sample}/mod.rs")).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/{sample}.{}.rs", target.arch.name()));
    if std::env::var("SANDBLASTER_BLESS").as_deref() == Ok("1") {
        std::fs::write(&path, &code).unwrap();
    } else {
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {}; run with SANDBLASTER_BLESS=1", path.display()));
        if expected != code {
            let diff_line = expected.lines().zip(code.lines()).position(|(a, b)| a != b).unwrap_or(0);
            panic!("golden mismatch for {} at line {}:\n  expected: {:?}\n  actual:   {:?}\n(run with SANDBLASTER_BLESS=1 to update)", path.display(), diff_line + 1, expected.lines().nth(diff_line), code.lines().nth(diff_line));
        }
    }
    // the printed code must compile (as the body of a library crate)
    let t = tmp(&format!("golden-{sample}-{}", target.arch.name()));
    std::fs::write(t.join("sandblaster.rs"), &code).unwrap();
    std::fs::write(t.join("lib.rs"), "include!(\"sandblaster.rs\");\n").unwrap();
    let out = Command::new("rustc")
        .args(["--edition", "2024", "--crate-type", "lib", "--target", triple, "-D", "warnings", "-o"])
        .arg(t.join("lib.rlib"))
        .arg(t.join("lib.rs"))
        .output()
        .unwrap();
    assert!(out.status.success(), "golden {sample} does not compile for {triple}:\n{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn golden_basic() {
    golden("basic", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
}

#[test]
fn golden_patterns() {
    golden("patterns", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
}

#[test]
fn golden_types() {
    golden("types", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
}

#[test]
fn golden_simd_aarch64() {
    golden("simd", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
}

#[test]
fn golden_simd_x86_64() {
    // the aarch64-only module is configured out, exactly as rustc would
    golden("simd", &TargetInfo::x86_64_apple_darwin(), "x86_64-apple-darwin");
}
