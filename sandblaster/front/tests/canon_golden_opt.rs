//! Golden tests of the phase-3 printer (DESIGN.md §2, §8.3, §9.3): the
//! optimized and round-tripped stage output (`driver::stage`, header
//! `STATUS: STAGE OUTPUT`: the §15 gates are not part of these tests) of
//! the `simd` sample (a
//! NEON variant `add4` of `add4_portable`: `VariantEquiv` by `BvRefl`,
//! dispatched statically on `aarch64-apple-darwin`; the SHA2 `mix` kernel;
//! unchecked indexing) and of the `e0` sample (checked arithmetic printed
//! through the `crate::__rt::chk` helpers, E0) is compared with
//! `tests/golden/opt_<sample>.<arch>.rs` and compiled with rustc under
//! `-D warnings`, with and without debug assertions (the two profiles of the
//! helpers). `SANDBLASTER_BLESS=1` updates the files.

mod common;

use std::path::Path;
use std::process::Command;

use common::*;
use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::target::TargetInfo;

fn golden(sample: &str, target: &TargetInfo, triple: &str) -> String {
    let root = samples().join(sample).join("mod.rs");
    let c = driver::check(&root, &RealFs, target);
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &opts, &OptOptions { strict: true, ..Default::default() }, &format!("samples/{sample}/mod.rs"));
    assert!(built.v.proofs_ok, "the sample must verify");
    let em = built.emit.unwrap().unwrap();
    assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "{:?}", em.roundtrip);
    let code = em.code;
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/opt_{sample}.{}.rs", target.arch.name()));
    if std::env::var("SANDBLASTER_BLESS").as_deref() == Ok("1") {
        std::fs::write(&path, &code).unwrap();
    } else {
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {}; run with SANDBLASTER_BLESS=1", path.display()));
        if expected != code {
            let diff_line = expected.lines().zip(code.lines()).position(|(a, b)| a != b).unwrap_or(0);
            panic!("golden mismatch for {} at line {}:\n  expected: {:?}\n  actual:   {:?}\n(run with SANDBLASTER_BLESS=1 to update)", path.display(), diff_line + 1, expected.lines().nth(diff_line), code.lines().nth(diff_line));
        }
    }
    let t = tmp(&format!("golden-opt-{sample}-{}", target.arch.name()));
    std::fs::write(t.join("sandblaster.rs"), &code).unwrap();
    std::fs::write(t.join("lib.rs"), "include!(\"sandblaster.rs\");\n").unwrap();
    for da in ["debug-assertions=off", "debug-assertions=on"] {
        let out = Command::new("rustc")
            .args(["--edition", "2024", "--crate-type", "lib", "--target", triple, "-D", "warnings", "-C", da, "-o"])
            .arg(t.join("lib.rlib"))
            .arg(t.join("lib.rs"))
            .output()
            .unwrap();
        assert!(out.status.success(), "golden opt_{sample} does not compile for {triple} ({da}):\n{}", String::from_utf8_lossy(&out.stderr));
    }
    code
}

#[test]
fn golden_opt_e0_aarch64() {
    let code = golden("e0", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
    // E0: proven arithmetic is printed through the checked-arithmetic helpers
    assert!(code.contains("crate::__rt::chk::") && code.contains("\nmod __rt {\n"), "{code}");
}

#[test]
fn golden_opt_simd_aarch64() {
    let code = golden("simd", &TargetInfo::aarch64_apple_darwin(), "aarch64-apple-darwin");
    // the NEON variant is proven and dispatched at the boundary
    assert!(code.contains("pub fn add4_portable(a0__arg"), "dispatcher:\n{code}");
    assert!(code.contains("fn add4_portable__portable("), "renamed portable function:\n{code}");
    assert!(code.contains("#[cfg(all(target_arch = \"aarch64\", target_endian = \"little\", target_feature = \"neon\"))]"));
}

#[test]
fn golden_opt_simd_x86_64() {
    // no variant on x86_64 (the NEON module is configured out)
    let code = golden("simd", &TargetInfo::x86_64_apple_darwin(), "x86_64-apple-darwin");
    assert!(!code.contains("__dispatch"), "{code}");
}
