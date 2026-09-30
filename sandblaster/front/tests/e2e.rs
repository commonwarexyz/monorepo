//! End-to-end: the canonical output of sample programs compiles with rustc
//! and computes the same results as the (annotation-erased) source on
//! sample inputs. Both builds use overflow checks and debug assertions
//! (the debug-profile oracle of DESIGN.md §10.3), so any divergence in
//! arithmetic or indexing shows up as a panic or a different output.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use sandblaster_front::intrinsics;
use sandblaster_front::target::Arch;

/// A stand-in for the `sandblaster` facade for source builds: an empty
/// prelude and the `arch` helpers generated from the trusted templates.
fn stub_facade(dir: &Path) -> PathBuf {
    let mut src = String::from("#![allow(unused)]\npub mod prelude {}\npub mod arch {\n");
    for (arch, cfg) in [(Arch::Aarch64, "aarch64"), (Arch::X86_64, "x86_64")] {
        src.push_str(&format!("#[cfg(target_arch = \"{cfg}\")] pub mod {cfg} {{\n"));
        for h in intrinsics::helpers().iter().filter(|h| h.arch == arch) {
            let p = ty_src(&h.params[0]);
            src.push_str(&format!("#[target_feature(enable = \"{}\")] #[inline] pub fn {}(a: {p}) -> {} {{ {} }}\n", h.features.join(","), h.name, ty_src(&h.ret), h.template));
        }
        src.push_str("}\n");
    }
    src.push_str("}\n");
    let f = dir.join("sandblaster_stub.rs");
    std::fs::write(&f, src).unwrap();
    let out = dir.join("libsandblaster.rlib");
    let st = Command::new("rustc").args(["--edition", "2024", "--crate-type", "lib", "--crate-name", "sandblaster", "-o"]).arg(&out).arg(&f).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    out
}

fn ty_src(t: &sandblaster_front::hir::Ty) -> String {
    use sandblaster_front::hir::Ty;
    match t {
        Ty::Uint(u) => u.name().into(),
        Ty::Array(e, n) => format!("[{}; {n}]", ty_src(e)),
        Ty::Ref(e) => format!("&{}", ty_src(e)),
        Ty::Vector(v) => v.path(),
        other => panic!("{other:?}"),
    }
}

fn differential(sample: &str, main: &str, facade: bool) -> String {
    let dir = samples().join(sample);
    let root = dir.join("mod.rs");
    let c = check_dir(&root);
    assert!(c.ok(), "{}", c.render());
    let code = sandblaster_front::driver::stage::emit(&c, &format!("samples/{sample}/mod.rs")).unwrap();
    assert!(code.contains("UNVERIFIED (phase 1)"));
    assert!(!code.contains("forbid"), "generated code never carries forbid(unsafe_code)");
    let t = tmp(&format!("e2e-{sample}"));
    std::fs::write(t.join("sandblaster.rs"), &code).unwrap();
    let main_path = samples().join(main);
    let gen_main = t.join("gen_main.rs");
    std::fs::write(&gen_main, format!("include!({:?});\ninclude!({:?});\n", t.join("sandblaster.rs"), main_path)).unwrap();
    let raw = t.join("raw");
    erase_copy(&dir, &raw);
    let src_main = t.join("src_main.rs");
    std::fs::write(&src_main, format!("#[path = {:?}]\nmod raw;\n#[allow(unused_imports)]\nuse raw::*;\ninclude!({:?});\n", raw.join("mod.rs"), main_path)).unwrap();
    let a = rustc_run(&gen_main, &t.join("gen_bin"), &[]);
    let extra: Vec<String> = if facade { vec!["--extern".into(), format!("sandblaster={}", stub_facade(&t).display())] } else { vec![] };
    let b = rustc_run(&src_main, &t.join("src_bin"), &extra);
    assert_eq!(a, b, "canonical output and source disagree for {sample}");
    assert!(!a.is_empty());
    a
}

#[test]
fn basic_sample_agrees_with_source() {
    let out = differential("basic", "basic_main.rs", false);
    // rustc retries the guard for each or-alternative: pick(Some(1), Some(9)) = 9
    assert!(out.contains("pick 9 7 0 0"), "{out}");
}

#[test]
fn patterns_sample_agrees_with_source() {
    differential("patterns", "patterns_main.rs", false);
}

#[test]
fn types_sample_agrees_with_source() {
    differential("types", "types_main.rs", false);
}

#[test]
fn simd_sample_agrees_with_source() {
    if !cfg!(target_arch = "aarch64") {
        return;
    }
    differential("simd", "simd_main.rs", true);
}
