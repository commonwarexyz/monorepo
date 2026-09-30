//! Red-team regressions of the canonical printer and the round trip
//! (canon *Generated names*, roundtrip *Name resolution*), each an executed
//! reproduction of a confirmed finding:
//!
//! * identifiers that are one name to rustc but two to the checker — an
//!   NFD `pub use` renamed like an NFC local (`p37`), a raw variant `r#A` or
//!   an NFC/NFD pair next to an associated function `A` (`p35b`, `p35c`,
//!   `p38`), a raw `r#None` pattern, a raw keyword `r#gen` — are rejected
//!   by the front end (ASCII, non-raw identifiers only), and the round trip
//!   rejects the printed code on its own (identifier check, variant-first
//!   rule);
//! * a method named like a variant of its enum (`p08`: `<E>::A(e, x)` names
//!   the variant) is rejected by the front end and by the round trip;
//! * a `usize` match exhaustive only up to `usize::MAX` (`p17`, `p17b`) is
//!   non-exhaustive, as in rustc (E0004);
//! * vacuously verified dead code with a statically known overflow or
//!   division by zero (`p21`, `p22`) compiles without `--cap-lints` (the
//!   const-propagation lints are allowed in `mod __sandblaster`) and computes
//!   the kernel's results;
//! * source names spelled like the glue (`p05`: a root `struct
//!   __sandblaster`; `p28`: a root `type __arch`) are rejected by the front
//!   end, and like an optimizer clone (`p19c`: `pub use self::K as
//!   top__sha2;`; a const `top__portable`) are reported after optimization;
//!   the round trip rejects every such duplicate name independently.
//!
//! Since optimizer O4 the Σ1 driver specializes functions that tier 0
//! finds stuck (a guard becomes an `if`, a callee is inlined), which removes
//! the printed forms `p37` and `p35` are about; those reproductions run
//! with the driver kept off their subjects (a hints-cache test hook,
//! [`driver_off`]), and again with the default pipeline, whose driven
//! output must be capture-free and compute the source's results.
//!
//! Run: `cargo test -p sandblaster-front --test redteam_codegen -- --nocapture`.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sandblaster_front::driver::{self, Checked, VerifyOptions};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::hooks::{self, CacheEntry, OptTestHooks};
use sandblaster_front::opt::{OptOptions, Rung};
use sandblaster_front::target::TargetInfo;

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub mod a;\n";

fn files(root: &str, a: &str) -> Vec<(String, String)> {
    let mut v = vec![("r/mod.rs".to_string(), root.to_string())];
    if !a.is_empty() {
        v.push(("r/a.rs".to_string(), format!("use sandblaster::prelude::*;\n{a}")));
    }
    v
}

fn check(fs: &[(String, String)]) -> Checked {
    let mfs = MemFs::from_files(fs.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    driver::check(Path::new("r/mod.rs"), &mfs, &TargetInfo::aarch64_apple_darwin())
}

/// What the build pipeline made of a source.
#[derive(Debug)]
#[allow(dead_code)] // (the payloads are shown by `Debug` in failures)
enum Build {
    FrontEnd(String),
    Verification(String),
    Emitted { code: String, opt_errors: Vec<String>, roundtrip: Vec<String> },
}

/// Front end, verification, optimization (`strict`), printing, round trip.
fn build(fs: &[(String, String)], strict: bool) -> Build {
    let c = check(fs);
    if !c.ok() {
        return Build::FrontEnd(c.render());
    }
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &OptOptions { strict, ..Default::default() }, "r/mod.rs");
    if !built.v.proofs_ok {
        return Build::Verification(built.v.diags.render(&c.sm));
    }
    match built.emit {
        Some(Ok(em)) => Build::Emitted { code: em.code, opt_errors: em.opt.errors, roundtrip: em.roundtrip },
        other => panic!("no emission: {:?}", other.map(|r| r.err())),
    }
}

/// The accepted build's code (no optimizer error, round trip clean).
fn accepted(fs: &[(String, String)], strict: bool) -> String {
    match build(fs, strict) {
        Build::Emitted { code, opt_errors, roundtrip } if opt_errors.is_empty() && roundtrip.is_empty() => code,
        other => panic!("expected an accepted build, got {other:#?}"),
    }
}

/// The front end's rejection (panics if the source gets further).
fn front_end_rejects(fs: &[(String, String)]) -> String {
    let c = check(fs);
    assert!(!c.ok(), "the front end accepted the source");
    let r = c.render();
    println!("front end: {}", r.lines().take(4).collect::<Vec<_>>().join(" | "));
    r
}

/// The printed code, optimizer errors and round-trip failures of a source
/// the front end rejects, lowered anyway (exec-only elaboration): the round
/// trip must reject the printed code on its own. `front` must be the only
/// kind of front-end error (so the rest of the pipeline sees a well-formed
/// crate).
fn bypass(fs: &[(String, String)], strict: bool, front: &str) -> (String, Vec<String>, Vec<String>) {
    let (code, errors, rt, _) = bypass_with(fs, &OptOptions { strict, ..Default::default() }, front);
    (code, errors, rt)
}

/// [`bypass`] with the given options; also the functions the Σ1 driver
/// specialized.
fn bypass_with(fs: &[(String, String)], opts: &OptOptions, front: &str) -> (String, Vec<String>, Vec<String>, BTreeSet<String>) {
    let c = check(fs);
    let r = c.render();
    assert!(r.contains(front), "the front end must report {front:?}: {r}");
    let k = c.krate.as_ref().expect("a crate");
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.verified(), "the exec code elaborates: {}", out.diags.render(&c.sm));
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", opts).unwrap();
        println!("--- printed (front end bypassed) ---\n{}", em.code);
        println!("optimizer errors: {:#?}\nround trip failures: {:#?}", em.opt.errors, em.roundtrip);
        let driven = em.opt.fns.iter().filter(|f| f.rung == Some(Rung::Driven)).map(|f| f.name.clone()).collect();
        (em.code, em.opt.errors, em.roundtrip, driven)
    })
}

/// Optimizer options that keep the Σ1 driver off `fns`, through an existing
/// test hook (production builds have none): a hints-cache entry without a
/// candidate (the untampered conversion skeleton) makes tier 0 a function's
/// only rung, and tier 0 finds these functions stuck, so their source is
/// printed.
fn driver_off(fns: &BTreeSet<String>, strict: bool) -> OptOptions {
    let cache = fns.iter().map(|f| (f.clone(), CacheEntry { candidate: None, proof: hooks::refl_skeleton() })).collect();
    OptOptions { strict, hooks: Some(Arc::new(OptTestHooks { cache, ..Default::default() })), ..Default::default() }
}

/// [`bypass`] with the driver kept off every function it specializes, and
/// the default pipeline's (driven) result: `((code, optimizer errors,
/// round trip failures) undriven, (…, driven functions) driven)`.
#[allow(clippy::type_complexity)]
fn bypass_undriven(fs: &[(String, String)], strict: bool, front: &str) -> ((String, Vec<String>, Vec<String>), (String, Vec<String>, Vec<String>, BTreeSet<String>)) {
    let driven = bypass_with(fs, &OptOptions { strict, ..Default::default() }, front);
    let (code, errors, rt, left) = bypass_with(fs, &driver_off(&driven.3, strict), front);
    assert!(left.is_empty(), "the hook did not keep the driver off {left:?}");
    ((code, errors, rt), driven)
}

/// Compiles the generated `code` (with `main` printing each call) — with
/// rustc's default lint levels unless `cap_lints` — and runs it.
fn run(tag: &str, code: &str, calls: &[&str], cap_lints: bool) -> Result<Vec<String>, String> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("redteam-codegen").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
    let mut main = String::from("include!(\"sandblaster.rs\");\nfn main() {\n");
    for call in calls {
        main.push_str(&format!("    println!(\"{{:?}}\", {call});\n"));
    }
    main.push_str("}\n");
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let mut cmd = Command::new("rustc");
    cmd.args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on"]);
    if cap_lints {
        cmd.args(["--cap-lints", "allow"]);
    }
    let st = cmd.arg("-o").arg(dir.join("bin")).arg(dir.join("main.rs")).output().expect("rustc");
    if !st.status.success() {
        return Err(String::from_utf8_lossy(&st.stderr).to_string());
    }
    let out = Command::new(dir.join("bin")).output().unwrap();
    if !out.status.success() {
        return Err(format!("run failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// The kernel's reference results of `calls` (`path|json args`).
fn kernel(fs: &[(String, String)], calls: &[&str]) -> Vec<String> {
    let c = check(fs);
    calls
        .iter()
        .map(|call| {
            let (p, a) = call.split_once('|').unwrap();
            let r = driver::stage::eval_json(&c, p, a).unwrap_or_else(|e| panic!("kernel eval of {call}: {e}"));
            r.trim_matches('"').to_string()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// identifiers: one name to rustc, two to the checker
// ---------------------------------------------------------------------------

/// p37: the local is the precomposed `y\u{e9}`, the re-export `l1_ye\u{301}`
/// (NFD) — rustc NFC-normalizes both to `l1_y\u{e9}`, the printed binding's
/// name, and reads the arm as a constant pattern (kernel `f(4) = 4`, rustc
/// `0`).
#[test]
fn p37_nfc_reexport_capture() {
    let a = "pub const K: u32 = 5;\n\npub fn f(x: u32) -> u32 {\n    match x {\n        y\u{e9} if y\u{e9} > 3 => y\u{e9},\n        _ => 0,\n    }\n}\n\npub use self::K as l1_ye\u{301};\n";
    let fs = files(ROOT, a);
    let r = front_end_rejects(&fs);
    assert!(r.contains("non-ASCII identifier `y\u{e9}`") && r.contains("non-ASCII identifier `l1_ye\u{301}`"), "{r}");
    // the round trip alone: the printed identifiers are not ASCII (the
    // driver kept off `f`, whose guard binding is printed)
    let ((code, _, rt), (dcode, _, drt, driven)) = bypass_undriven(&fs, true, "non-ASCII identifier");
    assert!(code.contains("l1_y\u{e9} if l1_y\u{e9} > 3u32"), "{code}");
    assert!(rt.iter().any(|f| f.contains("the identifier `l1_y\u{e9}` of the printed code is not ASCII")), "{rt:#?}");
    assert!(rt.iter().any(|f| f.contains("the identifier `l1_ye\u{301}` of the printed code is not ASCII")), "{rt:#?}");
    // the default pipeline drives `f` (`if l0_x > 3u32 { l0_x } else { 0u32 }`):
    // no binding is printed, so nothing is captured and rustc computes the
    // source's results; the round trip still rejects the re-export's name
    assert!(driven.contains("crate::a::f"), "{driven:?}\n{dcode}");
    assert!(!dcode.contains("l1_y\u{e9} if") && !dcode.contains("l1_ye\u{301} if"), "{dcode}");
    assert!(drt.iter().any(|f| f.contains("the identifier `l1_ye\u{301}` of the printed code is not ASCII")), "{drt:#?}");
    assert_eq!(run("p37-driven", &dcode, &["a::f(4)", "a::f(2)"], true).unwrap(), ["4", "0"], "{dcode}");
}

/// p35b / p35c: `enum E { r#A(u32), B }` and `fn A`: the checker keys the
/// variant `r#A` and the function `A` apart (`E::A(x)` is the function),
/// the printer strips `r#`, and rustc reads `<E>::A(l0_x)` as the variant
/// (kernel `g(7) = 100`, rustc `7`) — in strict mode (p35c, both branches
/// `E::B`) and in the default mode (p35b).
#[test]
fn p35_raw_variant_vs_assoc_fn() {
    let p35c = "#[derive(Clone, Copy)]\npub enum E {\n    r#A(u32),\n    B,\n}\n\nimpl E {\n    pub fn A(x: u32) -> E {\n        match x {\n            0 => E::B,\n            _ => E::B,\n        }\n    }\n}\n\npub fn g(x: u32) -> u32 {\n    match E::A(x) {\n        E::r#A(v) => v,\n        E::B => 100,\n    }\n}\n";
    let p35b = "#[derive(Clone, Copy)]\npub enum E {\n    r#A(u32),\n    B,\n}\n\nimpl E {\n    pub fn A(x: u32) -> E {\n        E::B\n    }\n}\n\npub fn g(x: u32) -> u32 {\n    match E::A(x) {\n        E::r#A(v) => v,\n        E::B => 100,\n    }\n}\n";
    for (tag, src, strict) in [("p35c", p35c, true), ("p35b", p35b, false)] {
        println!("=== {tag}");
        let fs = files(ROOT, src);
        let r = front_end_rejects(&fs);
        assert!(r.contains("raw identifier `r#A`"), "{tag}: {r}");
        // the round trip alone: `<E>::A(..)` names the variant (the driver
        // kept off `g`, which it would reduce to `100u32`)
        let ((code, _, rt), (dcode, _, drt, driven)) = bypass_undriven(&fs, strict, "raw identifier `r#A`");
        assert!(code.contains("pub fn A(") && code.contains(">::A(l0_x)"), "{tag}: {code}");
        assert!(rt.iter().any(|f| f.contains("::a::E>::A` names the variant `A` of the enum in rustc")), "{tag}: {rt:#?}");
        // the default pipeline drives `g` (to `100u32`, or keeping the call
        // of `A`): either the round trip rejects a printed `<E>::A(..)` on its
        // own, or nothing printed names the variant and rustc computes the
        // kernel's `g(7) = 100`
        assert!(driven.contains("crate::a::g"), "{tag}: {driven:?}\n{dcode}");
        if drt.is_empty() {
            assert!(!dcode.contains(">::A("), "{tag}: {dcode}");
            assert_eq!(run(&format!("{tag}-driven"), &dcode, &["a::g(7)", "a::g(0)"], true).unwrap(), ["100", "100"], "{tag}: {dcode}");
        } else {
            assert!(drt.iter().any(|f| f.contains("::a::E>::A` names the variant `A` of the enum in rustc")), "{tag}: {drt:#?}");
        }
    }
}

/// p38: the variant `A\u{e9}` (NFC) and the associated function
/// `Ae\u{301}` (NFD) are one name to rustc.
#[test]
fn p38_nfc_variant_vs_assoc_fn() {
    let a = "#[derive(Clone, Copy)]\npub enum E {\n    A\u{e9}(u32),\n    B,\n}\n\nimpl E {\n    pub fn Ae\u{301}(x: u32) -> E {\n        match x {\n            0 => E::B,\n            _ => E::B,\n        }\n    }\n}\n\npub fn g(x: u32) -> u32 {\n    match E::Ae\u{301}(x) {\n        E::A\u{e9}(v) => v,\n        E::B => 100,\n    }\n}\n";
    let fs = files(ROOT, a);
    let r = front_end_rejects(&fs);
    assert!(r.contains("non-ASCII identifier `A\u{e9}`") && r.contains("non-ASCII identifier `Ae\u{301}`"), "{r}");
    let (_, _, rt) = bypass(&fs, true, "non-ASCII identifier");
    assert!(rt.iter().any(|f| f.contains("`Ae\u{301}` of the printed code is not ASCII")), "{rt:#?}");
}

/// Raw identifiers elsewhere: `r#None` (the checker read a binding, rustc
/// the unit variant `None`: kernel `f(Some(5)) = 0`, the source read as
/// Rust `5`) and `r#gen` (printed `gen`, a Rust 2024 keyword); a plain
/// `gen` too.
#[test]
fn raw_identifiers_and_reserved_keywords() {
    let cases = [
        ("r#None pattern", "pub fn f(o: Option<u32>) -> u32 {\n    match o {\n        r#None => 0,\n        Some(v) => v,\n    }\n}\n", "raw identifier `r#None`"),
        ("r#gen function", "pub fn r#gen(x: u32) -> u32 {\n    x\n}\n", "raw identifier `r#gen`"),
        ("gen local", "pub fn f(x: u32) -> u32 {\n    let gen = x;\n    gen\n}\n", "`gen` is a reserved keyword"),
    ];
    for (label, src, needle) in cases {
        let r = front_end_rejects(&files(ROOT, src));
        assert!(r.contains(needle), "{label}: {r}");
    }
}

// ---------------------------------------------------------------------------
// methods named like variants
// ---------------------------------------------------------------------------

/// p08: `impl E { pub fn A(self, x: u32) -> u32 }` beside the variant
/// `A(u32)`, called `e.A(x)` in a generic function: printed `<E>::A(l0_e,
/// l0_x)`, which rustc reads as the variant constructor (E0061).
#[test]
fn p08_method_named_like_variant() {
    let a = "#[derive(Clone, Copy)]\npub enum E {\n    A(u32),\n    B,\n}\n\nimpl E {\n    pub fn A(self, x: u32) -> u32 {\n        x.wrapping_add(1)\n    }\n}\n\npub fn g<T: Copy>(x: u32, t: T) -> u32 {\n    let e = E::B;\n    e.A(x)\n}\n\npub fn h(x: u32) -> u32 {\n    g(x, true)\n}\n";
    let fs = files(ROOT, a);
    let r = front_end_rejects(&fs);
    assert!(r.contains("the associated function `crate::a::E::A` has the name of the variant `crate::a::E::A`"), "{r}");
    let (code, _, rt) = bypass(&fs, true, "has the name of the variant");
    assert!(code.contains(">::A(l") && code.contains(", l0_x)"), "{code}");
    assert!(rt.iter().any(|f| f.contains("names the variant `A` of the enum in rustc")), "{rt:#?}");
    // the same enum with the method renamed builds and computes the kernel's results
    let ok = a.replace("pub fn A(self", "pub fn a(self").replace("e.A(x)", "e.a(x)");
    let fs = files(ROOT, &ok);
    let code = accepted(&fs, true);
    assert_eq!(run("p08-renamed", &code, &["a::h(7)"], false).unwrap(), kernel(&fs, &["a::h|[7]"]));
}

// ---------------------------------------------------------------------------
// usize exhaustiveness
// ---------------------------------------------------------------------------

/// p17 / p17b: `0..=9` and `10..=18446744073709551615` cover `usize` on a
/// 64-bit target, but rustc treats `usize` as open-ended (E0004,
/// `usize::MAX..` not covered); the phase-3 printer emits no fallback arm.
#[test]
fn p17_usize_range_exhaustiveness() {
    let p17 = "pub fn f(x: usize) -> u32 {\n    match x {\n        0..=9 => 1,\n        10..=18446744073709551615 => 2,\n    }\n}\n";
    let p17b = "pub fn f<T: Copy>(x: usize, t: T) -> u32 {\n    match x {\n        0..=9 => 1,\n        10..=18446744073709551615 => 2,\n    }\n}\n\npub fn g(x: usize) -> u32 {\n    f(x, true)\n}\n";
    for (tag, src) in [("p17", p17), ("p17b", p17b)] {
        let r = front_end_rejects(&files(ROOT, src));
        assert!(r.contains("non-exhaustive patterns: `usize::MAX..` not covered"), "{tag}: {r}");
    }
    // nested in a tuple, and without a pattern reaching `usize::MAX`
    let nested = "pub fn f(x: usize, b: bool) -> u32 {\n    match (x, b) {\n        (0..=9, _) => 1,\n        (10..=18446744073709551615, true) => 2,\n        (_, false) => 3,\n    }\n}\n";
    let r = front_end_rejects(&files(ROOT, nested));
    assert!(r.contains("non-exhaustive patterns: `(usize::MAX.., true)` not covered"), "{r}");
    let partial = "pub fn f(x: usize) -> u32 {\n    match x {\n        0..=9 => 1,\n    }\n}\n";
    let r = front_end_rejects(&files(ROOT, partial));
    assert!(r.contains("non-exhaustive patterns: `10..` not covered"), "{r}");
    // a wildcard covers `usize`; fixed-width types stay exhaustive by ranges
    let ok = "pub fn f(x: usize) -> u32 {\n    match x {\n        0..=9 => 1,\n        _ => 2,\n    }\n}\n\npub fn g(x: u64) -> u32 {\n    match x {\n        0..=9 => 1,\n        10..=18446744073709551615 => 2,\n    }\n}\n";
    let fs = files(ROOT, ok);
    let code = accepted(&fs, true);
    let calls = ["a::f(3)", "a::f(300)", "a::g(3)", "a::g(1000)"];
    assert_eq!(run("p17-ok", &code, &calls, false).unwrap(), ["1", "2", "1", "2"]);
    assert_eq!(kernel(&fs, &["a::f|[3]", "a::f|[300]", "a::g|[3]", "a::g|[1000]"]), ["1", "2", "1", "2"]);
}

// ---------------------------------------------------------------------------
// deny-level lints on vacuously verified dead code
// ---------------------------------------------------------------------------

/// p21 / p22: `if x > 5 && x < 3 { x / 0 }` and `{ 200u8 + 100u8 }` verify
/// (the obligations hold under the contradictory guard) and must compile
/// with rustc's default lint levels (no `--cap-lints`): `unconditional_panic`
/// and `arithmetic_overflow` are deny-by-default const-propagation lints.
#[test]
fn p21_p22_dead_code_lints() {
    let p21 = "pub fn f<T: Copy>(x: u32, t: T) -> u32 {\n    if x > 5 && x < 3 { x / 0 } else { x }\n}\n\npub fn g(x: u32) -> u32 {\n    f(x, true)\n}\n";
    let p22 = "pub fn f<T: Copy>(x: u8, t: T) -> u8 {\n    if x > 5 && x < 3 { 200u8 + 100u8 } else { x }\n}\n\npub fn g(x: u8) -> u8 {\n    f(x, true)\n}\n";
    for (tag, src) in [("p21", p21), ("p22", p22)] {
        let fs = files(ROOT, src);
        let code = accepted(&fs, true);
        assert!(code.contains("#[allow(arithmetic_overflow, unconditional_panic,"), "{code}");
        let got = run(tag, &code, &["a::g(4)", "a::g(6)", "a::g(2)"], false).unwrap_or_else(|e| panic!("{tag}: rustc rejects the verified output with default lint levels:\n{e}\n{code}"));
        assert_eq!(got, ["4", "6", "2"], "{tag}");
        assert_eq!(kernel(&fs, &["a::g|[4]", "a::g|[6]", "a::g|[2]"]), got, "{tag}");
    }
}

// ---------------------------------------------------------------------------
// glue and optimizer names
// ---------------------------------------------------------------------------

/// A multiversioned call tree (the `sha2` variant set on aarch64): clones
/// `add4__sha2` / `top__sha2`, portable `top__portable`, dispatcher `top`,
/// the `__arch` helpers and the `__dispatch` module.
const MV: &str = r#"
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::vaddq_u32;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u32x4, store_u32x4};

pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[implements(crate::a::add4)]
pub fn add4_sha2(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

pub fn top(x: [u32; 4], k: u32) -> u32 {
    let r = add4(x, [1, 2, 3, 4]);
    r[0].wrapping_add(k)
}
"#;

/// p05: a root `pub struct __sandblaster` is exported at the top level beside
/// `mod __sandblaster` (E0255).
#[test]
fn p05_root_struct_named_sandblaster() {
    let root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[derive(Clone, Copy)]\npub struct __sandblaster {\n    pub x: u32,\n}\n\npub fn f(x: u32) -> u32 {\n    x\n}\n";
    let fs = files(root, "");
    let r = front_end_rejects(&fs);
    assert!(r.contains("the name `__sandblaster` is reserved for the generated code"), "{r}");
    let (_, opt_errors, rt) = bypass(&fs, true, "is reserved for the generated code");
    assert!(opt_errors.iter().any(|e| e.contains("the top level of the generated file") && e.contains("`__sandblaster`")), "{opt_errors:#?}");
    assert!(rt.iter().any(|f| f.contains("the top level of the generated file: `__sandblaster` is defined twice in the type namespace")), "{rt:#?}");
}

/// p28: a root `pub type __arch = u32;` beside the helpers' glue module
/// `__sandblaster::__arch` (E0428; the helper calls would resolve into the
/// alias).
#[test]
fn p28_root_alias_named_arch() {
    let root = format!("{ROOT}pub type __arch = u32;\n");
    let fs = files(&root, MV);
    let r = front_end_rejects(&fs);
    assert!(r.contains("the name `__arch` is reserved for the generated code"), "{r}");
    let (code, opt_errors, rt) = bypass(&fs, true, "is reserved for the generated code");
    assert!(code.contains("pub(crate) mod __arch {"), "{code}");
    assert!(opt_errors.iter().any(|e| e.contains("module `crate`") && e.contains("`__arch`")), "{opt_errors:#?}");
    assert!(rt.iter().any(|f| f.contains("`crate::__sandblaster`: `__arch` is defined twice in the type namespace")), "{rt:#?}");
}

/// p19c: `pub use self::K as top__sha2;` beside the multiversioned clone
/// `top__sha2` (E0255): reported after optimization with what to rename,
/// and rejected by the round trip on its own. Source items named like a
/// clone or a portable function are never an accepted build with two items
/// of one name: reported (the optimizer's own checks, the collision check,
/// the round trip), or printed without the generated item and computing the
/// kernel's results — in strict and in default mode.
#[test]
fn p19c_source_names_of_optimizer_items() {
    // the clean tree: every generated name present
    let fs = files(ROOT, MV);
    let code = accepted(&fs, true);
    assert!(code.contains("fn top__sha2(") && code.contains("fn top__portable(") && code.contains("pub fn top(a0__arg"), "{code}");
    assert_eq!(run("p19-clean", &code, &["a::top([7, 0, 0, 0], 3)"], false).unwrap(), ["11"]);
    // the checker's probe
    let fs = files(ROOT, &format!("{MV}\npub const K: u32 = 5;\npub use self::K as top__sha2;\n"));
    for strict in [true, false] {
        match build(&fs, strict) {
            Build::Emitted { opt_errors, roundtrip, .. } => {
                println!("strict {strict}: optimizer errors: {opt_errors:#?}\nround trip: {roundtrip:#?}");
                assert!(opt_errors.iter().any(|e| e.contains("module `crate::a`: the optimizer's multiversioned clone `crate::a::top__sha2` and the re-export `crate::a::top__sha2` (a `pub use` of the source) have the same name `top__sha2` in the value namespace") && e.contains("rename the source's `top__sha2`")), "{opt_errors:#?}");
                assert!(roundtrip.iter().any(|f| f.contains("`crate::__sandblaster::a`: `top__sha2` is defined twice in the value namespace")), "{roundtrip:#?}");
            }
            other => panic!("expected the collision to be reported, got {other:#?}"),
        }
    }
    // source items spelled like generated ones
    let cases = [("const clone name", "top__sha2"), ("const portable name", "top__portable"), ("fn clone name", "top__sha2")];
    for (label, name) in cases {
        let item = if label.starts_with("fn") { format!("pub fn {name}(x: u32) -> u32 {{\n    x\n}}\n") } else { format!("#[allow(non_upper_case_globals)]\npub const {name}: u32 = 5;\n") };
        let fs = files(ROOT, &format!("{MV}\n{item}"));
        for strict in [true, false] {
            println!("=== {label} (strict {strict})");
            match build(&fs, strict) {
                Build::Emitted { code, opt_errors, roundtrip } if opt_errors.is_empty() && roundtrip.is_empty() => {
                    let decls = code.matches(&format!(" {name}(")).count() + code.matches(&format!(" {name}:")).count();
                    assert_eq!(decls, 1, "{label}: exactly one item named `{name}`:\n{code}");
                    let calls = ["a::top([7, 0, 0, 0], 3)"];
                    assert_eq!(run(&format!("p19-{name}-{strict}"), &code, &calls, false).unwrap(), kernel(&fs, &["a::top|[[7,0,0,0],3]"]), "{label}");
                    println!("    accepted without the generated `{name}`");
                }
                Build::Emitted { opt_errors, roundtrip, .. } => {
                    println!("    optimizer errors: {opt_errors:#?}\n    round trip: {roundtrip:#?}");
                    assert!(opt_errors.iter().chain(&roundtrip).any(|e| e.contains(name)), "{label}: rejected without naming `{name}`");
                    if let Some(e) = opt_errors.iter().find(|e| e.contains("have the same name")) {
                        assert!(e.contains(&format!("rename the source's `{name}`")), "{e}");
                    }
                }
                other => panic!("{label}: {other:#?}"),
            }
        }
    }
}
