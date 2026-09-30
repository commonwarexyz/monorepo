//! §15 S2 types through the optimizer's O5 paths (merge of S2 into main
//! after O5): invariant types (`Irr` constructor fields, free facts) and
//! `#[ghost]` parameters (the `Irr` ghost bundle) in
//!
//! * callee summaries instantiated at call sites (case-of-case over a
//!   callee returning an invariant type; the varint reader into a checked
//!   `Loc` constructor),
//! * polyvariant call-site helpers with an invariant-typed dynamic
//!   parameter,
//! * a fold helper whose recursion carries an invariant-typed value,
//! * multiversion clones (`clone_equiv`) of a function with a ghost
//!   parameter, and driven callers of ghost-parameter callees (inlined, or
//!   kept as a call: the driven candidate then falls back without a fault),
//! * the hints-only proof cache: a warm build equals the cold one, also
//!   after the invariant is edited or added under a warm cache (strict: a
//!   stale entry is a miss, never a rejected hit).
//!
//! §15 S3 through the same paths (merge of S3 into main after O5 and S2):
//!
//! * deterministic budgets (DESIGN.md §15.8, §8.2 item 10): a safety net
//!   that trips inside the optimizer forces a fallback, so the build fails
//!   with `error[resource]` and is not verified (nothing is emitted);
//! * callee contract facts as hints (a contract mentioning a callee with an
//!   `ensures`), a law that fully specifies a section (its `complete_p`
//!   lemma in the environment) and the proof cache: warm = cold after the
//!   callee's `ensures` is edited and after the law is added, and the law
//!   and its section change nothing that is emitted.
//!
//! Every build is strict with no optimizer warning and a clean round trip;
//! the emitted code is compiled with rustc next to the plain-Rust source and
//! compared on many inputs (debug and release).
//!
//! `cargo test -p sandblaster-front --test spec15_opt_interplay -- --test-threads=2`

use std::path::{Path, PathBuf};
use std::process::Command;

use sandblaster_front::driver::{self, OptimizedEmit, ProverSet, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};
use sandblaster_front::target::TargetInfo;

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

fn build(src: &str, strict: bool, cache: Option<&Path>) -> OptimizedEmit {
    let src = format!("{HEADER}{src}");
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &opts, &OptOptions { strict, cache_dir: cache.map(|p| p.to_path_buf()), ..Default::default() }, "r/mod.rs");
    assert!(built.v.proofs_ok, "not verified:\n{}", built.v.diags.render(&c.sm));
    built.emit.expect("optimized").expect("optimizer ran")
}

fn show(tag: &str, em: &OptimizedEmit) {
    println!("==== {tag}: errors {:?}\n     warnings {:?}\n     roundtrip {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    for f in &em.opt.fns {
        match &f.outcome {
            Outcome::Specialized { nodes, .. } => println!("  {}: Specialized {nodes} nodes {:?} {:?}", f.name, f.link, f.rung),
            Outcome::Unspecialized { reason, failure } => println!("  {}: Unspecialized (failure {failure}): {}", f.name, reason.chars().take(300).collect::<String>()),
        }
        for c in &f.candidates {
            println!("      {:?} chosen={} {:?}: {}", c.rung, c.chosen, c.rejected_by, c.reason.chars().take(400).collect::<String>());
        }
    }
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("spec15-opt-interplay").join(tag);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Compiles the emitted code next to `reference` (plain Rust) and compares
/// `calls` (with `M::` standing for the module) in debug and release.
fn differential(tag: &str, em: &OptimizedEmit, reference: &str, calls: &[String]) -> Vec<String> {
    let dir = tmpdir(tag);
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    let mut main = String::from("#![allow(warnings)]\ninclude!(\"sandblaster.rs\");\nmod reference {\n");
    main.push_str(reference);
    main.push_str("\n}\nfn main() {\n");
    for call in calls {
        let a = call.replace("M::", "crate::");
        let b = call.replace("M::", "crate::reference::");
        main.push_str(&format!("    {{ let a = format!(\"{{:?}}\", {a}); let b = format!(\"{{:?}}\", {b}); if a != b {{ println!(\"MISMATCH {}: emitted {{a}} source {{b}}\"); }} }}\n", call.replace('"', "\\\"").replace('{', "{{").replace('}', "}}")));
    }
    main.push_str("    println!(\"done\");\n}\n");
    std::fs::write(dir.join("main.rs"), &main).unwrap();
    let mut out = Vec::new();
    for release in [false, true] {
        let exe = dir.join(if release { "gen_rel" } else { "gen_dbg" });
        let mut cmd = Command::new("rustc");
        cmd.args(["--edition", "2024", "--cap-lints", "allow", "-o"]).arg(&exe).arg(dir.join("main.rs"));
        if release {
            cmd.args(["-C", "opt-level=2", "-C", "debug-assertions=off", "-C", "overflow-checks=off"]);
        } else {
            cmd.args(["-C", "overflow-checks=on", "-C", "debug-assertions=on"]);
        }
        let st = cmd.output().expect("rustc");
        if !st.status.success() {
            out.push(format!("COMPILE ERROR: {}", String::from_utf8_lossy(&st.stderr).chars().take(3000).collect::<String>()));
            return out;
        }
        let run = Command::new(&exe).output().unwrap();
        let stdout = String::from_utf8_lossy(&run.stdout).to_string();
        if !run.status.success() {
            out.push(format!("RUN FAILED: {stdout} {}", String::from_utf8_lossy(&run.stderr)));
        }
        out.extend(stdout.lines().filter(|l| l.starts_with("MISMATCH")).map(String::from));
        if !stdout.contains("done") {
            out.push("did not finish".into());
        }
    }
    out
}

fn ok(tag: &str, em: &OptimizedEmit) {
    show(tag, em);
    assert!(em.opt.errors.is_empty(), "{tag}: optimizer errors {:?}", em.opt.errors);
    assert!(em.opt.warnings.is_empty(), "{tag}: optimizer warnings {:?}", em.opt.warnings);
    assert!(em.roundtrip.is_empty(), "{tag}: round trip {:?}\n{}", em.roundtrip, em.code);
}

fn report<'a>(em: &'a OptimizedEmit, n: &str) -> &'a sandblaster_front::opt::FnReport {
    em.opt.fns.iter().find(|f| f.name == n).unwrap_or_else(|| panic!("no report for {n}"))
}

fn driven(em: &OptimizedEmit, n: &str) -> bool {
    let f = report(em, n);
    matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_)))
}

/// The chosen candidate's reason (the process tree's shape for a driven one).
fn reason(em: &OptimizedEmit, n: &str) -> String {
    report(em, n).candidates.iter().find(|c| c.chosen).map(|c| c.reason.clone()).unwrap_or_default()
}

fn outcome(em: &OptimizedEmit, n: &str) -> String {
    em.opt.fns.iter().find(|f| f.name == n).map(|f| format!("{:?} {:?}", f.rung, f.link)).unwrap_or_else(|| "absent".into())
}

// ---------------------------------------------------------------------
// callee summaries over invariant types (varint reader into a Location)
// ---------------------------------------------------------------------

const LOC: &str = r#"
pub const MAX: u64 = 1u64 << 62u32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[invariant(self.0 <= MAX)]
pub struct Loc(u64);

impl Loc {
    pub fn new(x: u64) -> Option<Loc> {
        if x <= MAX { Some(Loc(x)) } else { None }
    }
    pub fn get(self) -> u64 { self.0 }
}
"#;

const LOC_REF: &str = r#"
pub const MAX: u64 = 1u64 << 62u32;
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Loc(u64);
impl Loc {
    pub fn new(x: u64) -> Option<Loc> { if x <= MAX { Some(Loc(x)) } else { None } }
    pub fn get(self) -> u64 { self.0 }
}
"#;

const PROG_A: &str = r#"
fn uint64_finish(ok: bool, value: u64, rest: &[u8]) -> Option<(u64, &[u8])> {
    if ok { Some((value, rest)) } else { None }
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn uint64_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        let ok = (fuel != 1 || h < 2) && (shift == 0 || h != 0);
        uint64_finish(ok, value, t)
    } else {
        uint64_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> {
    uint64_go(10, xs, 0, 0)
}

/// the range check through the invariant type's checked constructor
pub fn location(xs: &[u8]) -> Option<Loc> {
    let (value, _rest) = uint64(xs)?;
    Loc::new(value)
}

/// a caller of `location`: its result's invariant decides the check
pub fn loc_small(xs: &[u8]) -> Option<u64> {
    let l = location(xs)?;
    if l.0 <= MAX { Some(l.0 + 1) } else { None }
}

fn dec(l: Loc) -> Option<Loc> {
    if l.0 == 0 { None } else { Some(Loc(l.0 - 1)) }
}

/// case-of-case over a callee returning the invariant type
pub fn dec2(l: Loc) -> Option<u64> {
    let a = dec(l)?;
    let b = dec(a)?;
    if b.0 < MAX { Some(b.0 + a.0) } else { None }
}
"#;

const PROG_A_REF: &str = r#"
fn uint64_finish(ok: bool, value: u64, rest: &[u8]) -> Option<(u64, &[u8])> { if ok { Some((value, rest)) } else { None } }
fn uint64_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 { return None; }
    let [h, t @ ..] = xs else { return None; };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 { let ok = (fuel != 1 || h < 2) && (shift == 0 || h != 0); uint64_finish(ok, value, t) } else { uint64_go(fuel - 1, t, shift + 7, value) }
}
pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> { uint64_go(10, xs, 0, 0) }
pub fn location(xs: &[u8]) -> Option<Loc> { let (value, _rest) = uint64(xs)?; Loc::new(value) }
pub fn loc_small(xs: &[u8]) -> Option<u64> { let l = location(xs)?; if l.0 <= MAX { Some(l.0 + 1) } else { None } }
fn dec(l: Loc) -> Option<Loc> { if l.0 == 0 { None } else { Some(Loc(l.0 - 1)) } }
pub fn dec2(l: Loc) -> Option<u64> { let a = dec(l)?; let b = dec(a)?; if b.0 < MAX { Some(b.0 + a.0) } else { None } }
"#;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn byte_slices(n: usize, seed: u64) -> Vec<String> {
    let mut r = Rng(seed);
    (0..n)
        .map(|_| {
            let len = (r.next() % 12) as usize;
            let bytes: Vec<String> = (0..len).map(|_| format!("{}u8", if r.next().is_multiple_of(3) { r.next() % 128 } else { 128 + r.next() % 128 })).collect();
            format!("&[{}]", bytes.join(", "))
        })
        .collect()
}

fn loc_vals() -> Vec<u64> {
    vec![0, 1, 2, 3, 99, 1 << 40, (1 << 62) - 1, 1 << 62]
}

#[test]
fn callee_summaries_over_invariant_types() {
    let em = build(&format!("{LOC}{PROG_A}"), true, None);
    ok("summaries", &em);
    println!("location: {}; loc_small: {}; dec2: {}", outcome(&em, "crate::location"), outcome(&em, "crate::loc_small"), outcome(&em, "crate::dec2"));
    assert!(driven(&em, "crate::location") && driven(&em, "crate::dec2"), "the callers are driven");
    assert!(reason(&em, "crate::location").contains("callee instantiated through its link"), "{}", reason(&em, "crate::location"));
    assert!(reason(&em, "crate::dec2").contains("callee instantiated through its link"), "{}", reason(&em, "crate::dec2"));
    let mut calls = Vec::new();
    for s in byte_slices(300, 7) {
        calls.push(format!("M::location({s}).map(|l| l.get())"));
        calls.push(format!("M::loc_small({s})"));
    }
    for v in loc_vals() {
        calls.push(format!("M::dec2(M::Loc::new({v}u64).unwrap())"));
    }
    let bad = differential("summaries", &em, &format!("{LOC_REF}{PROG_A_REF}"), &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------
// polyvariant helpers with an invariant-typed dynamic parameter
// ---------------------------------------------------------------------

const PROG_B: &str = r#"
pub fn g3(a: u64, l: Loc, c: u64) -> u64 {
    let mut acc: u64 = a;
    for i in 0..64u32 {
        if (c >> i) & 1 == 1 {
            acc = acc ^ l.0.wrapping_shl(i);
        }
    }
    acc
}

pub fn use_g3(x: Loc, y: u64) -> u64 {
    g3(1, x, 2) ^ g3(y, x, 5).rotate_left(1)
}
"#;

const PROG_B_REF: &str = r#"
pub fn g3(a: u64, l: Loc, c: u64) -> u64 { let mut acc: u64 = a; for i in 0..64u32 { if (c >> i) & 1 == 1 { acc = acc ^ l.0.wrapping_shl(i); } } acc }
pub fn use_g3(x: Loc, y: u64) -> u64 { g3(1, x, 2) ^ g3(y, x, 5).rotate_left(1) }
"#;

#[test]
fn polyvariant_helpers_over_invariant_types() {
    let em = build(&format!("{LOC}{PROG_B}"), true, None);
    ok("polyvariant", &em);
    for l in em.code.lines().filter(|l| l.contains("fn g3")) {
        println!("  printed: {}", l.trim());
    }
    assert!(driven(&em, "crate::use_g3"), "use_g3 is driven");
    assert!(em.code.contains("fn g3__1_2(l1_l: crate::__sandblaster::Loc)") && em.code.contains("fn g3__5(l0_a: u64, l1_l: crate::__sandblaster::Loc)"), "the polyvariant helpers keep the invariant-typed parameter");
    let mut calls = Vec::new();
    for v in loc_vals() {
        for y in [0u64, 5, 1 << 33, u64::MAX] {
            calls.push(format!("M::use_g3(M::Loc::new({v}u64).unwrap(), {y}u64)"));
        }
    }
    let bad = differential("polyvariant", &em, &format!("{LOC_REF}{PROG_B_REF}"), &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------
// a fold helper whose recursion carries an invariant-typed value
// ---------------------------------------------------------------------

const PROG_C: &str = r#"
#[requires(xs.len() <= 65536)]
#[decreases(xs.len())]
fn sum_go(xs: &[u32], l: Loc, acc: u64) -> Option<u64> {
    match xs {
        [] => Some(acc ^ l.0),
        [h, t @ ..] => match acc.checked_add(*h as u64) {
            None => None,
            Some(a) => sum_go(t, l, a),
        },
    }
}

pub fn sum_small(xs: &[u32], l: Loc) -> Option<u64> {
    if xs.len() > 65536 {
        return None;
    }
    sum_go(xs, l, 0)
}
"#;

const PROG_C_REF: &str = r#"
fn sum_go(xs: &[u32], l: Loc, acc: u64) -> Option<u64> {
    match xs { [] => Some(acc ^ l.0), [h, t @ ..] => match acc.checked_add(*h as u64) { None => None, Some(a) => sum_go(t, l, a) } }
}
pub fn sum_small(xs: &[u32], l: Loc) -> Option<u64> { if xs.len() > 65536 { return None; } sum_go(xs, l, 0) }
"#;

#[test]
fn fold_helper_carrying_an_invariant_type() {
    let em = build(&format!("{LOC}{PROG_C}"), true, None);
    ok("fold", &em);
    println!("sum_small: {}", outcome(&em, "crate::sum_small"));
    assert!(driven(&em, "crate::sum_small") && reason(&em, "crate::sum_small").contains("fold"), "{}", reason(&em, "crate::sum_small"));
    assert!(em.code.contains("fn sum_go__fold("), "the fold helper is printed");
    let mut calls = Vec::new();
    let mut r = Rng(3);
    for v in loc_vals() {
        for n in [0usize, 1, 3, 17] {
            let xs: Vec<String> = (0..n).map(|_| format!("{}u32", r.next() as u32)).collect();
            calls.push(format!("M::sum_small(&[{}], M::Loc::new({v}u64).unwrap())", xs.join(", ")));
        }
    }
    let bad = differential("fold", &em, &format!("{LOC_REF}{PROG_C_REF}"), &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------
// ghost parameters through driven callers, summaries and clones
// ---------------------------------------------------------------------

const PROG_D: &str = r#"
#[requires(x as Int + 1 < k && k <= 256)]
fn bump(x: u8, #[ghost] k: Int) -> u8 { x + 1 }

#[ensures(|r: Option<u8>| true)]
fn pick(x: u8) -> Option<u8> {
    if x < 100 { Some(bump(x, ghost!(x as Int + 5))) } else { None }
}

#[ensures(|r: Option<u8>| true)]
pub fn pick2(x: u8) -> Option<u8> {
    let y = pick(x)?;
    if y < 250 { Some(bump(y, ghost!(y as Int + 2))) } else { None }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::vaddq_u32;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u32x4, store_u32x4};

pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "neon")]
#[implements(crate::add4)]
fn add4_neon(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

/// a multiversioned caller with a ghost parameter
#[requires(k == x[0] as Int)]
fn top(x: [u32; 4], #[ghost] k: Int) -> [u32; 4] {
    add4(add4(x, x), x)
}

#[ensures(|r: [u32; 4]| true)]
pub fn api(x: [u32; 4]) -> [u32; 4] {
    top(x, ghost!(x[0] as Int))
}
"#;

const PROG_D_REF: &str = r#"
fn bump(x: u8) -> u8 { x + 1 }
fn pick(x: u8) -> Option<u8> { if x < 100 { Some(bump(x)) } else { None } }
pub fn pick2(x: u8) -> Option<u8> { let y = pick(x)?; if y < 250 { Some(bump(y)) } else { None } }
pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] { [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])] }
fn top(x: [u32; 4]) -> [u32; 4] { add4(add4(x, x), x) }
pub fn api(x: [u32; 4]) -> [u32; 4] { top(x) }
"#;

#[test]
fn ghost_parameters_through_the_driver_and_clones() {
    let em = build(PROG_D, true, None);
    ok("ghost", &em);
    println!("pick2: {}; api: {}", outcome(&em, "crate::pick2"), outcome(&em, "crate::api"));
    println!("clones: {:?}", em.opt.clones.iter().map(|c| (c.clone.clone(), c.lemma.clone())).collect::<Vec<_>>());
    assert!(driven(&em, "crate::pick2") && reason(&em, "crate::pick2").contains("callee instantiated through its link"), "{}", reason(&em, "crate::pick2"));
    let cl = em.opt.clones.iter().find(|c| c.clone == "crate::top__neon").expect("clone of the ghost-parameter function top");
    assert_eq!(cl.lemma.as_deref(), Some("crate::top__neon::clone_equiv"));
    assert!(em.code.contains("fn top__neon(l0_x: [u32; 4usize])") && !em.code.contains("ghost!("), "the clone prints without the ghost parameter");
    let mut calls = Vec::new();
    for x in 0..=255u32 {
        calls.push(format!("M::pick2({x}u8)"));
    }
    for x in [0u32, 1, 7, u32::MAX] {
        calls.push(format!("M::api([{x}u32, 2, 3, 4])"));
    }
    let bad = differential("ghost", &em, PROG_D_REF, &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------
// the proof cache with invariant types: warm = cold, and an edited
// invariant under a warm cache (strict) is not a rejected entry
// ---------------------------------------------------------------------

#[test]
fn proof_cache_with_invariant_types() {
    let dir = tmpdir("cache");
    let src = format!("{LOC}{PROG_A}");
    let cold = build(&src, true, Some(&dir));
    ok("cache: cold", &cold);
    let n = std::fs::read_dir(&dir).map(|r| r.count()).unwrap_or(0);
    println!("cache entries: {n}");
    assert!(n > 0, "the cold build stores the driven lemmas' proofs");
    let warm = build(&src, true, Some(&dir));
    ok("cache: warm", &warm);
    assert_eq!(cold.code, warm.code, "warm build differs from cold");
    // the invariant tightened (the residuals' facts change), warm cache
    let src2 = src.replace("#[invariant(self.0 <= MAX)]", "#[invariant(self.0 < MAX)]").replace("if x <= MAX { Some(Loc(x)) }", "if x < MAX { Some(Loc(x)) }");
    assert_ne!(src, src2);
    let warm2 = build(&src2, true, Some(&dir));
    ok("cache: warm, edited invariant", &warm2);
    let cold2 = build(&src2, true, None);
    ok("cache: cold, edited invariant", &cold2);
    assert_eq!(cold2.code, warm2.code, "warm build of the edited program differs from its cold build");
    // an invariant added to a plain struct under a warm cache
    let srcb = format!("{LOC}{PROG_B}");
    let plain = srcb.replace("#[invariant(self.0 <= MAX)]\n", "");
    assert_ne!(srcb, plain);
    let dir2 = tmpdir("cache-invariant-added");
    let p = build(&plain, true, Some(&dir2));
    ok("cache: plain cold", &p);
    let w = build(&srcb, true, Some(&dir2));
    ok("cache: invariant added, warm", &w);
    let c = build(&srcb, true, None);
    assert_eq!(w.code, c.code, "adding the invariant under a warm cache changed the output vs cold");
}

// ---------------------------------------------------------------------
// a driven caller keeping a call of a ghost-parameter callee (the
// callee is neither straight-line nor driven: it stays a call)
// ---------------------------------------------------------------------

const PROG_F: &str = r#"
#[requires(x as Int + 1 < k && k <= 256)]
fn gstep(x: u8, #[ghost] k: Int) -> u8 {
    if x < 10 { x + 1 } else { x - 1 }
}

#[ensures(|r: Option<u8>| true)]
pub fn gcall(x: u8) -> Option<u8> {
    if x < 100 { Some(gstep(x, ghost!(x as Int + 5))) } else { None }
}
"#;

const PROG_F_REF: &str = r#"
fn gstep(x: u8) -> u8 { if x < 10 { x + 1 } else { x - 1 } }
pub fn gcall(x: u8) -> Option<u8> { if x < 100 { Some(gstep(x)) } else { None } }
"#;

#[test]
fn driven_caller_of_a_kept_ghost_parameter_callee() {
    for strict in [false, true] {
        let em = build(PROG_F, strict, None);
        show(&format!("kept ghost call, strict={strict}"), &em);
        println!("gstep: {}; gcall: {}", outcome(&em, "crate::gstep"), outcome(&em, "crate::gcall"));
        ok("kept ghost call", &em);
        // the kept call's ghost argument is printed from the call's ghost
        // bundle (a ghost expression, `x as Int + 5`), elaborated with the
        // residual, and erased from the printed code with the parameter:
        // the caller is driven (formerly refused: "callee argument count
        // mismatch")
        assert!(report(&em, "crate::gcall").candidates.iter().all(|c| c.rejected_by.is_none()), "{:?}", report(&em, "crate::gcall").candidates);
        assert!(driven(&em, "crate::gcall"), "{}", outcome(&em, "crate::gcall"));
        assert!(!em.code.contains("ghost!(") && em.code.contains("gstep(l0_x)"), "the ghost argument is erased:\n{}", em.code);
        let calls: Vec<String> = (0..=255u32).map(|x| format!("M::gcall({x}u8)")).collect();
        let bad = differential("kept-ghost-call", &em, PROG_F_REF, &calls);
        assert!(bad.is_empty(), "{bad:#?}");
    }
}

/// The same kept call in a straight-line caller (tier 0): the residual
/// printer used to refuse it ("callee argument count mismatch", an
/// optimizer failure: a strict build of correct code failed). The ghost
/// argument is now printed from the call's ghost bundle and erased.
#[test]
fn straight_line_caller_of_a_ghost_parameter_callee() {
    const SRC: &str = r#"
#[requires(x as Int + 1 < k && k <= 256)]
fn gstep(x: u8, #[ghost] k: Int) -> u8 {
    if x < 10 { x + 1 } else { x - 1 }
}

#[ensures(|r: u8| true)]
pub fn gwrap(x: u8) -> u8 {
    let y = x & 63;
    gstep(y, ghost!(y as Int + 5)) ^ 1
}
"#;
    const REF: &str = r#"
fn gstep(x: u8) -> u8 { if x < 10 { x + 1 } else { x - 1 } }
pub fn gwrap(x: u8) -> u8 { let y = x & 63; gstep(y) ^ 1 }
"#;
    let em = build(SRC, true, None);
    ok("straight-line ghost call", &em);
    let f = report(&em, "crate::gwrap");
    assert!(matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::StraightLine), "{}", outcome(&em, "crate::gwrap"));
    assert!(!em.code.contains("ghost!("), "{}", em.code);
    let calls: Vec<String> = (0..=255u32).map(|x| format!("M::gwrap({x}u8)")).collect();
    let bad = differential("straight-line-ghost-call", &em, REF, &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// ---------------------------------------------------------------------
// invariant facts in the driver's decisions (and the proof builder's)
// ---------------------------------------------------------------------

const PROG_I: &str = r#"
/// the invariant decides the test: the `else` arm is dead
pub fn bump(l: Loc) -> u64 {
    if l.0 <= MAX { l.0 + 1 } else { 0 }
}

/// one test decided by the invariant, one kept
pub fn pick(l: Loc, y: u64) -> u64 {
    if y > 3 {
        if l.0 > MAX { 1 } else { l.0 ^ y }
    } else {
        0
    }
}
"#;

const PROG_I_REF: &str = r#"
pub fn bump(l: Loc) -> u64 { if l.0 <= MAX { l.0 + 1 } else { 0 } }
pub fn pick(l: Loc, y: u64) -> u64 { if y > 3 { if l.0 > MAX { 1 } else { l.0 ^ y } } else { 0 } }
"#;

/// A parameter of a type with an `#[invariant]` has its invariant as a
/// fact (`S::inv#k`, the elaborator's free facts): the driver decides the
/// tests it implies and the proof builder replays those decisions with the
/// same facts (formerly the driver ignored them and split on the test).
#[test]
fn invariant_facts_decide_tests_in_the_driver() {
    let em = build(&format!("{LOC}{PROG_I}"), true, None);
    ok("invariant facts", &em);
    println!("bump: {} / {}; pick: {} / {}", outcome(&em, "crate::bump"), reason(&em, "crate::bump"), outcome(&em, "crate::pick"), reason(&em, "crate::pick"));
    for f in ["crate::bump", "crate::pick"] {
        assert!(driven(&em, f), "{f}: {}", outcome(&em, f));
        assert!(reason(&em, f).contains("1 prune"), "{f}: the invariant decides a test: {}", reason(&em, f));
    }
    let bump = em.code.lines().skip_while(|l| !l.contains("fn bump(")).take(4).collect::<Vec<_>>().join("\n");
    assert!(!bump.contains("if "), "the dead arm is gone: {bump}");
    let mut calls = Vec::new();
    for v in loc_vals() {
        calls.push(format!("M::bump(M::Loc::new({v}u64).unwrap())"));
        for y in [0u64, 3, 4, u64::MAX] {
            calls.push(format!("M::pick(M::Loc::new({v}u64).unwrap(), {y}u64)"));
        }
    }
    let bad = differential("invariant-facts", &em, &format!("{LOC_REF}{PROG_I_REF}"), &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}

// =====================================================================
// §15 S3 through the optimizer (merge of S3 into main after O5 and S2)
// =====================================================================

/// The build's pipeline (`driver::stage::verify_and_optimize`, as the build script
/// and the CLI run it) over several files, with the given options.
fn pipeline(files: &[(&str, String)], opts: OptOptions) -> (driver::Checked, driver::stage::StageBuild) {
    let owned: Vec<(String, String)> = files.iter().map(|(p, s)| (p.to_string(), if *p == "r/mod.rs" { format!("{HEADER}{s}") } else { s.clone() })).collect();
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let vopts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &vopts, &opts, "r/mod.rs");
    (c, built)
}

fn emitted(tag: &str, c: &driver::Checked, built: driver::stage::StageBuild) -> OptimizedEmit {
    assert!(built.v.proofs_ok, "{tag}: not verified:\n{}", built.v.diags.render(&c.sm));
    let em = built.emit.expect("optimized").expect("optimizer ran");
    ok(tag, &em);
    em
}

// ---------------------------------------------------------------------
// deterministic budgets (DESIGN.md §15.8, §8.2 item 10) against the
// optimizer's fallbacks
// ---------------------------------------------------------------------

/// A safety net that trips inside the optimizer (here the driver's
/// wall-clock deadline, simulated by the `DeadlineTrip` hook exactly as the
/// meter records a real one) makes the function fall back to a weaker
/// candidate: code that depends on the clock. The optimizer's own attempts
/// are decided by step budgets only; the deadline is a safety net, so the
/// build fails with `error[resource]` (`driver::resource_gate` after the
/// optimizer) and is not verified — the build script and `sandblaster emit`
/// then write no code — strict or not. The control (no trip) is the
/// budgets' result.
#[test]
fn a_safety_net_trip_in_the_optimizer_fails_the_build() {
    use sandblaster_front::diag::DiagKind;
    use sandblaster_front::opt::DriveFault;
    use sandblaster_front::opt::hooks::OptTestHooks;
    let files = [("r/mod.rs", format!("{LOC}{PROG_A}"))];
    let (c, built) = pipeline(&files, OptOptions { strict: true, ..Default::default() });
    let control = emitted("trip: control", &c, built);
    assert!(driven(&control, "crate::location"), "{}", outcome(&control, "crate::location"));
    for strict in [false, true] {
        let hooks = OptTestHooks { drive_faults: std::collections::BTreeMap::from([("crate::location".to_string(), DriveFault::DeadlineTrip)]), ..Default::default() };
        let (c, built) = pipeline(&files, OptOptions { strict, hooks: Some(std::sync::Arc::new(hooks)), ..Default::default() });
        let em = built.emit.as_ref().expect("the optimizer ran").as_ref().expect("optimized");
        show(&format!("trip, strict={strict}"), em);
        // the fallback: without the gate, the emitted code would differ
        assert!(!driven(em, "crate::location"), "{}", outcome(em, "crate::location"));
        assert!(report(em, "crate::location").candidates.iter().any(|x| x.rung == Rung::Driven && x.reason.contains("deadline exceeded")), "{:?}", report(em, "crate::location").candidates);
        assert_ne!(em.code, control.code);
        // ... so the build failed for resources, never as a proof result
        assert!(!built.v.proofs_ok, "strict={strict}: a trip in the optimizer must fail the build");
        let res: Vec<&str> = built.v.diags.list.iter().filter(|d| d.kind == DiagKind::Resource).map(|d| d.msg.as_str()).collect();
        assert!(res.iter().any(|m| m.contains("resource safety nets tripped")), "strict={strict}: {}", built.v.diags.render(&c.sm));
        assert!(!built.v.diags.list.iter().any(|d| d.kind == DiagKind::Obligation), "a trip is not an unproven obligation: {}", built.v.diags.render(&c.sm));
    }
    // the trip was taken by the gate: the next build is clean
    let (c, built) = pipeline(&files, OptOptions { strict: true, ..Default::default() });
    let again = emitted("trip: after", &c, built);
    assert_eq!(again.code, control.code);
}

// ---------------------------------------------------------------------
// callee contract facts are hints (S3), sections and `complete_p` lemmas,
// and the hints-only proof cache (O5)
// ---------------------------------------------------------------------

const PROG_S: &str = r#"
#[cfg(sandblaster)]
#[spec]
fn clamp_spec(x: Nat) -> Nat { if x > 1000 { 1000 } else { x } }

#[ensures(|r: u32| r <= 1000u32)]
pub fn clamp(x: u32) -> u32 {
    if x > 1000 { 1000 } else { x }
}

/// its contract mentions `clamp`, which has an `ensures`: since S3 those
/// facts are hints of the statement's proof slots, not part of it
#[requires(clamp(x) <= 1000u32)]
fn scaled(x: u32, k: u8) -> Option<u32> {
    let c = clamp(x);
    if k == 0 {
        None
    } else if c < 500 {
        Some(c * 2)
    } else {
        Some(c + (k as u32))
    }
}

pub fn run(x: u32, k: u8) -> Option<u32> {
    scaled(x, k)
}

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const PROG_S_LAWS: &str = r#"use sandblaster::prelude::*;
use super::{clamp, clamp_spec};

/// `clamp` agrees with the clamping specification on every input.
#[law]
fn clamp_is_spec(x: u32) {
    ensures(clamp(x) as Nat == clamp_spec(x as Nat));
}
"#;

const PROG_S_PROOF: &str = r#"use sandblaster::prelude::*;
#[allow(unused_imports)]
use super::{clamp, clamp_spec};

#[proof]
fn clamp_is_spec(x: u32) {
    follows();
}
"#;

const PROG_S_REF: &str = r#"
pub fn clamp(x: u32) -> u32 { if x > 1000 { 1000 } else { x } }
fn scaled(x: u32, k: u8) -> Option<u32> { let c = clamp(x); if k == 0 { None } else if c < 500 { Some(c * 2) } else { Some(c + (k as u32)) } }
pub fn run(x: u32, k: u8) -> Option<u32> { scaled(x, k) }
"#;

fn prog_s(ensures: &str, with_law: bool) -> Vec<(&'static str, String)> {
    let root = PROG_S.replace("#[ensures(|r: u32| r <= 1000u32)]", ensures);
    let laws = if with_law { PROG_S_LAWS.to_string() } else { "use sandblaster::prelude::*;\n".to_string() };
    let proof = if with_law { PROG_S_PROOF.to_string() } else { "use sandblaster::prelude::*;\n".to_string() };
    vec![("r/mod.rs", root), ("r/LAWS.rs", laws), ("r/PROOF.rs", proof)]
}

/// S3 changed how laws and contracts are elaborated (a callee's `ensures`
/// is a hint of the statement's proof slots, no longer a `let` inside the
/// statement) and adds `p::complete` lemmas for the computed sections. None
/// of it reaches the optimizer's output: a crate whose contract mentions a
/// callee with an `ensures`, with a law that fully specifies a section,
/// builds strict with no optimizer warning and a clean round trip, and its
/// emitted code agrees with the plain-Rust source. Under a warm proof cache
/// (O5; keys over the lemma statements and the Merkle hashes of the globals
/// they name) the output equals the cold build's also after the callee's
/// `ensures` is edited and after the law (with its section and
/// `complete_p` lemma) is added: a stale entry is a miss, never a rejected
/// hit (which strict would report), and the emitted code never changes.
#[test]
fn contract_facts_sections_and_the_proof_cache() {
    let dir = tmpdir("s3-cache");
    let base = prog_s("#[ensures(|r: u32| r <= 1000u32)]", true);
    let (c, built) = pipeline(&base, OptOptions { strict: true, cache_dir: Some(dir.clone()), ..Default::default() });
    assert!(built.spec15.sections.iter().any(|s| s.members == vec!["crate::clamp".to_string()] && s.fully_specified), "{:?}", built.spec15.sections);
    assert!(built.v.defs.iter().any(|d| d.name == "crate::clamp::complete"), "the section's complete_p lemma");
    let cold = emitted("s3: cold", &c, built);
    println!("scaled: {}; run: {}; clamp: {}", outcome(&cold, "crate::scaled"), outcome(&cold, "crate::run"), outcome(&cold, "crate::clamp"));
    let n = std::fs::read_dir(&dir).map(|r| r.count()).unwrap_or(0);
    println!("cache entries: {n}");
    let (c, built) = pipeline(&base, OptOptions { strict: true, cache_dir: Some(dir.clone()), ..Default::default() });
    let warm = emitted("s3: warm", &c, built);
    assert_eq!(cold.code, warm.code, "warm build differs from cold");
    // the callee's `ensures` edited (weaker), warm cache
    let edited = prog_s("#[ensures(|r: u32| r <= 1001u32)]", true);
    let (c, built) = pipeline(&edited, OptOptions { strict: true, cache_dir: Some(dir.clone()), ..Default::default() });
    let warm_e = emitted("s3: warm, edited ensures", &c, built);
    let (c, built) = pipeline(&edited, OptOptions { strict: true, ..Default::default() });
    let cold_e = emitted("s3: cold, edited ensures", &c, built);
    assert_eq!(warm_e.code, cold_e.code, "warm build of the edited program differs from its cold build");
    // the law (a section and its `complete_p` lemma) added under a warm cache
    let dir2 = tmpdir("s3-cache-law-added");
    let plain = prog_s("#[ensures(|r: u32| r <= 1000u32)]", false);
    let (c, built) = pipeline(&plain, OptOptions { strict: true, cache_dir: Some(dir2.clone()), ..Default::default() });
    assert!(!built.v.defs.iter().any(|d| d.name == "crate::clamp::complete"));
    let p = emitted("s3: no law, cold", &c, built);
    let (c, built) = pipeline(&base, OptOptions { strict: true, cache_dir: Some(dir2.clone()), ..Default::default() });
    let w = emitted("s3: law added, warm", &c, built);
    assert_eq!(w.code, cold.code, "adding the law under a warm cache changed the output vs cold");
    assert_eq!(p.code, cold.code, "the law and its section changed the emitted code");
    let mut calls = Vec::new();
    for x in [0u32, 1, 499, 500, 501, 999, 1000, 1001, 5000, u32::MAX] {
        for k in [0u8, 1, 7, 255] {
            calls.push(format!("M::run({x}u32, {k}u8)"));
        }
    }
    let bad = differential("s3-contracts", &cold, PROG_S_REF, &calls);
    assert!(bad.is_empty(), "{bad:#?}");
}
