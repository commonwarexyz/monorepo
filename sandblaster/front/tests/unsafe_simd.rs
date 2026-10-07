//! The narrow reading of existing `unsafe` (docs/DESIGN-UNSAFE-SIMD.md;
//! docs/mir-lift.md §20.10): raw-pointer formations, offsets, casts and the
//! admitted loads and stores of crate code, read by the literal reading
//! through a memory model checked by the kernel, with the window rule run on
//! the unoptimized extraction.

use std::collections::{BTreeMap, BTreeSet};

use sandblaster_front::mir::ir::{self, Callee, Term};
use sandblaster_front::mir::{self, ModuleNames};

type Code = (&'static str, &'static str, &'static str);
const PTR: Code = (include_str!("mir_fixtures/sd_ptr/src/a.rs"), include_str!("mir_fixtures/sd_ptr/a.sbmir"), include_str!("mir_fixtures/sd_ptr/a.window.sbmir"));
const TWINS: Code = (include_str!("mir_fixtures/sd_ptr_twins/src/a.rs"), include_str!("mir_fixtures/sd_ptr_twins/a.sbmir"), include_str!("mir_fixtures/sd_ptr_twins/a.window.sbmir"));

/// The build's static features of `aarch64-apple-darwin` (stable rustc's
/// `CARGO_CFG_TARGET_FEATURE`).
fn aarch64_features() -> Vec<String> {
    sandblaster_front::target::TargetInfo::aarch64_apple_darwin().features.into_iter().collect()
}

fn names(features: Option<Vec<String>>) -> ModuleNames {
    ModuleNames { module: String::new(), sealed: BTreeSet::new(), host_enums: BTreeMap::new(), requires: BTreeSet::new(), open: BTreeMap::new(), dsl_modules: vec!["crate::a".into()], current: Default::default(), consts: BTreeMap::new(), invariant_types: BTreeSet::new(), host: Default::default(), target_arch: Some("aarch64".into()), static_features: features, codegen_flags: Some((None, String::new())) }
}

fn loaded(code: Code) -> mir::Loaded {
    let src = code.0.as_bytes().to_vec();
    let mut l = mir::load(code.1, &|p| (p == "src/a.rs").then(|| src.clone()), names(Some(aarch64_features())), "a").unwrap_or_else(|e| panic!("{e}"));
    mir::load_window(code.2, &mut l).unwrap_or_else(|e| panic!("{e}"));
    l
}

/// The window rule (W0–W4) on the unoptimized MIR: every formation of the
/// chunk multiplier passes, the `&mut` parameter its family reaches named
/// (S8); each twin's formation fails with its rule.
#[test]
fn window_verdicts_of_the_fixtures() {
    let verdicts = |code: Code| -> Vec<(String, String, Result<(), String>, Vec<usize>)> {
        let l = loaded(code);
        let mut out = Vec::new();
        for (k, f) in &l.m.fns {
            for v in f.window.iter().flatten() {
                eprintln!("{k}: {} at {:?}: {:?} params {:?}", v.what, v.at, v.result, v.params);
                out.push((k.rsplit("::").next().unwrap_or(k).to_string(), v.what.clone(), v.result.clone(), v.params.clone()));
            }
        }
        out
    };
    let ptr = verdicts(PTR);
    for (f, params) in [("chunk_mul", vec![1]), ("mul_chunks", vec![1]), ("load_row", vec![])] {
        let v: Vec<_> = ptr.iter().filter(|v| v.0 == f).collect();
        assert!(!v.is_empty() && v.iter().all(|v| v.2.is_ok() && v.3 == params), "{f}: {v:?}");
    }
    let twins = verdicts(TWINS);
    let failed = |f: &str, rule: &str| twins.iter().any(|v| v.0 == f && v.2.as_ref().is_err_and(|e| e.contains(rule)));
    for (f, rule) in [("escape", "W1"), ("stored", "W1"), ("deref", "W1"), ("ptr_read", "W1"), ("alias", "W2"), ("alias_read", "W2"), ("two_formations", "W2"), ("store_through_shared", "W4"), ("bool_table", "has a niche")] {
        assert!(failed(f, rule), "{f}: no `{rule}` verdict: {:?}", twins.iter().filter(|v| v.0 == f).collect::<Vec<_>>());
    }
    // (the out-of-bounds twins pass the window rule: their offsets are
    // L's to refuse)
    for f in ["load_past_end", "offset_past_end"] {
        assert!(twins.iter().filter(|v| v.0 == f).all(|v| v.2.is_ok()), "{f}");
    }
}

/// A-S3: the static target features are facts only when they are the
/// build's own and come from the target's defaults; everything else is
/// refused at load, with its reason. Without the build's features (not
/// known) there is no static fact, and NEON outside a `#[target_feature]`
/// function is refused as a feature with no fact.
#[test]
fn the_static_features_are_bound_to_the_builds() {
    let src = PTR.0.as_bytes().to_vec();
    let load = |text: &str, n: ModuleNames| mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), n, "a").map(|_| ()).unwrap_or_else(|e| panic!("{e}"));
    let refused = |text: &str, n: ModuleNames| -> String {
        match mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), n, "a") {
            Ok(_) => panic!("loaded"),
            Err(e) => e,
        }
    };
    load(PTR.1, names(Some(aarch64_features())));
    // another build's static features
    let e = refused(PTR.1, names(Some(vec!["neon".to_string()])));
    assert!(e.contains("this build's are") && e.contains("extract it again"), "{e}");
    // a build with `-C target-cpu`, with `-C target-feature`
    let mut n = names(Some(aarch64_features()));
    n.codegen_flags = Some((Some("apple-m4".into()), String::new()));
    let e = refused(PTR.1, n);
    assert!(e.contains("this build sets -C target-cpu=Some(\"apple-m4\")"), "{e}");
    let mut n = names(Some(aarch64_features()));
    n.codegen_flags = Some((None, "+sme".into()));
    let e = refused(PTR.1, n);
    assert!(e.contains("-C target-feature=\"+sme\""), "{e}");
    // an extraction with a CPU or features of its own
    let cpu = PTR.1.replace("(target-cpu default \"apple-m1\")", "(target-cpu \"apple-m4\" \"apple-m1\")");
    let e = refused(&cpu, names(Some(aarch64_features())));
    assert!(e.contains("extracted with -C target-cpu=Some(\"apple-m4\")"), "{e}");
    let flags = PTR.1.replace("(target-feature-flags \"\")", "(target-feature-flags \"+sme\")");
    let e = refused(&flags, names(Some(aarch64_features())));
    assert!(e.contains("-C target-feature=Some(\"+sme\")"), "{e}");
    // a big-endian extraction
    let big = PTR.1.replace("(endian little)", "(endian big)");
    let e = refused(&big, names(Some(aarch64_features())));
    assert!(e.contains("little-endian"), "{e}");
    // the build's features unknown: no static fact
    let mut l = mir::load(PTR.1, &|p| (p == "src/a.rs").then(|| src.clone()), names(None), "a").unwrap_or_else(|e| panic!("{e}"));
    mir::load_window(PTR.2, &mut l).unwrap_or_else(|e| panic!("{e}"));
    assert!(l.m.static_facts.is_none());
    with_env(|env| {
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        let lf = lit.lfn("fx_sd_ptr::a::mul_16");
        let why = match lf {
            Some(lf) => lf.faults.join("\n"),
            None => lit.refused.iter().find(|(k, _)| k.ends_with("::mul_16")).map(|(_, e)| e.clone()).unwrap_or_default(),
        };
        assert!(why.contains("neon"), "mul_16 without static facts: {why}");
        eprintln!("mul_16 without the build's features: {why}");
    });
}

// ---------------------------------------------------------------------------
// the literal reading on the fixtures, evaluated by the kernel
// ---------------------------------------------------------------------------

use sandblaster_front::loader::MemFs;
use sandblaster_front::mir::checked;
use sandblaster_front::mir::literal::LFn;
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Lvl;
use sandblaster_kernel::value::{Budget, VEnv};

/// A kernel environment with the lift prelude and the aarch64 target
/// models (a lifted crate's), on the elaboration thread.
fn with_env(f: impl FnOnce(&mut Env) + Send) {
    let root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n";
    let fs = MemFs::from_files([("r/mod.rs", root), ("r/w.rs", include_str!("mir_fixtures/lift_w/w.rs")), ("r/w.sbmir", include_str!("mir_fixtures/lift_w/w.sbmir"))]);
    let c = sandblaster_front::driver::check(std::path::Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &[]);
        f(&mut out.env)
    });
}

/// The kernel's value of `got` is the value of `want` (both closed core text).
#[track_caller]
fn same(env: &Env, got: &str, want: &str) {
    let mut b = Budget { steps: 4_000_000_000 };
    let (g, w) = (env.parse_term(&[], got).unwrap_or_else(|e| panic!("{e}\n{got}")), env.parse_term(&[], want).unwrap_or_else(|e| panic!("{e}\n{want}")));
    let gv = env.eval(&VEnv::default(), Lvl(0), &g, &mut b).expect("eval");
    let wv = env.eval(&VEnv::default(), Lvl(0), &w, &mut b).expect("eval");
    if !env.conv(Lvl(0), &gv, &wv, &mut b).expect("conv") {
        let shown = env.eval_closed(&g, &mut b).map(|t| env.print_term(&[], &t)).unwrap_or_else(|e| format!("{e}"));
        panic!("the reading gives\n  {}\nwhere rustc's semantics gives\n  {want}", shown.chars().take(3000).collect::<String>());
    }
}

fn u8_array(v: &[u8]) -> String {
    let l = v.iter().rev().fold("Nil[U8]".to_string(), |l, b| format!("Cons[U8]({b}u8, {l})"));
    format!("pair(Array U8 {}usize, {l}, refl(Int, {}int))", v.len(), v.len())
}

fn chunks_slice(cs: &[[u8; 64]]) -> String {
    let t = "Array U8 64usize";
    let l = cs.iter().rev().fold(format!("Nil[{t}]"), |l, c| format!("Cons[{t}]({}, {l})", u8_array(c)));
    format!("slice::mk ({t}) {}usize ({l}) .pair(SliceOk ({t}) {}usize ({l}), refl(Int, {}int), refl(Bool, true))", cs.len(), cs.len(), cs.len())
}

/// `run fuel b0 (Ret init)` of `lf` with the parameters `args` (a `&mut`
/// parameter's argument is its referent, held in its cell).
fn run(lf: &LFn, fuel: usize, args: &[&str]) -> String {
    let rc = format!("Tuple2(L::{}::Root, List(mir::Proj))", lf.id);
    let code = |j: usize| format!("tuple2[L::{id}::Root, List(mir::Proj)](L::{id}::Root::rc{j}, Nil[mir::Proj])", id = lf.id);
    let mut slots: Vec<String> = Vec::new();
    for (i, t) in lf.local_tys.iter().enumerate() {
        let t = t.replace("@RC@", &rc);
        slots.push(match lf.cells.iter().position(|c| c.param == i && c.parent.is_none()) {
            Some(j) if i >= 1 && i <= args.len() => format!("Some[{t}]({})", code(j)),
            _ if i >= 1 && i <= args.len() => format!("Some[{t}]({})", args[i - 1]),
            _ => format!("None[{t}]"),
        });
    }
    for c in &lf.cells {
        slots.push(format!("Some[{}]({})", c.ty.replace("@RC@", &rc), args[c.param - 1]));
    }
    let fuel = (0..fuel).fold("Nil[Unit]".to_string(), |l, _| format!("Cons[Unit](tt, {l})"));
    format!("{} ({fuel}) {}::b0 (mir::Res::Ret[{st}]({st}::st({})))", lf.run, lf.blk, slots.join(", "), st = lf.st)
}

/// The scalar reference: each byte through the nibble tables.
fn mul_byte(b: u8, lo: &[u8; 16], hi: &[u8; 16]) -> u8 {
    lo[(b & 15) as usize] ^ hi[(b >> 4) as usize]
}

fn bytes(seed: &mut u64) -> u8 {
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*seed >> 56) as u8
}

#[test]
fn the_literal_reading_loads_and_stores_through_the_chunks_pointers_as_rustc_does() {
    with_env(|env| {
        let l = loaded(PTR);
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        assert!(lit.refused.is_empty(), "{:?}", lit.refused);
        let lf = lit.lfn("fx_sd_ptr::a::mul_chunks").expect("mul_chunks");
        assert!(lf.faults.is_empty(), "{:?}", lf.faults);
        let mut seed = 0x5eed_u64;
        for n in [0usize, 1, 2] {
            let x: Vec<[u8; 64]> = (0..n).map(|_| std::array::from_fn(|_| bytes(&mut seed))).collect();
            let (lo, hi): ([u8; 16], [u8; 16]) = (std::array::from_fn(|_| bytes(&mut seed)), std::array::from_fn(|_| bytes(&mut seed)));
            let want: Vec<[u8; 64]> = x.iter().map(|c| std::array::from_fn(|k| mul_byte(c[k], &lo, &hi))).collect();
            same(env, &run(lf, 8, &[&chunks_slice(&x), &u8_array(&lo), &u8_array(&hi)]), &format!("mir::Res::Ret[Slice (Array U8 64usize)]({})", chunks_slice(&want)));
            eprintln!("mul_chunks on {n} chunk(s): as rustc computes");
        }
        // the shared formation: a table row's sixteen bytes
        let lr = lit.lfn("fx_sd_ptr::a::load_row").expect("load_row");
        assert!(lr.faults.is_empty(), "{:?}", lr.faults);
        let row: [u8; 16] = std::array::from_fn(|i| (i * 7) as u8);
        same(env, &run(lr, 0, &[&u8_array(&row)]), &format!("mir::Res::Ret[Array U8 16usize]({})", u8_array(&row)));
    });
}

#[test]
fn the_literal_reading_is_stuck_on_each_twin_with_its_reason_named() {
    with_env(|env| {
        let l = loaded(TWINS);
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        let key = |f: &str| format!("fx_sd_ptr_twins::a::{f}");
        let faults = |f: &str| -> String {
            match lit.lfn(&key(f)) {
                Some(lf) => lf.faults.join("\n"),
                None => lit.refused.iter().find(|(k, _)| *k == key(f)).map(|(_, e)| e.clone()).unwrap_or_else(|| panic!("no reading of `{f}`")),
            }
        };
        // each refused construct, named
        for (f, why) in [
            ("store_through_shared", "W4: a store through a pointer formed from a shared reference"),
            ("escape", "takes or returns a raw pointer"),
            ("stored", "W1: the pointer"),
            ("alias", "W2: `_1`"),
            ("alias_read", "W2: `_1`"),
            ("two_formations", "W2: `_1`"),
            ("bool_table", "`bool` has a niche"),
            ("no_fact", "compiled with target feature(s) sm4"),
            ("ptr_read", "the library `unsafe fn` `std::ptr::read`"),
            ("unchecked", "the library `unsafe fn` `core::slice::<impl [T]>::get_unchecked`"),
            ("deref", "W1: the pointer"),
            // (S7: a library `unsafe fn` beside the admitted ones, matched by
            // its exact path and signature, not by its name)
            ("byte_offset", "the library `unsafe fn` `std::ptr::mut_ptr::<impl *mut T>::byte_add`"),
        ] {
            let got = faults(f);
            assert!(got.contains(why), "{f}: {why}\n{got}");
            eprintln!("{f}: refused ({why})");
        }
        // a crate function named `add` is a call of the crate (S7)
        let lf = lit.lfn(&key("calls_add")).expect("calls_add");
        assert!(lf.faults.is_empty(), "calls_add: {:?}", lf.faults);
        same(env, &run(lf, 2, &["40u64"]), "mir::Res::Ret[U64](41u64)");
        // read, but out of bounds on every input: stuck (no theorem can exist)
        let mut seed = 7u64;
        let x: [u8; 64] = std::array::from_fn(|_| bytes(&mut seed));
        for f in ["load_past_end", "offset_past_end"] {
            let lf = lit.lfn(&key(f)).expect(f);
            assert!(lf.faults.is_empty(), "{f}: {:?}", lf.faults);
            same(env, &run(lf, 4, &[&u8_array(&x)]), &format!("mir::Res::Stuck[{}]", lf.out_ty));
            eprintln!("{f}: read, and stuck (out of bounds)");
        }
    });
}

// ---------------------------------------------------------------------------
// in place: the host crate verified against its laws
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};

use sandblaster_front::driver::{self, Checked};

const ROOT_PATH: &str = "host/sandblaster/m/mod.rs";

/// The DSL root exporting `fns` (with a proof file when `proof` is set).
fn root(fns: &str, proof: bool) -> String {
    let proof = if proof { "\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n" } else { "" };
    format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\", window_mir = \"a.window.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n{proof}\npub use a::{{{fns}}};\n")
}

/// The host crate of `code` exporting `fns`, with the laws and proofs given.
fn files(code: Code, fns: &str, laws: Option<&str>, proof: Option<&str>) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = vec![
        ("host/Cargo.toml".into(), "[package]\nname = \"sd-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n".into()),
        ("host/src/lib.rs".into(), format!("//! The host crate.\nmod a;\npub use a::{{{fns}}};\n")),
        ("host/src/a.rs".into(), code.0.into()),
        (ROOT_PATH.into(), root(fns, proof.is_some())),
        ("host/sandblaster/m/a.sbmir".into(), code.1.into()),
        ("host/sandblaster/m/a.window.sbmir".into(), code.2.into()),
        ("host/sandblaster/m/LAWS.rs".into(), laws.unwrap_or("//! No laws.\nuse sandblaster::prelude::*;\n").into()),
    ];
    if let Some(p) = proof {
        v.push(("host/sandblaster/m/PROOF.rs".into(), p.into()));
    }
    v
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sandblaster-unsafe-simd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir }
    }

    fn abs(&self, files: &[(String, String)]) -> (Vec<(String, String)>, String) {
        let abs: Vec<(String, String)> = files.iter().map(|(p, t)| (self.dir.join(p).display().to_string(), t.clone())).collect();
        (abs, self.dir.join(ROOT_PATH).display().to_string())
    }

    fn check(&self, files: &[(String, String)]) -> Checked {
        let (abs, root) = self.abs(files);
        let fs = MemFs::from_files(abs.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        driver::check(Path::new(&root), &fs, &TargetInfo::aarch64_apple_darwin())
    }

}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

const PTR_FNS: &str = "mul_16, chunk_mul, mul_chunks, mul, load_row, xor_rows";

/// The elements `f(i)` for `i` in `0..n`, comma separated.
fn elems(n: usize, f: impl Fn(usize) -> String) -> String {
    (0..n).map(f).collect::<Vec<_>>().join(", ")
}

/// What the chunk multiplier computes: each byte through the nibble tables,
/// on a vector; what a table row's load reads.
fn chunk_laws() -> String {
    format!(
        r#"//! What the chunk multiplier computes: each byte `b` through the nibble
//! tables, `lo[b & 15] ^ hi[b >> 4]` (what a scalar Reed–Solomon engine
//! computes per byte), on a vector; and what a table row's load reads.
use sandblaster::prelude::*;
use core::arch::aarch64::*;
use crate::a::{{mul_16, chunk_mul, mul_chunks, mul, load_row}};

/// A table lookup of one byte: `t[k]`, or 0 past the table (TBL's scalar
/// meaning).
#[spec]
#[example(tbl([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 3u8) == 13u8)]
#[example(tbl([10u8, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25], 16u8) == 0u8)]
pub fn tbl(t: [u8; 16], k: u8) -> u8 {{
    if k < 16u8 {{ t[k as usize] }} else {{ 0u8 }}
}}

/// One byte through the nibble tables: its low nibble looked up in `lo`,
/// its high nibble in `hi`, the two combined by xor.
#[spec]
#[example(mul_byte(0x21u8, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == 0x21u8)]
#[example(mul_byte(0xffu8, [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 7], [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]) == 4u8)]
pub fn mul_byte(b: u8, lo: [u8; 16], hi: [u8; 16]) -> u8 {{
    tbl(lo, b & 15u8) ^ tbl(hi, b >> 4u32)
}}

/// `mul_byte` in every lane, lane 0 first.
#[spec]
#[example(mul_lanes([0x21u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff], [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]) == [0x21u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff])]
pub fn mul_lanes(x: [u8; 16], lo: [u8; 16], hi: [u8; 16]) -> [u8; 16] {{
    [{lanes}]
}}

/// `mul_16` is the scalar reference in every lane (a vector is the array of
/// its lanes, lane 0 first).
#[law]
fn mul_16_is_the_scalar_reference(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {{
    ensures(mul_16(x, lo, hi) == mul_lanes(x, lo, hi));
}}

/// `load_row` reads the row's sixteen bytes, lane 0 first.
#[law]
fn load_row_reads_the_row(t: [u8; 16]) {{
    ensures(load_row(&t) == t);
}}
"#,
        lanes = elems(16, |i| format!("mul_byte(x[{i}], lo, hi)")),
    )
}

/// The proofs of [`chunk_laws`], and the lemma that a quarter of a chunk,
/// loaded, multiplied and stored through the reading's models, is the
/// scalar reference.
fn chunk_proof() -> String {
    r#"use sandblaster::prelude::*;
use core::arch::aarch64::*;
#[allow(unused_imports)]
use crate::a::{mul_16, chunk_mul, mul_chunks, mul, load_row};
#[allow(unused_imports)]
use crate::laws::{tbl, mul_byte, mul_lanes};

/// Lane for lane, by word algebra: the models unfold on symbolic lanes.
#[proof]
fn mul_16_is_the_scalar_reference(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    unfold(mul_16);
    bv();
}

/// A quarter of a chunk: its sixteen bytes loaded, multiplied and stored
/// (the models of `vld1q_u8` and `vst1q_u8`) are the scalar reference's.
#[lemma]
fn quarter(q: [u8; 16], lo: uint8x16_t, hi: uint8x16_t) {
    ensures(vst1q_u8(mul_16(vld1q_u8(q), lo, hi)) == mul_lanes(q, lo, hi));
    unfold(mul_16);
    bv();
}

/// Lane for lane: the load's model reinterprets the bytes.
#[proof]
fn load_row_reads_the_row(t: [u8; 16]) {
    unfold(load_row);
    bv();
}

#[proof(complete = crate::a::mul_16)]
fn mul_16_determined(x: uint8x16_t, lo: uint8x16_t, hi: uint8x16_t) {
    use_hyp(0, x, lo, hi);
    use_real(0, x, lo, hi);
    by_arithmetic();
}

#[proof(complete = crate::a::load_row)]
fn load_row_determined(t: &[u8; 16]) {
    use_hyp(0, *t);
    use_real(0, t);
    by_arithmetic();
}
"#
    .to_string()
}

/// The scalar reference of a whole chunk and of every chunk of a slice: the
/// laws the unsafe-reading stage stated but could not prove (the
/// automation's read-back bound on the 64-byte chunk bodies). The chunk's
/// four quarter laws now prove by the lane closer (`auto::lanes`, stage
/// table-lookup-lanes); the loop's contract and the slice laws are still
/// open (the stage reports).
fn pending_laws() -> (String, String) {
    let laws = format!(
        r#"
/// Quarter `q` of a chunk: its sixteen bytes from byte `16 q` (the last
/// quarter for `q >= 3`).
#[spec]
pub fn quarter_of(c: [u8; 64], q: usize) -> [u8; 16] {{
    match q {{
        {quarters}
    }}
}}

{chunk_laws}
/// `mul_chunks` keeps the slice's length.
#[law]
fn mul_chunks_keeps_the_length(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t) {{
    ensures({{ let mut y = x; mul_chunks(&mut y, lo, hi); y }}.len() == x.len());
}}

/// `mul_chunks` multiplies every byte of every chunk.
#[law]
fn mul_chunks_is_the_scalar_reference(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t, k: usize, j: usize) {{
    requires(k < x.len() && j < 64usize);
    ensures({{ let mut y = x; mul_chunks(&mut y, lo, hi); y }}[k][j] == mul_byte(x[k][j], lo, hi));
}}
"#,
        quarters = (0..4).map(|q| format!("{} => [{}],", if q == 3 { "_".to_string() } else { format!("{q}usize") }, elems(16, |i| format!("c[{}]", 16 * q + i)))).collect::<Vec<_>>().join("\n        "),
        chunk_laws = (0..4).map(|q| format!("/// `chunk_mul` multiplies every byte of quarter {q} of the chunk.\n#[law]\nfn chunk_mul_quarter_{q}(c: [u8; 64], lo: uint8x16_t, hi: uint8x16_t) {{\n    ensures(quarter_of({{ let mut d = c; chunk_mul(&mut d, lo, hi); d }}, {q}usize) == mul_lanes(quarter_of(c, {q}usize), lo, hi));\n}}\n")).collect::<Vec<_>>().join("\n"),
    );
    let proof = format!(
        r#"
{chunk_proofs}
/// `mul_chunks`' loop from chunk `iter` on: the length kept, the chunks
/// before `iter` as they are, each from `iter` on as `chunk_mul` leaves it.
#[lift_attach(crate::a::mul_chunks, loop_nr = 0)]
fn mul_chunks_loop() {{
    invariant(iter <= x.len());
    decreases(x.len() - iter);
    ensures(|ret: &[[u8; 64]]| ret.len() == x.len()
        && forall(|k: usize| implies(k < x.len(), ret[k] == if k < iter {{ x[k] }} else {{ {{ let mut c = x[k]; crate::a::chunk_mul(&mut c, lo, hi); c }} }})));
}}

#[proof]
fn mul_chunks_keeps_the_length(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t) {{
    unfold(mul_chunks);
    follows();
}}

#[proof]
fn mul_chunks_is_the_scalar_reference(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t, k: usize, j: usize) {{
    unfold(mul_chunks);
    follows();
}}
"#,
        chunk_proofs = (0..4).map(|q| format!("/// Lane for lane (the lane closer: each lane's lookups are of nibbles).\n#[proof]\nfn chunk_mul_quarter_{q}(c: [u8; 64], lo: uint8x16_t, hi: uint8x16_t) {{\n    unfold(chunk_mul);\n    unfold(mul_16);\n    follows();\n}}\n")).collect::<Vec<_>>().join("\n"),
    );
    (laws, proof)
}

impl Scratch {
    /// Every proof and gate of `files` but the lock: whether all passed, and
    /// every diagnostic rendered.
    fn gates(&self, files: &[(String, String)]) -> (bool, String) {
        let c = self.check(files);
        if !c.ok() {
            return (false, c.render());
        }
        let (_, root) = self.abs(files);
        let b = driver::build_crate(&c, sandblaster_front::driver::LockUse::Accepting, &root);
        (b.permit.is_some(), format!("{}\n{}", b.render_failure(&c, &root), b.gates.diags.render(&c.sm)))
    }
}

/// Element attachments (stage neon-mul): `#[lift_attach(f, loop_nr = k,
/// element)]` states the contract of the `k`-th loop's body on one element
/// (`requires(..)`, `ensures(..)`, `at_start! { .. }`), and the reading
/// builds that body as an element function. Negative twins: `element`
/// without `loop_nr`; `requires(..)` on a loop attachment (a loop states
/// `invariant(..)`); another statement in an element attachment.
#[test]
fn an_element_attachment_states_a_loop_body_on_one_element() {
    let s = Scratch::new("element");
    let proof = |attr: &str, body: &str| format!("use sandblaster::prelude::*;\nuse core::arch::aarch64::*;\n\n#[lift_attach({attr})]\nfn chunk() {{\n    {body}\n}}\n");
    let c = s.check(&files(PTR, PTR_FNS, None, Some(&proof("crate::a::mul_chunks, loop_nr = 0, element", "requires(true);\n    ensures(|ret: [u8; 64]| ret.len() == 64usize);"))));
    assert!(c.ok(), "{}", c.render());
    assert_eq!(c.lift_facts.mir_elements.len(), 1, "{:?}", c.lift_facts.mir_elements);
    let refused = |attr: &str, body: &str, needle: &str| {
        let c = s.check(&files(PTR, PTR_FNS, None, Some(&proof(attr, body))));
        assert!(!c.ok() && c.render().contains(needle), "expected {needle:?}:\n{}", c.render());
    };
    refused("crate::a::mul_chunks, element", "ensures(|ret: [u8; 64]| ret.len() == 64usize);", "`element` names a loop's body");
    refused("crate::a::mul_chunks, loop_nr = 0", "requires(true);", "`requires(..)` is an element attachment's");
    refused("crate::a::mul_chunks, loop_nr = 0, element", "invariant(true);", "an element attachment holds");
}

/// The pending laws of the whole chunk and the slice, with their proof
/// attempts, through every gate: they do not all pass yet (run on demand,
/// `-- --ignored`; the stage reports' open issue: the quarter laws pass, the
/// loop's contract and the slice laws do not).
#[test]
#[ignore]
fn pending_chunk_and_slice_laws() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("pending-laws");
    let (laws, proof) = pending_laws();
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&(chunk_laws() + &laws)), Some(&(chunk_proof() + &proof))));
    eprintln!("ok: {ok}\n{why}");
}

/// The laws of the vector function and of the row load, and the lemma of a
/// quarter of a chunk, are proven; the crate is not yet fully specified:
/// the sections gate names exactly the three functions whose laws are
/// pending ([`pending_laws`]), and nothing else fails.
#[test]
fn the_vector_and_row_laws_are_proven() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("laws");
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&chunk_laws()), Some(&chunk_proof())));
    assert!(!ok, "the pending laws are missing, so the sections gate fails:\n{why}");
    assert!(why.contains("the proofs checked") && why.contains("failed the §15 gates (sections)"), "{why}");
    for f in ["chunk_mul", "mul_chunks", "mul", "xor_rows"] {
        assert!(why.contains(&format!("`crate::a::{f}` is not determined by the specification")), "{f}: {why}");
    }
    for f in ["mul_16", "load_row"] {
        assert!(!why.contains(&format!("`crate::a::{f}` is not determined")), "{f}: {why}");
    }
    assert!(!why.contains("error[obligation]") && !why.contains("error[example]") && !why.contains("error[law"), "{why}");
}

use sandblaster_front::lift::LiftFacts;
use sandblaster_front::mir::checked::{GateOptions, ModuleTheorems};

/// The gate's theorems on the structured reading of `c`'s lifted functions,
/// with the MIR the literal reading reads taken from `facts`.
fn theorems(c: &Checked, facts: &LiftFacts) -> ModuleTheorems {
    theorems_only(c, facts, None)
}

fn theorems_only(c: &Checked, facts: &LiftFacts, only: Option<&str>) -> ModuleTheorems {
    let only = only.map(str::to_string);
    let mut reps = sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        let mut out = checked::elaborate_names(k, &items);
        checked::prove_and_check(&mut out, k, facts, &GateOptions { only, trace: std::env::var("UR_TRACE").is_ok(), ..GateOptions::default() })
    });
    assert_eq!(reps.len(), 1, "one lifted MIR module");
    reps.remove(0)
}

/// Every function of the chunk multiplier read from MIR has its theorem:
/// the literal reading (the loads and stores through the pointers, the
/// slice's `IterMut`) equals the structured one, the loop's lemma included.
#[test]
fn the_chunk_multipliers_theorems_are_proven() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("theorems");
    let c = s.check(&files(PTR, PTR_FNS, None, None));
    assert!(c.ok(), "{}", c.render());
    // (A-S8: the `&mut` parameters raw pointers are formed from, listed in
    // the record as assumed non-aliasing; a shared formation's `y` is not)
    let mut pp = c.lift_facts.pointer_params.clone();
    pp.sort();
    assert_eq!(pp, [("chunk_mul", "chunk"), ("mul_chunks", "x"), ("xor_rows", "x")].map(|(a, b)| (a.to_string(), b.to_string())).to_vec());
    let m = theorems(&c, &c.lift_facts);
    for o in &m.outcomes {
        eprintln!("{} {} : {}", o.kind, o.global, o.result.as_ref().map(|p| format!("proven ({} nodes, walk {:.2}s, check {:.2}s)", p.nodes, p.walk_secs, p.check_secs)).unwrap_or_else(|e| e.chars().take(3000).collect()));
    }
    assert!(m.missing.is_empty(), "{:?}", m.missing);
    let proven: BTreeSet<&str> = m.outcomes.iter().filter(|o| o.result.is_ok()).map(|o| o.global.as_str()).collect();
    for f in ["mul_16", "chunk_mul", "mul_chunks__loop0", "mul_chunks", "mul", "load_row", "xor_rows"] {
        assert!(proven.contains(format!("crate::a::{f}").as_str()), "{f}: not proven");
    }
    assert!(m.outcomes.iter().all(|o| o.result.is_ok()), "a theorem failed");
}


/// Lifted in place, every twin is refused with its reason named, before
/// any theorem (the diagnostic pass names what is outside the narrow
/// reading; the structured reading names an access out of bounds), and the
/// crate function named `add` is read as any function of the crate.
#[test]
fn each_twin_is_refused_by_name_when_lifted() {
    let s = Scratch::new("twins");
    let c = s.check(&files(TWINS, "calls_add", None, None));
    assert!(!c.ok());
    let r = c.render();
    // the source lines of each function of the twins' file
    let src: Vec<&str> = TWINS.0.lines().collect();
    let range = |f: &str| -> std::ops::Range<usize> {
        let start = src.iter().position(|l| l.starts_with(&format!("pub fn {f}("))).unwrap_or_else(|| panic!("no `{f}`")) + 1;
        let end = src[start..].iter().position(|l| l.starts_with("pub fn ") || l.starts_with("pub unsafe fn ")).map_or(src.len(), |e| start + e) + 1;
        start..end
    };
    // the diagnostics at a line of `f` (each with its continuation lines)
    let diags = |f: &str| -> String {
        let rg = range(f);
        let mut out = String::new();
        let mut keep = false;
        for l in r.lines() {
            if let Some(at) = l.find("src/a.rs:") {
                let n: usize = l[at + 9..].split(':').next().and_then(|x| x.parse().ok()).unwrap_or(0);
                keep = rg.contains(&n);
            }
            if keep {
                out.push_str(l);
                out.push('\n');
            }
        }
        out
    };
    for (f, why) in [
        ("load_past_end", "bytes 49..65 of a 64-byte base"),
        ("offset_past_end", "a pointer offset to byte 65, outside its base's 64 bytes"),
        ("store_through_shared", "W4: a store through a pointer formed from a shared reference"),
        ("escape", "a raw pointer used as a value"),
        ("stored", "W1: the pointer"),
        ("alias", "W2:"),
        ("alias_read", "W2:"),
        ("two_formations", "W2:"),
        ("bool_table", "`bool` has a niche"),
        ("ptr_read", "a call of the library `unsafe fn` `std::ptr::read`"),
        ("unchecked", "a call of the library `unsafe fn` `core::slice::<impl [T]>::get_unchecked`"),
        ("deref", "dereferenced as a place (`*p`)"),
        ("byte_offset", "a call of the library `unsafe fn` `std::ptr::mut_ptr::<impl *mut T>::byte_add`"),
    ] {
        let d = diags(f);
        assert!(d.contains(why), "{f}: no `{why}` in\n{d}\n(all:\n{r})");
        eprintln!("{f}: refused ({why})");
    }
    assert!(r.contains("requires feature(s) sm4"), "{r}");
    // (nothing about the crate's own `add` or its caller)
    for f in ["add", "calls_add"] {
        assert!(!diags(f).contains("error"), "{f}:\n{}", diags(f));
    }
}

// ---------------------------------------------------------------------------
// fault injection: the literal side of the pointer constructs
// ---------------------------------------------------------------------------

/// The theorem outcome of `global` in `m`.
fn outcome<'m>(m: &'m ModuleTheorems, global: &str) -> Result<(), &'m str> {
    if let Some(o) = m.outcomes.iter().find(|o| o.global == global) {
        return o.result.as_ref().map(|_| ()).map_err(|e| e.as_str());
    }
    m.missing.iter().find(|(g, _)| g == global).map(|(_, why)| Err(why.as_str())).unwrap_or_else(|| panic!("no theorem planned for `{global}`"))
}

/// The call terminators of `f` (block, callee, arguments).
fn calls(f: &mut ir::Fn) -> Vec<(usize, &mut Callee, &mut Vec<ir::Operand>)> {
    f.blocks.iter_mut().enumerate().filter_map(|(b, bl)| match &mut bl.term {
        Term::Call(c, args, _, _) => Some((b, c, args)),
        _ => None,
    }).collect()
}

/// Fault injection on the chunk multiplier (the literal side: the
/// structured reading, read from the unchanged MIR, stays): an offset, a
/// load's width, the family a load goes through, a formation's kind — each
/// must break the theorem of the function that holds it, for its own reason
/// — and an `IterMut` model whose codes overlap (A-S4's disjointness lost)
/// must break the loop's lemma. The functions not mutated keep theirs.
#[test]
fn a_mutated_pointer_construct_breaks_its_functions_theorem() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("faults");
    let c = s.check(&files(PTR, PTR_FNS, None, None));
    assert!(c.ok(), "{}", c.render());
    let key = |f: &str| format!("fx_sd_ptr::a::{f}");
    type Change = Box<dyn Fn(&mut ir::Fn)>;
    let mutations: Vec<(&str, &str, Change)> = vec![
        // `x_ptr.add(16)` read as `add(17)`
        ("an offset", "chunk_mul", Box::new(|f: &mut ir::Fn| {
            let mut done = false;
            for (_, _, args) in calls(f) {
                if let [_, ir::Operand::Const(ir::Const::Int(_, v))] = &mut args[..]
                    && *v == 16
                    && !done
                {
                    *v = 17;
                    done = true;
                }
            }
            assert!(done, "no `add(16)`");
        })),
        // the first 16-byte load read as the 8-byte `vld1_u8`
        ("a load's width", "chunk_mul", Box::new(|f: &mut ir::Fn| {
            let (_, c, _) = calls(f).into_iter().find(|(_, c, _)| matches!(c, Callee::Arch(a) if a.path.ends_with("::vld1q_u8"))).expect("a load");
            let Callee::Arch(a) = c else { unreachable!() };
            a.path = "core::arch::aarch64::vld1_u8".into();
        })),
        // `y`'s first load through `x`'s pointer: another family's base
        ("a load's family", "xor_rows", Box::new(|f: &mut ir::Fn| {
            let mut ptrs: Vec<usize> = Vec::new();
            for (_, c, args) in calls(f) {
                if let (Callee::Arch(a), [ir::Operand::Copy(p) | ir::Operand::Move(p)]) = (&*c, &args[..])
                    && a.path.ends_with("::vld1q_u8")
                    && !ptrs.contains(&p.local)
                {
                    ptrs.push(p.local);
                }
            }
            assert!(ptrs.len() >= 2, "{ptrs:?}");
            // (the first load of the second family reads the first's pointer)
            let (x, y) = (ptrs[0], *ptrs.last().unwrap());
            let mut done = false;
            for (_, c, args) in calls(f) {
                if let (Callee::Arch(a), [ir::Operand::Copy(p) | ir::Operand::Move(p)]) = (&*c, &mut args[..])
                    && a.path.ends_with("::vld1q_u8")
                    && p.local == y
                    && !done
                {
                    p.local = x;
                    done = true;
                }
            }
            assert!(done);
        })),
        // `chunk.as_mut_ptr()` read as `as_ptr()`: a shared formation
        ("a formation's kind", "chunk_mul", Box::new(|f: &mut ir::Fn| {
            let (_, c, _) = calls(f).into_iter().find(|(_, c, _)| matches!(c, Callee::Fn(k) if k.contains("as_mut_ptr"))).expect("a formation");
            let Callee::Fn(k) = c else { unreachable!() };
            *k = k.replace("as_mut_ptr", "as_ptr");
        })),
    ];
    let mut caught = Vec::new();
    for (what, target, change) in &mutations {
        let mut facts = c.lift_facts.clone();
        let mut loaded = (*facts.mir_loaded[0].loaded).clone();
        change(loaded.m.fns.get_mut(&key(target)).unwrap_or_else(|| panic!("no MIR of `{target}`")));
        facts.mir_loaded[0].loaded = std::sync::Arc::new(loaded);
        let m = theorems(&c, &facts);
        let global = format!("crate::a::{target}");
        match outcome(&m, &global) {
            Ok(()) => panic!("{what} changed in `{target}`: its theorem still holds"),
            Err(why) => {
                assert!(!why.starts_with("not attempted"), "{what}: `{target}` failed only through a callee: {why}");
                eprintln!("{what} in `{target}`: caught ({})", why.lines().next().unwrap_or("").chars().take(200).collect::<String>());
                caught.push(*what);
            }
        }
        for g in ["mul_16", "load_row", "mul_chunks__loop0"] {
            if g != *target {
                assert_eq!(outcome(&m, &format!("crate::a::{g}")), Ok(()), "`{g}` is not touched by {what}");
            }
        }
    }
    // the IterMut model with overlapping codes (`literal::test_fault`; the
    // readings are generated on the thread that sets it)
    let m = {
        let (c, facts) = (&c, c.lift_facts.clone());
        let mut reps = sandblaster_front::elab::with_big_stack(move || {
            sandblaster_front::mir::literal::test_fault::set_iter_mut_overlaps(true);
            let k = c.krate.as_ref().unwrap();
            let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
            let mut out = checked::elaborate_names(k, &items);
            let r = checked::prove_and_check(&mut out, k, &facts, &GateOptions::default());
            sandblaster_front::mir::literal::test_fault::set_iter_mut_overlaps(false);
            r
        });
        reps.remove(0)
    };
    let why = outcome(&m, "crate::a::mul_chunks__loop0").expect_err("the loop lemma holds with overlapping codes");
    eprintln!("overlapping IterMut codes: caught ({})", why.lines().next().unwrap_or("").chars().take(200).collect::<String>());
    assert_eq!(outcome(&m, "crate::a::chunk_mul"), Ok(()));
    caught.push("overlapping IterMut codes");
    assert_eq!(caught.len(), 5, "{caught:?}");
}

// ---------------------------------------------------------------------------
// A-S5: the admitted rows against the toolchain's stdarch
// ---------------------------------------------------------------------------

/// Every admitted load and store row (`ptr::MEM_INTRINSICS`) is, in the
/// toolchain's own stdarch source, an unaligned copy of its bytes
/// (`read_unaligned`, `write_unaligned`, or `copy_nonoverlapping` of the
/// bytes), as the row records: its alignment obligation (none) and its
/// byte count rest on that. Re-run at every toolchain bump (the source is
/// the `rust-src` component of the toolchain that builds the shipped code).
#[test]
fn the_admitted_rows_are_unaligned_copies_in_the_toolchains_stdarch() {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = std::process::Command::new(&rustc).args(["--print", "sysroot"]).output().expect("rustc --print sysroot");
    let sysroot = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let src = Path::new(&sysroot).join("lib/rustlib/src/rust/library/stdarch/crates/core_arch/src");
    assert!(src.is_dir(), "no stdarch source at {} (install the toolchain's `rust-src` component)", src.display());
    let mut checked = 0;
    for row in sandblaster_front::mir::ptr::MEM_INTRINSICS {
        let (file, prim) = row.source.split_once(": ").unwrap_or_else(|| panic!("{}: source `{}`", row.path, row.source));
        let prim = prim.split_whitespace().next().unwrap();
        let name = row.path.rsplit("::").next().unwrap();
        let text = std::fs::read_to_string(src.join(file)).unwrap_or_else(|e| panic!("{}: {file}: {e}", row.path));
        let start = [format!("pub unsafe fn {name}("), format!("pub const unsafe fn {name}(")].iter().find_map(|h| text.find(h.as_str())).unwrap_or_else(|| panic!("`{name}` is not defined in {file}"));
        let body = &text[start..start + text[start..].find("\n}").unwrap_or_else(|| panic!("`{name}`: no end"))];
        let sig = &body[..body.find('{').unwrap()];
        assert!(sig.contains("*const") || sig.contains("*mut"), "`{name}` takes no raw pointer: {sig}");
        assert!(body.contains(prim), "`{name}` in {file} is not `{prim}` (the row's reading); its body:\n{body}");
        for bad in ["read_volatile", "write_volatile", "simd_masked", "simd_gather", "simd_scatter", "nontemporal"] {
            assert!(!body.contains(bad), "`{name}` uses `{bad}`:\n{body}");
        }
        checked += 1;
    }
    assert_eq!(checked, sandblaster_front::mir::ptr::MEM_INTRINSICS.len());
    eprintln!("{checked} rows checked against {}", src.display());
}

// ---------------------------------------------------------------------------
// The Miri gate's record (A-S1, A-process): re-run at every toolchain bump
// ---------------------------------------------------------------------------

/// The files the Miri gate covers (`tests/miri/run.sh` hashes the same
/// list): the fixtures, the harnesses, the `cpufeatures` patch and
/// Commonware's NEON engine. Paths from the repository's root.
const MIRI_GATE_FILES: &[&str] = &[
    "sandblaster/front/tests/mir_fixtures/sd_ptr/src/a.rs",
    "sandblaster/front/tests/mir_fixtures/sd_ptr_twins/src/a.rs",
    "sandblaster/front/tests/miri/src/lib.rs",
    "sandblaster/front/tests/miri/tests/positive.rs",
    "sandblaster/front/tests/miri/tests/twins.rs",
    "sandblaster/front/tests/miri/engines/tests/neon.rs",
    "sandblaster/front/tests/miri/engines/cpufeatures-static/src/miri.rs",
    "cryptography/src/reed_solomon/engine/engine_neon.rs",
];

/// Why the gate's record `record` does not cover this tree (empty when it
/// does): it must name the pinned toolchain `channel` and, for every file
/// of [`MIRI_GATE_FILES`], that file's current SHA-256.
fn miri_gate_stale(record: &str, channel: &str, root: &Path) -> Vec<String> {
    use sandblaster_front::surface::{hex, sha256};
    let mut why = Vec::new();
    let mut toolchain = None;
    let mut hashed = BTreeMap::new();
    for l in record.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match l.split_whitespace().collect::<Vec<_>>()[..] {
            ["toolchain", t] => toolchain = Some(t.to_string()),
            ["sha256", h, f] => {
                hashed.insert(f.to_string(), h.to_string());
            }
            _ => why.push(format!("a line the record does not have: `{l}`")),
        }
    }
    if toolchain.as_deref() != Some(channel) {
        why.push(format!("run on {}, while the pinned toolchain is {channel}", toolchain.as_deref().unwrap_or("no toolchain")));
    }
    for f in MIRI_GATE_FILES {
        match (hashed.get(*f), std::fs::read(root.join(f))) {
            (None, _) => why.push(format!("`{f}` not covered")),
            (Some(_), Err(e)) => why.push(format!("`{f}`: {e}")),
            (Some(h), Ok(b)) if *h != hex(&sha256(&b)) => why.push(format!("`{f}` changed since")),
            _ => {}
        }
    }
    why
}

/// The Miri gate (`sh sandblaster/front/tests/miri/run.sh --engines`) ran
/// clean on the pinned toolchain over the files it covers as they are: its
/// record names that toolchain and each file's SHA-256. A toolchain bump,
/// or a change to a covered file, fails here until the gate is run again.
/// Twins: a record of another toolchain, of a file since changed, or
/// missing a file, is refused.
#[test]
fn the_miri_gate_ran_on_this_toolchain_over_these_files() {
    let front = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = front.join("../..");
    let pin = std::fs::read_to_string(root.join("sandblaster/mirx/rust-toolchain.toml")).expect("mirx/rust-toolchain.toml");
    let channel = pin.lines().find_map(|l| l.trim().strip_prefix("channel = \"")?.strip_suffix('"')).expect("the pinned channel");
    let record = std::fs::read_to_string(front.join("tests/miri/GATE.txt")).expect("tests/miri/GATE.txt: run `sh sandblaster/front/tests/miri/run.sh --engines` (the Miri gate writes it when clean)");
    let why = miri_gate_stale(&record, channel, &root);
    assert!(why.is_empty(), "the Miri gate's record does not cover this tree ({}): run `sh sandblaster/front/tests/miri/run.sh --engines` again", why.join("; "));
    // the twins
    let other = record.replace(&format!("toolchain {channel}"), "toolchain nightly-2000-01-01");
    assert!(miri_gate_stale(&other, channel, &root).iter().any(|w| w.contains("pinned toolchain")));
    let engine = MIRI_GATE_FILES.last().unwrap();
    let line = record.lines().find(|l| l.ends_with(engine)).unwrap();
    let changed = record.replace(line, &format!("sha256 {} {engine}", "0".repeat(64)));
    assert_eq!(miri_gate_stale(&changed, channel, &root), vec![format!("`{engine}` changed since")]);
    let missing = record.replace(line, "");
    assert_eq!(miri_gate_stale(&missing, channel, &root), vec![format!("`{engine}` not covered")]);
}
