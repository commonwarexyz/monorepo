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
/// Pointers whose base lives in a local of the forming function, and the
/// window rule's other siblings (stage soundness-fixes, the review's F1).
const LOCAL: Code = (include_str!("mir_fixtures/sd_ptr_local/src/a.rs"), include_str!("mir_fixtures/sd_ptr_local/a.sbmir"), include_str!("mir_fixtures/sd_ptr_local/a.window.sbmir"));

/// The build's static features of `aarch64-apple-darwin` (stable rustc's
/// `CARGO_CFG_TARGET_FEATURE`).
fn aarch64_features() -> Vec<String> {
    sandblaster_front::target::TargetInfo::aarch64_apple_darwin().features.into_iter().collect()
}

fn names(features: Option<Vec<String>>) -> ModuleNames {
    ModuleNames { module: String::new(), sealed: BTreeSet::new(), host_enums: BTreeMap::new(), requires: BTreeSet::new(), open: BTreeMap::new(), dsl_modules: vec!["crate::a".into()], current: Default::default(), consts: BTreeMap::new(), invariant_types: BTreeSet::new(), host: Default::default(), target_arch: Some("aarch64".into()), static_features: features, codegen_flags: Some((None, String::new())), build_cfg: None }
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

/// The window verdicts of every formation of `code`'s functions: (function,
/// formation, verdict, the `&mut` parameters named).
fn window_verdicts(code: Code) -> Vec<(String, String, Result<(), String>, Vec<usize>)> {
    let l = loaded(code);
    let mut out = Vec::new();
    for (k, f) in &l.m.fns {
        for v in f.window.iter().flatten() {
            eprintln!("{k}: {} at {:?}: {:?} params {:?}", v.what, v.at, v.result, v.params);
            out.push((k.rsplit("::").next().unwrap_or(k).to_string(), v.what.clone(), v.result.clone(), v.params.clone()));
        }
    }
    out
}

/// The review's F1 (stage soundness-fixes): a base that lives in a local of
/// the forming function — a local array, a by-value parameter, a field of a
/// local struct or tuple, a row of a local array, a temporary — is an
/// ancestor whatever its type, and its storage markers are uses: every
/// direct use of it inside the window (a write, a mutable borrow, a move,
/// its storage's end, a closure or a call lent it) is refused, W2 for a
/// mutable family, W3 for a shared one. The positive functions (a local
/// written only through its pointer, two shared pointers to one local, an
/// immutable static, a promoted constant) pass.
#[test]
fn a_base_that_lives_in_a_local_is_an_ancestor() {
    let vs = window_verdicts(LOCAL);
    for f in ["local_ok", "two_shared_ok", "static_ok", "promoted_ok"] {
        let v: Vec<_> = vs.iter().filter(|v| v.0 == f).collect();
        assert!(!v.is_empty() && v.iter().all(|v| v.2.is_ok() && v.3.is_empty()), "{f}: {v:?}");
    }
    let failed = |f: &str, rule: &str| vs.iter().any(|v| v.0 == f && v.2.as_ref().is_err_and(|e| e.starts_with(rule)));
    let mut wrong = Vec::new();
    for (f, rule) in [
        // the review's six programs
        ("local_write", "W2"),
        ("local_shared", "W3"),
        ("local_scope", "W2"),
        ("local_from_mut", "W2"),
        ("local_raw_deref", "W2"),
        ("param_by_value", "W3"),
        // the siblings
        ("param_by_value_mut", "W2"),
        ("local_raw_write", "W2"),
        ("raw_scope", "W2"),
        ("struct_field", "W2"),
        ("tuple_field", "W2"),
        ("nested_array", "W2"),
        ("boxed", "W2"),
        ("vec_slice", "W2"),
        ("temporary", "W3"),
        ("temporary_mut", "W2"),
        ("closure_write", "W2"),
        ("two_pointers", "W2"),
        ("shared_then_mut", "W3"),
        ("reborrow_moved", "W2"),
        ("after_loop", "W2"),
        ("after_call", "W2"),
        ("loop_scope", "W2"),
        ("moved_into_call", "W3"),
    ] {
        if !failed(f, rule) {
            wrong.push(format!("{f}: no `{rule}` verdict: {:?}", vs.iter().filter(|v| v.0 == f).collect::<Vec<_>>()));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// W3 fails closed (stage soundness-fixes): inside a shared family's window
/// an ancestor is only read, a reference moved whole, a non-base storage
/// marked. On a hand-written window extraction — a shared formation from a
/// reference parameter `_1` (an ancestor that is no base) and one from a
/// local array `_5` (a base), each with one point inside its window — each
/// other use is refused: a move out of memory behind the reference, a drop
/// of an ancestor's place, an unprinted statement, rvalue or callee
/// (anything; a statement W1 refuses first, as it reads every local), a
/// borrow of a kind that is not `shared` or `fake` (mutable, whatever it is
/// named), a base moved or dropped, and an owning value (a `Box` the base is
/// reached through) moved, which its new owner could free; the reads, and a
/// shared reference moved whole, pass.
#[test]
fn the_window_rule_fails_closed_inside_a_shared_window() {
    // (`_1: &[u8; 16]` the parameter, `_5: [u8; 16]` a local; the
    // formation is `as_ptr` of `_3`, an `unsize` of `_4`; the window is
    // `bb1`: its statement `{stmt}` and its terminator `{term}`)
    let func = |name: &str, borrow: &str, stmt: &str, term: &str| {
        format!(
            "(fn \"fx_sd_ptr_local::a::{name}\"\n  (kind root) (def \"fx_sd_ptr_local::a::{name}\") (args ())\n  (item fn \"{name}\")\n  (span \"src/a.rs\" 1 1)\n  (local)\n  (argc 1)\n  (locals\n    (0 (simd \"core::arch::aarch64::uint8x16_t\" u8 16) mut)\n    (1 (ref shared (array u8 16)) imm)\n    (2 (ptr const u8) imm)\n    (3 (ref shared (slice u8)) mut)\n    (4 (ref shared (array u8 16)) mut)\n    (5 (array u8 16) mut)\n    (6 (ref mut (array u8 16)) mut)\n    (7 (array u8 16) mut)\n    (8 (ref shared (array u8 16)) mut)\n    (9 (ptr mut (array u8 16)) mut)\n    (10 (adt \"std::boxed::Box<[u8; 16]>\") mut)\n    (11 (adt \"std::boxed::Box<[u8; 16]>\") mut))\n  (bb 0\n    (assign (p 5) (repeat (int u8 0) 16) (at \"src/a.rs\" 2 5))\n    (assign (p 4) {borrow} (at \"src/a.rs\" 3 13))\n    (assign (p 3) (cast unsize (move (p 4)) (ref shared (slice u8))) (at \"src/a.rs\" 3 13))\n    (call (fn \"core::slice::<impl [u8]>::as_ptr\") (args (move (p 3))) (p 2) 1 (at \"src/a.rs\" 3 13)))\n  (bb 1\n    {stmt}\n    {term})\n  (bb 2\n    (call (arch \"core::arch::aarch64::vld1q_u8\" (imms) (features \"neon\") unsafe pointer) (args (copy (p 2))) (p 0) 3 (at \"src/a.rs\" 5 14)))\n  (bb 3\n    (return (at \"src/a.rs\" 6 2)))\n)\n"
        )
    };
    let (param, local, boxed) = ("(ref shared (p 1 deref))", "(ref shared (p 5))", "(ref shared (p 10 deref))");
    let read = "(assign (p 7) (use (copy (p 1 deref))) (at \"src/a.rs\" 4 5))";
    let goto = "(goto 2 (at \"src/a.rs\" 4 5))";
    let cases: Vec<(&str, &str, &str, &str, Option<&str>)> = vec![
        // the reads, a whole reference moved, a non-base storage marker: pass
        ("w3_read", param, read, goto, None),
        ("w3_shared_borrow", param, "(assign (p 8) (ref shared (p 1 deref)) (at \"src/a.rs\" 4 5))", goto, None),
        ("w3_move_reference", param, "(assign (p 8) (use (move (p 1))) (at \"src/a.rs\" 4 5))", goto, None),
        ("w3_base_read", local, "(assign (p 7) (use (copy (p 5))) (at \"src/a.rs\" 4 5))", goto, None),
        ("w3_storage_reference", param, "(storage-dead 4)", goto, None),
        // refused
        ("w3_move_out", param, "(assign (p 7) (use (move (p 1 deref))) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_1`, through which the base is reached, is moved out of")),
        ("w3_drop", param, read, "(drop (p 1) glue 2 (at \"src/a.rs\" 4 5))", Some("W3: `_1`, through which the base is reached, is dropped")),
        // (an unprinted statement reads every local, the family's too: W1)
        ("w3_unprinted_statement", param, "(deinit (p 7))", goto, Some("W1: the pointer `_2` escapes")),
        ("w3_unprinted_rvalue", param, "(assign (p 7) (shallow-init-box (move (p 1))) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_1`, through which the base is reached, is used by an operation the extraction does not print")),
        ("w3_unprinted_callee", param, read, "(call (unsupported \"call through a function pointer\") (args) (p 7) 2 (at \"src/a.rs\" 4 5))", Some("W3: `_1`, through which the base is reached, is used by an operation the extraction does not print")),
        ("w3_borrow_kind", param, "(assign (p 6) (ref two-phase (p 1 deref)) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_1`, through which the base is reached, is written or used mutably")),
        ("w3_raw_mut", param, "(assign (p 9) (addr-of mut (p 1 deref)) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_1`, through which the base is reached, is written or used mutably")),
        ("w3_base_moved", local, "(assign (p 7) (use (move (p 5))) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_5`, the local the base lives in, is moved")),
        // (an owning value moved whole: its new owner could free the base)
        ("w3_box_moved", boxed, "(assign (p 11) (use (move (p 10))) (at \"src/a.rs\" 4 5))", goto, Some("W3: `_10`, through which the base is reached, is moved")),
        ("w3_base_dropped", local, "(assign (p 7) (use (copy (p 5))) (at \"src/a.rs\" 4 5))", "(drop (p 5) glue 2 (at \"src/a.rs\" 4 5))", Some("W3: `_5`, the local the base lives in, is dropped")),
    ];
    let mut text = LOCAL.2.to_string();
    for (name, borrow, stmt, term, _) in &cases {
        text.push_str(&func(name, borrow, stmt, term));
    }
    let w = ir::parse(&text).unwrap_or_else(|e| panic!("{e}"));
    let mut wrong = Vec::new();
    for (name, _, _, _, want) in &cases {
        let f = &w.fns[&format!("fx_sd_ptr_local::a::{name}")];
        // (the formation at line 3; `w3_raw_mut`'s `&raw mut` is another)
        let vs = mir::window::check(&w, f);
        let [v] = vs.iter().filter(|v| v.at.as_ref().is_some_and(|a| a.1 == 3)).collect::<Vec<_>>()[..] else { panic!("{name}: {vs:?}") };
        eprintln!("{name}: {:?}", v.result);
        match (want, &v.result) {
            (None, Ok(())) => {}
            (Some(w), Err(e)) if e.starts_with(w) => {}
            _ => wrong.push(format!("{name}: expected {want:?}, got {:?}", v.result)),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The window verdicts of every checked-in window extraction (the fixtures'
/// and the shipped root's), one line each, printed (`--nocapture`) so that a
/// change of the window rule can be compared verdict by verdict; the
/// shipped root's nine formations (`mul_128`'s eight table rows, `mul_neon`'s
/// chunk) pass, `mul_neon`'s naming its `&mut` parameter `x`.
#[test]
fn every_checked_in_window_verdict() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut pairs = vec![repo.join("cryptography/sandblaster/rs_engine/rs_engine")];
    for d in std::fs::read_dir(repo.join("sandblaster/front/tests/mir_fixtures")).unwrap().map(Result::unwrap) {
        if d.path().join("a.window.sbmir").exists() {
            pairs.push(d.path().join("a"));
        }
    }
    pairs.sort();
    let mut rs_engine = Vec::new();
    for p in pairs {
        let w = ir::parse(&std::fs::read_to_string(p.with_extension("window.sbmir")).unwrap()).unwrap();
        let name = p.parent().unwrap().file_name().unwrap().to_string_lossy().to_string();
        for (k, f) in &w.fns {
            for v in mir::window::check(&w, f) {
                eprintln!("VERDICT {name} {k}: {} at {:?}: {:?} params {:?}", v.what, v.at, v.result, v.params);
                if name == "rs_engine" {
                    rs_engine.push((k.rsplit("::").next().unwrap().to_string(), v));
                }
            }
        }
    }
    assert_eq!(rs_engine.len(), 9, "{rs_engine:?}");
    for (f, v) in &rs_engine {
        let params: &[usize] = if f == "mul_neon" { &[2] } else { &[] };
        assert!(v.result.is_ok() && v.params == params && (f == "mul_128" || f == "mul_neon"), "{f}: {v:?}");
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

/// The literal reading of the review's F1 programs and their siblings
/// (stage soundness-fixes): each refused formation leaves L stuck there,
/// its window rule named. Three twins are stuck earlier in this test's
/// environment, which declares none of the fixture's types (`struct_field`
/// on `Pair`, `moved_into_call` on `Holder`) or holds a `Box`, which L does
/// not model (`boxed`): their formations' verdicts are the window rule's
/// (`a_base_that_lives_in_a_local_is_an_ancestor`), and the lift names them
/// (`each_local_base_twin_is_refused_by_name_when_lifted`). The positive
/// functions that need no constant reference read as rustc computes them (a
/// local written only through its pointer, two shared pointers to one
/// local); an immutable static and a promoted constant pass the window rule,
/// but L does not read a constant reference to an array (stuck, named): a
/// conservative refusal.
#[test]
fn the_literal_reading_is_stuck_where_a_base_in_a_local_is_used_in_the_window() {
    with_env(|env| {
        let l = loaded(LOCAL);
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        let key = |f: &str| format!("fx_sd_ptr_local::a::{f}");
        let faults = |f: &str| -> String {
            match lit.lfn(&key(f)) {
                Some(lf) => lf.faults.join("\n"),
                None => lit.refused.iter().find(|(k, _)| *k == key(f)).map(|(_, e)| e.clone()).unwrap_or_else(|| panic!("no reading of `{f}`")),
            }
        };
        for (f, why) in [
            ("local_write", "W2: `_2`, the local the base lives in, is written"),
            ("local_shared", "W3: `_2`, the local the base lives in, is written"),
            ("local_scope", "W2: `_4`, the local the base lives in, is given a storage marker"),
            ("local_from_mut", "W2: `_2`, the local the base lives in, is written"),
            ("local_raw_deref", "W2: `_2`, the local the base lives in, is written"),
            ("param_by_value", "W3: `_1`, the local the base lives in, is written"),
            ("param_by_value_mut", "W2: `_1`, the local the base lives in, is written"),
            ("local_raw_write", "W2: `_2`, the local the base lives in, is written"),
            ("raw_scope", "W2: `_4`, the local the base lives in, is given a storage marker"),
            ("struct_field", "no kernel declaration `crate::a::Pair`"),
            ("tuple_field", "W2: `_2`, the local the base lives in, is read"),
            ("nested_array", "W2: `_2`, the local the base lives in, is written"),
            ("boxed", "the projection Deref of Ptr"),
            ("vec_slice", "W2: `_2`, the local the base lives in, is borrowed mutably"),
            ("temporary", "W3: `_5`, the local the base lives in, is given a storage marker"),
            ("temporary_mut", "W2: `_5`, the local the base lives in, is given a storage marker"),
            ("closure_write", "W2: `_2`, the local the base lives in, is borrowed mutably"),
            ("two_pointers", "W2: `_3`, the local the base lives in, is borrowed mutably"),
            ("shared_then_mut", "W3: `_2`, the local the base lives in, is borrowed mutably"),
            ("reborrow_moved", "W2: `_3`, through which the base is reached"),
            ("after_loop", "W2: `_3`, the local the base lives in, is written"),
            ("after_call", "W2: `_2`, the local the base lives in, is borrowed mutably"),
            ("loop_scope", "W2: `_5`, the local the base lives in, is given a storage marker"),
            ("moved_into_call", "no kernel declaration `crate::a::Holder`"),
            ("static_ok", "an aggregate constant of Array(Int(false, 8), 16)"),
            ("promoted_ok", "an aggregate constant of Array(Int(false, 8), 16)"),
            ("static_mut_store", "constant of type (ptr mut (array u8 16))"),
        ] {
            let got = faults(f);
            assert!(got.contains(why), "{f}: {why}\n{got}");
            eprintln!("{f}: stuck ({why})");
        }
        // the positive functions without a constant reference: read, and as
        // rustc computes them
        for (f, args, want) in [("local_ok", vec![u8_array(&[7u8; 16])], u8_array(&[7u8; 16])), ("two_shared_ok", vec!["4u8".to_string()], u8_array(&[4u8; 16]))] {
            let lf = lit.lfn(&key(f)).unwrap_or_else(|| panic!("{f}: no reading"));
            assert!(lf.faults.is_empty(), "{f}: {:?}", lf.faults);
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            same(env, &run(lf, 2, &a), &format!("mir::Res::Ret[Array U8 16usize]({want})"));
            eprintln!("{f}: as rustc computes");
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
        self.check_with(files, &TargetInfo::aarch64_apple_darwin())
    }

    fn check_with(&self, files: &[(String, String)], target: &TargetInfo) -> Checked {
        let (abs, root) = self.abs(files);
        let fs = MemFs::from_files(abs.iter().map(|(p, c)| (p.as_str(), c.as_str())));
        driver::check(Path::new(&root), &fs, target)
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
/// automation's read-back bound on the 64-byte chunk bodies), and their
/// proofs. The chunk's four quarter laws prove by the lane closer
/// (`auto::lanes`, stage table-lookup-lanes). `mul_chunks` is read with its
/// loop's body on one chunk as an element function (stage neon-mul): the
/// element's contract (every byte multiplied, `chunk64`), the loop's
/// (`muls_from`, one chunk at a time) and the function's summary prove, and
/// with them the length law (stage prover-gaps). The law of every byte
/// (`pending: true`) proves since stage leftovers: its last step reads a
/// 64-byte array literal at a symbolic byte (`mul64(c)[j] ==
/// mul_byte(c[j])`) through its element function, `map64_at` (`[g(c[0]),
/// .., g(c[63])][j] == g(c[j])`, proven once for the width by its 64 cases
/// with `g` and `c` symbolic, where enumerating the bytes of `mul64` itself
/// outgrew the kernel's check), under the precondition `j < 64` that
/// `by_cases` now generalizes with `j` (it built an ill-typed proof); the
/// byte is stated over the opaque `chunk64` (`chunk64_at`), so the law's
/// goal never holds the 64 bytes; and the loop's chunk `k = i` is read
/// through `seq::index_update_same`.
fn pending_laws(pending: bool) -> (String, String) {
    let byte_law = r#"
/// `mul_chunks` multiplies every byte of every chunk.
#[law]
fn mul_chunks_is_the_scalar_reference(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t, k: usize, j: usize) {
    requires(k < x.len() && j < 64usize);
    ensures({ let mut y = x; mul_chunks(&mut y, lo, hi); y }[k][j] == mul_byte(x[k][j], lo, hi));
}
"#;
    let laws = format!(
        r#"
/// Quarter `q` of a chunk: its sixteen bytes from byte `16 q` (the last
/// quarter for `q >= 3`).
#[spec]
#[example(quarter_of([7u8; 64], 2usize) == [7u8; 16])]
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
{byte_law}"#,
        quarters = (0..4).map(|q| format!("{} => [{}],", if q == 3 { "_".to_string() } else { format!("{q}usize") }, elems(16, |i| format!("c[{}]", 16 * q + i)))).collect::<Vec<_>>().join("\n        "),
        chunk_laws = (0..4).map(|q| format!("/// `chunk_mul` multiplies every byte of quarter {q} of the chunk.\n#[law]\nfn chunk_mul_quarter_{q}(c: [u8; 64], lo: uint8x16_t, hi: uint8x16_t) {{\n    ensures(quarter_of({{ let mut d = c; chunk_mul(&mut d, lo, hi); d }}, {q}usize) == mul_lanes(quarter_of(c, {q}usize), lo, hi));\n}}\n")).collect::<Vec<_>>().join("\n"),
        byte_law = if pending { byte_law } else { "" },
    );
    let byte_proof = r#"
/// Chunk `k` of `muls_from` from `i`: as it is before `i`, multiplied from
/// `i` on.
#[lemma]
#[decreases((x.len() as Int) - (i as Int))]
fn muls_from_at(x: Seq<[u8; 64]>, i: Nat, k: Nat, lo: [u8; 16], hi: [u8; 16]) {
    requires(k < x.len());
    ensures(muls_from(x, i, lo, hi).len() == x.len() && muls_from(x, i, lo, hi)[k] == if k < i { x[k] } else { chunk64(x[k], lo, hi) });
    muls_from_step(x, i, lo, hi);
    muls_from_end(x, i, lo, hi);
    muls_from_len(x, i, lo, hi);
    if i < x.len() {
        let y = x.update(i, chunk64(x[i], lo, hi));
        muls_from_at(y, i + 1, k, lo, hi);
        // chunk `k` of the updated slice: `x[k]` but at `i`
        if k == i {
            assert(k == i);
            sandblaster::lemmas::seq::index_update_same(x, i as Int, chunk64(x[i], lo, hi));
            follows();
        } else {
            assert(y[k] == x[k]);
            follows();
        }
    } else {
        follows();
    }
}

/// Element `j` of 64 bytes mapped through `g` is `g` of byte `j`: an array
/// literal read at a symbolic index through its element function (proven
/// once for the width, by its 64 cases, `g` and `c` symbolic: each case
/// reads one element of a literal of 64 applications of a variable).
#[lemma]
fn map64_at(c: [u8; 64], g: fn(u8) -> u8, j: usize) {
    requires(j < 64usize);
    ensures(MAP64[j] == g(c[j]));
    by_cases(j, 0..64);
}

/// Byte `j` of a chunk multiplied: `mul64` maps `mul_byte` over the chunk.
#[lemma]
fn mul64_at(c: [u8; 64], j: usize, lo: [u8; 16], hi: [u8; 16]) {
    requires(j < 64usize);
    ensures(mul64(c, lo, hi)[j] == crate::laws::mul_byte(c[j], lo, hi));
    map64_at(c, |b: u8| crate::laws::mul_byte(b, lo, hi), j);
    follows();
}

/// The same over the opaque `chunk64`, so the law's goal never holds the
/// 64 bytes.
#[lemma]
fn chunk64_at(c: [u8; 64], j: usize, lo: [u8; 16], hi: [u8; 16]) {
    requires(j < 64usize);
    ensures(chunk64(c, lo, hi)[j] == crate::laws::mul_byte(c[j], lo, hi));
    chunk64_is(c, lo, hi);
    rewrite(chunk64(c, lo, hi) == mul64(c, lo, hi));
    mul64_at(c, j, lo, hi);
    follows();
}

#[proof]
fn mul_chunks_is_the_scalar_reference(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t, k: usize, j: usize) {
    let y = { let mut y = x; mul_chunks(&mut y, lo, hi); y };
    muls_from_at(x, 0, k as Nat, lo, hi);
    chunk64_at(x[k], j, lo, hi);
    follows();
}
"#;
    let proof = format!(
        r#"
{chunk_proofs}
/// The nibble tables of the multiplier one: every byte is itself.
pub const ID_LO: [u8; 16] = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const ID_HI: [u8; 16] = [0u8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240];

/// Every byte of a chunk through the nibble tables.
#[spec]
#[example(mul64([7u8; 64], ID_LO, ID_HI) == [7u8; 64])]
pub fn mul64(c: [u8; 64], lo: [u8; 16], hi: [u8; 16]) -> [u8; 64] {{
    [{bytes}]
}}

/// The same, opaque: the loop's facts name a chunk's product whole.
#[spec]
#[opaque]
#[example(chunk64([7u8; 64], ID_LO, ID_HI) == [7u8; 64])]
pub fn chunk64(c: [u8; 64], lo: [u8; 16], hi: [u8; 16]) -> [u8; 64] {{
    mul64(c, lo, hi)
}}

#[lemma]
fn chunk64_is(c: [u8; 64], lo: [u8; 16], hi: [u8; 16]) {{
    ensures(chunk64(c, lo, hi) == mul64(c, lo, hi));
    unfold(chunk64);
    follows();
}}

/// `mul_chunks`'s loop body on one chunk: every byte multiplied.
#[lift_attach(crate::a::mul_chunks, loop_nr = 0, element)]
fn mul_chunks_chunk() {{
    ensures(|ret: [u8; 64]| ret == crate::proof::chunk64(chunk, lo, hi));
    at_start! {{
        crate::proof::chunk64_is(chunk, lo, hi);
    }}
}}

/// `x` with every chunk from `i` on multiplied, one at a time.
#[spec]
#[decreases((x.len() as Int) - (i as Int))]
#[example(muls_from(seq![[7u8; 64], [9u8; 64]], 0, ID_LO, ID_HI) == seq![[7u8; 64], [9u8; 64]])]
pub fn muls_from(x: Seq<[u8; 64]>, i: Nat, lo: [u8; 16], hi: [u8; 16]) -> Seq<[u8; 64]> {{
    if i < x.len() {{ muls_from(x.update(i, chunk64(x[i], lo, hi)), i + 1, lo, hi) }} else {{ x }}
}}

#[lemma]
fn muls_from_step(x: Seq<[u8; 64]>, i: Nat, lo: [u8; 16], hi: [u8; 16]) {{
    ensures(implies(i < x.len(), muls_from(x, i, lo, hi) == muls_from(x.update(i, chunk64(x[i], lo, hi)), i + 1, lo, hi)));
    follows();
}}

#[lemma]
fn muls_from_end(x: Seq<[u8; 64]>, i: Nat, lo: [u8; 16], hi: [u8; 16]) {{
    ensures(implies(x.len() <= i, muls_from(x, i, lo, hi) == x));
    follows();
}}

/// A slice's chunks, as a sequence.
#[spec]
#[example(chunks_of(seq![[7u8; 64]]) == seq![[7u8; 64]])]
pub fn chunks_of(s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {{
    s
}}

#[lemma]
fn loop_step(x: &[[u8; 64]], iter: usize, lo: [u8; 16], hi: [u8; 16]) {{
    ensures(implies(iter < x.len(), muls_from(x, iter as Nat, lo, hi) == muls_from(chunks_of(x).update(iter as Nat, chunk64(x[iter], lo, hi)), iter.wrapping_add(1usize) as Nat, lo, hi)));
    muls_from_step(x, iter as Nat, lo, hi);
    follows();
}}

#[lemma]
fn loop_end(x: &[[u8; 64]], iter: usize, lo: [u8; 16], hi: [u8; 16]) {{
    ensures(implies((iter < x.len()) == false, muls_from(x, iter as Nat, lo, hi) == chunks_of(x)));
    muls_from_end(x, iter as Nat, lo, hi);
    follows();
}}

/// `mul_chunks`'s loop from chunk `iter` on.
#[lift_attach(crate::a::mul_chunks, loop_nr = 0)]
fn mul_chunks_loop() {{
    invariant(iter <= x.len());
    decreases((x.len() as Int) - (iter as Int));
    ensures(|ret: &[[u8; 64]]| ret.len() == x.len() && ret == crate::proof::muls_from(x, iter as Nat, lo, hi));
    at_start! {{
        crate::proof::loop_step(x, iter, lo, hi);
        crate::proof::loop_end(x, iter, lo, hi);
    }}
}}

/// `mul_chunks`'s summary: every chunk multiplied.
#[lift_attach(crate::a::mul_chunks)]
fn mul_chunks_summary() {{
    ensures(|ret: &[[u8; 64]]| ret.len() == x.len() && ret == crate::proof::muls_from(x, 0, lo, hi));
}}

/// `muls_from` keeps the length.
#[lemma]
#[decreases((x.len() as Int) - (i as Int))]
fn muls_from_len(x: Seq<[u8; 64]>, i: Nat, lo: [u8; 16], hi: [u8; 16]) {{
    ensures(muls_from(x, i, lo, hi).len() == x.len());
    muls_from_step(x, i, lo, hi);
    muls_from_end(x, i, lo, hi);
    if i < x.len() {{
        muls_from_len(x.update(i, chunk64(x[i], lo, hi)), i + 1, lo, hi);
        follows();
    }} else {{
        follows();
    }}
}}

#[proof]
fn mul_chunks_keeps_the_length(x: &[[u8; 64]], lo: uint8x16_t, hi: uint8x16_t) {{
    let y = {{ let mut y = x; mul_chunks(&mut y, lo, hi); y }};
    muls_from_len(x, 0, lo, hi);
    follows();
}}
{byte_proof}"#,
        chunk_proofs = (0..4).map(|q| format!("/// Lane for lane (the lane closer: each lane's lookups are of nibbles).\n#[proof]\nfn chunk_mul_quarter_{q}(c: [u8; 64], lo: uint8x16_t, hi: uint8x16_t) {{\n    unfold(chunk_mul);\n    unfold(mul_16);\n    follows();\n}}\n")).collect::<Vec<_>>().join("\n"),
        bytes = elems(64, |i| format!("crate::laws::mul_byte(c[{i}], lo, hi)")),
        byte_proof = if pending { byte_proof.replace("MAP64", &format!("[{}]", elems(64, |i| format!("g(c[{i}])")))) } else { String::new() },
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

/// The chunk's quarter laws and the slice's length law are proven, with
/// `mul_chunks`' element, loop and summary contracts ([`pending_laws`]),
/// and every MIR theorem: no obligation fails, every example holds; the
/// sections gate names the functions the laws leave open (`mul_chunks`,
/// whose length alone is stated here, `mul` and `xor_rows`, which have no
/// laws, and `chunk_mul`, whose quarter laws the completeness discharge
/// does not combine into the whole chunk).
#[test]
fn the_loop_contract_and_the_length_law_are_proven() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("length-law");
    let (laws, proof) = pending_laws(false);
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&(chunk_laws() + &laws)), Some(&(chunk_proof() + &proof))));
    assert!(!ok, "the slice's byte law is missing, so the sections gate fails:\n{why}");
    assert!(why.contains("the proofs checked") && why.contains("failed the §15 gates (sections)"), "{why}");
    for f in ["chunk_mul", "mul_chunks", "mul", "xor_rows"] {
        assert!(why.contains(&format!("`crate::a::{f}` is not determined by the specification")), "{f}: {why}");
    }
    assert!(!why.contains("error[obligation]") && !why.contains("error[example]") && !why.contains("error[law") && !why.contains("error[elab]"), "{why}");
}

/// The law of every byte of every chunk (stage leftovers, [`pending_laws`]):
/// every proof checks, the per-width lemma `map64_at` and the byte law
/// among them; the sections gate names the functions the laws leave open,
/// as without the byte law. Negative twins (unproven, never a kernel
/// rejection): the law with the two tables swapped, and the per-width
/// lemma claiming another element.
#[test]
fn the_law_of_every_byte_of_every_chunk_is_proven() {
    sandblaster_front::memguard::init_from_env();
    let s = Scratch::new("byte-law");
    let (laws, proof) = pending_laws(true);
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&(chunk_laws() + &laws)), Some(&(chunk_proof() + &proof))));
    assert!(!ok, "the sections gate fails (the laws leave functions open):\n{why}");
    assert!(why.contains("the proofs checked") && why.contains("failed the §15 gates (sections)"), "{why}");
    for f in ["chunk_mul", "mul_chunks", "mul", "xor_rows"] {
        assert!(why.contains(&format!("`crate::a::{f}` is not determined by the specification")), "{f}: {why}");
    }
    assert!(!why.contains("error[obligation]") && !why.contains("error[example]") && !why.contains("error[law") && !why.contains("error[elab]") && !why.contains("error[resource]"), "{why}");
    // negative twins
    let swapped = laws.replace("== mul_byte(x[k][j], lo, hi));", "== mul_byte(x[k][j], hi, lo));");
    assert_ne!(swapped, laws);
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&(chunk_laws() + &swapped)), Some(&(chunk_proof() + &proof))));
    assert!(!ok && why.contains("unproven obligation [law-goal] in `crate::laws::mul_chunks_is_the_scalar_reference`") && !why.contains("rejected"), "{why}");
    let other = proof.replace("ensures([g(c[0]), ", "ensures([g(c[1]), ");
    assert_ne!(other, proof);
    let (ok, why) = s.gates(&files(PTR, PTR_FNS, Some(&(chunk_laws() + &laws)), Some(&(chunk_proof() + &other))));
    assert!(!ok && why.contains("in `crate::proof::map64_at`") && !why.contains("rejected"), "{why}");
}

/// The laws of the vector function and of the row load, and the lemma of a
/// quarter of a chunk, are proven; the crate is not yet fully specified:
/// the sections gate names exactly the functions whose laws are pending
/// ([`pending_laws`]), and nothing else fails.
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

/// The two twins whose reading above stops at a type its environment does
/// not declare (`struct_field`'s `Pair`, `moved_into_call`'s `Holder`), read
/// in the lifted crate's own environment, where the module's types are
/// declared: L is stuck at their formations, the window rule named.
#[test]
fn with_the_modules_types_declared_the_struct_twins_are_stuck_at_their_formations() {
    let s = Scratch::new("local-types");
    let c = s.check(&files(LOCAL, "local_ok", None, None));
    let k = c.krate.as_ref().expect("the lifted crate (its refused functions' bodies are dropped)");
    let l = loaded(LOCAL);
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &[]);
        let env = &mut out.env;
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        for (f, why) in [("struct_field", "W2: `_2`, the local the base lives in, is read"), ("moved_into_call", "W3: `_2`, the local the base lives in, is moved")] {
            let key = format!("fx_sd_ptr_local::a::{f}");
            let got = match lit.lfn(&key) {
                Some(lf) => lf.faults.join("\n"),
                None => lit.refused.iter().find(|(k, _)| *k == key).map(|(_, e)| e.clone()).unwrap_or_else(|| panic!("no reading of `{f}`")),
            };
            assert!(got.contains(why) && !got.contains("no kernel declaration"), "{f}: {why}\n{got}");
            eprintln!("{f}: stuck ({why})");
        }
    });
}

/// The diagnostics of `r` at the source lines of `f` in `src` (each with its
/// continuation lines).
fn diags_of(src: &str, r: &str, f: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let start = lines.iter().position(|l| l.starts_with(&format!("pub fn {f}("))).unwrap_or_else(|| panic!("no `{f}`")) + 1;
    let end = lines[start..].iter().position(|l| l.starts_with("pub fn ") || l.starts_with("pub unsafe fn ") || l.starts_with("fn ") || l.starts_with("pub struct ") || l.starts_with("pub static ") || l.starts_with("/// ")).map_or(lines.len(), |e| start + e) + 1;
    let rg = start..end;
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
}

/// Lifted in place, each of the review's F1 programs and their siblings is
/// refused before any theorem, the window rule named by the lift's
/// diagnostic pass (a store into a `static mut` is refused as a cast of a
/// pointer constant, no admitted formation); the positive functions are not
/// refused (the lift refuses the `static` item itself).
#[test]
fn each_local_base_twin_is_refused_by_name_when_lifted() {
    let s = Scratch::new("local-twins");
    let c = s.check(&files(LOCAL, "local_ok", None, None));
    assert!(!c.ok());
    let r = c.render();
    let mut wrong = Vec::new();
    for (f, why) in [
        ("local_write", "W2: `_2`, the local the base lives in, is written"),
        ("local_shared", "W3: `_2`, the local the base lives in, is written"),
        ("local_scope", "W2: `_4`, the local the base lives in, is given a storage marker"),
        ("local_from_mut", "W2: `_2`, the local the base lives in, is written"),
        ("local_raw_deref", "W2: `_2`, the local the base lives in, is written"),
        ("param_by_value", "W3: `_1`, the local the base lives in, is written"),
        ("param_by_value_mut", "W2: `_1`, the local the base lives in, is written"),
        ("local_raw_write", "W2: `_2`, the local the base lives in, is written"),
        ("raw_scope", "W2: `_4`, the local the base lives in, is given a storage marker"),
        ("struct_field", "W2: `_2`, the local the base lives in, is read"),
        ("tuple_field", "W2: `_2`, the local the base lives in, is read"),
        ("nested_array", "W2: `_2`, the local the base lives in, is written"),
        ("boxed", "W2: `_2`, through which the base is reached"),
        ("vec_slice", "W2: `_2`, the local the base lives in, is borrowed mutably"),
        ("temporary", "W3: `_5`, the local the base lives in, is given a storage marker"),
        ("temporary_mut", "W2: `_5`, the local the base lives in, is given a storage marker"),
        ("closure_write", "W2: `_2`, the local the base lives in, is borrowed mutably"),
        ("two_pointers", "W2: `_3`, the local the base lives in, is borrowed mutably"),
        ("shared_then_mut", "W3: `_2`, the local the base lives in, is borrowed mutably"),
        ("reborrow_moved", "W2: `_3`, through which the base is reached"),
        ("after_loop", "W2: `_3`, the local the base lives in, is written"),
        ("after_call", "W2: `_2`, the local the base lives in, is borrowed mutably"),
        ("loop_scope", "W2: `_5`, the local the base lives in, is given a storage marker"),
        ("moved_into_call", "W3: `_2`, the local the base lives in, is moved"),
        // (rustc folds `&raw mut SCRATCH` into a pointer constant at level 1:
        // no formation, so its cast is refused)
        ("static_mut_store", "a pointer cast of something that is no pointer of an admitted formation"),
    ] {
        let d = diags_of(LOCAL.0, &r, f);
        if !d.contains(why) {
            wrong.push(format!("{f}: no `{why}` in\n{d}"));
        } else {
            eprintln!("{f}: refused ({why})");
        }
    }
    assert!(wrong.is_empty(), "{}\n(all:\n{r})", wrong.join("\n"));
    for f in ["local_ok", "two_shared_ok"] {
        assert!(!diags_of(LOCAL.0, &r, f).contains("error"), "{f}:\n{}", diags_of(LOCAL.0, &r, f));
    }
}

// ---------------------------------------------------------------------------
// the window extraction's configuration (the review's F2)
// ---------------------------------------------------------------------------

/// Bodies that differ by the codegen configuration (`sd_ptr_cfg`), with the
/// matching window extraction.
const CFG: Code = (include_str!("mir_fixtures/sd_ptr_cfg/src/a.rs"), include_str!("mir_fixtures/sd_ptr_cfg/a.sbmir"), include_str!("mir_fixtures/sd_ptr_cfg/a.window.sbmir"));
/// Its window extraction made under `-C target-feature=+sm4`, and under
/// `--cfg sd_twin` (`extract.sh --rustflags`, for these twins only).
const CFG_WINDOW_SM4: &str = include_str!("mir_fixtures/sd_ptr_cfg/a.window-sm4.sbmir");
const CFG_WINDOW_CFG: &str = include_str!("mir_fixtures/sd_ptr_cfg/a.window-cfg.sbmir");
/// Its window extraction under `--cfg sd_quote="a\tc\u{301}\u{7f}"` (the
/// printer's quoting, stage cfg-binding-fixes).
const CFG_WINDOW_QUOTE: &str = include_str!("mir_fixtures/sd_ptr_cfg/a.window-quote.sbmir");

/// The review's F2 (stage soundness-fixes): a window extraction made under
/// other codegen flags than its main extraction is another program — the
/// write `x[0] = 5` compiled out under `-C target-feature=+sm4`, or under
/// `--cfg sd_twin`, is in the body L reads but not in the one the window
/// rule would judge — and `load_window` refuses it, naming the header
/// records that differ: every record but the optimization level is
/// compared (the `--cfg` twin differs in its `(rustflags ..)` record and,
/// since stage leftovers, its `(cfg ..)` record alone). With the matching
/// window extraction each function's formation
/// fails W2 (`param_write`'s undefined behaviour). Each header record
/// changed alone in the window extraction, and a shared type definition
/// changed, is refused too; a main extraction compiled with rustflags is
/// refused by `load`.
#[test]
fn a_window_extraction_under_other_codegen_flags_is_refused() {
    let src = CFG.0.as_bytes().to_vec();
    let main_of = |text: &str| mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), names(Some(aarch64_features())), "a");
    let main = || main_of(CFG.1).unwrap_or_else(|e| panic!("{e}"));
    // the matching window extraction: both formations refused by W2
    let mut l = main();
    mir::load_window(CFG.2, &mut l).unwrap_or_else(|e| panic!("{e}"));
    for f in ["cfg_alias", "cfg_flag_alias"] {
        let vs = l.m.fns[&format!("fx_sd_ptr_cfg::a::{f}")].window.clone().expect("verdicts");
        assert!(vs.iter().any(|v| v.result.as_ref().is_err_and(|e| e.starts_with("W2: `_1`"))), "{f}: {vs:?}");
    }
    // the window extractions made under other flags: refused, the records named
    for (text, records) in [
        (CFG_WINDOW_SM4, &["(target-static-features", "(target-feature-flags \"+sm4\")", "(rustflags \"-Ctarget-feature=+sm4\")", "(\"target_feature\" \"sm4\")"][..]),
        (CFG_WINDOW_CFG, &["(rustflags \"--cfg sd_twin\")", "(\"sd_twin\")"][..]),
    ] {
        let e = mir::load_window(text, &mut main()).expect_err("a window extraction under other flags");
        for r in records {
            assert!(e.contains(r), "{r}: {e}");
        }
        eprintln!("refused: {e}");
    }
    // (the `--cfg` twin differs in no other record: without its rustflags
    // and cfg records nothing would tell the two programs apart, so an
    // extraction by this printer must have both, `ir::parse`)
    let no_flags = |t: &str| t.lines().filter(|l| !l.starts_with("(rustflags ") && !l.starts_with("(cfg ")).collect::<Vec<_>>().join("\n") + "\n";
    let (m0, w0) = (no_flags(CFG.1), no_flags(CFG_WINDOW_CFG));
    let header = |t: &str| t.lines().take_while(|l| !l.starts_with("(fn ") && !l.starts_with("(adt-def ")).filter(|l| !l.starts_with("(mir-opt-level")).map(str::to_string).collect::<Vec<_>>();
    assert_eq!(header(&m0), header(&w0), "the `--cfg` twin differs in another record");
    // each header record changed alone, and a shared type definition
    for (from, to) in [
        ("(rustflags \"\")", "(rustflags \"-Cdebug-assertions\")"),
        ("(endian little)", "(endian big)"),
        ("(target-cpu default \"apple-m1\")", "(target-cpu \"apple-m4\" \"apple-m1\")"),
        ("(target-feature-flags \"\")", "(target-feature-flags \"+sm4\")"),
        ("(unsafe-reading 1)\n", ""),
        ("(overflow-checks on)", "(overflow-checks off)"),
        ("(exclude)", "(exclude \"u128\")"),
        ("(root \"fx_sd_ptr_cfg::a::cfg_alias\")\n", "(root \"fx_sd_ptr_cfg::a::cfg_alias\")\n(note \"a note\")\n"),
    ] {
        assert!(CFG.2.contains(from), "{from}");
        let e = mir::load_window(&CFG.2.replacen(from, to, 1), &mut main()).expect_err(from);
        assert!(e.contains("header records are not the extraction's"), "{from}: {e}");
    }
    // a type definition both extractions have (`sd_ptr_local`'s `Pair`), changed
    let (from, to) = ("(field \"b\" u8)", "(field \"b\" u16)");
    assert_eq!(LOCAL.2.matches(from).count(), 1, "{from}");
    let src_local = LOCAL.0.as_bytes().to_vec();
    let mut l = mir::load(LOCAL.1, &|p| (p == "src/a.rs").then(|| src_local.clone()), names(Some(aarch64_features())), "a").unwrap_or_else(|e| panic!("{e}"));
    let e = mir::load_window(&LOCAL.2.replacen(from, to, 1), &mut l).expect_err("a type definition changed");
    assert!(e.contains("definition of `a::Pair`"), "{e}");
    // a main extraction compiled with rustflags: refused by `load`
    let e = main_of(&CFG.1.replace("(rustflags \"\")", "(rustflags \"--cfg sd_twin\")")).err().expect("a main extraction with rustflags");
    assert!(e.contains("rustflags \"--cfg sd_twin\""), "{e}");
}

// ---------------------------------------------------------------------------
// the extraction's configuration: its cfg set (stage leftovers)
// ---------------------------------------------------------------------------

/// A body that differs by a Cargo feature (`sd_ptr_feat`): the crate
/// extracted without its feature `alias` (no aliasing write), and with it,
/// each with its window extraction.
const FEAT: Code = (include_str!("mir_fixtures/sd_ptr_feat/src/a.rs"), include_str!("mir_fixtures/sd_ptr_feat/a.sbmir"), include_str!("mir_fixtures/sd_ptr_feat/a.window.sbmir"));
const FEAT_ALIAS: Code = (include_str!("mir_fixtures/sd_ptr_feat/src/a.rs"), include_str!("mir_fixtures/sd_ptr_feat/a-alias.sbmir"), include_str!("mir_fixtures/sd_ptr_feat/a.window-alias.sbmir"));

/// `text` without its `(cfg ..)` record (an extraction older than it).
fn without_cfg(text: &str) -> String {
    text.lines().filter(|l| !l.starts_with("(cfg ")).collect::<Vec<_>>().join("\n") + "\n"
}

/// The variables a build script gets from the workspace's stable toolchain
/// (cargo 1.98.1 on `aarch64-apple-darwin`, captured by a build script
/// that printed them, stage leftovers): the dev profile's
/// (`debug_assertions`) or the release profile's, with the crate's
/// features and its encoded rustflags as given.
fn build_env(features: &'static str, release: bool, rustflags: &'static str) -> impl Fn(&str) -> Option<String> {
    move |k: &str| {
        let v = match k {
            "CARGO_CFG_DEBUG_ASSERTIONS" if !release => "",
            "CARGO_CFG_FEATURE" => features,
            "CARGO_CFG_PANIC" => "unwind",
            "CARGO_CFG_TARGET_ABI" | "CARGO_CFG_TARGET_ENV" | "CARGO_CFG_UNIX" => "",
            "CARGO_CFG_TARGET_ARCH" => "aarch64",
            "CARGO_CFG_TARGET_ENDIAN" => "little",
            "CARGO_CFG_TARGET_FAMILY" => "unix",
            "CARGO_CFG_TARGET_FEATURE" => "aes,crc,dit,dotprod,dpb,dpb2,fcma,fhm,flagm,fp16,frintts,jsconv,lor,lse,neon,paca,pacg,pan,pmuv3,ras,rcpc,rcpc2,rdm,sb,sha2,sha3,ssbs,vh",
            "CARGO_CFG_TARGET_HAS_ATOMIC" | "CARGO_CFG_TARGET_HAS_ATOMIC_PRIMITIVE_ALIGNMENT" => "128,16,32,64,8,ptr",
            "CARGO_CFG_TARGET_OS" => "macos",
            "CARGO_CFG_TARGET_POINTER_WIDTH" => "64",
            "CARGO_CFG_TARGET_VENDOR" => "apple",
            "CARGO_ENCODED_RUSTFLAGS" => rustflags,
            _ => return None,
        };
        Some(v.to_string())
    }
}

/// A Cargo feature (stage leftovers; F2's open item): mirx records the
/// session's cfg set, `(cfg ..)`, the crate's features among it, and the
/// window extraction must record its main extraction's. The window
/// extraction made with the feature `alias` judges a body with the
/// aliasing write (W2 refuses its formation), the one made without it a
/// body without (the formation passes); across the features each is
/// refused, the feature named. The two programs differ in no other header
/// record: without the record the window extraction without the write is
/// accepted beside the main extraction with it, and the verdict it carries
/// passes the formation whose write it never saw. So since stage
/// cfg-binding-fixes an extraction by this printer without the record is
/// refused (`ir::parse`), whichever of the two it is.
#[test]
fn a_window_extraction_under_other_features_is_refused() {
    let src = FEAT.0.as_bytes().to_vec();
    let main_of = |text: &str| mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), names(Some(aarch64_features())), "a").unwrap_or_else(|e| panic!("{e}"));
    let verdicts = |l: &mir::Loaded| l.m.fns["fx_sd_ptr_feat::a::feat_alias"].window.clone().expect("verdicts");
    // each extraction with its own window extraction
    let mut l = main_of(FEAT.1);
    mir::load_window(FEAT.2, &mut l).unwrap_or_else(|e| panic!("{e}"));
    assert!(!verdicts(&l).is_empty() && verdicts(&l).iter().all(|v| v.result.is_ok()), "{:?}", verdicts(&l));
    let mut l = main_of(FEAT_ALIAS.1);
    mir::load_window(FEAT_ALIAS.2, &mut l).unwrap_or_else(|e| panic!("{e}"));
    assert!(verdicts(&l).iter().any(|v| v.result.as_ref().is_err_and(|e| e.starts_with("W2: `_1`"))), "{:?}", verdicts(&l));
    // across the features: refused both ways, the feature named
    for (main, window) in [(FEAT_ALIAS.1, FEAT.2), (FEAT.1, FEAT_ALIAS.2)] {
        let e = mir::load_window(window, &mut main_of(main)).expect_err("a window extraction under other features");
        assert!(e.contains("header records are not the extraction's") && e.contains("(\"feature\" \"alias\")"), "{e}");
        eprintln!("refused: {}", &e[..e.len().min(300)]);
    }
    // the cfg record is the only one they differ in
    let header = |t: &str| t.lines().take_while(|l| !l.starts_with("(fn ") && !l.starts_with("(adt-def ")).filter(|l| !l.starts_with("(mir-opt-level")).map(str::to_string).collect::<Vec<_>>();
    assert_eq!(header(&without_cfg(FEAT_ALIAS.1)), header(&without_cfg(FEAT.2)), "the feature twin differs in another record");
    // without it: refused, the main extraction and the window one alike
    for text in [without_cfg(FEAT_ALIAS.1), without_cfg(FEAT.2)] {
        let e = ir::parse(&text).expect_err("an extraction by the narrow reading's printer without its cfg set");
        assert!(e.contains("records its rustflags and its cfg set"), "{e}");
    }
    let e = mir::load(&without_cfg(FEAT_ALIAS.1), &|p| (p == "src/a.rs").then(|| src.clone()), names(Some(aarch64_features())), "a").err().expect("refused");
    assert!(e.contains("extract it again"), "{e}");
}

/// The build's side (stage leftovers): a build script knows its Cargo
/// features, the target's and the profile's cfgs a stable compiler shows
/// and its rustflags' `--cfg`s (`target::build_cfg`), and `mir::load`
/// refuses an extraction whose `(cfg ..)` record differs there: the
/// extraction without the aliasing write under a build that compiles it in
/// (the feature `alias`) and the reverse, a dev extraction under a release
/// build (no `debug_assertions`), a build with a `--cfg` (both forms). The
/// record's nightly-only cfgs, its unstable target features and the
/// nightly's bare `target_has_atomic` are not compared (a stable build does
/// not see them): under the build's own configuration both extractions
/// load. An extraction recorded with `test` (`extract.sh --profile test`
/// checks the crate in test mode) is refused by every build: Cargo never
/// sets `CARGO_CFG_TEST`, so the library's compile is bound and the test
/// harness's is not (AUDIT.md §21.1). Not bound: a build that does not
/// know its configuration (`sandblaster check`); an extraction by this
/// printer without the record is refused (stage cfg-binding-fixes).
#[test]
fn a_build_under_other_features_or_flags_refuses_the_extraction() {
    let src = FEAT.0.as_bytes().to_vec();
    let load = |text: &str, build_cfg: Option<sandblaster_front::target::BuildCfg>| {
        let mut n = names(Some(aarch64_features()));
        n.build_cfg = build_cfg;
        mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), n, "a").err()
    };
    let of = |env: &dyn Fn(&str) -> Option<String>| TargetInfo::from_cargo_env(env).unwrap_or_else(|e| panic!("{e}")).cfg;
    // the build's own configuration: both extractions load
    assert_eq!(load(FEAT.1, of(&build_env("", false, ""))), None);
    assert_eq!(load(FEAT_ALIAS.1, of(&build_env("alias", false, ""))), None);
    // another feature set, profile or `--cfg`: refused, the difference named
    let test_mode = FEAT.1.replacen("(cfg ", "(cfg (\"test\") ", 1);
    for (text, build_cfg, extraction_has, build_has) in [
        (FEAT.1, of(&build_env("alias", false, "")), "", "feature=\"alias\""),
        (FEAT_ALIAS.1, of(&build_env("", false, "")), "feature=\"alias\"", ""),
        (FEAT.1, of(&build_env("", true, "")), "debug_assertions", ""),
        (FEAT.1, of(&build_env("", false, "--cfg\u{1f}sd_twin")), "", "sd_twin"),
        (FEAT.1, of(&build_env("", false, "-Ccodegen-units=1\u{1f}--cfg=sd_twin=\"x\"")), "", "sd_twin=\"x\""),
        (test_mode.as_str(), of(&build_env("", false, "")), "test", ""),
    ] {
        let e = load(text, build_cfg).expect("another configuration");
        assert!(e.contains(&format!("only the extraction has [{extraction_has}], only this build has [{build_has}]")), "{e}");
        eprintln!("refused: {e}");
    }
    // what a stable build does not see is in the record, and not compared
    for c in ["(\"overflow_checks\")", "(\"ub_checks\")", "(\"relocation_model\" \"pic\")", "(\"target_feature\" \"lse2\")", "(\"target_feature\" \"v8.1a\")", "(\"target_has_atomic\")", "(\"debug_assertions\")"] {
        assert!(FEAT.1.contains(c), "{c}");
    }
    // not bound: a build that does not know its configuration; an
    // extraction by this printer without the record is refused
    assert_eq!(load(FEAT_ALIAS.1, None), None);
    let e = load(&without_cfg(FEAT.1), of(&build_env("alias", true, "--cfg\u{1f}sd_twin"))).expect("an extraction without its cfg set");
    assert!(e.contains("records its rustflags and its cfg set"), "{e}");
}

/// Through the lift, the build's configuration from a build script's
/// variables (`TargetInfo::from_cargo_env`): each extraction is refused,
/// named, in a build of the other features; in a build of its own the one
/// without the write is lifted, and the one with it is refused by the
/// window rule alone.
#[test]
fn the_lift_binds_the_extraction_to_the_builds_configuration() {
    let s = Scratch::new("feat");
    for (code, features, refused, w2) in [(FEAT, "", false, false), (FEAT, "alias", true, false), (FEAT_ALIAS, "alias", false, true), (FEAT_ALIAS, "", true, false)] {
        let target = TargetInfo::from_cargo_env(&build_env(features, false, "")).unwrap_or_else(|e| panic!("{e}"));
        let c = s.check_with(&files(code, "feat_alias", None, None), &target);
        let r = c.render();
        assert_eq!(r.contains("the MIR was extracted under another configuration than this build's"), refused, "features {features:?}:\n{r}");
        assert_eq!(r.contains("W2: `_1`"), w2, "features {features:?}:\n{r}");
        assert_eq!(c.ok(), !refused && !w2, "features {features:?}:\n{r}");
    }
}

// ---------------------------------------------------------------------------
// the build's rustflags, the printer's records and quoting (stage
// cfg-binding-fixes, the validator's V1, V5, V6 and N6)
// ---------------------------------------------------------------------------

/// The validator's V1: rustc derives `debug_assertions` from `-C
/// debug-assertions`, or without it from the optimization level (`-C
/// opt-level`, `-O`), and the overflow checks the MIR holds from `-C
/// overflow-checks`, or without it from `debug_assertions`; Cargo's
/// `CARGO_CFG_DEBUG_ASSERTIONS` follows the profile, not the rustflags
/// (which come last on rustc's command line), no variable shows the
/// overflow checks, and none the cfgs a `-Z` option sets. A build whose
/// rustflags set one, or name an `@file` (rustc reads arguments from it),
/// does not know its configuration: the extraction is refused, the flag
/// named, in every spelling rustc's option parser reads (`-C k=v`, `-Ck=v`,
/// `--codegen k=v`, `--codegen=k=v`, short options grouped, `_` for `-`),
/// and not for a `-O` that is another option's value. Both
/// directions: a dev extraction under a dev build with `-C
/// debug-assertions=off` (loaded before: the validator's case) and a
/// release extraction under a release build with `-C debug-assertions=on`;
/// each loads under its own build. An option that changes no cfg (`-C
/// codegen-units`, `-C debuginfo`) is no reason; `-C panic` is read from
/// `CARGO_CFG_PANIC`, which follows the rustflags (Cargo's `rustc --print
/// cfg` reads them); A-S3's `-C target-cpu` and `-C target-feature` are
/// read in rustc's other spellings too (`-C target_feature`).
#[test]
fn a_build_whose_rustflags_change_its_configuration_refuses_the_extraction() {
    let src = FEAT.0.as_bytes().to_vec();
    let load = |text: &str, env: &dyn Fn(&str) -> Option<String>| {
        let t = TargetInfo::from_cargo_env(env).unwrap_or_else(|e| panic!("{e}"));
        let mut n = names(Some(aarch64_features()));
        (n.build_cfg, n.codegen_flags) = (t.cfg, t.codegen_flags);
        mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), n, "a").err()
    };
    // a release extraction: the dev one's record without the profile's
    // `debug_assertions` (and `ub_checks`, which follows it)
    let release = FEAT.1.replacen(" (\"debug_assertions\")", "", 1).replacen(" (\"ub_checks\")", "", 1);
    assert_eq!(release.len() + " (\"debug_assertions\")".len() + " (\"ub_checks\")".len(), FEAT.1.len());
    // each under its own build: loads
    assert_eq!(load(FEAT.1, &build_env("", false, "")), None);
    assert_eq!(load(&release, &build_env("", true, "")), None);
    for (text, release_build, flags, named) in [
        // the validator's case, in rustc's spellings
        (FEAT.1, false, "-C\u{1f}debug-assertions=off", "-C debug-assertions=off"),
        (FEAT.1, false, "-Cdebug-assertions=no", "-C debug-assertions=no"),
        (FEAT.1, false, "--codegen\u{1f}debug_assertions=n", "-C debug-assertions=n"),
        (FEAT.1, false, "--codegen=debug-assertions=false", "-C debug-assertions=false"),
        // the other direction (a bare option is `on`)
        (release.as_str(), true, "-Cdebug-assertions", "-C debug-assertions"),
        (release.as_str(), true, "-C\u{1f}debug_assertions=on", "-C debug-assertions=on"),
        // the optimization level `debug_assertions` follows without it
        (FEAT.1, false, "-Copt-level=2", "-C opt-level=2"),
        (FEAT.1, false, "-O", "-C opt-level=3"),
        (release.as_str(), true, "-C\u{1f}opt-level=0", "-C opt-level=0"),
        // the overflow checks
        (FEAT.1, false, "-Coverflow-checks=off", "-C overflow-checks=off"),
        (release.as_str(), true, "--codegen=overflow_checks", "-C overflow-checks"),
        // a `-Z` option, in both forms
        (FEAT.1, false, "-Zub-checks=no", "-Z ub-checks=no"),
        (FEAT.1, false, "--cfg\u{1f}sd_twin\u{1f}-Z\u{1f}fmt-debug=none", "-Z fmt-debug=none"),
        // short options grouped (getopts: flags, then one option with a
        // value), and after an option whose value is the next argument
        (FEAT.1, false, "-gO", "-C opt-level=3"),
        (FEAT.1, false, "-vgCdebug_assertions=off", "-C debug-assertions=off"),
        (FEAT.1, false, "-gZ\u{1f}ub-checks=no", "-Z ub-checks=no"),
        (FEAT.1, false, "-D\u{1f}warnings\u{1f}-O", "-C opt-level=3"),
        // (an empty argument is an argument: Cargo passes it on, and rustc
        // takes it for `-A`'s lint)
        (FEAT.1, false, "-A\u{1f}\u{1f}-O", "-C opt-level=3"),
        // after a long option, whose value is the next argument (rustc
        // takes `-L` for a lint's name here, and reads the option after it)
        (FEAT.1, false, "--allow\u{1f}-L\u{1f}-O", "-C opt-level=3"),
        (FEAT.1, false, "--warn\u{1f}-L\u{1f}-Cdebug-assertions=off", "-C debug-assertions=off"),
        // (a long flag takes no value)
        (FEAT.1, false, "--verbose\u{1f}-O", "-C opt-level=3"),
        // an `@file`, wherever it is (rustc reads arguments from it)
        (FEAT.1, false, "@/tmp/sd-flags", "@/tmp/sd-flags"),
        (FEAT.1, false, "-L\u{1f}@/tmp/sd-flags", "@/tmp/sd-flags"),
    ] {
        let e = load(text, &build_env("", release_build, flags)).expect(flags);
        assert!(e.contains("cannot be bound to this build's") && e.contains(&format!("set {named}, from which")), "{flags}: {e}");
        eprintln!("refused ({flags}): {e}");
    }
    // no reason: options that change no cfg, and a `-O` that is another
    // option's value (`-L`'s path, a lint's name)
    for flags in ["-Ccodegen-units=1\u{1f}--codegen\u{1f}debuginfo=0\u{1f}-Cstrip=none", "-D\u{1f}warnings\u{1f}-Awarnings\u{1f}-g\u{1f}--cap-lints\u{1f}warn", "-L\u{1f}-O", "--allow\u{1f}-O", "--allow=-O"] {
        assert_eq!(load(FEAT.1, &build_env("", false, flags)), None, "{flags}");
    }
    // `-C panic`: in `CARGO_CFG_PANIC`, so in the build's set
    let abort = |k: &str| if k == "CARGO_CFG_PANIC" { Some("abort".to_string()) } else { build_env("", false, "-Cpanic=abort")(k) };
    let e = load(FEAT.1, &abort).expect("an unwinding extraction under -C panic=abort");
    assert!(e.contains("only the extraction has [panic=\"unwind\"], only this build has [panic=\"abort\"]"), "{e}");
    // A-S3's flags in rustc's other spellings
    for flags in ["-Ctarget_feature=+sm4", "--codegen=target_cpu=apple-m4", "-C\u{1f}target_cpu=apple-m4"] {
        let e = load(FEAT.1, &build_env("", false, flags)).expect(flags);
        assert!(e.contains("this build sets -C target-cpu="), "{flags}: {e}");
    }
}

/// Through the lift (`TargetInfo::from_cargo_env` to the load): a build
/// whose rustflags change its configuration refuses the extraction; one
/// whose rustflags change nothing of it does not.
#[test]
fn the_lift_refuses_a_build_whose_rustflags_change_its_configuration() {
    let s = Scratch::new("flags");
    // (stage cfg-final: a builtin cfg set by `--cfg`, F3; a `--cfg` that is
    // `-L`'s value, no cfg of the build, F1)
    for (flags, refused) in [("", false), ("-C\u{1f}debug-assertions=off", true), ("-Ccodegen-units=1", false), ("-A\u{1f}explicit_builtin_cfgs_in_flags\u{1f}--cfg\u{1f}debug_assertions", true), ("-L\u{1f}--cfg=sd_twin", false)] {
        let target = TargetInfo::from_cargo_env(&build_env("", false, flags)).unwrap_or_else(|e| panic!("{e}"));
        let c = s.check_with(&files(FEAT, "feat_alias", None, None), &target);
        let r = c.render();
        assert_eq!(r.contains("cannot be bound to this build's"), refused, "{flags:?}:\n{r}");
        assert_eq!(c.ok(), !refused, "{flags:?}:\n{r}");
    }
}

// ---------------------------------------------------------------------------
// the build's `--cfg`s (stage cfg-final, the validator's F1 and F3 of stage
// validate-cfg-fixes)
// ---------------------------------------------------------------------------

/// `FEAT`'s extraction `text` loaded under the build whose build script
/// gets the variables `env` (its cfg set and codegen flags,
/// `TargetInfo::from_cargo_env`): `None` when it loads, else why not.
fn load_under_build(text: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let src = FEAT.0.as_bytes().to_vec();
    let t = TargetInfo::from_cargo_env(env).unwrap_or_else(|e| panic!("{e}"));
    let mut n = names(Some(aarch64_features()));
    (n.build_cfg, n.codegen_flags) = (t.cfg, t.codegen_flags);
    mir::load(text, &|p| (p == "src/a.rs").then(|| src.clone()), n, "a").err()
}

/// `FEAT`'s dev extraction as a release one: its record without the
/// profile's `debug_assertions` (and `ub_checks`, which follows it).
fn release_extraction() -> String {
    FEAT.1.replacen(" (\"debug_assertions\")", "", 1).replacen(" (\"ub_checks\")", "", 1)
}

/// The validator's F1: rustc reads a `--cfg=x` that follows an option
/// taking a value (`-L`, `-A`, `--allow`, `--remap-path-prefix`, a short
/// group's last option) as that option's value and does not set `x`
/// (measured on rustc 1.98.1), so `build_cfg` takes the build's `--cfg`s
/// from the option reader (`rustc_options`), not from a scan of the
/// arguments. The release-build twin: under a release build whose
/// rustflags hold `-L --cfg=debug_assertions` the dev extraction is
/// refused, `debug_assertions` named, and the release extraction loads
/// (before, the build claimed `debug_assertions` and took the dev
/// extraction: the validator's probe, through the variables Cargo really
/// gave a release build). Likewise a feature: `-L --cfg=feature="alias"`
/// in a build without the feature refuses the extraction with the aliasing
/// write and loads the one without; and a `--cfg=sd_twin` that is another
/// option's value is no cfg of the build (before, the build claimed it and
/// refused). A `--cfg` rustc reads, after another option's whole value, is
/// the build's.
#[test]
fn a_cfg_that_is_another_options_value_is_not_the_builds() {
    let release = release_extraction();
    for flags in ["-L\u{1f}--cfg=debug_assertions", "-A\u{1f}--cfg=debug_assertions", "--allow\u{1f}--cfg=debug_assertions", "--remap-path-prefix\u{1f}--cfg=debug_assertions", "-gL\u{1f}--cfg=debug_assertions"] {
        let e = load_under_build(FEAT.1, &build_env("", true, flags)).expect(flags);
        assert!(e.contains("only the extraction has [debug_assertions], only this build has []"), "{flags}: {e}");
        assert_eq!(load_under_build(&release, &build_env("", true, flags)), None, "{flags}");
    }
    let alias = "-L\u{1f}--cfg=feature=\"alias\"";
    let e = load_under_build(FEAT_ALIAS.1, &build_env("", false, alias)).expect(alias);
    assert!(e.contains("only the extraction has [feature=\"alias\"], only this build has []"), "{e}");
    assert_eq!(load_under_build(FEAT.1, &build_env("", false, alias)), None);
    for flags in ["-L\u{1f}--cfg=sd_twin", "--remap-path-prefix\u{1f}--cfg=sd_twin", "-Cdebuginfo=0\u{1f}--allow\u{1f}--cfg=sd_twin"] {
        assert_eq!(load_under_build(FEAT.1, &build_env("", false, flags)), None, "{flags}");
    }
    // a `--cfg` rustc reads: the build's
    for flags in ["-L\u{1f}dir\u{1f}--cfg=sd_twin", "-Ldir\u{1f}--cfg\u{1f}sd_twin", "--remap-path-prefix=a=b\u{1f}--cfg=sd_twin", "--allow\u{1f}warnings\u{1f}--cfg\u{1f}sd_twin"] {
        let e = load_under_build(FEAT.1, &build_env("", false, flags)).expect(flags);
        assert!(e.contains("only the extraction has [], only this build has [sd_twin]"), "{flags}: {e}");
    }
}

/// The validator's F3: past `-A explicit_builtin_cfgs_in_flags` (or with a
/// value rustc does not refuse, `--cfg debug_assertions="x"`), rustc takes
/// a `--cfg` of a builtin cfg's name and sets that cfg, but derives the
/// rest of the configuration from the option that sets it: in a release
/// build `--cfg debug_assertions` gives `cfg!(debug_assertions)` and no
/// overflow checks (measured on rustc 1.98.1), while Cargo's
/// `CARGO_CFG_DEBUG_ASSERTIONS` follows the profile, so the build's set
/// equalled a dev extraction's and the build took it. A build whose
/// rustflags set a builtin cfg by `--cfg` — a name of `BUILD_CFGS`,
/// `NIGHTLY_CFGS` or `target_feature`, in either form, with any value —
/// refuses every extraction, the cfg named, whatever its profile (fail
/// closed: `test` too, which rustc allows). Not refused: a `--cfg` of
/// another name (the build's own: the feature twin loads under a build
/// given the feature by `--cfg`), and a builtin's `--cfg` that is another
/// option's value (F1).
#[test]
fn a_build_that_sets_a_builtin_cfg_by_cfg_refuses_the_extraction() {
    let release = release_extraction();
    for (flags, name) in [
        // the validator's case, and the lint capped
        ("-A\u{1f}explicit_builtin_cfgs_in_flags\u{1f}--cfg\u{1f}debug_assertions", "debug_assertions"),
        ("--cap-lints\u{1f}allow\u{1f}--cfg=debug_assertions", "debug_assertions"),
        // a value, and spaces, rustc does not refuse
        ("--cfg=debug_assertions=\"x\"", "debug_assertions"),
        ("--cfg\u{1f} unix ", "unix"),
        // `BUILD_CFGS`, `NIGHTLY_CFGS` and `target_feature`
        ("--cfg=panic=\"abort\"", "panic"),
        ("--cfg=target_os=\"linux\"", "target_os"),
        ("--codegen=codegen-units=1\u{1f}--cfg\u{1f}target_has_atomic=\"8\"", "target_has_atomic"),
        ("--cfg=proc_macro", "proc_macro"),
        ("--cfg=test", "test"),
        ("--cfg\u{1f}overflow_checks", "overflow_checks"),
        ("--cfg=ub_checks", "ub_checks"),
        ("--cfg=relocation_model=\"static\"", "relocation_model"),
        ("--cfg=target_feature=\"sm4\"", "target_feature"),
    ] {
        for (text, release_build) in [(FEAT.1, false), (FEAT.1, true), (release.as_str(), true)] {
            let e = load_under_build(text, &build_env("", release_build, flags)).expect(flags);
            assert!(e.contains("cannot be bound to this build's") && e.contains(&format!("set the builtin cfg `{name}` by `--cfg`")), "{flags}: {e}");
        }
    }
    // another name: the build's own
    assert_eq!(load_under_build(FEAT_ALIAS.1, &build_env("", false, "--cfg=feature=\"alias\"")), None);
    for (flags, has) in [("--cfg=debug_assertion", "debug_assertion"), ("--cfg=target", "target"), ("--cfg\u{1f}sd_twin=\"panic\"", "sd_twin=\"panic\"")] {
        let e = load_under_build(FEAT.1, &build_env("", false, flags)).expect(flags);
        assert!(e.contains(&format!("only the extraction has [], only this build has [{has}]")), "{flags}: {e}");
    }
    // a builtin's `--cfg` that is another option's value: no cfg (F1)
    assert_eq!(load_under_build(&release, &build_env("", true, "-L\u{1f}--cfg=debug_assertions")), None);
}

/// The validator's V5: an extraction by the narrow reading's printer,
/// `(unsafe-reading 1)`, records its rustflags and its cfg set, and
/// `ir::parse` refuses one without either — compared without them, a main
/// and a window extraction of two configurations, or an extraction and a
/// build of two, would look alike (an extraction older than the records,
/// or made without `extract.sh`, is extracted again). Every checked-in
/// extraction with the printer's record (the fixtures, extracted again for
/// it, and rs_engine's) has both and parses, and is refused with either
/// removed; without the printer's record as well (the legacy rule:
/// varint's, the MMR's and the verifier's extractions) it parses.
#[test]
fn an_extraction_by_the_printer_records_its_rustflags_and_cfg_set() {
    use sandblaster_front::mir::sexp;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in ["sandblaster/front/tests/mir_fixtures", "cryptography/sandblaster", "codec/sandblaster", "storage/sandblaster"] {
        for d in std::fs::read_dir(repo.join(dir)).unwrap().map(Result::unwrap).filter(|d| d.path().is_dir()) {
            files.extend(std::fs::read_dir(d.path()).unwrap().map(|f| f.unwrap().path()).filter(|f| f.extension().is_some_and(|e| e == "sbmir")));
        }
    }
    files.sort();
    // `text` without its top-level records headed by one of `gone`
    let without = |text: &str, gone: &[&str]| sexp::parse(text).unwrap().iter().filter(|e| !e.head().is_some_and(|h| gone.contains(&h))).map(|e| e.to_string()).collect::<Vec<_>>().join("\n");
    let mut narrow = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let m = ir::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        if !m.unsafe_reading {
            continue;
        }
        narrow.push(f.strip_prefix(&repo).unwrap().display().to_string());
        assert!(m.cfg.is_some() && m.rustflags.is_some(), "{}", f.display());
        for gone in [&["cfg"][..], &["rustflags"], &["cfg", "rustflags"]] {
            let e = ir::parse(&without(&text, gone)).expect_err(&format!("{} without {gone:?}", f.display()));
            assert!(e.contains("records its rustflags and its cfg set"), "{}: {e}", f.display());
        }
        ir::parse(&without(&text, &["cfg", "rustflags", "unsafe-reading"])).unwrap_or_else(|e| panic!("{} as an older printer's: {e}", f.display()));
    }
    eprintln!("{} extractions by the narrow reading's printer: {narrow:?}", narrow.len());
    assert_eq!(narrow.len(), 23, "{narrow:?}");
}

/// The validator's N6: `ir::parse` reads each `(cfg ..)` entry as one or
/// two strings, and refuses any other shape, named (a bare word or string,
/// an empty list, a word for the name or the value, three strings, a list
/// inside), never reading it as an entry; a well-formed record reads as
/// its entries.
#[test]
fn a_malformed_cfg_entry_is_refused() {
    let rec = FEAT.1.lines().find(|l| l.starts_with("(cfg ")).expect("the record");
    let with = |r: &str| FEAT.1.replacen(rec, r, 1);
    let m = ir::parse(&with("(cfg (\"debug_assertions\") (\"feature\" \"std\"))")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(m.cfg, Some(vec![("debug_assertions".to_string(), None), ("feature".to_string(), Some("std".to_string()))]));
    for bad in ["(cfg debug_assertions)", "(cfg \"debug_assertions\")", "(cfg ())", "(cfg (debug_assertions))", "(cfg (\"feature\" std))", "(cfg (\"feature\" \"std\" \"x\"))", "(cfg ((\"feature\")))", "(cfg (\"unix\") ())"] {
        let e = ir::parse(&with(bad)).expect_err(bad);
        assert!(e.starts_with("malformed .sbmir: cfg entry"), "{bad}: {e}");
    }
}

/// The validator's V6: mirx writes a string with `"` and `\` escaped and
/// every other character as it is, which the reader reads back exactly;
/// with `{:?}`'s escapes it read a cfg value with a tab, a combining accent
/// and a DEL (`--cfg sd_quote="a\tc\u{301}\u{7f}"`, a window twin of
/// `sd_ptr_cfg`; Cargo refuses a newline in a cfg value) back as
/// `atcu{301}u{7f}`, the reader dropping each escape's backslash, so two
/// values could print the same record.
#[test]
fn a_cfg_value_reads_back_as_rustc_holds_it() {
    let w = ir::parse(CFG_WINDOW_QUOTE).unwrap_or_else(|e| panic!("{e}"));
    let v: Vec<&(String, Option<String>)> = w.cfg.as_ref().expect("the record").iter().filter(|(n, _)| n == "sd_quote").collect();
    assert_eq!(v, [&("sd_quote".to_string(), Some("a\tc\u{301}\u{7f}".to_string()))]);
    // the rustflags as passed, their backslashes kept
    assert_eq!(w.rustflags.as_deref(), Some("--cfg sd_quote=\"a\\tc\\u{301}\\u{7f}\""));
}

// ---------------------------------------------------------------------------
// the alignment arm (A-S5, the review's F5)
// ---------------------------------------------------------------------------

/// `[u128; n]` as L holds it (each element its (low, high) words).
fn u128_array(v: &[u128]) -> String {
    let t = "Tuple2(U64, U64)";
    let l = v.iter().rev().fold(format!("Nil[{t}]"), |l, x| format!("Cons[{t}](tuple2[U64, U64]({}u64, {}u64), {l})", *x as u64, (*x >> 64) as u64));
    format!("pair(Array ({t}) {}usize, {l}, refl(Int, {}int))", v.len(), v.len())
}

/// A-S5's alignment arm (the review's F5): every admitted row is unaligned,
/// so no row exercises it. With every row read as needing 16 bytes
/// (`literal::test_fault::set_row_align`, never set by a build) a load from
/// a base aligned to 16 (`[u128; 2]`) reads at offsets 0 and 16 and is stuck
/// at 8 (the address could be aligned; the reading cannot show it), and a
/// load from a byte array (aligned to 1) is refused, named; with the rows'
/// own alignment every offset in bounds reads.
#[test]
fn the_alignment_arm_reads_only_aligned_offsets_of_an_aligned_base() {
    with_env(|env| {
        let l = loaded(LOCAL);
        let bytes: Vec<u8> = (0..32).collect();
        let rows: [u128; 2] = [u128::from_le_bytes(bytes[..16].try_into().unwrap()), u128::from_le_bytes(bytes[16..].try_into().unwrap())];
        let key = |f: &str| format!("fx_sd_ptr_local::a::{f}");
        let want = |k: usize| format!("mir::Res::Ret[Array U8 16usize]({})", u8_array(&bytes[k..k + 16]));
        // the rows' own alignment (1): every offset reads
        let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
        let (ra, ba) = (lit.lfn(&key("rows_at")).expect("rows_at"), lit.lfn(&key("bytes_at")).expect("bytes_at"));
        assert!(ra.faults.is_empty() && ba.faults.is_empty(), "{:?} {:?}", ra.faults, ba.faults);
        for k in [0usize, 8, 16] {
            same(env, &run(ra, 2, &[&u128_array(&rows), &format!("{k}usize")]), &want(k));
            same(env, &run(ba, 2, &[&u8_array(&bytes), &format!("{k}usize")]), &want(k));
        }
        // every row read as needing 16 bytes (on this thread, which generates the reading)
        sandblaster_front::mir::literal::test_fault::set_row_align(16);
        let lit16 = checked::load_literal(env, &l.m, &l.names, &[], None);
        sandblaster_front::mir::literal::test_fault::set_row_align(0);
        let lit16 = lit16.unwrap_or_else(|e| panic!("{e}"));
        let ra = lit16.lfn(&key("rows_at")).expect("rows_at");
        assert!(ra.faults.is_empty(), "{:?}", ra.faults);
        for k in [0usize, 16] {
            same(env, &run(ra, 2, &[&u128_array(&rows), &format!("{k}usize")]), &want(k));
        }
        same(env, &run(ra, 2, &[&u128_array(&rows), "8usize"]), &format!("mir::Res::Stuck[{}]", ra.out_ty));
        let why = match lit16.lfn(&key("bytes_at")) {
            Some(lf) => lf.faults.join("\n"),
            None => lit16.refused.iter().find(|(k, _)| *k == key("bytes_at")).map(|(_, e)| e.clone()).unwrap_or_default(),
        };
        assert!(why.contains("needs 16-byte alignment, which a base of Array(Int(false, 8), 32) does not give"), "{why}");
        eprintln!("rows_at: offsets 0 and 16 read, 8 stuck; bytes_at refused ({why})");
    });
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
    "sandblaster/front/tests/mir_fixtures/sd_ptr_local/src/a.rs",
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
