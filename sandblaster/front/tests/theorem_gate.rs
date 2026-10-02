//! The theorem gate (`docs/checked-structuring.md`, amendment (e)): every
//! lifted exec function read from rustc's MIR has its theorem `L::thm::f`
//! (the literal reading of its MIR returns, at sufficient fuel, exactly the
//! structured reading's value) kernel-checked, or the module is not
//! verified. On codec's varint:
//!
//! * all 63 lifted functions are proven (with the loop lemmas of `read` and
//!   of `write`'s `while` loop), and the gate passes;
//! * negative twins: the two wrong readings of `lift::test_hook` (a signed
//!   `Shr` read as the logical shift; `&a[..=j]` read as `&a[..j]`) make the
//!   theorems of the functions they misread fail, and the gate reports each
//!   one as an error (the module is not verified); a walk out of budget
//!   leaves its theorem missing;
//! * the verdict cache: a second run takes every theorem from the cache; a
//!   changed instance of the MIR misses for the functions whose literal
//!   reading runs it, and only for them.
//!
//! On storage: every lifted function of the verifier's first set (69), and
//! of the MMR (76, with the model lemma of core's `u64::div_ceil`).
//! The shipped code's theorems of the lifted round trip (§20.7) are tested
//! in `tests/lowered_use.rs`.

use std::path::Path;
use std::sync::Arc;

use sandblaster_front::lift::LiftFacts;

use sandblaster_front::driver::cache::{Store, VerdictCache};
use sandblaster_front::driver::gates::{theorem_gate, GateReport};
use sandblaster_front::driver::Checked;
use sandblaster_front::lift::test_hook::{self, WrongRule};
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir;
use sandblaster_front::surface::sha256;
use sandblaster_front::target::TargetInfo;

const VARINT: &str = "../../codec/sandblaster/varint/mod.rs";

/// The varint crate as the front end reads it (with a wrong reading rule).
fn varint(hook: Option<WrongRule>) -> Checked {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(VARINT);
    test_hook::set(hook);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    test_hook::set(None);
    assert!(c.ok(), "{}", c.render());
    c
}

/// The structured reading of the lifted functions (and their helpers) the
/// theorems are about; `f` runs on it.
fn with_reading<T: Send>(c: &Checked, f: impl FnOnce(&mut sandblaster_front::elab::Output, &Checked) -> T + Send) -> T {
    sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        let mut out = checked::elaborate_names(k, &items);
        f(&mut out, c)
    })
}

fn module(reps: &[ModuleTheorems]) -> &ModuleTheorems {
    assert_eq!(reps.len(), 1, "one lifted MIR module");
    &reps[0]
}

#[test]
fn every_varint_function_has_its_theorem_and_the_gate_passes() {
    let c = varint(None);
    let (rep, gate) = with_reading(&c, |out, c| {
        let k = c.krate.as_ref().unwrap();
        let mut gate = GateReport::default();
        theorem_gate(out, k, c, &mut gate);
        (gate.theorems.clone(), gate)
    });
    let m = module(&rep);
    assert_eq!((m.functions(), m.proven()), (63, 63), "missing: {:?}", m.missing.iter().map(|x| &x.0).collect::<Vec<_>>());
    assert!(m.missing.is_empty());
    // the loop lemmas: `read`'s helper and `write`'s `while` loop, per width
    let lemmas: Vec<&str> = m.outcomes.iter().filter(|o| o.kind == "loop lemma").map(|o| o.global.as_str()).collect();
    // the model lemma of core's `usize::div_ceil` (`size`): untrusted, a callee lemma
    assert!(m.outcomes.iter().any(|o| o.kind == "model lemma" && o.global == "usize::div_ceil" && o.result.is_ok()), "{:?}", m.outcomes.iter().map(|o| (&o.global, o.kind)).collect::<Vec<_>>());
    assert_eq!(lemmas.len(), 6, "{lemmas:?}");
    assert!(lemmas.contains(&"crate::varint::write__u16::loop#0") && lemmas.contains(&"crate::varint::read__u64__loop0"), "{lemmas:?}");
    assert!(gate.passed(), "{:?}", gate.results);
    let r = gate.results.iter().find(|r| r.gate == "mir-theorems").expect("the gate ran");
    assert_eq!(r.errors, 0);
    assert!(r.note.starts_with("63 of 63"), "{}", r.note);
}

/// The gate on the crate read with a wrong rule: its errors' messages.
fn gate_errors(hook: WrongRule) -> (Vec<String>, bool) {
    let c = varint(Some(hook));
    with_reading(&c, |out, c| {
        let k = c.krate.as_ref().unwrap();
        let mut gate = GateReport::default();
        theorem_gate(out, k, c, &mut gate);
        let errs: Vec<String> = gate.diags.list.iter().filter(|d| d.kind == sandblaster_front::diag::DiagKind::MirTheorem).map(|d| d.msg.clone()).collect();
        (errs, gate.passed())
    })
}

#[test]
fn an_inclusive_range_read_as_exclusive_fails_write_and_the_module_is_not_verified() {
    let (errs, passed) = gate_errors(WrongRule::InclusiveRangeAsExclusive);
    assert!(!passed, "a misread module must not pass the gate");
    for w in ["u16", "u32", "u64"] {
        let f = format!("`crate::varint::write__{w}` has no kernel-checked theorem");
        assert!(errs.iter().any(|e| e.starts_with(&f)), "{f}: {errs:?}");
    }
    // the functions that call it have none either (their walks need it)
    assert!(errs.iter().any(|e| e.starts_with("`crate::varint::UInt__u32::write`") && e.contains("not attempted")), "{errs:?}");
    // and only those: the reading of `read` is right
    assert!(!errs.iter().any(|e| e.starts_with("`crate::varint::read__u32`")), "{errs:?}");
}

#[test]
fn a_signed_shift_read_as_logical_fails_zigzag_and_the_module_is_not_verified() {
    let (errs, passed) = gate_errors(WrongRule::SignedShrLogical);
    assert!(!passed);
    for i in ["i16", "i32", "i64"] {
        let f = format!("`crate::varint::SPrim__{i}__as_zigzag` has no kernel-checked theorem");
        assert!(errs.iter().any(|e| e.starts_with(&f)), "{f}: {errs:?}");
    }
    assert!(!errs.iter().any(|e| e.starts_with("`crate::varint::write__u16`")), "{errs:?}");
}

#[test]
fn a_walk_out_of_budget_leaves_its_theorem_missing() {
    let c = varint(None);
    let reps = with_reading(&c, |out, c| checked::prove_lifted(out, &c.lift_facts, &GateOptions { max_steps: 3, ..Default::default() }));
    let m = module(&reps);
    assert!(m.proven() < m.functions());
    let (_, why) = m.missing.iter().find(|(g, _)| g == "crate::varint::Decoder__u32::feed").expect("feed needs more steps");
    assert!(why.contains("budget of 3 steps is exhausted"), "{why}");
}

#[test]
fn theorems_are_cached_by_their_inputs() {
    let dir = std::env::temp_dir().join(format!("sb-theorem-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let vc = VerdictCache::new(Store::open(dir.clone(), sha256(b"theorem gate test")), "theorem gate test toolchain");
    let run = |c: &Checked, facts: &LiftFacts, vc: &VerdictCache| with_reading(c, |out, _| checked::prove_lifted(out, facts, &GateOptions { cache: Some(vc), ..Default::default() }));
    let c = varint(None);
    let first = run(&c, &c.lift_facts, &vc);
    let m = module(&first);
    assert_eq!((m.proven(), m.cached()), (63, 0));
    // the same inputs: every theorem from the cache, nothing walked
    let second = run(&c, &c.lift_facts, &vc);
    let m = module(&second);
    assert_eq!((m.proven(), m.cached()), (63, 63));
    assert!(m.outcomes.iter().all(|o| o.cached), "{:?}", m.outcomes.iter().filter(|o| !o.cached).map(|o| &o.global).collect::<Vec<_>>());
    // a constant of `Decoder::<u16>::feed`'s MIR changed: the functions whose
    // literal reading runs it miss (and are walked: the changed reading no
    // longer matches), the others still hit
    let mut facts = c.lift_facts.clone();
    let mut loaded = (*facts.mir_loaded[0].loaded).clone();
    let n = fault(&mut loaded.m, "Decoder::<u16>::feed", 7, 6);
    assert!(n > 0);
    facts.mir_loaded[0].loaded = Arc::new(loaded);
    let third = run(&c, &facts, &vc);
    let m = module(&third);
    let o = |g: &str| m.outcomes.iter().find(|o| o.global == g).unwrap_or_else(|| panic!("no outcome for {g}"));
    assert!(!o("crate::varint::Decoder__u16::feed").cached && o("crate::varint::Decoder__u16::feed").result.is_err());
    assert!(m.missing.iter().any(|(g, _)| g == "crate::varint::read__u16"), "read::<u16> calls feed");
    assert!(o("crate::varint::size__u32").cached && o("crate::varint::Decoder__u32::feed").cached);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every integer constant `old` of the statements of the functions whose
/// key contains `pat` becomes `new`; the number changed.
fn fault(m: &mut ir::Sbmir, pat: &str, old: i128, new: i128) -> usize {
    let mut n = 0;
    for (_, f) in m.fns.iter_mut().filter(|(k, _)| k.contains(pat)) {
        for st in f.blocks.iter_mut().flat_map(|b| b.stmts.iter_mut()) {
            if let ir::Stmt::Assign(_, rv, _) = st {
                let ops: Vec<&mut ir::Operand> = match rv {
                    ir::Rvalue::Bin(_, a, b) | ir::Rvalue::Checked(_, a, b) => vec![a, b],
                    ir::Rvalue::Use(a) => vec![a],
                    _ => vec![],
                };
                for o in ops {
                    if let ir::Operand::Const(c) = o
                        && let ir::Const::Int(t, x) = c.value().clone()
                        && x == old
                    {
                        *c = ir::Const::Int(t, new);
                        n += 1;
                    }
                }
            }
        }
    }
    n
}

/// A storage root as the front end reads it.
fn storage(root: &str) -> Checked {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(root);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    c
}

/// The gate on the structured reading of `items` (and of the prover's
/// bridges and library, as the build elaborates them).
fn gate_on(c: &Checked, items: Vec<String>, opts: GateOptions<'static>) -> Vec<ModuleTheorems> {
    sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let mut items = items;
        items.extend(["^words::", "^stdlib::", "^sha256::"].map(String::from));
        let mut out = checked::elaborate_names(k, &items);
        checked::prove_lifted(&mut out, &c.lift_facts, &opts)
    })
}

/// The verifier's first set: every lifted function proven, among them
/// `Subtree::is_inside`, whose walk rewrites a fact through a match on a
/// transparent call's result (`Location::cmp` inside `ge`) — the proofs
/// of an idiom whose scrutinee holds the test transported, not refreshed.
#[test]
fn every_verifier_function_has_its_theorem() {
    let c = storage("../../storage/sandblaster/verifier/mod.rs");
    let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
    let reps = gate_on(&c, items, GateOptions::default());
    let m = module(&reps);
    assert_eq!((m.functions(), m.proven()), (69, 69), "missing: {:?}", m.missing);
    assert!(m.outcomes.iter().any(|o| o.global == "crate::merkle::proof::Subtree::is_inside" && o.result.is_ok()));
}

/// The MMR's functions this stage's fixes reach, each with what its walk
/// needs: `position_to_location` (a closure without captures that the MIR
/// never assigns), `parent_heights` and `chunk_peaks` (core's
/// `RangeInclusive<u32>` and `Once<T>` against the prelude's models),
/// `PeakIterator::to_nearest_size` (core's `div_ceil` by its model lemma,
/// a `while` loop), `Family::is_valid_size` (a measure with a boolean
/// atom, the quoter's sharing `let`s in its facts).
#[test]
fn the_mmr_functions_of_this_stage_have_their_theorems() {
    let c = storage("../../storage/sandblaster/mmr/mod.rs");
    let wanted = [
        "crate::merkle::mmr::Family::position_to_location",
        "crate::merkle::mmr::Family::parent_heights",
        "crate::merkle::mmr::Family::chunk_peaks",
        "crate::merkle::mmr::iterator::PeakIterator::to_nearest_size",
        "crate::merkle::mmr::Family::is_valid_size",
    ];
    let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
    let reps = gate_on(&c, items, GateOptions::default());
    let m = module(&reps);
    for w in wanted {
        let o = m.outcomes.iter().find(|o| o.global == w && o.is_fn).unwrap_or_else(|| panic!("`{w}` was not planned"));
        assert!(o.result.is_ok(), "`{w}`: {:?}", o.result);
    }
    assert!(m.outcomes.iter().any(|o| o.kind == "model lemma" && o.global == "u64::div_ceil" && o.result.is_ok()));
    assert_eq!((m.functions(), m.proven()), (76, 76), "missing: {:?}", m.missing);
}
