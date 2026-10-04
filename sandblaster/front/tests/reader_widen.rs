//! The reader widening (`docs/mir-lift.md` §20, stage reader-widen): ordinary
//! code the MIR reading takes, end to end on rustc's own MIR (the fixture
//! `mir_fixtures/rw_mix`, lifted in place): core's slice iterator, nested
//! loops, a loop test of two conditions, loops without attachments (their
//! measures guessed), signed comparisons, wrapping and sign extension, `?` on
//! `Option`, byte conversions, rotations, a slice's `get` by a range, a
//! call into another file of the crate and a match through a shared
//! reference (core's `Option::eq`). For each function the structured
//! reading is elaborated (every obligation proven) and its theorem against
//! the literal reading is kernel-checked. Negative twins: a changed constant
//! of a construct's MIR breaks that function's theorem and no other; a
//! signed range reads but its termination is not proven. `window` (`get` by
//! a range) reads and elaborates; its theorem is not proven yet.

use std::path::Path;
use std::sync::Arc;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked};
use sandblaster_front::lift::LiftFacts;
use sandblaster_front::loader::MemFs;
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir;
use sandblaster_front::target::TargetInfo;

const A: &str = include_str!("mir_fixtures/rw_mix/src/a.rs");
const B: &str = include_str!("mir_fixtures/rw_mix/src/b.rs");
const MIR: &str = include_str!("mir_fixtures/rw_mix/a.sbmir");

/// The functions of `src/a.rs` whose readings are proven end to end.
const PROVEN: &[&str] = &["sum_bytes", "count_zeros", "mix_grid", "steps", "smax", "sclass", "widen", "widen_bits", "plus4", "le32", "be32", "le_bytes", "rot", "low_sum", "crc8", "same"];

/// Read and elaborated, the theorem not proven yet: `window` (`get` by a
/// range; the walk's abstraction of the literal side's dependent tests
/// meets a slice value whose pair type it does not recover).
const READ_ONLY: &[&str] = &["window"];

/// `src/a.rs` lifted in place with `items`, its MIR beside the DSL root;
/// `b.rs` (which `a.rs` calls into) is a file of the host crate, not lifted.
fn check(items: &[&str]) -> Checked {
    let root = format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[lift(in_place, mir = \"a.sbmir\", items = \"{}\")]\n#[path = \"../../src/a.rs\"]\npub mod a;\n", items.join(", "));
    let fs = MemFs::from_files([("c/sandblaster/m/mod.rs", root.as_str()), ("c/src/a.rs", A), ("c/src/b.rs", B), ("c/sandblaster/m/a.sbmir", MIR)]);
    driver::check(Path::new("c/sandblaster/m/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin())
}

/// The elaboration errors and the theorems of the lifted functions (with
/// `facts`, the lift's facts possibly with a changed MIR).
fn theorems(c: &Checked, facts: &LiftFacts) -> (Vec<String>, ModuleTheorems) {
    sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let names: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        let mut out = checked::elaborate_names(k, &names);
        let mut errs: Vec<String> = out.diags.list.iter().filter(|d| d.severity == Severity::Error && d.kind == DiagKind::Elab).map(|d| d.msg.clone()).collect();
        // (a definition with an obligation not proven, or blocked by one)
        errs.extend(out.defs.iter().filter(|d| d.name.starts_with("crate::a::") && !matches!(d.status, sandblaster_front::elab::DefStatus::Checked)).map(|d| format!("{}: {:?}", d.name, d.status)));
        errs.extend(out.obligations.iter().filter(|o| o.def.starts_with("crate::a::") && !o.proven()).map(|o| format!("{} obligation {:?} of `{}`: {}", if o.hinted { "hinted" } else { "an" }, o.kind, o.def, o.goal)));
        let mut reps = checked::prove_and_check(&mut out, k, facts, &GateOptions::default());
        assert_eq!(reps.len(), 1, "one lifted MIR module");
        (errs, reps.remove(0))
    })
}

#[track_caller]
fn front_ok(items: &[&str]) -> Checked {
    let c = check(items);
    assert!(c.ok(), "the front end refused the lifted functions:\n{}", c.render());
    c
}

fn missing(m: &ModuleTheorems) -> Vec<String> {
    let mut v: Vec<String> = m.missing.iter().map(|(g, why)| format!("{g}: {}", &why[..why.len().min(1500)])).collect();
    for o in &m.outcomes {
        if let Err(e) = &o.result {
            v.push(format!("{} ({}): {}", o.global, o.kind, &e[..e.len().min(if std::env::var("CS_FULL").is_ok() { 1_000_000 } else { 3000 })]));
        }
    }
    v
}

#[test]
fn every_widened_construct_reads_elaborates_and_has_its_theorem() {
    let items: Vec<&str> = PROVEN.iter().chain(READ_ONLY).copied().collect();
    let c = front_ok(&items);
    let (errs, m) = theorems(&c, &c.lift_facts);
    assert!(errs.is_empty(), "{errs:#?}");
    assert_eq!(m.functions(), items.len(), "{:?}", m.outcomes.iter().map(|o| &o.global).collect::<Vec<_>>());
    for f in PROVEN {
        let g = format!("crate::a::{f}");
        assert!(m.outcomes.iter().any(|o| o.is_fn && o.global == g && o.result.is_ok()), "{g} has no theorem; missing: {:#?}", missing(&m));
    }
    assert_eq!(m.proven(), PROVEN.len(), "missing: {:#?}", missing(&m));
    // the loops' lemmas: the slice and range helpers, the nested loops'
    // helpers (the inner one returns: a `while`-style lemma; both with fuel
    // functions), the `while` of two conditions
    let lemmas: Vec<&str> = m.outcomes.iter().filter(|o| o.kind == "loop lemma" && o.result.is_ok()).map(|o| o.global.as_str()).collect();
    for l in ["crate::a::sum_bytes__loop0", "crate::a::mix_grid__loop1", "crate::a::mix_grid__loop0", "crate::a::steps::loop#0", "crate::a::crc8__loop1", "crate::a::crc8__loop0"] {
        assert!(lemmas.contains(&l), "{l}: {lemmas:?}");
    }
}

/// The lift's facts with every integer constant `old` of the statements and
/// calls of the function `key` changed to `new` (it must change something).
fn faulted(c: &Checked, key: &str, old: i128, new: i128) -> LiftFacts {
    let mut facts = c.lift_facts.clone();
    let mut loaded = (*facts.mir_loaded[0].loaded).clone();
    let mut n = 0;
    let f = loaded.m.fns.get_mut(key).unwrap_or_else(|| panic!("no MIR for {key}"));
    for b in f.blocks.iter_mut() {
        let mut ops: Vec<&mut ir::Operand> = Vec::new();
        for st in b.stmts.iter_mut() {
            if let ir::Stmt::Assign(_, rv, _) = st {
                match rv {
                    ir::Rvalue::Bin(_, a, b) | ir::Rvalue::Checked(_, a, b) => ops.extend([a, b]),
                    ir::Rvalue::Use(a) => ops.push(a),
                    ir::Rvalue::Agg(_, xs) => ops.extend(xs.iter_mut()),
                    _ => {}
                }
            }
        }
        if let ir::Term::Call(_, args, _, _) = &mut b.term {
            ops.extend(args.iter_mut());
        }
        for o in ops {
            if let ir::Operand::Const(k) = o
                && let ir::Const::Int(t, x) = k.value().clone()
                && x == old
            {
                *k = ir::Const::Int(t, new);
                n += 1;
            }
        }
    }
    assert!(n > 0, "the fault changed nothing in {key}");
    facts.mir_loaded[0].loaded = Arc::new(loaded);
    facts
}

#[test]
fn a_changed_constant_of_a_widened_construct_breaks_its_theorem_only() {
    let items = ["sum_bytes", "mix_grid", "smax", "same"];
    let c = front_ok(&items);
    // the slice loop's initial sum (0 read as 1), the nested loop's factor (31
    // as 37) and its inner range (`0..3` as `0..2`), the constants of core's
    // `Option::eq` (a different variant compares equal)
    for (key, old, new, global) in [
        ("fx_rw_mix::a::sum_bytes", 0, 1, "crate::a::sum_bytes"),
        ("fx_rw_mix::a::mix_grid", 31, 37, "crate::a::mix_grid"),
        ("fx_rw_mix::a::mix_grid", 3, 2, "crate::a::mix_grid"),
        ("<std::option::Option<u8> as std::cmp::PartialEq>::eq", 0, 1, "crate::a::same"),
    ] {
        let (_, m) = theorems(&c, &faulted(&c, key, old, new));
        let lost: Vec<&str> = m.missing.iter().map(|(g, _)| g.as_str()).collect();
        assert!(lost.contains(&global), "{global}: {:#?}", missing(&m));
        assert!(!lost.contains(&"crate::a::smax"), "{lost:?}");
    }
}

#[test]
fn a_signed_range_reads_but_its_termination_is_not_proven() {
    // `for _ in 0..8` over `i32`: both readings take it (signed comparisons,
    // the signed overflow flag of `Step::forward_unchecked`), but no measure
    // of a signed range is guessed, so its helper does not elaborate
    let c = front_ok(&["spin"]);
    let (errs, m) = theorems(&c, &c.lift_facts);
    assert!(errs.iter().any(|e| e.contains("spin__loop0") && e.contains("termination measure")), "{errs:#?}");
    assert_eq!(m.proven(), 0, "{:?}", m.outcomes.iter().map(|o| &o.global).collect::<Vec<_>>());
}
