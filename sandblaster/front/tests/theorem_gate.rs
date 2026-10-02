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
//! * the trusted check (`mir::gate`): a theorem the kernel accepted with a
//!   weaker statement (a dropped component of `erase`, a vacuous
//!   precondition) or about an untrusted redefinition of `S_f` is refused,
//!   the original accepted; a function without its theorem is refused; a
//!   stale verdict-cache entry for a changed MIR is not accepted; a module
//!   type the subset declares with its fields reordered is refused; a
//!   function listed with another function's MIR instance is refused; a
//!   reading whose names another extraction's reading took over is refused.
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
use sandblaster_front::elab::Output;
use sandblaster_front::hir::ItemKind;
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir;
use sandblaster_front::mir::literal::{Gen, KNames, LFn};
use sandblaster_front::mir::stmt::{self, StmtSpec};
use sandblaster_kernel::term::{DefDecl, DefKind, Recursion, Rel};
use sandblaster_kernel::value::Budget;
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
    let reps = with_reading(&c, |out, c| checked::prove_and_check(out, c.krate.as_ref().unwrap(), &c.lift_facts, &GateOptions { max_steps: 3, ..Default::default() }));
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
    let run = |c: &Checked, facts: &LiftFacts, vc: &VerdictCache| with_reading(c, |out, c| checked::prove_and_check(out, c.krate.as_ref().unwrap(), facts, &GateOptions { cache: Some(vc), ..Default::default() }));
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
        checked::prove_and_check(&mut out, k, &c.lift_facts, &opts)
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

// ---------------------------------------------------------------------------
// the trusted check (`mir::gate`)
// ---------------------------------------------------------------------------

const FEED: &str = "crate::varint::Decoder__u32::feed";

/// The trusted check's verdict on `global`.
fn verdict(out: &Output, c: &Checked, global: &str) -> Result<(), String> {
    out.mir_gate.ledger.verdicts(&out.env, c.krate.as_ref().unwrap(), &c.lift_facts).into_iter().find(|v| v.global == global).unwrap_or_else(|| panic!("`{global}` is not listed")).result
}

/// The varint reading with `Decoder::<u32>::feed`'s theorem proven (and
/// what its walk needs), nothing else; `f` runs on it with feed's
/// statement and theorem name.
fn with_feed<T: Send>(f: impl FnOnce(&mut Output, &Checked, StmtSpec, LFn) -> T + Send) -> T {
    let c = varint(None);
    with_reading(&c, |out, c| {
        checked::prove_lifted(out, &c.lift_facts, &GateOptions { only: Some("Decoder__u32::feed".into()), ..Default::default() });
        let mm = &c.lift_facts.mir_loaded[0].loaded;
        let contract = c.lift_facts.mir_contracts.iter().find(|x| x.global == FEED).expect("feed's contract");
        let state = out.mir_gate.ledger.state(&mm.m.module).expect("the reading").clone();
        let lf = state.fns[&contract.key].clone();
        let k = KNames { names: &mm.names, env: &out.env };
        let st = stmt::statement(&out.env, &mut Gen::resume(&mm.m, &k, state.clone()), &lf, &mm.m.fns[&contract.key], FEED).expect("feed's statement");
        f(out, c, st, lf)
    })
}

/// A copy of the global `name` under `as_name`, kernel-checked.
fn copy_global(out: &mut Output, name: &str, as_name: &str) -> DefDecl {
    let g = out.env.lookup_global(name).unwrap_or_else(|| panic!("no `{name}`"));
    let d = DefDecl { name: as_name.into(), kind: DefKind::Lemma, ty: out.env.global_type(g).unwrap(), body: out.env.global_body(g).unwrap(), recursion: Recursion::None, arity: out.env.global_arity(g).unwrap(), opaque: false };
    out.env.add_def(d.clone(), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("{e}"));
    d
}

/// `fun (x0 : T0) .. =>` and ` x0 ..` of a statement's telescope.
fn binders(st: &StmtSpec) -> (String, String) {
    let dot = |r: &Rel| if *r == Rel::Irr { "." } else { "" };
    (st.params.iter().map(|(n, r, t)| format!("({}{n} : {t}) ", dot(r))).collect(), st.params.iter().map(|(n, r, _)| format!(" {}{n}", dot(r))).collect())
}

/// Negative twins: the kernel accepts `L::thm::<feed>` with a weaker
/// statement — only the return value, not the final `&mut self` (a
/// component of `erase` dropped); a precondition `false = true` — or about
/// a redefinition of `S_f` made outside the elaboration, and the trusted
/// check refuses each; the original declaration is accepted before and
/// after.
#[test]
fn the_trusted_check_refuses_a_weaker_theorem_the_kernel_accepted() {
    with_feed(|out, c, st, lf| {
        let thm = format!("L::thm::{}", lf.id);
        assert_eq!(verdict(out, c, FEED), Ok(()));
        let orig = copy_global(out, &thm, "test::orig");
        let (lam, args) = (binders(&st).0, binders(&st).1);
        let arity = st.params.len();
        // (1) a component of `erase` dropped: the return value only
        let out_ty = st.l_out.clone();
        let parts = &lf.out_parts;
        assert_eq!(parts.len(), 2, "feed's `Out`: the final `self`, the result");
        let ret = &parts[1];
        let proj = format!("(fun (t : {out_ty}) => match t : {out_ty} as _ return {ret} with | tuple2(p0, p1) => p1 end)");
        let (lhs, rhs) = (st.l_of(), format!("Some[{out_ty}]({})", st.erase_ret.replace("@Y@", &format!("({})", st.app()))));
        let sig = format!("Sigma (k : Int), ((n : List(Unit)) -> (.hle : Eq(Bool, #le_int(k, seq::len Unit n), true)) -> Eq(Option({ret}), mir::map {out_ty} {ret} ({lhs}) {proj}, mir::map {out_ty} {ret} ({rhs}) {proj}))");
        let full = format!("(test::orig{args})");
        let body = format!("fun {lam}=> pair({sig}, fst {full}, fun (n : List(Unit)) (.hle : Eq(Bool, #le_int(fst {full}, seq::len Unit n), true)) => eq::cong (Option({out_ty})) (Option({ret})) (fun (o : Option({out_ty})) => mir::map {out_ty} {ret} o {proj}) ({lhs}) ({rhs}) ((snd {full}) n .hle))");
        out.env.load_core(&format!("def[lemma, arity = {arity}] {thm} : {}{sig} := {body}", st.tele()), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("the kernel accepts the weaker theorem: {e}"));
        let e = verdict(out, c, FEED).expect_err("a dropped component of `erase`");
        assert!(e.contains("states something else"), "{e}");
        // (2) a vacuous precondition
        let tele = st.tele();
        let ty = format!("{tele}(.hx : Eq(Bool, false, true)) -> {}", &st.theorem_ty()[tele.len()..]);
        out.env.load_core(&format!("def[lemma, arity = {}] {thm} : {ty} := fun {lam}(.hx : Eq(Bool, false, true)) => test::orig{args}", arity + 1), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("the kernel accepts the vacuous theorem: {e}"));
        let e = verdict(out, c, FEED).expect_err("a vacuous precondition");
        assert!(e.contains("states something else"), "{e}");
        // the original again: accepted
        out.env.add_def(DefDecl { name: thm.as_str().into(), ..orig.clone() }, &mut Budget { steps: 4_000_000_000 }).unwrap();
        assert_eq!(verdict(out, c, FEED), Ok(()));
        // (3) `S_f` redefined after the elaboration (the same function, by a
        // definition the trusted check did not see made): its statement now
        // names the redefinition, and the theorem is refused
        out.env.load_core(&format!("def[exec, arity = {arity}] {FEED} : {tele}{} := fun {lam}=> {}", st.s_ret, st.app()), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("{e}"));
        out.env.add_def(DefDecl { name: thm.as_str().into(), ..orig }, &mut Budget { steps: 4_000_000_000 }).unwrap();
        assert!(verdict(out, c, FEED).is_err());
    });
}

/// A listed function without its theorem is refused by the trusted check
/// (`size::<u32>`, not proven here), next to one with it (feed).
#[test]
fn the_trusted_check_refuses_a_function_without_its_theorem() {
    with_feed(|out, c, _, _| {
        assert_eq!(verdict(out, c, FEED), Ok(()));
        let e = verdict(out, c, "crate::varint::size__u32").expect_err("no theorem");
        assert!(e.starts_with("the kernel holds no `L::thm::"), "{e}");
    });
}

/// The MIR and the subset declare each module type alike (kernel field
/// names are positional, so a theorem cannot see a mismatch): with feed's
/// theorem proven, the trusted check accepts it for the crate as declared;
/// the negative twin: the subset's `Decoder__u32` with its fields reordered
/// (`bits_read` first; the types stay in place, so the kernel environment,
/// whose fields are `f0`, `f1`, and the theorem are the same) is refused,
/// with both declarations named.
#[test]
fn a_module_type_declared_with_its_fields_reordered_is_refused() {
    with_feed(|out, c, _, _| {
        assert_eq!(verdict(out, c, FEED), Ok(()));
        let mut k2 = c.krate.clone().unwrap();
        let it = k2.items.iter_mut().find(|it| it.path.0 == ["varint", "Decoder__u32"]).expect("the declaration");
        let ItemKind::Struct(s) = &mut it.kind else { panic!("a struct") };
        let n1 = s.fields[1].name.take();
        s.fields[1].name = std::mem::replace(&mut s.fields[0].name, n1);
        let e = out.mir_gate.ledger.verdicts(&out.env, &k2, &c.lift_facts).into_iter().find(|v| v.global == FEED).unwrap().result.expect_err("a reordered declaration");
        assert!(e.contains("`commonware_codec::varint::Decoder` as {=0(result, bits_read)}") && e.contains("`crate::varint::Decoder__u32` as {=0(bits_read, result)}"), "{e}");
    });
}

/// `L::thm::<id>` of `key`'s literal reading against the structured reading
/// `s_global` (no parameters, no loop: proven by evaluation, `refl`), added
/// to the kernel.
fn prove_by_evaluation(out: &mut Output, c: &Checked, key: &str, s_global: &str) {
    let mm = &c.lift_facts.mir_loaded[0].loaded;
    let state = out.mir_gate.ledger.state(&mm.m.module).expect("the reading").clone();
    let lf = state.fns[key].clone();
    let st = {
        let k = KNames { names: &mm.names, env: &out.env };
        stmt::statement(&out.env, &mut Gen::resume(&mm.m, &k, state.clone()), &lf, &mm.m.fns[key], s_global).expect("the statement")
    };
    let ty = st.theorem_ty();
    let pf = format!("pair({ty}, 0int, fun (n : List(Unit)) (.hle : Eq(Bool, #le_int(0int, seq::len Unit n), true)) => refl(Option({}), {}))", st.l_out, st.l_of());
    out.env.load_core(&format!("def[lemma, arity = 0] L::thm::{} : {ty} := {pf}", lf.id), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("the kernel accepts the theorem of `{key}`: {e}"));
}

/// Each listed function is checked against its own MIR instance (stage
/// tcb-review): the lift finds an instance by its lifted name alone, which
/// a function of another extracted module may share. `Decoder__u32::new`,
/// with its theorem, is accepted. The negative twin lists it with the
/// instance of `<Decoder<u32> as Default>::default`: that instance calls
/// `new`, so the theorem of its reading against `new`'s structured reading
/// holds, the kernel accepts it, and the statement, the MIR and the module
/// types all check; only the instance's identity tells it apart, and the
/// trusted check refuses it.
#[test]
fn a_function_listed_with_another_functions_instance_is_refused() {
    with_feed(|out, c, _, _| {
        const NEW: &str = "crate::varint::Decoder__u32::new";
        const DEFAULT: &str = "<commonware_codec::varint::Decoder<u32> as std::default::Default>::default";
        let new_key = c.lift_facts.mir_contracts.iter().find(|x| x.global == NEW).expect("new's contract").key.clone();
        prove_by_evaluation(out, c, &new_key, NEW);
        prove_by_evaluation(out, c, DEFAULT, NEW);
        assert_eq!(verdict(out, c, NEW), Ok(()));
        let mut facts = c.lift_facts.clone();
        facts.mir_contracts.iter_mut().find(|x| x.global == NEW).unwrap().key = DEFAULT.into();
        let e = out.mir_gate.ledger.verdicts(&out.env, c.krate.as_ref().unwrap(), &facts).into_iter().find(|v| v.global == NEW).unwrap().result.expect_err("another function's instance");
        assert!(e.contains("is `crate::varint::Decoder__u32::default`, not this function"), "{e}");
    });
}

/// L's names restart with each extraction's reading (`L::f0`, ..), and the
/// kernel lets a later definition take over a name (stage tcb-review): with
/// feed proven, a second reading of the same MIR under another module name,
/// its feed proven too, takes over feed's names. Feed is accepted for the
/// second extraction (the twin) and refused for the first, whose statement
/// now names the second's `run`: the theorem would be about another
/// extraction's reading (check 3 counts only the library's load and the
/// function's own extraction's).
#[test]
fn a_reading_whose_names_a_later_extraction_took_over_is_refused() {
    with_feed(|out, c, _, lf| {
        assert_eq!(verdict(out, c, FEED), Ok(()));
        let mut facts = c.lift_facts.clone();
        let mut loaded = (*facts.mir_loaded[0].loaded).clone();
        loaded.m.module = format!("{}, commonware_codec::other", loaded.m.module);
        facts.mir_loaded[0].loaded = Arc::new(loaded);
        checked::prove_lifted(out, &facts, &GateOptions { only: Some("Decoder__u32::feed".into()), ..Default::default() });
        let second = out.mir_gate.ledger.state(&facts.mir_loaded[0].loaded.m.module).expect("the second reading").fns[&lf.key].clone();
        assert_eq!(second.run, lf.run, "the second reading reuses feed's names");
        let v = |f: &LiftFacts| out.mir_gate.ledger.verdicts(&out.env, c.krate.as_ref().unwrap(), f).into_iter().find(|v| v.global == FEED).unwrap().result;
        assert_eq!(v(&facts), Ok(()));
        let e = v(&c.lift_facts).expect_err("the first reading's names were taken over");
        // (it names the first definition of the second reading it reaches: feed's or a callee's)
        assert!(e.contains("reaches `L::f") && e.contains("which neither the elaboration nor this extraction's literal reading defined"), "{e}");
    });
}

/// A stale verdict-cache entry: with keys that leave out the MIR (a test
/// hook), the entries stored for varint's MIR are served for a changed
/// `Decoder::<u16>::feed`; the kernel does not accept the replayed proof,
/// and feed has no theorem. The twin: the same entries for the same MIR
/// are replayed and accepted.
#[test]
fn a_stale_cache_entry_for_a_changed_mir_is_not_accepted() {
    let dir = std::env::temp_dir().join(format!("sb-theorem-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let vc = VerdictCache::new(Store::open(dir.clone(), sha256(b"theorem gate stale test")), "theorem gate stale test toolchain");
    let run = |c: &Checked, facts: &LiftFacts, vc: &VerdictCache| with_reading(c, |out, c| checked::prove_and_check(out, c.krate.as_ref().unwrap(), facts, &GateOptions { cache: Some(vc), key_ignores_mir: true, ..Default::default() }));
    let c = varint(None);
    let m = run(&c, &c.lift_facts, &vc);
    assert_eq!((module(&m).proven(), module(&m).cached()), (63, 0));
    let m = run(&c, &c.lift_facts, &vc);
    assert_eq!((module(&m).proven(), module(&m).cached()), (63, 63), "rejected: {:?}", module(&m).rejected.iter().take(3).collect::<Vec<_>>());
    assert!(module(&m).rejected.is_empty());
    let mut facts = c.lift_facts.clone();
    let mut loaded = (*facts.mir_loaded[0].loaded).clone();
    assert!(fault(&mut loaded.m, "Decoder::<u16>::feed", 7, 6) > 0);
    facts.mir_loaded[0].loaded = Arc::new(loaded);
    let m = run(&c, &facts, &vc);
    let m = module(&m);
    assert!(m.rejected.iter().any(|(g, why)| g == "crate::varint::Decoder__u16::feed" && why.contains("not accepted")), "{:?}", m.rejected);
    assert!(m.missing.iter().any(|(g, _)| g == "crate::varint::Decoder__u16::feed"), "{:?}", m.missing);
    assert!(m.outcomes.iter().any(|o| o.global == "crate::varint::size__u32" && o.result.is_ok()));
    let _ = std::fs::remove_dir_all(&dir);
}
