//! Panic contracts (C1; DESIGN.md §16.5, `docs/mir-lift.md` §20.4–§20.6):
//! a function's documented panics are part of its laws, `panics_when(p)` in
//! the laws file, and proven of rustc's MIR. On its domain (where its
//! `requires` hold) the function panics exactly when `p` holds:
//!
//! * where `p` does not hold, the theorem `L::thm::f` (whose preconditions
//!   end in the no-panic clause `!(p)`): the MIR returns the structured
//!   reading's value;
//! * where `p` holds, the panic theorem `L::pthm::f`: the literal reading of
//!   the MIR reaches `Panic` (a failed `Assert`, a call of a panic function,
//!   a callee's panic), never merely `Stuck` (out of fuel, undefined
//!   behaviour, a construct it does not model).
//!
//! The fixture `mir_fixtures/pc_guard` is a host crate verified in place, as
//! `sandblaster::build::compile_lifted` runs it, with three documented
//! panics: `halve_capped` asserts `x <= 1000` (with a message: the panic's
//! `fmt::Arguments` is built on the way), `succ` overflows at `u64::MAX`
//! (an `Assert` terminator), `half_of` unwraps an `Option` (the panic is in
//! core's `Option::unwrap`, a callee).
//!
//! * the exact contracts verify; the record and the lock state them;
//! * a contract too wide (`x > 999`: at 1000 the code returns) is refused
//!   by its panic theorem; one too narrow (`x > 1001`: at 1001 the code
//!   panics) by the structured reading's own obligation (the value theorem
//!   needs the no-panic clause to exclude every panic);
//! * the literal reading's panic is the MIR's: with the panic call replaced
//!   by a jump to itself (a path that does not terminate), or by a call of
//!   `std::process::abort` (a function returning `!` that is no panic), the
//!   same contract is refused, while the value theorem still holds;
//! * a function without a panic contract keeps today's reading: a
//!   precondition excluding the panic verifies as before, with no panic
//!   theorem; with neither, the function is refused (verified code cannot
//!   panic in its domain);
//! * verified code is safe Rust (DESIGN.md §2): a function read from MIR
//!   with an `unsafe` block is refused;
//! * a panic lemma (`panic_lemma(path);` in a proof file) gives the panic
//!   walk the panic condition in the code's terms: a condition stated
//!   through an opaque predicate is proven with it and refused without it;
//! * the lift conformance check seeks inputs inside each panic region on
//!   purpose and compares them with rustc (rustc panics, the literal
//!   reading gives `Panic`); a panic contract compared on no input, such as
//!   one whose condition never holds on the function's domain (its panic
//!   theorem would be vacuous), fails the check;
//! * a change in a panic contract is never classified *equivalent* by
//!   `sandblaster spec --diff` and `--accept --equivalent-only` (its
//!   no-panic clause is an ordinary hypothesis of the kernel type, so
//!   `requires(!(p))` and `panics_when(p)` have the same kernel statement):
//!   it is added, removed or its condition changed, in either direction,
//!   and only review accepts it; a change that keeps the panic contract is
//!   still compared by the kernel;
//! * the verified roots' panic contracts (the MMR's 18, the verifier's 13)
//!   are proven as checked in (`--ignored`: minutes).

#[path = "gated_util.rs"]
mod gated;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sandblaster_front::conform::{self, Config, Report};
use sandblaster_front::driver::{self, stage::SpecBaseline, BuildOutcome, Checked, ProverSet, VerifyOptions};
use sandblaster_front::lift::LiftFacts;
use sandblaster_front::loader::MemFs;
use sandblaster_front::lock::{self, LockEntry, Selection, What};
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir::{Callee, Term};
use sandblaster_front::specdiff::{self, Class};
use sandblaster_front::target::TargetInfo;

/// The host file and rustc's MIR of it (`mir_fixtures/extract.py`).
const CODE: &str = include_str!("mir_fixtures/pc_guard/src/a.rs");
const MIR: &str = include_str!("mir_fixtures/pc_guard/a.sbmir");

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[lift(in_place, mir = \"a.sbmir\")]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\npub use a::{halve_capped, succ, half_of};\n";

/// The exact panic contracts of the three functions (as the documentation
/// states them).
const EXACT: [&str; 3] = ["panics_when(x > 1000u64);", "panics_when(x > 18446744073709551614u64);", "panics_when(x.is_none());"];

/// The laws file: each function's contract, its panic contract (or
/// precondition) given by `pre`.
fn laws(pre: [&str; 3]) -> String {
    format!(
        r#"//! What the guarded functions return, and exactly where they panic.
use sandblaster::prelude::*;

/// `halve_capped` is half of `x`, and panics above 1000.
#[lift_attach(crate::a::halve_capped)]
fn halve_capped_contract() {{
    {}
    ensures(|ret: u64| ret == x / 2u64);
}}

/// `succ` is `x + 1`, and panics at `u64::MAX`.
#[lift_attach(crate::a::succ)]
fn succ_contract() {{
    {}
    ensures(|ret: u64| ret as Int == x as Int + 1);
}}

/// `half_of` is half of the value in `x`, and panics without one.
#[lift_attach(crate::a::half_of)]
fn half_of_contract() {{
    {}
    ensures(|ret: u64| ret == x.unwrap_or(0u64) / 2u64);
}}
"#,
        pre[0], pre[1], pre[2]
    )
}

const LOCK: &str = "host/sandblaster/m/SPEC.lock";
const ROOT_PATH: &str = "host/sandblaster/m/mod.rs";

/// The host crate with the laws `laws`, without a lock.
fn files(laws: &str) -> Vec<(String, String)> {
    vec![
        ("host/Cargo.toml".into(), "[package]\nname = \"pc-host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[workspace]\n".into()),
        ("host/src/lib.rs".into(), "//! The host crate.\nmod a;\npub use a::{halve_capped, succ, half_of};\n".into()),
        ("host/src/a.rs".into(), CODE.into()),
        (ROOT_PATH.into(), ROOT.into()),
        ("host/sandblaster/m/a.sbmir".into(), MIR.into()),
        ("host/sandblaster/m/LAWS.rs".into(), laws.into()),
    ]
}

fn with_lock(mut files: Vec<(String, String)>, lock: &str) -> Vec<(String, String)> {
    files.retain(|(p, _)| p != LOCK);
    files.push((LOCK.into(), lock.into()));
    files
}

/// A scratch directory: the crate, its target directories and its cache.
struct Scratch {
    dir: PathBuf,
    builds: usize,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sandblaster-panic-contracts-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir, builds: 0 }
    }

    /// The lock `sandblaster spec --accept` writes for `files` (every gate
    /// but the lock must pass, the theorem gate's panic theorems included),
    /// or why there is none.
    fn accept(&self, files: &[(String, String)]) -> Result<String, String> {
        let abs: Vec<(String, String)> = files.iter().map(|(p, t)| (self.dir.join(p).display().to_string(), t.clone())).collect();
        let root = self.dir.join(ROOT_PATH).display().to_string();
        gated::accept_lock(&abs, &root, &TargetInfo::aarch64_apple_darwin())
    }

    /// An enforcing in-place build of `files`, as the facade's
    /// `compile_lifted` runs it.
    fn build(&mut self, files: &[(String, String)]) -> BuildOutcome {
        let _ = std::fs::remove_dir_all(self.dir.join("host"));
        for (p, t) in files {
            let f = self.dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, t).unwrap();
        }
        self.builds += 1;
        let out = self.dir.join(format!("target{}/out", self.builds));
        std::fs::create_dir_all(&out).unwrap();
        let mut e: HashMap<String, String> = [
            ("CARGO_MANIFEST_DIR", self.dir.join("host").display().to_string()),
            ("OUT_DIR", out.display().to_string()),
            ("CARGO_CFG_TARGET_ARCH", "aarch64".into()),
            ("CARGO_CFG_TARGET_FEATURE", "neon,sha2,sha3,aes".into()),
            ("CARGO_CFG_TARGET_ENDIAN", "little".into()),
            ("CARGO_CFG_TARGET_POINTER_WIDTH", "64".into()),
            ("SANDBLASTER_CACHE_DIR", self.dir.join("cache").display().to_string()),
            ("SANDBLASTER_CACHE_KEY", "test secret".into()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for k in ["RUSTC", "CARGO"] {
            if let Ok(v) = std::env::var(k) {
                e.insert(k.into(), v);
            }
        }
        driver::build_lifted("sandblaster/m/mod.rs", "m", Some("panic-contracts-test-toolchain"), &|k| e.get(k).cloned(), &sandblaster_front::loader::RealFs)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn output<'o>(o: &'o BuildOutcome, name: &str) -> Option<&'o str> {
    o.outputs.iter().find(|(p, _)| p.file_name().is_some_and(|f| f == name)).map(|(_, c)| c.as_str())
}

/// The crate read by the front end (in memory).
fn checked(laws: &str) -> Checked {
    let files = files(laws);
    let fs = MemFs::from_files(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let c = driver::check(Path::new(ROOT_PATH), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// The theorem gate on `c`'s structured reading, with the MIR the literal
/// reading reads taken from `facts`: its walks, and the trusted check's
/// verdict per function (`mir::gate`, which wants a function's panic
/// theorem with its theorem).
struct Gate {
    walks: ModuleTheorems,
    verdicts: Vec<(String, Result<(), String>)>,
}

fn gate(c: &Checked, facts: &LiftFacts) -> Gate {
    sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let mut items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).collect();
        // (the panic lemmas a proof file attaches: reached through the
        // lift's hints, not through the functions)
        items.extend(c.lift_facts.panic_lemmas.iter().map(|(_, l)| l.trim_start_matches("crate::").to_string()));
        let mut out = checked::elaborate_names(k, &items);
        let mut reps = checked::prove_lifted(&mut out, facts, &GateOptions::default());
        assert_eq!(reps.len(), 1, "one lifted MIR module");
        let verdicts = out.mir_gate.ledger.verdicts(&out.env, k, facts).into_iter().map(|v| (v.global, v.result)).collect();
        Gate { walks: reps.remove(0), verdicts }
    })
}

impl Gate {
    /// The walk of `global`'s theorem of kind `kind` (`theorem` or `panic
    /// theorem`): `Ok` proven, `Err` why not.
    fn walk(&self, global: &str, kind: &str) -> Result<(), String> {
        match self.walks.outcomes.iter().find(|o| o.kind == kind && o.global == global) {
            Some(o) => o.result.as_ref().map(|_| ()).map_err(|e| e.clone()),
            None => Err(format!("no {kind} planned for `{global}`")),
        }
    }

    /// The trusted check's verdict on `global`.
    fn verdict(&self, global: &str) -> Result<(), String> {
        self.verdicts.iter().find(|v| v.0 == global).map(|v| v.1.clone()).unwrap_or_else(|| panic!("`{global}` is not listed"))
    }
}

const HALVE: &str = "crate::a::halve_capped";
const SUCC: &str = "crate::a::succ";
const HALF_OF: &str = "crate::a::half_of";

#[test]
fn exact_panic_contracts_are_proven_recorded_and_locked() {
    let mut s = Scratch::new("exact");
    let laws = laws(EXACT);
    let lock = s.accept(&files(&laws)).unwrap_or_else(|e| panic!("the exact contracts' gates:\n{e}"));
    // the lock states each panic contract
    for p in ["panics_when ((x > 1000u64) == true)", "panics_when ((x > 18446744073709551614u64) == true)", "panics_when (<::core::option::Option<u64>>::is_none((&x)) == true)"] {
        assert!(lock.contains(p), "the lock does not state `{p}`:\n{lock}");
    }
    let o = s.build(&with_lock(files(&laws), &lock));
    assert!(o.ok, "no verdict:\n{}\n{:?}", o.stderr, o.cargo);
    let record = output(&o, "m-verified.txt").expect("a record");
    assert!(record.contains("VERIFIED + LIFTED IN PLACE"), "{record}");
    assert!(record.contains("Panic contract") && record.contains("`halve_capped` panics when `x > 1000u64`"), "{record}");
    // the panic contract is no host obligation: nothing for the host to meet
    assert!(!record.contains("Host obligation (a precondition"), "{record}");
    let report = output(&o, "m-report.json").expect("a report");
    assert!(report.contains("3 of 3 panic contract(s) with a kernel-checked panic theorem"), "{report}");
    // the conformance check compared the panic region with rustc: rustc
    // panicked, and the literal reading gave `Panic`, on each input
    for f in ["halve_capped", "succ", "half_of"] {
        assert!(report.contains(&format!("`crate::a::{f}`: its panic contract's panic region compared with rustc on")), "{f}: {report}");
    }
}

#[test]
fn every_function_has_its_theorem_and_its_panic_theorem() {
    let c = checked(&laws(EXACT));
    let g = gate(&c, &c.lift_facts);
    for f in [HALVE, SUCC, HALF_OF] {
        assert_eq!(g.walk(f, "theorem"), Ok(()), "{f}");
        assert_eq!(g.walk(f, "panic theorem"), Ok(()), "{f}");
        assert_eq!(g.verdict(f), Ok(()), "{f}");
    }
    assert_eq!(g.walks.panic_theorems(), (3, 3));
    assert!(g.walks.missing.is_empty(), "{:?}", g.walks.missing);
}

#[test]
fn a_panic_contract_too_wide_is_refused_by_its_panic_theorem() {
    // `x > 999`: at 1000 the code returns 500, the contract says it panics
    let c = checked(&laws(["panics_when(x > 999u64);", EXACT[1], EXACT[2]]));
    let g = gate(&c, &c.lift_facts);
    assert_eq!(g.walk(HALVE, "theorem"), Ok(()));
    let e = g.walk(HALVE, "panic theorem").expect_err("a panic contract too wide");
    assert!(e.contains("returns a value on a path where the panic condition holds"), "{e}");
    // the gate refuses the function (its verdict needs both theorems)
    let e = g.verdict(HALVE).expect_err("no verdict without the panic theorem");
    assert!(e.contains("its panic contract") && e.contains("L::pthm::"), "{e}");
    // the others are untouched
    assert_eq!(g.verdict(SUCC), Ok(()));
    let s = Scratch::new("wide");
    let e = s.accept(&files(&laws(["panics_when(x > 999u64);", EXACT[1], EXACT[2]]))).expect_err("no lock for a contract too wide");
    assert!(e.contains("halve_capped"), "{e}");
}

#[test]
fn a_panic_contract_too_narrow_is_refused_by_the_value_theorem() {
    // `x > 1001`: at 1001 the code panics, the contract says it returns; the
    // structured reading's `unreachable!()` there is not excluded by the
    // no-panic clause, so `halve_capped` has no definition and no theorem
    let laws_narrow = laws(["panics_when(x > 1001u64);", EXACT[1], EXACT[2]]);
    let s = Scratch::new("narrow");
    let e = s.accept(&files(&laws_narrow)).expect_err("no lock for a contract too narrow");
    assert!(e.contains("halve_capped"), "{e}");
    let c = checked(&laws_narrow);
    let g = gate(&c, &c.lift_facts);
    assert!(g.walk(HALVE, "theorem").is_err());
    assert!(g.verdict(HALVE).is_err());
    assert_eq!(g.verdict(SUCC), Ok(()));
}

/// The literal reading of `halve_capped`'s MIR with its panic path (`bb2`
/// builds the message, `bb3` calls `std::rt::panic_fmt`) changed: `bb3`'s
/// call replaced by `term`, and with `skip_message` `bb2` going straight to
/// `bb3` (the message's construction is not modeled outside a panic block,
/// so without it the path would be stuck before reaching `term`).
fn with_panic_call(c: &Checked, term: Term, skip_message: bool) -> LiftFacts {
    let mut facts = c.lift_facts.clone();
    let mut loaded = (*facts.mir_loaded[0].loaded).clone();
    let f = loaded.m.fns.get_mut("fx_pc_guard::a::halve_capped").expect("halve_capped's MIR");
    assert!(matches!(&f.blocks[3].term, Term::Call(Callee::Diverge(k), ..) if k == "std::rt::panic_fmt"), "{:?}", f.blocks[3].term);
    f.blocks[3].term = term;
    if skip_message {
        assert!(matches!(&f.blocks[2].term, Term::Call(Callee::Fn(k), _, _, Some(3)) if k == "std::fmt::Arguments::<'_>::from_str"), "{:?}", f.blocks[2].term);
        f.blocks[2].term = Term::Goto(3);
    }
    facts.mir_loaded[0].loaded = Arc::new(loaded);
    facts
}

#[test]
fn a_path_that_does_not_terminate_or_aborts_is_not_a_panic() {
    let c = checked(&laws(EXACT));
    // the panic path made a jump to its own block: where `x > 1000` the
    // function loops forever (the literal reading is stuck at every fuel)
    let g = gate(&c, &with_panic_call(&c, Term::Goto(3), true));
    let e = g.walk(HALVE, "panic theorem").expect_err("a loop is no panic");
    assert!(e.contains("does not reach a panic"), "{e}");
    assert!(g.verdict(HALVE).is_err());
    // the value theorem is about the other path: it holds
    assert_eq!(g.walk(HALVE, "theorem"), Ok(()));
    // a function returning `!` that is no panic function (`process::abort`),
    // with and without the message's construction on the way
    for skip in [true, false] {
        let g = gate(&c, &with_panic_call(&c, Term::Call(Callee::Diverge("std::process::abort".into()), vec![], sandblaster_front::mir::ir::Place { local: 3, proj: vec![] }, None), skip));
        let e = g.walk(HALVE, "panic theorem").expect_err("an abort is no panic");
        assert!(e.contains("is stuck"), "{e}");
        assert!(g.verdict(HALVE).is_err());
        assert_eq!(g.walk(HALVE, "theorem"), Ok(()));
    }
    // the twin: the MIR as extracted
    let g = gate(&c, &c.lift_facts);
    assert_eq!(g.walk(HALVE, "panic theorem"), Ok(()));
    assert_eq!(g.verdict(HALVE), Ok(()));
}

#[test]
fn without_a_panic_contract_a_function_keeps_todays_reading() {
    // a precondition that excludes the panic: verified as before, and no
    // panic theorem is planned
    let pre = laws(["requires(x <= 1000u64);", "requires(x < 18446744073709551615u64);", "requires(x.is_some());"]);
    let c = checked(&pre);
    let g = gate(&c, &c.lift_facts);
    for f in [HALVE, SUCC, HALF_OF] {
        assert_eq!(g.walk(f, "theorem"), Ok(()), "{f}");
        assert_eq!(g.verdict(f), Ok(()), "{f}");
    }
    assert_eq!(g.walks.panic_theorems(), (0, 0));
    let s = Scratch::new("pre");
    let lock = s.accept(&files(&pre)).unwrap_or_else(|e| panic!("{e}"));
    assert!(!lock.contains("panics_when"), "{lock}");
    // the negative twin: neither (verified code cannot panic in its domain)
    let none = laws(["", EXACT[1], EXACT[2]]);
    let e = s.accept(&files(&none)).expect_err("a function that can panic, without a contract");
    assert!(e.contains("halve_capped"), "{e}");
}

/// Verified code is safe Rust (DESIGN.md §2, "No `unsafe`, for good"): a
/// function read from MIR with an `unsafe` block is refused by the lift,
/// even one whose operation L reads (an unchecked addition, stuck on
/// overflow, which a proof could exclude); as written, without it, the
/// crate is accepted.
#[test]
fn an_unsafe_block_in_verified_code_is_refused() {
    use sandblaster_front::surface::{hex, sha256};
    let code = CODE.replace("    x + 1\n", "    unsafe { x.unchecked_add(1) }\n");
    assert_ne!(code, CODE);
    // (the extraction's record of the source follows it, so that the
    // refusal is the `unsafe`'s, not a stale extraction's)
    let mir = MIR.replace(&hex(&sha256(CODE.as_bytes())), &hex(&sha256(code.as_bytes())));
    assert_ne!(mir, MIR);
    let mut fs = files(&laws(EXACT));
    for (p, t) in fs.iter_mut() {
        if p == "host/src/a.rs" {
            *t = code.clone();
        } else if p.ends_with("a.sbmir") {
            *t = mir.clone();
        }
    }
    let mem = MemFs::from_files(fs.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    let c = driver::check(Path::new(ROOT_PATH), &mem, &TargetInfo::aarch64_apple_darwin());
    let r = c.render();
    assert!(!c.ok() && r.contains("`unsafe` in a lifted function"), "{r}");
    assert!(!r.contains("changed since the MIR was extracted"), "{r}");
    // the twin: as written
    assert!(checked(&laws(EXACT)).ok());
}

/// The trusted check (`mir::gate`) on a panic theorem: the kernel accepts
/// `L::pthm::<halve_capped>` redefined with a weaker statement — a vacuous
/// precondition, or a panic hypothesis strengthened to `x > 2000` (proven
/// from the original by `linarith`) — and the check refuses each, since it
/// is not the panic statement of the declared contract; the original is
/// accepted before and after. A panic contract the lift lists otherwise
/// than the function declares it is refused too.
#[test]
fn the_trusted_check_refuses_a_weaker_panic_theorem() {
    use sandblaster_front::mir::literal::{Gen, KNames};
    use sandblaster_front::mir::stmt;
    use sandblaster_kernel::term::{DefDecl, DefKind, Recursion, Rel};
    use sandblaster_kernel::value::Budget;
    let c = checked(&laws(EXACT));
    sandblaster_front::elab::with_big_stack(|| {
        let k = c.krate.as_ref().unwrap();
        let items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).collect();
        let mut out = checked::elaborate_names(k, &items);
        checked::prove_lifted(&mut out, &c.lift_facts, &GateOptions::default());
        let verdict = |out: &sandblaster_front::elab::Output| out.mir_gate.ledger.verdicts(&out.env, k, &c.lift_facts).into_iter().find(|v| v.global == HALVE).expect("listed").result;
        assert_eq!(verdict(&out), Ok(()));
        let mm = &c.lift_facts.mir_loaded[0].loaded;
        let contract = c.lift_facts.mir_contracts.iter().find(|x| x.global == HALVE).expect("its contract");
        assert_eq!(contract.panic, Some(0), "the no-panic clause is the first precondition");
        let state = out.mir_gate.ledger.state(&mm.m.module).expect("the reading").clone();
        let lf = state.fns[&contract.key].clone();
        let st = {
            let kn = KNames { names: &mm.names, env: &out.env };
            stmt::statement_panic(&out.env, &mut Gen::resume(&mm.m, &kn, state.clone()), &lf, &mm.m.fns[&contract.key], HALVE, 0).expect("the panic statement")
        };
        assert_eq!(st.params.len(), 2);
        assert_eq!(st.params[1].2, "Eq(Bool, #gt_u64(x0, 1000u64), true)", "the hypothesis is the panic condition");
        let thm = format!("L::pthm::{}", lf.id);
        let g = out.env.lookup_global(&thm).expect("the panic theorem");
        let orig = DefDecl { name: "test::porig".into(), kind: DefKind::Lemma, ty: out.env.global_type(g).unwrap(), body: out.env.global_body(g).unwrap(), recursion: Recursion::None, arity: 2, opaque: false };
        out.env.add_def(orig.clone(), &mut Budget { steps: 4_000_000_000 }).unwrap();
        let tele = st.tele();
        let rest = st.theorem_ty()[tele.len()..].to_string();
        // (1) a vacuous precondition
        out.env.load_core(&format!("def[lemma, arity = 3] {thm} : {tele}(.hx : Eq(Bool, false, true)) -> {rest} := fun (x0 : U64) (.x1 : Eq(Bool, #gt_u64(x0, 1000u64), true)) (.hx : Eq(Bool, false, true)) => test::porig x0 .x1"), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("the kernel accepts the vacuous theorem: {e}"));
        let e = verdict(&out).expect_err("a vacuous precondition");
        assert!(e.contains("states something else"), "{e}");
        // (2) the panic hypothesis strengthened (a weaker theorem)
        out.env.load_core(&format!("def[lemma, arity = 2] {thm} : (x0 : U64) -> (.x1 : Eq(Bool, #gt_u64(x0, 2000u64), true)) -> {rest} := fun (x0 : U64) (.x1 : Eq(Bool, #gt_u64(x0, 2000u64), true)) => test::porig x0 .linarith([x1 : Eq(Bool, #gt_u64(x0, 2000u64), true)]; Eq(Bool, #gt_u64(x0, 1000u64), true); [])"), &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("the kernel accepts the weaker theorem: {e}"));
        let e = verdict(&out).expect_err("a stronger panic hypothesis");
        assert!(e.contains("states something else"), "{e}");
        // the original again: accepted
        out.env.add_def(DefDecl { name: thm.as_str().into(), ..orig }, &mut Budget { steps: 4_000_000_000 }).unwrap();
        assert_eq!(verdict(&out), Ok(()));
        // the lift's listing must be the declaration's: a panic contract
        // listed as none (only the value theorem wanted) or at another
        // precondition is refused
        for (panic, want) in [(None, "listed as none but declared as precondition 0"), (Some(1), "listed as precondition 1 but declared as precondition 0")] {
            let mut facts = c.lift_facts.clone();
            facts.mir_contracts.iter_mut().find(|x| x.global == HALVE).expect("its contract").panic = panic;
            let e = out.mir_gate.ledger.verdicts(&out.env, k, &facts).into_iter().find(|v| v.global == HALVE).expect("listed").result.expect_err("a listing other than the declaration");
            assert!(e.contains(want), "{e}");
        }
        let _ = Rel::Irr;
    });
}

/// `succ` with its panic condition stated through an opaque predicate (a
/// law's vocabulary the literal reading's arithmetic does not see into),
/// and a proof file: the value region's fact (`at_start!`) and, with
/// `lemma`, the panic lemma that states the condition in the code's terms.
fn opaque_files(lemma: &str) -> Vec<(String, String)> {
    let laws = format!(
        r#"//! `succ` with its panic stated through an opaque predicate.
use sandblaster::prelude::*;

/// Whether `x` is the largest word (opaque: proofs read it through its
/// lemma).
#[spec]
#[opaque]
#[example(at_max(18446744073709551615u64) && !at_max(7u64))]
pub fn at_max(x: u64) -> bool {{
    x == 18446744073709551615u64
}}

/// `halve_capped` is half of `x`, and panics above 1000.
#[lift_attach(crate::a::halve_capped)]
fn halve_capped_contract() {{
    {}
    ensures(|ret: u64| ret == x / 2u64);
}}

/// `succ` is `x + 1`, and panics at the largest word.
#[lift_attach(crate::a::succ)]
fn succ_contract() {{
    panics_when(crate::laws::at_max(x));
    ensures(|ret: u64| ret as Int == x as Int + 1);
}}

/// `half_of` is half of the value in `x`, and panics without one.
#[lift_attach(crate::a::half_of)]
fn half_of_contract() {{
    {}
    ensures(|ret: u64| ret == x.unwrap_or(0u64) / 2u64);
}}
"#,
        EXACT[0], EXACT[2]
    );
    let proof = format!(
        r#"//! The proofs.
use sandblaster::prelude::*;

/// `succ`'s no-panic clause in the code's terms: below the largest word.
#[lemma]
fn succ_np(x: u64) {{
    requires(!crate::laws::at_max(x));
    ensures(x < 18446744073709551615u64);
    by_unfolding(crate::laws::at_max);
}}

/// `succ`'s panic condition in the code's terms: the largest word.
#[lemma]
fn succ_panics(x: u64) {{
    requires(crate::laws::at_max(x));
    ensures(x == 18446744073709551615u64);
    by_unfolding(crate::laws::at_max);
}}

#[lift_attach(crate::a::succ)]
fn succ_facts() {{
    at_start! {{
        crate::proof::succ_np(x);
    }}
    {lemma}
}}
"#
    );
    let mut fs = files(&laws);
    for (p, t) in fs.iter_mut() {
        if p == ROOT_PATH {
            *t = ROOT.replace("\npub use a::", "\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::");
        }
    }
    fs.push(("host/sandblaster/m/PROOF.rs".into(), proof));
    fs
}

fn checked_files(files: &[(String, String)]) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
    driver::check(Path::new(ROOT_PATH), &fs, &TargetInfo::aarch64_apple_darwin())
}

/// A panic lemma (`panic_lemma(path);` in a proof file's attachment) gives
/// the panic walk the panic condition in the code's terms: `succ`'s panic
/// stated through an opaque predicate is proven with it, and refused
/// without it (the walk's arithmetic does not see into the predicate, so
/// the path where the addition does not overflow is not refuted). Its
/// value theorem holds either way. A panic lemma attached from the laws
/// file is refused: it is a proof step, not a contract.
#[test]
fn a_panic_lemma_states_the_panic_condition_in_the_codes_terms() {
    let c = checked_files(&opaque_files("panic_lemma(crate::proof::succ_panics);"));
    assert!(c.ok(), "{}", c.render());
    assert_eq!(c.lift_facts.panic_lemmas, vec![(SUCC.to_string(), "crate::proof::succ_panics".to_string())]);
    let g = gate(&c, &c.lift_facts);
    assert_eq!(g.walk(SUCC, "theorem"), Ok(()));
    assert_eq!(g.walk(SUCC, "panic theorem"), Ok(()));
    assert_eq!(g.verdict(SUCC), Ok(()));
    // the twin: no panic lemma
    let c = checked_files(&opaque_files(""));
    assert!(c.ok(), "{}", c.render());
    let g = gate(&c, &c.lift_facts);
    assert_eq!(g.walk(SUCC, "theorem"), Ok(()));
    let e = g.walk(SUCC, "panic theorem").expect_err("the walk cannot decide the code's test from an opaque predicate");
    assert!(e.contains("returns a value on a path where the panic condition holds"), "{e}");
    assert!(g.verdict(SUCC).is_err());
    // a panic lemma in the laws file: refused
    let mut fs = opaque_files("");
    for (p, t) in fs.iter_mut() {
        if p.ends_with("LAWS.rs") {
            *t = t.replace("    panics_when(crate::laws::at_max(x));\n", "    panics_when(crate::laws::at_max(x));\n    panic_lemma(crate::proof::succ_panics);\n");
        }
    }
    let c = checked_files(&fs);
    let r = c.render();
    assert!(!c.ok() && r.contains("`panic_lemma(..);` is a proof step"), "{r}");
}

/// The lift conformance check of the fixture with the laws `laws`, in
/// place (a copy of the host crate compiled by rustc), without the gates:
/// the report.
fn conformance(laws: &str, name: &str) -> Report {
    let s = Scratch::new(&format!("conform-{name}"));
    for (p, t) in files(laws) {
        let f = s.dir.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, t).unwrap();
    }
    let c = driver::check(&s.dir.join(ROOT_PATH), &sandblaster_front::loader::RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let infos: Vec<&sandblaster_front::lift::LiftedInfo> = c.lifted.iter().filter(|l| l.in_place && !l.ghost).collect();
    let mut cfg = Config::new(PathBuf::from(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into())), s.dir.join("work"), "2024", "tests/panic_contracts.rs");
    cfg.manifest_dir = Some(s.dir.join("host"));
    cfg.cargo = PathBuf::from(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    driver::stage::with_elaboration_mut(k, &opts, |out| conform::check_in_place(out, k, &c, &infos, &cfg))
}

fn entry<'r>(r: &'r Report, lifted: &str) -> &'r conform::EntryReport {
    r.entries.iter().find(|e| e.lifted == lifted).unwrap_or_else(|| panic!("no entry `{lifted}`"))
}

/// The conformance check compares each panic region on inputs inside it,
/// sought on purpose after the coverage-driven ones: `halve_capped`'s
/// region (`x > 1000`) is wide, so it reaches at least the search's quota
/// (16; up to the literal budget, 64); `succ`'s and `half_of`'s hold one
/// input each (`u64::MAX`, `None`), and each is found. On every one rustc
/// panicked and the literal reading gave `Panic`.
#[test]
fn the_conformance_check_compares_each_panic_region_on_inputs_sought_inside_it() {
    let r = conformance(&laws(EXACT), "exact");
    assert!(r.passed(), "{:#?}", r.failures());
    let halve = entry(&r, HALVE).panics;
    assert!((16..=64).contains(&halve), "{:?}", entry(&r, HALVE));
    assert_eq!(entry(&r, SUCC).panics, 1, "{:?}", entry(&r, SUCC));
    assert_eq!(entry(&r, HALF_OF).panics, 1, "{:?}", entry(&r, HALF_OF));
    assert!(r.notes.iter().any(|n| n.contains(&format!("`crate::a::halve_capped`: its panic contract's panic region compared with rustc on {halve} input(s)"))), "{:#?}", r.notes);
}

/// Negative twin: a panic contract whose condition never holds on the
/// function's domain (`x > 1000` where it requires `x <= 1000`) passes the
/// gates vacuously (its panic theorem has contradictory hypotheses), but
/// the conformance check finds no input inside it and fails, naming it;
/// the other contracts are compared as before.
#[test]
fn a_panic_contract_compared_on_no_input_fails_the_conformance_check() {
    let vacuous = laws(["requires(x <= 1000u64);\n    panics_when(x > 1000u64);", EXACT[1], EXACT[2]]);
    // the theorem gate accepts it: both theorems hold, the panic theorem
    // vacuously
    let c = checked(&vacuous);
    let g = gate(&c, &c.lift_facts);
    assert_eq!(g.walk(HALVE, "panic theorem"), Ok(()));
    assert_eq!(g.verdict(HALVE), Ok(()));
    let r = conformance(&vacuous, "vacuous");
    assert!(!r.passed(), "a vacuous panic contract went unnoticed: {}", r.summary());
    assert_eq!(entry(&r, HALVE).panics, 0);
    let named: Vec<&String> = r.errors.iter().filter(|e| e.contains("compared with rustc on no input")).collect();
    assert_eq!(named.len(), 1, "{:#?}", r.errors);
    assert!(named[0].contains("crate::a::halve_capped"), "{}", named[0]);
    assert!(r.mismatches.is_empty(), "{:#?}", r.mismatches);
    assert_eq!(entry(&r, SUCC).panics, 1);
}

// ---------------------------------------------------------------------
// the classification of a changed panic contract (`spec --diff`,
// `spec --accept --equivalent-only`)
// ---------------------------------------------------------------------

/// One classified change: what changed, its class and why.
type Classified = (What, Option<Class>, String);

/// The surface of the fixture with the laws `laws` (the proofs must check).
fn surface_of(laws: &str) -> sandblaster_front::surface::Surface {
    let c = checked(laws);
    let r = driver::stage::spec_run(&c, &SpecBaseline::None, false);
    assert!(r.v.proofs_ok, "the fixture does not verify:\n{}", r.v.diags.render(&c.sm));
    r.surface.expect("a surface")
}

/// The key of `f`'s contract (`boundary-fn:` or `contract:`).
fn fn_key(s: &sandblaster_front::surface::Surface, f: &str) -> String {
    let keys: Vec<&String> = s.items.iter().map(|i| &i.key).filter(|k| (k.starts_with("boundary-fn:") || k.starts_with("contract:")) && k.ends_with(&format!("::{f}"))).collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    keys[0].clone()
}

/// `sandblaster spec --diff`: the changes from the laws `old` to `new`,
/// classified, by key; and whether `f`'s kernel statement (`canon`) is the
/// same on both sides.
fn diff(old: &str, new: &str, f: &str) -> (std::collections::BTreeMap<String, Classified>, bool) {
    let so = surface_of(old);
    let entries: Vec<LockEntry> = so.items.iter().map(|i| LockEntry::of(i, &so.target)).collect();
    let c = checked(new);
    let r = driver::stage::spec_run(&c, &SpecBaseline::Old(entries), true);
    assert!(r.v.proofs_ok, "{}", r.v.diags.render(&c.sm));
    let sn = r.surface.as_ref().unwrap();
    let key = fn_key(sn, f);
    let same_canon = so.get(&key).unwrap().canon == sn.get(&key).unwrap().canon;
    (r.changes.into_iter().map(|ch| (ch.key, (ch.what, ch.class, ch.reason))).collect(), same_canon)
}

/// `sandblaster spec --accept --equivalent-only` on the fixture with the
/// laws `new` and the lock accepted for `old`: the keys it would accept.
fn equivalent_only(old: &str, new: &str) -> Vec<String> {
    let text = lock::preview_accept(None, &surface_of(old), &Selection::All).expect("accept").0.render();
    let c = checked_files(&with_lock(files(new), &text));
    assert!(c.ok(), "{}", c.render());
    let r = driver::stage::spec_run(&c, &SpecBaseline::Lock, true);
    assert!(r.v.proofs_ok, "{}", r.v.diags.render(&c.sm));
    specdiff::equivalent_keys(&r.changes)
}

/// A change in `halve_capped`'s panic contract: never equivalent, in either
/// direction, whatever the kernel says of the two function types, and
/// neither is any item that depends on it; `--equivalent-only` accepts none
/// of them. The case that slipped through before: `requires(!(p))` to
/// `panics_when(p)` has an identical kernel statement (the no-panic clause
/// is that very hypothesis), and `requires(x <= 1000)` to
/// `panics_when(x > 1000)` (the MMR's `to_nearest_size`) a kernel-proven
/// equivalent one.
#[test]
fn a_changed_panic_contract_is_never_equivalent() {
    let req_not = laws(["requires(!(x > 1000u64));", EXACT[1], EXACT[2]]);
    let req_le = laws(["requires(x <= 1000u64);", EXACT[1], EXACT[2]]);
    let exact = laws(EXACT);
    let flipped = laws(["panics_when(1000u64 < x);", EXACT[1], EXACT[2]]);
    for (old, new, same_canon, why) in [
        (&req_not, &exact, true, "a panic contract was added"),
        (&exact, &req_not, true, "the panic contract was removed"),
        (&req_le, &exact, false, "a panic contract was added"),
        (&exact, &req_le, false, "the panic contract was removed"),
        (&exact, &flipped, false, "the panic condition changed"),
    ] {
        let (d, same) = diff(old, new, "halve_capped");
        assert_eq!(same, same_canon, "{why}: {d:#?}");
        let key = d.keys().find(|k| k.starts_with("boundary-fn:") || k.starts_with("contract:")).cloned();
        let (what, class, reason) = &d[key.as_deref().unwrap_or_else(|| panic!("{why}: halve_capped unchanged: {d:#?}"))];
        assert_eq!((*what, *class), (What::Changed, Some(Class::Unrelated)), "{why}: {reason}");
        assert!(reason.starts_with(why) && reason.contains("never equivalent"), "{reason}");
        // nothing that changed with it is equivalent (its section depends on
        // it), and `--equivalent-only` accepts nothing
        assert!(d.values().all(|(_, c, _)| *c != Some(Class::Equivalent)), "{why}: {d:#?}");
        assert_eq!(equivalent_only(old, new), Vec::<String>::new(), "{why}");
    }
}

/// Negative twin: a change that leaves the panic contract alone is not
/// caught by the panic-contract rule; it goes to the kernel comparison as
/// before. `succ`'s `ensures` restated under its unchanged panic contract:
/// both directions of the `ensures` are proven (the class is then the
/// domain comparison's; today it does not prove a domain with a no-panic
/// clause, so it stays conservative). The same restatement with no panic
/// contract on either side: kernel-proven equivalent, and accepted by
/// `--equivalent-only`.
#[test]
fn a_change_that_keeps_the_panic_contract_is_still_compared_by_the_kernel() {
    let exact = laws(EXACT);
    let restated = exact.replace("ensures(|ret: u64| ret as Int == x as Int + 1);", "ensures(|ret: u64| ret as Int == 1 + x as Int);");
    assert_ne!(restated, exact);
    let (d, same) = diff(&exact, &restated, "succ");
    assert!(!same, "the kernel statement changed");
    let key = fn_key(&surface_of(&exact), "succ");
    let (what, _, reason) = &d[&key];
    assert_eq!(*what, What::Changed, "{reason}");
    assert!(!reason.contains("panic contract") && reason.starts_with("domain: ") && reason.contains("ensures: old ⇒ new proven; new ⇒ old proven"), "{reason}");
    // the same restatement with no panic contract on either side (`succ`'s
    // overflow a precondition): compared, and equivalent
    let pre = laws([EXACT[0], "requires(x < 18446744073709551615u64);", EXACT[2]]);
    let pre_restated = pre.replace("ensures(|ret: u64| ret as Int == x as Int + 1);", "ensures(|ret: u64| ret as Int == 1 + x as Int);");
    assert_ne!(pre_restated, pre);
    let (d, same) = diff(&pre, &pre_restated, "succ");
    assert!(!same, "the kernel statement changed");
    let (what, class, reason) = &d[&key];
    assert_eq!((*what, *class), (What::Changed, Some(Class::Equivalent)), "{reason}");
    assert!(equivalent_only(&pre, &pre_restated).contains(&key), "{d:#?}");
    // and with no change at all, nothing is reported
    assert!(diff(&exact, &exact, "succ").0.is_empty());
}

/// The panic contracts of a verified root as checked in: the gate run on
/// the lifted functions (and what they reach, elaborated without the laws
/// that only state things about them). Per function with a panic contract:
/// its theorem's walk, its panic theorem's walk (with the walk's
/// statistics) and the trusted check's verdict.
fn root_panic_contracts(rel: &str) -> Vec<(String, Result<(), String>, Result<String, String>, Result<(), String>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(rel);
    let c = driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let with_panic: Vec<String> = c.lift_facts.mir_contracts.iter().filter(|x| x.panic.is_some()).map(|x| x.global.clone()).collect();
    sandblaster_front::elab::with_big_stack(|| {
        let k = c.krate.as_ref().unwrap();
        let mut items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        items.extend(["^words::", "^stdlib::", "^sha256::"].map(String::from));
        // (the panic lemmas the proof files attach: reached through the
        // lift's hints, not through the functions)
        items.extend(c.lift_facts.panic_lemmas.iter().map(|(_, l)| l.trim_start_matches("crate::").to_string()));
        let mut out = checked::elaborate_names(k, &items);
        for d in out.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error) {
            eprintln!("elaboration: {}", d.render(&c.sm));
        }
        let only = std::env::var("SANDBLASTER_PC_ONLY").ok();
        let mut reps = checked::prove_lifted(&mut out, &c.lift_facts, &GateOptions { only, ..Default::default() });
        let verdicts: Vec<(String, Result<(), String>)> = out.mir_gate.ledger.verdicts(&out.env, k, &c.lift_facts).into_iter().map(|v| (v.global, v.result)).collect();
        let walks = reps.remove(0);
        with_panic
            .iter()
            .map(|g| {
                let walk = |kind: &str| walks.outcomes.iter().find(|o| &o.global == g && o.kind == kind).map(|o| o.result.as_ref().map(|p| p.stats.clone()).map_err(|e| e.clone())).unwrap_or_else(|| Err(format!("no {kind} planned")));
                let verdict = verdicts.iter().find(|v| &v.0 == g).map(|v| v.1.clone()).unwrap_or_else(|| Err("not listed".into()));
                (g.clone(), walk("theorem").map(|_| ()), walk("panic theorem"), verdict)
            })
            .collect()
    })
}

/// Prints and checks [`root_panic_contracts`]: every panic contract of the
/// root has both theorems and passes the trusted check.
fn check_root_panic_contracts(rel: &str, want: &[&str]) {
    let rs = root_panic_contracts(rel);
    let mut bad = Vec::new();
    for (g, thm, pthm, verdict) in &rs {
        eprintln!("{g}:\n  theorem: {thm:?}\n  panic theorem: {pthm:?}\n  verdict: {verdict:?}");
        if thm.is_err() || pthm.is_err() || verdict.is_err() {
            bad.push(g.clone());
        }
    }
    let have: Vec<&str> = rs.iter().map(|r| r.0.as_str()).collect();
    for w in want {
        assert!(have.contains(w), "`{w}` has no panic contract: {have:?}");
    }
    assert!(bad.is_empty(), "panic contracts not proven: {bad:?}");
}

/// The MMR's documented panics (DESIGN.md §16.5, pilot A's among them:
/// `PeakIterator::to_nearest_size` above `MAX_NODES`, its `assert!` with
/// its message reached through core's `PartialOrd::le` and the lifted
/// `Position::partial_cmp`), each proven of rustc's MIR with its theorem.
/// Minutes (the MMR's lifted functions are elaborated): run with
/// `--ignored`.
#[test]
#[ignore]
fn the_mmr_panic_contracts_prove() {
    check_root_panic_contracts("storage/sandblaster/mmr/mod.rs", &["crate::merkle::mmr::iterator::PeakIterator::to_nearest_size"]);
}

/// The Merkle proof verifier's panic contracts (its position arithmetic),
/// proven like the MMR's. Minutes: run with `--ignored`.
#[test]
#[ignore]
fn the_verifier_panic_contracts_prove() {
    check_root_panic_contracts("storage/sandblaster/verifier/mod.rs", &["crate::merkle::position::Position::add"]);
}
