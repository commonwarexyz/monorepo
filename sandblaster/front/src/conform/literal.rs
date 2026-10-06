//! Conformance of the literal reading L against `rustc`
//! (`docs/checked-structuring.md`, amendment (f); `docs/mir-lift.md` §20.8).
//!
//! The kernel theorem `L::thm::f` equates L, the trusted reading of a
//! function's MIR, with the structured reading S at sufficient fuel. What
//! no theorem can show is that L means what `rustc`'s build does (the
//! generator, its library, the parse and the printer are trusted:
//! DESIGN.md §1.1 item 8). This part of the check runs L itself, in the
//! kernel, on the inputs the check compares S on, and compares its result
//! with `rustc`'s output for the same input, independently of S:
//!
//! * the left side is `L::<f>::run fuel b0 (Ret(init(x̄)))` at the inputs
//!   (`init` from the theorem's statement, `mir::stmt`), with fuel `2^16`;
//! * the right side is `Ret(erase(r))`, where `r` is `rustc`'s output
//!   read back as a value of S's result type (the states, then the
//!   result) and `erase` the statement's own map into L's `Out`;
//! * both are evaluated by `Env::eval_closed` (the kernel's type check and
//!   closed evaluation; a value with invariant fields carries erased proofs
//!   and goes through the reference strategy of `sandblaster eval`, as the
//!   structured reading's evaluation does) and compared by the kernel's
//!   conversion.
//!
//! An input where the function's panic contract says it panics (in place:
//! its domain holds, its no-panic clause does not; `conform::PANIC_CASE`)
//! is compared too: rustc must panic there, and L must give `Panic` (a test
//! of the trusted panic reading, `literal::must_panic`, against rustc). The
//! check seeks such inputs on purpose (`Gen::panic_region`), compares them
//! on a budget of their own, and fails a panic contract compared on none.
//!
//! A difference is a mismatch of the check (the build fails). It is bounded
//! (the first [`LITERAL_CASES`] compared inputs of each function, in the
//! check's deterministic order) and part of the check's cached record.

use sandblaster_kernel::term::{Lvl, Rel, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, VEnv, V};

use std::collections::HashMap;

use super::{Case, Gen, Mismatch, Plan, Report};
use crate::driver::Checked;
use crate::lift::ConformEntry;
use crate::elab::value::J;
use crate::elab::{self};
use crate::mir::checked;
use crate::mir::literal::{Gen as LGen, KNames};
use crate::mir::stmt;

/// Inputs per function on which L is compared with `rustc`.
pub const LITERAL_CASES: usize = 64;
/// Kernel steps per evaluation of either side.
const STEPS: u64 = 500_000_000;
/// The fuel: `2^FUEL_LOG` units (a loop iteration or a self-call on a path
/// consumes one; fuel is a bound on depth, not a count of steps).
const FUEL_LOG: usize = 16;

/// The closed terms of one function's comparison.
pub(super) struct LitFn {
    /// `λ x̄ n. L::<f>::run n b0 (Ret(init(x̄)))` over the relevant parameters.
    run: Tm,
    /// `λ (yy : R_S). erase(yy)`.
    erase: Tm,
    /// `λ (o : Out). Ret(o)` (the value outcome, `mir::Res`).
    some: Tm,
    /// `Panic` (the panic outcome at `Out`).
    panic: Tm,
    fuel: Tm,
}

/// The comparison terms of each entry whose function is read from MIR, by
/// its lifted name (a function read from MIR but not comparable is an
/// error of the check: L is compared on every one). The
/// literal reading is the theorem gate's when it ran on `out`, else it is
/// generated and kernel-checked here.
pub(super) fn prepare(out: &mut elab::Output, c: &Checked, entries: &[&ConformEntry], rep: &mut Report) -> HashMap<String, LitFn> {
    let mut res: HashMap<String, LitFn> = HashMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for mm in &c.lift_facts.mir_loaded {
        let (m, names) = (&mm.loaded.m, &mm.loaded.names);
        if !seen.insert(m.module.clone()) {
            continue;
        }
        let ours: Vec<(&str, &crate::lift::MirContract)> = entries.iter().filter_map(|e| c.lift_facts.mir_contracts.iter().find(|k| k.global == e.lifted && m.fns.contains_key(&k.key)).map(|k| (e.lifted.as_str(), k))).collect();
        if ours.is_empty() {
            continue;
        }
        let state = match out.mir_gate.ledger.state(&m.module) {
            Some(st) => st.clone(),
            None => {
                let keys: Vec<String> = ours.iter().map(|(_, k)| k.key.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                match checked::load_into(&mut out.mir_gate.ledger, &mut out.env, m, names, &keys, None) {
                    Ok(l) => l.state,
                    Err(e) => {
                        rep.errors.push(format!("the literal reading of `{}` was not accepted, so it cannot be compared with rustc: {e}", m.module));
                        continue;
                    }
                }
            }
        };
        let fuel = match fuel_term(&out.env) {
            Ok(t) => t,
            Err(e) => {
                rep.errors.push(format!("the literal reading's fuel: {e}"));
                return res;
            }
        };
        for (i, k) in ours {
            let (Some(lf), Some(f)) = (state.fns.get(&k.key), m.fns.get(&k.key)) else {
                rep.errors.push(format!("`{}`: no literal reading of `{}`, so it cannot be compared with rustc", k.global, k.key));
                continue;
            };
            let kn = KNames { names, env: &out.env };
            let mut g = LGen::resume(m, &kn, state.clone());
            let spec = match stmt::statement(&out.env, &mut g, lf, f, &k.global) {
                Ok(s) => s,
                Err(e) => {
                    rep.errors.push(format!("`{}`: the statement of its theorem cannot be generated, so L cannot be compared: {e}", k.global));
                    continue;
                }
            };
            let binders: Vec<String> = spec.params.iter().filter(|p| p.1 == Rel::Rel).map(|(n, _, t)| format!("({n} : {t}) ")).collect();
            let texts = [format!("fun {}(n : List(Unit)) => {}", binders.concat(), spec.l_of()), spec.erase_fn(), format!("fun (o : {o}) => mir::Res::Ret[{o}](o)", o = spec.l_out), format!("mir::Res::Panic[{}]", spec.l_out)];
            let parsed: Result<Vec<Tm>, String> = texts.iter().map(|t| out.env.parse_term(&[], t).map_err(|e| e.to_string())).collect();
            match parsed {
                Ok(v) => {
                    let [run, erase, some, panic]: [Tm; 4] = v.try_into().unwrap_or_else(|_| unreachable!());
                    res.insert(i.to_string(), LitFn { run, erase, some, panic, fuel: fuel.clone() });
                }
                Err(e) => rep.errors.push(format!("`{}`: L's comparison terms do not parse: {e}", k.global)),
            }
        }
    }
    res
}

/// `2^FUEL_LOG` units of fuel, by doubling.
fn fuel_term(env: &sandblaster_kernel::api::Env) -> Result<Tm, String> {
    let one = env.parse_term(&[], "Cons[Unit](tt, Nil[Unit])").map_err(|e| e.to_string())?;
    let dbl = env.parse_term(&[], "fun (x : List(Unit)) => seq::append Unit x x").map_err(|e| e.to_string())?;
    Ok((0..FUEL_LOG).fold(one, |t, _| mk::app(dbl.clone(), t)))
}

/// Compares L with `rustc` on the first [`LITERAL_CASES`] inputs of each
/// function `rustc` returned on (its outputs in `rustc`, by case), and on
/// up to as many inputs of its panic contract's panic region where rustc
/// panicked (L must give `Panic`); returns, per function, the panic inputs
/// on which both panicked (`conform::panic_coverage` fails a contract
/// with none).
pub(super) fn compare(g: &Gen<'_>, plans: &[Plan<'_>], cases: &[Case], rustc: &[Result<Vec<J>, String>], lits: &HashMap<String, LitFn>, rep: &mut Report) -> std::collections::BTreeMap<String, usize> {
    let env = &g.out.env;
    let conv = g.conv();
    // (per function, the panics compared: inputs of its panic region where
    // rustc panicked and L gave `Panic`)
    let mut panics: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (c, r) in cases.iter().zip(rustc) {
        let p = &plans[c.plan];
        // (an input of a panic contract's panic region, where rustc panicked:
        // L must give `Panic`)
        let panic_case = c.model.as_ref().err().is_some_and(|e| e == super::PANIC_CASE) && r.as_ref().is_err_and(|e| e.starts_with("a panic ("));
        // (the panic inputs have a budget of their own: the search for them
        // runs after the coverage-driven inputs, which spend `literal`'s)
        if panic_case && let Some(lit) = lits.get(&p.e.lifted) && rep.entries[p.index].panics < LITERAL_CASES {
            let Ok(args) = p.params.iter().zip(&c.args).map(|(t, j)| conv.term(t, j)).collect::<Result<Vec<Tm>, String>>() else { continue };
            let input = format!("({})", c.args.iter().map(J::render).collect::<Vec<_>>().join(", "));
            let lhs = mk::apps(lit.run.clone(), args.into_iter().map(|a| (Rel::Rel, a)).chain([(Rel::Rel, lit.fuel.clone())]));
            let got = env.eval_closed(&lhs, &mut Budget { steps: STEPS }).and_then(|nf| env.eval(&VEnv::default(), Lvl(0), &nf, &mut Budget { steps: STEPS }).map_err(|e| e.into()));
            let want = env.eval(&VEnv::default(), Lvl(0), &lit.panic, &mut Budget { steps: STEPS });
            let ok = matches!((&got, &want), (Ok(l), Ok(w)) if env.conv(Lvl(0), l, w, &mut Budget { steps: STEPS }).unwrap_or(false));
            if ok {
                *panics.entry(p.e.lifted.clone()).or_default() += 1;
                rep.entries[p.index].panics += 1;
            } else {
                let what = match &got {
                    Ok(l) => env.print_term(&[], &env.quote(Lvl(0), l, false)),
                    Err(e) => format!("no outcome (its kernel evaluation failed: {})", format!("{e:?}").lines().next().unwrap_or("")),
                };
                rep.mismatches.push(Mismatch { lifted: p.e.lifted.clone(), callee: p.callee.clone(), input, model: format!("the literal reading of rustc's MIR gives {what} where its panic contract says it panics"), rustc: r.as_ref().err().cloned().unwrap_or_default() });
            }
            rep.entries[p.index].literal += 1;
            rep.literal_cases += 1;
            continue;
        }
        // (a panic input where rustc returned is a mismatch of the check
        // already: there is no value of the model to compare L with)
        if c.model.as_ref().err().is_some_and(|e| e == super::PANIC_CASE) {
            continue;
        }
        let (Some(lit), Ok(comps)) = (lits.get(&p.e.lifted), r) else { continue };
        if rep.entries[p.index].literal >= LITERAL_CASES {
            continue;
        }
        // the arguments (a value the kernel cannot build, an invariant that
        // does not hold, is not an input of the function)
        let Ok(args) = p.params.iter().zip(&c.args).map(|(t, j)| conv.term(t, j)).collect::<Result<Vec<Tm>, String>>() else { continue };
        let jret = if comps.len() == 1 { comps[0].clone() } else { J::Arr(comps.clone()) };
        let input = format!("({})", c.args.iter().map(J::render).collect::<Vec<_>>().join(", "));
        let shown = if comps.len() == 1 { comps[0].render() } else { format!("[{}]", comps.iter().map(J::render).collect::<Vec<_>>().join(", ")) };
        let mut mismatch = |what: String| rep.mismatches.push(Mismatch { lifted: p.e.lifted.clone(), callee: p.callee.clone(), input: input.clone(), model: format!("the literal reading of rustc's MIR gives {what}"), rustc: shown.clone() });
        let rv = match conv.term(&p.ret, &jret) {
            Ok(t) => t,
            Err(e) => {
                mismatch(format!("a value rustc's output cannot be compared with ({e})"));
                continue;
            }
        };
        let lhs = mk::apps(lit.run.clone(), args.into_iter().map(|a| (Rel::Rel, a)).chain([(Rel::Rel, lit.fuel.clone())]));
        let rhs = mk::app(lit.some.clone(), mk::app(lit.erase.clone(), rv));
        // (an argument or output with invariant fields carries erased
        // proofs, which the kernel's closed evaluation refuses: those go
        // through the reference strategy of `sandblaster eval`, as the
        // structured reading's evaluation does)
        let eval = |t: &Tm| -> Result<V, String> {
            match env.eval_closed(t, &mut Budget { steps: STEPS }) {
                Ok(nf) => env.eval(&VEnv::default(), Lvl(0), &nf, &mut Budget { steps: STEPS }).map_err(|e| format!("{e:?}")),
                Err(_) => crate::driver::stage::eval_reference(env, t, STEPS),
            }
        };
        let (l, rr) = match (eval(&lhs), eval(&rhs)) {
            (Ok(l), Ok(rr)) => (l, rr),
            (Err(e), _) => {
                mismatch(format!("no value (its kernel evaluation failed: {})", e.lines().next().unwrap_or("")));
                continue;
            }
            (_, Err(e)) => {
                mismatch(format!("a value rustc's output, erased, cannot be compared with (evaluation failed: {})", e.lines().next().unwrap_or("")));
                continue;
            }
        };
        if !env.conv(Lvl(0), &l, &rr, &mut Budget { steps: STEPS }).unwrap_or(false) {
            let t = env.print_term(&[], &env.quote(Lvl(0), &l, false));
            mismatch(if t.len() > 600 { format!("{}..", &t[..t.floor_char_boundary(600)]) } else { t });
        }
        rep.entries[p.index].literal += 1;
        rep.literal_cases += 1;
    }
    for (f, n) in &panics {
        rep.notes.push(format!("`{f}`: its panic contract's panic region compared with rustc on {n} input(s): rustc panicked and the literal reading gave `Panic` on each"));
    }
    panics
}
