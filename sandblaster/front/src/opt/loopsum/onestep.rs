//! One iteration on symbolic state (optimizer design §7.1).
//!
//! The loop head `h(s̄)` (a tail-recursive user function; the recursion is
//! its only self-reference and sits in tail position) is unfolded once on a
//! fully symbolic state: its parameters are fresh variables and its
//! `requires` fresh binders (facts), exactly as the driver's root
//! (`drive::root`). The body's stuck boolean matches at the head are split
//! (a path per outcome), and each path ends either in `h(τ(s̄))` — the next
//! state, whose arguments may contain in-place selects (`found`'s update) —
//! or in an exit value. This is SYMPLE's set of guarded transformers
//! `(φ_π, τ_π)`.
//!
//! The values live in the root context (de Bruijn levels: the parameters,
//! then the `requires` binders); the guards are the path's scrutinees with
//! the constructor taken.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Rel};
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, V, Value};

use crate::auto::state::St;
use crate::opt::drive::step::{Eval, HeadKind, head_of};

/// How one path of an iteration ends.
#[derive(Clone, Debug)]
pub enum End {
    /// The recursive call with these arguments (relevant and irrelevant).
    Continue(Vec<Arg>),
    /// An exit value.
    Exit(V),
}

/// One guarded path of an iteration.
#[derive(Clone, Debug)]
pub struct Path {
    /// The scrutinees split on, with the constructor taken (`true` = 1).
    pub guards: Vec<(V, bool)>,
    pub end: End,
}

/// The one-iteration analysis of a loop head.
pub struct OneStep {
    pub def: GlobalId,
    /// The root state (parameters and `requires` binders, fresh).
    pub root: St,
    /// Number of relevant parameters (the leading binders; `requires`
    /// binders follow).
    pub nparams: u32,
    /// The telescope's relevance per binder.
    pub rels: Vec<Rel>,
    pub paths: Vec<Path>,
    pub bool_ind: IndId,
    /// Kernel steps used.
    pub steps: u64,
}

/// At most this many paths per iteration.
pub const MAX_PATHS: usize = 64;

/// Whether `g` occurs in `v` (a recursive call not in tail position, or in
/// a guard).
pub fn mentions(v: &V, g: GlobalId) -> bool {
    let mut found = false;
    crate::auto::util::walk(v, &mut |x| {
        if found {
            return false;
        }
        if let Value::Neu(n) = &**x
            && let Head::Global { def, .. } = &n.head
            && *def == g
        {
            found = true;
            return false;
        }
        true
    });
    found
}

/// One iteration of the loop head `def` (see the module docs).
pub fn one_step(env: &Env, def: GlobalId, budget: u64) -> Result<OneStep, String> {
    let (root, _app, nparams) = crate::opt::drive::root(env, def)?;
    let tele = crate::opt::symex::telescope(env, def).ok_or("no telescope")?;
    let rels: Vec<Rel> = tele.binders.iter().map(|(_, r, _)| *r).collect();
    let opaque = move |g: GlobalId| g == def;
    let ev = Eval { env, opaque: &opaque };
    let mut b = Budget { steps: budget };
    let depth = root.depth();
    let args: Vec<Arg> = root.venv.0.iter().map(crate::auto::util::entry_arg).collect();
    let body = ev.unfold(def, &args, depth, &mut b)?;
    let bool_ind = env.bool_ind();
    let mut paths = Vec::new();
    let mut work: Vec<(Vec<(V, bool)>, V)> = vec![(Vec::new(), body)];
    while let Some((guards, v)) = work.pop() {
        if paths.len() + work.len() > MAX_PATHS {
            return Err(format!("more than {MAX_PATHS} paths in one iteration"));
        }
        match head_of(&v) {
            HeadKind::Folded { def: d, args, elims, .. } if d == def => {
                if !elims.is_empty() {
                    return Err("the recursive call is not in tail position".into());
                }
                for a in args {
                    if let Arg::Rel(x) = a
                        && mentions(x, def)
                    {
                        return Err("a nested recursive call".into());
                    }
                }
                paths.push(Path { guards, end: End::Continue(args.to_vec()) });
            }
            HeadKind::Stuck { scrut, ind, arms, rest, .. } if ind == bool_ind => {
                if mentions(&scrut, def) {
                    return Err("a guard depends on a recursive call".into());
                }
                let rest: Vec<Elim> = rest.iter().map(crate::auto::util::clone_elim).collect();
                for k in [0u32, 1] {
                    let arm = arms.get(k as usize).ok_or("a boolean match without both arms")?;
                    let w = ev.inst(arm, vec![], depth, &mut b).and_then(|w| ev.elims(w, &rest, depth, &mut b))?;
                    let mut g = guards.clone();
                    g.push((scrut.clone(), k == 1));
                    work.push((g, w));
                }
            }
            HeadKind::Stuck { .. } => return Err("a match on a non-boolean scrutinee in the loop body".into()),
            _ => {
                if mentions(&v, def) {
                    return Err("a recursive call not in tail position".into());
                }
                paths.push(Path { guards, end: End::Exit(v) });
            }
        }
    }
    // deterministic order: by the guard outcomes
    paths.sort_by(|a, b| {
        let ka: Vec<bool> = a.guards.iter().map(|g| g.1).collect();
        let kb: Vec<bool> = b.guards.iter().map(|g| g.1).collect();
        ka.cmp(&kb)
    });
    Ok(OneStep { def, root, nparams, rels, paths, bool_ind, steps: budget - b.steps })
}

impl OneStep {
    /// The relevant arguments of a continue path (the next state), by
    /// parameter index.
    pub fn next_state(args: &[Arg]) -> Vec<V> {
        args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect()
    }

    /// The value of parameter `i` in the root context.
    pub fn param(&self, i: u32) -> Option<V> {
        match self.root.venv.0.get(i as usize)? {
            EnvEntry::Rel(v) => Some(v.clone()),
            EnvEntry::Irr(_) => None,
        }
    }
}
