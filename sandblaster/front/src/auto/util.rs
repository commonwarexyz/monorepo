//! Small term and value helpers for the automation (DESIGN.md §5.1, §5.11):
//! de Bruijn conversions, closure instantiation, neutral inspection, and the
//! syntactic recognizers `auto` uses on normalized values.

use std::rc::Rc;

use num_bigint::BigInt;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, Idx, IndId, Lvl, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Closure, Elim, EnvEntry, EvalError, Head, Neutral, V, VEnv, Value};

/// Level of the first metavariable used by matching ([`super::ematch`]).
/// Metavariables are neutral variables far above any context depth; values
/// containing them are never quoted.
pub const META_BASE: u32 = 1 << 28;

/// The term for the variable at level `lvl` in a context of depth `depth`.
pub fn var_at(depth: u32, lvl: u32) -> Tm {
    debug_assert!(lvl < depth, "variable level {lvl} not below depth {depth}");
    Rc::new(Term::Var(Idx(depth - 1 - lvl)))
}

/// Extend an evaluation environment (the new entry is index 0).
pub fn venv_push(env: &VEnv, e: EnvEntry) -> VEnv {
    let mut v: Vec<EnvEntry> = Vec::with_capacity(env.0.len() + 1);
    v.extend(env.0.iter().cloned());
    v.push(e);
    VEnv(Rc::new(v))
}

/// Extend an evaluation environment with several entries (last = index 0).
pub fn venv_extend(env: &VEnv, es: impl IntoIterator<Item = EnvEntry>) -> VEnv {
    let mut v: Vec<EnvEntry> = env.0.as_ref().clone();
    v.extend(es);
    VEnv(Rc::new(v))
}

/// Instantiate a closure with entries.
pub fn inst(env: &Env, c: &Closure, es: Vec<EnvEntry>, depth: u32, b: &mut Budget) -> Result<V, EvalError> {
    env.eval(&venv_extend(&c.env, es), Lvl(depth), &c.body, b)
}

/// Spine argument → environment entry.
pub fn arg_entry(a: &Arg) -> EnvEntry {
    match a {
        Arg::Rel(v) => EnvEntry::Rel(v.clone()),
        Arg::Irr(c) => EnvEntry::Irr(c.clone()),
    }
}

/// Environment entry → spine argument.
pub fn entry_arg(e: &EnvEntry) -> Arg {
    match e {
        EnvEntry::Rel(v) => Arg::Rel(v.clone()),
        EnvEntry::Irr(c) => Arg::Irr(c.clone()),
    }
}

/// An irrelevant entry that denotes the term `t` evaluated in `env`.
pub fn irr_entry(env: &VEnv, t: &Tm) -> EnvEntry {
    EnvEntry::Irr(Closure { env: env.clone(), body: t.clone() })
}

pub fn clone_head(h: &Head) -> Head {
    match h {
        Head::Var(l) => Head::Var(*l),
        Head::Global { def, args } => Head::Global { def: *def, args: args.clone() },
        Head::Prim { op, args, proofs } => Head::Prim { op: *op, args: args.clone(), proofs: proofs.clone() },
        Head::Absurd { ty } => Head::Absurd { ty: ty.clone() },
        Head::Transport { ty, lhs, rhs, motive, val } => {
            Head::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), motive: motive.clone(), val: val.clone() }
        }
        Head::Axiom { ax, args } => Head::Axiom { ax: *ax, args: args.clone() },
    }
}

pub fn clone_elim(e: &Elim) -> Elim {
    match e {
        Elim::App(a) => Elim::App(a.clone()),
        Elim::Fst => Elim::Fst,
        Elim::Snd => Elim::Snd,
        Elim::Match { ind, params, motive, arms } => {
            Elim::Match { ind: *ind, params: params.clone(), motive: motive.clone(), arms: arms.clone() }
        }
    }
}

/// The neutral made of `n`'s head and its first `i` eliminators.
pub fn prefix(n: &Neutral, i: usize) -> V {
    Rc::new(Value::Neu(Neutral { head: clone_head(&n.head), spine: n.spine[..i].iter().map(clone_elim).collect() }))
}

/// The neutral variable at level `l`.
pub fn neu_var(l: u32) -> V {
    Rc::new(Value::Neu(Neutral { head: Head::Var(Lvl(l)), spine: Vec::new() }))
}

pub fn as_neu(v: &V) -> Option<&Neutral> {
    match &**v {
        Value::Neu(n) => Some(n),
        _ => None,
    }
}

/// `Eq(ty, lhs, rhs)`.
pub fn as_eq(v: &V) -> Option<(&V, &V, &V)> {
    match &**v {
        Value::Eq { ty, lhs, rhs } => Some((ty, lhs, rhs)),
        _ => None,
    }
}

/// A boolean literal.
pub fn bool_lit(bool_ind: IndId, v: &V) -> Option<bool> {
    match &**v {
        Value::Ctor { ind, ctor, .. } if *ind == bool_ind => Some(*ctor == 1),
        _ => None,
    }
}

pub fn lit(v: &V) -> Option<(Width, &BigInt)> {
    match &**v {
        Value::Lit { w, n } => Some((*w, n)),
        _ => None,
    }
}

/// A primitive application with an empty spine.
pub fn as_prim(v: &V) -> Option<(PrimOp, &[V])> {
    match &**v {
        Value::Neu(Neutral { head: Head::Prim { op, args, .. }, spine }) if spine.is_empty() => Some((*op, args)),
        _ => None,
    }
}

/// A global applied to arguments, with an empty spine.
pub fn as_global_app(v: &V) -> Option<(GlobalId, &[Arg])> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if spine.is_empty() => Some((*def, args)),
        _ => None,
    }
}

/// A variable applied to arguments (a neutral whose spine is applications
/// only): its level and the arguments.
pub fn as_var_app(v: &V) -> Option<(u32, Vec<Arg>)> {
    match &**v {
        Value::Neu(Neutral { head: Head::Var(l), spine }) if !spine.is_empty() => {
            let mut args = Vec::with_capacity(spine.len());
            for e in spine {
                let sandblaster_kernel::value::Elim::App(a) = e else { return None };
                args.push(match a {
                    Arg::Rel(x) => Arg::Rel(x.clone()),
                    Arg::Irr(c) => Arg::Irr(c.clone()),
                });
            }
            Some((l.0, args))
        }
        _ => None,
    }
}

/// The variable level of a bare neutral variable.
pub fn as_var(v: &V) -> Option<u32> {
    match &**v {
        Value::Neu(Neutral { head: Head::Var(l), spine }) if spine.is_empty() => Some(l.0),
        _ => None,
    }
}

/// Comparison primitives (`eq ne lt le gt ge` at any width), with their
/// width.
pub fn cmp_width(op: PrimOp) -> Option<Width> {
    match op {
        PrimOp::Eq(w) | PrimOp::Ne(w) | PrimOp::Lt(w) | PrimOp::Le(w) | PrimOp::Gt(w) | PrimOp::Ge(w) => Some(w),
        _ => None,
    }
}

/// Is the value in canonical (constructor) form at its head?
pub fn is_canonical(v: &V) -> bool {
    matches!(&**v, Value::Lit { .. } | Value::Ctor { .. } | Value::Pair { .. } | Value::Refl { .. })
}

/// A multiplicative hasher for the pointer and small-integer keys of the
/// traversal memos (never attacker-chosen; the default SipHash dominated
/// the walks). Deterministic, and the memos are never iterated.
#[derive(Default, Clone, Copy)]
pub struct FxHasher(u64);

impl std::hash::Hasher for FxHasher {
    fn finish(&self) -> u64 {
        // the product's high bits are the well-mixed ones, and the table
        // indexes by the low bits (aligned addresses end in zero bits)
        self.0.rotate_left(26)
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.write_u64(*b as u64);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    fn write_u32(&mut self, n: u32) {
        self.write_u64(n as u64);
    }
    fn write_u8(&mut self, n: u8) {
        self.write_u64(n as u64);
    }
    fn write_usize(&mut self, n: usize) {
        self.write_u64(n as u64);
    }
}

/// A `HashMap` with [`FxHasher`].
pub type FxMap<K, V> = std::collections::HashMap<K, V, std::hash::BuildHasherDefault<FxHasher>>;
/// A `HashSet` with [`FxHasher`].
pub type FxSet<K> = std::collections::HashSet<K, std::hash::BuildHasherDefault<FxHasher>>;

/// Does the value contain a metavariable (a variable at level ≥
/// [`META_BASE`]), including in the environments of its closures?
pub fn has_meta(v: &V) -> bool {
    let mut found = false;
    for_each_var(v, 0, &mut |l| {
        if l >= META_BASE {
            found = true;
        }
    });
    found
}

/// The variable levels occurring in a value, including in the environments
/// of its closures (bounded depth). Each value node and closure environment
/// is visited once (values are DAGs).
pub fn for_each_var(v: &V, n: u32, f: &mut dyn FnMut(u32)) {
    let mut seen: FxSet<usize> = FxSet::default();
    for_each_var_in(v, n, f, &mut seen);
}

fn for_each_var_in(v: &V, n: u32, f: &mut dyn FnMut(u32), seen: &mut FxSet<usize>) {
    if n > 32 {
        return;
    }
    let mut clos: Vec<Closure> = Vec::new();
    walk(v, &mut |x| {
        match &**x {
            Value::Neu(Neutral { head, spine }) => {
                if let Head::Var(l) = head {
                    f(l.0);
                }
                for e in spine {
                    if let Elim::Match { motive, arms, .. } = e {
                        clos.push(motive.clone());
                        clos.extend(arms.iter().cloned());
                    }
                }
            }
            Value::Pi { cod: c, .. } | Value::Lam { body: c, .. } | Value::Sigma { snd: c, .. } => clos.push(c.clone()),
            _ => {}
        }
        true
    });
    for c in clos {
        closure_vars(&c, n, f, seen);
    }
}

fn closure_vars(c: &Closure, n: u32, f: &mut dyn FnMut(u32), seen: &mut FxSet<usize>) {
    if !seen.insert(Rc::as_ptr(&c.env.0) as *const () as usize) {
        return;
    }
    super::meter::spend(c.env.0.len() as u64);
    for e in c.env.0.iter() {
        match e {
            EnvEntry::Rel(v) => {
                if seen.insert(Rc::as_ptr(v) as *const () as usize) {
                    for_each_var_in(v, n + 1, f, seen)
                }
            }
            EnvEntry::Irr(c2) => closure_vars(c2, n + 1, f, seen),
        }
    }
}

/// Pre-order walk over the top-level value DAG (closures are not entered);
/// every node is visited once. `f` returns whether to descend into the
/// node's children.
pub fn walk(v: &V, f: &mut dyn FnMut(&V) -> bool) {
    let mut seen: FxSet<usize> = FxSet::default();
    walk_in(v, f, &mut seen);
}

fn walk_in(v: &V, f: &mut dyn FnMut(&V) -> bool, seen: &mut FxSet<usize>) {
    if !seen.insert(Rc::as_ptr(v) as *const () as usize) {
        return;
    }
    super::meter::spend(1);
    if !f(v) {
        return;
    }
    let mut walk = |x: &V, f: &mut dyn FnMut(&V) -> bool| walk_in(x, f, seen);
    let rel = |a: &Arg, f: &mut dyn FnMut(&V) -> bool, walk: &mut dyn FnMut(&V, &mut dyn FnMut(&V) -> bool)| {
        if let Arg::Rel(x) = a {
            walk(x, f);
        }
    };
    match &**v {
        Value::Sort(_) | Value::IntTy(_) | Value::Lit { .. } => {}
        Value::Pi { dom, .. } | Value::Lam { dom, .. } => walk(dom, f),
        Value::Sigma { fst, .. } => walk(fst, f),
        Value::Pair { fst, snd } => {
            walk(fst, f);
            rel(snd, f, &mut walk);
        }
        Value::Eq { ty, lhs, rhs } => {
            walk(ty, f);
            walk(lhs, f);
            walk(rhs, f);
        }
        Value::Refl { ty, val } => {
            walk(ty, f);
            walk(val, f);
        }
        Value::Ind { params, .. } => params.iter().for_each(|p| walk(p, f)),
        Value::Ctor { params, args, .. } => {
            params.iter().for_each(|p| walk(p, f));
            args.iter().for_each(|a| rel(a, f, &mut walk));
        }
        Value::Neu(n) => {
            match &n.head {
                Head::Var(_) => {}
                Head::Global { args, .. } | Head::Axiom { args, .. } => args.iter().for_each(|a| rel(a, f, &mut walk)),
                Head::Prim { args, .. } => args.iter().for_each(|a| walk(a, f)),
                Head::Absurd { ty } => walk(ty, f),
                Head::Transport { ty, lhs, rhs, val, .. } => {
                    walk(ty, f);
                    walk(lhs, f);
                    walk(rhs, f);
                    walk(val, f);
                }
            }
            for e in &n.spine {
                match e {
                    Elim::App(a) => rel(a, f, &mut walk),
                    Elim::Match { params, .. } => params.iter().for_each(|p| walk(p, f)),
                    Elim::Fst | Elim::Snd => {}
                }
            }
        }
    }
}

/// Does `Var(idx)` (relative to `t`) occur in `t`? (Linear in the term
/// graph; charged to the goal, [`super::meter`].)
pub fn occurs(t: &Tm, idx: u32) -> bool {
    crate::elab::tm::any_node_depth(t, &mut |n, depth| matches!(n, Term::Var(Idx(i)) if *i == idx + depth))
}

/// Shift free variables of `t` by `d`.
pub fn shift(t: &Tm, d: i64) -> Tm {
    shift_from(t, d, 0)
}

/// Shift free variables `≥ cutoff` of `t` by `d` (linear in the term graph;
/// every node visited is charged to the goal, [`super::meter`]).
pub fn shift_from(t: &Tm, d: i64, cutoff: u32) -> Tm {
    if d == 0 {
        return t.clone();
    }
    crate::elab::tm::map_post(t, 0, &mut |n, depth| {
        Some(match &*n {
            Term::Var(Idx(i)) if *i >= depth + cutoff => Rc::new(Term::Var(Idx((*i as i64 + d) as u32))),
            _ => n,
        })
    })
    .expect("shift_from")
}

/// An application spine `f a₁ … aₙ` with explicit relevances.
pub fn apps(f: Tm, args: impl IntoIterator<Item = (Rel, Tm)>) -> Tm {
    sandblaster_kernel::util::mk::apps(f, args)
}

/// The number of leading Π binders of a type value whose final codomain is
/// the sort `Type` (a predicate), or `None`.
pub fn predicate_arity(env: &Env, ty: &V, depth: u32, b: &mut Budget) -> Option<u32> {
    let mut t = ty.clone();
    let mut n = 0u32;
    loop {
        match &*t.clone() {
            Value::Pi { rel, dom, cod, .. } => {
                let x = env.fresh_var(Lvl(depth + n), *rel, dom);
                t = inst(env, cod, vec![x], depth + n + 1, b).ok()?;
                n += 1;
            }
            Value::Sort(sandblaster_kernel::term::Sort::Type) => return Some(n),
            _ => return None,
        }
    }
}

/// Rebuild a term top-down: `f(node, k)` may replace a node (`k` = binders
/// crossed); otherwise its children are rebuilt. `f` must be a function of
/// its arguments: shared subterms (the same `Rc` at the same binder depth)
/// are visited once and stay shared in the result, so the cost is linear in
/// the size of the term *graph* (terms built by substitution and quoting
/// share heavily; as trees they can be exponentially larger).
pub fn map_term(t: &Tm, k: u32, f: &mut dyn FnMut(&Tm, u32) -> Option<Tm>) -> Tm {
    let mut memo: FxMap<(*const Term, u32), Tm> = FxMap::default();
    map_term_memo(t, k, f, &mut memo)
}

fn map_term_memo(t: &Tm, k: u32, f: &mut dyn FnMut(&Tm, u32) -> Option<Tm>, memo: &mut FxMap<(*const Term, u32), Tm>) -> Tm {
    let key = (Rc::as_ptr(t), k);
    if let Some(r) = memo.get(&key) {
        return r.clone();
    }
    super::meter::spend(1);
    let r = map_term_node(t, k, f, memo);
    memo.insert(key, r.clone());
    r
}

fn map_term_node(t: &Tm, k: u32, f: &mut dyn FnMut(&Tm, u32) -> Option<Tm>, memo: &mut FxMap<(*const Term, u32), Tm>) -> Tm {
    use sandblaster_kernel::term::Arm;
    if let Some(r) = f(t, k) {
        return r;
    }
    let mut g = |x: &Tm, b: u32| map_term_memo(x, k + b, f, memo);
    let node = match &**t {
        Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => return t.clone(),
        Term::Pi { name, rel, dom, cod } => Term::Pi { name: name.clone(), rel: *rel, dom: g(dom, 0), cod: g(cod, 1) },
        Term::Lam { name, rel, dom, body } => Term::Lam { name: name.clone(), rel: *rel, dom: g(dom, 0), body: g(body, 1) },
        Term::App { rel, fun, arg } => Term::App { rel: *rel, fun: g(fun, 0), arg: g(arg, 0) },
        Term::Let { name, rel, ty, val, body } => {
            Term::Let { name: name.clone(), rel: *rel, ty: g(ty, 0), val: g(val, 0), body: g(body, 1) }
        }
        Term::Sigma { name, snd_rel, fst, snd } => Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: g(fst, 0), snd: g(snd, 1) },
        Term::Pair { ty, fst, snd } => Term::Pair { ty: g(ty, 0), fst: g(fst, 0), snd: g(snd, 0) },
        Term::Fst(p) => Term::Fst(g(p, 0)),
        Term::Snd(p) => Term::Snd(g(p, 0)),
        Term::Eq { ty, lhs, rhs } => Term::Eq { ty: g(ty, 0), lhs: g(lhs, 0), rhs: g(rhs, 0) },
        Term::Refl { ty, val } => Term::Refl { ty: g(ty, 0), val: g(val, 0) },
        Term::Transport { ty, lhs, rhs, eq, motive, val } => {
            Term::Transport { ty: g(ty, 0), lhs: g(lhs, 0), rhs: g(rhs, 0), eq: g(eq, 0), motive: g(motive, 1), val: g(val, 0) }
        }
        Term::Ind { ind, params } => Term::Ind { ind: *ind, params: params.iter().map(|p| g(p, 0)).collect() },
        Term::Ctor { ind, ctor, params, args } => Term::Ctor {
            ind: *ind,
            ctor: *ctor,
            params: params.iter().map(|p| g(p, 0)).collect(),
            args: args.iter().map(|p| g(p, 0)).collect(),
        },
        Term::Match { ind, params, scrut, motive, arms } => Term::Match {
            ind: *ind,
            params: params.iter().map(|p| g(p, 0)).collect(),
            scrut: g(scrut, 0),
            motive: g(motive, 1),
            arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: g(&a.body, a.names.len() as u32) }).collect(),
        },
        Term::Prim { op, args, proofs } => {
            Term::Prim { op: *op, args: args.iter().map(|p| g(p, 0)).collect(), proofs: proofs.iter().map(|p| g(p, 0)).collect() }
        }
        Term::Rec { args, proof } => Term::Rec { args: args.iter().map(|p| g(p, 0)).collect(), proof: proof.as_ref().map(|p| g(p, 0)) },
        Term::Delta { def, args } => Term::Delta { def: *def, args: args.iter().map(|p| g(p, 0)).collect() },
        Term::Unfold { def, args, to_body, val } => {
            Term::Unfold { def: *def, args: args.iter().map(|p| g(p, 0)).collect(), to_body: *to_body, val: g(val, 0) }
        }
        Term::Linarith { hyps, goal, cert } => {
            Term::Linarith { hyps: hyps.iter().map(|(p, s)| (g(p, 0), g(s, 0))).collect(), goal: g(goal, 0), cert: cert.clone() }
        }
        Term::BvRefl { ty, lhs, rhs } => Term::BvRefl { ty: g(ty, 0), lhs: g(lhs, 0), rhs: g(rhs, 0) },
        Term::Absurd { ty, proof } => Term::Absurd { ty: g(ty, 0), proof: g(proof, 0) },
        Term::Axiom { ax, args } => Term::Axiom { ax: *ax, args: args.iter().map(|p| g(p, 0)).collect() },
    };
    Rc::new(node)
}

/// Kernel-friendly form of a quoted term. The kernel quotes proof closures
/// by substitution, which puts untyped value pairs (`pair(_, ..)`, an
/// `Erased` Σ type) where a proof mentions a slice or array value — e.g.
/// `fst(s)` or `slice::ok_bound T s` with `s := pair(_, n, pair(_, l, p))`.
/// Such terms cannot be re-checked (motives of rewrites and case splits);
/// their reduced/typed forms can:
///
/// * projections of pairs are reduced (`fst(pair(T, a, b)) ↦ a`, `snd(..) ↦
///   b`, definitional equalities);
/// * an untyped pair passed to a global at a parameter of type `Slice T` is
///   rebuilt as `slice::mk T n l p`, at `Array T N` it gets that type, at a
///   literal Σ type it gets the Σ (and its second component, if an untyped
///   pair, the instantiated second type).
pub fn kernel_friendly(env: &Env, t: &Tm) -> Tm {
    let slice_mk = env.lookup_global("slice::mk");
    let (slice_g, array_g) = (env.lookup_global("Slice"), env.lookup_global("Array"));
    crate::elab::tm::map_post(t, 0, &mut |n, _| {
        Some(match &*n {
            Term::Fst(p) => match &**p {
                Term::Pair { fst, .. } => fst.clone(),
                _ => n,
            },
            Term::Snd(p) => match &**p {
                Term::Pair { snd, .. } => snd.clone(),
                _ => n,
            },
            Term::Ctor { ind, ctor, params, args } if args.iter().any(is_untyped_pair) => {
                // field types from the declaration, instantiated with the
                // parameters and the earlier fields
                let Some(decl) = env.inductive_decl(*ind) else { return Some(n) };
                let Some(c) = decl.ctors.get(*ctor as usize) else { return Some(n) };
                let mut done: Vec<Tm> = params.clone();
                let mut out = Vec::with_capacity(args.len());
                for (i, a) in args.iter().enumerate() {
                    let Some((_, _, fty)) = c.fields.get(i) else { return Some(n) };
                    let fty_i = crate::elab::tm::subst_closed(fty, &done);
                    let a2 = match &**a {
                        Term::Pair { fst, snd, .. } if is_untyped_pair(a) => type_pair(&fty_i, fst, snd, slice_mk, slice_g, array_g).unwrap_or_else(|| a.clone()),
                        _ => a.clone(),
                    };
                    done.push(a2.clone());
                    out.push(a2);
                }
                Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: out })
            }
            Term::Eq { ty, lhs, rhs } if is_untyped_pair(lhs) || is_untyped_pair(rhs) => {
                let fix = |x: &Tm| match &**x {
                    Term::Pair { fst, snd, .. } if is_untyped_pair(x) => type_pair(ty, fst, snd, slice_mk, slice_g, array_g).unwrap_or_else(|| x.clone()),
                    _ => x.clone(),
                };
                Rc::new(Term::Eq { ty: ty.clone(), lhs: fix(lhs), rhs: fix(rhs) })
            }
            Term::Refl { ty, val } if is_untyped_pair(val) => match &**val {
                Term::Pair { fst, snd, .. } => Rc::new(Term::Refl { ty: ty.clone(), val: type_pair(ty, fst, snd, slice_mk, slice_g, array_g).unwrap_or_else(|| val.clone()) }),
                _ => n,
            },
            Term::App { .. } => {
                let (h, args) = crate::elab::items::spine(&n);
                let Term::Global(g) = &*h else { return Some(n) };
                if !args.iter().any(|a| matches!(&**a, Term::Pair { ty, .. } if matches!(&**ty, Term::Erased))) {
                    return Some(n);
                }
                let Some(mut ty) = env.global_type(*g) else { return Some(n) };
                let mut out: Vec<(Rel, Tm)> = Vec::with_capacity(args.len());
                let mut done: Vec<Tm> = Vec::new();
                for a in &args {
                    let Term::Pi { rel, dom, cod, .. } = &*ty.clone() else { return Some(n) };
                    let dom_i = crate::elab::tm::subst_closed(dom, &done);
                    let a2 = match &**a {
                        Term::Pair { ty: pty, fst, snd } if matches!(&**pty, Term::Erased) => type_pair(&dom_i, fst, snd, slice_mk, slice_g, array_g).unwrap_or_else(|| a.clone()),
                        _ => a.clone(),
                    };
                    out.push((*rel, a2.clone()));
                    done.push(a2);
                    ty = cod.clone();
                }
                mk::apps(h, out)
            }
            _ => n,
        })
    })
    .unwrap_or_else(|| t.clone())
}

fn is_untyped_pair(t: &Tm) -> bool {
    matches!(&**t, Term::Pair { ty, .. } if matches!(&**ty, Term::Erased))
}

/// An untyped pair `(a, b)` at the expected type `ty` (see
/// [`kernel_friendly`]).
fn type_pair(ty: &Tm, a: &Tm, b: &Tm, slice_mk: Option<GlobalId>, slice_g: Option<GlobalId>, array_g: Option<GlobalId>) -> Option<Tm> {
    match &**ty {
        Term::Sigma { snd: sty, .. } => {
            let b2 = match &**b {
                Term::Pair { ty: bt, fst, snd } if matches!(&**bt, Term::Erased) => {
                    let inner = subst0(sty, a);
                    type_pair(&inner, fst, snd, slice_mk, slice_g, array_g).unwrap_or_else(|| b.clone())
                }
                _ => b.clone(),
            };
            Some(Rc::new(Term::Pair { ty: ty.clone(), fst: a.clone(), snd: b2 }))
        }
        Term::App { .. } => {
            let (h, targs) = crate::elab::items::spine(ty);
            let Term::Global(g) = &*h else { return None };
            if Some(*g) == slice_g && targs.len() == 1 {
                let Term::Pair { fst: l, snd: p, .. } = &**b else { return None };
                Some(mk::apps(mk::global(slice_mk?), [(Rel::Rel, targs[0].clone()), (Rel::Rel, a.clone()), (Rel::Rel, l.clone()), (Rel::Irr, p.clone())]))
            } else if Some(*g) == array_g && targs.len() == 2 {
                Some(Rc::new(Term::Pair { ty: ty.clone(), fst: a.clone(), snd: b.clone() }))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `body[0 := arg]`: instantiate the innermost binder of `body` (a term
/// under one binder) with `arg` (a term in the enclosing context).
pub fn subst0(body: &Tm, arg: &Tm) -> Tm {
    map_term(body, 0, &mut |t, k| match &**t {
        Term::Var(Idx(i)) if *i == k => Some(shift(arg, k as i64)),
        Term::Var(Idx(i)) if *i > k => Some(Rc::new(Term::Var(Idx(i - 1)))),
        _ => None,
    })
}

/// Fold kernel-built array eta expansions in a quoted term back to their
/// variable (DESIGN.md §5.9): the kernel introduces a variable `x : Array
/// T N` (literal `N`) as `([index(T, fst x, 0), .., index(T, fst x, N-1)],
/// snd x)`, and read-back returns the whole pair as `x` but a projected
/// list as its `N` elements. `fst(x)` is convertible with that list
/// wherever `x` is eta-expanded, and it is also what conversion under
/// binders that do not eta-expand sees, so folding makes quoted terms both
/// smaller and robust. A chain is folded only when it has exactly `N`
/// elements `0..N-1` of the same `x` (read from the kernel's bound proof,
/// `transport(Int, N, len(fst x), ..)`).
pub fn fold_array_eta(t: &Tm, index: GlobalId, list: IndId) -> Tm {
    map_term(t, 0, &mut |x, _| eta_list_var(x, index, list).map(|v| Rc::new(Term::Fst(v))))
}

/// The variable term `x` if `t` is the full eta list of `x`.
fn eta_list_var(t: &Tm, index: GlobalId, list: IndId) -> Option<Tm> {
    let mut cur = t;
    let mut k = 0u64;
    let mut var: Option<Tm> = None;
    let mut len: Option<u64> = None;
    loop {
        match &**cur {
            Term::Ctor { ind, args, .. } if *ind == list && args.is_empty() => break,
            Term::Ctor { ind, args, .. } if *ind == list && args.len() == 2 => {
                let mut a = Vec::new();
                let mut h = &args[0];
                while let Term::App { rel, fun, arg } = &**h {
                    a.push((*rel, arg));
                    h = fun;
                }
                a.reverse();
                if !matches!(&**h, Term::Global(g) if *g == index) || a.len() != 5 {
                    return None;
                }
                let Term::Fst(xv) = &**a[1].1 else { return None };
                if !matches!(&**xv, Term::Var(_))
                    || var.as_ref().is_some_and(|v| !matches!((&**v, &**xv), (Term::Var(p), Term::Var(q)) if p == q))
                {
                    return None;
                }
                let Term::Lit { w: Width::Int, n } = &**a[2].1 else { return None };
                if u64::try_from(n.clone()).ok() != Some(k) {
                    return None;
                }
                let Term::Transport { lhs, .. } = &**a[4].1 else { return None };
                let Term::Lit { w: Width::Int, n: nn } = &**lhs else { return None };
                let nn = u64::try_from(nn.clone()).ok()?;
                if len.is_some_and(|l| l != nn) {
                    return None;
                }
                len = Some(nn);
                var = Some(xv.clone());
                k += 1;
                cur = &args[1];
            }
            _ => return None,
        }
    }
    if k == 0 || len != Some(k) {
        return None;
    }
    var
}
