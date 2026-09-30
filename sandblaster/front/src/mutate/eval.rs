//! Distinguishing inputs (DESIGN.md §15.9 item 3): candidate inputs by HIR
//! type (values from the crate's examples, boundary values, the constants
//! of the mutated code ±1, deterministic pseudo-random values), their
//! closed kernel terms, evaluation of a function on them, the shrinking
//! candidates of a found input ([`simpler`]), and printing — inputs in
//! source syntax (named-field structs as `S { f: v }`; long byte sequences
//! and word arrays in hex), outputs with the positions where two differ
//! ([`Evaluator::differences`]).
//!
//! Evaluation uses the kernel's closed evaluator `Env::eval_closed` (TCB)
//! whenever the application is a closed, well-typed term; a function with
//! `Irr` binders (a `requires`, a ghost parameter) is applied to erased
//! proofs, which the type checker of `eval_closed` rejects, so it is
//! evaluated by the untrusted reference strategy instead (transparent
//! evaluation plus completion of stuck recursive applications, as the
//! driver's `sandblaster eval`). Each witness says which evaluator decided
//! it. Everything here is untrusted and diagnostic (§15.9): a witness is a
//! reason for an error, never a reason for anything to pass.

use std::collections::{BTreeSet, HashMap};

use num_bigint::BigInt;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, VEnv, Value, V};

use crate::hir::*;

/// A candidate input value (first-order data, by HIR type).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Val {
    Bool(bool),
    Int(BigInt),
    Tuple(Vec<Val>),
    /// Arrays, slices and `Seq`s.
    Seq(Vec<Val>),
    Opt(Option<Box<Val>>),
    Adt { ctor: u32, fields: Vec<Val> },
}

/// A deterministic pseudo-random generator (splitmix64).
pub struct Rng(pub u64);

impl Rng {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// FNV-1a of a string (seeds).
pub fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// What candidate generation knows about the code under test.
pub struct Hints {
    /// Integer constants of the mutated code (each also ±1 is tried).
    pub consts: BTreeSet<u128>,
    pub rng: Rng,
}

fn max_of(t: &Ty) -> Option<BigInt> {
    match t {
        Ty::Uint(u) => Some(BigInt::from(u.max_value())),
        _ => None,
    }
}

fn int_pool(t: &Ty, h: &mut Hints) -> Vec<Val> {
    let max = max_of(t);
    let mut base: Vec<BigInt> = [0u128, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 100, 127, 128, 255, 256, 1000, 65535, 65536, 1 << 31, (1 << 32) - 1, 1 << 32].iter().map(|x| BigInt::from(*x)).collect();
    if let Some(m) = &max {
        base.push(m - 1);
        base.push(m.clone());
    }
    if *t == Ty::Int {
        base.push(BigInt::from(-1));
        base.push(BigInt::from(-2));
    }
    for c in &h.consts {
        let c = BigInt::from(*c);
        for d in [-1i32, 0, 1] {
            base.push(&c + d);
        }
    }
    let bits = match t {
        Ty::Uint(u) => u.bits(),
        _ => 16,
    };
    for _ in 0..4 {
        let r = h.rng.next_u64() as u128 & if bits >= 64 { u64::MAX as u128 } else { (1u128 << bits) - 1 };
        base.push(BigInt::from(r));
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for x in base {
        let ok = x >= BigInt::from(0) || *t == Ty::Int;
        let ok = ok && max.as_ref().is_none_or(|m| &x <= m);
        if ok && seen.insert(x.clone()) {
            out.push(Val::Int(x));
        }
    }
    out
}

/// Candidate values of a type (bounded, deterministic; see the module
/// docs). `depth` bounds recursive types.
pub fn pool(krate: &Crate, t: &Ty, h: &mut Hints, depth: u32) -> Vec<Val> {
    if depth > 3 {
        return vec![];
    }
    match t {
        Ty::Ref(x) => pool(krate, x, h, depth),
        Ty::Bool => vec![Val::Bool(false), Val::Bool(true)],
        Ty::Uint(_) | Ty::Int | Ty::Nat => int_pool(t, h),
        Ty::Tuple(ts) if ts.is_empty() => vec![Val::Tuple(vec![])],
        Ty::Tuple(ts) => {
            let ps: Vec<Vec<Val>> = ts.iter().map(|x| pool(krate, x, h, depth + 1)).collect();
            if ps.iter().any(|p| p.is_empty()) {
                return vec![];
            }
            let mut out = Vec::new();
            let n = ps.iter().map(|p| p.len()).max().unwrap_or(0).min(12);
            for i in 0..n {
                out.push(Val::Tuple(ps.iter().map(|p| p[i % p.len()].clone()).collect()));
            }
            for (j, p) in ps.iter().enumerate() {
                for v in p.iter().take(6) {
                    let mut t: Vec<Val> = ps.iter().map(|q| q[0].clone()).collect();
                    t[j] = v.clone();
                    out.push(Val::Tuple(t));
                }
            }
            dedup(out)
        }
        Ty::Array(e, n) => seq_pool(krate, e, Some(*n), h, depth),
        Ty::Slice(e) | Ty::Seq(e) => seq_pool(krate, e, None, h, depth),
        Ty::Option(e) => {
            let mut out = vec![Val::Opt(None)];
            for v in pool(krate, e, h, depth + 1).into_iter().take(8) {
                out.push(Val::Opt(Some(Box::new(v))));
            }
            out
        }
        Ty::Adt(id, args) => match &krate.item(*id).kind {
            ItemKind::Struct(s) if s.invariant.is_none() => {
                let ftys: Vec<Ty> = s.fields.iter().map(|f| f.ty.subst(args)).collect();
                fields_pool(krate, &ftys, h, depth).into_iter().map(|fields| Val::Adt { ctor: 0, fields }).collect()
            }
            ItemKind::Enum(en) => {
                let mut out = Vec::new();
                for (vi, v) in en.variants.iter().enumerate() {
                    let ftys: Vec<Ty> = v.fields.iter().map(|f| f.ty.subst(args)).collect();
                    for fields in fields_pool(krate, &ftys, h, depth).into_iter().take(6) {
                        out.push(Val::Adt { ctor: vi as u32, fields });
                    }
                }
                out
            }
            _ => vec![],
        },
        _ => vec![],
    }
}

fn fields_pool(krate: &Crate, ftys: &[Ty], h: &mut Hints, depth: u32) -> Vec<Vec<Val>> {
    if ftys.is_empty() {
        return vec![vec![]];
    }
    let ps: Vec<Vec<Val>> = ftys.iter().map(|x| pool(krate, x, h, depth + 1)).collect();
    if ps.iter().any(|p| p.is_empty()) {
        return vec![];
    }
    let mut out = Vec::new();
    for i in 0..ps.iter().map(|p| p.len()).max().unwrap_or(0).min(8) {
        out.push(ps.iter().map(|p| p[i % p.len()].clone()).collect());
    }
    for (j, p) in ps.iter().enumerate() {
        for v in p.iter().take(4) {
            let mut t: Vec<Val> = ps.iter().map(|q| q[0].clone()).collect();
            t[j] = v.clone();
            out.push(t);
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|x| seen.insert(x.clone()));
    out
}

fn seq_pool(krate: &Crate, e: &Ty, fixed: Option<u64>, h: &mut Hints, depth: u32) -> Vec<Val> {
    let ep = pool(krate, e, h, depth + 1);
    if ep.is_empty() {
        return if fixed == Some(0) { vec![Val::Seq(vec![])] } else { vec![] };
    }
    let zero = ep[0].clone();
    let lens: Vec<usize> = match fixed {
        Some(n) => vec![n as usize],
        None => {
            let mut l: BTreeSet<usize> = [0usize, 1, 2, 3, 4, 5, 8, 9, 16, 32, 33, 64, 65].into_iter().collect();
            for c in &h.consts {
                if *c <= 130 {
                    for d in [-1i64, 0, 1] {
                        let x = *c as i64 + d;
                        if x >= 0 {
                            l.insert(x as usize);
                        }
                    }
                }
            }
            l.into_iter().collect()
        }
    };
    let mut out = Vec::new();
    for &n in &lens {
        if n > 4096 {
            continue;
        }
        // all the same value
        for v in ep.iter().take(if n <= 2 { 8 } else { 3 }) {
            out.push(Val::Seq(vec![v.clone(); n]));
        }
        // one element different
        if n > 0 {
            for &pos in [0, n - 1, 1.min(n - 1)].iter().collect::<BTreeSet<_>>() {
                for v in ep.iter().skip(1).take(if n <= 4 { 8 } else { 2 }) {
                    let mut xs = vec![zero.clone(); n];
                    xs[pos] = v.clone();
                    out.push(Val::Seq(xs));
                }
            }
        }
        // incrementing and random
        if n > 0 {
            out.push(Val::Seq((0..n).map(|i| ep[i % ep.len()].clone()).collect()));
            let r: Vec<Val> = (0..n).map(|_| ep[h.rng.below(ep.len() as u64) as usize].clone()).collect();
            out.push(Val::Seq(r));
        }
        // short sequences: every pair of small values
        if n == 2 {
            for a in ep.iter().take(6) {
                for b in ep.iter().take(6) {
                    out.push(Val::Seq(vec![a.clone(), b.clone()]));
                }
            }
        }
    }
    dedup(out)
}

fn dedup(v: Vec<Val>) -> Vec<Val> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

/// Candidate argument tuples for parameter types `params` (at most `n`):
/// the `given` tuples (from examples) first, then the diagonal of the
/// per-parameter pools, one parameter varied at a time, pairs, and
/// pseudo-random picks.
pub fn inputs(krate: &Crate, params: &[Ty], given: Vec<Vec<Val>>, n: usize, h: &mut Hints) -> Vec<Vec<Val>> {
    let pools: Vec<Vec<Val>> = params.iter().map(|t| pool(krate, t, h, 0)).collect();
    let mut out: Vec<Vec<Val>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |t: Vec<Val>, out: &mut Vec<Vec<Val>>| {
        if out.len() < n && seen.insert(t.clone()) {
            out.push(t);
        }
    };
    for g in given {
        if g.len() == params.len() {
            push(g, &mut out);
        }
    }
    if params.is_empty() {
        push(vec![], &mut out);
        return out;
    }
    if pools.iter().any(|p| p.is_empty()) {
        return out;
    }
    let longest = pools.iter().map(|p| p.len()).max().unwrap_or(0);
    for i in 0..longest {
        push(pools.iter().map(|p| p[i % p.len()].clone()).collect(), &mut out);
    }
    for j in 0..pools.len() {
        for v in &pools[j] {
            let mut t: Vec<Val> = pools.iter().map(|p| p[0].clone()).collect();
            t[j] = v.clone();
            push(t, &mut out);
        }
    }
    if pools.len() == 2 {
        for a in pools[0].iter().take(24) {
            for b in pools[1].iter().take(24) {
                push(vec![a.clone(), b.clone()], &mut out);
            }
        }
    } else if pools.len() >= 3 {
        for a in 0..pools[0].len().min(8) {
            for b in 0..pools[1].len().min(8) {
                for c in 0..pools[2].len().min(8) {
                    let mut t: Vec<Val> = pools.iter().map(|p| p[0].clone()).collect();
                    t[0] = pools[0][a].clone();
                    t[1] = pools[1][b].clone();
                    t[2] = pools[2][c].clone();
                    push(t, &mut out);
                }
            }
        }
    }
    let mut guard = 0;
    while out.len() < n && guard < n * 4 {
        guard += 1;
        let t: Vec<Val> = pools.iter().map(|p| p[h.rng.below(p.len() as u64) as usize].clone()).collect();
        push(t, &mut out);
    }
    out
}

/// A HIR expression as a candidate value (literals, arrays, tuples,
/// `Some`/`None`, byte strings through their literal form): the arguments
/// of calls in examples.
pub fn val_of_expr(e: &Expr) -> Option<Val> {
    match &e.kind {
        ExprKind::Lit(Lit::Int(n)) => Some(Val::Int(BigInt::from(*n))),
        ExprKind::Lit(Lit::Bool(b)) => Some(Val::Bool(*b)),
        ExprKind::Tuple(es) => Some(Val::Tuple(es.iter().map(val_of_expr).collect::<Option<_>>()?)),
        ExprKind::Array(es) => Some(Val::Seq(es.iter().map(val_of_expr).collect::<Option<_>>()?)),
        ExprKind::Repeat { elem, count } if *count <= 4096 => Some(Val::Seq(vec![val_of_expr(elem)?; *count as usize])),
        ExprKind::Adt { ctor: Ctor::None, .. } => Some(Val::Opt(None)),
        ExprKind::Adt { ctor: Ctor::Some, fields, .. } if fields.len() == 1 => Some(Val::Opt(Some(Box::new(val_of_expr(&fields[0].1)?)))),
        ExprKind::Coerce(_, x) | ExprKind::Ref(x) | ExprKind::Cast(x, _) => val_of_expr(x),
        ExprKind::Block(b) if b.stmts.is_empty() => val_of_expr(b.tail.as_ref()?),
        _ => None,
    }
}

/// The argument tuples of every call of `target` with literal arguments in
/// the examples of the crate.
pub fn example_calls(krate: &Crate, target: ItemId) -> Vec<Vec<Val>> {
    struct V<'a> {
        target: ItemId,
        out: &'a mut Vec<Vec<Val>>,
    }
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(id, _), args } = &e.kind
                && *id == self.target
                && let Some(vs) = args.iter().map(val_of_expr).collect::<Option<Vec<_>>>()
            {
                self.out.push(vs);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut out = Vec::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind {
            let mut v = V { target, out: &mut out };
            crate::visit::walk_fn_spec(&mut v, &f.spec);
        }
    }
    out
}

/// The integer literals of an expression.
pub fn literals(e: &Expr, out: &mut BTreeSet<u128>) {
    struct L<'a>(&'a mut BTreeSet<u128>);
    impl crate::visit::Visitor for L<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Lit(Lit::Int(n)) = &e.kind
                && *n < (1u128 << 64)
            {
                self.0.insert(*n);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    crate::visit::Visitor::expr(&mut L(out), e);
}

// ---------------------------------------------------------------------------
// Terms and evaluation
// ---------------------------------------------------------------------------

/// Closed terms of candidate values, evaluation, and printing, over one
/// kernel environment.
pub struct Evaluator<'e> {
    pub env: &'e Env,
    pub krate: &'e Crate,
    pub adts: &'e HashMap<ItemId, IndId>,
    /// Kernel steps per evaluation.
    pub budget: u64,
}

/// How a value was computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `Env::eval_closed` (kernel, TCB).
    Kernel,
    /// The untrusted reference strategy (erased `Irr` arguments).
    Reference,
}

impl Method {
    pub fn word(self) -> &'static str {
        match self {
            Method::Kernel => "the kernel's closed evaluator (eval_closed)",
            Method::Reference => "the reference evaluator (untrusted; the function has `Irr` binders)",
        }
    }
}

impl<'e> Evaluator<'e> {
    fn g(&self, n: &str) -> Result<Tm, String> {
        self.env.lookup_global(n).map(mk::global).ok_or_else(|| format!("missing prelude `{n}`"))
    }

    fn ind(&self, n: &str) -> Result<IndId, String> {
        self.env.lookup_ind(n).ok_or_else(|| format!("missing prelude inductive `{n}`"))
    }

    /// The closed core type of a HIR type.
    pub fn ty(&self, t: &Ty) -> Result<Tm, String> {
        Ok(match t {
            Ty::Bool => mk::bool_ty(self.env.bool_ind()),
            Ty::Uint(u) => mk::int_ty(u.width()),
            Ty::Int | Ty::Nat => mk::int_ty(Width::Int),
            Ty::Tuple(ts) if ts.is_empty() => mk::ind(self.ind("Unit")?, vec![]),
            Ty::Tuple(ts) => mk::ind(self.ind(&format!("Tuple{}", ts.len()))?, ts.iter().map(|x| self.ty(x)).collect::<Result<_, _>>()?),
            Ty::Array(e, n) => mk::apps(self.g("Array")?, [(Rel::Rel, self.ty(e)?), (Rel::Rel, mk::lit(Width::Usize, *n))]),
            Ty::Slice(e) => mk::app(self.g("Slice")?, self.ty(e)?),
            Ty::Ref(e) => self.ty(e)?,
            Ty::Option(e) => mk::ind(self.ind("Option")?, vec![self.ty(e)?]),
            Ty::Seq(e) => mk::ind(self.ind("List")?, vec![self.ty(e)?]),
            Ty::Adt(id, args) => mk::ind(*self.adts.get(id).ok_or("unknown type")?, args.iter().map(|x| self.ty(x)).collect::<Result<_, _>>()?),
            other => return Err(format!("type `{other:?}` has no candidate values")),
        })
    }

    fn list(&self, et: &Tm, elems: Vec<Tm>) -> Result<Tm, String> {
        let list = self.ind("List")?;
        let mut l = mk::ctor(list, 0, vec![et.clone()], vec![]);
        for e in elems.into_iter().rev() {
            l = mk::ctor(list, 1, vec![et.clone()], vec![e, l]);
        }
        Ok(l)
    }

    /// The closed term of a candidate value of type `t`.
    pub fn term(&self, t: &Ty, v: &Val) -> Result<Tm, String> {
        let bool_ = self.env.bool_ind();
        Ok(match (t.peel_refs(), v) {
            (Ty::Bool, Val::Bool(b)) => mk::bool_lit(bool_, *b),
            (Ty::Uint(u), Val::Int(n)) => mk::lit(u.width(), n.clone()),
            (Ty::Int | Ty::Nat, Val::Int(n)) => mk::lit(Width::Int, n.clone()),
            (Ty::Tuple(ts), Val::Tuple(xs)) if ts.is_empty() && xs.is_empty() => mk::ctor(self.ind("Unit")?, 0, vec![], vec![]),
            (Ty::Tuple(ts), Val::Tuple(xs)) if ts.len() == xs.len() => {
                let ps = ts.iter().map(|x| self.ty(x)).collect::<Result<Vec<_>, _>>()?;
                let vs = ts.iter().zip(xs).map(|(t, x)| self.term(t, x)).collect::<Result<Vec<_>, _>>()?;
                mk::ctor(self.ind(&format!("Tuple{}", ts.len()))?, 0, ps, vs)
            }
            (Ty::Array(e, n), Val::Seq(xs)) if xs.len() as u64 == *n => {
                let et = self.ty(e)?;
                let es = xs.iter().map(|x| self.term(e, x)).collect::<Result<Vec<_>, _>>()?;
                let l = self.list(&et, es)?;
                mk::pair(self.ty(&Ty::Array(e.clone(), *n))?, l, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, *n)))
            }
            (Ty::Slice(e), Val::Seq(xs)) => {
                let et = self.ty(e)?;
                let es = xs.iter().map(|x| self.term(e, x)).collect::<Result<Vec<_>, _>>()?;
                let n = es.len();
                let l = self.list(&et, es)?;
                let ok_ty = mk::apps(self.g("SliceOk")?, [(Rel::Rel, et.clone()), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, l.clone())]);
                let ok = mk::pair(ok_ty, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, n)), mk::refl(mk::bool_ty(bool_), mk::bool_lit(bool_, true)));
                mk::apps(self.g("slice::mk")?, [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, l), (Rel::Irr, ok)])
            }
            (Ty::Seq(e), Val::Seq(xs)) => {
                let et = self.ty(e)?;
                let es = xs.iter().map(|x| self.term(e, x)).collect::<Result<Vec<_>, _>>()?;
                self.list(&et, es)?
            }
            (Ty::Option(e), Val::Opt(x)) => {
                let et = self.ty(e)?;
                let opt = self.ind("Option")?;
                match x {
                    None => mk::ctor(opt, 0, vec![et], vec![]),
                    Some(x) => mk::ctor(opt, 1, vec![et], vec![self.term(e, x)?]),
                }
            }
            (Ty::Adt(id, args), Val::Adt { ctor, fields }) => {
                let ind = *self.adts.get(id).ok_or("unknown type")?;
                let ps = args.iter().map(|x| self.ty(x)).collect::<Result<Vec<_>, _>>()?;
                let ftys: Vec<Ty> = match &self.krate.item(*id).kind {
                    ItemKind::Struct(s) if s.invariant.is_none() => s.fields.iter().map(|f| f.ty.subst(args)).collect(),
                    ItemKind::Enum(en) => en.variants.get(*ctor as usize).ok_or("bad variant")?.fields.iter().map(|f| f.ty.subst(args)).collect(),
                    _ => return Err("no candidate values of this type".into()),
                };
                if ftys.len() != fields.len() {
                    return Err("field count".into());
                }
                let vs = ftys.iter().zip(fields).map(|(t, x)| self.term(t, x)).collect::<Result<Vec<_>, _>>()?;
                mk::ctor(ind, *ctor, ps, vs)
            }
            _ => return Err(format!("value {v:?} does not fit type {t:?}")),
        })
    }

    /// Evaluates `g` applied to `args` (relevant arguments in order; `Irr`
    /// binders get erased proofs). Returns the value and the evaluator.
    pub fn call(&self, g: GlobalId, args: &[Tm]) -> Result<(V, Method), String> {
        let rels = self.env.global_param_rels(g).ok_or("no parameter list")?;
        let mut rel_args = args.iter();
        let mut all: Vec<(Rel, Tm)> = Vec::new();
        let mut erased = false;
        for r in rels {
            match r {
                Rel::Rel => all.push((Rel::Rel, rel_args.next().ok_or("argument count")?.clone())),
                Rel::Irr => {
                    erased = true;
                    all.push((Rel::Irr, std::rc::Rc::new(Term::Erased)));
                }
            }
        }
        if rel_args.next().is_some() {
            return Err("argument count".into());
        }
        let term = mk::apps(mk::global(g), all);
        let mut b = Budget { steps: self.budget };
        if !erased {
            let nf = self.env.eval_closed(&term, &mut b).map_err(|e| format!("eval_closed: {}", e.message.lines().next().unwrap_or("")))?;
            let mut b2 = Budget { steps: self.budget };
            let v = self.env.eval(&VEnv::default(), Lvl(0), &nf, &mut b2).map_err(|e| format!("{e:?}"))?;
            return Ok((v, Method::Kernel));
        }
        let v = self.env.eval_opaque(&VEnv::default(), Lvl(0), &term, &|_| false, &mut b).map_err(|e| format!("{e:?}"))?;
        let mut u = Unfolder { env: self.env, rounds: 0, b: &mut b };
        Ok((u.deep(v)?, Method::Reference))
    }

    /// A `bool` result.
    pub fn as_bool(&self, v: &V) -> Option<bool> {
        match &**v {
            Value::Ctor { ind, ctor, .. } if *ind == self.env.bool_ind() => Some(*ctor == 1),
            _ => None,
        }
    }

    /// Prints a (normal-form) value of type `t`.
    pub fn show(&self, t: &Ty, v: &V) -> Result<String, String> {
        let stuck = || "the value is not first-order data".to_string();
        let rel = |a: &Arg| match a {
            Arg::Rel(x) => Some(x.clone()),
            Arg::Irr(_) => None,
        };
        Ok(match t.peel_refs() {
            Ty::Bool => self.as_bool(v).ok_or_else(stuck)?.to_string(),
            Ty::Uint(_) | Ty::Int | Ty::Nat => match &**v {
                Value::Lit { n, .. } => n.to_string(),
                _ => return Err(stuck()),
            },
            Ty::Tuple(ts) if ts.is_empty() => "()".into(),
            Ty::Tuple(ts) => match &**v {
                Value::Ctor { args, .. } => {
                    let parts = ts.iter().zip(args).map(|(t, a)| self.show(t, &rel(a).ok_or_else(stuck)?)).collect::<Result<Vec<_>, _>>()?;
                    format!("({})", parts.join(", "))
                }
                _ => return Err(stuck()),
            },
            Ty::Array(e, _) => match &**v {
                Value::Pair { fst, .. } => self.show_list(e, fst)?,
                _ => return Err(stuck()),
            },
            Ty::Slice(e) => match &**v {
                Value::Pair { snd: Arg::Rel(inner), .. } => match &**inner {
                    Value::Pair { fst, .. } => self.show_list(e, fst)?,
                    _ => return Err(stuck()),
                },
                _ => return Err(stuck()),
            },
            Ty::Seq(e) => format!("seq!{}", self.show_list(e, v)?),
            Ty::Option(e) => match &**v {
                Value::Ctor { ctor: 0, .. } => "None".into(),
                Value::Ctor { ctor: 1, args, .. } => format!("Some({})", self.show(e, &rel(&args[0]).ok_or_else(stuck)?)?),
                _ => return Err(stuck()),
            },
            Ty::Adt(id, targs) => match (&self.krate.item(*id).kind, &**v) {
                (ItemKind::Struct(s), Value::Ctor { args, .. }) => {
                    let name = &self.krate.item(*id).name;
                    let vals: Vec<String> = s.fields.iter().zip(args.iter().filter_map(rel)).map(|(f, x)| self.show(&f.ty.subst(targs), &x)).collect::<Result<_, _>>()?;
                    match s.shape {
                        Shape::Named => format!("{name} {{ {} }}", s.fields.iter().zip(&vals).map(|(f, x)| format!("{}: {x}", f.name.clone().unwrap_or_default())).collect::<Vec<_>>().join(", ")),
                        Shape::Tuple => format!("{name}({})", vals.join(", ")),
                        Shape::Unit => name.clone(),
                    }
                }
                (ItemKind::Enum(en), Value::Ctor { ctor, args, .. }) => {
                    let var = &en.variants[*ctor as usize];
                    let name = format!("{}::{}", self.krate.item(*id).name, var.name);
                    let vals: Vec<String> = var.fields.iter().zip(args.iter().filter_map(rel)).map(|(f, x)| self.show(&f.ty.subst(targs), &x)).collect::<Result<_, _>>()?;
                    match var.shape {
                        Shape::Unit => name,
                        Shape::Tuple => format!("{name}({})", vals.join(", ")),
                        Shape::Named => format!("{name} {{ {} }}", var.fields.iter().zip(&vals).map(|(f, x)| format!("{}: {x}", f.name.clone().unwrap_or_default())).collect::<Vec<_>>().join(", ")),
                    }
                }
                _ => return Err(stuck()),
            },
            _ => return Err("cannot print a value of this type".into()),
        })
    }

    /// The elements of a (normal-form) prelude `List`.
    fn list_elems(&self, l: &V) -> Result<Vec<V>, String> {
        let mut out = Vec::new();
        let mut cur = l.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ctor: 0, .. } => break,
                Value::Ctor { ctor: 1, args, .. } if args.len() == 2 => {
                    match &args[0] {
                        Arg::Rel(x) => out.push(x.clone()),
                        Arg::Irr(_) => return Err("bad list".into()),
                    }
                    match &args[1] {
                        Arg::Rel(t) => t.clone(),
                        Arg::Irr(_) => return Err("bad list".into()),
                    }
                }
                _ => return Err("the list is not first-order data".into()),
            };
            cur = next;
        }
        Ok(out)
    }

    fn show_list(&self, e: &Ty, l: &V) -> Result<String, String> {
        let elems = self.list_elems(l)?;
        let hex = hex_digits(e, elems.len());
        let out: Vec<String> = elems.iter().map(|x| self.show(e, x).map(|s| hexify(&s, hex))).collect::<Result<_, _>>()?;
        if out.len() > 2 && out.iter().all(|x| x == &out[0]) {
            return Ok(format!("[{}; {}]", out[0], out.len()));
        }
        Ok(format!("[{}]", out.join(", ")))
    }

    /// The elements of a value of sequence type `t` (array, slice, `Seq`).
    fn seq_elems(&self, t: &Ty, v: &V) -> Option<Vec<V>> {
        match (t.peel_refs(), &**v) {
            (Ty::Array(..), Value::Pair { fst, .. }) => self.list_elems(fst).ok(),
            (Ty::Slice(_), Value::Pair { snd: Arg::Rel(inner), .. }) => match &**inner {
                Value::Pair { fst, .. } => self.list_elems(fst).ok(),
                _ => None,
            },
            (Ty::Seq(_), _) => self.list_elems(v).ok(),
            _ => None,
        }
    }

    /// Where two values of type `t` differ, for a compound `t`: at most
    /// `max` positions (`[14]: 3 vs 4`, `.0`, `.lo`, `.Some`), then how many
    /// more; empty for a scalar.
    pub fn differences(&self, t: &Ty, a: &V, b: &V, max: usize) -> Vec<String> {
        if matches!(t.peel_refs(), Ty::Bool | Ty::Uint(_) | Ty::Int | Ty::Nat) {
            return vec![];
        }
        let mut out = Vec::new();
        let mut count = 0usize;
        self.diff_rec(t, a, b, String::new(), &mut out, &mut count, max);
        if count > out.len() {
            out.push(format!("… {} more", count - out.len()));
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn diff_rec(&self, t: &Ty, a: &V, b: &V, path: String, out: &mut Vec<String>, count: &mut usize, max: usize) {
        let rel = |x: &Arg| match x {
            Arg::Rel(v) => Some(v.clone()),
            Arg::Irr(_) => None,
        };
        let leaf = |out: &mut Vec<String>, count: &mut usize, hex: Option<usize>| {
            let (sa, sb) = (self.show(t, a).unwrap_or_else(|_| "?".into()), self.show(t, b).unwrap_or_else(|_| "?".into()));
            if sa != sb {
                *count += 1;
                if out.len() < max {
                    out.push(format!("{}: {} vs {}", if path.is_empty() { "the value".to_string() } else { path.clone() }, hexify(&sa, hex), hexify(&sb, hex)));
                }
            }
        };
        match t.peel_refs() {
            Ty::Tuple(ts) if !ts.is_empty() => match (&**a, &**b) {
                (Value::Ctor { args: xa, .. }, Value::Ctor { args: xb, .. }) if xa.len() == ts.len() && xb.len() == ts.len() => {
                    for (i, ti) in ts.iter().enumerate() {
                        if let (Some(va), Some(vb)) = (rel(&xa[i]), rel(&xb[i])) {
                            self.diff_rec(ti, &va, &vb, format!("{path}.{i}"), out, count, max);
                        }
                    }
                }
                _ => leaf(out, count, None),
            },
            Ty::Array(e, _) | Ty::Slice(e) | Ty::Seq(e) => match (self.seq_elems(t, a), self.seq_elems(t, b)) {
                (Some(xa), Some(xb)) if xa.len() == xb.len() => {
                    let hex = hex_digits(e, xa.len());
                    for (i, (va, vb)) in xa.iter().zip(&xb).enumerate() {
                        if matches!(e.peel_refs(), Ty::Bool | Ty::Uint(_) | Ty::Int | Ty::Nat) {
                            let (sa, sb) = (self.show(e, va).unwrap_or_default(), self.show(e, vb).unwrap_or_default());
                            if sa != sb {
                                *count += 1;
                                if out.len() < max {
                                    out.push(format!("{path}[{i}]: {} vs {}", hexify(&sa, hex), hexify(&sb, hex)));
                                }
                            }
                        } else {
                            self.diff_rec(e, va, vb, format!("{path}[{i}]"), out, count, max);
                        }
                    }
                }
                (Some(xa), Some(xb)) => {
                    *count += 1;
                    if out.len() < max {
                        out.push(format!("{}: length {} vs {}", if path.is_empty() { "the value" } else { path.as_str() }, xa.len(), xb.len()));
                    }
                }
                _ => leaf(out, count, None),
            },
            Ty::Option(e) => match (&**a, &**b) {
                (Value::Ctor { ctor: 1, args: xa, .. }, Value::Ctor { ctor: 1, args: xb, .. }) => match (rel(&xa[0]), rel(&xb[0])) {
                    (Some(va), Some(vb)) => self.diff_rec(e, &va, &vb, format!("{path}.Some"), out, count, max),
                    _ => leaf(out, count, None),
                },
                _ => leaf(out, count, None),
            },
            Ty::Adt(id, targs) => {
                let fields: Option<Vec<FieldDef>> = match (&self.krate.item(*id).kind, &**a, &**b) {
                    (ItemKind::Struct(s), Value::Ctor { .. }, Value::Ctor { .. }) => Some(s.fields.clone()),
                    (ItemKind::Enum(en), Value::Ctor { ctor: ca, .. }, Value::Ctor { ctor: cb, .. }) if ca == cb => en.variants.get(*ca as usize).map(|v| v.fields.clone()),
                    _ => None,
                };
                match (fields, &**a, &**b) {
                    (Some(fs), Value::Ctor { args: xa, .. }, Value::Ctor { args: xb, .. }) => {
                        let (ra, rb): (Vec<V>, Vec<V>) = (xa.iter().filter_map(rel).collect(), xb.iter().filter_map(rel).collect());
                        for (i, f) in fs.iter().enumerate() {
                            if let (Some(va), Some(vb)) = (ra.get(i), rb.get(i)) {
                                let name = f.name.clone().unwrap_or_else(|| i.to_string());
                                self.diff_rec(&f.ty.subst(targs), va, vb, format!("{path}.{name}"), out, count, max);
                            }
                        }
                    }
                    _ => leaf(out, count, None),
                }
            }
            _ => leaf(out, count, None),
        }
    }
}

/// Long byte sequences and word arrays (digests, hash states) print in
/// hex: the number of hex digits per element.
fn hex_digits(e: &Ty, n: usize) -> Option<usize> {
    match e.peel_refs() {
        Ty::Uint(UintTy::U8) if n >= 16 => Some(2),
        Ty::Uint(UintTy::U32) if n >= 8 => Some(8),
        Ty::Uint(UintTy::U64) if n >= 8 => Some(16),
        _ => None,
    }
}

/// A decimal integer (with an optional type suffix) in hex with `digits`
/// digits; anything else unchanged.
fn hexify(s: &str, digits: Option<usize>) -> String {
    let Some(d) = digits else { return s.to_string() };
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    match s[..end].parse::<u128>() {
        Ok(n) if end > 0 => format!("0x{n:0d$x}{}", &s[end..]),
        _ => s.to_string(),
    }
}

/// A zero of a type (the first candidate value), if any.
pub fn zero(krate: &Crate, t: &Ty) -> Option<Val> {
    Some(match t.peel_refs() {
        Ty::Bool => Val::Bool(false),
        Ty::Uint(_) | Ty::Int | Ty::Nat => Val::Int(BigInt::from(0)),
        Ty::Tuple(ts) => Val::Tuple(ts.iter().map(|x| zero(krate, x)).collect::<Option<_>>()?),
        Ty::Array(e, n) if *n <= 4096 => Val::Seq(vec![zero(krate, e)?; *n as usize]),
        Ty::Slice(_) | Ty::Seq(_) => Val::Seq(vec![]),
        Ty::Option(_) => Val::Opt(None),
        Ty::Adt(id, args) => match &krate.item(*id).kind {
            ItemKind::Struct(s) if s.invariant.is_none() => Val::Adt { ctor: 0, fields: s.fields.iter().map(|f| zero(krate, &f.ty.subst(args))).collect::<Option<_>>()? },
            ItemKind::Enum(en) => {
                let v = en.variants.first()?;
                Val::Adt { ctor: 0, fields: v.fields.iter().map(|f| zero(krate, &f.ty.subst(args))).collect::<Option<_>>()? }
            }
            _ => return None,
        },
        _ => return None,
    })
}

/// Simpler candidates for a value of type `t` (the shrinking of a
/// distinguishing input): integers towards zero, `true` to `false`,
/// `Some(x)` to `None`, sequences shorter, and components and elements
/// towards their zero. Every candidate is a value of the type (a struct
/// with an invariant is left alone).
pub fn simpler(krate: &Crate, t: &Ty, v: &Val) -> Vec<Val> {
    let mut out: Vec<Val> = Vec::new();
    match (t.peel_refs(), v) {
        (_, Val::Bool(true)) => out.push(Val::Bool(false)),
        (_, Val::Int(n)) => {
            let zero = BigInt::from(0);
            let one = BigInt::from(1);
            if *n != zero {
                out.push(Val::Int(zero.clone()));
                if *n > one {
                    out.push(Val::Int(one.clone()));
                }
                let half: BigInt = n / BigInt::from(2);
                if half != zero && half != one && half != *n {
                    out.push(Val::Int(half));
                }
                let dec: BigInt = if *n < zero { n + &one } else { n - &one };
                if dec != zero && dec != one && !out.contains(&Val::Int(dec.clone())) {
                    out.push(Val::Int(dec));
                }
            }
        }
        (Ty::Tuple(ts), Val::Tuple(xs)) if ts.len() == xs.len() => {
            for (i, (ti, x)) in ts.iter().zip(xs).enumerate() {
                for c in simpler(krate, ti, x) {
                    let mut y = xs.clone();
                    y[i] = c;
                    out.push(Val::Tuple(y));
                }
            }
        }
        (Ty::Array(e, _), Val::Seq(xs)) => out.extend(elementwise(krate, e, xs).into_iter().map(Val::Seq)),
        (Ty::Slice(e) | Ty::Seq(e), Val::Seq(xs)) => {
            if !xs.is_empty() {
                out.push(Val::Seq(vec![]));
                if xs.len() > 2 {
                    out.push(Val::Seq(xs[..xs.len() / 2].to_vec()));
                }
                if xs.len() > 1 {
                    out.push(Val::Seq(xs[..xs.len() - 1].to_vec()));
                }
            }
            out.extend(elementwise(krate, e, xs).into_iter().map(Val::Seq));
        }
        (Ty::Option(e), Val::Opt(Some(x))) => {
            out.push(Val::Opt(None));
            out.extend(simpler(krate, e, x).into_iter().map(|c| Val::Opt(Some(Box::new(c)))));
        }
        (Ty::Adt(id, targs), Val::Adt { ctor, fields }) => {
            let ftys: Option<Vec<Ty>> = match &krate.item(*id).kind {
                ItemKind::Struct(s) if s.invariant.is_none() => Some(s.fields.iter().map(|f| f.ty.subst(targs)).collect()),
                ItemKind::Enum(en) => en.variants.get(*ctor as usize).map(|v| v.fields.iter().map(|f| f.ty.subst(targs)).collect()),
                _ => None,
            };
            if let Some(ftys) = ftys {
                for (i, (ti, x)) in ftys.iter().zip(fields).enumerate() {
                    for c in simpler(krate, ti, x) {
                        let mut y = fields.clone();
                        y[i] = c;
                        out.push(Val::Adt { ctor: *ctor, fields: y });
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Every integer of a value halved (towards zero): the joint shrinking
/// step that keeps bit-aligned differences (`a & b != 0`) alive.
pub fn halved(v: &Val) -> Val {
    match v {
        Val::Int(n) => Val::Int(n / BigInt::from(2)),
        Val::Bool(b) => Val::Bool(*b),
        Val::Tuple(xs) => Val::Tuple(xs.iter().map(halved).collect()),
        Val::Seq(xs) => Val::Seq(xs.iter().map(halved).collect()),
        Val::Opt(x) => Val::Opt(x.as_ref().map(|x| Box::new(halved(x)))),
        Val::Adt { ctor, fields } => Val::Adt { ctor: *ctor, fields: fields.iter().map(halved).collect() },
    }
}

/// Element-wise simplifications of a sequence: all elements zero, one
/// element zero, and (short sequences) one element simpler.
fn elementwise(krate: &Crate, e: &Ty, xs: &[Val]) -> Vec<Vec<Val>> {
    let mut out = Vec::new();
    let z = zero(krate, e);
    if let Some(z) = &z {
        if xs.iter().filter(|x| *x != z).count() > 1 {
            out.push(vec![z.clone(); xs.len()]);
        }
        for (i, x) in xs.iter().enumerate() {
            if x != z {
                let mut y = xs.to_vec();
                y[i] = z.clone();
                out.push(y);
            }
        }
    }
    if xs.len() <= 8 {
        for (i, x) in xs.iter().enumerate() {
            for c in simpler(krate, e, x) {
                if Some(&c) == z.as_ref() {
                    continue;
                }
                let mut y = xs.to_vec();
                y[i] = c;
                out.push(y);
            }
        }
    }
    out
}

/// Prints a candidate value of type `t` (for witnesses) in Rust/spec
/// syntax: integer literals carry their type suffix once per sequence
/// (`[0u8, 1, 2]`), and a sequence of one repeated value is `[v; n]`.
pub fn show_val(krate: &Crate, t: &Ty, v: &Val) -> String {
    show_val_s(krate, t, v, true)
}

fn show_seq(krate: &Crate, e: &Ty, xs: &[Val], seq: bool) -> String {
    let open = if seq { "seq![" } else { "[" };
    let hex = hex_digits(e, xs.len());
    if xs.len() > 2 && xs.iter().all(|x| x == &xs[0]) {
        return format!("{open}{}; {}]", hexify(&show_val_s(krate, e, &xs[0], true), hex), xs.len());
    }
    let parts: Vec<String> = xs.iter().enumerate().map(|(i, x)| hexify(&show_val_s(krate, e, x, i == 0), hex)).collect();
    format!("{open}{}]", parts.join(", "))
}

fn show_val_s(krate: &Crate, t: &Ty, v: &Val, suffix: bool) -> String {
    match (t.peel_refs(), v) {
        (_, Val::Bool(b)) => b.to_string(),
        (Ty::Uint(u), Val::Int(n)) if suffix => format!("{n}{}", u.name()),
        (_, Val::Int(n)) => n.to_string(),
        (Ty::Tuple(ts), Val::Tuple(xs)) => format!("({})", ts.iter().zip(xs).map(|(t, x)| show_val_s(krate, t, x, true)).collect::<Vec<_>>().join(", ")),
        (Ty::Array(e, _) | Ty::Slice(e), Val::Seq(xs)) => show_seq(krate, e, xs, false),
        (Ty::Seq(e), Val::Seq(xs)) => show_seq(krate, e, xs, true),
        (Ty::Option(e), Val::Opt(x)) => match x {
            None => "None".into(),
            Some(x) => format!("Some({})", show_val_s(krate, e, x, true)),
        },
        (Ty::Adt(id, targs), Val::Adt { ctor, fields }) => {
            // in the syntax of the type's shape: `S { a: 1u32 }`, `S(1u32)`,
            // `E::V`
            let it = krate.item(*id);
            let (name, fdefs, shape): (String, &[FieldDef], Shape) = match &it.kind {
                ItemKind::Struct(s) => (it.name.clone(), s.fields.as_slice(), s.shape),
                ItemKind::Enum(en) => {
                    let var = &en.variants[*ctor as usize];
                    (format!("{}::{}", it.name, var.name), var.fields.as_slice(), var.shape)
                }
                _ => (it.name.clone(), &[], Shape::Unit),
            };
            let vals: Vec<String> = fdefs.iter().zip(fields).map(|(f, x)| show_val_s(krate, &f.ty.subst(targs), x, true)).collect();
            match shape {
                _ if fields.is_empty() => name,
                Shape::Named => format!("{name} {{ {} }}", fdefs.iter().zip(&vals).map(|(f, v)| format!("{}: {v}", f.name.clone().unwrap_or_default())).collect::<Vec<_>>().join(", ")),
                _ => format!("{name}({})", vals.join(", ")),
            }
        }
        (_, v) => format!("{v:?}"),
    }
}

/// Maximum number of manual unfoldings of stuck recursive applications in
/// one reference evaluation.
const MAX_UNFOLDS: u32 = 1 << 20;

/// The reference strategy (the driver's `sandblaster eval` completion,
/// untrusted): a neutral headed by a global applied to all its arguments is
/// replaced by its body evaluated on them, and its eliminators re-applied;
/// constructor fields and pairs are completed recursively.
struct Unfolder<'e, 'b> {
    env: &'e Env,
    rounds: u32,
    b: &'b mut Budget,
}

impl Unfolder<'_, '_> {
    fn eval(&mut self, entries: Vec<EnvEntry>, t: &Tm) -> Result<V, String> {
        self.env.eval_opaque(&VEnv(std::rc::Rc::new(entries)), Lvl(0), t, &|_| false, self.b).map_err(|e| format!("evaluation failed: {e:?}"))
    }

    fn entry(a: &Arg) -> EnvEntry {
        match a {
            Arg::Rel(v) => EnvEntry::Rel(v.clone()),
            Arg::Irr(c) => EnvEntry::Irr(c.clone()),
        }
    }

    fn force(&mut self, v: V) -> Result<V, String> {
        let mut v = v;
        loop {
            let Value::Neu(n) = &*v else { return Ok(v) };
            let Head::Global { def, args } = &n.head else { return Err("evaluation is stuck".into()) };
            let Some(body) = self.env.global_body(*def) else { return Err("evaluation is stuck on an opaque global".into()) };
            let arity = self.env.global_arity(*def).unwrap_or(0) as usize;
            if args.len() != arity || self.rounds >= MAX_UNFOLDS {
                return Err("evaluation is stuck".into());
            }
            let mut inner = body;
            for _ in 0..arity {
                let next = match &*inner {
                    Term::Lam { body, .. } => body.clone(),
                    _ => return Err("evaluation is stuck".into()),
                };
                inner = next;
            }
            self.rounds += 1;
            let mut hv = self.eval(args.iter().map(Self::entry).collect(), &inner)?;
            for e in &n.spine {
                hv = self.force(hv)?;
                hv = match e {
                    Elim::App(a) => {
                        let rel = if matches!(a, Arg::Rel(_)) { Rel::Rel } else { Rel::Irr };
                        self.eval(vec![EnvEntry::Rel(hv), Self::entry(a)], &mk::apps(mk::var(1), [(rel, mk::var(0))]))?
                    }
                    Elim::Fst => self.eval(vec![EnvEntry::Rel(hv)], &mk::fst(mk::var(0)))?,
                    Elim::Snd => self.eval(vec![EnvEntry::Rel(hv)], &mk::snd(mk::var(0)))?,
                    Elim::Match { arms, .. } => match &*hv {
                        Value::Ctor { ctor, args: fields, .. } => {
                            let arm = arms.get(*ctor as usize).ok_or("bad match arm")?;
                            let mut es: Vec<EnvEntry> = (*arm.env.0).clone();
                            es.extend(fields.iter().map(Self::entry));
                            self.eval(es, &arm.body)?
                        }
                        _ => return Err("evaluation is stuck on a match".into()),
                    },
                };
            }
            v = hv;
        }
    }

    fn deep(&mut self, v: V) -> Result<V, String> {
        let v = self.force(v)?;
        Ok(match &*v {
            Value::Ctor { ind, ctor, params, args } => {
                let mut new_args = Vec::with_capacity(args.len());
                for a in args {
                    new_args.push(match a {
                        Arg::Rel(x) => Arg::Rel(self.deep(x.clone())?),
                        Arg::Irr(c) => Arg::Irr(c.clone()),
                    });
                }
                std::rc::Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: new_args })
            }
            Value::Pair { fst, snd } => {
                let fst = self.deep(fst.clone())?;
                let snd = match snd {
                    Arg::Rel(x) => Arg::Rel(self.deep(x.clone())?),
                    Arg::Irr(c) => Arg::Irr(c.clone()),
                };
                std::rc::Rc::new(Value::Pair { fst, snd })
            }
            _ => v,
        })
    }
}
