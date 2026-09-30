//! Proof outlining: the linear-arithmetic proofs inside a definition's type
//! and body, turned into lemma globals (optimizer design §7, proof size).
//!
//! An equality lemma's proof restates the source it rewrites (unfolded
//! bodies, their `let`-bound parameters) and the residual it justifies in
//! the types of its transports, and the kernel type-checks every copy:
//! every `linarith` proof of the definitions' checked arithmetic and
//! `requires` clauses, and the statements of their hypotheses, which carry
//! further proofs (the proofs of a body nest). Outlining a definition
//! replaces each `linarith` node of its type and body by the application of
//! a lemma `Π Γ. P` over the node's free variables (closed under the
//! variables their types mention): the lemma is checked once, every copy of
//! the body then costs an application.
//!
//! Only irrelevant positions change, and conversion skips them (DESIGN.md
//! §5.3), so an outlined body is convertible with the definition's own (a
//! `Delta` step's equation holds for it unchanged). Nothing is trusted: a
//! node whose lemma the kernel refuses (its proof needs a `let` definition
//! of its context, say) stays as it was, and a use site passes an
//! irrelevant variable only where the kernel's usage rule admits it.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Arm, DefDecl, DefKind, GlobalId, Idx, Name, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use crate::auto::util::shift;
use crate::elab::tm::{any_node_depth, rename_levels};

/// Kernel steps for checking one outlined lemma.
const LEMMA_STEPS: u64 = 20_000_000;

/// Nodes whose closed context is larger than this stay in place (the
/// application would cost about as much as the proof).
const MAX_PARAMS: usize = 40;

/// Irrelevant `let`s whose value has at most this many nodes are
/// substituted into their bodies.
const SMALL_PROOF: usize = 16;

/// The outlined definitions of one optimizer run: `(type, body)` by global
/// (`None`: nothing to outline, or not outlinable).
#[derive(Default)]
pub struct Outlines {
    defs: HashMap<GlobalId, Option<Rc<(Tm, Tm)>>>,
    /// Lemmas committed / refused by the kernel (reported by the timing
    /// trace).
    pub lemmas: usize,
    pub refused: usize,
}

impl Outlines {
    /// The outlined `(type, body)` of `g`, if it has any.
    pub fn get(&self, g: GlobalId) -> Option<Rc<(Tm, Tm)>> {
        self.defs.get(&g).cloned().flatten()
    }

    /// Outlines `g` (once).
    pub fn ensure(&mut self, env: &mut Env, g: GlobalId) {
        if self.defs.contains_key(&g) {
            return;
        }
        let r = outline_def(env, g, self);
        self.defs.insert(g, r.map(Rc::new));
    }

    /// The outlined definitions among `gs`.
    pub fn table(&mut self, env: &mut Env, gs: impl IntoIterator<Item = GlobalId>) -> HashMap<GlobalId, Rc<(Tm, Tm)>> {
        let mut out = HashMap::new();
        for g in gs {
            self.ensure(env, g);
            if let Some(o) = self.get(g) {
                out.insert(g, o);
            }
        }
        out
    }
}

fn outline_def(env: &mut Env, g: GlobalId, stats: &mut Outlines) -> Option<(Tm, Tm)> {
    let ty = env.global_type(g)?;
    let body = env.global_body(g)?;
    let prefix = env.global_name(g)?.to_string();
    let mut w = Walker { env, prefix, next: 0, stack: Vec::new(), mode: None, has: HashMap::new(), worth: HashMap::new(), memo: HashMap::new(), scope: 0, next_scope: 1, lemmas: 0, refused: 0, zeta: 0 };
    let ty2 = w.go(&ty);
    let body2 = w.go(&body);
    stats.lemmas += w.lemmas;
    stats.refused += w.refused;
    (w.lemmas > 0 || w.zeta > 0).then_some((ty2, body2))
}

struct Walker<'e> {
    env: &'e mut Env,
    prefix: String,
    next: u32,
    /// The context: each entry's name, relevance and type (a term at the
    /// entry's own depth, already outlined).
    stack: Vec<(Name, Rel, Tm)>,
    /// The kernel's relevance mode at the current position (`Some(d)`:
    /// inside an irrelevant position entered at depth `d`; the irrelevant
    /// entries below `d` are usable), tracked conservatively: a position
    /// not known to be irrelevant keeps the enclosing mode.
    mode: Option<u32>,
    /// "Contains a `linarith` node", by subterm identity (the subterm is
    /// kept alive so its address is not reused).
    has: HashMap<*const Term, (Tm, bool)>,
    /// "Contains a `linarith` node or an irrelevant `let`".
    worth: HashMap<*const Term, (Tm, bool)>,
    /// Results by (subterm identity, scope, mode).
    memo: HashMap<(*const Term, u64, Option<u32>), (Tm, Tm)>,
    scope: u64,
    next_scope: u64,
    lemmas: usize,
    refused: usize,
    /// Irrelevant `let`s substituted.
    zeta: usize,
}

impl Walker<'_> {
    fn depth(&self) -> u32 {
        self.stack.len() as u32
    }

    fn has_lin(&mut self, t: &Tm) -> bool {
        let key = Rc::as_ptr(t);
        if let Some((_, b)) = self.has.get(&key) {
            return *b;
        }
        let mut found = matches!(&**t, Term::Linarith { .. });
        if !found {
            for c in crate::opt::symex::children(t) {
                if self.has_lin(&c) {
                    found = true;
                    break;
                }
            }
        }
        self.has.insert(key, (t.clone(), found));
        found
    }

    /// Whether `t` contains a `linarith` node or an irrelevant `let`
    /// (memoized like [`Self::has_lin`]).
    fn worth(&mut self, t: &Tm) -> bool {
        let key = Rc::as_ptr(t);
        if let Some((_, b)) = self.worth.get(&key) {
            return *b;
        }
        let mut found = matches!(&**t, Term::Linarith { .. } | Term::Let { rel: Rel::Irr, .. });
        if !found {
            for c in crate::opt::symex::children(t) {
                if self.worth(&c) {
                    found = true;
                    break;
                }
            }
        }
        self.worth.insert(key, (t.clone(), found));
        found
    }

    /// Runs `f` under the binders `bs` (types at successive depths).
    fn under<T>(&mut self, bs: Vec<(Name, Rel, Tm)>, f: impl FnOnce(&mut Self) -> T) -> T {
        let saved = (self.stack.len(), self.scope);
        self.stack.extend(bs);
        self.scope = self.next_scope;
        self.next_scope += 1;
        let r = f(self);
        self.stack.truncate(saved.0);
        self.scope = saved.1;
        r
    }

    /// `f` in an irrelevant position entered here.
    fn irr<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        let saved = self.mode;
        self.mode = Some(self.depth());
        let r = f(self);
        self.mode = saved;
        r
    }

    fn sub(&mut self, rel: Rel, t: &Tm) -> Tm {
        if rel == Rel::Irr { self.irr(|s| s.go(t)) } else { self.go(t) }
    }

    fn go(&mut self, t: &Tm) -> Tm {
        if !self.worth(t) {
            return t.clone();
        }
        let key = (Rc::as_ptr(t), self.scope, self.mode);
        if let Some((_, r)) = self.memo.get(&key) {
            return r.clone();
        }
        let r = self.go_inner(t);
        self.memo.insert(key, (t.clone(), r.clone()));
        r
    }

    fn go_inner(&mut self, t: &Tm) -> Tm {
        use Term::*;
        match &**t {
            Linarith { hyps, goal, cert } => {
                let hyps2: Vec<(Tm, Tm)> = hyps.iter().map(|(p, s)| (self.go(p), self.go(s))).collect();
                let goal2 = self.go(goal);
                let node: Tm = Rc::new(Linarith { hyps: hyps2, goal: goal2, cert: cert.clone() });
                self.outline(&node).unwrap_or(node)
            }
            Pi { name, rel, dom, cod } => {
                let dom2 = self.go(dom);
                let cod2 = self.under(vec![(name.clone(), *rel, dom2.clone())], |s| s.go(cod));
                Rc::new(Pi { name: name.clone(), rel: *rel, dom: dom2, cod: cod2 })
            }
            Lam { name, rel, dom, body } => {
                let dom2 = self.go(dom);
                let body2 = self.under(vec![(name.clone(), *rel, dom2.clone())], |s| s.go(body));
                Rc::new(Lam { name: name.clone(), rel: *rel, dom: dom2, body: body2 })
            }
            Let { name, rel, ty, val, body } => {
                let ty2 = self.go(ty);
                let val2 = self.sub(*rel, val);
                let body2 = self.under(vec![(name.clone(), *rel, ty2.clone())], |s| s.go(body));
                // an irrelevant `let` of a small proof (a slice's `h_ok`)
                // is substituted: its variable occurs only in irrelevant
                // positions, so the body is convertible either way, and
                // every copy of the body saves the `let`'s checks — unless a
                // `linarith` node stayed in the body (the kernel may search
                // the context's facts for it, the `let` among them)
                if *rel == Rel::Irr && crate::elab::tm::size_capped(&val2, SMALL_PROOF + 1) <= SMALL_PROOF && !self.has_lin(&body2) {
                    self.zeta += 1;
                    return crate::auto::util::subst0(&body2, &val2);
                }
                Rc::new(Let { name: name.clone(), rel: *rel, ty: ty2, val: val2, body: body2 })
            }
            Sigma { name, snd_rel, fst, snd } => {
                let fst2 = self.go(fst);
                let snd2 = self.under(vec![(name.clone(), Rel::Rel, fst2.clone())], |s| s.go(snd));
                Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst2, snd: snd2 })
            }
            Pair { ty, fst, snd } => {
                let snd_rel = match &**ty {
                    Sigma { snd_rel, .. } => *snd_rel,
                    _ => Rel::Rel,
                };
                Rc::new(Pair { ty: self.go(ty), fst: self.go(fst), snd: self.sub(snd_rel, snd) })
            }
            Match { ind, params, scrut, motive, arms } => {
                let params2: Vec<Tm> = params.iter().map(|p| self.go(p)).collect();
                let scrut2 = self.go(scrut);
                let dty: Tm = Rc::new(Ind { ind: *ind, params: params2.clone() });
                let motive2 = self.under(vec![(Rc::from("y"), Rel::Rel, dty)], |s| s.go(motive));
                let Some(decl) = self.env.inductive_decl(*ind) else { return t.clone() };
                let mut arms2 = Vec::with_capacity(arms.len());
                for (a, c) in arms.iter().zip(&decl.ctors) {
                    let fields: Vec<(Name, Rel, Tm)> = c.fields.iter().enumerate().map(|(i, (n, r, fty))| (n.clone(), *r, field_ty(fty, i as u32, &params2))).collect();
                    let body2 = self.under(fields, |s| s.go(&a.body));
                    arms2.push(Arm { names: a.names.clone(), body: body2 });
                }
                Rc::new(Match { ind: *ind, params: params2, scrut: scrut2, motive: motive2, arms: arms2 })
            }
            Transport { ty, lhs, rhs, eq, motive, val } => {
                let ty2 = self.go(ty);
                let motive2 = self.under(vec![(Rc::from("y"), Rel::Rel, ty2.clone())], |s| s.go(motive));
                Rc::new(Transport { ty: ty2, lhs: self.go(lhs), rhs: self.go(rhs), eq: self.irr(|s| s.go(eq)), motive: motive2, val: self.go(val) })
            }
            App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: self.go(fun), arg: self.sub(*rel, arg) }),
            Fst(p) => Rc::new(Fst(self.go(p))),
            Snd(p) => Rc::new(Snd(self.go(p))),
            Eq { ty, lhs, rhs } => Rc::new(Eq { ty: self.go(ty), lhs: self.go(lhs), rhs: self.go(rhs) }),
            Refl { ty, val } => Rc::new(Refl { ty: self.go(ty), val: self.go(val) }),
            Ind { ind, params } => Rc::new(Ind { ind: *ind, params: params.iter().map(|p| self.go(p)).collect() }),
            Ctor { ind, ctor, params, args } => {
                let rels: Vec<Rel> = self.env.inductive_decl(*ind).and_then(|d| d.ctors.get(*ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect())).unwrap_or_default();
                let params2 = params.iter().map(|p| self.go(p)).collect();
                let args2 = args.iter().enumerate().map(|(i, a)| self.sub(rels.get(i).copied().unwrap_or(Rel::Rel), a)).collect();
                Rc::new(Ctor { ind: *ind, ctor: *ctor, params: params2, args: args2 })
            }
            Prim { op, args, proofs } => {
                let args2 = args.iter().map(|a| self.go(a)).collect();
                let proofs2 = proofs.iter().map(|p| self.irr(|s| s.go(p))).collect();
                Rc::new(Prim { op: *op, args: args2, proofs: proofs2 })
            }
            Absurd { ty, proof } => Rc::new(Absurd { ty: self.go(ty), proof: self.irr(|s| s.go(proof)) }),
            // the remaining nodes keep their proofs (rare in bodies)
            _ => t.clone(),
        }
    }

    /// The lemma of a `linarith` node at the current position, and its
    /// application here; `None` (the node stays) when the kernel refuses
    /// the lemma or the use site could not pass an irrelevant variable.
    fn outline(&mut self, node: &Tm) -> Option<Tm> {
        let Term::Linarith { goal, .. } = &**node else { return None };
        let d = self.depth();
        let mut fv = BTreeSet::new();
        free_levels(node, d, &mut fv);
        let mut work: Vec<u32> = fv.iter().copied().collect();
        while let Some(l) = work.pop() {
            let mut s = BTreeSet::new();
            free_levels(&self.stack[l as usize].2, l, &mut s);
            for x in s {
                if fv.insert(x) {
                    work.push(x);
                }
            }
        }
        if fv.len() > MAX_PARAMS {
            return None;
        }
        // the use site passes every variable relevantly: an irrelevant
        // entry must be usable in the current mode (bound outside the
        // irrelevant position; the kernel's rule)
        if fv.iter().any(|&l| self.stack[l as usize].1 == Rel::Irr && !matches!(self.mode, Some(m) if l < m)) {
            return None;
        }
        let levels: Vec<u32> = fv.into_iter().collect();
        let m = levels.len() as u32;
        let map: HashMap<u32, usize> = levels.iter().enumerate().map(|(i, &l)| (l, i)).collect();
        let mut tele = Vec::with_capacity(levels.len());
        for (i, &l) in levels.iter().enumerate() {
            let (name, _, ty) = &self.stack[l as usize];
            tele.push((name.clone(), rename_levels(ty, l, &map, i as u32)?));
        }
        let mut ty = rename_levels(goal, d, &map, m)?;
        let mut body = rename_levels(node, d, &map, m)?;
        for (name, t) in tele.iter().rev() {
            ty = mk::pi(name, Rel::Rel, t.clone(), ty);
            body = mk::lam(name, Rel::Rel, t.clone(), body);
        }
        let name = loop {
            let n = format!("{}::lin#{}", self.prefix, self.next);
            self.next += 1;
            if self.env.lookup_global(&n).is_none() {
                break n;
            }
        };
        let decl = DefDecl { name: Rc::from(name.as_str()), kind: DefKind::Lemma, ty, body, recursion: Recursion::None, arity: m, opaque: true };
        let mut b = Budget { steps: LEMMA_STEPS };
        match self.env.add_def(decl, &mut b) {
            Ok(g) => {
                self.lemmas += 1;
                Some(mk::apps(mk::global(g), levels.iter().map(|&l| (Rel::Rel, mk::var(d - 1 - l)))))
            }
            Err(e) => {
                self.refused += 1;
                if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                    eprintln!("opt: outline {name} refused: {}", e.to_string().chars().take(400).collect::<String>());
                }
                None
            }
        }
    }
}

/// The levels of the free variables of `t` (a term at depth `depth`).
fn free_levels(t: &Tm, depth: u32, out: &mut BTreeSet<u32>) {
    any_node_depth(t, &mut |n, b| {
        if let Term::Var(Idx(i)) = n
            && *i >= b
            && let Some(l) = depth.checked_sub(1 + (*i - b))
        {
            out.insert(l);
        }
        false
    });
}

/// The type of field `i` of a constructor (`fty`, in the declaration's
/// context: parameters, then the fields before it) at the match's
/// parameters `params` (terms at the match's depth), as a term at that
/// depth plus the `i` fields.
fn field_ty(fty: &Tm, i: u32, params: &[Tm]) -> Tm {
    let np = params.len() as u32;
    crate::auto::util::map_term(fty, i, &mut |t, k| match &**t {
        Term::Var(Idx(j)) if *j >= k && *j < k + np => Some(shift(&params[(np - 1 - (j - k)) as usize], k as i64)),
        _ => None,
    })
}
