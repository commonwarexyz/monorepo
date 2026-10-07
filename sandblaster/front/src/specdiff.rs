//! Classifying specification changes (DESIGN.md §15.6; stage **S1**,
//! agent D): `sandblaster spec --diff <rev>` and `sandblaster spec --accept
//! --equivalent-only`.
//!
//! The *old* side is a list of lock entries — the committed `SPEC.lock`,
//! or the surface of an old revision elaborated in a **separate kernel
//! environment** — whose statements are stored as kernel core text. The
//! *new* side is the surface of the current elaboration. For every item
//! whose hash differs, a bounded kernel attempt is made at `old ⇒ new` and
//! `new ⇒ old`, **over the same Merkle dependencies**: the old statement is
//! parsed into the new environment, which is sound only if every global it
//! names means what it meant — so every dependency of the old entry must
//! have the same hash now (or be itself classified *equivalent*); otherwise
//! the item is *unrelated* ("depends on X, which changed").
//!
//! | outcome | meaning |
//! | --- | --- |
//! | *equivalent* | both directions proven (or the kernel statement is identical and only the source text changed) |
//! | *weakened* | `old ⇒ new` only: the new statement claims less (an added `requires`, a weaker `ensures`, a spec predicate that accepts more) |
//! | *strengthened* | `new ⇒ old` only (a dropped `requires`, a stronger `ensures`) |
//! | *unrelated* | neither was proven within the budget, or the item is not a proposition the kernel compares (examples, vector files, types, target models: only an identical kernel statement is *equivalent*) |
//!
//! What is compared, per kind: a **law** is its proven statement (a Π
//! type); a **contract** is its domain (the `requires` of the function
//! type, compared as `Π x̄. Req_old(x̄) → Req_new(x̄)` and back) and its
//! `f::ensures` / `f::refines` statements (which mention `f` itself, so
//! they are comparable only while `f`'s type — its `requires` — is
//! unchanged); a **definition** (spec fn, spec or exec constant, view,
//! representation relation) is compared extensionally, `Π x̄. old(x̄) =
//! new(x̄)`, and a `Prop`/`bool` predicate also by implication; recursive
//! definitions only by identity (a closed term cannot restate `rec`).
//!
//! Each attempt builds a proof term — the old statement's hypotheses proven
//! from the new one's with the prover chain, its conclusion instantiated —
//! and the **kernel checks** `Π(h : old). new` against it. Nothing here is
//! trusted: an unproven direction only makes the classification weaker,
//! and acceptance of a change is still a reviewed `SPEC.lock` diff. A
//! hypothesis the stronger side binds irrelevantly (a `requires`, a panic
//! contract's no-panic clause `Not(p)`) is an argument in an irrelevant
//! position of that term, where a proof may use the other side's
//! irrelevant hypotheses (DESIGN.md §5.3); its proof is pre-checked the way
//! the kernel checks such a position, every other proof relevantly, and the
//! assembled term is checked as a whole either way.
//!
//! **Implementations are abstracted.** A law or contract constrains exec
//! functions whose *bodies* are not part of the surface (a contract's hash
//! covers its signature and statements, never the body). Comparing in the
//! environment where `f` is transparent would let any two statements that
//! are both true of the current `f` prove each other (`f(x) == 7` "equivalent"
//! to `f(x) < 100` because `f` returns 7). So every exec global a comparison
//! mentions that is not established (§15.1) — functions and loop helpers;
//! exec constants are locked by value and stay — is replaced by a
//! Π-bound variable of its type (`Π F̄'. old[F̄'] → new[F̄']`, as
//! `Env::abstract_section` abstracts a section), and the comparison is
//! refused (*unrelated*) when an abstracted part still reaches an
//! implementation through another global's definition. The kernel checks the
//! abstracted implication, so no proof can unfold the real body.
//!
//! **A panic contract is compared only by review.** A function's panic
//! contract (`panics_when(p)`, DESIGN.md §16.5) reaches its kernel type as
//! an ordinary hypothesis, the no-panic clause `Not(p)`, so the kernel
//! statement cannot tell `requires(!(p))` (the caller must avoid `p`) from
//! `panics_when(p)` (the function promises to panic on `p`). Any change in
//! whether a function has a panic contract, or in its condition as
//! rendered, is therefore never *equivalent*, in either direction and
//! whatever the kernel proves of the two types: the item is *unrelated*
//! ("the panic contract changed"), and with it every item that depends on
//! it. This decides only the classification: what an item hashes and
//! renders is unchanged.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{DefKind, GlobalId, Lvl, Name, Rel, Sort, Term, Tm};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Budget, V};

use crate::elab::{Output, ProverChain};
use crate::lock::{LockEntry, LockStatus, What};
use crate::prover::{FactOrigin, FactRef, Goal, ObligationId, ObligationKind, Prover};
use crate::span::Span;
use crate::surface::{hex, Canon, Hash, Stmt, Surface, SurfaceKind, Toolchain, TCB};

/// The classification of a changed item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Strengthened,
    Weakened,
    Equivalent,
    Unrelated,
}

impl Class {
    pub fn word(self) -> &'static str {
        match self {
            Class::Strengthened => "strengthened",
            Class::Weakened => "weakened",
            Class::Equivalent => "equivalent",
            Class::Unrelated => "unrelated",
        }
    }
    fn of(old_implies_new: bool, new_implies_old: bool) -> Class {
        match (old_implies_new, new_implies_old) {
            (true, true) => Class::Equivalent,
            (true, false) => Class::Weakened,
            (false, true) => Class::Strengthened,
            (false, false) => Class::Unrelated,
        }
    }
}

/// One difference between the old and the new surface.
#[derive(Clone, Debug)]
pub struct Change {
    pub key: String,
    pub what: What,
    /// For changed and restated items.
    pub class: Option<Class>,
    /// Why (what was proven, what blocked the comparison).
    pub reason: String,
    pub old: Vec<String>,
    pub new: Vec<String>,
}

/// Kernel steps per prover goal of an attempt (the build's goal budget).
pub const GOAL_BUDGET: u64 = 20_000_000;
/// Kernel steps for evaluating and checking one attempt's statements.
const CHECK_BUDGET: u64 = 200_000_000;

/// Whether a term is a proposition, syntactically (the kernel's `is_prop`
/// shape, with the head of a global application unfolded when it is a
/// non-recursive definition): hypotheses of a statement are its
/// proposition binders, its parameters the others.
fn is_prop(env: &Env, t: &Tm, fuel: u32) -> bool {
    match &**t {
        Term::Eq { .. } => true,
        Term::Pi { cod, .. } => is_prop(env, cod, fuel),
        Term::Sigma { fst, snd, .. } => is_prop(env, fst, fuel) && is_prop(env, snd, fuel),
        Term::Ind { ind, .. } => {
            *ind == env.empty_ind()
                || env.inductive_decl(*ind).is_some_and(|d| match d.ctors.as_slice() {
                    [] => true,
                    [c] => !c.fields.is_empty() && c.fields.iter().all(|f| f.1 == Rel::Irr),
                    _ => false,
                })
        }
        Term::App { .. } | Term::Global(_) => {
            let mut head = t;
            let mut args: Vec<(Rel, Tm)> = Vec::new();
            while let Term::App { rel, fun, arg } = &**head {
                args.push((*rel, arg.clone()));
                head = fun;
            }
            args.reverse();
            let Term::Global(g) = &**head else { return false };
            let body = env.global_body(*g);
            let recursive = body.as_ref().is_some_and(|b| crate::elab::tm::any_node(b, &mut |n| matches!(n, Term::Rec { .. })));
            match body {
                Some(b) if fuel > 0 && !recursive && env.global_opaque(*g) != Some(true) => {
                    // β: strip as many λs as there are arguments
                    let mut inner = b;
                    let mut vals = Vec::new();
                    for (_, a) in &args {
                        let Term::Lam { body, .. } = &*inner.clone() else { return false };
                        inner = body.clone();
                        vals.push(a.clone());
                    }
                    // the body under the λs refers to the arguments by index;
                    // substitute them (all at the application's depth)
                    let inst = crate::elab::tm::subst_closed(&inner, &vals);
                    is_prop(env, &inst, fuel - 1)
                }
                // a predicate that does not unfold (recursive `-> Prop`)
                _ => env.global_kind(*g) == Some(sandblaster_kernel::term::DefKind::Spec),
            }
        }
        _ => false,
    }
}

/// Every leading Π binder, and the rest.
fn split_pi(t: &Tm) -> (Vec<(Name, Rel, Tm)>, Tm) {
    let mut bs = Vec::new();
    let mut t = t.clone();
    while let Term::Pi { name, rel, dom, cod } = &*t.clone() {
        bs.push((name.clone(), *rel, dom.clone()));
        t = cod.clone();
    }
    (bs, t)
}

/// The first `n` Π binders (fewer if the type has fewer), and the rest.
fn split_n(t: &Tm, n: usize) -> (Vec<(Name, Rel, Tm)>, Tm) {
    let mut bs = Vec::new();
    let mut t = t.clone();
    while bs.len() < n {
        let Term::Pi { name, rel, dom, cod } = &*t.clone() else { break };
        bs.push((name.clone(), *rel, dom.clone()));
        t = cod.clone();
    }
    (bs, t)
}

fn pis(bs: &[(Name, Rel, Tm)], body: Tm) -> Tm {
    bs.iter().rev().fold(body, |acc, (n, r, d)| mk::pi(n, *r, d.clone(), acc))
}

fn lams(bs: &[(Name, Rel, Tm)], body: Tm) -> Tm {
    bs.iter().rev().fold(body, |acc, (n, r, d)| mk::lam(n, *r, d.clone(), acc))
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").chars().take(300).collect()
}

/// The panic contract of an item as its review statement renders it (the
/// `panics_when p` clause of a function's contract, `deelab`; a lock entry
/// stores the same lines): `None` without one. The kernel statement does
/// not carry it (the no-panic clause is an ordinary hypothesis `Not(p)`).
fn panic_contract<S: AsRef<str>>(statement: &[S]) -> Option<Vec<String>> {
    let lines: Vec<String> = statement.iter().flat_map(|s| s.as_ref().lines()).map(str::trim).filter(|l| l.starts_with("panics_when ")).map(str::to_string).collect();
    (!lines.is_empty()).then_some(lines)
}

/// Why a change is not equivalent because of the panic contract: `Some`
/// when the old and the new statement differ in whether the function has a
/// panic contract or in its condition (module docs).
fn panic_change<A: AsRef<str>, B: AsRef<str>>(old: &[A], new: &[B]) -> Option<String> {
    let (o, n) = (panic_contract(old), panic_contract(new));
    if o == n {
        return None;
    }
    let show = |p: &Option<Vec<String>>| p.as_ref().map(|l| format!("`{}`", l.join(" "))).unwrap_or_else(|| "none".into());
    let what = match (&o, &n) {
        (None, Some(_)) => "a panic contract was added",
        (Some(_), None) => "the panic contract was removed",
        _ => "the panic condition changed",
    };
    Some(format!(
        "{what} ({} -> {}): a panic contract reaches the kernel type only as its no-panic clause, an ordinary hypothesis (`requires(!(p))` and `panics_when(p)` have the same type), so a change in it is never equivalent: review it",
        show(&o),
        show(&n)
    ))
}

/// The classifier (on the elaboration thread of the new surface).
pub struct Classifier<'a> {
    out: &'a Output,
    new: &'a Surface,
    terms: &'a HashMap<String, Stmt>,
    old: BTreeMap<String, LockEntry>,
    chain: ProverChain,
    canon: Canon<'a>,
    memo: HashMap<String, (Class, String)>,
    active: HashSet<String>,
    goals: u32,
    /// Exec globals whose body is not locked and which are not established:
    /// abstracted in every comparison (see the module docs).
    established: HashSet<GlobalId>,
}

/// The implementation globals of one comparison, abstracted: `F_j'` is a
/// Π binder of `gs[j]`'s type with the earlier ones abstracted (a term at
/// depth `j`). Every term of the comparison is placed at depth `k`.
#[derive(Clone, Debug, Default)]
struct Abs {
    gs: Vec<GlobalId>,
    binders: Vec<(Name, Rel, Tm)>,
}

impl Abs {
    fn k(&self) -> u32 {
        self.gs.len() as u32
    }

    /// `t` (closed) with every abstracted global replaced by its binder's
    /// variable, as a term at depth `depth` (only `F_0' … F_{depth-1}'` are
    /// in scope). `None` if `t` mentions a later one or unfolds one (a
    /// `Delta`/`Unfold` of an implementation has no abstracted form).
    fn place_at(&self, t: &Tm, depth: u32) -> Option<Tm> {
        crate::elab::tm::map_post(t, 0, &mut |n, b| match &*n {
            Term::Global(g) => match self.gs.iter().position(|x| x == g) {
                Some(j) if (j as u32) < depth => Some(mk::var(depth - 1 - j as u32 + b)),
                Some(_) => None,
                None => Some(n),
            },
            Term::Delta { def, .. } | Term::Unfold { def, .. } if self.gs.contains(def) => None,
            _ => Some(n),
        })
    }

    fn place(&self, t: &Tm) -> Result<Tm, String> {
        self.place_at(t, self.k()).ok_or_else(|| "a proof inside the statement unfolds an implementation function".to_string())
    }
}

impl<'a> Classifier<'a> {
    /// `old`: the old entries of the new surface's target.
    pub fn new(out: &'a Output, new: &'a Surface, terms: &'a HashMap<String, Stmt>, old: impl IntoIterator<Item = LockEntry>) -> Classifier<'a> {
        let mut chain = ProverChain::standard();
        // a resource safety net only: the step budgets decide the attempt
        chain.timeout = Some(std::time::Duration::from_secs(20));
        Classifier {
            out,
            new,
            terms,
            old: old.into_iter().map(|e| (e.key.clone(), e)).collect(),
            chain,
            canon: Canon::new(&out.env),
            memo: HashMap::new(),
            active: HashSet::new(),
            goals: 0,
            established: out.established.iter().copied().collect(),
        }
    }

    /// Whether global `g` is an implementation a comparison must not look
    /// into: an exec function or loop helper that is not established. Exec
    /// constants are locked by value (their surface entry hashes the body)
    /// and are compared through it.
    fn is_impl(&self, g: GlobalId) -> bool {
        let env = &self.out.env;
        if !matches!(env.global_kind(g), Some(DefKind::Exec | DefKind::LoopHelper)) || self.established.contains(&g) {
            return false;
        }
        let name = env.global_name(g).map(|n| n.to_string()).unwrap_or_default();
        self.new.get(&format!("{}:{name}", SurfaceKind::Constant.tag())).is_none()
    }

    fn global_display(&self, g: GlobalId) -> String {
        self.out.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("#{}", g.0))
    }

    /// The abstraction of the implementation globals mentioned by `terms`
    /// (closed kernel statements of both sides), closed under their types;
    /// an error when an abstracted part still reaches an implementation
    /// through the definition of another global (a spec fn that calls the
    /// implementation, a lemma), which no abstraction can hide.
    fn abstraction(&self, terms: &[&Tm]) -> Result<Abs, String> {
        let env = &self.out.env;
        let mut gs: BTreeSet<GlobalId> = BTreeSet::new();
        let mut todo: Vec<Tm> = terms.iter().map(|t| (*t).clone()).collect();
        while let Some(t) = todo.pop() {
            let mut found = Vec::new();
            crate::elab::tm::any_node(&t, &mut |n| {
                if let Term::Global(g) | Term::Delta { def: g, .. } | Term::Unfold { def: g, .. } = n
                    && self.is_impl(*g)
                {
                    found.push(*g);
                }
                false
            });
            for g in found {
                if gs.insert(g)
                    && let Some(ty) = env.global_type(g)
                {
                    todo.push(ty);
                }
            }
        }
        let mut abs = Abs { gs: gs.into_iter().collect(), binders: Vec::new() };
        for j in 0..abs.gs.len() {
            let g = abs.gs[j];
            let ty = env.global_type(g).ok_or_else(|| format!("`{}` has no type", self.global_display(g)))?;
            let placed = abs.place_at(&ty, j as u32).ok_or_else(|| format!("the type of `{}` cannot be abstracted", self.global_display(g)))?;
            let short = self.global_display(g).rsplit("::").next().unwrap_or("f").to_string();
            abs.binders.push((Rc::from(format!("{short}'")), Rel::Rel, placed));
        }
        let mut placed: Vec<Tm> = abs.binders.iter().map(|b| b.2.clone()).collect();
        for t in terms {
            placed.push(abs.place(t)?);
        }
        let stop: Vec<GlobalId> = self.out.established.clone();
        for t in &placed {
            if let Some(g) = env.refs_closure(t, &stop).into_iter().find(|g| self.is_impl(*g)) {
                return Err(format!("the statement reaches the implementation of `{}` through the definition of another global, so it is compared only when identical", self.global_display(g)));
            }
        }
        Ok(abs)
    }

    /// Every difference, sorted by key.
    pub fn changes(&mut self) -> Vec<Change> {
        let mut keys: BTreeSet<String> = self.old.keys().cloned().collect();
        keys.extend(self.new.items.iter().map(|i| i.key.clone()));
        let mut out = Vec::new();
        for k in keys {
            let old = self.old.get(&k).cloned();
            let new = self.new.get(&k).cloned();
            match (old, new) {
                (None, Some(n)) => out.push(Change { key: k, what: What::Added, class: None, reason: String::new(), old: vec![], new: n.statement.clone() }),
                (Some(o), None) => out.push(Change { key: k, what: What::Removed, class: None, reason: String::new(), old: o.statement.clone(), new: vec![] }),
                (Some(o), Some(n)) => {
                    let new_stmt = LockEntry::of(&n, &self.new.target).statement;
                    if o.hash == n.hash {
                        if o.statement != new_stmt {
                            let (class, reason) = match panic_change(&o.statement, &new_stmt) {
                                Some(why) => (Class::Unrelated, why),
                                None => (Class::Equivalent, "the same hash: only the rendering of the statement changed".into()),
                            };
                            out.push(Change { key: k, what: What::Restated, class: Some(class), reason, old: o.statement.clone(), new: new_stmt });
                        }
                        continue;
                    }
                    let (class, reason) = self.classify(&k);
                    out.push(Change { key: k, what: What::Changed, class: Some(class), reason, old: o.statement.clone(), new: new_stmt });
                }
                (None, None) => {}
            }
        }
        out
    }

    /// The classification of a changed item (memoized; dependencies first).
    pub fn classify(&mut self, key: &str) -> (Class, String) {
        if let Some(c) = self.memo.get(key) {
            return c.clone();
        }
        if !self.active.insert(key.to_string()) {
            return (Class::Unrelated, "a cyclic dependency changed".into());
        }
        let r = self.classify_now(key);
        self.active.remove(key);
        self.memo.insert(key.to_string(), r.clone());
        r
    }

    fn new_dep_hash(&self, key: &str, name: &str, item: bool) -> Option<Hash> {
        if item {
            return self.new.get(name).map(|i| i.hash);
        }
        if let Some(d) = self.new.get(key).and_then(|i| i.deps.iter().find(|d| d.name == name)) {
            return Some(d.hash);
        }
        let tc = Toolchain::current();
        match name {
            n if n.starts_with("builtins:") => Some(tc.builtins),
            "ghost:ghost.core" => Some(tc.ghost),
            "semantics:semantics.rs" => Some(tc.semantics_defs),
            n if n.starts_with("prelude:") => tc.prelude_files.get(&n["prelude:".len()..]).copied(),
            n if n.starts_with("target:") => tc.target.get(&n["target:".len()..]).copied(),
            _ => None,
        }
    }

    /// `Ok` when every dependency of the old entry is unchanged (or itself
    /// equivalent): the old statement then means, in the new environment,
    /// what it meant.
    fn same_dependencies(&mut self, key: &str) -> Result<(), String> {
        let Some(o) = self.old.get(key).cloned() else { return Ok(()) };
        for d in &o.deps {
            let item = d.kind != crate::lock::DepKind::Ext;
            let old_h = match d.hash {
                Some(h) => Some(h),
                None => self.old.get(&d.name).map(|e| e.hash),
            };
            let new_h = self.new_dep_hash(key, &d.name, item);
            if old_h.is_some() && old_h == new_h {
                continue;
            }
            if item && self.old.contains_key(&d.name) && self.new.get(&d.name).is_some() && self.classify(&d.name).0 == Class::Equivalent {
                continue;
            }
            return Err(format!("depends on `{}`, which changed", d.name));
        }
        Ok(())
    }

    fn classify_now(&mut self, key: &str) -> (Class, String) {
        let (Some(o), Some(n)) = (self.old.get(key).cloned(), self.new.get(key).cloned()) else { return (Class::Unrelated, "not on both sides".into()) };
        if o.hash == n.hash {
            return (Class::Equivalent, "unchanged".into());
        }
        // before the kernel comparison, which cannot see a panic contract
        // (and before the identical-statement rule, which would call
        // `requires(!(p))` to `panics_when(p)` equivalent)
        if let Some(why) = panic_change(&o.statement, &n.statement) {
            return (Class::Unrelated, why);
        }
        if let Err(why) = self.same_dependencies(key) {
            return (Class::Unrelated, why);
        }
        if o.canon == n.canon {
            return (Class::Equivalent, "the kernel statement is identical; only the source text changed".into());
        }
        if n.kind == SurfaceKind::Section {
            // derived from its hypotheses (laws, contracts): their entries
            // are classified; the section itself only when identical
            return (Class::Unrelated, "a computed section changed with its hypotheses (the laws and contracts it lists) or its members: review those; only an identical statement counts as equivalent".into());
        }
        let Some(stmt) = self.terms.get(key).cloned() else { return (Class::Unrelated, "no kernel statement".into()) };
        let old_parts = match self.old_parts(&o) {
            Ok(p) => p,
            Err(e) => return (Class::Unrelated, e),
        };
        let r = match n.kind {
            SurfaceKind::Law => self.law(&old_parts, &stmt),
            SurfaceKind::Contract | SurfaceKind::BoundarySignature => self.contract(&old_parts, &stmt),
            SurfaceKind::SpecFn | SurfaceKind::SpecConst | SurfaceKind::Constant | SurfaceKind::View | SurfaceKind::Represents => self.definition(&old_parts, &stmt),
            k => Err(format!("a {} changed: only an identical kernel statement counts as equivalent", k.tag())),
        };
        match r {
            Ok(x) => x,
            Err(e) => (Class::Unrelated, e),
        }
    }

    /// The old statement parsed into the new environment, checked to be
    /// well-typed and to hash to the entry's `canon` (the lock's core text
    /// is what was hashed).
    fn old_parts(&mut self, o: &LockEntry) -> Result<Vec<(String, Tm)>, String> {
        if !o.kernel_omitted.is_empty() {
            return Err(format!("the old kernel statement ({}) is not stored (too large)", o.kernel_omitted.join(", ")));
        }
        if o.kernel.is_empty() {
            return Err("the old entry has no kernel statement".into());
        }
        let env = &self.out.env;
        let mut parts = Vec::new();
        for (p, text) in &o.kernel {
            let t = env.parse_term(&[], text).map_err(|e| format!("the old statement does not parse in the new environment ({})", first_line(&e.to_string())))?;
            let mut b = Budget { steps: CHECK_BUDGET };
            env.infer(&Ctx::default(), &t, &mut b).map_err(|e| format!("the old statement is ill-typed in the new environment ({})", first_line(&e.to_string())))?;
            parts.push((p.clone(), t));
        }
        if crate::surface::statement_canon(&mut self.canon, &parts, &[]) != o.canon {
            return Err("the old kernel text does not hash to its `canon` (corrupted lock?)".into());
        }
        Ok(parts)
    }

    fn part<'p>(parts: &'p [(String, Tm)], name: &str) -> Option<&'p Tm> {
        parts.iter().find(|(p, _)| p == name).map(|(_, t)| t)
    }

    fn law(&mut self, old: &[(String, Tm)], new: &Stmt) -> Result<(Class, String), String> {
        let a = Self::part(old, "type").ok_or("no old statement")?.clone();
        let b = Self::part(&new.parts, "type").ok_or("no new statement")?.clone();
        let abs = self.abstraction(&[&a, &b])?;
        let (a, b) = (abs.place(&a)?, abs.place(&b)?);
        let fwd = self.implies(&abs, &a, &b);
        let bwd = self.implies(&abs, &b, &a);
        Ok((Class::of(fwd.is_ok(), bwd.is_ok()), with_abstracted(self, &abs, describe(&fwd, &bwd))))
    }

    /// `D(F)`: the function type `F` with its result replaced by `true =
    /// true` (its domain: the parameters and the `requires`).
    fn domain(&self, f: &Tm) -> Tm {
        let (bs, _) = split_pi(f);
        let b = self.out.env.bool_ind();
        let t = mk::bool_lit(b, true);
        pis(&bs, mk::eq(mk::bool_ty(b), t.clone(), t))
    }

    fn contract(&mut self, old: &[(String, Tm)], new: &Stmt) -> Result<(Class, String), String> {
        let fo = Self::part(old, "fn").ok_or("no old function type")?.clone();
        let fnew = Self::part(&new.parts, "fn").ok_or("no new function type")?.clone();
        let mut all: Vec<Tm> = vec![fo.clone(), fnew.clone()];
        for part in ["ensures", "refines"] {
            all.extend(Self::part(old, part).cloned());
            all.extend(Self::part(&new.parts, part).cloned());
        }
        let abs = self.abstraction(&all.iter().collect::<Vec<_>>())?;
        let (fo, fnew) = (abs.place(&fo)?, abs.place(&fnew)?);
        let ((bo, ro), (bn, rn)) = (split_pi(&fo), split_pi(&fnew));
        let same_ret = if bo.len() == bn.len() {
            self.out.env.alpha_eq_relevant(&ro, &rn, &|x, y| x == y)
        } else {
            crate::surface::is_closed(&ro) && crate::surface::is_closed(&rn) && self.out.env.alpha_eq_relevant(&ro, &rn, &|x, y| x == y)
        };
        if !same_ret {
            return Err("the result type changed".into());
        }
        let (dom_old, dom_new) = (self.domain(&fo), self.domain(&fnew));
        // the domain grows iff every old-valid input is new-valid
        let grows = self.implies(&abs, &dom_new, &dom_old);
        let shrinks = self.implies(&abs, &dom_old, &dom_new);
        let mut notes = vec![format!("domain: {}", match (grows.is_ok(), shrinks.is_ok()) {
            (true, true) => "unchanged".to_string(),
            (true, false) => "grows (a requires dropped or weakened)".to_string(),
            (false, true) => "shrinks (a requires added or strengthened)".to_string(),
            (false, false) => format!("incomparable ({})", grows.as_ref().err().cloned().unwrap_or_default()),
        })];
        let (mut all_fwd, mut all_bwd) = (true, true);
        for part in ["ensures", "refines"] {
            match (Self::part(old, part).cloned(), Self::part(&new.parts, part).cloned()) {
                (Some(a), Some(b)) => {
                    let (a, b) = (abs.place(&a)?, abs.place(&b)?);
                    let fwd = self.implies(&abs, &a, &b);
                    let bwd = self.implies(&abs, &b, &a);
                    all_fwd &= fwd.is_ok();
                    all_bwd &= bwd.is_ok();
                    notes.push(format!("{part}: {}", describe(&fwd, &bwd)));
                }
                (None, Some(_)) => {
                    all_fwd = false;
                    notes.push(format!("{part}: added"));
                }
                (Some(_), None) => {
                    all_bwd = false;
                    notes.push(format!("{part}: removed"));
                }
                (None, None) => {}
            }
        }
        let strengthened = grows.is_ok() && all_bwd;
        let weakened = shrinks.is_ok() && all_fwd;
        Ok((Class::of(weakened, strengthened), with_abstracted(self, &abs, notes.join("; "))))
    }

    fn definition(&mut self, old: &[(String, Tm)], new: &Stmt) -> Result<(Class, String), String> {
        if new.recursive {
            return Err("a recursive definition changed: compared by identity only".into());
        }
        let (to, bo) = (Self::part(old, "type").ok_or("no old type")?.clone(), Self::part(old, "body").ok_or("no old body")?.clone());
        let (tn, bn) = (Self::part(&new.parts, "type").ok_or("no new type")?.clone(), Self::part(&new.parts, "body").ok_or("no new body")?.clone());
        if !self.out.env.alpha_eq_relevant(&to, &tn, &|x, y| x == y) {
            return Err("its type changed".into());
        }
        // a legacy spec definition may still call an implementation (spec
        // closure fails its build in the examples gate, but `--diff` must
        // still classify it): abstracted like a law
        let abs = self.abstraction(&[&to, &bo, &tn, &bn])?;
        let (tn, bo, bn) = (abs.place(&tn)?, abs.place(&bo)?, abs.place(&bn)?);
        let env = &self.out.env;
        let (bs, r) = split_n(&tn, new.np);
        let n = bs.len() as u32;
        let args: Vec<(Rel, Tm)> = bs.iter().enumerate().map(|(j, (_, rel, _))| (*rel, mk::var(n - 1 - j as u32))).collect();
        // the bodies are terms at depth k, applied under the n parameters
        let lhs = mk::apps(shift(&bo, n as i64), args.clone());
        let rhs = mk::apps(shift(&bn, n as i64), args);
        let eq = pis(&bs, mk::eq(r.clone(), lhs.clone(), rhs.clone()));
        let eq_r = self.prove_closed(&abs, &eq);
        if eq_r.is_ok() {
            return Ok((Class::Equivalent, with_abstracted(self, &abs, "extensionally equal (kernel-checked)".into())));
        }
        // predicates: by implication
        let b = env.bool_ind();
        let as_prop = |x: &Tm| -> Option<Tm> {
            match &*r {
                Term::Sort(Sort::Type) => Some(x.clone()),
                Term::Ind { ind, .. } if *ind == b => Some(mk::eq_bool(b, x.clone(), true)),
                _ => None,
            }
        };
        let (Some(pl), Some(pr)) = (as_prop(&lhs), as_prop(&rhs)) else {
            return Ok((Class::Unrelated, format!("not proven extensionally equal ({})", eq_r.err().unwrap_or_default())));
        };
        let fwd = self.prove_closed(&abs, &pis(&bs, mk::pi("h", Rel::Rel, pl.clone(), shift(&pr, 1))));
        let bwd = self.prove_closed(&abs, &pis(&bs, mk::pi("h", Rel::Rel, pr, shift(&pl, 1))));
        Ok((Class::of(fwd.is_ok(), bwd.is_ok()), with_abstracted(self, &abs, format!("predicate: {}", describe(&fwd, &bwd)))))
    }

    /// One prover goal (bounded), the result re-certified and checked.
    /// `Some((rel, t))` (`t` the target as a term of `ctx`): the proof is
    /// the argument of a hypothesis bound with relevance `rel`, and is
    /// checked as the kernel checks that position — an irrelevant one (a
    /// `requires`, a panic contract's no-panic clause `Not(p)` in a
    /// function's domain) lets a proof use the irrelevant variables of its
    /// context (DESIGN.md §5.3, resurrection: `.h_req0 : Not(p)` proves
    /// `Not(p)` there), a relevant one does not. `None`: a conclusion,
    /// checked against the target. Either way the assembled comparison is
    /// checked by the kernel as a whole ([`Classifier::implies`],
    /// [`Classifier::prove_closed`]), so this check only decides which
    /// proofs are worth assembling.
    fn prove(&mut self, ctx: &Ctx, facts: &[FactRef], target: V, position: Option<(Rel, &Tm)>) -> Result<Tm, String> {
        self.goals += 1;
        let goal = Goal { id: ObligationId(u32::MAX - self.goals), kind: ObligationKind::LawGoal, span: Span::DUMMY, ctx: ctx.clone(), facts: facts.to_vec(), target, hints: vec![] };
        let env = &self.out.env;
        let mut b = Budget { steps: GOAL_BUDGET };
        let p = self.chain.prove(env, &goal, &mut b).map_err(|f| format!("not proven: {}", f.goal.lines().next().unwrap_or("")))?;
        let p = crate::elab::recert::recertify(env, &goal.ctx, &p);
        let mut cb = Budget { steps: CHECK_BUDGET };
        let checked = match position {
            None => env.check(&goal.ctx, &p, &goal.target, &mut cb),
            // as the kernel checks the proof's position, an argument bound
            // relevantly or irrelevantly: `let h : P = p; true : Bool` (the
            // value of a relevant `let` is a relevant position, an
            // irrelevant `let`'s value `.h` is not)
            Some((rel, ty)) => {
                let bi = env.bool_ind();
                let wrapped = mk::let_("h", rel, ty.clone(), p.clone(), mk::bool_lit(bi, true));
                let bool_ty = self.eval(&goal.ctx, &mk::bool_ty(bi))?;
                env.check(&goal.ctx, &wrapped, &bool_ty, &mut cb)
            }
        };
        checked.map_err(|e| format!("the prover's proof was rejected: {}", first_line(&e.to_string())))?;
        Ok(p)
    }

    fn eval(&self, ctx: &Ctx, t: &Tm) -> Result<V, String> {
        let mut b = Budget { steps: CHECK_BUDGET };
        self.out.env.eval(&self.out.env.ctx_venv(ctx), ctx.depth(), t, &mut b).map_err(|e| format!("evaluation failed: {e:?}"))
    }

    /// The context of the abstracted implementation binders `F̄'`.
    fn abs_ctx(&self, abs: &Abs) -> Result<Ctx, String> {
        let mut ctx = Ctx::default();
        for (name, rel, dom) in &abs.binders {
            let dv = self.eval(&ctx, dom)?;
            ctx = ctx.push(CtxEntry { name: name.clone(), rel: *rel, ty: dv, def: None });
        }
        Ok(ctx)
    }

    /// Proves a proposition `Π(bs). concl` over the abstraction (a term at
    /// depth `k`): its proposition binders are facts, the conclusion the
    /// prover's goal; the kernel checks the assembled `λ(F̄' bs). proof`
    /// against `Π(F̄'). prop`.
    fn prove_closed(&mut self, abs: &Abs, prop: &Tm) -> Result<(), String> {
        let (bs, concl) = split_pi(prop);
        let mut ctx = self.abs_ctx(abs)?;
        let env = &self.out.env;
        let mut facts = Vec::new();
        for (name, rel, dom) in &bs {
            let dv = self.eval(&ctx, dom)?;
            if is_prop(env, dom, 8) {
                facts.push(FactRef { lvl: ctx.depth(), origin: FactOrigin::LemmaHyp, span: Span::DUMMY });
            }
            ctx = ctx.push(CtxEntry { name: name.clone(), rel: *rel, ty: dv, def: None });
        }
        let target = self.eval(&ctx, &concl)?;
        let p = self.prove(&ctx, &facts, target, None)?;
        let term = lams(&abs.binders, lams(&bs, p));
        let tyv = self.eval(&Ctx::default(), &pis(&abs.binders, prop.clone()))?;
        let mut b = Budget { steps: CHECK_BUDGET };
        self.out.env.check(&Ctx::default(), &term, &tyv, &mut b).map_err(|e| format!("the kernel rejected the proof: {}", first_line(&e.to_string())))
    }

    /// Proves `Π(F̄'). Π(h : a). b` (statements over the abstraction: terms
    /// at depth `k`, see the module docs): `b`'s binders are introduced;
    /// `a`'s parameters (non-proposition binders) are instantiated with
    /// `b`'s in order, `a`'s hypotheses proven from `b`'s by the prover
    /// chain, and `b`'s conclusion proven from `a`'s instantiated
    /// conclusion. The kernel checks the assembled term.
    fn implies(&mut self, abs: &Abs, a: &Tm, b: &Tm) -> Result<(), String> {
        let k = abs.k();
        let (a_bs, a_concl) = split_pi(a);
        // `b` under `h_old`
        let b1 = shift(b, 1);
        let (b_bs, b_concl) = split_pi(&b1);
        let mut ctx = self.abs_ctx(abs)?;
        let env = &self.out.env;
        let av = self.eval(&ctx, a)?;
        ctx = ctx.push(CtxEntry { name: Rc::from("h_old"), rel: Rel::Rel, ty: av, def: None });
        let mut facts = vec![FactRef { lvl: Lvl(k), origin: FactOrigin::LemmaHyp, span: Span::DUMMY }];
        let mut b_params: Vec<Lvl> = Vec::new();
        for (name, rel, dom) in &b_bs {
            let dv = self.eval(&ctx, dom)?;
            let lvl = ctx.depth();
            if is_prop(env, dom, 8) {
                facts.push(FactRef { lvl, origin: FactOrigin::LemmaHyp, span: Span::DUMMY });
            } else {
                b_params.push(lvl);
            }
            ctx = ctx.push(CtxEntry { name: name.clone(), rel: *rel, ty: dv, def: None });
        }
        let d = ctx.depth().0;
        let var = |l: Lvl| mk::var(d - 1 - l.0);
        // `a`'s terms are closed over `F̄'` and `a`'s own binders
        let mut vals: Vec<Tm> = (0..k).map(|j| var(Lvl(j))).collect();
        let mut args: Vec<(Rel, Tm)> = Vec::new();
        let mut next = 0usize;
        for (_, rel, dom) in &a_bs {
            let inst = crate::elab::tm::subst_closed(dom, &vals);
            if is_prop(env, dom, 8) {
                let target = self.eval(&ctx, &inst)?;
                // the proof is `a`'s argument, in the position `a` binds it:
                // an irrelevant one (its `requires`, a no-panic clause) may
                // use `b`'s irrelevant hypotheses, a relevant one may not
                let p = self.prove(&ctx, &facts, target, Some((*rel, &inst))).map_err(|e| format!("a hypothesis of the stronger side is not implied ({e})"))?;
                vals.push(p.clone());
                args.push((*rel, p));
            } else {
                let lvl = *b_params.get(next).ok_or("the parameters differ")?;
                next += 1;
                // (a relevant parameter cannot be given an irrelevant one)
                if *rel == Rel::Rel && ctx.entries[lvl.0 as usize].rel == Rel::Irr {
                    return Err("the parameters differ (a relevant one is irrelevant on the other side)".into());
                }
                let want = self.eval(&ctx, &inst)?;
                let have = ctx.entries[lvl.0 as usize].ty.clone();
                let mut cb = Budget { steps: CHECK_BUDGET };
                if !env.conv(ctx.depth(), &want, &have, &mut cb).unwrap_or(false) {
                    return Err("the parameter types differ".into());
                }
                vals.push(var(lvl));
                args.push((*rel, var(lvl)));
            }
        }
        if next != b_params.len() {
            return Err("the parameters differ".into());
        }
        let q_term = mk::apps(var(Lvl(k)), args);
        let qa = crate::elab::tm::subst_closed(&a_concl, &vals);
        let qv = self.eval(&ctx, &qa)?;
        let ctx2 = ctx.push(CtxEntry { name: Rc::from("h_concl"), rel: Rel::Rel, ty: qv, def: None });
        facts.push(FactRef { lvl: Lvl(d), origin: FactOrigin::LemmaHyp, span: Span::DUMMY });
        let bc = shift(&b_concl, 1);
        let target = self.eval(&ctx2, &bc)?;
        let r = self.prove(&ctx2, &facts, target, None).map_err(|e| format!("the conclusion is not implied ({e})"))?;
        let body = mk::let_("h_concl", Rel::Rel, qa, q_term, r);
        let term = lams(&abs.binders, mk::lam("h_old", Rel::Rel, a.clone(), lams(&b_bs, body)));
        let ty = pis(&abs.binders, mk::pi("h_old", Rel::Rel, a.clone(), b1));
        let tyv = self.eval(&Ctx::default(), &ty)?;
        let mut cb = Budget { steps: CHECK_BUDGET };
        self.out.env.check(&Ctx::default(), &term, &tyv, &mut cb).map_err(|e| format!("the kernel rejected the implication proof: {}", first_line(&e.to_string())))
    }

    /// `implies` on two closed statements (tests and tools): the
    /// implementation globals they mention are abstracted first.
    pub fn implies_closed(&mut self, a: &Tm, b: &Tm) -> Result<(), String> {
        let abs = self.abstraction(&[a, b])?;
        let (a, b) = (abs.place(a)?, abs.place(b)?);
        self.implies(&abs, &a, &b)
    }
}

/// The reason with the abstracted implementation functions named.
fn with_abstracted(c: &Classifier<'_>, abs: &Abs, reason: String) -> String {
    if abs.gs.is_empty() {
        return reason;
    }
    let names: Vec<String> = abs.gs.iter().map(|g| format!("`{}`", c.global_display(*g))).collect();
    format!("{reason} (compared for every implementation of {}: bodies are not part of the specification)", names.join(", "))
}

fn describe(fwd: &Result<(), String>, bwd: &Result<(), String>) -> String {
    let dir = |r: &Result<(), String>| match r {
        Ok(()) => "proven".to_string(),
        Err(e) => format!("not proven ({e})"),
    };
    format!("old ⇒ new {}; new ⇒ old {}", dir(fwd), dir(bwd))
}

/// The classifications of `changes` by key (for [`crate::lock::enforce`]).
pub fn classes(changes: &[Change]) -> BTreeMap<String, String> {
    changes.iter().filter_map(|c| c.class.map(|k| (c.key.clone(), k.word().to_string()))).collect()
}

/// The keys `--accept --equivalent-only` accepts: changed or restated items
/// classified equivalent (kernel-proven, or an identical kernel statement).
pub fn equivalent_keys(changes: &[Change]) -> Vec<String> {
    changes.iter().filter(|c| matches!(c.what, What::Changed | What::Restated) && c.class == Some(Class::Equivalent)).map(|c| c.key.clone()).collect()
}

/// What a green build means (DESIGN.md §15), printed on the spec sheet.
pub const GREEN_BUILD: &str = "for every boundary function, the function the proofs are about — for lifted Rust the structured reading of the crate's own source, tied to rustc's MIR of that source by a kernel-checked theorem per function (the theorem gate) — is obs_eq to the function the locked specification surface (§15.6) determines, relative to a well-founded chain of fully specified sections (§15.5), within the TCB below. It does not mean the specification says what its author intended: that is the reviewer's reading of the locked surface, which the known answers (§15.7) and the on-demand spec-mutation tool (`sandblaster mutate`, §15.7) help. Every §15.8 gate — boundary, examples and coverage, sections, law rules and the lock — passed for the build that states it.";

/// The spec sheet (`sandblaster spec`): per kind, every item's source text,
/// de-elaborated statement and kernel statement, its dependencies and its
/// lock status.
pub fn sheet(root: &str, s: &Surface, status: &LockStatus, changes: &[Change]) -> String {
    let mut o = String::new();
    o.push_str(&format!("SPECIFICATION SHEET: {root} (target {})\n\n", s.target));
    o.push_str(&format!("What a green build means: {GREEN_BUILD}\n\n"));
    o.push_str("Trusted computing base and assumptions (DESIGN.md §1.1):\n");
    for t in TCB {
        o.push_str(&format!("  {t}\n"));
    }
    o.push_str(&format!(
        "\nToolchain: kernel {}  prelude {}  semantics {}  builtins {}  target-model({}) {}\n",
        &hex(&s.kernel)[..16],
        &hex(&s.prelude)[..16],
        &hex(&s.semantics)[..16],
        &hex(&s.builtins)[..16],
        s.target,
        &hex(&s.target_model)[..16]
    ));
    o.push_str(&format!("SPEC.lock ({}): {}\n", status.file, status.summary()));
    if !s.internal.is_empty() {
        o.push_str(&format!("Proof internals (not locked, checked by the gates: helper spec functions, their examples, invariants and contracts no statement mentions): {}\n", s.internal.len()));
    }
    for h in &status.header {
        o.push_str(&format!("  toolchain differs: {h}\n"));
    }
    let change: HashMap<&str, &Change> = changes.iter().map(|c| (c.key.as_str(), c)).collect();
    for kind in SurfaceKind::ALL {
        let items: Vec<_> = s.items.iter().filter(|i| i.kind == kind).collect();
        if items.is_empty() {
            continue;
        }
        o.push_str(&format!("\n== {} ({}) ==\n", kind.heading(), items.len()));
        for i in items {
            let mark = match change.get(i.key.as_str()) {
                Some(c) => format!("  [{}{}]", c.what.word(), c.class.map(|k| format!(": {}", k.word())).unwrap_or_default()),
                None => match status.mismatches.iter().find(|m| m.key == i.key) {
                    Some(m) => format!("  [{}]", m.what.word()),
                    None => String::new(),
                },
            };
            o.push_str(&format!("\n{}  (hash {}…){mark}\n", i.key, &hex(&i.hash)[..16]));
            if !i.source.is_empty() {
                o.push_str(&format!("  source:    {}\n", i.source));
            }
            for (k, line) in i.statement.iter().enumerate() {
                o.push_str(&format!("  {} {line}\n", if k == 0 { "statement:" } else { "          " }));
            }
            for n in &i.notes {
                o.push_str(&format!("  note:      {n}\n"));
            }
            for (p, text) in &i.kernel {
                let t: String = text.chars().take(2000).collect();
                o.push_str(&format!("  kernel {p}: {}{}\n", t.replace('\n', " "), if text.chars().count() > 2000 { " …" } else { "" }));
            }
            for p in &i.kernel_omitted {
                o.push_str(&format!("  kernel {p}: (too large to print)\n"));
            }
            if !i.deps.is_empty() {
                o.push_str(&format!("  depends on: {}\n", i.deps.iter().map(|d| d.name.clone()).collect::<Vec<_>>().join(", ")));
            }
            if let Some(c) = change.get(i.key.as_str())
                && !c.reason.is_empty()
            {
                o.push_str(&format!("  change:    {}\n", c.reason));
            }
        }
    }
    let removed: Vec<&Change> = changes.iter().filter(|c| c.what == What::Removed).collect();
    if !removed.is_empty() {
        o.push_str("\n== Removed since the lock ==\n");
        for c in removed {
            o.push_str(&format!("{}\n  locked: {}\n", c.key, c.old.join(" ")));
        }
    }
    if !s.laws.is_empty() {
        o.push_str("\n== Laws: guarantees and assumptions (DESIGN.md §15.1 LR9) ==\n");
        for l in crate::elab::law_rules::table_lines(&s.laws) {
            o.push_str(&l);
            o.push('\n');
        }
    }
    if !s.items.iter().any(|i| i.kind == SurfaceKind::Section) {
        o.push_str("\n== Sections ==\nnone: every function that must be determined is determined by its refinement (DESIGN.md §15.5)\n");
    }
    if !s.errors.is_empty() {
        o.push_str("\n== Errors (the surface cannot be locked, DESIGN.md §15.6) ==\n");
        for e in &s.errors {
            o.push_str(&format!("{}: {}\n  {}\n", e.key, e.msg, e.note));
        }
    }
    o
}
