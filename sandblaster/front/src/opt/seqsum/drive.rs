//! Consumer driving over segments (optimizer design §8.2): the Σ1
//! driver's leaf hook.
//!
//! At a leaf (a value the driver does not decompose further) the hook looks
//! for **sites** — lists that are not a slice of the program (a buffer
//! assembled by `copy_range`/`update` over a `replicate`, or a sub-slice of
//! such a buffer):
//!
//! * an element read `index(L, i)` becomes the element the normal form
//!   finds (forwarding: a written value, or a read of a piece's slice);
//! * a call `f(…, s, …)` of a user function whose slice argument `s` has
//!   such a list becomes a call of `f` on a sub-slice (one piece) or of the
//!   **segment specialization** of `f` at the pieces' shape (several):
//!   `E(…, s₁, e₁, s₂, …)` with the entry `E` of [`Registry`], printed as a
//!   call of its helper.
//!
//! A read whose piece the facts do not determine yields a **demand split**
//! on the emptiness of a piece ([`LeafOut::Demand`]). The rewritten value is
//! only what the residual prints: the proof builder closes the leaf from the
//! seq lemmas (`seqsum::prove`), so a mistake here is a failed candidate.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use sandblaster_kernel::term::{GlobalId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Closure, Elim, Head, Neutral, V, VEnv, Value};

use super::segments::{Elem, Ids, Norm, NormErr, Oracle, Piece, usize_term};
use crate::auto::state::St;
use crate::hir::ItemId;
use crate::opt::drive::process::{Driver, Path};

/// The kind of a piece parameter of a segment specialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PK {
    /// A slice parameter (`&[T]`).
    Seg,
    /// An element parameter (`T`).
    Elem,
}

/// A segment specialization: the function, the kernel argument index of
/// its slice parameter, and the shape of the pieces replacing it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SegKey {
    pub def: GlobalId,
    pub pos: usize,
    pub shape: Vec<PK>,
}

/// A committed segment specialization.
#[derive(Clone, Debug)]
pub struct SegEntry {
    /// The entry `E(x̄, s̄, h̄) = f(x̄, mk(s₁ ++ [e₁] ++ …))` (a transparent
    /// kernel definition; `h̄` bound each `Seg` piece's length).
    pub entry: GlobalId,
    /// The bound of each `Seg` piece's length in `E`'s `requires`.
    pub bound: u64,
    /// The specialization's number among its consumer's: the entry is
    /// `f__seg<index>::entry`, the helper `f__seg<index>`. Fixed when the
    /// entry is created ([`Registry::reserve`]), never a position in
    /// [`Registry::entries`] (a key created later can sort before one whose
    /// helper is already named).
    pub index: u32,
    /// The printed helper and its lemma `Π x̄ s̄ h̄. Eq(R, H x̄ s̄ h̄, E x̄ s̄ h̄)`,
    /// once built.
    pub helper: Option<SegHelper>,
}

#[derive(Clone, Copy, Debug)]
pub struct SegHelper {
    pub item: ItemId,
    pub global: GlobalId,
    pub lemma: GlobalId,
}

/// The segment specializations of a crate.
#[derive(Default)]
pub struct Registry {
    pub entries: BTreeMap<SegKey, SegEntry>,
    /// Keys a driving asked for that have no entry yet (the caller creates
    /// the entries and drives again).
    pub requested: RefCell<BTreeSet<SegKey>>,
    /// Keys whose entry or helper failed (not proposed again).
    pub failed: BTreeSet<SegKey>,
    /// The next specialization number of each consumer (monotonic: numbers
    /// of failed entries are not reused).
    next: BTreeMap<GlobalId, u32>,
}

impl Registry {
    /// A fresh specialization number for the consumer `def` (its helper and
    /// entry names are unique among `def`'s specializations).
    pub fn reserve(&mut self, def: GlobalId) -> u32 {
        let n = self.next.entry(def).or_insert(0);
        let k = *n;
        *n += 1;
        k
    }

    /// The number [`Registry::reserve`] would give `def` next (nothing is
    /// reserved).
    pub fn peek(&self, def: GlobalId) -> u32 {
        self.next.get(&def).copied().unwrap_or(0)
    }

    /// The entry whose global is `g`.
    pub fn by_entry(&self, g: GlobalId) -> Option<(&SegKey, &SegEntry)> {
        self.entries.iter().find(|(_, e)| e.entry == g)
    }

    /// `(entry, (helper, lemma))` of every built helper (the proof builder's
    /// fold map: a helper call rewrites to its entry by its lemma).
    pub fn lemmas(&self) -> Vec<(GlobalId, (GlobalId, GlobalId))> {
        self.entries.values().filter_map(|e| e.helper.map(|h| (e.entry, (h.global, h.lemma)))).collect()
    }

    /// `(entry, helper item)` of every built helper (the printer prints an
    /// entry's application as a call of its helper).
    pub fn items(&self) -> Vec<(GlobalId, ItemId)> {
        self.entries.values().filter_map(|e| e.helper.map(|h| (e.entry, h.item))).collect()
    }
}

/// What the driver does with a leaf.
pub enum LeafOut {
    /// No site (or one Σ3 does not handle): the leaf as it is.
    Keep,
    /// The rewritten, printable value.
    Rewrite(V),
    /// Split on this boolean first (a demand split).
    Demand(V),
}

/// Why a rewrite stopped.
enum Stop {
    Keep,
    Demand(V),
}

/// The driver's oracle: its linear-arithmetic decisions over the path's
/// facts, no proofs.
struct DriverOracle<'x, 'd, 'a> {
    d: &'x mut Driver<'a>,
    st: &'d St,
}

impl Oracle for DriverOracle<'_, '_, '_> {
    fn decide(&mut self, c: &Tm) -> Option<(bool, Option<Tm>)> {
        let cv = self.d.eval_tm(self.st, c).ok()?;
        if let Value::Ctor { ind, ctor, .. } = &*cv
            && *ind == self.d.bool_ind
        {
            return Some((*ctor == 1, None));
        }
        self.d.decide_lin(self.st, c, &cv).map(|b| (b, None))
    }

    fn prove(&mut self, goal: &Tm, _extra: &[(Tm, Tm)]) -> Option<Option<Tm>> {
        match &**goal {
            Term::Eq { ty, lhs, rhs } if matches!(&**ty, Term::IntTy(Width::Int)) => {
                let le = |a: &Tm, b: &Tm| mk::prim(PrimOp::Le(Width::Int), vec![a.clone(), b.clone()], vec![]);
                let a = self.decide(&le(lhs, rhs))?;
                let b = self.decide(&le(rhs, lhs))?;
                (a.0 && b.0).then_some(None)
            }
            Term::Eq { lhs, rhs, .. } if matches!(&**rhs, Term::Ctor { ctor: 1, .. }) => match self.decide(lhs)? {
                (true, _) => Some(None),
                _ => None,
            },
            _ => None,
        }
    }

    fn proofs(&self) -> bool {
        false
    }
}

/// A closure standing for an irrelevant argument the printer ignores (the
/// residual's elaboration proves the real one).
fn dummy() -> Closure {
    Closure { env: VEnv::default(), body: Rc::new(Term::Erased) }
}

fn rel(a: &Arg) -> Option<&V> {
    match a {
        Arg::Rel(v) => Some(v),
        Arg::Irr(_) => None,
    }
}

/// `x` if `v` is `x` projected by exactly `[Snd, Fst]` (a slice's list).
fn slice_of_list(v: &V) -> Option<V> {
    let Value::Neu(n) = &**v else { return None };
    let k = n.spine.len().checked_sub(2)?;
    if !matches!(&n.spine[k..], [Elim::Snd, Elim::Fst]) {
        return None;
    }
    Some(crate::auto::util::prefix(n, k))
}

/// The list and length of a slice value `(n, (list, _))`.
fn slice_parts(v: &V) -> Option<(V, V)> {
    let Value::Pair { fst, snd: Arg::Rel(inner) } = &**v else { return None };
    let Value::Pair { fst: list, snd: Arg::Irr(_) } = &**inner else { return None };
    Some((list.clone(), fst.clone()))
}

/// Whether the residual printer can print a slice whose list is `v`: a
/// slice's list, or `drop`/`take` of one at a `usize` offset.
fn printable_list(ids: &Ids, v: &V) -> bool {
    if slice_of_list(v).is_some() {
        return true;
    }
    let Value::Neu(Neutral { head: Head::Global { def, args }, spine }) = &**v else { return false };
    if !spine.is_empty() || !(*def == ids.drop || *def == ids.take) || args.len() != 3 {
        return false;
    }
    let (Some(l), Some(k)) = (rel(&args[1]), rel(&args[2])) else { return false };
    printable_list(ids, l) && printable_int(k)
}

fn printable_int(v: &V) -> bool {
    match &**v {
        Value::Lit { .. } => true,
        Value::Neu(Neutral { head: Head::Prim { op: PrimOp::Cast { to: Width::Int, from }, .. }, spine }) => spine.is_empty() && *from != Width::Int,
        _ => false,
    }
}

/// The element type `T` of a `Slice T` binder type term.
fn slice_elem(env: &sandblaster_kernel::api::Env, dom: &Tm) -> Option<Tm> {
    let (g, args) = super::segments::head_app(dom)?;
    (env.global_name(g).as_deref() == Some("Slice") && args.len() == 1).then(|| args[0].1.clone())
}

/// The leaf hook (see the module docs).
pub fn leaf(d: &mut Driver<'_>, path: &Path, v: &V) -> LeafOut {
    let policy = d.policy;
    let Some(reg) = policy.seg_registry() else { return LeafOut::Keep };
    let Some(ids) = Ids::new(d.env) else { return LeafOut::Keep };
    if !has_site(d, &ids, v) {
        return LeafOut::Keep;
    }
    let mut rw = Rewriter { d, path, ids, reg, memo: HashMap::new(), changed: false };
    match rw.map(v) {
        Ok(nv) if rw.changed => LeafOut::Rewrite(nv),
        Ok(_) => LeafOut::Keep,
        Err(Stop::Demand(c)) => LeafOut::Demand(c),
        Err(Stop::Keep) => LeafOut::Keep,
    }
}

/// Whether `v` contains a site (a quick scan before any work).
fn has_site(d: &Driver<'_>, ids: &Ids, v: &V) -> bool {
    let mut seen: std::collections::HashSet<*const Value> = std::collections::HashSet::new();
    let mut stack = vec![v.clone()];
    while let Some(x) = stack.pop() {
        if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 200_000 {
            continue;
        }
        match &*x {
            Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(rel).cloned()),
            Value::Pair { fst, snd } => {
                stack.push(fst.clone());
                stack.extend(rel(snd).cloned());
            }
            Value::Neu(n) => {
                match &n.head {
                    Head::Global { def, args } => {
                        if *def == ids.index && args.len() == 5 && rel(&args[1]).is_some_and(|l| !printable_list(ids, l)) {
                            return true;
                        }
                        if d.policy.seg_consumer(*def) && args.iter().filter_map(rel).any(|a| slice_parts(a).is_some_and(|(l, _)| !printable_list(ids, &l))) {
                            return true;
                        }
                        stack.extend(args.iter().filter_map(rel).cloned());
                    }
                    Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                    _ => {}
                }
                for e in &n.spine {
                    if let Elim::App(a) = e {
                        stack.extend(rel(a).cloned());
                    }
                }
            }
            _ => {}
        }
    }
    false
}

struct Rewriter<'r, 'p, 'a> {
    d: &'r mut Driver<'a>,
    path: &'p Path,
    ids: Ids,
    reg: &'a Registry,
    memo: HashMap<*const Value, V>,
    changed: bool,
}

impl Rewriter<'_, '_, '_> {
    fn quote(&self, v: &V) -> Tm {
        let env = self.d.env;
        let t = env.quote_typed(&self.path.st.ctx, v, None, false);
        let t = crate::auto::util::kernel_friendly(env, &t);
        crate::auto::util::fold_array_eta(&t, self.ids.index, self.ids.list)
    }

    fn eval(&mut self, t: &Tm) -> Result<V, Stop> {
        self.d.eval_tm(&self.path.st, t).map_err(|_| Stop::Keep)
    }

    /// Runs `f` with a normalizer of element type `t` over the driver's
    /// oracle.
    fn with_norm<X>(&mut self, t: Tm, f: impl FnOnce(&mut Norm<'_>) -> Result<X, NormErr>) -> Result<X, Stop> {
        let env = self.d.env;
        let r = {
            let mut o = DriverOracle { d: &mut *self.d, st: &self.path.st };
            let mut n = Norm { env, ids: &self.ids, t, oracle: &mut o };
            f(&mut n)
        };
        match r {
            Ok(x) => Ok(x),
            Err(NormErr::Undecided(c)) => Err(self.demand(&c)),
            Err(NormErr::Unsupported(why)) => {
                if self.d.trace {
                    eprintln!("opt: drive: seq: not handled: {why}");
                }
                Err(Stop::Keep)
            }
        }
    }

    /// The demand split for the undecided comparison `c` (over `Int`), as
    /// the printable `usize` comparison; never twice on one path.
    fn demand(&mut self, c: &Tm) -> Stop {
        match super::demand::split(self.d, self.path, &self.ids, c) {
            Some(cv) => Stop::Demand(cv),
            None => Stop::Keep,
        }
    }

    /// The value with its sites rewritten (post-order, shared nodes once).
    fn map(&mut self, v: &V) -> Result<V, Stop> {
        if let Some(x) = self.memo.get(&Rc::as_ptr(v)) {
            return Ok(x.clone());
        }
        let out = self.map_uncached(v)?;
        self.memo.insert(Rc::as_ptr(v), out.clone());
        Ok(out)
    }

    fn map_args(&mut self, args: &[Arg]) -> Result<(Vec<Arg>, bool), Stop> {
        let mut out = Vec::with_capacity(args.len());
        let mut any = false;
        for a in args {
            match a {
                Arg::Rel(x) => {
                    let y = self.map(x)?;
                    any |= !Rc::ptr_eq(x, &y);
                    out.push(Arg::Rel(y));
                }
                Arg::Irr(c) => out.push(Arg::Irr(c.clone())),
            }
        }
        Ok((out, any))
    }

    fn map_uncached(&mut self, v: &V) -> Result<V, Stop> {
        match &**v {
            Value::Ctor { ind, ctor, params, args } => {
                let (args2, any) = self.map_args(args)?;
                Ok(if any { Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args2 }) } else { v.clone() })
            }
            Value::Pair { fst, snd } => {
                let f2 = self.map(fst)?;
                let s2 = match snd {
                    Arg::Rel(x) => Arg::Rel(self.map(x)?),
                    Arg::Irr(c) => Arg::Irr(c.clone()),
                };
                let same = Rc::ptr_eq(fst, &f2)
                    && match (snd, &s2) {
                        (Arg::Rel(a), Arg::Rel(b)) => Rc::ptr_eq(a, b),
                        _ => true,
                    };
                Ok(if same { v.clone() } else { Rc::new(Value::Pair { fst: f2, snd: s2 }) })
            }
            Value::Neu(n) => {
                let (head, hany) = match &n.head {
                    Head::Global { def, args } => {
                        let (args2, any) = self.map_args(args)?;
                        if n.spine.is_empty()
                            && let Some(r) = self.site(*def, &args2)?
                        {
                            self.changed = true;
                            return Ok(r);
                        }
                        (Head::Global { def: *def, args: args2 }, any)
                    }
                    Head::Prim { op, args, proofs } => {
                        let mut any = false;
                        let mut a2 = Vec::new();
                        for x in args {
                            let y = self.map(x)?;
                            any |= !Rc::ptr_eq(x, &y);
                            a2.push(y);
                        }
                        (Head::Prim { op: *op, args: a2, proofs: proofs.clone() }, any)
                    }
                    h => (crate::auto::util::clone_head(h), false),
                };
                let mut sany = false;
                let mut spine = Vec::with_capacity(n.spine.len());
                for e in &n.spine {
                    match e {
                        Elim::App(Arg::Rel(x)) => {
                            let y = self.map(x)?;
                            sany |= !Rc::ptr_eq(x, &y);
                            spine.push(Elim::App(Arg::Rel(y)));
                        }
                        e => spine.push(crate::auto::util::clone_elim(e)),
                    }
                }
                Ok(if hany || sany { Rc::new(Value::Neu(Neutral { head, spine })) } else { v.clone() })
            }
            _ => Ok(v.clone()),
        }
    }

    /// The replacement of the global application `def args` if it is a
    /// site.
    fn site(&mut self, def: GlobalId, args: &[Arg]) -> Result<Option<V>, Stop> {
        if def == self.ids.index && args.len() == 5 {
            let (Some(l), Some(i), Some(t)) = (rel(&args[1]), rel(&args[2]), rel(&args[0])) else { return Ok(None) };
            // (a list read through a variable — a slice's or an array's, a
            // field's — is not assembled: nothing to rewrite)
            if printable_list(&self.ids, l) || matches!(&**l, Value::Neu(Neutral { head: Head::Var(_), .. })) {
                return Ok(None);
            }
            return self.read(t, l, i).map(Some);
        }
        if !self.d.policy.seg_consumer(def) {
            return Ok(None);
        }
        let sites: Vec<usize> = args.iter().enumerate().filter(|(_, a)| rel(a).and_then(slice_parts).is_some_and(|(l, _)| !printable_list(&self.ids, &l))).map(|(j, _)| j).collect();
        match sites.as_slice() {
            [] => Ok(None),
            [pos] => self.call(def, args, *pos).map(Some),
            _ => Err(Stop::Keep),
        }
    }

    /// An element read `index(t, l, i)` of an assembled list.
    fn read(&mut self, t: &V, l: &V, i: &V) -> Result<V, Stop> {
        let (t_tm, l_tm, i_tm) = (self.quote(t), self.quote(l), self.quote(i));
        let erased: Tm = Rc::new(Term::Erased);
        let e = self.with_norm(t_tm.clone(), |n| {
            let r = n.norm(&l_tm)?;
            Ok(n.index_p(&r.pieces, &i_tm, &erased, &erased)?.0)
        })?;
        match e {
            Elem::Val(x) => self.eval(&x),
            Elem::At { base, j, .. } => {
                if slice_of_list_tm(&base).is_none() {
                    if self.d.trace {
                        let names = self.path.st.names();
                        eprintln!("opt: drive: seq: a read of a list that is not a slice's: {} (of {})", self.d.env.print_term(&names, &base).chars().take(400).collect::<String>(), self.d.env.print_term(&names, &l_tm).chars().take(1200).collect::<String>());
                    }
                    return Err(Stop::Keep);
                }
                let Some(ju) = usize_term(&self.ids, &j) else {
                    if self.d.trace {
                        let names = self.path.st.names();
                        eprintln!("opt: drive: seq: a read position without a usize form: {}", self.d.env.print_term(&names, &j));
                    }
                    return Err(Stop::Keep);
                };
                let tm = mk::apps(mk::global(self.ids.index), [(Rel::Rel, t_tm), (Rel::Rel, base), (Rel::Rel, cast_int(ju)), (Rel::Irr, erased.clone()), (Rel::Irr, erased)]);
                self.eval(&tm)
            }
        }
    }

    /// A call `def args` whose argument `pos` is a slice of an assembled
    /// list.
    fn call(&mut self, def: GlobalId, args: &[Arg], pos: usize) -> Result<V, Stop> {
        let env = self.d.env;
        let tele = crate::opt::symex::telescope(env, def).ok_or(Stop::Keep)?;
        let dom = &tele.binders.get(pos).ok_or(Stop::Keep)?.2;
        let t_tm = slice_elem(env, dom).ok_or(Stop::Keep)?;
        let (list, _) = rel(&args[pos]).and_then(slice_parts).ok_or(Stop::Keep)?;
        let l_tm = self.quote(&list);
        let pieces = self.with_norm(t_tm.clone(), |n| Ok(n.norm(&l_tm)?.pieces))?;
        if pieces.iter().any(|p| matches!(p, Piece::Rep { .. })) || pieces.is_empty() {
            return Err(Stop::Keep);
        }
        if let [Piece::Seg { base, lo, n }] = pieces.as_slice() {
            // one piece: the function itself on a sub-slice
            let s = self.piece_slice(&t_tm, base, lo, n)?;
            let mut a2 = args.to_vec();
            a2[pos] = Arg::Rel(s);
            return Ok(Rc::new(Value::Neu(Neutral { head: Head::Global { def, args: a2 }, spine: vec![] })));
        }
        let shape: Vec<PK> = pieces.iter().map(|p| if matches!(p, Piece::Seg { .. }) { PK::Seg } else { PK::Elem }).collect();
        let key = SegKey { def, pos, shape };
        if self.reg.failed.contains(&key) {
            return Err(Stop::Keep);
        }
        let Some(entry) = self.reg.entries.get(&key).map(|e| e.entry) else {
            if self.d.trace {
                eprintln!("opt: drive: seq: requesting a segment specialization of {}", env.global_name(def).unwrap_or_default());
            }
            self.reg.requested.borrow_mut().insert(key);
            return Err(Stop::Keep);
        };
        let mut a2: Vec<Arg> = args[..pos].to_vec();
        let mut nseg = 0;
        for p in &pieces {
            match p {
                Piece::Seg { base, lo, n } => {
                    nseg += 1;
                    a2.push(Arg::Rel(self.piece_slice(&t_tm, base, lo, n)?));
                }
                Piece::Elem(x) => a2.push(Arg::Rel(self.eval(x)?)),
                Piece::Rep { .. } => unreachable!(),
            }
        }
        // the R9 fault: a helper's back-edge with its first and last
        // segments swapped
        if super::fault_fold_swap() && self.d.policy.seg_root() == Some(def) {
            let segs: Vec<usize> = pieces.iter().enumerate().filter(|(_, p)| matches!(p, Piece::Seg { .. })).map(|(k, _)| pos + k).collect();
            if let (Some(&a), Some(&b)) = (segs.first(), segs.last())
                && a != b
            {
                a2.swap(a, b);
            }
        }
        a2.extend(args[pos + 1..].iter().cloned());
        for _ in 0..nseg {
            a2.push(Arg::Irr(dummy()));
        }
        Ok(Rc::new(Value::Neu(Neutral { head: Head::Global { def: entry, args: a2 }, spine: vec![] })))
    }

    /// The printable slice of a `Seg` piece of a slice's list: the slice
    /// itself, or `&s[lo..]`, `&s[..n]`, `&s[lo..][..n]`.
    fn piece_slice(&mut self, t: &Tm, base: &Tm, lo: &Tm, n: &Tm) -> Result<V, Stop> {
        if self.d.trace {
            let names = self.path.st.names();
            eprintln!("opt: drive: seq: piece {} [{}; {}]", self.d.env.print_term(&names, base), self.d.env.print_term(&names, lo), self.d.env.print_term(&names, n));
        }
        let s_tm = slice_of_list_tm(base).ok_or(Stop::Keep)?;
        let len = mk::apps(mk::global(self.ids.len), [(Rel::Rel, t.clone()), (Rel::Rel, base.clone())]);
        let zero = mk::lit(Width::Int, 0);
        let eq = |a: Tm, b: Tm| mk::prim(PrimOp::Eq(Width::Int), vec![a, b], vec![]);
        let iadd = |a: Tm, b: Tm| mk::prim(PrimOp::IAdd, vec![a, b], vec![]);
        let from_start = matches!(&**lo, Term::Lit { n, .. } if n == &0.into()) || self.holds(&eq(lo.clone(), zero))?;
        let to_end = self.holds(&eq(iadd(lo.clone(), n.clone()), len))?;
        if from_start && to_end {
            return self.eval(&s_tm);
        }
        let take = |l: Tm, k: Tm| mk::apps(mk::global(self.ids.take), [(Rel::Rel, t.clone()), (Rel::Rel, l), (Rel::Rel, k)]);
        let drop = |l: Tm, k: Tm| mk::apps(mk::global(self.ids.drop), [(Rel::Rel, t.clone()), (Rel::Rel, l), (Rel::Rel, k)]);
        let n_u = usize_term(&self.ids, n).ok_or(Stop::Keep)?;
        let list = if from_start {
            take(base.clone(), cast_int(n_u.clone()))
        } else {
            let lo_u = usize_term(&self.ids, lo).ok_or(Stop::Keep)?;
            if to_end { drop(base.clone(), cast_int(lo_u)) } else { take(drop(base.clone(), cast_int(lo_u)), cast_int(n_u.clone())) }
        };
        let list_v = self.eval(&list)?;
        let n_v = self.eval(&n_u)?;
        Ok(Rc::new(Value::Pair { fst: n_v, snd: Arg::Rel(Rc::new(Value::Pair { fst: list_v, snd: Arg::Irr(dummy()) })) }))
    }

    /// Whether the facts show the comparison `c`.
    fn holds(&mut self, c: &Tm) -> Result<bool, Stop> {
        let cv = self.eval(c)?;
        if let Value::Ctor { ind, ctor, .. } = &*cv
            && *ind == self.d.bool_ind
        {
            return Ok(*ctor == 1);
        }
        let st = &self.path.st;
        Ok(self.d.decide_lin(st, c, &cv) == Some(true))
    }
}

/// `s` if the list term is `fst(snd(s))`.
pub fn slice_of_list_tm(t: &Tm) -> Option<Tm> {
    let Term::Fst(x) = &**t else { return None };
    let Term::Snd(s) = &**x else { return None };
    Some(s.clone())
}

fn cast_int(u: Tm) -> Tm {
    mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u], vec![])
}
