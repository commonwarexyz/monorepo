//! Word algebra: `BvRefl` and the word normalizer `bvnorm` (DESIGN.md §9.8).
//! **TRUSTED** (DESIGN.md §1.1).
//!
//! `bvrefl(ty, lhs, rhs) : Eq(ty, lhs, rhs)` is accepted iff the two sides
//! are equal modulo word algebra:
//!
//! 1. Both sides are first compared by ordinary conversion (so `BvRefl`
//!    accepts everything `refl` accepts).
//! 2. Otherwise both terms are evaluated in the `BvRefl` evaluation mode
//!    (`Ev::bv`): **transparent** — opaque definitions unfold (phase 3;
//!    unfolding is an identity, so this is sound, and it lets `BvRefl` prove
//!    a hardware variant equal to a portable function that is opaque
//!    because it contains loops, DESIGN.md §9.3) — and intrinsics unfold on
//!    symbolic data (§5.6); folded applications found in context values
//!    are unfolded too when the mode's policy unfolds them; array-typed
//!    variables are eta-expanded as everywhere in the kernel (§5.9).
//! 3. **One bottom-up pass over both value DAGs** (`Norm::visit`, an
//!    iterative post-order traversal, so nodes are finished in topological
//!    order): every node is normalized with its children replaced by their
//!    class ids, its canonical key is interned (hash-consing) to a class id,
//!    and atoms are ordered by class id (sets, sums and truth-table variables
//!    are sorted by class id). The node memo (address and depth → class,
//!    keeping every visited value alive, cf. §5.9) and the builder memo (op
//!    and argument classes → class) record every result, whether it later
//!    matches the other side or not, so shared and recomputed subterms (e.g.
//!    the Arm `SHA256H2` model recomputing `SHA256H`'s rounds) are normalized
//!    once. Classes are canonical by construction (a node's class is the
//!    class of its canonical key), so the union-find of §9.8 degenerates to
//!    interning: the two roots must land in the same class.
//! 4. **Tripwire** (module `tripwire`): before accepting, both *original* value
//!    DAGs are evaluated on 36 valuations of their free atoms — 4 corner
//!    valuations (every atom 0, ~0, 1, 0x80…0) and 32 pseudo-random ones —
//!    independently of the normalizer's rewriting; any mismatch rejects.
//!
//! **Depths.** A node is visited at a depth `d` such that it mentions only
//! variables below `d`; closures are instantiated with the fresh variable
//! `d` and their instances visited at `d + 1`. Keys of generic nodes combine
//! children visited at the node's own depth (and instances at `d + 1`), so
//! two nodes compared in corresponding positions of two keys are always at
//! the same depth, where equal classes mean equal values (the node memo is
//! keyed by address *and* depth for this reason).
//!
//! Generic nodes (binders, constructors, pairs, neutral heads and spines)
//! are keyed structurally with irrelevant positions skipped exactly as in
//! conversion (§5.3); closures (λ bodies, Π/Σ codomains, match arms,
//! transport motives) are instantiated with fresh variables at the current
//! depth, like conversion does, and keyed by the class of the instance;
//! match motives are ignored (as in conversion). Σ-η: a pair `(fst p, _)`
//! whose second component is irrelevant is the class of `p`. A match on a
//! `Bool` whose class is a constructor (a comparison that normalizes to
//! `true`/`false`) takes that arm.
//!
//! **One width per class.** A variable's class is its level, whatever its
//! type, so two binders at the same depth (sibling λs, the arms of a match)
//! share it. The word rules (support masks, rule 7's views) and the
//! tripwire's atom masks read a class's width, so a problem in which some
//! class is used at two widths (`Norm::width_clash`) is rejected.
//!
//! The word-algebra rules (§9.8 rules 1–7) live in the module `word`; see its module
//! documentation for the exact identities.

mod tripwire;
mod word;

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;

use crate::api::{Ctx, Env, KernelError, KernelErrorKind as K};
use crate::check::kerr;
use crate::eval::{Ev, clone_elim, clone_head, neu};
use crate::term::{AxiomId, DefKind, GlobalId, IndId, Lvl, Name, PrimOp, Rel, Sort, Tm, Width};
use crate::util::tick;
use crate::value::{Arg, Budget, Elim, EvalError, Head, Neutral, V, Value};

pub(crate) use word::mask;

type R<T> = Result<T, EvalError>;

/// A class id: an index into [`Norm::classes`].
pub(crate) type ClassId = u32;

/// Marker for an irrelevant position in a generic key (class ids are `u32`).
const IRR: u64 = u64::MAX;

// Tags of generic keys.
const T_SORT: u64 = 1;
const T_INTTY: u64 = 2;
const T_PI: u64 = 3;
const T_LAM: u64 = 4;
const T_SIGMA: u64 = 5;
const T_PAIR: u64 = 6;
const T_EQ: u64 = 7;
const T_REFL: u64 = 8;
const T_IND: u64 = 9;
const T_CTOR: u64 = 10;
const T_VAR: u64 = 11;
const T_GLOBAL: u64 = 12;
const T_AXIOM: u64 = 13;
const T_ABSURD: u64 = 14;
const T_TRANSPORT: u64 = 15;
const T_APP: u64 = 16;
const T_APPIRR: u64 = 17;
const T_FST: u64 = 18;
const T_SND: u64 = 19;
const T_MATCH: u64 = 20;

/// The canonical key of a class. Word-algebra keys (see [`word`]) are
/// normal forms; `Gen` keys are structural keys of generic nodes.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum Key {
    /// Machine literal (value in range).
    Lit(Width, u64),
    /// `Int` literal.
    IntLit(BigInt),
    /// GF(2)-linear form `c ⊕ ⨁ (rotr(atom, r) & m)` (rules 2, 3, 7).
    Lin(Width, u64, Vec<(ClassId, u32, u64)>),
    /// Canonical sum `c + Σ k·atom mod 2^w` (rule 6).
    Sum(Width, u64, Vec<(ClassId, u64)>),
    /// Truth table over ≤ 4 variables sorted by class id (rule 5).
    Tt(Width, Vec<ClassId>, u16),
    /// `and`/`or` sets sorted by class id (rule 4).
    And(Width, Vec<ClassId>),
    Or(Width, Vec<ClassId>),
    /// Zero-extension view of a base atom at a wider (or equally wide but
    /// differently typed) width (rule 7).
    Zext(Width, ClassId),
    /// Chunk `k` (bits `[k·w, (k+1)·w)`) of a wider base atom (rule 7).
    Chunk(Width, ClassId, u32),
    /// Any other primitive, on argument classes (commutative ops sorted).
    Prim(PrimOp, Vec<ClassId>),
    /// Generic structural node.
    Gen(Vec<u64>),
}

/// Per-class data.
pub(crate) struct ClassInfo {
    pub key: Key,
    /// Width of an integer class (`Int` for ghost integers); `None` for
    /// non-integers and for atoms not (yet) used under a primitive.
    pub width: Option<Width>,
    /// Bits that may be nonzero (integer classes whose form determines it).
    pub supp: Option<u64>,
    /// A value of the class (for diagnostics).
    pub repr: Option<(V, Lvl)>,
}

/// How a node combines its children (shared by the normalizer and the
/// tripwire, which must agree on the order of `kids`).
#[derive(Clone, Debug)]
pub(crate) enum Shape {
    Lit(Width, BigInt),
    /// kids = arguments.
    Prim(PrimOp),
    Sort(Sort),
    IntTy(Width),
    /// kids = [dom, cod instance].
    Pi(Rel),
    /// kids = [body instance].
    Lam(Rel),
    /// kids = [fst, snd instance].
    Sigma(Rel),
    /// kids = [fst] or [fst, snd].
    Pair(bool),
    /// kids = [p] for `(fst p, _)` with an irrelevant second component.
    PairEta,
    /// kids = [ty, lhs, rhs].
    Eq,
    Refl,
    /// kids = params.
    Ind(IndId),
    /// kids = params, then the relevant fields.
    Ctor {
        ind: IndId,
        ctor: u32,
        nparams: usize,
        rels: Vec<Rel>,
    },
    Var(Lvl),
    /// kids = relevant arguments.
    Global {
        def: GlobalId,
        rels: Vec<Rel>,
    },
    Axiom {
        ax: AxiomId,
        rels: Vec<Rel>,
    },
    /// kids = [ty].
    Absurd,
    /// kids = [ty, lhs, rhs, val, motive instance].
    Transport,
    /// kids = [prefix] (irrelevant argument) or [prefix, arg].
    App(bool),
    Fst,
    Snd,
    /// kids = [prefix], params, arm instances.
    Match {
        ind: IndId,
        nparams: usize,
        nfields: Vec<usize>,
    },
    /// kids = [the value of an intrinsic unfolded in the `BvRefl` mode].
    Unfolded,
}

/// A visited node: its shape, its children (node indices) and its class.
pub(crate) struct Node {
    pub shape: Shape,
    pub kids: Vec<u32>,
    pub class: ClassId,
}

fn addr(v: &V) -> usize {
    Rc::as_ptr(v) as *const () as usize
}

fn rel_code(r: Rel) -> u64 {
    match r {
        Rel::Rel => 0,
        Rel::Irr => 1,
    }
}

pub(crate) fn width_code(w: Width) -> u64 {
    match w {
        Width::U8 => 0,
        Width::U16 => 1,
        Width::U32 => 2,
        Width::U64 => 3,
        Width::Usize => 4,
        Width::Int => 5,
    }
}

/// The normalizer state for one `BvRefl` problem.
pub(crate) struct Norm<'e> {
    pub env: &'e Env,
    ev: Ev<'e>,
    pub classes: Vec<ClassInfo>,
    table: crate::util::FxMap<Key, ClassId>,
    /// Visited nodes in completion (topological) order.
    pub nodes: Vec<Node>,
    memo: crate::util::FxMap<(usize, u32), u32>,
    /// Keeps every memoized value alive (no address reuse, §5.9).
    keep: Vec<V>,
    /// Builder memo: primitive and argument classes → class.
    raw: crate::util::FxMap<(PrimOp, Vec<ClassId>), ClassId>,
    /// View memo: (base, width, chunk or `u32::MAX` for zero-extension).
    views: crate::util::FxMap<(ClassId, Width, u32), ClassId>,
    /// Distributed low chunks (rule 7): `lows[c] = b` iff class `c` was
    /// created by distributing the low chunk of the wider base atom `b`, so
    /// bit `j` of `c` is bit `j` of `b`. `b` is never a view and has no
    /// entry of its own.
    lows: crate::util::FxMap<ClassId, ClassId>,
    /// Some class was used at two widths: every entry point rejects.
    width_clash: bool,
}

/// Why a problem with a class used at two widths is not accepted.
const WIDTH_CLASH: &str = "not decided: a class is used at two machine widths (e.g. bound variables of different widths at the same depth, in sibling binders or match arms), and the word rules need one width per class";

impl<'e> Norm<'e> {
    fn new(env: &'e Env) -> Self {
        Norm {
            env,
            ev: Ev::bv(env).sharing(Default::default()),
            classes: Vec::new(),
            table: Default::default(),
            nodes: Vec::new(),
            memo: Default::default(),
            keep: Vec::new(),
            raw: Default::default(),
            views: Default::default(),
            lows: Default::default(),
            width_clash: false,
        }
    }

    /// Intern a key.
    pub(crate) fn intern(&mut self, key: Key, width: Option<Width>, supp: Option<u64>) -> ClassId {
        if let Some(&c) = self.table.get(&key) {
            return c;
        }
        let c = self.classes.len() as ClassId;
        self.classes.push(ClassInfo { key: key.clone(), width, supp, repr: None });
        self.table.insert(key, c);
        c
    }

    pub(crate) fn key(&self, c: ClassId) -> &Key {
        &self.classes[c as usize].key
    }

    /// The class of a field-less constructor of `ind`, if `c` is one.
    fn fieldless_ctor(&self, c: ClassId, ind: IndId) -> Option<usize> {
        // Layout: [T_CTOR, ind, ctor, nparams, params.., nargs, args..].
        match self.key(c) {
            Key::Gen(k) if k.len() >= 5 && k[0] == T_CTOR && k[1] == ind.0 as u64 => {
                let np = k[3] as usize;
                (k.len() == 5 + np && k[4 + np] == 0).then_some(k[2] as usize)
            }
            _ => None,
        }
    }

    /// The class of a Bool constructor value.
    pub(crate) fn bool_class(&mut self, b: bool) -> ClassId {
        let bi = self.env.bool_ind();
        self.intern(Key::Gen(vec![T_CTOR, bi.0 as u64, b as u64, 0, 0]), None, None)
    }

    // -----------------------------------------------------------------------
    // The bottom-up pass.
    // -----------------------------------------------------------------------

    /// Visit the DAG of `root` (at depth `d`) bottom-up; returns its node.
    pub(crate) fn visit(&mut self, root: &V, d: Lvl, b: &mut crate::value::Budget) -> R<u32> {
        struct Frame {
            v: V,
            d: Lvl,
            st: Option<(Shape, Vec<(V, Lvl)>)>,
            done: Vec<u32>,
        }
        if let Some(&i) = self.memo.get(&(addr(root), d.0)) {
            return Ok(i);
        }
        let mut stack = vec![Frame { v: root.clone(), d, st: None, done: Vec::new() }];
        let mut result = 0;
        while !stack.is_empty() {
            tick(b)?;
            let top = stack.len() - 1;
            if stack[top].st.is_none() {
                let (v, d) = (stack[top].v.clone(), stack[top].d);
                if let Some(&i) = self.memo.get(&(addr(&v), d.0)) {
                    stack.pop();
                    result = i;
                    continue;
                }
                let x = self.expand(&v, d, b)?;
                stack[top].st = Some(x);
                continue;
            }
            let next = {
                let f = &stack[top];
                let kids = &f.st.as_ref().expect("expanded").1;
                kids.get(f.done.len()).cloned()
            };
            if let Some((kv, kd)) = next {
                match self.memo.get(&(addr(&kv), kd.0)) {
                    Some(&i) => stack[top].done.push(i),
                    None => stack.push(Frame { v: kv, d: kd, st: None, done: Vec::new() }),
                }
                continue;
            }
            let f = stack.pop().expect("nonempty");
            let (shape, _) = f.st.expect("expanded");
            let kid_classes: Vec<ClassId> = f.done.iter().map(|&i| self.nodes[i as usize].class).collect();
            let class = self.build(&shape, &kid_classes);
            if self.classes[class as usize].repr.is_none() {
                self.classes[class as usize].repr = Some((f.v.clone(), f.d));
            }
            let idx = self.nodes.len() as u32;
            self.nodes.push(Node { shape, kids: f.done, class });
            self.memo.insert((addr(&f.v), f.d.0), idx);
            self.keep.push(f.v);
            result = idx;
            if let Some(parent) = stack.last_mut() {
                parent.done.push(idx);
            }
        }
        Ok(result)
    }

    /// The shape and children of a value (closures instantiated with fresh
    /// variables at depth `d`).
    fn expand(&mut self, v: &V, d: Lvl, b: &mut crate::value::Budget) -> R<(Shape, Vec<(V, Lvl)>)> {
        let d1 = Lvl(d.0 + 1);
        Ok(match &**v {
            Value::Sort(s) => (Shape::Sort(*s), vec![]),
            Value::IntTy(w) => (Shape::IntTy(*w), vec![]),
            Value::Lit { w, n } => (Shape::Lit(*w, n.clone()), vec![]),
            Value::Pi { rel, dom, cod, .. } => {
                let x = self.ev.fresh(d, *rel, dom);
                let c = self.ev.inst_root(cod, x, d1, b)?;
                (Shape::Pi(*rel), vec![(dom.clone(), d), (c, d1)])
            }
            Value::Lam { rel, dom, body, .. } => {
                let x = self.ev.fresh(d, *rel, dom);
                let c = self.ev.inst_root(body, x, d1, b)?;
                (Shape::Lam(*rel), vec![(c, d1)])
            }
            Value::Sigma { snd_rel, fst, snd, .. } => {
                let x = self.ev.fresh(d, Rel::Rel, fst);
                let c = self.ev.inst_root(snd, x, d1, b)?;
                (Shape::Sigma(*snd_rel), vec![(fst.clone(), d), (c, d1)])
            }
            Value::Pair { fst, snd } => match snd {
                Arg::Irr(_) => match fst_prefix(fst) {
                    Some(p) => (Shape::PairEta, vec![(p, d)]),
                    None => (Shape::Pair(false), vec![(fst.clone(), d)]),
                },
                Arg::Rel(s) => (Shape::Pair(true), vec![(fst.clone(), d), (s.clone(), d)]),
            },
            Value::Eq { ty, lhs, rhs } => (Shape::Eq, vec![(ty.clone(), d), (lhs.clone(), d), (rhs.clone(), d)]),
            Value::Refl { .. } => (Shape::Refl, vec![]),
            Value::Ind { ind, params } => (Shape::Ind(*ind), params.iter().map(|p| (p.clone(), d)).collect()),
            Value::Ctor { ind, ctor, params, args } => {
                let mut kids: Vec<(V, Lvl)> = params.iter().map(|p| (p.clone(), d)).collect();
                let mut rels = Vec::with_capacity(args.len());
                for a in args {
                    match a {
                        Arg::Rel(x) => {
                            rels.push(Rel::Rel);
                            kids.push((x.clone(), d));
                        }
                        Arg::Irr(_) => rels.push(Rel::Irr),
                    }
                }
                (Shape::Ctor { ind: *ind, ctor: *ctor, nparams: params.len(), rels }, kids)
            }
            Value::Neu(n) => self.expand_neutral(n, d, b)?,
        })
    }

    fn expand_neutral(&mut self, n: &Neutral, d: Lvl, b: &mut crate::value::Budget) -> R<(Shape, Vec<(V, Lvl)>)> {
        if let Some(last) = n.spine.last() {
            let prefix = neu(clone_head(&n.head), n.spine[..n.spine.len() - 1].iter().map(clone_elim).collect());
            return Ok(match last {
                Elim::App(Arg::Rel(a)) => (Shape::App(false), vec![(prefix, d), (a.clone(), d)]),
                Elim::App(Arg::Irr(_)) => (Shape::App(true), vec![(prefix, d)]),
                Elim::Fst => (Shape::Fst, vec![(prefix, d)]),
                Elim::Snd => (Shape::Snd, vec![(prefix, d)]),
                Elim::Match { ind, params, arms, .. } => {
                    let mut kids = vec![(prefix, d)];
                    kids.extend(params.iter().map(|p| (p.clone(), d)));
                    let mut nfields = Vec::with_capacity(arms.len());
                    for (k, arm) in arms.iter().enumerate() {
                        // Fields introduced as everywhere else (array
                        // fields eta-expanded, §5.9; `Ev::arm_fields`).
                        let es = self.ev.arm_fields(d, *ind, k as u32, params, b)?;
                        let nf = es.len();
                        let dk = Lvl(d.0 + nf as u32);
                        let v = self.ev.inst_n_root(arm, es, dk, b)?;
                        nfields.push(nf);
                        kids.push((v, dk));
                    }
                    (Shape::Match { ind: *ind, nparams: params.len(), nfields }, kids)
                }
            });
        }
        let args_kids = |args: &[Arg]| {
            let mut rels = Vec::with_capacity(args.len());
            let mut kids = Vec::new();
            for a in args {
                match a {
                    Arg::Rel(x) => {
                        rels.push(Rel::Rel);
                        kids.push((x.clone(), d));
                    }
                    Arg::Irr(_) => rels.push(Rel::Irr),
                }
            }
            (rels, kids)
        };
        Ok(match &n.head {
            Head::Var(l) => (Shape::Var(*l), vec![]),
            Head::Global { def, args } => {
                // A folded application found in a value (e.g. a context
                // value computed in the checking mode, where opaque
                // definitions and intrinsics on symbolic data stay folded):
                // apply the `BvRefl` mode's policy to it; if it unfolds, the
                // node is its unfolding. (Non-opaque recursive applications
                // were already refused by the same policy.)
                let info = self.env.defs.get(def.0 as usize);
                let retry =
                    info.is_some_and(|i| i.arity as usize == args.len() && (i.kind == DefKind::Intrinsic || i.opaque || !i.is_recursive()));
                let unfolded = if retry {
                    let u = self.ev.apply_global_full(*def, args.clone(), d, b)?;
                    let same =
                        matches!(&*u, Value::Neu(Neutral { head: Head::Global { def: d2, .. }, spine }) if d2 == def && spine.is_empty());
                    if same { None } else { Some(u) }
                } else {
                    None
                };
                match unfolded {
                    Some(u) => (Shape::Unfolded, vec![(u, d)]),
                    None => {
                        let (rels, kids) = args_kids(args);
                        (Shape::Global { def: *def, rels }, kids)
                    }
                }
            }
            Head::Prim { op, args, .. } => (Shape::Prim(*op), args.iter().map(|a| (a.clone(), d)).collect()),
            Head::Absurd { ty } => (Shape::Absurd, vec![(ty.clone(), d)]),
            Head::Transport { ty, lhs, rhs, motive, val } => {
                let y = self.ev.fresh(d, Rel::Rel, ty);
                let m = self.ev.inst(motive, y, Lvl(d.0 + 1), b)?;
                (Shape::Transport, vec![(ty.clone(), d), (lhs.clone(), d), (rhs.clone(), d), (val.clone(), d), (m, Lvl(d.0 + 1))])
            }
            Head::Axiom { ax, args } => {
                let (rels, kids) = args_kids(args);
                (Shape::Axiom { ax: *ax, rels }, kids)
            }
        })
    }

    /// The class of a node from its shape and its children's classes.
    fn build(&mut self, shape: &Shape, k: &[ClassId]) -> ClassId {
        let gk = |mut v: Vec<u64>, rest: &[ClassId]| {
            v.extend(rest.iter().map(|&c| c as u64));
            Key::Gen(v)
        };
        let key = match shape {
            Shape::Lit(w, n) => {
                return if *w == Width::Int {
                    self.intern(Key::IntLit(n.clone()), Some(Width::Int), None)
                } else {
                    self.lit(*w, n.to_u64().unwrap_or(0))
                };
            }
            Shape::Prim(op) => return self.prim(*op, k),
            Shape::Unfolded | Shape::PairEta => return k[0],
            Shape::Match { ind, nparams, nfields } => {
                // Only `Bool` scrutinees can become constructors through
                // normalization (comparisons); the tripwire evaluates exactly
                // these matches arm by arm.
                if *ind == self.env.bool_ind()
                    && let Some(c) = self.fieldless_ctor(k[0], *ind)
                    && nfields.get(c) == Some(&0)
                {
                    return k[1 + nparams + c];
                }
                let mut v = vec![T_MATCH, ind.0 as u64, k[0] as u64, *nparams as u64];
                v.extend(k[1..1 + nparams].iter().map(|&c| c as u64));
                v.push(nfields.len() as u64);
                gk(v, &k[1 + nparams..])
            }
            Shape::Sort(s) => Key::Gen(vec![T_SORT, matches!(s, Sort::Kind) as u64]),
            Shape::IntTy(w) => Key::Gen(vec![T_INTTY, width_code(*w)]),
            Shape::Pi(r) => gk(vec![T_PI, rel_code(*r)], k),
            Shape::Lam(r) => gk(vec![T_LAM, rel_code(*r)], k),
            Shape::Sigma(r) => gk(vec![T_SIGMA, rel_code(*r)], k),
            Shape::Pair(true) => gk(vec![T_PAIR], k),
            Shape::Pair(false) => Key::Gen(vec![T_PAIR, k[0] as u64, IRR]),
            Shape::Eq => gk(vec![T_EQ], k),
            Shape::Refl => Key::Gen(vec![T_REFL]),
            Shape::Ind(ind) => gk(vec![T_IND, ind.0 as u64, k.len() as u64], k),
            Shape::Ctor { ind, ctor, nparams, rels } => {
                let mut v = vec![T_CTOR, ind.0 as u64, *ctor as u64, *nparams as u64];
                v.extend(k[..*nparams].iter().map(|&c| c as u64));
                v.push(rels.len() as u64);
                push_rel_args(&mut v, rels, &k[*nparams..]);
                Key::Gen(v)
            }
            Shape::Var(l) => Key::Gen(vec![T_VAR, l.0 as u64]),
            Shape::Global { def, rels } => {
                let mut v = vec![T_GLOBAL, def.0 as u64, rels.len() as u64];
                push_rel_args(&mut v, rels, k);
                Key::Gen(v)
            }
            Shape::Axiom { ax, rels } => {
                let mut v = vec![T_AXIOM, ax.0 as u64, rels.len() as u64];
                push_rel_args(&mut v, rels, k);
                Key::Gen(v)
            }
            Shape::Absurd => gk(vec![T_ABSURD], k),
            Shape::Transport => gk(vec![T_TRANSPORT], k),
            Shape::App(false) => gk(vec![T_APP], k),
            Shape::App(true) => gk(vec![T_APPIRR], k),
            Shape::Fst => gk(vec![T_FST], k),
            Shape::Snd => gk(vec![T_SND], k),
        };
        self.intern(key, None, None)
    }

    // -----------------------------------------------------------------------
    // Diagnostics.
    // -----------------------------------------------------------------------

    /// Render a class (bounded size) for error messages.
    pub(crate) fn show(&self, c: ClassId, names: &[Name], fuel: &mut usize) -> String {
        if *fuel == 0 {
            return "…".into();
        }
        *fuel -= 1;
        let hex = |x: u64| format!("{x:#x}");
        match self.key(c).clone() {
            Key::Lit(_, n) => hex(n),
            Key::IntLit(n) => format!("{n}int"),
            Key::Lin(_, k, t) => {
                let mut parts: Vec<String> = t
                    .iter()
                    .map(|&(a, r, m)| {
                        let a = self.show(a, names, fuel);
                        let a = if r == 0 { a } else { format!("rotr({a}, {r})") };
                        format!("({a} & {})", hex(m))
                    })
                    .collect();
                if k != 0 {
                    parts.push(hex(k));
                }
                format!("[{}]", parts.join(" ^ "))
            }
            Key::Sum(_, k, t) => {
                let mut parts: Vec<String> = t.iter().map(|&(a, m)| format!("{}*{}", hex(m), self.show(a, names, fuel))).collect();
                if k != 0 {
                    parts.push(hex(k));
                }
                format!("[{}]", parts.join(" + "))
            }
            Key::Tt(_, vars, tt) => {
                format!("tt{:#06x}({})", tt, vars.iter().map(|&v| self.show(v, names, fuel)).collect::<Vec<_>>().join(", "))
            }
            Key::And(_, ops) => format!("and({})", ops.iter().map(|&v| self.show(v, names, fuel)).collect::<Vec<_>>().join(", ")),
            Key::Or(_, ops) => format!("or({})", ops.iter().map(|&v| self.show(v, names, fuel)).collect::<Vec<_>>().join(", ")),
            Key::Zext(w, bse) => format!("zext_{}({})", crate::prim::width_suffix(w), self.show(bse, names, fuel)),
            Key::Chunk(w, bse, k) => format!("chunk_{}[{k}]({})", crate::prim::width_suffix(w), self.show(bse, names, fuel)),
            Key::Prim(op, args) => {
                format!(
                    "#{}({})",
                    crate::prim::prim_name(op),
                    args.iter().map(|&v| self.show(v, names, fuel)).collect::<Vec<_>>().join(", ")
                )
            }
            Key::Gen(_) => match &self.classes[c as usize].repr {
                Some((v, d)) => {
                    let t = crate::quote::Quoter::bounded(self.env, Vec::new(), 60).quote_root(*d, v, None, false);
                    let mut ns: Vec<Name> = names.to_vec();
                    while ns.len() < d.0 as usize {
                        ns.push(Rc::from(format!("x{}", ns.len()).as_str()));
                    }
                    let s = self.env.print_term(&ns[..d.0 as usize], &t);
                    if s.len() > 80 { format!("{}…", &s[..s.char_indices().nth(80).map(|x| x.0).unwrap_or(s.len())]) } else { s }
                }
                None => format!("c{c}"),
            },
        }
    }
}

/// Push the arguments of a telescope: a class for a relevant one, [`IRR`]
/// for an irrelevant one.
fn push_rel_args(v: &mut Vec<u64>, rels: &[Rel], kids: &[ClassId]) {
    let mut it = kids.iter();
    for r in rels {
        match r {
            Rel::Rel => v.push(it.next().map(|&c| c as u64).unwrap_or(IRR - 1)),
            Rel::Irr => v.push(IRR),
        }
    }
}

/// `p` if `fst` is the neutral `fst p`.
fn fst_prefix(fst: &V) -> Option<V> {
    match &**fst {
        Value::Neu(n) if matches!(n.spine.last(), Some(Elim::Fst)) => {
            Some(neu(clone_head(&n.head), n.spine[..n.spine.len() - 1].iter().map(clone_elim).collect()))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

/// Options of [`decide`].
#[derive(Clone, Copy, Debug)]
pub struct BvOptions {
    /// Run the tripwire before accepting (the checker always does; tests
    /// disable it to exercise the normalizer alone).
    pub tripwire: bool,
}

impl Default for BvOptions {
    fn default() -> Self {
        BvOptions { tripwire: true }
    }
}

/// Outcome of [`decide`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BvVerdict {
    /// Equal by conversion or by the normalizer (and the tripwire agreed).
    Equal,
    /// The normal forms differ (the message shows both), or some class is
    /// used at two widths (not decided; the message says so).
    Different(String),
    /// The normal forms agree but the tripwire found a valuation on which the
    /// sides differ (a normalizer bug; the equation is rejected).
    TripwireMismatch(String),
}

/// Decide `lhs ≡ rhs` modulo word algebra in context `ctx` (DESIGN.md
/// §9.8), without type checking the terms (the checker does that before
/// calling it). This is exactly the test the kernel applies to
/// `bvrefl(ty, lhs, rhs)` when `opts.tripwire` is set.
pub fn decide(env: &Env, ctx: &Ctx, lhs: &Tm, rhs: &Tm, opts: BvOptions, b: &mut Budget) -> Result<BvVerdict, KernelError> {
    let _guard = crate::util::StackGuard::enter();
    let cx = crate::check::cx_of_ctx(env, ctx);
    let names = cx.names();
    decide_in(env, &cx.venv, cx.depth(), &names, lhs, rhs, None, opts, b)
}

/// Compare `lhs`/`rhs` by conversion (on their default-mode values, given
/// or computed), then evaluate them in the `BvRefl` mode and compare by
/// normalization (and the tripwire).
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_in(
    env: &Env,
    venv: &crate::value::VEnv,
    depth: Lvl,
    names: &[Name],
    lhs: &Tm,
    rhs: &Tm,
    values: Option<(&V, &V)>,
    opts: BvOptions,
    b: &mut Budget,
) -> Result<BvVerdict, KernelError> {
    let (lv, rv) = match values {
        Some((l, r)) => (l.clone(), r.clone()),
        None => (Ev::new(env).eval(venv, depth, lhs, b)?, Ev::new(env).eval(venv, depth, rhs, b)?),
    };
    if crate::conv::Conv::new(env).conv(depth, &lv, &rv, b)? {
        return Ok(BvVerdict::Equal);
    }
    drop((lv, rv));
    let mut norm = Norm::new(env);
    norm.ev.register(venv);
    let lv = norm.ev.eval(venv, depth, lhs, b)?;
    let rv = norm.ev.eval(venv, depth, rhs, b)?;
    let li = norm.visit(&lv, depth, b)?;
    let ri = norm.visit(&rv, depth, b)?;
    if norm.width_clash {
        return Ok(BvVerdict::Different(WIDTH_CLASH.into()));
    }
    let (lc, rc) = (norm.nodes[li as usize].class, norm.nodes[ri as usize].class);
    if lc != rc {
        let (mut f1, mut f2) = (40usize, 40usize);
        return Ok(BvVerdict::Different(format!(
            "normal forms differ:\n  lhs: {}\n  rhs: {}",
            norm.show(lc, names, &mut f1),
            norm.show(rc, names, &mut f2)
        )));
    }
    if opts.tripwire
        && let Some(msg) = tripwire::check(&norm, li, ri, b)?
    {
        return Ok(BvVerdict::TripwireMismatch(msg));
    }
    Ok(BvVerdict::Equal)
}

/// Normalize several terms (of the same context) in **one** normalizer and
/// return their class ids: equal ids mean equal modulo word algebra (the
/// verdict [`decide`] gives without the tripwire, for any pair; an error if
/// some class is used at two widths). Used by the exhaustive soundness tests
/// and available to automation for bucketing.
pub fn classify(env: &Env, ctx: &Ctx, terms: &[Tm], b: &mut Budget) -> Result<Vec<u32>, KernelError> {
    let _guard = crate::util::StackGuard::enter();
    let cx = crate::check::cx_of_ctx(env, ctx);
    let mut norm = Norm::new(env);
    norm.ev.register(&cx.venv);
    let mut out = Vec::with_capacity(terms.len());
    for t in terms {
        let v = norm.ev.eval(&cx.venv, cx.depth(), t, b)?;
        let i = norm.visit(&v, cx.depth(), b)?;
        out.push(norm.nodes[i as usize].class);
    }
    if norm.width_clash {
        return Err(kerr(K::BvRefl, WIDTH_CLASH));
    }
    Ok(out)
}

/// Run only the tripwire on `lhs`/`rhs` (both evaluated in the `BvRefl`
/// mode): `Ok(true)` iff they agree on every tripwire valuation (an error if
/// some class is used at two widths). For tests of the tripwire itself.
pub fn tripwire_agrees(env: &Env, ctx: &Ctx, lhs: &Tm, rhs: &Tm, b: &mut Budget) -> Result<bool, KernelError> {
    let _guard = crate::util::StackGuard::enter();
    let cx = crate::check::cx_of_ctx(env, ctx);
    let mut norm = Norm::new(env);
    norm.ev.register(&cx.venv);
    let lv = norm.ev.eval(&cx.venv, cx.depth(), lhs, b)?;
    let rv = norm.ev.eval(&cx.venv, cx.depth(), rhs, b)?;
    let li = norm.visit(&lv, cx.depth(), b)?;
    let ri = norm.visit(&rv, cx.depth(), b)?;
    if norm.width_clash {
        return Err(kerr(K::BvRefl, WIDTH_CLASH));
    }
    Ok(tripwire::check(&norm, li, ri, b)?.is_none())
}

/// The kernel's `BvRefl` rule on checked sides with their default-mode
/// values: `Ok(())` iff accepted.
pub(crate) fn check_bvrefl(
    env: &Env,
    cx: &crate::check::Cx,
    lhs: &Tm,
    rhs: &Tm,
    lv: &V,
    rv: &V,
    b: &mut Budget,
) -> Result<(), KernelError> {
    let names = cx.names();
    match decide_in(env, &cx.venv, cx.depth(), &names, lhs, rhs, Some((lv, rv)), BvOptions::default(), b)? {
        BvVerdict::Equal => Ok(()),
        BvVerdict::Different(m) => Err(kerr(K::BvRefl, format!("bvrefl: the sides are not equal modulo word algebra (§9.8); {m}"))),
        BvVerdict::TripwireMismatch(m) => Err(kerr(K::BvRefl, format!("bvrefl: rejected by the tripwire (§9.8): {m}"))),
    }
}
