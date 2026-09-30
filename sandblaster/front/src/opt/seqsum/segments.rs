//! The segment normal form (optimizer design §8.1) and its proofs.
//!
//! A list term is rewritten into **pieces** joined by `append`:
//!
//! | piece | canonical term | valid when |
//! | --- | --- | --- |
//! | `Seg { base, lo, n }` | `take(drop(base, lo), n)` | `0 ≤ lo`, `0 ≤ n`, `lo + n ≤ len base` |
//! | `Elem(x)` | `Cons(x, _)` | — |
//! | `Rep { v, n }` | `replicate(n, v)` | `0 < n` (empty ones are dropped) |
//!
//! `canon([p₁, …, pₖ])` is `p₁ ++ (p₂ ++ … (pₖ ++ []))`, an `Elem` consing
//! directly. A `Seg` base is an **atom**: a list the rules do not decompose
//! (a slice's list `fst(snd(s))`, a variable). Every normalization step is an
//! instance of a lemma of `lemmas/seq.core`; its side conditions are linear
//! comparisons over the pieces' bounds, decided by the [`Oracle`] (the
//! path's facts). A comparison the oracle cannot decide is
//! [`NormErr::Undecided`]: the driver splits on it (a demand split), the
//! proof builder fails the leaf.
//!
//! [`Norm`] builds the proof `Eq(List T, input, canon(pieces))` when its
//! oracle builds proofs (the proof builder), and only the pieces otherwise
//! (the driver). Everything is untrusted: the kernel checks the proof.

use std::collections::HashMap;
use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use crate::auto::util::shift;

/// The globals the normal form works with.
#[derive(Clone, Debug)]
pub struct Ids {
    pub take: GlobalId,
    pub drop: GlobalId,
    pub append: GlobalId,
    pub update: GlobalId,
    pub replicate: GlobalId,
    pub index: GlobalId,
    pub len: GlobalId,
    pub list: IndId,
    pub bool_ind: IndId,
    pub slice_mk: GlobalId,
    pub slice_ext: GlobalId,
    pub slice_ok_len: GlobalId,
    pub eq_trans: GlobalId,
    pub eq_sym: GlobalId,
    pub eq_cong: GlobalId,
    /// The prelude's slice and array constructors (kept folded by the leaf
    /// proofs' evaluation, unfolded definitionally by [`Norm::view`]).
    pub slice_suffix: GlobalId,
    pub slice_prefix: GlobalId,
    pub slice_range: GlobalId,
    pub array_as_slice: GlobalId,
    pub array_copy_range: Option<GlobalId>,
    pub array_set: GlobalId,
    pub array_repeat: GlobalId,
    /// The prelude's element reads (`s[i]`, `a[i]`: `seq::index` of the
    /// list, definitionally).
    pub slice_index: GlobalId,
    pub array_index: GlobalId,
    /// The type former `Array` (element types read back from values are
    /// refolded to it, see [`Ids::refold`]).
    pub array_ty: GlobalId,
    lemmas: HashMap<&'static str, GlobalId>,
}

/// The `seq.core` lemmas used by the normalizer.
const LEMMAS: &[&str] = &[
    "seq::take_cons_pos",
    "seq::take_cons_nonpos",
    "seq::drop_cons_pos",
    "seq::take_nonpos",
    "seq::drop_nonpos",
    "seq::replicate_nonpos",
    "seq::append_assoc",
    "seq::append_nil",
    "seq::update_neg",
    "seq::update_cons_eq",
    "seq::update_cons_ne",
    "seq::seg_atom",
    "seq::seg_len",
    "seq::seg_empty",
    "seq::rep_empty",
    "seq::take_seg_full",
    "seq::take_seg_part",
    "seq::drop_seg_full",
    "seq::drop_seg_part",
    "seq::take_rep_full",
    "seq::drop_rep_full",
    "seq::drop_rep_part",
    "seq::update_seg_right",
    "seq::update_rep_right",
    "seq::update_rep_mid",
    "seq::index_cons_zero",
    "seq::index_cons_succ",
    "seq::index_seg_in",
    "seq::index_seg_after",
    "seq::index_rep_in",
    "seq::index_rep_after",
    "seq::index_at_eq",
    "seq::index_list_eq",
    "seq::len_append",
    "seq::len_replicate",
];

impl Ids {
    /// `None` when the prelude is not loaded. The `seq.core` lemmas may be
    /// missing (the driver needs none: [`Ids::has_lemmas`]; they are loaded
    /// on the first segment specialization, see [`super::ensure_lemmas`]).
    pub fn new(env: &Env) -> Option<Ids> {
        let g = |n: &str| env.lookup_global(n);
        let mut lemmas = HashMap::new();
        for n in LEMMAS {
            if let Some(x) = g(n) {
                lemmas.insert(*n, x);
            }
        }
        Some(Ids {
            take: g("seq::take")?,
            drop: g("seq::drop")?,
            append: g("seq::append")?,
            update: g("seq::update")?,
            replicate: g("seq::replicate")?,
            index: g("seq::index")?,
            len: g("seq::len")?,
            list: env.lookup_ind("List")?,
            bool_ind: env.bool_ind(),
            slice_mk: g("slice::mk")?,
            slice_ext: g("slice::ext")?,
            slice_ok_len: g("slice::ok_len")?,
            eq_trans: g("eq::trans")?,
            eq_sym: g("eq::sym")?,
            eq_cong: g("eq::cong")?,
            slice_suffix: g("slice::suffix")?,
            slice_prefix: g("slice::prefix")?,
            slice_range: g("slice::range")?,
            array_as_slice: g("array::as_slice")?,
            array_copy_range: g("array::copy_range"),
            array_set: g("array::set")?,
            array_repeat: g("array::repeat")?,
            slice_index: g("slice::index")?,
            array_index: g("array::index")?,
            array_ty: g("Array")?,
            lemmas,
        })
    }

    /// The constructors a leaf proof keeps folded (their results read back
    /// as applications, never as pairs).
    pub fn constructors(&self) -> Vec<GlobalId> {
        let mut v = vec![self.slice_mk, self.slice_suffix, self.slice_prefix, self.slice_range, self.array_as_slice, self.array_set, self.array_repeat];
        v.extend(self.array_copy_range);
        v
    }

    pub fn lemma(&self, n: &str) -> GlobalId {
        self.lemmas[n]
    }

    /// Whether the `seq.core` lemmas the proofs use are loaded.
    pub fn has_lemmas(&self) -> bool {
        self.lemmas.len() == LEMMAS.len()
    }

    /// `t` (a type read back from a value) with every unfolded array type
    /// `Σ(l : List X). .Eq(Int, len X l, N)` written `Array X N` again
    /// (definitionally equal; the atoms of the normal form's comparisons
    /// then match the facts', which name the type former).
    pub fn refold(&self, t: &Tm) -> Tm {
        crate::auto::util::map_term(t, 0, &mut |x, _| {
            let Term::Sigma { snd_rel: Rel::Irr, fst, snd, .. } = &**x else { return None };
            let Term::Ind { ind, params } = &**fst else { return None };
            if *ind != self.list || params.len() != 1 {
                return None;
            }
            let Term::Eq { ty, lhs, rhs } = &**snd else { return None };
            if !matches!(&**ty, Term::IntTy(Width::Int)) {
                return None;
            }
            let (g, args) = head_app(lhs)?;
            if g != self.len || args.len() != 2 || !matches!(&*args[1].1, Term::Var(sandblaster_kernel::term::Idx(0))) {
                return None;
            }
            let n = match &**rhs {
                Term::Lit { w: Width::Int, n } => mk::lit(Width::Usize, n.clone()),
                Term::Prim { op: PrimOp::Cast { from: Width::Usize, to: Width::Int }, args, .. } if args.len() == 1 => shift(&args[0], -1),
                _ => return None,
            };
            let x_ty = self.refold(&params[0]);
            Some(mk::apps(mk::global(self.array_ty), [(Rel::Rel, x_ty), (Rel::Rel, n)]))
        })
    }
}

/// One piece of the normal form (terms in the context of the normalization).
#[derive(Clone, Debug)]
pub enum Piece {
    Seg { base: Tm, lo: Tm, n: Tm },
    Elem(Tm),
    Rep { v: Tm, n: Tm },
}

impl Piece {
    pub fn kind(&self) -> &'static str {
        match self {
            Piece::Seg { .. } => "Seg",
            Piece::Elem(_) => "Elem",
            Piece::Rep { .. } => "Rep",
        }
    }
}

/// Why a normalization stopped.
#[derive(Clone, Debug)]
pub enum NormErr {
    /// A side condition the facts do not decide: the boolean comparison
    /// term (over `Int`).
    Undecided(Tm),
    Unsupported(String),
}

impl std::fmt::Display for NormErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NormErr::Undecided(_) => write!(f, "a length comparison the facts do not decide"),
            NormErr::Unsupported(s) => write!(f, "{s}"),
        }
    }
}

type R<T> = Result<T, NormErr>;

/// Decides the side conditions (linear comparisons over the path's facts).
pub trait Oracle {
    /// The value of the boolean term `c` (a comparison of `Int` terms) and,
    /// when proofs are built, a proof of `Eq(Bool, c, value)`.
    fn decide(&mut self, c: &Tm) -> Option<(bool, Option<Tm>)>;
    /// A proof of the proposition `goal` (`Eq(Int, a, b)` or `Eq(Bool, c,
    /// true)`) from the facts and the extra hypotheses `(proof, type)`;
    /// `Some(None)` when the oracle builds no proofs but the goal holds.
    fn prove(&mut self, goal: &Tm, extra: &[(Tm, Tm)]) -> Option<Option<Tm>>;
    /// Whether proofs are built.
    fn proofs(&self) -> bool;
    /// Whether the kernel accepts `p` as a proof of `goal` at the oracle's
    /// state (a `linarith` claim whose certificate the kernel searches).
    fn accepts(&mut self, _p: &Tm, _goal: &Tm) -> bool {
        true
    }
}

/// A normalized list: its pieces and (with proofs) `Eq(List T, input,
/// canon(pieces))`.
#[derive(Clone, Debug)]
pub struct Normed {
    pub pieces: Vec<Piece>,
    pub proof: Option<Tm>,
}

/// The value of an element read after normalization.
#[derive(Clone, Debug)]
pub enum Elem {
    /// A written or replicated value.
    Val(Tm),
    /// `index(base, j, g0, g1)` of an atom.
    At { base: Tm, j: Tm, g0: Tm, g1: Tm },
}

/// The normalizer (see the module docs).
pub struct Norm<'a> {
    pub env: &'a Env,
    pub ids: &'a Ids,
    /// The element type.
    pub t: Tm,
    pub oracle: &'a mut dyn Oracle,
}

// ---------------------------------------------------------------------------
// Terms.
// ---------------------------------------------------------------------------

/// Whether `t` has no free variable.
pub fn closed(t: &Tm) -> bool {
    !crate::elab::tm::any_node_depth(t, &mut |n, depth| matches!(n, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= depth))
}

fn iadd(a: Tm, b: Tm) -> Tm {
    mk::prim(PrimOp::IAdd, vec![a, b], vec![])
}

fn isub(a: Tm, b: Tm) -> Tm {
    mk::prim(PrimOp::ISub, vec![a, b], vec![])
}

fn lit(n: i64) -> Tm {
    mk::lit(Width::Int, n)
}

/// `(g, args)` of a global application term.
pub fn head_app(t: &Tm) -> Option<(GlobalId, Vec<(Rel, Tm)>)> {
    let mut args = Vec::new();
    let mut h = t;
    while let Term::App { rel, fun, arg } = &**h {
        args.push((*rel, arg.clone()));
        h = fun;
    }
    let Term::Global(g) = &**h else { return None };
    args.reverse();
    Some((*g, args))
}

/// The literal of an `Int` term.
pub fn int_lit(t: &Tm) -> Option<BigInt> {
    match &**t {
        Term::Lit { n, .. } => Some(n.clone()),
        _ => None,
    }
}

/// The shape of a list term.
enum View {
    Nil,
    Cons(Tm, Tm),
    Append(Tm, Tm),
    Take(Tm, Tm),
    Drop(Tm, Tm),
    Update(Tm, Tm, Tm),
    Replicate(Tm, Tm),
    /// A definitionally equal term (a constructor's list).
    Alias(Tm),
    Atom,
}

impl<'a> Norm<'a> {
    pub fn proofs(&self) -> bool {
        self.oracle.proofs()
    }

    fn list_ty(&self) -> Tm {
        mk::ind(self.ids.list, vec![self.t.clone()])
    }

    fn g(&self, g: GlobalId, args: Vec<Tm>) -> Tm {
        mk::apps(mk::global(g), args.into_iter().map(|a| (Rel::Rel, a)))
    }

    pub fn nil(&self) -> Tm {
        mk::ctor(self.ids.list, 0, vec![self.t.clone()], vec![])
    }

    pub fn cons(&self, x: Tm, r: Tm) -> Tm {
        mk::ctor(self.ids.list, 1, vec![self.t.clone()], vec![x, r])
    }

    pub fn append(&self, a: Tm, b: Tm) -> Tm {
        self.g(self.ids.append, vec![self.t.clone(), a, b])
    }

    pub fn take(&self, l: Tm, k: Tm) -> Tm {
        self.g(self.ids.take, vec![self.t.clone(), l, k])
    }

    pub fn drop(&self, l: Tm, k: Tm) -> Tm {
        self.g(self.ids.drop, vec![self.t.clone(), l, k])
    }

    pub fn update(&self, l: Tm, i: Tm, v: Tm) -> Tm {
        self.g(self.ids.update, vec![self.t.clone(), l, i, v])
    }

    pub fn replicate(&self, n: Tm, v: Tm) -> Tm {
        self.g(self.ids.replicate, vec![self.t.clone(), n, v])
    }

    pub fn len(&self, l: Tm) -> Tm {
        self.g(self.ids.len, vec![self.t.clone(), l])
    }

    pub fn index(&self, l: Tm, i: Tm, p0: Tm, p1: Tm) -> Tm {
        mk::apps(mk::global(self.ids.index), [(Rel::Rel, self.t.clone()), (Rel::Rel, l), (Rel::Rel, i), (Rel::Irr, p0), (Rel::Irr, p1)])
    }

    pub fn le(&self, a: Tm, b: Tm) -> Tm {
        mk::prim(PrimOp::Le(Width::Int), vec![a, b], vec![])
    }

    pub fn lt(&self, a: Tm, b: Tm) -> Tm {
        mk::prim(PrimOp::Lt(Width::Int), vec![a, b], vec![])
    }

    pub fn eqi(&self, a: Tm, b: Tm) -> Tm {
        mk::prim(PrimOp::Eq(Width::Int), vec![a, b], vec![])
    }

    /// `Eq(Bool, c, true)`.
    pub fn holds(&self, c: Tm) -> Tm {
        mk::eq_bool(self.ids.bool_ind, c, true)
    }

    pub fn seg_tm(&self, base: &Tm, lo: &Tm, n: &Tm) -> Tm {
        self.take(self.drop(base.clone(), lo.clone()), n.clone())
    }

    /// The canonical term of a piece list.
    pub fn canon(&self, ps: &[Piece]) -> Tm {
        let mut out = self.nil();
        for p in ps.iter().rev() {
            out = match p {
                Piece::Seg { base, lo, n } => self.append(self.seg_tm(base, lo, n), out),
                Piece::Elem(x) => self.cons(x.clone(), out),
                Piece::Rep { v, n } => self.append(self.replicate(n.clone(), v.clone()), out),
            };
        }
        out
    }

    /// The canonical term of a `Seg`/`Rep` piece (not an `Elem`).
    fn piece_tm(&self, p: &Piece) -> Tm {
        match p {
            Piece::Seg { base, lo, n } => self.seg_tm(base, lo, n),
            Piece::Rep { v, n } => self.replicate(n.clone(), v.clone()),
            Piece::Elem(_) => unreachable!("an element is not a list piece"),
        }
    }

    // -----------------------------------------------------------------------
    // Proof combinators (all `None` without proofs).
    // -----------------------------------------------------------------------

    fn refl(&self, a: &Tm) -> Option<Tm> {
        self.proofs().then(|| mk::refl(self.list_ty(), a.clone()))
    }

    /// `trans(p : a = b, q : b = c) : a = c` over lists.
    fn trans(&self, a: &Tm, b: &Tm, c: &Tm, p: Option<Tm>, q: Option<Tm>) -> Option<Tm> {
        if !self.proofs() {
            return None;
        }
        Some(self.g(self.ids.eq_trans, vec![self.list_ty(), a.clone(), b.clone(), c.clone(), p?, q?]))
    }

    fn trans_ty(&self, ty: &Tm, a: &Tm, b: &Tm, c: &Tm, p: Option<Tm>, q: Option<Tm>) -> Option<Tm> {
        if !self.proofs() {
            return None;
        }
        Some(self.g(self.ids.eq_trans, vec![ty.clone(), a.clone(), b.clone(), c.clone(), p?, q?]))
    }

    fn sym_ty(&self, ty: &Tm, a: &Tm, b: &Tm, p: Option<Tm>) -> Option<Tm> {
        if !self.proofs() {
            return None;
        }
        Some(self.g(self.ids.eq_sym, vec![ty.clone(), a.clone(), b.clone(), p?]))
    }

    /// `cong(λz. ctx[z], a, b, p) : ctx[a] = ctx[b]` for a list context:
    /// `ctx` is a closure producing the context's term around a hole term.
    fn cong(&self, from_ty: &Tm, f: impl Fn(Tm) -> Tm, a: &Tm, b: &Tm, p: Option<Tm>) -> Option<Tm> {
        // the context's terms use the element type `t` unshifted under the
        // `λz`: sound only for a closed `t` (the callers resolve a `let`-bound
        // element type to its value; otherwise no proof, never an ill-typed
        // one)
        if !self.proofs() || !closed(&self.t) {
            return None;
        }
        let body = f(mk::var(0));
        let lam = mk::lam("z", Rel::Rel, from_ty.clone(), body);
        Some(self.g(self.ids.eq_cong, vec![from_ty.clone(), self.list_ty(), lam, a.clone(), b.clone(), p?]))
    }

    /// A lemma instance with the lemma's own parameter relevances.
    fn inst(&self, name: &str, args: Vec<Tm>) -> Option<Tm> {
        if !self.proofs() {
            return None;
        }
        let g = self.ids.lemma(name);
        let rels = self.env.global_param_rels(g)?;
        if rels.len() != args.len() {
            return None;
        }
        Some(mk::apps(mk::global(g), rels.into_iter().zip(args)))
    }

    /// The proof slot of a decision (an erased placeholder without proofs).
    fn slot(p: Option<Tm>) -> Tm {
        p.unwrap_or_else(|| Rc::new(Term::Erased))
    }

    // -----------------------------------------------------------------------
    // Decisions.
    // -----------------------------------------------------------------------

    /// Decides the comparison `c`; undecided is an error (a demand split).
    pub fn decide(&mut self, c: Tm) -> R<(bool, Option<Tm>)> {
        // literal comparisons decide by evaluation of the terms' literals
        if let Term::Prim { op, args, .. } = &*c
            && args.len() == 2
            && let (Some(a), Some(b)) = (int_lit(&args[0]), int_lit(&args[1]))
        {
            let v = match op {
                PrimOp::Le(Width::Int) => a <= b,
                PrimOp::Lt(Width::Int) => a < b,
                PrimOp::Eq(Width::Int) => a == b,
                _ => return self.oracle.decide(&c).ok_or(NormErr::Undecided(c)),
            };
            return Ok((v, self.proofs().then(|| mk::refl(mk::bool_ty(self.ids.bool_ind), mk::bool_lit(self.ids.bool_ind, v)))));
        }
        // a nonnegative combination of unsigned casts: true by the casts'
        // ranges (the kernel's `linarith` knows them)
        if nonneg_by_ranges(&c) {
            let goal = mk::eq_bool(self.ids.bool_ind, c.clone(), true);
            return Ok((true, self.proofs().then(|| Rc::new(Term::Linarith { hyps: vec![], goal, cert: vec![] }) as Tm)));
        }
        self.oracle.decide(&c).ok_or(NormErr::Undecided(c))
    }

    /// Decides `c` when the facts do (`None`: undecided, not an error).
    fn try_decide(&mut self, c: Tm) -> Option<(bool, Option<Tm>)> {
        self.decide(c).ok()
    }

    /// A proof that `c` holds (decided true), or an error.
    fn must(&mut self, c: Tm, what: &str) -> R<Tm> {
        match self.decide(c)? {
            (true, p) => Ok(Self::slot(p)),
            (false, _) => Err(NormErr::Unsupported(format!("a side condition that fails ({what})"))),
        }
    }

    /// The validity proofs `(0 ≤ lo, 0 ≤ n, lo + n ≤ len base)` of a `Seg`.
    fn valid(&mut self, base: &Tm, lo: &Tm, n: &Tm) -> R<(Tm, Tm, Tm)> {
        let v0 = self.must(self.le(lit(0), lo.clone()), "segment start")?;
        let v1 = self.must(self.le(lit(0), n.clone()), "segment length")?;
        let v2 = self.must(self.le(iadd(lo.clone(), n.clone()), self.len(base.clone())), "segment end")?;
        Ok((v0, v1, v2))
    }

    // -----------------------------------------------------------------------
    // Normalization.
    // -----------------------------------------------------------------------

    /// The list of a slice or array constructor's result, when `t` is a
    /// projection of one (`fst(snd(suffix(s, k)))` is `drop(fst(snd(s)),
    /// k)`, …): definitionally equal to `t`.
    fn unfold_ctor(&self, t: &Tm) -> Option<Tm> {
        let cast = |u: Tm| mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u], vec![]);
        let list_of = |s: Tm| mk::fst(mk::snd(s));
        let arr_list = |a: Tm| mk::fst(a);
        let Term::Fst(x) = &**t else { return None };
        if let Term::Snd(y) = &**x {
            // a slice's list
            if let Term::Pair { snd, .. } = &**y
                && let Term::Pair { fst, .. } = &**snd
            {
                return Some(fst.clone());
            }
            let (g, args) = head_app(y)?;
            let a: Vec<Tm> = args.iter().map(|(_, x)| x.clone()).collect();
            if g == self.ids.slice_mk && a.len() == 4 {
                return Some(a[2].clone());
            }
            if g == self.ids.slice_suffix && a.len() == 4 {
                return Some(self.drop(list_of(a[1].clone()), cast(a[2].clone())));
            }
            if g == self.ids.slice_prefix && a.len() == 4 {
                return Some(self.take(list_of(a[1].clone()), cast(a[2].clone())));
            }
            if g == self.ids.slice_range && a.len() == 6 {
                let n = mk::prim(PrimOp::Sub(Width::Usize), vec![a[3].clone(), a[2].clone()], vec![a[4].clone()]);
                return Some(self.take(self.drop(list_of(a[1].clone()), cast(a[2].clone())), cast(n)));
            }
            if g == self.ids.array_as_slice && a.len() == 4 {
                return Some(arr_list(a[2].clone()));
            }
            return None;
        }
        // an array's list
        if let Term::Pair { fst, .. } = &**x {
            return Some(fst.clone());
        }
        let (g, args) = head_app(x)?;
        let a: Vec<Tm> = args.iter().map(|(_, x)| x.clone()).collect();
        if Some(g) == self.ids.array_copy_range && a.len() == 9 {
            let (arr, lo, hi, src) = (a[2].clone(), a[3].clone(), a[4].clone(), a[5].clone());
            return Some(self.append(self.take(arr_list(arr.clone()), cast(lo)), self.append(list_of(src), self.drop(arr_list(arr), cast(hi)))));
        }
        if g == self.ids.array_set && a.len() == 6 {
            return Some(self.update(arr_list(a[2].clone()), cast(a[3].clone()), a[4].clone()));
        }
        if g == self.ids.array_repeat && a.len() == 4 {
            return Some(self.replicate(cast(a[1].clone()), a[2].clone()));
        }
        None
    }

    fn view(&self, t: &Tm) -> View {
        match &**t {
            Term::Ctor { ind, ctor: 0, .. } if *ind == self.ids.list => return View::Nil,
            Term::Ctor { ind, ctor: 1, args, .. } if *ind == self.ids.list && args.len() == 2 => return View::Cons(args[0].clone(), args[1].clone()),
            _ => {}
        }
        if let Some(u) = self.unfold_ctor(t) {
            return View::Alias(u);
        }
        let Some((g, args)) = head_app(t) else { return View::Atom };
        let a: Vec<Tm> = args.iter().map(|(_, x)| x.clone()).collect();
        if g == self.ids.append && a.len() == 3 {
            View::Append(a[1].clone(), a[2].clone())
        } else if g == self.ids.take && a.len() == 3 {
            View::Take(a[1].clone(), a[2].clone())
        } else if g == self.ids.drop && a.len() == 3 {
            View::Drop(a[1].clone(), a[2].clone())
        } else if g == self.ids.update && a.len() == 4 {
            View::Update(a[1].clone(), a[2].clone(), a[3].clone())
        } else if g == self.ids.replicate && a.len() == 3 {
            View::Replicate(a[1].clone(), a[2].clone())
        } else {
            View::Atom
        }
    }

    /// A constructor spine of at least 4 equal elements (`[z; N]` evaluated):
    /// `(z, N)`.
    fn uniform_spine(&self, t: &Tm) -> Option<(Tm, u64)> {
        let mut cur = t.clone();
        let mut first: Option<Tm> = None;
        let mut n = 0u64;
        loop {
            let next = match &*cur {
                Term::Ctor { ind, ctor: 0, .. } if *ind == self.ids.list => break,
                Term::Ctor { ind, ctor: 1, args, .. } if *ind == self.ids.list && args.len() == 2 => {
                    match &first {
                        None => first = Some(args[0].clone()),
                        Some(f) => {
                            if !Rc::ptr_eq(f, &args[0]) && !self.env.alpha_eq_relevant(f, &args[0], &|x, y| x == y) {
                                return None;
                            }
                        }
                    }
                    n += 1;
                    args[1].clone()
                }
                _ => return None,
            };
            cur = next;
        }
        if n >= 4 { first.map(|f| (f, n)) } else { None }
    }

    /// The pieces of the list term `l`.
    pub fn norm(&mut self, l: &Tm) -> R<Normed> {
        if let Some((z, k)) = self.uniform_spine(l) {
            // the spine is `replicate(k, z)` by evaluation (conversion)
            let rep = self.replicate(lit(k as i64), z.clone());
            let r = self.norm_replicate(&lit(k as i64), &z)?;
            let p0 = self.proofs().then(|| mk::refl(self.list_ty(), l.clone()));
            let c = self.canon(&r.pieces);
            let proof = self.trans(l, &rep, &c, p0, r.proof);
            return Ok(Normed { pieces: r.pieces, proof });
        }
        match self.view(l) {
            View::Nil => Ok(Normed { pieces: vec![], proof: self.refl(l) }),
            View::Cons(x, r) => {
                let nr = self.norm(&r)?;
                let cr = self.canon(&nr.pieces);
                let xx = x.clone();
                let lt = self.list_ty();
                let proof = self.cong(&lt, |z| self.cons(shift(&xx, 1), z), &r, &cr, nr.proof);
                let mut pieces = vec![Piece::Elem(x)];
                pieces.extend(nr.pieces);
                Ok(Normed { pieces, proof })
            }
            View::Append(a, b) => {
                let na = self.norm(&a)?;
                let nb = self.norm(&b)?;
                self.flatten(&a, &b, na, nb)
            }
            View::Take(x, k) => {
                let nx = self.norm(&x)?;
                let cx = self.canon(&nx.pieces);
                let (q, p) = self.take_p(&nx.pieces, &k)?;
                self.finish_op(l, &self.take(cx.clone(), k.clone()), q, nx.proof, p, &x, &cx, |me, z| me.take(z, shift(&k, 1)))
            }
            View::Drop(x, k) => {
                let nx = self.norm(&x)?;
                let cx = self.canon(&nx.pieces);
                let (q, p) = self.drop_p(&nx.pieces, &k)?;
                self.finish_op(l, &self.drop(cx.clone(), k.clone()), q, nx.proof, p, &x, &cx, |me, z| me.drop(z, shift(&k, 1)))
            }
            View::Update(x, i, v) => {
                let nx = self.norm(&x)?;
                let cx = self.canon(&nx.pieces);
                let (q, p) = self.update_p(&nx.pieces, &i, &v)?;
                self.finish_op(l, &self.update(cx.clone(), i.clone(), v.clone()), q, nx.proof, p, &x, &cx, |me, z| me.update(z, shift(&i, 1), shift(&v, 1)))
            }
            View::Replicate(n, v) => self.norm_replicate(&n, &v),
            // (a proof for the alias proves the term: conversion)
            View::Alias(u) => self.norm(&u),
            View::Atom => {
                let n = self.len(l.clone());
                let pieces = vec![Piece::Seg { base: l.clone(), lo: lit(0), n }];
                let proof = self.inst("seq::seg_atom", vec![self.t.clone(), l.clone()]);
                Ok(Normed { pieces, proof })
            }
        }
    }

    /// The proof of `op(x) = canon(q)` from `px : x = cx` and `p : op(cx) =
    /// canon(q)` (`op` given as a context around its list argument), then
    /// empty pieces dropped.
    #[allow(clippy::too_many_arguments)]
    fn finish_op(&mut self, l: &Tm, op_cx: &Tm, q: Vec<Piece>, px: Option<Tm>, p: Option<Tm>, x: &Tm, cx: &Tm, ctx: impl Fn(&Self, Tm) -> Tm) -> R<Normed> {
        let lt = self.list_ty();
        let p0 = self.cong(&lt, |z| ctx(self, z), x, cx, px);
        let cq = self.canon(&q);
        let proof = self.trans(l, op_cx, &cq, p0, p);
        let cleaned = self.clean(q)?;
        let cc = self.canon(&cleaned.pieces);
        let proof = self.trans(l, &cq, &cc, proof, cleaned.proof);
        Ok(Normed { pieces: cleaned.pieces, proof })
    }

    fn norm_replicate(&mut self, n: &Tm, v: &Tm) -> R<Normed> {
        let rep = self.replicate(n.clone(), v.clone());
        let (d, pd) = self.decide(self.le(n.clone(), lit(0)))?;
        if d {
            let proof = self.inst("seq::replicate_nonpos", vec![self.t.clone(), n.clone(), v.clone(), Self::slot(pd)]);
            return Ok(Normed { pieces: vec![], proof });
        }
        // replicate(n, v) = replicate(n, v) ++ []
        let with_nil = self.append(rep.clone(), self.nil());
        let an = self.inst("seq::append_nil", vec![self.t.clone(), rep.clone()]);
        let proof = self.sym_ty(&self.list_ty(), &with_nil, &rep, an);
        Ok(Normed { pieces: vec![Piece::Rep { v: v.clone(), n: n.clone() }], proof })
    }

    /// `append(a, b) = canon(na ++ nb)`.
    fn flatten(&mut self, a: &Tm, b: &Tm, na: Normed, nb: Normed) -> R<Normed> {
        let ca = self.canon(&na.pieces);
        let cb = self.canon(&nb.pieces);
        let lt = self.list_ty();
        let bb = b.clone();
        let p1 = self.cong(&lt, |z| self.append(z, shift(&bb, 1)), a, &ca, na.proof);
        let caa = ca.clone();
        let p2 = self.cong(&lt, |z| self.append(shift(&caa, 1), z), b, &cb, nb.proof);
        let mid = self.append(ca.clone(), b.clone());
        let lhs = self.append(a.clone(), b.clone());
        let joined = self.append(ca.clone(), cb.clone());
        let p0 = self.trans(&lhs, &mid, &joined, p1, p2);
        let p3 = self.assoc_chain(&na.pieces, &cb);
        let mut pieces = na.pieces.clone();
        pieces.extend(nb.pieces);
        let c = self.canon(&pieces);
        let proof = self.trans(&lhs, &joined, &c, p0, p3);
        Ok(Normed { pieces, proof })
    }

    /// `append(canon(ps), cb) = canon(ps ++ pieces of cb)`.
    fn assoc_chain(&self, ps: &[Piece], cb: &Tm) -> Option<Tm> {
        if !self.proofs() {
            return None;
        }
        let Some((first, rest)) = ps.split_first() else { return self.refl(cb) };
        let crest = self.canon(rest);
        let inner = self.append(crest.clone(), cb.clone());
        // the canonical term of `rest ++ cb` is `cb` substituted for the end
        let target_rest = self.canon_onto(rest, cb);
        let q = self.assoc_chain(rest, cb);
        let lt = self.list_ty();
        match first {
            Piece::Elem(x) => {
                let xx = x.clone();
                self.cong(&lt, |z| self.cons(shift(&xx, 1), z), &inner, &target_rest, q)
            }
            p => {
                let pt = self.piece_tm(p);
                let lhs = self.append(self.append(pt.clone(), crest.clone()), cb.clone());
                let mid = self.append(pt.clone(), inner.clone());
                let target = self.append(pt.clone(), target_rest.clone());
                let a = self.inst("seq::append_assoc", vec![self.t.clone(), pt.clone(), crest, cb.clone()]);
                let ptt = pt.clone();
                let c = self.cong(&lt, |z| self.append(shift(&ptt, 1), z), &inner, &target_rest, q);
                self.trans(&lhs, &mid, &target, a, c)
            }
        }
    }

    /// `canon(ps)` with `tail` in place of the final `[]`.
    fn canon_onto(&self, ps: &[Piece], tail: &Tm) -> Tm {
        let mut out = tail.clone();
        for p in ps.iter().rev() {
            out = match p {
                Piece::Elem(x) => self.cons(x.clone(), out),
                p => self.append(self.piece_tm(p), out),
            };
        }
        out
    }

    /// Drops the pieces the facts show empty: `canon(ps) = canon(q)`.
    fn clean(&mut self, ps: Vec<Piece>) -> R<Normed> {
        let mut kept: Vec<Piece> = Vec::new();
        // right to left, the proof of `canon(ps[i..]) = canon(kept)`
        let mut proof = self.refl(&self.nil());
        let mut cur_src = self.nil();
        for p in ps.into_iter().rev() {
            let empty = match &p {
                Piece::Seg { n, .. } | Piece::Rep { n, .. } => match self.oracle.decide(&self.le(n.clone(), lit(0))) {
                    Some((true, pd)) => Some(pd),
                    _ => None,
                },
                Piece::Elem(_) => None,
            };
            let ck = self.canon(&kept);
            match (empty, &p) {
                (Some(pd), Piece::Seg { base, lo, n }) => {
                    // append(S, src) = src = canon(kept)
                    let src = self.append(self.seg_tm(base, lo, n), cur_src.clone());
                    let e = self.inst("seq::seg_empty", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cur_src.clone(), Self::slot(pd)]);
                    proof = self.trans(&src, &cur_src, &ck, e, proof);
                    cur_src = src;
                }
                (Some(pd), Piece::Rep { v, n }) => {
                    let src = self.append(self.replicate(n.clone(), v.clone()), cur_src.clone());
                    let e = self.inst("seq::rep_empty", vec![self.t.clone(), n.clone(), v.clone(), cur_src.clone(), Self::slot(pd)]);
                    proof = self.trans(&src, &cur_src, &ck, e, proof);
                    cur_src = src;
                }
                _ => {
                    let lt = self.list_ty();
                    let (src, new_proof) = match &p {
                        Piece::Elem(x) => {
                            let xx = x.clone();
                            (self.cons(x.clone(), cur_src.clone()), self.cong(&lt, |z| self.cons(shift(&xx, 1), z), &cur_src, &ck, proof.clone()))
                        }
                        q => {
                            let pt = self.piece_tm(q);
                            let ptt = pt.clone();
                            (self.append(pt, cur_src.clone()), self.cong(&lt, |z| self.append(shift(&ptt, 1), z), &cur_src, &ck, proof.clone()))
                        }
                    };
                    proof = new_proof;
                    cur_src = src;
                    kept.insert(0, p);
                }
            }
        }
        Ok(Normed { pieces: kept, proof })
    }

    /// `take(canon(ps), k) = canon(q)`.
    fn take_p(&mut self, ps: &[Piece], k: &Tm) -> R<(Vec<Piece>, Option<Tm>)> {
        let Some((first, rest)) = ps.split_first() else { return Ok((vec![], self.refl(&self.nil()))) };
        let c = self.canon(ps);
        let cr = self.canon(rest);
        let lt = self.list_ty();
        // `k ≤ 0`: nothing is taken (decided for an element; tried for a
        // piece, whose partial rule also covers `k = 0`)
        let d0 = match first {
            Piece::Elem(_) => Some(self.decide(self.le(k.clone(), lit(0)))?),
            _ => self.try_decide(self.le(k.clone(), lit(0))),
        };
        // the R5 fault: a `take` claimed to end before a replicated piece
        let d0 = match first {
            Piece::Rep { .. } if super::fault_take_short() && !matches!(d0, Some((true, _))) => {
                let goal = mk::eq_bool(self.ids.bool_ind, self.le(k.clone(), lit(0)), true);
                Some((true, self.proofs().then(|| Rc::new(Term::Linarith { hyps: vec![], goal, cert: vec![] }) as Tm)))
            }
            _ => d0,
        };
        let p0 = match d0 {
            Some((true, p0)) => {
                let p = match first {
                    Piece::Elem(x) => self.inst("seq::take_cons_nonpos", vec![self.t.clone(), x.clone(), cr, k.clone(), Self::slot(p0)]),
                    _ => self.inst("seq::take_nonpos", vec![self.t.clone(), c, k.clone(), Self::slot(p0)]),
                };
                return Ok((vec![], p));
            }
            Some((false, p0)) => p0,
            None => None,
        };
        match first {
            Piece::Elem(x) => {
                let k1 = isub(k.clone(), lit(1));
                let (q, pq) = self.take_p(rest, &k1)?;
                let cq = self.canon(&q);
                let step = self.inst("seq::take_cons_pos", vec![self.t.clone(), x.clone(), cr.clone(), k.clone(), Self::slot(p0)]);
                let xx = x.clone();
                let c2 = self.cong(&lt, |z| self.cons(shift(&xx, 1), z), &self.take(cr.clone(), k1.clone()), &cq, pq);
                let lhs = self.take(c.clone(), k.clone());
                let mid = self.cons(x.clone(), self.take(cr, k1));
                let tgt = self.cons(x.clone(), cq);
                let mut out = vec![first.clone()];
                out.extend(q);
                Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
            }
            Piece::Seg { base, lo, n } => {
                let (v0, v1, v2) = self.valid(base, lo, n)?;
                // the whole piece when the facts say so, else its prefix
                // (the two rules overlap at `k = n`)
                let (d1, p1) = self.try_decide(self.le(n.clone(), k.clone())).unwrap_or((false, None));
                let s = self.seg_tm(base, lo, n);
                if d1 {
                    let k2 = isub(k.clone(), n.clone());
                    let (q, pq) = self.take_p(rest, &k2)?;
                    let cq = self.canon(&q);
                    let step = self.inst("seq::take_seg_full", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cr.clone(), k.clone(), v0, v1, v2, Self::slot(p1)]);
                    let ss = s.clone();
                    let c2 = self.cong(&lt, |z| self.append(shift(&ss, 1), z), &self.take(cr.clone(), k2.clone()), &cq, pq);
                    let lhs = self.take(c.clone(), k.clone());
                    let mid = self.append(s.clone(), self.take(cr, k2));
                    let tgt = self.append(s, cq);
                    let mut out = vec![first.clone()];
                    out.extend(q);
                    Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
                } else {
                    let k0 = self.must(self.le(lit(0), k.clone()), "take length")?;
                    let k1 = self.must(self.le(k.clone(), n.clone()), "take length")?;
                    let step = self.inst("seq::take_seg_part", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cr, k.clone(), v0, v1, v2, k0, k1]);
                    Ok((vec![Piece::Seg { base: base.clone(), lo: lo.clone(), n: k.clone() }], step))
                }
            }
            Piece::Rep { v, n } => {
                let (d1, p1) = self.decide(self.le(n.clone(), k.clone()))?;
                if !d1 {
                    return Err(NormErr::Unsupported("a `take` that ends inside a replicated piece".into()));
                }
                let v1 = self.must(self.le(lit(0), n.clone()), "replicate length")?;
                let r = self.replicate(n.clone(), v.clone());
                let k2 = isub(k.clone(), n.clone());
                let (q, pq) = self.take_p(rest, &k2)?;
                let cq = self.canon(&q);
                let step = self.inst("seq::take_rep_full", vec![self.t.clone(), n.clone(), v.clone(), cr.clone(), k.clone(), v1, Self::slot(p1)]);
                let rr = r.clone();
                let c2 = self.cong(&lt, |z| self.append(shift(&rr, 1), z), &self.take(cr.clone(), k2.clone()), &cq, pq);
                let lhs = self.take(c.clone(), k.clone());
                let mid = self.append(r.clone(), self.take(cr, k2));
                let tgt = self.append(r, cq);
                let mut out = vec![first.clone()];
                out.extend(q);
                Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
            }
        }
    }

    /// `drop(canon(ps), k) = canon(q)`.
    fn drop_p(&mut self, ps: &[Piece], k: &Tm) -> R<(Vec<Piece>, Option<Tm>)> {
        let Some((first, rest)) = ps.split_first() else { return Ok((vec![], self.refl(&self.nil()))) };
        let c = self.canon(ps);
        let cr = self.canon(rest);
        let d0 = match first {
            Piece::Elem(_) => Some(self.decide(self.le(k.clone(), lit(0)))?),
            _ => self.try_decide(self.le(k.clone(), lit(0))),
        };
        let p0 = match d0 {
            Some((true, p0)) => {
                let p = self.inst("seq::drop_nonpos", vec![self.t.clone(), c, k.clone(), Self::slot(p0)]);
                return Ok((ps.to_vec(), p));
            }
            Some((false, p0)) => p0,
            None => None,
        };
        let lhs = self.drop(c.clone(), k.clone());
        match first {
            Piece::Elem(x) => {
                let k1 = isub(k.clone(), lit(1));
                let (q, pq) = self.drop_p(rest, &k1)?;
                let cq = self.canon(&q);
                let step = self.inst("seq::drop_cons_pos", vec![self.t.clone(), x.clone(), cr.clone(), k.clone(), Self::slot(p0)]);
                let mid = self.drop(cr, k1);
                Ok((q, self.trans(&lhs, &mid, &cq, step, pq)))
            }
            Piece::Seg { base, lo, n } => {
                let (v0, v1, v2) = self.valid(base, lo, n)?;
                let (d1, p1) = self.try_decide(self.le(n.clone(), k.clone())).unwrap_or((false, None));
                if d1 {
                    let k2 = isub(k.clone(), n.clone());
                    let (q, pq) = self.drop_p(rest, &k2)?;
                    let cq = self.canon(&q);
                    let step = self.inst("seq::drop_seg_full", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cr.clone(), k.clone(), v0, v1, v2, Self::slot(p1)]);
                    let mid = self.drop(cr, k2);
                    Ok((q, self.trans(&lhs, &mid, &cq, step, pq)))
                } else {
                    let k0 = self.must(self.le(lit(0), k.clone()), "drop length")?;
                    let k1 = self.must(self.le(k.clone(), n.clone()), "drop length")?;
                    let step = self.inst("seq::drop_seg_part", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cr, k.clone(), v0, v1, v2, k0, k1]);
                    let mut out = vec![Piece::Seg { base: base.clone(), lo: iadd(lo.clone(), k.clone()), n: isub(n.clone(), k.clone()) }];
                    out.extend(rest.iter().cloned());
                    Ok((out, step))
                }
            }
            Piece::Rep { v, n } => {
                let (d1, p1) = self.try_decide(self.le(n.clone(), k.clone())).unwrap_or((false, None));
                if d1 {
                    let v1 = self.must(self.le(lit(0), n.clone()), "replicate length")?;
                    let k2 = isub(k.clone(), n.clone());
                    let (q, pq) = self.drop_p(rest, &k2)?;
                    let cq = self.canon(&q);
                    let step = self.inst("seq::drop_rep_full", vec![self.t.clone(), n.clone(), v.clone(), cr.clone(), k.clone(), v1, Self::slot(p1)]);
                    let mid = self.drop(cr, k2);
                    Ok((q, self.trans(&lhs, &mid, &cq, step, pq)))
                } else {
                    let k0 = self.must(self.le(lit(0), k.clone()), "drop length")?;
                    let k1 = self.must(self.le(k.clone(), n.clone()), "drop length")?;
                    let step = self.inst("seq::drop_rep_part", vec![self.t.clone(), n.clone(), v.clone(), cr, k.clone(), k0, k1]);
                    let mut out = vec![Piece::Rep { v: v.clone(), n: isub(n.clone(), k.clone()) }];
                    out.extend(rest.iter().cloned());
                    Ok((out, step))
                }
            }
        }
    }

    /// `update(canon(ps), i, x) = canon(q)`.
    fn update_p(&mut self, ps: &[Piece], i: &Tm, x: &Tm) -> R<(Vec<Piece>, Option<Tm>)> {
        let Some((first, rest)) = ps.split_first() else { return Ok((vec![], self.refl(&self.nil()))) };
        let c = self.canon(ps);
        let cr = self.canon(rest);
        let lt = self.list_ty();
        // a negative position changes nothing (tried for a piece; an
        // element's test `i == 0` covers it)
        if !matches!(first, Piece::Elem(_))
            && let Some((true, pn)) = self.try_decide(self.lt(i.clone(), lit(0)))
        {
            let p = self.inst("seq::update_neg", vec![self.t.clone(), c, i.clone(), x.clone(), Self::slot(pn)]);
            return Ok((ps.to_vec(), p));
        }
        let lhs = self.update(c.clone(), i.clone(), x.clone());
        match first {
            Piece::Elem(e) => {
                let (z, pz) = self.decide(self.eqi(i.clone(), lit(0)))?;
                let i1 = isub(i.clone(), lit(1));
                let (q, pq) = self.update_p(rest, &i1, x)?;
                let cq = self.canon(&q);
                let head = if z { x.clone() } else { e.clone() };
                let name = if z { "seq::update_cons_eq" } else { "seq::update_cons_ne" };
                let step = self.inst(name, vec![self.t.clone(), e.clone(), cr.clone(), i.clone(), x.clone(), Self::slot(pz)]);
                let hh = head.clone();
                let c2 = self.cong(&lt, |zz| self.cons(shift(&hh, 1), zz), &self.update(cr.clone(), i1.clone(), x.clone()), &cq, pq);
                let mid = self.cons(head.clone(), self.update(cr, i1, x.clone()));
                let tgt = self.cons(head.clone(), cq);
                let mut out = vec![Piece::Elem(head)];
                out.extend(q);
                Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
            }
            Piece::Seg { base, lo, n } => {
                let (d1, p1) = self.decide(self.le(n.clone(), i.clone()))?;
                if !d1 {
                    return Err(NormErr::Unsupported("an update inside a slice piece".into()));
                }
                let (v0, v1, v2) = self.valid(base, lo, n)?;
                let s = self.seg_tm(base, lo, n);
                let i2 = isub(i.clone(), n.clone());
                let (q, pq) = self.update_p(rest, &i2, x)?;
                let cq = self.canon(&q);
                let step = self.inst("seq::update_seg_right", vec![self.t.clone(), base.clone(), lo.clone(), n.clone(), cr.clone(), i.clone(), x.clone(), v0, v1, v2, Self::slot(p1)]);
                let ss = s.clone();
                let c2 = self.cong(&lt, |z| self.append(shift(&ss, 1), z), &self.update(cr.clone(), i2.clone(), x.clone()), &cq, pq);
                let mid = self.append(s.clone(), self.update(cr, i2, x.clone()));
                let tgt = self.append(s, cq);
                let mut out = vec![first.clone()];
                out.extend(q);
                Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
            }
            Piece::Rep { v: z, n } => {
                let (d1, p1) = self.try_decide(self.le(n.clone(), i.clone())).unwrap_or((false, None));
                if d1 {
                    let v1 = self.must(self.le(lit(0), n.clone()), "replicate length")?;
                    let r = self.replicate(n.clone(), z.clone());
                    let i2 = isub(i.clone(), n.clone());
                    let (q, pq) = self.update_p(rest, &i2, x)?;
                    let cq = self.canon(&q);
                    let step = self.inst("seq::update_rep_right", vec![self.t.clone(), n.clone(), z.clone(), cr.clone(), i.clone(), x.clone(), v1, Self::slot(p1)]);
                    let rr = r.clone();
                    let c2 = self.cong(&lt, |zz| self.append(shift(&rr, 1), zz), &self.update(cr.clone(), i2.clone(), x.clone()), &cq, pq);
                    let mid = self.append(r.clone(), self.update(cr, i2, x.clone()));
                    let tgt = self.append(r, cq);
                    let mut out = vec![first.clone()];
                    out.extend(q);
                    Ok((out, self.trans(&lhs, &mid, &tgt, step, c2)))
                } else {
                    let h0 = self.must(self.le(lit(0), i.clone()), "update position")?;
                    let h1 = self.must(self.lt(i.clone(), n.clone()), "update position")?;
                    let step = self.inst("seq::update_rep_mid", vec![self.t.clone(), n.clone(), z.clone(), cr, i.clone(), x.clone(), h0, h1]);
                    let mut out = vec![Piece::Rep { v: z.clone(), n: i.clone() }, Piece::Elem(x.clone()), Piece::Rep { v: z.clone(), n: isub(isub(n.clone(), i.clone()), lit(1)) }];
                    out.extend(rest.iter().cloned());
                    Ok((out, step))
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Element reads.
    // -----------------------------------------------------------------------

    /// The element at `i` of `canon(ps)`, with `Eq(T, index(canon(ps), i, h0,
    /// bound), elem)`; `bound : Eq(Bool, lt_int(i, len(canon(ps))), true)`.
    pub fn index_p(&mut self, ps: &[Piece], i: &Tm, h0: &Tm, bound: &Tm) -> R<(Elem, Option<Tm>)> {
        let Some((first, rest)) = ps.split_first() else { return Err(NormErr::Unsupported("a read past the end of the normal form".into())) };
        let c = self.canon(ps);
        let cr = self.canon(rest);
        let lhs = self.index(c.clone(), i.clone(), h0.clone(), bound.clone());
        let tt = self.t.clone();
        match first {
            Piece::Elem(x) => {
                let (z, pz) = self.decide(self.le(i.clone(), lit(0)))?;
                if z {
                    let p = self.inst("seq::index_cons_zero", vec![tt, x.clone(), cr, i.clone(), h0.clone(), bound.clone(), Self::slot(pz)]);
                    return Ok((Elem::Val(x.clone()), p));
                }
                let i1 = isub(i.clone(), lit(1));
                let g0 = self.lin_or_slot(pz.clone().map(|p| (p, mk::eq_bool(self.ids.bool_ind, self.le(i.clone(), lit(0)), false))).into_iter().collect(), self.holds(self.le(lit(0), i1.clone())))?;
                let bound_ty = self.holds(self.lt(i.clone(), self.len(c.clone())));
                let g1 = self.lin_or_slot(vec![(bound.clone(), bound_ty)], self.holds(self.lt(i1.clone(), self.len(cr.clone()))))?;
                let (e, pe) = self.index_p(rest, &i1, &g0, &g1)?;
                let step = self.inst("seq::index_cons_succ", vec![tt, x.clone(), cr.clone(), i.clone(), h0.clone(), bound.clone(), Self::slot(pz)]);
                let mid = self.index(cr, i1, g0, g1);
                let et = self.elem_tm(&e);
                Ok((e, self.trans_ty(&self.t.clone(), &lhs, &mid, &et, step, pe)))
            }
            Piece::Seg { base, lo, n } => {
                let (v0, v1, v2) = self.valid(base, lo, n)?;
                let (inside, pin) = self.decide(self.lt(i.clone(), n.clone()))?;
                if inside {
                    let j = iadd(lo.clone(), i.clone());
                    let g0 = self.must(self.le(lit(0), j.clone()), "read position")?;
                    let g1 = self.must(self.lt(j.clone(), self.len(base.clone())), "read position")?;
                    let p = self.inst("seq::index_seg_in", vec![tt, base.clone(), lo.clone(), n.clone(), cr, i.clone(), v0, v1, v2, h0.clone(), Self::slot(pin), bound.clone(), g0.clone(), g1.clone()]);
                    return Ok((Elem::At { base: base.clone(), j, g0, g1 }, p));
                }
                let hge = self.must(self.le(n.clone(), i.clone()), "read position")?;
                let i2 = isub(i.clone(), n.clone());
                let g0 = self.must(self.le(lit(0), i2.clone()), "read position")?;
                // the bound on the rest: from `bound`, `len_append` and `seg_len`
                let s = self.seg_tm(base, lo, n);
                let hyps = if self.proofs() {
                    vec![
                        (bound.clone(), self.holds(self.lt(i.clone(), self.len(c.clone())))),
                        (self.inst("seq::len_append", vec![tt.clone(), s.clone(), cr.clone()]).unwrap(), mk::eq(mk::int_ty(Width::Int), self.len(c.clone()), iadd(self.len(s.clone()), self.len(cr.clone())))),
                        (self.inst("seq::seg_len", vec![tt.clone(), base.clone(), lo.clone(), n.clone(), v0.clone(), v1.clone(), v2.clone()]).unwrap(), mk::eq(mk::int_ty(Width::Int), self.len(s.clone()), n.clone())),
                    ]
                } else {
                    vec![]
                };
                let g1 = self.lin_or_slot(hyps, self.holds(self.lt(i2.clone(), self.len(cr.clone()))))?;
                let (e, pe) = self.index_p(rest, &i2, &g0, &g1)?;
                let step = self.inst("seq::index_seg_after", vec![tt, base.clone(), lo.clone(), n.clone(), cr.clone(), i.clone(), v0, v1, v2, h0.clone(), hge, bound.clone(), g0.clone(), g1.clone()]);
                let mid = self.index(cr, i2, g0, g1);
                let et = self.elem_tm(&e);
                Ok((e, self.trans_ty(&self.t.clone(), &lhs, &mid, &et, step, pe)))
            }
            Piece::Rep { v, n } => {
                let (inside, pin) = self.decide(self.lt(i.clone(), n.clone()))?;
                if inside {
                    let p = self.inst("seq::index_rep_in", vec![tt, n.clone(), v.clone(), cr, i.clone(), h0.clone(), Self::slot(pin), bound.clone()]);
                    return Ok((Elem::Val(v.clone()), p));
                }
                let v1 = self.must(self.le(lit(0), n.clone()), "replicate length")?;
                let hge = self.must(self.le(n.clone(), i.clone()), "read position")?;
                let i2 = isub(i.clone(), n.clone());
                let g0 = self.must(self.le(lit(0), i2.clone()), "read position")?;
                let r = self.replicate(n.clone(), v.clone());
                let hyps = if self.proofs() {
                    vec![
                        (bound.clone(), self.holds(self.lt(i.clone(), self.len(c.clone())))),
                        (self.inst("seq::len_append", vec![tt.clone(), r.clone(), cr.clone()]).unwrap(), mk::eq(mk::int_ty(Width::Int), self.len(c.clone()), iadd(self.len(r.clone()), self.len(cr.clone())))),
                        (self.inst("seq::len_replicate", vec![tt.clone(), n.clone(), v.clone(), v1.clone()]).unwrap(), mk::eq(mk::int_ty(Width::Int), self.len(r.clone()), n.clone())),
                    ]
                } else {
                    vec![]
                };
                let g1 = self.lin_or_slot(hyps, self.holds(self.lt(i2.clone(), self.len(cr.clone()))))?;
                let (e, pe) = self.index_p(rest, &i2, &g0, &g1)?;
                let step = self.inst("seq::index_rep_after", vec![tt, n.clone(), v.clone(), cr.clone(), i.clone(), v1, h0.clone(), hge, bound.clone(), g0.clone(), g1.clone()]);
                let mid = self.index(cr, i2, g0, g1);
                let et = self.elem_tm(&e);
                Ok((e, self.trans_ty(&self.t.clone(), &lhs, &mid, &et, step, pe)))
            }
        }
    }

    /// A proof of `goal` by `linarith` over `hyps` (the kernel searches the
    /// certificate); an erased slot without proofs.
    fn lin_or_slot(&mut self, hyps: Vec<(Tm, Tm)>, goal: Tm) -> R<Tm> {
        if !self.proofs() {
            return Ok(Rc::new(Term::Erased));
        }
        match self.oracle.prove(&goal, &hyps) {
            Some(Some(p)) => Ok(p),
            _ => {
                // the kernel's own certificate search (it also uses the
                // context's hypotheses), checked here: a claim it refuses is
                // a proof not found — the helper fails, which is not an
                // optimizer fault — never a lemma the kernel rejects later
                let claim: Tm = Rc::new(Term::Linarith { hyps, goal: goal.clone(), cert: vec![] });
                if self.oracle.accepts(&claim, &goal) {
                    Ok(claim)
                } else {
                    Err(NormErr::Unsupported("a side condition that linear arithmetic does not prove".into()))
                }
            }
        }
    }

    /// The term of an element.
    pub fn elem_tm(&self, e: &Elem) -> Tm {
        match e {
            Elem::Val(x) => x.clone(),
            Elem::At { base, j, g0, g1 } => self.index(base.clone(), j.clone(), g0.clone(), g1.clone()),
        }
    }

    // -----------------------------------------------------------------------
    // Equality of two normal forms.
    // -----------------------------------------------------------------------

    /// `Eq(Int, a, b)` (refl when the terms are equal).
    fn int_eq(&mut self, a: &Tm, b: &Tm) -> R<Option<Tm>> {
        if self.env.alpha_eq_relevant(a, b, &|x, y| x == y) {
            return Ok(self.proofs().then(|| mk::refl(mk::int_ty(Width::Int), a.clone())));
        }
        let goal = mk::eq(mk::int_ty(Width::Int), a.clone(), b.clone());
        match self.oracle.prove(&goal, &[]) {
            Some(p) => Ok(p),
            None => Err(NormErr::Unsupported("two piece bounds that are not equal".into())),
        }
    }

    /// `Eq(T, e1, e2)` for two elements (`None` proof without proofs).
    pub fn elem_eq(&mut self, e1: &Elem, e2: &Elem) -> R<Option<Tm>> {
        let (t1, t2) = (self.elem_tm(e1), self.elem_tm(e2));
        if self.env.alpha_eq_relevant(&t1, &t2, &|x, y| x == y) {
            return Ok(self.proofs().then(|| mk::refl(self.t.clone(), t1)));
        }
        match (e1, e2) {
            (Elem::At { base: b1, j: j1, g0: a0, g1: a1 }, Elem::At { base: b2, j: j2, g0: c0, g1: c1 }) if self.env.alpha_eq_relevant(b1, b2, &|x, y| x == y) => {
                // (the `Int` equation is an irrelevant argument)
                let e = self.int_eq(j1, j2)?;
                Ok(self.inst("seq::index_at_eq", vec![self.t.clone(), b1.clone(), j1.clone(), j2.clone(), a0.clone(), a1.clone(), c0.clone(), c1.clone(), Self::slot(e)]))
            }
            _ => Err(NormErr::Unsupported("two elements the normal form does not identify".into())),
        }
    }

    /// `Eq(List T, canon(ps1), canon(ps2))`.
    pub fn pieces_eq(&mut self, ps1: &[Piece], ps2: &[Piece]) -> R<Option<Tm>> {
        if ps1.len() != ps2.len() {
            return Err(NormErr::Unsupported(format!("normal forms of different shapes ({} and {} pieces)", ps1.len(), ps2.len())));
        }
        let Some(((p1, r1), (p2, r2))) = ps1.split_first().zip(ps2.split_first()) else { return Ok(self.refl(&self.nil())) };
        let rest = self.pieces_eq(r1, r2)?;
        let (c1, c2) = (self.canon(r1), self.canon(r2));
        let lt = self.list_ty();
        match (p1, p2) {
            (Piece::Elem(x1), Piece::Elem(x2)) => {
                let q = self.elem_eq(&Elem::Val(x1.clone()), &Elem::Val(x2.clone()))?;
                let a = self.cons(x1.clone(), c1.clone());
                let b = self.cons(x2.clone(), c1.clone());
                let c = self.cons(x2.clone(), c2.clone());
                let cc = c1.clone();
                let s1 = self.cong(&self.t.clone(), |z| self.cons(z, shift(&cc, 1)), x1, x2, q);
                let xx = x2.clone();
                let s2 = self.cong(&lt, |z| self.cons(shift(&xx, 1), z), &c1, &c2, rest);
                Ok(self.trans(&a, &b, &c, s1, s2))
            }
            (Piece::Seg { base: b1, lo: l1, n: n1 }, Piece::Seg { base: b2, lo: l2, n: n2 }) => {
                if !self.env.alpha_eq_relevant(b1, b2, &|x, y| x == y) {
                    return Err(NormErr::Unsupported("pieces of different lists".into()));
                }
                let el = self.int_eq(l1, l2)?;
                let en = self.int_eq(n1, n2)?;
                let it = mk::int_ty(Width::Int);
                let (bb, nn1, ll2) = (b1.clone(), n1.clone(), l2.clone());
                let q1 = self.cong(&it, |z| self.take(self.drop(shift(&bb, 1), z), shift(&nn1, 1)), l1, l2, el);
                let q2 = self.cong(&it, |z| self.take(self.drop(shift(&bb, 1), shift(&ll2, 1)), z), n1, n2, en);
                let (s_a, s_b, s_c) = (self.seg_tm(b1, l1, n1), self.seg_tm(b1, l2, n1), self.seg_tm(b1, l2, n2));
                let qs = self.trans(&s_a, &s_b, &s_c, q1, q2);
                let (a, b, c) = (self.append(s_a.clone(), c1.clone()), self.append(s_c.clone(), c1.clone()), self.append(s_c.clone(), c2.clone()));
                let cc = c1.clone();
                let t1 = self.cong(&lt, |z| self.append(z, shift(&cc, 1)), &s_a, &s_c, qs);
                let sc = s_c.clone();
                let t2 = self.cong(&lt, |z| self.append(shift(&sc, 1), z), &c1, &c2, rest);
                Ok(self.trans(&a, &b, &c, t1, t2))
            }
            (Piece::Rep { v: v1, n: n1 }, Piece::Rep { v: v2, n: n2 }) => {
                if !self.env.alpha_eq_relevant(v1, v2, &|x, y| x == y) {
                    return Err(NormErr::Unsupported("replicated pieces of different values".into()));
                }
                let en = self.int_eq(n1, n2)?;
                let it = mk::int_ty(Width::Int);
                let vv = v1.clone();
                let q = self.cong(&it, |z| self.replicate(z, shift(&vv, 1)), n1, n2, en);
                let (r_a, r_c) = (self.replicate(n1.clone(), v1.clone()), self.replicate(n2.clone(), v1.clone()));
                let (a, b, c) = (self.append(r_a.clone(), c1.clone()), self.append(r_c.clone(), c1.clone()), self.append(r_c.clone(), c2.clone()));
                let cc = c1.clone();
                let t1 = self.cong(&lt, |z| self.append(z, shift(&cc, 1)), &r_a, &r_c, q);
                let rc = r_c.clone();
                let t2 = self.cong(&lt, |z| self.append(shift(&rc, 1), z), &c1, &c2, rest);
                Ok(self.trans(&a, &b, &c, t1, t2))
            }
            _ => Err(NormErr::Unsupported(format!("pieces of different kinds ({} and {})", p1.kind(), p2.kind()))),
        }
    }

    /// `Eq(List T, l1, l2)` through their normal forms.
    pub fn lists_eq(&mut self, l1: &Tm, l2: &Tm) -> R<Option<Tm>> {
        let n1 = self.norm(l1)?;
        let n2 = self.norm(l2)?;
        let q = self.pieces_eq(&n1.pieces, &n2.pieces)?;
        let (c1, c2) = (self.canon(&n1.pieces), self.canon(&n2.pieces));
        let lt = self.list_ty();
        let back = self.sym_ty(&lt, l2, &c2, n2.proof);
        let mid = self.trans(&c1, &c2, l2, q, back);
        Ok(self.trans(l1, &c1, l2, n1.proof, mid))
    }
}

/// A linear form `Σ cᵢ·aᵢ + c` of an `Int` term over atoms (casts from
/// `usize`, slice list lengths, anything else opaque), for printing a
/// comparison in `usize`.
#[derive(Clone, Debug, Default)]
pub struct Lin {
    pub atoms: Vec<(Tm, BigInt)>,
    pub constant: BigInt,
}

impl Lin {
    fn add_atom(&mut self, a: Tm, c: BigInt) {
        for (x, k) in self.atoms.iter_mut() {
            if Rc::ptr_eq(x, &a) || tm_eq(x, &a) {
                *k += &c;
                return;
            }
        }
        self.atoms.push((a, c));
    }

    fn scaled(&self, k: &BigInt) -> Lin {
        Lin { atoms: self.atoms.iter().map(|(a, c)| (a.clone(), c * k)).collect(), constant: &self.constant * k }
    }

    fn plus(mut self, o: &Lin) -> Lin {
        for (a, c) in &o.atoms {
            self.add_atom(a.clone(), c.clone());
        }
        self.constant += &o.constant;
        self.atoms.retain(|(_, c)| !c.is_zero());
        self
    }

    /// The linear form of `t`.
    pub fn of(t: &Tm) -> Lin {
        match &**t {
            Term::Lit { n, .. } => Lin { atoms: vec![], constant: n.clone() },
            Term::Prim { op: PrimOp::IAdd, args, .. } if args.len() == 2 => Lin::of(&args[0]).plus(&Lin::of(&args[1])),
            Term::Prim { op: PrimOp::ISub, args, .. } if args.len() == 2 => Lin::of(&args[0]).plus(&Lin::of(&args[1]).scaled(&BigInt::from(-1))),
            Term::Prim { op: PrimOp::IMul, args, .. } if args.len() == 2 && int_lit(&args[1]).is_some() => Lin::of(&args[0]).scaled(&int_lit(&args[1]).unwrap()),
            _ => {
                let mut l = Lin::default();
                l.add_atom(t.clone(), BigInt::from(1));
                l
            }
        }
    }
}

/// The linear form of `t` seen through the exact machine arithmetic of the
/// printed code: `cast(a +ᵤ b)` is `cast a + cast b` and `cast(a −ᵤ b)` is
/// `cast a − cast b` (checked operations, their proofs rule out wrapping),
/// `cast(lit)` a constant, `fst(slice::mk T n l p)` is `n` and a slice's
/// list length `len(fst(snd(s)))` the atom `cast(fst s)` (`slice::ok_len`).
/// For printing only: the printed residual is elaborated and related to its
/// source by the leaf proofs, never by this form.
pub fn lin_exact(ids: &Ids, t: &Tm) -> Lin {
    fn usize_lin(ids: &Ids, u: &Tm) -> Lin {
        match &**u {
            Term::Lit { n, .. } => Lin { atoms: vec![], constant: n.clone() },
            Term::Prim { op: PrimOp::Add(Width::Usize), args, .. } if args.len() == 2 => usize_lin(ids, &args[0]).plus(&usize_lin(ids, &args[1])),
            Term::Prim { op: PrimOp::Sub(Width::Usize), args, .. } if args.len() == 2 => usize_lin(ids, &args[0]).plus(&usize_lin(ids, &args[1]).scaled(&BigInt::from(-1))),
            Term::Fst(x) => match head_app(x) {
                Some((g, args)) if g == ids.slice_mk && args.len() == 4 => usize_lin(ids, &args[1].1),
                _ => atom(mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u.clone()], vec![])),
            },
            _ => atom(mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u.clone()], vec![])),
        }
    }
    fn atom(t: Tm) -> Lin {
        let mut l = Lin::default();
        l.add_atom(t, BigInt::from(1));
        l
    }
    match &**t {
        Term::Lit { n, .. } => Lin { atoms: vec![], constant: n.clone() },
        Term::Prim { op: PrimOp::IAdd, args, .. } if args.len() == 2 => lin_exact(ids, &args[0]).plus(&lin_exact(ids, &args[1])),
        Term::Prim { op: PrimOp::ISub, args, .. } if args.len() == 2 => lin_exact(ids, &args[0]).plus(&lin_exact(ids, &args[1]).scaled(&BigInt::from(-1))),
        Term::Prim { op: PrimOp::IMul, args, .. } if args.len() == 2 && int_lit(&args[1]).is_some() => lin_exact(ids, &args[0]).scaled(&int_lit(&args[1]).unwrap()),
        Term::Prim { op: PrimOp::Cast { from: Width::Usize, to: Width::Int }, args, .. } if args.len() == 1 => usize_lin(ids, &args[0]),
        _ => {
            if let Some((g, args)) = head_app(t)
                && g == ids.len
                && args.len() == 2
                && let Some(s) = super::drive::slice_of_list_tm(&args[1].1)
            {
                return usize_lin(ids, &mk::fst(s));
            }
            atom(t.clone())
        }
    }
}

/// Whether `c` (`a ≤ b` or `a < b` over `Int`) holds because `b − a` (minus
/// one for `<`) is a nonnegative combination of casts of unsigned values
/// plus a nonnegative constant.
fn nonneg_by_ranges(c: &Tm) -> bool {
    let Term::Prim { op, args, .. } = &**c else { return false };
    if args.len() != 2 {
        return false;
    }
    let strict = match op {
        PrimOp::Le(Width::Int) => false,
        PrimOp::Lt(Width::Int) => true,
        _ => return false,
    };
    let d = Lin::of(&args[1]).plus(&Lin::of(&args[0]).scaled(&BigInt::from(-1)));
    let k = if strict { &d.constant - BigInt::from(1) } else { d.constant.clone() };
    !k.is_negative()
        && d.atoms.iter().all(|(a, c)| {
            !c.is_negative() && matches!(&**a, Term::Prim { op: PrimOp::Cast { from: Width::Usize | Width::U8 | Width::U16 | Width::U32 | Width::U64, to: Width::Int }, .. })
        })
}

/// The `usize` term of a nonnegative combination of atoms and a constant
/// (`cast_usize_int(u)` ↦ `u`, `len(fst(snd(s)))` ↦ `fst(s)`), as checked
/// `usize` additions (their proof slots erased: the printed residual's
/// elaboration proves them). `None` when an atom has no `usize` form.
pub fn usize_of(ids: &Ids, atoms: &[(Tm, BigInt)], constant: &BigInt) -> Option<Tm> {
    let mut parts: Vec<Tm> = Vec::new();
    for (a, c) in atoms {
        let u = usize_atom(ids, a)?;
        let k = c.to_u64()?;
        for _ in 0..k.min(4) {
            parts.push(u.clone());
        }
        if k > 4 {
            return None;
        }
    }
    if constant.is_negative() {
        return None;
    }
    if !constant.is_zero() || parts.is_empty() {
        parts.push(mk::lit(Width::Usize, constant.clone()));
    }
    let mut it = parts.into_iter();
    let mut acc = it.next()?;
    for p in it {
        acc = mk::prim(PrimOp::Add(Width::Usize), vec![acc, p], vec![Rc::new(Term::Erased)]);
    }
    Some(acc)
}

/// The `usize` form of an `Int` atom.
pub fn usize_atom(ids: &Ids, a: &Tm) -> Option<Tm> {
    match &**a {
        Term::Prim { op: PrimOp::Cast { from: Width::Usize, to: Width::Int }, args, .. } if args.len() == 1 => Some(args[0].clone()),
        _ => {
            let (g, args) = head_app(a)?;
            if g != ids.len || args.len() != 2 {
                return None;
            }
            // len(fst(snd(s))) = cast(fst(s)) (slice::ok_len)
            let Term::Fst(x) = &*args[1].1 else { return None };
            let Term::Snd(s) = &**x else { return None };
            Some(mk::fst(s.clone()))
        }
    }
}

/// The `usize` form of an `Int` term (a nonnegative linear form).
pub fn usize_term(ids: &Ids, t: &Tm) -> Option<Tm> {
    if let Some(u) = usize_atom(ids, t) {
        return Some(u);
    }
    let l = lin_exact(ids, t);
    if l.atoms.iter().any(|(_, c)| c.is_negative()) {
        // a − b: a checked subtraction
        let pos: Vec<(Tm, BigInt)> = l.atoms.iter().filter(|(_, c)| c.is_positive()).cloned().collect();
        let neg: Vec<(Tm, BigInt)> = l.atoms.iter().filter(|(_, c)| c.is_negative()).map(|(a, c)| (a.clone(), -c)).collect();
        let (pc, nc) = if l.constant.is_negative() { (BigInt::zero(), -l.constant.clone()) } else { (l.constant.clone(), BigInt::zero()) };
        let p = usize_of(ids, &pos, &pc)?;
        let n = usize_of(ids, &neg, &nc)?;
        return Some(mk::prim(PrimOp::Sub(Width::Usize), vec![p, n], vec![Rc::new(Term::Erased)]));
    }
    if l.constant.is_negative() {
        let pos: Vec<(Tm, BigInt)> = l.atoms.clone();
        let p = usize_of(ids, &pos, &BigInt::zero())?;
        return Some(mk::prim(PrimOp::Sub(Width::Usize), vec![p, mk::lit(Width::Usize, -l.constant.clone())], vec![Rc::new(Term::Erased)]));
    }
    usize_of(ids, &l.atoms, &l.constant)
}

/// The printable `usize` comparison equivalent to the `Int` comparison `c`
/// (`le_int`, `lt_int`, `eq_int` of linear forms): both sides moved to
/// nonnegative combinations. `None` when an atom has no `usize` form.
pub fn usize_cmp(ids: &Ids, c: &Tm) -> Option<Tm> {
    let Term::Prim { op, args, .. } = &**c else { return None };
    if args.len() != 2 {
        return None;
    }
    let d = lin_exact(ids, &args[0]).plus(&lin_exact(ids, &args[1]).scaled(&BigInt::from(-1)));
    // d ⋈ 0 ⟺ P + p ⋈ N + n
    let pos: Vec<(Tm, BigInt)> = d.atoms.iter().filter(|(_, k)| k.is_positive()).cloned().collect();
    let neg: Vec<(Tm, BigInt)> = d.atoms.iter().filter(|(_, k)| k.is_negative()).map(|(a, k)| (a.clone(), -k)).collect();
    let (pc, nc) = if d.constant.is_negative() { (BigInt::zero(), -d.constant.clone()) } else { (d.constant.clone(), BigInt::zero()) };
    let l = usize_of(ids, &pos, &pc)?;
    let r = usize_of(ids, &neg, &nc)?;
    let op2 = match op {
        PrimOp::Le(Width::Int) => PrimOp::Le(Width::Usize),
        PrimOp::Lt(Width::Int) => PrimOp::Lt(Width::Usize),
        PrimOp::Eq(Width::Int) => PrimOp::Eq(Width::Usize),
        _ => return None,
    };
    Some(mk::prim(op2, vec![l, r], vec![]))
}

/// Structural equality of two (small) terms, proofs included.
pub fn tm_eq(a: &Tm, b: &Tm) -> bool {
    Rc::ptr_eq(a, b) || format!("{a:?}") == format!("{b:?}")
}

/// The oracle of the proof builder: `auto`'s linear arithmetic over the
/// facts of a state, proofs built (the extra hypotheses of a goal become
/// facts of a child frame, closed around the proof).
pub struct EngineOracle<'x, 'a> {
    pub e: &'x mut crate::auto::search::Engine<'a>,
    pub st: &'x crate::auto::state::St,
    /// Shared by the oracles of one state (a leaf asks the same validity
    /// conditions many times, over the same facts).
    cache: Rc<std::cell::RefCell<OracleCache>>,
}

/// Decisions by the comparison's term, and the state's arithmetic facts as
/// `linarith` hypotheses (read back once).
#[derive(Default)]
pub struct OracleCache {
    memo: HashMap<String, (bool, Tm)>,
    base: Option<Vec<(Tm, Tm)>>,
}

impl<'x, 'a> EngineOracle<'x, 'a> {
    pub fn new(e: &'x mut crate::auto::search::Engine<'a>, st: &'x crate::auto::state::St) -> Self {
        EngineOracle { e, st, cache: Rc::default() }
    }

    /// An oracle sharing `cache` (with the other oracles of the same state).
    pub fn with_cache(e: &'x mut crate::auto::search::Engine<'a>, st: &'x crate::auto::state::St, cache: Rc<std::cell::RefCell<OracleCache>>) -> Self {
        EngineOracle { e, st, cache }
    }
}

impl EngineOracle<'_, '_> {
    fn decide_traced(&mut self, c: &Tm) -> Option<(bool, Option<Tm>)> {
        let a = crate::auto::meter::available();
        let t = std::time::Instant::now();
        let r = self.decide_(c);
        if std::env::var_os("SANDBLASTER_OPT_TRACE_SEQ_ORACLE").is_some() {
            let names = self.st.names();
            eprintln!("opt: seq: oracle {:?} in {} steps {} us: {}", r.as_ref().map(|x| x.0), a.saturating_sub(crate::auto::meter::available()), t.elapsed().as_micros(), self.e.env.print_term(&names, &crate::opt::seqsum::prove::strip_proofs(c)).chars().take(400).collect::<String>());
        }
        r
    }
}

impl EngineOracle<'_, '_> {
    fn decide_(&mut self, c: &Tm) -> Option<(bool, Option<Tm>)> {
        let key = format!("{c:?}");
        let hit = self.cache.borrow().memo.get(&key).cloned();
        if let Some((v, p)) = hit {
            return Some((v, Some(p)));
        }
        self.e.settle();
        let cv = self.st.eval(self.e.env, c, self.e.b).ok()?;
        if let sandblaster_kernel::value::Value::Ctor { ind, ctor, .. } = &*cv
            && *ind == self.e.env.bool_ind()
        {
            // decided by evaluation: `refl` proves it (conversion)
            let v = *ctor == 1;
            let p = mk::refl(mk::bool_ty(*ind), mk::bool_lit(*ind, v));
            self.cache.borrow_mut().memo.insert(key, (v, p.clone()));
            return Some((v, Some(p)));
        }
        let ids = Ids::new(self.e.env)?;
        let cached = self.cache.borrow().base.clone();
        let base = match cached {
            Some(b) => b,
            None => {
                let b = self.e.lin_hyps(self.st);
                self.cache.borrow_mut().base = Some(b.clone());
                b
            }
        };
        let r = lin_decide_with(self.e, &ids, self.st, c, &cv, base)?;
        if has_erased(&r.1) {
            // a refused read-back inside the proof: no decision
            if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                let names = self.st.names();
                eprintln!("opt: seq: a decision whose proof has a placeholder: {}", self.e.env.print_term(&names, c).chars().take(300).collect::<String>());
            }
            return None;
        }
        self.cache.borrow_mut().memo.insert(key, r.clone());
        Some((r.0, Some(r.1)))
    }
}

impl Oracle for EngineOracle<'_, '_> {
    fn decide(&mut self, c: &Tm) -> Option<(bool, Option<Tm>)> {
        EngineOracle::decide_traced(self, c)
    }

    fn prove(&mut self, goal: &Tm, extra: &[(Tm, Tm)]) -> Option<Option<Tm>> {
        // linear over the facts, `extra` and the slices' length facts first
        // (the goals are linear in lengths); the automation otherwise
        self.e.settle();
        if let Ok(gv) = self.st.eval(self.e.env, goal, self.e.b) {
            let cached = self.cache.borrow().base.clone();
            let mut hyps = match cached {
                Some(b) => b,
                None => {
                    let b = self.e.lin_hyps(self.st);
                    self.cache.borrow_mut().base = Some(b.clone());
                    b
                }
            };
            hyps.extend(extra.iter().cloned());
            if let Some(ids) = Ids::new(self.e.env) {
                hyps.extend(ok_len_hyps(&ids, goal));
                for (_, ty) in extra {
                    hyps.extend(ok_len_hyps(&ids, ty));
                }
            }
            if let Ok(Some(p)) = self.e.lin_with(self.st, &hyps, &gv)
                && !has_erased(&p)
            {
                return Some(Some(p));
            }
        }
        let mut st = self.st.child();
        // (each fact is a binder: the later ones' terms are shifted over the
        // earlier ones)
        for (j, (p, ty)) in extra.iter().enumerate() {
            self.e.settle();
            let tv = st.eval(self.e.env, &shift(ty, j as i64), self.e.b).ok()?;
            st.push_fact(self.e.env, tv, shift(p, j as i64), crate::auto::state::Origin::Derived("seq"));
        }
        let k = extra.len() as i64;
        let goal = shift(goal, k);
        self.e.settle();
        let gv = st.eval(self.e.env, &goal, self.e.b).ok()?;
        let p = self.e.solve(&st, gv, true).ok()??;
        let p = st.finish(p);
        if has_erased(&p) {
            if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                eprintln!("opt: seq: a proof with a placeholder");
            }
            return None;
        }
        Some(Some(p))
    }

    fn proofs(&self) -> bool {
        true
    }

    fn accepts(&mut self, p: &Tm, goal: &Tm) -> bool {
        self.e.settle();
        let Ok(gv) = self.st.eval(self.e.env, goal, self.e.b) else { return false };
        let ok = self.e.env.check(&self.st.ctx, p, &gv, self.e.b).is_ok();
        self.e.settle();
        ok
    }
}

/// Decides the comparison `c` (its value `cv`, at `st`) by `linarith` over
/// the state's arithmetic facts and the length facts (`slice::ok_len`) of
/// the slices whose lists' lengths `c` mentions, without enrichment rounds
/// or case splits: cheap, and undecided when that fails (the side
/// conditions of the normal form are linear in the pieces' lengths).
pub fn lin_decide(e: &mut crate::auto::search::Engine<'_>, ids: &Ids, st: &crate::auto::state::St, c: &Tm, cv: &sandblaster_kernel::value::V) -> Option<(bool, Tm)> {
    let base = e.lin_hyps(st);
    lin_decide_with(e, ids, st, c, cv, base)
}

/// [`lin_decide`] with the state's facts as hypotheses already read back.
pub fn lin_decide_with(e: &mut crate::auto::search::Engine<'_>, ids: &Ids, st: &crate::auto::state::St, c: &Tm, cv: &sandblaster_kernel::value::V, base: Vec<(Tm, Tm)>) -> Option<(bool, Tm)> {
    use sandblaster_kernel::value::Value;
    let mut hyps = base;
    hyps.extend(ok_len_hyps(ids, c));
    let bt = Rc::new(Value::Ind { ind: ids.bool_ind, params: vec![] });
    for b in [true, false] {
        let g = Rc::new(Value::Eq { ty: bt.clone(), lhs: cv.clone(), rhs: e.bool_v(b) });
        if let Ok(Some(p)) = e.lin_with(st, &hyps, &g) {
            return Some((b, p));
        }
    }
    None
}

/// `slice::ok_len T s : Eq(Int, len(fst(snd(s))), cast(fst s))` for every
/// slice `s` whose list's length `t` mentions (outside binders).
fn ok_len_hyps(ids: &Ids, t: &Tm) -> Vec<(Tm, Tm)> {
    let mut hyps = Vec::new();
    let mut seen: Vec<Tm> = Vec::new();
    let mut slices: Vec<(Tm, Tm)> = Vec::new();
    crate::auto::util::map_term(t, 0, &mut |x, k| {
        if k == 0
            && let Some((g, args)) = head_app(x)
            && g == ids.len
            && args.len() == 2
            && let Term::Fst(y) = &*args[1].1
            && let Term::Snd(sl) = &**y
            && !seen.iter().any(|t| tm_eq(t, sl))
        {
            seen.push(sl.clone());
            slices.push((args[0].1.clone(), sl.clone()));
        }
        None
    });
    for (t, sl) in slices {
        let pf = mk::apps(mk::global(ids.slice_ok_len), [(Rel::Rel, t.clone()), (Rel::Rel, sl.clone())]);
        let ty = mk::eq(mk::int_ty(Width::Int), mk::apps(mk::global(ids.len), [(Rel::Rel, t), (Rel::Rel, mk::fst(mk::snd(sl.clone())))]), mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![mk::fst(sl)], vec![]));
        hyps.push((pf, ty));
    }
    hyps
}

/// Whether a term holds an `Erased` placeholder (a refused read-back).
pub fn has_erased(t: &Tm) -> bool {
    crate::elab::tm::any_node(t, &mut |n| matches!(n, Term::Erased))
}
