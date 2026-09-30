//! The `Word` step (optimizer design §5 `Word`, §12.4): a comparison of two
//! byte lists of one static length `8m`,
//! `seq::eq U8 (==) [a₀, …, a₈ₘ₋₁] [b₀, …, b₈ₘ₋₁]` (what
//! `[u8; 8m] == [u8; 8m]` unfolds to), is rewritten to its word form
//!
//! ```text
//! ((W(a, 0) ⊕ W(b, 0)) | ((W(a, 1) ⊕ W(b, 1)) | … (W(a, m−1) ⊕ W(b, m−1)))) == 0
//! W(x, j) = u64::from_le_bytes([x₈ⱼ, …, x₈ⱼ₊₇])
//! ```
//!
//! which is branch-free where the unrolled comparison is a chain of `8m`
//! branches. The proof is one lemma instance per block of eight bytes
//! (`lemmas/words.core`, checked): `word::seq_eq8_last` for the last block
//! and `word::seq_eq8_or` for the others, each given the proof of the blocks
//! after it; the last instance's right side is `seq::eq` on the two spines
//! of element terms, which is the source's comparison by conversion. No
//! `BvRefl` is issued per function: the word algebra lives in the lemmas.

use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, V, Value};

/// The globals the word form and its proof use.
#[derive(Clone, Copy, Debug)]
pub struct WordIds {
    pub seq_eq: GlobalId,
    pub index: GlobalId,
    pub and: GlobalId,
    pub from_le: GlobalId,
    pub array: GlobalId,
    pub list: IndId,
    pub bool_: IndId,
    pub eq8_or: GlobalId,
    pub eq8_last: GlobalId,
}

/// Largest compared length (bytes) rewritten to the word form.
pub const MAX_BYTES: usize = 256;

impl WordIds {
    /// The ids, when the environment has the prelude and the word lemmas.
    pub fn new(env: &Env) -> Option<WordIds> {
        Some(WordIds {
            seq_eq: env.lookup_global("seq::eq")?,
            index: env.lookup_global("seq::index")?,
            and: env.lookup_global("bool::and")?,
            from_le: env.lookup_global("u64::from_le_bytes")?,
            array: env.lookup_global("Array")?,
            list: env.lookup_ind("List")?,
            bool_: env.bool_ind(),
            eq8_or: env.lookup_global("word::seq_eq8_or")?,
            eq8_last: env.lookup_global("word::seq_eq8_last")?,
        })
    }

    /// The elements of the two byte lists of a word-form comparison
    /// `seq::eq T eq xs ys` (values): `T` is `U8`, `eq` the primitive
    /// equality `λx y. #eq_u8(x, y)`, `xs` and `ys` constructor spines of
    /// one length `8m` (`8 ≤ 8m ≤ MAX_BYTES`).
    pub fn detect(&self, def: GlobalId, args: &[Arg]) -> Option<(Vec<V>, Vec<V>)> {
        if def != self.seq_eq || args.len() != 4 {
            return None;
        }
        let rel = |i: usize| match &args[i] {
            Arg::Rel(v) => Some(v.clone()),
            Arg::Irr(_) => None,
        };
        if !matches!(&*rel(0)?, Value::IntTy(Width::U8)) || !is_prim_eq_u8(&rel(1)?) {
            return None;
        }
        let xs = self.elems(&rel(2)?)?;
        let ys = self.elems(&rel(3)?)?;
        (xs.len() == ys.len() && !xs.is_empty() && xs.len() % 8 == 0 && xs.len() <= MAX_BYTES).then_some((xs, ys))
    }

    fn elems(&self, v: &V) -> Option<Vec<V>> {
        let mut out = Vec::new();
        let mut cur = v.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ind, ctor: 0, .. } if *ind == self.list => return Some(out),
                Value::Ctor { ind, ctor: 1, args, .. } if *ind == self.list => match (args.first(), args.get(1)) {
                    (Some(Arg::Rel(x)), Some(Arg::Rel(t))) => {
                        out.push(x.clone());
                        t.clone()
                    }
                    _ => return None,
                },
                _ => return None,
            };
            if out.len() > MAX_BYTES {
                return None;
            }
            cur = next;
        }
    }

    /// `u64::from_le_bytes([x₈ⱼ, …, x₈ⱼ₊₇])` over the element terms of side
    /// `side` (0: the left list, 1: the right one).
    fn word(&self, elem: &dyn Fn(usize, usize) -> Tm, side: usize, j: usize) -> Tm {
        let u8t = mk::int_ty(Width::U8);
        let mut list = mk::ctor(self.list, 0, vec![u8t.clone()], vec![]);
        for i in (8 * j..8 * j + 8).rev() {
            list = mk::ctor(self.list, 1, vec![u8t.clone()], vec![elem(side, i), list]);
        }
        let arr_ty = mk::apps(mk::global(self.array), [(Rel::Rel, u8t), (Rel::Rel, mk::lit(Width::Usize, 8))]);
        let arr = mk::pair(arr_ty, list, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, 8)));
        mk::app(mk::global(self.from_le), arr)
    }

    fn xor_block(&self, elem: &dyn Fn(usize, usize) -> Tm, j: usize) -> Tm {
        mk::prim(PrimOp::Xor(Width::U64), vec![self.word(elem, 0, j), self.word(elem, 1, j)], vec![])
    }

    /// `Tⱼ`: the blocks from `j` on, `(W(a, j) ⊕ W(b, j)) | Tⱼ₊₁` (the last
    /// block alone).
    fn tail(&self, elem: &dyn Fn(usize, usize) -> Tm, m: usize, j: usize) -> Tm {
        let x = self.xor_block(elem, j);
        if j + 1 == m { x } else { mk::prim(PrimOp::Or(Width::U64), vec![x, self.tail(elem, m, j + 1)], vec![]) }
    }

    /// The word form of an `8m`-byte comparison: `T₀ == 0`.
    pub fn form(&self, elem: &dyn Fn(usize, usize) -> Tm, m: usize) -> Tm {
        mk::prim(PrimOp::Eq(Width::U64), vec![self.tail(elem, m, 0), mk::lit(Width::U64, 0)], vec![])
    }

    /// The list `[x_i, …, x_{n−1}]` of side `side`.
    fn list_from(&self, elem: &dyn Fn(usize, usize) -> Tm, side: usize, n: usize, i: usize) -> Tm {
        let u8t = mk::int_ty(Width::U8);
        let mut l = mk::ctor(self.list, 0, vec![u8t.clone()], vec![]);
        for k in (i..n).rev() {
            l = mk::ctor(self.list, 1, vec![u8t.clone()], vec![elem(side, k), l]);
        }
        l
    }

    /// The proof of `Eq(Bool, form, seq::eq U8 (==) [a₀, …] [b₀, …])`:
    /// `P₀` where `Pₘ₋₁ = word::seq_eq8_last ā b̄` and
    /// `Pⱼ = word::seq_eq8_or ā b̄ restₐ rest_b Tⱼ₊₁ .Pⱼ₊₁` (the bytes of
    /// block `j`, the lists after it).
    pub fn proof(&self, elem: &dyn Fn(usize, usize) -> Tm, m: usize) -> Tm {
        let n = 8 * m;
        let bytes = |j: usize| -> Vec<(Rel, Tm)> { (0..2).flat_map(|side| (8 * j..8 * j + 8).map(move |i| (side, i))).map(|(side, i)| (Rel::Rel, elem(side, i))).collect() };
        let mut p = mk::apps(mk::global(self.eq8_last), bytes(m - 1));
        for j in (0..m - 1).rev() {
            let mut args = bytes(j);
            args.push((Rel::Rel, self.list_from(elem, 0, n, 8 * (j + 1))));
            args.push((Rel::Rel, self.list_from(elem, 1, n, 8 * (j + 1))));
            args.push((Rel::Rel, self.tail(elem, m, j + 1)));
            args.push((Rel::Irr, p));
            p = mk::apps(mk::global(self.eq8_or), args);
        }
        p
    }

    /// The element term `seq::index T xs i` (with the bound proofs by
    /// computation: the list is a spine of known length) of a syntactic
    /// list `xs : List(T)`.
    pub fn index_tm(&self, t: &Tm, xs: &Tm, i: usize) -> Tm {
        let refl_true = mk::refl(mk::bool_ty(self.bool_), mk::bool_lit(self.bool_, true));
        mk::apps(mk::global(self.index), [(Rel::Rel, t.clone()), (Rel::Rel, xs.clone()), (Rel::Rel, mk::lit(Width::Int, i as u64)), (Rel::Irr, refl_true.clone()), (Rel::Irr, refl_true)])
    }
}

/// `λx y. #eq_u8(x, y)`.
fn is_prim_eq_u8(v: &V) -> bool {
    let Value::Lam { body, .. } = &**v else { return false };
    let Term::Lam { body: inner, .. } = &*body.body else { return false };
    matches!(&**inner, Term::Prim { op: PrimOp::Eq(Width::U8), args, .. } if args.len() == 2
        && matches!(&*args[0], Term::Var(sandblaster_kernel::term::Idx(1)))
        && matches!(&*args[1], Term::Var(sandblaster_kernel::term::Idx(0))))
}

/// The element term of the driver's evaluation environment: the `2n`
/// elements bound in order (left list, then right list) as the innermost
/// variables.
pub fn env_elem(n: usize) -> impl Fn(usize, usize) -> Tm {
    move |side, i| Rc::new(Term::Var(sandblaster_kernel::term::Idx((2 * n - 1 - (side * n + i)) as u32)))
}
