//! Reference tests of the read-back memo (`src/quote.rs`; AUDIT.md §7.5):
//! memoized read-back must return **exactly** the term that unmemoized
//! read-back computes — same indices, names, relevance, `Erased`
//! placeholders and Σ annotations — for untyped and typed quoting, across
//! several calls on one quoter (the memo persists between them) compared
//! with a fresh unmemoized quoter per call.
//!
//! This file is a unit-test module of `src/quote.rs` (included under
//! `cfg(test)` because it needs the crate-private `Quoter`), kept here so it
//! does not count towards the kernel's size. Run:
//! `cargo test -p sandblaster-kernel --lib`.
//!
//! Covered: random value DAGs with sharing across binders at different
//! depths; closures whose environments are captured at different levels,
//! quoted by substitution at different depths and under binders of their
//! own; irrelevant positions (arguments, pair components, constructor
//! fields, primitive proof slots, `let`s); `Erased` in closure bodies;
//! neutral heads of every kind and match/projection spines; typed contexts
//! (the one input besides the key: a level whose type changes must drop the
//! deeper entries); proof chains that are exponential as trees; and — the
//! red-team generator of 2026-09-25 — values outside the level discipline
//! (closure environments mentioning levels their body binds, values
//! mentioning levels not bound where they are read back), for which the type
//! read for a level must still be a function of the path to the read.

use std::rc::Rc;

use num_bigint::BigInt;

use super::{Key, Quoter};
use crate::api::Env;
use crate::eval::{neu, var_v};
use crate::term::{GlobalId, IndId, Lvl, PrimOp, Rel, Sort, Term, Tm, Width};
use crate::util::{FxSet, children, mk, rebuild_with};
use crate::value::{Arg, Budget, Closure, Elim, EnvEntry, Head, V, VEnv, Value};

// ---------------------------------------------------------------------------
// exact comparison of terms (DAG-aware)
// ---------------------------------------------------------------------------

/// A node without its children: its `Debug` with every child `Erased`
/// (variant, names, relevance, indices, literals, widths, ids, ...).
fn shape(t: &Tm) -> String {
    let n = children(t).len();
    format!("{:?}", rebuild_with(t, (0..n).map(|_| Rc::new(Term::Erased)).collect()))
}

/// Exact structural equality, linear in the two DAGs.
fn same(a: &Tm, b: &Tm, seen: &mut FxSet<(usize, usize)>) -> bool {
    if Rc::ptr_eq(a, b) || !seen.insert((Rc::as_ptr(a) as *const () as usize, Rc::as_ptr(b) as *const () as usize)) {
        return true;
    }
    if shape(a) != shape(b) {
        return false;
    }
    let (ka, kb) = (children(a), children(b));
    ka.len() == kb.len() && ka.iter().zip(&kb).all(|((x, i), (y, j))| i == j && same(x, y, seen))
}

fn assert_same(a: &Tm, b: &Tm, what: &str) {
    assert!(same(a, b, &mut FxSet::default()), "{what}: memoized read-back differs from the reference\n memo: {a:?}\n  ref: {b:?}");
}

/// Distinct nodes of a term DAG.
fn dag_nodes(t: &Tm) -> usize {
    let mut seen: FxSet<usize> = FxSet::default();
    let mut stack = vec![t.clone()];
    while let Some(n) = stack.pop() {
        if seen.insert(Rc::as_ptr(&n) as *const () as usize) {
            stack.extend(children(&n).into_iter().map(|(c, _)| c.clone()));
        }
    }
    seen.len()
}

// ---------------------------------------------------------------------------
// random values
// ---------------------------------------------------------------------------

struct Gen {
    s: u64,
    /// Values generated so far, with the depth they are valid at (they
    /// mention only levels below it): reused to make DAGs, also deeper.
    vals: Vec<(u32, V)>,
    /// Closures (no binders of their own) with the depth they are valid at.
    clos: Vec<(u32, Closure)>,
    /// Closure bodies by their number of free variables: reused with other
    /// environments (as evaluation instantiates one body in many).
    bodies: Vec<(u32, Tm)>,
    opt: IndId,
    list: IndId,
    /// `BoxP (T) { | mk(x : T, .p : Eq(T, x, x)) }`: an irrelevant field.
    boxp: IndId,
    len: GlobalId,
}

impl Gen {
    fn new(env: &Env, seed: u64) -> Gen {
        Gen {
            s: seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5eed,
            vals: Vec::new(),
            clos: Vec::new(),
            bodies: Vec::new(),
            opt: env.lookup_ind("Option").unwrap(),
            list: env.lookup_ind("List").unwrap(),
            boxp: env.lookup_ind("BoxP").unwrap(),
            len: env.lookup_global("seq::len").unwrap(),
        }
    }

    fn next(&mut self) -> u64 {
        self.s = self.s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn coin(&mut self, k: u64) -> bool {
        self.below(k) == 0
    }

    fn rel(&mut self) -> Rel {
        if self.coin(3) { Rel::Irr } else { Rel::Rel }
    }

    fn lit(&mut self) -> V {
        Rc::new(Value::Lit { w: Width::U64, n: BigInt::from(self.below(1000)) })
    }

    fn u64t() -> V {
        Rc::new(Value::IntTy(Width::U64))
    }

    /// A value valid at depth `d` (mentions levels `< d` only), of about
    /// `n` nodes; often one generated before (sharing), possibly for a
    /// smaller depth (shared under binders).
    fn val(&mut self, d: u32, n: u32) -> V {
        if self.coin(3) {
            let c: Vec<V> = self.vals.iter().filter(|(e, _)| *e <= d).map(|(_, v)| v.clone()).collect();
            if !c.is_empty() {
                return c[self.below(c.len() as u64) as usize].clone();
            }
        }
        let v = self.new_val(d, n);
        self.vals.push((d, v.clone()));
        v
    }

    fn new_val(&mut self, d: u32, n: u32) -> V {
        if n == 0 {
            return match self.below(if d > 0 { 5 } else { 4 }) {
                0 => self.lit(),
                1 => Rc::new(Value::Sort(Sort::Type)),
                2 => Gen::u64t(),
                3 => Rc::new(Value::Ctor { ind: self.opt, ctor: 0, params: vec![Gen::u64t()], args: vec![] }),
                _ => var_v(Lvl(self.below(d as u64) as u32)),
            };
        }
        let m = n - 1;
        match self.below(9) {
            0 | 1 => self.neutral(d, m),
            2 => Rc::new(Value::Lam { name: mk::name("x"), rel: self.rel(), dom: self.val(d, m / 3), body: self.clo(d, 1, m) }),
            3 => Rc::new(Value::Pi { name: mk::name("x"), rel: self.rel(), dom: self.val(d, m / 3), cod: self.clo(d, 1, m) }),
            4 => Rc::new(Value::Sigma { name: mk::name("x"), snd_rel: self.rel(), fst: self.val(d, m / 3), snd: self.clo(d, 1, m) }),
            5 => Rc::new(Value::Pair { fst: self.val(d, m / 2), snd: self.arg(d, m / 2) }),
            6 => match self.below(3) {
                0 => Rc::new(Value::Ctor { ind: self.opt, ctor: 1, params: vec![self.val(d, 0)], args: vec![Arg::Rel(self.val(d, m))] }),
                1 => Rc::new(Value::Ctor {
                    ind: self.list,
                    ctor: 1,
                    params: vec![self.val(d, 0)],
                    args: vec![Arg::Rel(self.val(d, m / 2)), Arg::Rel(self.val(d, m / 2))],
                }),
                _ => Rc::new(Value::Ctor {
                    ind: self.boxp,
                    ctor: 0,
                    params: vec![self.val(d, 0)],
                    args: vec![Arg::Rel(self.val(d, m / 2)), Arg::Irr(self.clo(d, 0, m / 2))],
                }),
            },
            7 => Rc::new(Value::Eq { ty: self.val(d, m / 3), lhs: self.val(d, m / 3), rhs: self.val(d, m / 3) }),
            _ => Rc::new(Value::Refl { ty: self.val(d, m / 2), val: self.val(d, m / 2) }),
        }
    }

    fn arg(&mut self, d: u32, n: u32) -> Arg {
        if self.coin(2) { Arg::Irr(self.clo(d, 0, n)) } else { Arg::Rel(self.val(d, n)) }
    }

    fn neutral(&mut self, d: u32, n: u32) -> V {
        let head = match self.below(if d > 0 { 7 } else { 5 }) {
            0 => Head::Prim { op: PrimOp::WAdd(Width::U64), args: vec![self.val(d, n / 2), self.val(d, n / 2)], proofs: vec![] },
            1 => Head::Prim {
                op: PrimOp::Add(Width::U64),
                args: vec![self.val(d, n / 3), self.val(d, n / 3)],
                proofs: vec![self.clo(d, 0, n / 3)],
            },
            2 => Head::Global { def: self.len, args: vec![Arg::Rel(Gen::u64t()), self.arg(d, n / 2)] },
            3 => Head::Transport {
                ty: self.val(d, 0),
                lhs: self.val(d, n / 4),
                rhs: self.val(d, n / 4),
                motive: self.clo(d, 1, n / 4),
                val: self.val(d, n / 4),
            },
            4 => Head::Absurd { ty: self.val(d, n / 2) },
            _ => Head::Var(Lvl(self.below(d as u64) as u32)),
        };
        let mut spine = Vec::new();
        for _ in 0..self.below(3) {
            spine.push(match self.below(5) {
                0 | 1 => Elim::App(self.arg(d, n / 3)),
                2 => Elim::Fst,
                3 => Elim::Snd,
                _ => Elim::Match {
                    ind: self.opt,
                    params: vec![self.val(d, 0)],
                    motive: self.clo(d, 1, n / 3),
                    arms: vec![self.clo(d, 0, n / 3), self.clo(d, 1, n / 3)],
                },
            });
        }
        neu(head, spine)
    }

    /// A closure quoted at depth `d` or deeper, with `binders` binders of its
    /// own: its environment is captured at a random level `c ≤ d` (values
    /// and closures valid there, often shared), its body a random term.
    fn clo(&mut self, d: u32, binders: u32, n: u32) -> Closure {
        if binders == 0 && self.coin(3) {
            let c: Vec<Closure> = self.clos.iter().filter(|(e, _)| *e <= d).map(|(_, c)| c.clone()).collect();
            if !c.is_empty() {
                return c[self.below(c.len() as u64) as usize].clone();
            }
        }
        let c = self.below(d as u64 + 1) as u32;
        let m = if n == 0 { 0 } else { self.below(4) as u32 };
        let mut env = Vec::new();
        for _ in 0..m {
            env.push(if self.coin(3) { EnvEntry::Irr(self.clo(c, 0, n / 2)) } else { EnvEntry::Rel(self.val(c, n / 2)) });
        }
        let nv = m + binders;
        let old: Vec<Tm> = self.bodies.iter().filter(|(k, _)| *k == nv).map(|(_, t)| t.clone()).collect();
        let body = if !old.is_empty() && self.coin(3) {
            old[self.below(old.len() as u64) as usize].clone()
        } else {
            let t = self.term(nv, n);
            self.bodies.push((nv, t.clone()));
            t
        };
        let cl = Closure { env: VEnv(Rc::new(env)), body };
        if binders == 0 {
            self.clos.push((c, cl.clone()));
        }
        cl
    }

    /// A closure body over `nv` variables: evaluable shapes (applications,
    /// binders, pairs, projections, `let`s whose body uses the bound
    /// variable twice, primitives, matches, transports) and `Erased`.
    fn term(&mut self, nv: u32, n: u32) -> Tm {
        let var = |g: &mut Gen| if nv > 0 { mk::var(g.below(nv as u64) as u32) } else { mk::lit(Width::U64, 7u64) };
        if n == 0 {
            return match self.below(4) {
                0 => Rc::new(Term::Erased),
                1 => mk::lit(Width::U64, self.below(100)),
                _ => var(self),
            };
        }
        let m = n - 1;
        match self.below(13) {
            0 | 1 => var(self),
            2 => mk::app(self.term(nv, m / 2), self.term(nv, m / 2)),
            3 => {
                let a = if self.coin(2) { Rc::new(Term::Erased) } else { self.term(nv, m / 2) };
                mk::app_irr(self.term(nv, m / 2), a)
            }
            4 => mk::lam("y", self.rel(), self.term(nv, m / 3), self.term(nv + 1, m)),
            5 => mk::pi("y", self.rel(), self.term(nv, m / 3), self.term(nv + 1, m)),
            6 => mk::sigma("y", self.rel(), self.term(nv, m / 3), self.term(nv + 1, m)),
            7 => {
                let ty = if self.coin(2) { Rc::new(Term::Erased) } else { self.term(nv, m / 3) };
                mk::pair(ty, self.term(nv, m / 2), self.term(nv, m / 2))
            }
            8 => {
                let p = self.term(nv, m);
                if self.coin(2) { mk::fst(p) } else { mk::snd(p) }
            }
            9 => {
                let rel = self.rel();
                let (ty, val) = (self.term(nv, 0), self.term(nv, m / 2));
                let f = self.term(nv + 1, m / 2);
                mk::let_("z", rel, ty, val, mk::pair(Rc::new(Term::Erased), mk::var(0), mk::app(f, mk::var(0))))
            }
            10 => mk::prim(PrimOp::WAdd(Width::U64), vec![self.term(nv, m / 2), self.term(nv, m / 2)], vec![]),
            11 => Rc::new(Term::Match {
                ind: self.opt,
                params: vec![mk::int_ty(Width::U64)],
                scrut: self.term(nv, m / 3),
                motive: self.term(nv + 1, m / 3),
                arms: vec![mk::arm(&[], self.term(nv, m / 3)), mk::arm(&["v"], self.term(nv + 1, m / 3))],
            }),
            _ => {
                let eq = if self.coin(2) { Rc::new(Term::Erased) } else { self.term(nv, m / 5) };
                Rc::new(Term::Transport {
                    ty: self.term(nv, 0),
                    lhs: self.term(nv, m / 5),
                    rhs: self.term(nv, m / 5),
                    eq,
                    motive: self.term(nv + 1, m / 5),
                    val: self.term(nv, m / 5),
                })
            }
        }
    }

    /// Types of the context levels `0..d` for typed quoting (unknown,
    /// integers, Σ, Π from a Σ, an inductive).
    fn context(&mut self, d: u32) -> Vec<Option<V>> {
        (0..d)
            .map(|l| match self.below(5) {
                0 => None,
                1 => Some(Gen::u64t()),
                2 => Some(Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: Rel::Rel, fst: Gen::u64t(), snd: self.clo(l, 1, 2) })),
                3 => {
                    let dom = Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: self.rel(), fst: Gen::u64t(), snd: self.clo(l, 1, 2) });
                    Some(Rc::new(Value::Pi { name: mk::name("p"), rel: Rel::Rel, dom, cod: self.clo(l, 1, 2) }))
                }
                _ => Some(Rc::new(Value::Ind { ind: self.opt, params: vec![Gen::u64t()] })),
            })
            .collect()
    }
}

fn env() -> Env {
    let mut env = Env::with_prelude();
    env.load_core("inductive BoxP (T : Type) { | mk(x : T, .p : Eq(T, x, x)) }", &mut Budget { steps: 1_000_000 }).unwrap();
    env
}

/// The memoized and the reference (unmemoized) quoter of one mode.
fn quoters<'e>(env: &'e Env, typed: bool, types: &[Option<V>]) -> (Quoter<'e>, Quoter<'e>) {
    let make = |on: bool| {
        let mut q = if typed { Quoter::typed(env, types.to_vec()) } else { Quoter::untyped(env) };
        q.memo_on = on;
        q
    };
    (make(true), make(false))
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

/// Random sequences of read-backs on one quoter (values with and without an
/// expected type, closures by substitution with 0–2 binders of their own,
/// at depths at and above the context's), untyped and typed: every result
/// equals a fresh reference quoter's.
#[test]
fn memo_matches_the_reference_on_random_values() {
    let env = env();
    let mut entries = 0usize;
    for seed in 0..600u64 {
        let mut g = Gen::new(&env, seed);
        let typed = seed % 2 == 1;
        let d0 = g.below(4) as u32;
        let types = if typed { g.context(d0) } else { Vec::new() };
        let mut qm = quoters(&env, typed, &types).0;
        let size = 3 + (seed % 5) as u32;
        for step in 0..6 {
            let mut qr = quoters(&env, typed, &types).1;
            let d = d0 + g.below(4) as u32;
            let what = format!("seed {seed} step {step} (typed {typed}, depth {d})");
            if g.coin(3) {
                let binders = g.below(3) as u32;
                let c = g.clo(d, binders, size);
                let (a, b) = (qm.q_clo(Lvl(d), &c, binders), qr.q_clo(Lvl(d), &c, binders));
                assert_same(&a, &b, &what);
            } else {
                let v = g.val(d, size);
                let ty = if typed && g.coin(2) { g.val(d, 2) } else { Gen::u64t() };
                let ty = if g.coin(2) { Some(&ty) } else { None };
                let (a, b) = (qm.q(Lvl(d), &v, ty), qr.q(Lvl(d), &v, ty));
                assert_same(&a, &b, &what);
            }
            assert!(qr.memo.iter().all(|m| m.is_empty()), "the reference quoter memoized");
        }
        entries += qm.memo.iter().map(|m| m.len()).sum::<usize>();
    }
    assert!(entries > 1000, "the memo was hardly used ({entries} entries)");
}

/// A closure quoted by substitution at several depths, interleaved, on one
/// quoter: the indices are relative to each depth (`x1 x0` with `x0`, `x1`
/// captured at levels 0 and 1 reads back as `Var(d-1) Var(d-2)` at depth
/// `d`), a repeated read-back at the same depth is a hit (the same `Rc`),
/// and with a binder of its own the local variable stays `Var(0)`.
#[test]
fn closures_quoted_at_different_depths() {
    let env = env();
    let c = Closure {
        env: VEnv(Rc::new(vec![EnvEntry::Rel(var_v(Lvl(0))), EnvEntry::Rel(var_v(Lvl(1)))])),
        body: mk::app(mk::var(1), mk::var(0)),
    };
    let c1 = Closure { env: c.env.clone(), body: mk::app(mk::app(mk::var(2), mk::var(0)), mk::var(1)) };
    for typed in [false, true] {
        let types = vec![
            Some(Rc::new(Value::Pi {
                name: mk::name("p"),
                rel: Rel::Rel,
                dom: Gen::u64t(),
                cod: Closure { env: VEnv::default(), body: mk::int_ty(Width::U64) },
            })),
            None,
        ];
        let (mut qm, mut qr) = quoters(&env, typed, &types);
        let mut first: Vec<Option<Tm>> = vec![None; 8];
        for d in [2u32, 5, 3, 2, 5, 7, 3] {
            let (a, b) = (qm.q_clo(Lvl(d), &c, 0), qr.q_clo(Lvl(d), &c, 0));
            assert_same(&a, &b, &format!("depth {d}"));
            assert_eq!(shape(&a), shape(&mk::app(mk::var(0), mk::var(0))));
            let want = mk::app(mk::var(d - 1), mk::var(d - 2));
            assert!(same(&a, &want, &mut FxSet::default()), "depth {d}: {a:?}");
            match &first[d as usize] {
                Some(t) => assert!(Rc::ptr_eq(t, &a), "depth {d}: a repeated read-back must be a memo hit"),
                None => first[d as usize] = Some(a.clone()),
            }
            let (a1, b1) = (qm.q_clo(Lvl(d), &c1, 1), qr.q_clo(Lvl(d), &c1, 1));
            assert_same(&a1, &b1, &format!("depth {d}, one binder"));
            let want1 = mk::app(mk::app(mk::var(d), mk::var(0)), mk::var(d - 1));
            assert!(same(&a1, &want1, &mut FxSet::default()), "depth {d}, one binder: {a1:?}");
        }
        // the same closure with and without a binder of its own, same depth
        let (a0, a1) = (qm.q_clo(Lvl(3), &c, 0), qm.q_clo(Lvl(3), &c, 1));
        assert_same(&a0, &qr.q_clo(Lvl(3), &c, 0), "binders 0");
        assert_same(&a1, &qr.q_clo(Lvl(3), &c, 1), "binders 1");
        assert!(same(&a1, &mk::app(mk::var(2), mk::var(0)), &mut FxSet::default()), "{a1:?}");
        let key = |b: u32| Key::Clo(Rc::as_ptr(&c.env.0) as *const () as usize, Rc::as_ptr(&c.body) as *const () as usize, b);
        assert!(qm.memo[2].contains_key(&key(0)) && qm.memo[7].contains_key(&key(0)));
    }
}

/// Typed quoting reads the type of a variable head (Π domains annotate the
/// pairs of its arguments). Two sibling λs bind level 0 with different
/// types and their bodies evaluate to the same value `x (1, 2)`, quoted
/// both times at depth 1: the second λ must not reuse the first's entry
/// (its pair has another Σ). Setting the type of level 0 drops `memo[1..]`.
#[test]
fn a_level_whose_type_changes_drops_the_deeper_entries() {
    let env = env();
    let konst = |t: Tm| Closure { env: VEnv::default(), body: t };
    let sig = |snd: Tm| Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: Rel::Rel, fst: Gen::u64t(), snd: konst(snd) });
    let pi = |dom: V| Rc::new(Value::Pi { name: mk::name("p"), rel: Rel::Rel, dom, cod: konst(mk::int_ty(Width::U64)) });
    let lit = |n: u64| Rc::new(Value::Lit { w: Width::U64, n: BigInt::from(n) });
    let x_pair = neu(Head::Var(Lvl(0)), vec![Elim::App(Arg::Rel(Rc::new(Value::Pair { fst: lit(1), snd: Arg::Rel(lit(2)) })))]);
    // the body `Var(1)` is the environment's value (`Var(0)` is the λ's variable)
    let body = Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(x_pair)])), body: mk::var(1) };
    let lam = |dom: V| Rc::new(Value::Lam { name: mk::name("x"), rel: Rel::Rel, dom, body: body.clone() });
    let (la, lb) = (lam(pi(sig(mk::int_ty(Width::U64)))), lam(pi(sig(mk::ind(env.bool_id, vec![])))));
    let root = Rc::new(Value::Pair { fst: la, snd: Arg::Rel(lb) });
    let (mut qm, mut qr) = quoters(&env, true, &[]);
    let (a, b) = (qm.q(Lvl(0), &root, None), qr.q(Lvl(0), &root, None));
    assert_same(&a, &b, "sibling λs");
    let Term::Pair { fst, snd, .. } = &*a else { panic!("{a:?}") };
    let (Term::Lam { body: ba, .. }, Term::Lam { body: bb, .. }) = (&**fst, &**snd) else { panic!("{a:?}") };
    assert!(!same(ba, bb, &mut FxSet::default()), "the two bodies carry different Σ annotations: {ba:?} / {bb:?}");
    // and the same value under the same binder type is shared
    let root2 = Rc::new(Value::Pair { fst: lam(pi(sig(mk::int_ty(Width::U64)))), snd: Arg::Rel(lam(pi(sig(mk::int_ty(Width::U64))))) });
    let (a2, b2) = (qm.q(Lvl(0), &root2, None), qr.q(Lvl(0), &root2, None));
    assert_same(&a2, &b2, "sibling λs, equal types");
}

/// A value quoted twice at depth `d` whose read-back contains match arms:
/// their fields bind levels `d`, `d + 1`, and an arm body reads the type of
/// level `d + 1` (a variable head captured there). Between the two
/// read-backs, level `d + 1` gets another type. The memo entry at depth `d`
/// is kept (only deeper entries are dropped), so it is exact only because
/// every field sets the type of its level — also an irrelevant field, and
/// a field whose type could not be evaluated (budget: `None`).
#[test]
fn match_arm_fields_set_their_types() {
    let env = env();
    let lit = |n: u64| Rc::new(Value::Lit { w: Width::U64, n: BigInt::from(n) });
    let konst = |t: Tm| Closure { env: VEnv::default(), body: t };
    let sig = |snd: Tm| Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: Rel::Rel, fst: Gen::u64t(), snd: konst(snd) });
    let pi = |dom: V| Rc::new(Value::Pi { name: mk::name("p"), rel: Rel::Rel, dom, cod: konst(mk::int_ty(Width::U64)) });
    let lam = |dom: V| Rc::new(Value::Lam { name: mk::name("x"), rel: Rel::Rel, dom, body: konst(mk::var(0)) });
    let (ta, tb) = (pi(sig(mk::int_ty(Width::U64))), pi(sig(mk::ind(env.bool_id, vec![]))));
    let d = 1u32;
    // `y (1, 2)` with `y` the variable at level d + 1 (a field of the arm)
    let y_pair = neu(Head::Var(Lvl(d + 1)), vec![Elim::App(Arg::Rel(Rc::new(Value::Pair { fst: lit(1), snd: Arg::Rel(lit(2)) })))]);
    let list = env.lookup_ind("List").unwrap();
    let boxp = env.lookup_ind("BoxP").unwrap();
    for (ind, budget) in [(list, 0u64), (boxp, 0), (boxp, super::QUOTE_BUDGET)] {
        // arm k = the constructor with two fields: its body is the captured `y (1, 2)`
        let two = Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(y_pair.clone())])), body: mk::var(2) };
        let arms = if ind == list { vec![konst(mk::lit(Width::U64, 0u64)), two] } else { vec![two] };
        let s = neu(Head::Var(Lvl(0)), vec![Elim::Match { ind, params: vec![Gen::u64t()], motive: konst(mk::int_ty(Width::U64)), arms }]);
        let (mut qm, mut qr) = quoters(&env, true, &[None]);
        qm.budget = Budget { steps: budget };
        qr.budget = Budget { steps: budget };
        let mut outs = Vec::new();
        for (step, v, at) in [(0, lam(ta.clone()), d + 1), (1, s.clone(), d), (2, lam(tb.clone()), d + 1), (3, s.clone(), d)] {
            let (a, b) = (qm.q(Lvl(at), &v, None), qr.q(Lvl(at), &v, None));
            assert_same(&a, &b, &format!("{ind:?} budget {budget} step {step}"));
            outs.push(a);
        }
    }
}

/// A chain of proofs, each referring to the previous one twice (two
/// distinct variable nodes, as `hn` in the chunking loops before the §15
/// fix): as a tree the read-back doubles per link. Memoized it is linear
/// (and equal to the reference while the reference is feasible).
#[test]
fn proof_chains_read_back_linearly() {
    let env = env();
    let chain = |k: usize| {
        let mut c = Closure { env: VEnv::default(), body: mk::lit(Width::U64, 0u64) };
        for _ in 0..k {
            let body = mk::pair(Rc::new(Term::Erased), mk::var(0), mk::var(0));
            c = Closure { env: VEnv(Rc::new(vec![EnvEntry::Irr(c)])), body };
        }
        c
    };
    for typed in [false, true] {
        for k in [1usize, 5, 12, 16] {
            let c = chain(k);
            let (mut qm, mut qr) = quoters(&env, typed, &[]);
            let (a, b) = (qm.q_clo(Lvl(0), &c, 0), qr.q_clo(Lvl(0), &c, 0));
            assert_same(&a, &b, &format!("chain {k}"));
            assert!(dag_nodes(&a) <= 6 * k + 2, "chain {k}: {} nodes", dag_nodes(&a));
            assert!(k < 12 || dag_nodes(&b) > 1 << k, "the reference is a tree");
        }
        // far beyond the reference: linear
        let c = chain(300);
        let (mut qm, _) = quoters(&env, typed, &[]);
        let a = qm.q_clo(Lvl(0), &c, 0);
        assert!(dag_nodes(&a) <= 6 * 300 + 2, "{} nodes", dag_nodes(&a));
        // under a binder: a λ whose body is an application to the chain
        let lam = Rc::new(Value::Lam {
            name: mk::name("x"),
            rel: Rel::Rel,
            dom: Gen::u64t(),
            body: Closure { env: VEnv(Rc::new(vec![EnvEntry::Irr(chain(40))])), body: mk::app_irr(mk::var(0), mk::var(1)) },
        });
        let (mut qm, _) = quoters(&env, typed, &[]);
        let t = qm.q(Lvl(0), &lam, None);
        assert!(dag_nodes(&t) <= 6 * 40 + 10, "{} nodes", dag_nodes(&t));
    }
}

/// Bounded, sharing and abstracting quoters never use the memo.
#[test]
fn the_memo_is_off_in_the_other_modes() {
    let env = env();
    let v = neu(Head::Var(Lvl(0)), vec![Elim::App(Arg::Rel(Gen::u64t()))]);
    let mut qb = Quoter::bounded(&env, vec![], 100);
    qb.q(Lvl(1), &v, None);
    assert!(qb.memo.iter().all(|m| m.is_empty()));
    let mut qs = Quoter::untyped(&env);
    qs.quote_root(Lvl(1), &v, None, true);
    assert!(qs.memo.iter().all(|m| m.is_empty()));
    let mut qa = Quoter::typed(&env, vec![None, None]).abstracting(Gen::u64t(), Lvl(1), true);
    qa.q(Lvl(2), &v, None);
    assert!(qa.memo.iter().all(|m| m.is_empty()));
}

/// Size of the tree a term DAG unfolds to (what a traversal without a memo
/// visits), saturating.
fn tree_size(t: &Tm, memo: &mut crate::util::FxMap<usize, u128>) -> u128 {
    let a = Rc::as_ptr(t) as *const () as usize;
    if let Some(n) = memo.get(&a) {
        return *n;
    }
    let n = children(t).into_iter().fold(1u128, |acc, (c, _)| acc.saturating_add(tree_size(c, memo)));
    memo.insert(a, n);
    n
}

/// The §15.7 known-answer path (`Env::eval_closed`, typed read-back) on
/// chunked data, whose length certificates are chains of proofs through the
/// loops' `hn` (and, for the Σ results of `chunks_c`/`chunks_rest_c` and the
/// `SliceOk` proofs of `slice::as_chunks`, through the loops' own
/// certificates `snd(r)`): the read-back is linear in the number of chunks
/// (quote memo), and so is the evaluation. For the chunks themselves the
/// tree the result unfolds to is polynomial — cubic: chunk k's certificate
/// is a chain of k links, each mentioning the rest of the list — because
/// each step of `seq::chunks_go` refers to `hn` once (with the S1 prelude,
/// where `p1` and `pn` each referred to it, the tree doubled per chunk, and
/// so did the read-back without the memo: a 22-chunk
/// `Option<Seq<[u8; 4]>>` example exhausted 4 GB). The loops' certificates
/// mention the previous result `r` twice (`snd(r) : … fst(r) …`), so their
/// trees still grow exponentially; only the memo keeps them linear.
#[test]
fn chunk_certificates_read_back_linearly() {
    let run = || {
        crate::util::set_stack_limit(60 << 20);
        let env = Env::with_prelude();
        // (form, whether its unfolded tree is polynomial)
        let forms = [
            ("seq::chunks U8 4usize .refl(Bool, true) ({L})", true),
            ("Some[List(Array U8 4usize)](seq::chunks U8 4usize .refl(Bool, true) ({L}))", true),
            ("seq::chunks_c U8 4usize .refl(Bool, true) ({L})", false),
            ("seq::chunks_rest_c U8 4usize .refl(Bool, true) (Cons[U8](1u8, {L}))", false),
            (
                "slice::as_chunks U8 (array::as_slice U8 {N}usize (pair(Array U8 {N}usize, {L}, refl(Int, {N}int))) .refl(Bool, true)) 4usize .refl(Bool, true)",
                false,
            ),
        ];
        for (form, poly) in forms {
            let mut rows: Vec<(usize, usize, u128, u64)> = Vec::new();
            for k in [4usize, 8, 12, 16, 19, 22, 32, 64] {
                let l = (0..4 * k).rev().fold("Nil[U8]".to_string(), |acc, i| format!("Cons[U8]({}u8, {acc})", i % 251));
                let src = form.replace("{N}", &(4 * k).to_string()).replace("{L}", &l);
                let t = env.parse_term(&[], &src).unwrap_or_else(|e| panic!("{form}: {e}"));
                let mut b = Budget { steps: 100_000_000 };
                let r = env.eval_closed(&t, &mut b).unwrap_or_else(|e| panic!("{form}, {k} chunks: {e}"));
                rows.push((k, dag_nodes(&r), tree_size(&r, &mut Default::default()), 100_000_000 - b.steps));
            }
            println!("{form}\n  (chunks, read-back DAG nodes, unfolded tree nodes, steps): {rows:?}");
            let at = |k: usize| rows.iter().find(|r| r.0 == k).unwrap();
            let (a, b) = (at(32), at(64));
            assert!(b.1 * 10 <= a.1 * 22, "{form}: read-back not linear: {rows:?}");
            assert!(b.3 * 10 <= a.3 * 22, "{form}: evaluation not linear: {rows:?}");
            assert!(!poly || b.2 <= a.2 * 9, "{form}: the unfolded result grows faster than cubically: {rows:?}");
        }
    };
    std::thread::Builder::new().stack_size(64 << 20).spawn(run).unwrap().join().unwrap();
}

// ---------------------------------------------------------------------------
// the type read for a level is a function of the path to the read
// ---------------------------------------------------------------------------
//
// Red-team finding of 2026-09-25: a single typed read-back on a fresh quoter
// returned other Σ annotations memoized than unmemoized. A memo hit skips
// the binders inside the memoized node, so the types those binders would
// have set are not set; that is harmless only if nothing reads a level's
// type except under the binder of that level on the path to the read. The
// levels bound by a closure quoted by substitution broke it (its own binders
// and those in its body set no type), for values outside the level
// discipline of AUDIT.md §2.1 (an environment value mentioning a level the
// body binds), which the memo must not rely on. Also, an earlier call from
// outside could leave types below a later call's depth.

fn konst(t: Tm) -> Closure {
    Closure { env: VEnv::default(), body: t }
}

fn lit(n: u64) -> V {
    Rc::new(Value::Lit { w: Width::U64, n: BigInt::from(n) })
}

/// `Π(p : Σ(a : U64). B). U64`: a variable of this type annotates the pair
/// it is applied to with `Σ(a : U64). B`.
fn pi_sig(b: Tm) -> V {
    let dom = Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: Rel::Rel, fst: Gen::u64t(), snd: konst(b) });
    Rc::new(Value::Pi { name: mk::name("p"), rel: Rel::Rel, dom, cod: konst(mk::int_ty(Width::U64)) })
}

/// `x (1, 2)` for the variable `x` at level `l`.
fn x_pair(l: u32) -> V {
    neu(Head::Var(Lvl(l)), vec![Elim::App(Arg::Rel(Rc::new(Value::Pair { fst: lit(1), snd: Arg::Rel(lit(2)) })))])
}

fn lam_v(dom: V, body: Closure) -> V {
    Rc::new(Value::Lam { name: mk::name("x"), rel: Rel::Rel, dom, body })
}

fn pair_v(fst: V, snd: Arg) -> V {
    Rc::new(Value::Pair { fst, snd })
}

/// The second components of the Σ annotations of the pairs in `t`, in
/// pre-order (`None`: `Erased`).
fn annotations(t: &Tm) -> Vec<Option<String>> {
    fn go(t: &Tm, out: &mut Vec<Option<String>>) {
        if let Term::Pair { ty, .. } = &**t {
            out.push(match &**ty {
                Term::Sigma { snd, .. } => Some(format!("{snd:?}")),
                _ => None,
            });
        }
        for (c, _) in children(t) {
            go(c, out);
        }
    }
    let mut out = Vec::new();
    go(t, &mut out);
    out
}

/// `A = Π(p : Σ(a : U64). U64). U64`, `B = Π(p : Σ(a : U64). Bool). U64`, and
/// `m = x0 (λ(x : B). x)` at depth 1: a neutral (memoized) whose read-back
/// binds level 1 with type `B`.
fn two_types(env: &Env) -> (V, V, V) {
    let (ta, tb) = (pi_sig(mk::int_ty(Width::U64)), pi_sig(mk::ind(env.bool_id, vec![])));
    let m = neu(Head::Var(Lvl(0)), vec![Elim::App(Arg::Rel(lam_v(tb.clone(), konst(mk::var(0)))))]);
    (ta, tb, m)
}

/// A closure quoted by substitution binds levels without a type: a value
/// its body reads back under such a binder that mentions the binder's level
/// reads `None` there. The red-team case: `(m, (λ(x : A). 0, (m, p)))` at
/// depth 1, with `p` the proof `λ(y : U64). x1 (1, 2)`: memoized, the hit on
/// the second `m` skipped its binder of type `B`, and `p`'s pair got `A`'s Σ;
/// unmemoized it got `B`'s.
#[test]
fn closure_binders_read_as_unknown() {
    let env = env();
    let (ta, _, m) = two_types(&env);
    let la = lam_v(ta, konst(mk::lit(Width::U64, 0u64)));
    let p =
        Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(x_pair(1))])), body: mk::lam("y", Rel::Rel, mk::int_ty(Width::U64), mk::var(1)) };
    let root = pair_v(m.clone(), Arg::Rel(pair_v(la, Arg::Rel(pair_v(m, Arg::Irr(p))))));
    let (mut qm, mut qr) = quoters(&env, true, &[None]);
    let (a, b) = (qm.q(Lvl(1), &root, None), qr.q(Lvl(1), &root, None));
    assert_same(&a, &b, "a proof's binder");
    assert!(annotations(&a).iter().all(|x| x.is_none()), "{a:?}");
}

/// Within one closure body the free variables are read back at several
/// depths in turn, and one read-back may bind levels the body binds too
/// (here the λ of type `B`, read back under one binder, binds the level of
/// the body's second binder): a later read-back under both binders must
/// again read `None` for them.
#[test]
fn closure_binders_stay_unknown_between_free_variables() {
    let env = env();
    let (_, tb, _) = two_types(&env);
    let e = VEnv(Rc::new(vec![EnvEntry::Rel(lam_v(tb, konst(mk::var(0)))), EnvEntry::Rel(x_pair(2))]));
    let u = || mk::int_ty(Width::U64);
    let under2 = || mk::lam("a", Rel::Rel, u(), mk::lam("b", Rel::Rel, u(), mk::var(2)));
    // (λa. λb. x2 (1, 2), (λa. (λ(x : B). x), λa. λb. x2 (1, 2)))
    let body =
        mk::pair(Rc::new(Term::Erased), under2(), mk::pair(Rc::new(Term::Erased), mk::lam("a", Rel::Rel, u(), mk::var(2)), under2()));
    let c = Closure { env: e, body };
    let (mut qm, mut qr) = quoters(&env, true, &[None]);
    let (a, b) = (qm.q_clo(Lvl(1), &c, 0), qr.q_clo(Lvl(1), &c, 0));
    assert_same(&a, &b, "free variables in turn");
    assert_eq!(annotations(&a), vec![None, None, None, None], "{a:?}");
}

/// A match-arm field whose type cannot be evaluated sets `None` for its
/// level (it used to keep the type of an earlier binder of that level). With
/// budget left — the type of `BigF`'s second field overflows `Int` — the arm
/// is read back by NbE, and its body applies that field: after `λ(x : A). x`
/// at depth 2 (level 2 of type `A`), `x0` matched with `mk(a, x) => x (1,
/// 2)` at depth 1 (`x` at level 2) must not annotate the pair with `A`'s Σ.
#[test]
fn a_field_whose_type_cannot_be_evaluated_sets_none() {
    let mut env = env();
    env.load_core("inductive BigF (n : Int) { | mk(a : U64, x : Eq(Int, #imul(n, n), n)) }", &mut Budget { steps: 1_000_000 }).unwrap();
    let (ta, tb, _) = two_types(&env);
    let big = Rc::new(Value::Lit { w: Width::Int, n: BigInt::from(1u8) << 3000u32 });
    let arm = konst(mk::app(mk::var(0), mk::pair(Rc::new(Term::Erased), mk::lit(Width::U64, 1u64), mk::lit(Width::U64, 2u64))));
    let ind = env.lookup_ind("BigF").unwrap();
    let s = neu(Head::Var(Lvl(0)), vec![Elim::Match { ind, params: vec![big], motive: konst(mk::int_ty(Width::U64)), arms: vec![arm] }]);
    let mut qm = quoters(&env, true, &[None]).0;
    for (step, (v, d)) in [(lam_v(ta, konst(mk::var(0))), 2), (s.clone(), 1), (lam_v(tb, konst(mk::var(0))), 2), (s, 1)].iter().enumerate()
    {
        let a = qm.q(Lvl(*d), v, None);
        assert_same(&a, &quoters(&env, true, &[None]).1.q(Lvl(*d), v, None), &format!("step {step}"));
        assert!(annotations(&a).iter().all(|x| x.is_none()), "step {step}: {a:?}");
    }
}

/// Every call from outside the quoter reads the context it was given, not
/// the types an earlier call's binders left: at a depth beyond the context
/// (its levels unknown) and after a call below the context's depth (which
/// binds a context level); through `q` and `q_clo`.
#[test]
fn each_call_starts_from_the_context() {
    let env = env();
    let (ta, tb, _) = two_types(&env);
    let binder_b = lam_v(tb, konst(mk::var(0)));
    let fresh = |types: &[Option<V>]| quoters(&env, true, types).1;
    // beyond the context: level 1 is unknown to the second call
    let (mut qm, _) = quoters(&env, true, &[None]);
    qm.q(Lvl(1), &binder_b, None);
    let a = qm.q(Lvl(2), &x_pair(1), None);
    assert_same(&a, &fresh(&[None]).q(Lvl(2), &x_pair(1), None), "beyond the context");
    assert_eq!(annotations(&a), vec![None]);
    // below it: the first call binds level 0, whose type the context gives
    let ctx = [Some(ta)];
    let want = vec![Some(format!("{:?}", mk::int_ty(Width::U64)))];
    let (mut qm, _) = quoters(&env, true, &ctx);
    qm.q(Lvl(0), &binder_b, None);
    let a = qm.q(Lvl(1), &x_pair(0), None);
    assert_same(&a, &fresh(&ctx).q(Lvl(1), &x_pair(0), None), "below the context");
    assert_eq!(annotations(&a), want);
    qm.q(Lvl(0), &binder_b, None);
    let c = Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(x_pair(0))])), body: mk::var(0) };
    let a = qm.q_clo(Lvl(1), &c, 0);
    assert_same(&a, &fresh(&ctx).q_clo(Lvl(1), &c, 0), "below the context, by substitution");
    assert_eq!(annotations(&a), want);
}

// ---------------------------------------------------------------------------
// red-team generator (2026-09-25)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn coin(&mut self, k: u64) -> bool {
        self.below(k) == 0
    }
}

/// Values built to make typed read-back consult levels whose type differs
/// between address-identical occurrences: binder types that annotate
/// (`Π` from a `Σ`), shared or freshly allocated; open values shared across
/// sibling binders of one level and reused deeper; match arms over two
/// fields of such types whose body is a value captured at the arm's field
/// levels; closures whose environment mentions the level they bind; proof
/// closures (by substitution) with a binder in their body.
struct Atk {
    fb: IndId,
    opt: IndId,
    bool_id: IndId,
    pool: Vec<V>,
    /// Open values by the depth they were made for.
    opens: Vec<(u32, V)>,
    /// Binder values by the depth they are read back at.
    binders: Vec<(u32, V)>,
    /// Proof closures by the depth they were made for.
    clos: Vec<(u32, Closure)>,
}

impl Atk {
    fn new(env: &Env) -> Atk {
        Atk {
            fb: env.lookup_ind("FB").unwrap(),
            opt: env.lookup_ind("Option").unwrap(),
            bool_id: env.bool_id,
            pool: Vec::new(),
            opens: Vec::new(),
            binders: Vec::new(),
            clos: Vec::new(),
        }
    }

    fn sig(&self, which: u64) -> V {
        let snd = match which % 3 {
            0 => mk::int_ty(Width::U64),
            1 => mk::ind(self.bool_id, vec![]),
            _ => mk::int_ty(Width::U32),
        };
        Rc::new(Value::Sigma { name: mk::name("a"), snd_rel: Rel::Rel, fst: Gen::u64t(), snd: konst(snd) })
    }

    /// A binder type: `U64` or a `Π` whose domain is a `Σ`, shared or new.
    fn ty(&mut self, r: &mut Rng) -> V {
        if !self.pool.is_empty() && r.coin(2) {
            return self.pool[r.below(self.pool.len() as u64) as usize].clone();
        }
        let t = match r.below(4) {
            0 => Gen::u64t(),
            k => Rc::new(Value::Pi { name: mk::name("p"), rel: Rel::Rel, dom: self.sig(k), cod: konst(mk::int_ty(Width::U64)) }),
        };
        if r.coin(2) {
            self.pool.push(t.clone());
        }
        t
    }

    fn pair(&self, r: &mut Rng) -> V {
        pair_v(lit(r.below(3)), Arg::Rel(lit(r.below(3))))
    }

    /// An open value mentioning levels `< hi` (often `hi - 1`).
    fn open(&mut self, r: &mut Rng, hi: u32, n: u32) -> V {
        if hi == 0 {
            return lit(r.below(5));
        }
        if r.coin(3) {
            let c: Vec<V> = self.opens.iter().filter(|(h, _)| *h <= hi).map(|(_, v)| v.clone()).collect();
            if !c.is_empty() {
                return c[r.below(c.len() as u64) as usize].clone();
            }
        }
        let l = if r.coin(2) { hi - 1 } else { r.below(hi as u64) as u32 };
        let v = match if n == 0 { 0 } else { r.below(6) } {
            0 | 1 => neu(Head::Var(Lvl(l)), vec![Elim::App(Arg::Rel(self.pair(r)))]),
            2 => neu(Head::Var(Lvl(l)), vec![Elim::App(Arg::Rel(self.open(r, hi, n - 1)))]),
            3 => Rc::new(Value::Ctor { ind: self.opt, ctor: 1, params: vec![Gen::u64t()], args: vec![Arg::Rel(self.open(r, hi, n - 1))] }),
            4 => neu(
                Head::Prim { op: PrimOp::WAdd(Width::U64), args: vec![self.open(r, hi, n - 1), self.open(r, hi, n - 1)], proofs: vec![] },
                vec![],
            ),
            _ => {
                // a match whose arm returns a value over the fields (levels hi, hi + 1 at depth hi)
                let s = r.below(hi as u64) as u32;
                let inner = self.open(r, hi + 2, n - 1);
                let arm = Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(inner)])), body: mk::var(2) };
                neu(
                    Head::Var(Lvl(s)),
                    vec![Elim::Match { ind: self.fb, params: vec![], motive: konst(mk::int_ty(Width::U64)), arms: vec![arm] }],
                )
            }
        };
        self.opens.push((hi, v.clone()));
        v
    }

    /// A binder value read back at depth `d` whose body returns values
    /// captured in its environment that mention its own level `d`.
    fn binder(&mut self, r: &mut Rng, d: u32, n: u32) -> V {
        if r.coin(3) {
            let c: Vec<V> = self.binders.iter().filter(|(e, _)| *e == d).map(|(_, v)| v.clone()).collect();
            if !c.is_empty() {
                return c[r.below(c.len() as u64) as usize].clone();
            }
        }
        let mut env = Vec::new();
        for _ in 0..1 + r.below(3) {
            env.push(EnvEntry::Rel(if n > 0 && r.coin(3) { self.binder(r, d + 1, n - 1) } else { self.open(r, d + 1, n) }));
        }
        let k = env.len() as u32;
        let body = match r.below(4) {
            0 => mk::app(mk::var(0), mk::pair(Rc::new(Term::Erased), mk::lit(Width::U64, 1u64), mk::lit(Width::U64, 2u64))),
            _ => mk::var(1 + r.below(k as u64) as u32),
        };
        let clo = Closure { env: VEnv(Rc::new(env)), body };
        let dom = self.ty(r);
        let v = match r.below(4) {
            0 => Rc::new(Value::Pi { name: mk::name("x"), rel: Rel::Rel, dom, cod: clo }),
            1 => Rc::new(Value::Sigma { name: mk::name("x"), snd_rel: Rel::Rel, fst: dom, snd: clo }),
            _ => lam_v(dom, clo),
        };
        self.binders.push((d, v.clone()));
        v
    }

    /// A proof closure over open values and other proofs.
    fn proof(&mut self, r: &mut Rng, d: u32, n: u32) -> Closure {
        if r.coin(3) {
            let c: Vec<Closure> = self.clos.iter().filter(|(e, _)| *e <= d).map(|(_, c)| c.clone()).collect();
            if !c.is_empty() {
                return c[r.below(c.len() as u64) as usize].clone();
            }
        }
        let mut env = Vec::new();
        for _ in 0..1 + r.below(3) {
            env.push(if n > 0 && r.coin(2) { EnvEntry::Irr(self.proof(r, d, n - 1)) } else { EnvEntry::Rel(self.open(r, d, n)) });
        }
        let k = env.len() as u32;
        let body = match r.below(3) {
            0 => mk::pair(Rc::new(Term::Erased), mk::var(r.below(k as u64) as u32), mk::var(r.below(k as u64) as u32)),
            1 => mk::lam("y", Rel::Rel, mk::int_ty(Width::U64), mk::app(mk::var(1 + r.below(k as u64) as u32), mk::var(0))),
            _ => mk::var(r.below(k as u64) as u32),
        };
        let c = Closure { env: VEnv(Rc::new(env)), body };
        self.clos.push((d, c.clone()));
        c
    }

    fn root(&mut self, r: &mut Rng, d: u32, n: u32) -> V {
        match r.below(5) {
            0 => {
                let (a, b) = (self.binder(r, d, n), self.binder(r, d, n));
                pair_v(a, Arg::Rel(b))
            }
            1 => {
                let mut l: V = Rc::new(Value::Ctor { ind: self.opt, ctor: 0, params: vec![Gen::u64t()], args: vec![] });
                for _ in 0..1 + r.below(4) {
                    l = pair_v(self.binder(r, d, n), Arg::Rel(l));
                }
                l
            }
            2 => {
                let p = self.proof(r, d, n);
                pair_v(self.binder(r, d, n), Arg::Irr(p))
            }
            3 if d > 0 => {
                let f = r.below(d as u64) as u32;
                neu(Head::Var(Lvl(f)), vec![Elim::App(Arg::Rel(self.binder(r, d, n))), Elim::App(Arg::Irr(self.proof(r, d, n)))])
            }
            _ => self.open(r, d, n),
        }
    }

    /// A context of `d0` levels for typed quoting.
    fn context(&mut self, r: &mut Rng, d0: u32) -> Vec<Option<V>> {
        (0..d0).map(|_| if r.coin(4) { None } else { Some(self.ty(r)) }).collect()
    }
}

fn atk_env() -> Env {
    let mut env = env();
    env.load_core(
        "inductive FB { | mk(f : (p : Sigma (a : U64), U64) -> U64, g : (p : Sigma (a : U64), Bool) -> U64) }",
        &mut Budget { steps: 1_000_000 },
    )
    .unwrap();
    env
}

/// The kernel's use: one read-back on a fresh quoter (typed, and untyped),
/// values and proofs by substitution. The red-team run failed at seed 4421.
#[test]
fn one_read_back_matches_on_red_team_values() {
    let env = atk_env();
    for seed in 0..40_000u64 {
        let mut r = Rng(seed ^ 0x1234_5678);
        let mut a = Atk::new(&env);
        let typed = seed % 3 != 0;
        let d0 = r.below(3) as u32;
        let types = a.context(&mut r, d0);
        let d = d0 + r.below(2) as u32;
        let n = 2 + (seed % 3) as u32;
        let v = a.root(&mut r, d, n);
        let ty = if r.coin(3) { Some(a.ty(&mut r)) } else { None };
        let (mut qm, mut qr) = quoters(&env, typed, &types);
        let what = format!("seed {seed} typed {typed} depth {d}");
        assert_same(&qm.q(Lvl(d), &v, ty.as_ref()), &qr.q(Lvl(d), &v, ty.as_ref()), &what);
        let c = a.proof(&mut r, d, n);
        let b = r.below(2) as u32;
        let (mut qm, mut qr) = quoters(&env, typed, &types);
        assert_same(&qm.q_clo(Lvl(d), &c, b), &qr.q_clo(Lvl(d), &c, b), &format!("{what}, by substitution"));
    }
}

/// Deeper values: the red-team search for a *wrong* Σ annotation (another
/// non-`Erased` type than the reference's; seeds 443 at size 3 and 33912 at
/// size 5 found one) finds no difference at all.
#[test]
fn one_read_back_matches_on_deeper_red_team_values() {
    let env = atk_env();
    for n in 3..=6u32 {
        for seed in 0..20_000u64 {
            let mut r = Rng(seed ^ 0xBEEF);
            let mut a = Atk::new(&env);
            let d0 = r.below(3) as u32;
            let types = a.context(&mut r, d0);
            let d = d0 + r.below(2) as u32;
            let v = a.root(&mut r, d, n);
            let ty = if r.coin(3) { Some(a.ty(&mut r)) } else { None };
            let (mut qm, mut qr) = quoters(&env, true, &types);
            assert_same(&qm.q(Lvl(d), &v, ty.as_ref()), &qr.q(Lvl(d), &v, ty.as_ref()), &format!("size {n} seed {seed} depth {d}"));
        }
    }
}

/// Long sequences of calls on one memoized quoter, at depths at and above
/// the context's, each compared with a fresh reference quoter.
#[test]
fn calls_on_one_quoter_match_on_red_team_values() {
    let env = atk_env();
    for seed in 0..4000u64 {
        let mut r = Rng(seed ^ 0xA77A);
        let mut a = Atk::new(&env);
        let typed = seed % 4 != 0;
        let d0 = r.below(3) as u32;
        let types = a.context(&mut r, d0);
        let mut qm = quoters(&env, typed, &types).0;
        let n = 2 + (seed % 3) as u32;
        for step in 0..25 {
            let mut qr = quoters(&env, typed, &types).1;
            let d = d0 + r.below(3) as u32;
            let what = format!("seed {seed} step {step} typed {typed} depth {d}");
            if r.coin(4) {
                let c = a.proof(&mut r, d, n);
                let b = r.below(2) as u32;
                assert_same(&qm.q_clo(Lvl(d), &c, b), &qr.q_clo(Lvl(d), &c, b), &what);
            } else {
                let v = a.root(&mut r, d, n);
                let ty = if r.coin(3) { Some(a.ty(&mut r)) } else { None };
                assert_same(&qm.q(Lvl(d), &v, ty.as_ref()), &qr.q(Lvl(d), &v, ty.as_ref()), &what);
            }
        }
    }
}

/// Values, closures and types allocated and dropped between the calls on
/// one memoized quoter (addresses are reused by the allocator): each result
/// equals a fresh reference quoter's.
#[test]
fn address_reuse_between_calls() {
    let env = atk_env();
    for typed in [false, true] {
        let mut qm = quoters(&env, typed, &[None, None]).0;
        for i in 0..20_000u64 {
            let mut r = Rng(i);
            let mut a = Atk::new(&env);
            let d = 2 + r.below(2) as u32;
            let mut qr = quoters(&env, typed, &[None, None]).1;
            if r.coin(2) {
                let c = a.proof(&mut r, d, 1);
                assert_same(&qm.q_clo(Lvl(d), &c, 0), &qr.q_clo(Lvl(d), &c, 0), &format!("closure {i}"));
            } else {
                let v = a.root(&mut r, d, 1);
                assert_same(&qm.q(Lvl(d), &v, None), &qr.q(Lvl(d), &v, None), &format!("value {i}"));
            }
        }
    }
}
