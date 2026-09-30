//! Types (DESIGN.md §3.2, §3.5): the translation `⟦T⟧` of HIR types to
//! core types, user structs and enums as inductives (§5.4), and the term
//! builders that depend only on types (projections, tuples, slices, arrays).
//!
//! | Rust | core |
//! | --- | --- |
//! | `bool` | `Bool` |
//! | `u8 … u64`, `usize` | `IntTy(U8 … Usize)` |
//! | `()`, `(A,)`, `(A, B, ..)` | `Unit`, `Tuple1(A)`, `TupleN(A, B, ..)` |
//! | `[T; N]` | `Array ⟦T⟧ N` |
//! | `&[T]` (and the unsized place `[T]`) | `Slice ⟦T⟧` |
//! | `&T` | `⟦T⟧` |
//! | `Option<T>` | `Option(⟦T⟧)` |
//! | user struct / enum `S<A..>` | inductive `crate::path::S(⟦A⟧..)` (one constructor per variant; a struct has one) |
//! | type parameter `T` | the `T : Type` binder (the first binders of every definition) |
//! | NEON / x86 vectors | `Array(lane, n)` (§9.2) |
//! | `Int`, `Nat` (ghost) | `IntTy(Int)` (`Nat`: the bound `0 ≤ n` is an obligation/hypothesis, SEMANTICS.md §13.5) |
//! | `Seq<T>` (ghost) | `List(⟦T⟧)` |
//! | `Prop` (ghost) | `Type` |
//! | `fn(A, B) -> C` (ghost) | `Π(_ : ⟦A⟧). Π(_ : ⟦B⟧). ⟦C⟧` |
//! | `!` | `Empty` |

use std::rc::Rc;

use num_bigint::BigInt;
use sandblaster_kernel::term::{Arm, CtorDecl, IndId, InductiveDecl, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};

use super::{internal, unsupported, Elab, R};
use crate::hir::{ItemId, ItemKind, Shape, Ty, UintTy};
use crate::span::Span;

impl<'a> Elab<'a> {
    /// `⟦t⟧` at context depth `depth` (type parameters are levels
    /// `0..ngen`).
    pub fn ty_at(&self, t: &Ty, depth: u32, span: Span) -> R<Tm> {
        Ok(match t {
            Ty::Bool => mk::bool_ty(self.p.bool_),
            Ty::Uint(u) => mk::int_ty(u.width()),
            Ty::Int | Ty::Nat => mk::int_ty(Width::Int),
            Ty::Seq(e) => mk::ind(self.p.list, vec![self.ty_at(e, depth, span)?]),
            Ty::Tuple(ts) if ts.is_empty() => mk::ind(self.p.unit, vec![]),
            Ty::Tuple(ts) => {
                let Some(ind) = self.p.tuple(ts.len()) else { return unsupported(span, format!("tuples of {} elements are not supported", ts.len())) };
                let ps = ts.iter().map(|x| self.ty_at(x, depth, span)).collect::<R<Vec<_>>>()?;
                mk::ind(ind, ps)
            }
            Ty::Array(e, n) => self.array_ty(self.ty_at(e, depth, span)?, *n),
            Ty::Slice(e) => self.slice_ty(self.ty_at(e, depth, span)?),
            Ty::Ref(inner) => self.ty_at(inner, depth, span)?,
            Ty::Option(e) => mk::ind(self.p.option, vec![self.ty_at(e, depth, span)?]),
            Ty::Adt(id, args) => {
                let ind = self.adt(*id, span)?;
                let ps = args.iter().map(|x| self.ty_at(x, depth, span)).collect::<R<Vec<_>>>()?;
                mk::ind(ind, ps)
            }
            Ty::Param(i, name) => {
                if *i >= depth {
                    return internal(span, format!("type parameter `{name}` is not in scope"));
                }
                mk::var(depth - 1 - *i)
            }
            Ty::Vector(v) => {
                let (lane, n) = v.lanes();
                self.array_ty(mk::int_ty(lane.width()), n)
            }
            // `fn(A, B) -> C` (ghost): `Π(_ : ⟦A⟧). Π(_ : ⟦B⟧). ⟦C⟧`, each type at
            // the depth of its binder (type parameters are levels)
            Ty::Fn(ps, r) => {
                let mut t = self.ty_at(r, depth + ps.len() as u32, span)?;
                for (i, p) in ps.iter().enumerate().rev() {
                    t = mk::pi("x", Rel::Rel, self.ty_at(p, depth + i as u32, span)?, t);
                }
                t
            }
            Ty::Prop => mk::ty(),
            Ty::Never => mk::ind(self.p.empty, vec![]),
            Ty::I32 => return unsupported(span, "`i32` is only the type of intrinsic immediates"),
            Ty::Proof => return internal(span, "a proof has no value type"),
            Ty::Error => return internal(span, "type error in a checked crate"),
        })
    }

    /// `⟦t⟧` at the current depth.
    pub fn ty(&self, t: &Ty, span: Span) -> R<Tm> {
        self.ty_at(t, self.depth(), span)
    }

    /// `Array T N`.
    pub fn array_ty(&self, elem: Tm, n: u64) -> Tm {
        mk::apps(mk::global(self.p.g("Array")), [(Rel::Rel, elem), (Rel::Rel, mk::lit(Width::Usize, n))])
    }

    /// `Slice T`.
    pub fn slice_ty(&self, elem: Tm) -> Tm {
        mk::app(mk::global(self.p.g("Slice")), elem)
    }

    /// `true` / `false`.
    pub fn bool_lit(&self, b: bool) -> Tm {
        mk::bool_lit(self.p.bool_, b)
    }

    /// `Eq(Bool, t, true)`.
    pub fn holds(&self, t: Tm) -> Tm {
        mk::eq_bool(self.p.bool_, t, true)
    }

    /// `tt`.
    pub fn unit_val(&self) -> Tm {
        mk::ctor(self.p.unit, 0, vec![], vec![])
    }

    /// A tuple value (`()` for no components, `Tuple1` for one).
    pub fn tuple_val(&self, tys: Vec<Tm>, vals: Vec<Tm>, span: Span) -> R<Tm> {
        if vals.is_empty() {
            return Ok(self.unit_val());
        }
        let Some(ind) = self.p.tuple(vals.len()) else { return unsupported(span, "tuple too large") };
        Ok(mk::ctor(ind, 0, tys, vals))
    }

    /// The inductive and parameters of a tuple type (`None` for unit).
    pub fn tuple_ind(&self, n: usize, span: Span) -> R<IndId> {
        match self.p.tuple(n) {
            Some(i) => Ok(i),
            None => unsupported(span, format!("tuples of {n} elements are not supported")),
        }
    }

    /// Projection `πₖ s` of a single-constructor value: `match s as _
    /// return Tₖ with c(x₀..xₙ) => xₖ`. `field_ty` is `Tₖ` at the current
    /// depth. The constructor's field count is taken from the kernel's
    /// declaration of `ind` (a struct with an invariant has trailing `Irr`
    /// fields the HIR does not list, DESIGN.md §15.3); `nfields` (the
    /// caller's count of relevant fields) is only a fallback for an
    /// inductive the environment does not know.
    pub fn proj(&self, ind: IndId, params: Vec<Tm>, s: Tm, k: usize, nfields: usize, field_ty: Tm) -> Tm {
        // (prelude tuples have exactly their components)
        let nfields = if self.p.tuple(nfields) == Some(ind) { nfields } else { self.ctor_nfields(ind, 0).unwrap_or(nfields) };
        // shortcut: projection of a constructor application
        if let Term::Ctor { ind: i2, ctor: 0, args, .. } = &*s
            && *i2 == ind
            && args.len() == nfields
        {
            return args[k].clone();
        }
        let names: Vec<&str> = (0..nfields).map(|_| "x").collect();
        let body = mk::var((nfields - 1 - k) as u32);
        Rc::new(Term::Match { ind, params, scrut: s, motive: shift(&field_ty, 1), arms: vec![Arm { names: names.iter().map(|n| Rc::from(*n)).collect(), body }] })
    }

    /// The number of fields (relevant and `Irr`) of constructor `ctor` of
    /// the kernel inductive `ind`.
    pub fn ctor_nfields(&self, ind: IndId, ctor: usize) -> Option<usize> {
        self.env.inductive_decl(ind).and_then(|d| d.ctors.get(ctor).map(|c| c.fields.len()))
    }

    /// The core parameters of a HIR type that is an inductive (tuple, option,
    /// ADT, bool, unit): `(ind, params)`.
    pub fn ind_of(&self, t: &Ty, span: Span) -> R<(IndId, Vec<Tm>)> {
        match t.peel_refs() {
            Ty::Bool => Ok((self.p.bool_, vec![])),
            Ty::Tuple(ts) if ts.is_empty() => Ok((self.p.unit, vec![])),
            Ty::Tuple(ts) => {
                let ind = self.tuple_ind(ts.len(), span)?;
                Ok((ind, ts.iter().map(|x| self.ty(x, span)).collect::<R<Vec<_>>>()?))
            }
            Ty::Option(e) => Ok((self.p.option, vec![self.ty(e, span)?])),
            // the prelude list (`Nil`, `Cons(head, tail)`)
            Ty::Seq(e) => Ok((self.p.list, vec![self.ty(e, span)?])),
            Ty::Adt(id, args) => Ok((self.adt(*id, span)?, args.iter().map(|x| self.ty(x, span)).collect::<R<Vec<_>>>()?)),
            other => internal(span, format!("`{}` is not an inductive type", self.krate.ty_str(other))),
        }
    }

    /// HIR field types of constructor `ctor` of the (peeled) inductive type
    /// `t`, instantiated with its type arguments.
    pub fn ctor_field_tys(&self, t: &Ty, ctor: u32, span: Span) -> R<Vec<Ty>> {
        match t.peel_refs() {
            Ty::Bool => Ok(vec![]),
            Ty::Tuple(ts) => Ok(ts.clone()),
            Ty::Option(e) => Ok(if ctor == 1 { vec![(**e).clone()] } else { vec![] }),
            Ty::Seq(e) => Ok(if ctor == 1 { vec![(**e).clone(), Ty::Seq(e.clone())] } else { vec![] }),
            Ty::Adt(id, args) => match &self.krate.item(*id).kind {
                ItemKind::Struct(s) => Ok(s.fields.iter().map(|f| f.ty.subst(args)).collect()),
                ItemKind::Enum(e) => match e.variants.get(ctor as usize) {
                    Some(v) => Ok(v.fields.iter().map(|f| f.ty.subst(args)).collect()),
                    None => internal(span, "variant out of range"),
                },
                _ => internal(span, "not an ADT"),
            },
            other => internal(span, format!("`{}` has no constructors", self.krate.ty_str(other))),
        }
    }

    /// Number of constructors of an inductive HIR type.
    pub fn ctor_count(&self, t: &Ty, span: Span) -> R<usize> {
        match t.peel_refs() {
            Ty::Bool => Ok(2),
            Ty::Tuple(_) => Ok(1),
            Ty::Option(_) | Ty::Seq(_) => Ok(2),
            Ty::Adt(id, _) => match &self.krate.item(*id).kind {
                ItemKind::Struct(_) => Ok(1),
                ItemKind::Enum(e) => Ok(e.variants.len()),
                _ => internal(span, "not an ADT"),
            },
            other => internal(span, format!("`{}` has no constructors", self.krate.ty_str(other))),
        }
    }

    /// Adds a user struct/enum as an inductive (§5.4). Field types are
    /// `: Type` by construction; user types are never recursive (§3.1),
    /// except recursive spec enums, whose direct recursive fields are the
    /// kernel's recursive occurrences (SEMANTICS.md §13.9); those also get
    /// their structural size ([`Elab::declare_size`]).
    /// A struct with an invariant (or a `Nat` field) gets one trailing
    /// `Irr` field per conjunct (DESIGN.md §15.3, `elab::invariant`).
    pub fn declare_adt(&mut self, id: ItemId) -> R<IndId> {
        let it = self.krate.item(id);
        let span = it.span;
        // §15.3: the invariant's `Irr` constructor fields (field k's type is
        // a term at depth `generics + fields + k`: a conjunct may take the
        // earlier `Irr` fields as hypotheses)
        let irr_fields: Vec<(String, Tm)> = match &it.kind {
            ItemKind::Struct(s) => self.invariant_fields(id, s)?,
            _ => vec![],
        };
        let (generics, ctors): (usize, Vec<(String, Vec<Ty>)>) = match &it.kind {
            ItemKind::Struct(s) => (s.generics.len(), vec![(ctor_name_struct(&it.name, s.shape), s.fields.iter().map(|f| f.ty.clone()).collect())]),
            ItemKind::Enum(e) => (e.generics.len(), e.variants.iter().map(|v| (v.name.clone(), v.fields.iter().map(|f| f.ty.clone()).collect())).collect()),
            _ => return internal(span, "not a type"),
        };
        let params = match &it.kind {
            ItemKind::Struct(s) => s.generics.iter().map(|g| (Rc::from(g.name.as_str()), mk::ty())).collect(),
            ItemKind::Enum(e) => e.generics.iter().map(|g| (Rc::from(g.name.as_str()), mk::ty())).collect(),
            _ => vec![],
        };
        // a recursive spec type (§15 S5, SEMANTICS.md §13.9): its own
        // fields refer to the inductive being declared, whose id is the
        // next one the kernel assigns (checked below)
        let recursive = self.krate.is_recursive_adt(id);
        let predicted = if recursive { Some(next_ind_id(&self.env)) } else { None };
        if let Some(p) = predicted {
            self.adts.insert(id, p);
        }
        let mut cdecls = Vec::new();
        for (cname, fields) in ctors {
            let mut fs = Vec::new();
            for (j, fty) in fields.iter().enumerate() {
                let t = self.ty_at(fty, (generics + j) as u32, span)?;
                fs.push((Rc::from(format!("f{j}").as_str()), Rel::Rel, t));
            }
            for (n, t) in &irr_fields {
                fs.push((Rc::from(n.as_str()), Rel::Irr, t.clone()));
            }
            cdecls.push(CtorDecl { name: Rc::from(cname.as_str()), fields: fs });
        }
        let decl = InductiveDecl { name: Rc::from(it.path.to_string().as_str()), params, ctors: cdecls };
        match self.env.add_inductive(decl) {
            Ok(ind) if predicted.is_some_and(|p| p != ind) => {
                self.adts.remove(&id);
                internal(span, format!("recursive type `{}`: the kernel assigned an unexpected inductive id", it.path))
            }
            Ok(ind) => {
                self.adts.insert(id, ind);
                if !irr_fields.is_empty() {
                    self.invariant_lemmas(id, ind)?;
                }
                if recursive {
                    self.declare_size(id, ind)?;
                }
                Ok(ind)
            }
            Err(e) => {
                self.adts.remove(&id);
                internal(span, format!("the kernel rejected type `{}`: {e}", it.path))
            }
        }
    }

    /// A literal of a machine width or `Int`.
    pub fn lit(&self, w: Width, n: impl Into<BigInt>) -> Tm {
        mk::lit(w, n)
    }

    /// Width of a HIR integer type (`Int` included).
    pub fn width_of(&self, t: &Ty, span: Span) -> R<Width> {
        match t.peel_refs() {
            Ty::Uint(u) => Ok(u.width()),
            Ty::Int | Ty::Nat => Ok(Width::Int),
            other => internal(span, format!("`{}` is not an integer type", self.krate.ty_str(other))),
        }
    }
}

/// Constructor name of a struct (the struct's own name).
/// The id the kernel gives the next inductive: ids are dense from 0
/// (`Env::add_inductive`), so it is the first id without a declaration.
fn next_ind_id(env: &sandblaster_kernel::api::Env) -> IndId {
    let (mut lo, mut hi) = (0u32, 1u32);
    while env.inductive_decl(IndId(hi)).is_some() {
        lo = hi;
        hi *= 2;
    }
    // invariant: `lo` is declared (or 0), `hi` is not
    if env.inductive_decl(IndId(lo)).is_none() {
        return IndId(lo);
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if env.inductive_decl(IndId(mid)).is_some() { lo = mid } else { hi = mid }
    }
    IndId(hi)
}

fn ctor_name_struct(name: &str, _shape: Shape) -> String {
    name.to_string()
}

/// The unsigned HIR type of a kernel width.
pub fn uint_of_width(w: Width) -> Option<UintTy> {
    Some(match w {
        Width::U8 => UintTy::U8,
        Width::U16 => UintTy::U16,
        Width::U32 => UintTy::U32,
        Width::U64 => UintTy::U64,
        Width::Usize => UintTy::Usize,
        Width::Int => return None,
    })
}
