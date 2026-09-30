//! Pattern checking (DESIGN.md §3.3 patterns, §3.6).
//!
//! * **Default binding modes** (rustc "match ergonomics", edition 2024):
//!   matching a reference `&T` against a non-reference pattern inserts an
//!   implicit [`PatKind::Deref`] and switches the default binding mode to
//!   by-reference, so bindings below get type `&U` ([`BindingMode::ByRef`]).
//!   As in edition 2024, `mut x` and `&p` are rejected while the default
//!   mode is by-reference, and `ref`/`ref mut` are not supported at all.
//! * **Identifier patterns** (§3.3): a bare identifier is a binding, and it
//!   is an error if its name is the name of any const, unit struct or unit
//!   variant anywhere in the crate (ghost items included) or the prelude.
//!   The only exception is `None`, which is the `Option::None` pattern when
//!   the name resolves to the prelude variant (rustc agrees).
//! * Or-pattern alternatives must bind the same names at the same types;
//!   they share [`LocalId`]s.
//! * Slice patterns: `[a, b]`, `[h, t @ ..]`, `[init @ .., last]`,
//!   `[first, .., last]` on slices (the sub-slice binding requires matching
//!   through a reference) and arrays (sub-arrays by value or reference).
//! * Literal and inclusive range patterns (`a..=b`) of unsigned integers and
//!   bool; exclusive ranges and constant patterns are rejected.
//! * **Names bound by `use`** (§3.3): once every body is checked, every
//!   local is resolved the way rustc resolves an identifier pattern; one
//!   that a `use` brings into scope as a constant or constructor is an error
//!   (`Checker::check_imported_pattern_names`).

use syn::spanned::Spanned;

use super::expr::Cx;
use super::Checker;
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::resolve::{Def, Ext, ItemTag, Ns};
use crate::span::Span;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Move,
    Ref,
}

/// Names bound by the first alternative of an or-pattern, and the names
/// seen so far in the current alternative.
type AltNames = (Vec<(String, LocalId)>, Vec<String>);

/// Bindings of one (possibly or-) pattern.
#[derive(Default)]
struct Binds {
    list: Vec<(String, LocalId)>,
    /// Or-alternative reuse maps: names of the first alternative, and the
    /// names seen in the current alternative.
    reuse: Vec<AltNames>,
}

impl Checker<'_> {
    /// The identifier-pattern rule of DESIGN.md §3.3 for names bound by `use`.
    /// The pattern checker rejects a binding named like a constant, unit
    /// struct or unit variant *definition* (`Resolver::pattern_hazard`), but a
    /// `use` / `pub use` binds such a definition under any name (`pub use
    /// self::K as y;`, `use core::option::Option::None as y;`): in that module
    /// rustc reads the identifier pattern `y` as the constant or constructor,
    /// while the checker reads a binding — the verified meaning would not be
    /// the source's. Every local of every checked function and constant is
    /// resolved the way rustc resolves an identifier pattern (the module's
    /// value namespace: items, `use` bindings, globs, the prelude); one that
    /// names a constant, a unit or tuple constructor is an error (unless the
    /// pattern checker already reported the name). Runs after every body is
    /// checked ([`Checker::check_bodies`]).
    pub(super) fn check_imported_pattern_names(&mut self) {
        let mut found = Vec::new();
        for (i, kind) in self.hir_items.iter().enumerate() {
            let locals = match kind {
                Some(ItemKind::Fn(f)) => &f.locals,
                Some(ItemKind::Const(c)) => &c.locals,
                _ => continue,
            };
            let it = &self.res.items[i];
            if crate::resolve::prelude_lemma_kernel_name(&it.path).is_some() {
                continue;
            }
            let mut seen = std::collections::HashSet::new();
            for l in locals {
                if l.name == "self" || self.res.pattern_hazard(&l.name) || l.name == "Some" || !seen.insert(l.name.as_str()) {
                    continue;
                }
                let Some((def, _)) = self.res.lookup(it.module, &l.name, Ns::Value, it.ghost || l.ghost) else { continue };
                let path = |id: ItemId| &self.res.items[id.0 as usize].path;
                let what = match def {
                    Def::Item(id) => match &self.hir_items[id.0 as usize] {
                        Some(ItemKind::Const(_)) => Some(format!("the constant `{}`", path(id))),
                        Some(ItemKind::Struct(s)) if s.shape != Shape::Named => Some(format!("the {} struct `{}`", if s.shape == Shape::Unit { "unit" } else { "tuple" }, path(id))),
                        _ => None,
                    },
                    Def::Variant(e, k) => match &self.hir_items[e.0 as usize] {
                        Some(ItemKind::Enum(en)) => en.variants.get(k as usize).filter(|v| v.shape != Shape::Named).map(|v| format!("the variant `{}::{}`", path(e), v.name)),
                        _ => None,
                    },
                    Def::Ext(Ext::NoneCtor) => Some("`core::option::Option::None`".into()),
                    Def::Ext(Ext::SomeCtor) => Some("`core::option::Option::Some`".into()),
                    Def::Ext(Ext::IsizeMax) => Some("the ghost constant `ISIZE_MAX`".into()),
                    _ => None,
                };
                if let Some(what) = what {
                    found.push(
                        Diagnostic::error(DiagKind::IdentPattern, l.span, format!("identifier pattern `{}` names {what}, in scope as `{}` in this module through a `use`", l.name, l.name))
                            .note("rustc reads the pattern as that constant or constructor, not as a binding; use a different binding name (DESIGN.md §3.3)"),
                    );
                }
            }
        }
        found.into_iter().for_each(|d| self.diags.push(d));
    }
}

impl<'c, 'a> Cx<'c, 'a> {
    /// A pattern that must match every value of `ty` (let, parameters).
    pub fn irrefutable_pat(&mut self, p: &syn::Pat, ty: &Ty, what: &str) -> Pat {
        let pat = self.pattern_top(p, ty);
        let span = pat.span;
        self.check_exhaustive(ty, &[&pat], span, what);
        pat
    }

    /// A pattern that may fail (match arms, `if let`, `let .. else`).
    pub fn refutable_pat(&mut self, p: &syn::Pat, ty: &Ty) -> Pat {
        self.pattern_top(p, ty)
    }

    fn pattern_top(&mut self, p: &syn::Pat, ty: &Ty) -> Pat {
        let mut b = Binds::default();
        let pat = self.pattern(p, ty, Mode::Move, &mut b);
        for (name, id) in b.list {
            self.bind_existing(&name, id);
        }
        pat
    }

    fn bind(&mut self, b: &mut Binds, name: &str, ty: Ty, mutable: bool, span: Span) -> LocalId {
        if let Some((first, seen)) = b.reuse.last_mut() {
            if let Some((_, id)) = first.iter().find(|(n, _)| n == name) {
                let id = *id;
                seen.push(name.to_string());
                let prev = self.locals[id.0 as usize].ty.clone();
                if prev != ty && !prev.is_error() && !ty.is_error() {
                    let (x, y) = (self.tys(&prev), self.tys(&ty));
                    self.err(DiagKind::Type, span, format!("variable `{name}` is bound with type `{x}` in one alternative and `{y}` in another"));
                }
                if self.locals[id.0 as usize].mutable != mutable {
                    self.err(DiagKind::Type, span, format!("variable `{name}` is bound inconsistently (mutability) across alternatives"));
                }
                return id;
            }
            self.err(DiagKind::Type, span, format!("variable `{name}` is not bound in all alternatives"));
        }
        if b.list.iter().any(|(n, _)| n == name) {
            self.err(DiagKind::Type, span, format!("identifier `{name}` is bound more than once in the same pattern"));
        }
        let id = LocalId(self.locals.len() as u32);
        let ghost = self.ghost;
        self.locals.push(LocalDecl { name: name.to_string(), ty, mutable, ghost, span });
        b.list.push((name.to_string(), id));
        id
    }

    fn is_non_reference_pattern(p: &syn::Pat) -> bool {
        match p {
            syn::Pat::Lit(_) | syn::Pat::Range(_) | syn::Pat::Tuple(_) | syn::Pat::TupleStruct(_) | syn::Pat::Struct(_) | syn::Pat::Path(_) | syn::Pat::Slice(_) => true,
            syn::Pat::Ident(pi) => pi.subpat.is_none() && pi.by_ref.is_none() && pi.mutability.is_none() && pi.ident == "None",
            syn::Pat::Paren(p) => Self::is_non_reference_pattern(&p.pat),
            syn::Pat::Or(_) => false,
            _ => false,
        }
    }

    fn pattern(&mut self, p: &syn::Pat, expected: &Ty, mode: Mode, b: &mut Binds) -> Pat {
        let span = self.sp(p.span());
        let err = |ty: &Ty| Pat { kind: PatKind::Wild, ty: ty.clone(), span };
        if expected.is_error() {
            // still declare bindings for recovery
            self.declare_all(p, b);
            return err(expected);
        }
        // implicit dereference (default binding modes)
        if Self::is_non_reference_pattern(p)
            && let Ty::Ref(inner) = expected {
                let inner = (**inner).clone();
                let sub = self.pattern(p, &inner, Mode::Ref, b);
                return Pat { kind: PatKind::Deref { pat: Box::new(sub), implicit: true }, ty: expected.clone(), span };
            }
        match p {
            syn::Pat::Paren(pp) => self.pattern(&pp.pat, expected, mode, b),
            syn::Pat::Wild(_) => Pat { kind: PatKind::Wild, ty: expected.clone(), span },
            syn::Pat::Ident(pi) => {
                let name = pi.ident.to_string();
                if pi.by_ref.is_some() {
                    self.push(Diagnostic::error(DiagKind::Unsupported, span, "`ref` bindings are not supported").note("bindings under a reference already bind by reference (default binding modes)"));
                }
                if pi.subpat.is_none() && pi.mutability.is_none() && pi.by_ref.is_none() && name == "None"
                    && let Some((Def::Ext(Ext::NoneCtor), _)) = self.ck.res.lookup(self.m, "None", Ns::Value, self.ghost || self.lift) {
                        return self.ctor_pat(Ctor::None, None, &[], false, expected, mode, b, span);
                    }
                // (a synthesized prelude lemma's parameters are its own
                // names, whatever the crate defines)
                if (self.ck.res.pattern_hazard(&name) || name == "Some") && !self.prelude_lemma() {
                    self.push(
                        Diagnostic::error(DiagKind::IdentPattern, span, format!("identifier pattern `{name}` has the name of a constant, unit struct or unit variant"))
                            .note("rustc and a naive resolver disagree on such patterns; use a different binding name, or a path (`Type::Variant`) to match a variant (DESIGN.md §3.3)"),
                    );
                }
                if mode == Mode::Ref && pi.mutability.is_some() {
                    self.push(Diagnostic::error(DiagKind::Type, span, "`mut` bindings are not allowed under a by-reference default binding mode (edition 2024)").note("bind the reference and copy the value into a `let mut`"));
                }
                if let Some((_, sub)) = &pi.subpat
                    && matches!(**sub, syn::Pat::Rest(_)) {
                        self.err(DiagKind::Unsupported, span, "`name @ ..` is only allowed inside slice patterns");
                        return err(expected);
                    }
                let sub = pi.subpat.as_ref().map(|(_, s)| Box::new(self.pattern(s, expected, mode, b)));
                let (bty, bm) = match mode {
                    Mode::Move => (expected.clone(), BindingMode::ByValue),
                    Mode::Ref => (Ty::reference(expected.clone()), BindingMode::ByRef),
                };
                let local = self.bind(b, &name, bty, pi.mutability.is_some(), span);
                Pat { kind: PatKind::Binding { local, mode: bm, sub }, ty: expected.clone(), span }
            }
            syn::Pat::Reference(r) => {
                if r.mutability.is_some() {
                    self.err(DiagKind::MutRef, span, "`&mut` patterns are not supported");
                    return err(expected);
                }
                if mode == Mode::Ref {
                    self.push(Diagnostic::error(DiagKind::Type, span, "reference patterns are not allowed under a by-reference default binding mode (edition 2024)"));
                }
                match expected {
                    Ty::Ref(inner) => {
                        let inner = (**inner).clone();
                        let sub = self.pattern(&r.pat, &inner, Mode::Move, b);
                        Pat { kind: PatKind::Deref { pat: Box::new(sub), implicit: false }, ty: expected.clone(), span }
                    }
                    other => {
                        let s = self.tys(other);
                        self.err(DiagKind::Type, span, format!("mismatched types: expected `{s}`, found a reference pattern"));
                        self.declare_all(&r.pat, b);
                        err(expected)
                    }
                }
            }
            syn::Pat::Lit(l) => self.lit_pat(&l.lit, expected, span),
            syn::Pat::Range(r) => {
                if !matches!(r.limits, syn::RangeLimits::Closed(_)) {
                    self.err(DiagKind::Unsupported, span, "only inclusive range patterns `a..=b` are supported");
                    return err(expected);
                }
                let (Some(lo), Some(hi)) = (&r.start, &r.end) else {
                    self.err(DiagKind::Unsupported, span, "range patterns need both bounds");
                    return err(expected);
                };
                let Ty::Uint(w) = expected else {
                    let s = self.tys(expected);
                    self.err(DiagKind::Type, span, format!("range patterns need an unsigned integer scrutinee, found `{s}`"));
                    return err(expected);
                };
                let lo = self.pat_bound(lo, *w);
                let hi = self.pat_bound(hi, *w);
                match (lo, hi) {
                    (Some(lo), Some(hi)) => {
                        if lo > hi {
                            self.err(DiagKind::Type, span, "lower range bound must be less than or equal to upper");
                        }
                        Pat { kind: PatKind::Range { lo, hi }, ty: expected.clone(), span }
                    }
                    _ => err(expected),
                }
            }
            syn::Pat::Tuple(t) => {
                let Ty::Tuple(ts) = expected else {
                    let s = self.tys(expected);
                    self.err(DiagKind::Type, span, format!("mismatched types: expected `{s}`, found a tuple pattern"));
                    for e in &t.elems {
                        self.declare_all(e, b);
                    }
                    return err(expected);
                };
                let ts = ts.clone();
                let elems: Vec<&syn::Pat> = t.elems.iter().collect();
                let fields = self.positional_fields(&elems, &ts, mode, b, span);
                let mut ps: Vec<Pat> = ts.iter().map(|t| Pat { kind: PatKind::Wild, ty: t.clone(), span }).collect();
                for (i, p) in fields {
                    ps[i as usize] = p;
                }
                Pat { kind: PatKind::Tuple(ps), ty: expected.clone(), span }
            }
            syn::Pat::TupleStruct(ts) => {
                let Some((ctor, targs)) = self.pat_ctor_path(&ts.path, Ns::Value, span) else {
                    for e in &ts.elems {
                        self.declare_all(e, b);
                    }
                    return err(expected);
                };
                if self.ctor_shape(ctor) != Shape::Tuple {
                    self.err(DiagKind::Type, span, "expected a tuple struct or tuple variant");
                    return err(expected);
                }
                let elems: Vec<&syn::Pat> = ts.elems.iter().collect();
                self.ctor_pat(ctor, targs, &elems, false, expected, mode, b, span)
            }
            syn::Pat::Struct(sp) => {
                if sp.qself.is_some() {
                    self.err(DiagKind::Unsupported, span, "qualified paths are not supported");
                    return err(expected);
                }
                let Some((ctor, targs)) = self.pat_ctor_path(&sp.path, Ns::Type, span) else {
                    for f in &sp.fields {
                        self.declare_all(&f.pat, b);
                    }
                    return err(expected);
                };
                if self.ctor_shape(ctor) != Shape::Named {
                    if sp.fields.is_empty() && sp.rest.is_some() {
                        // `S { .. }` is allowed for any shape in rustc
                    } else {
                        self.err(DiagKind::Type, span, "expected a struct or struct variant with named fields");
                        return err(expected);
                    }
                }
                let (fields, _, _) = self.ctor_fields(ctor);
                let mut named: Vec<(u32, &syn::Pat, Span)> = Vec::new();
                for f in &sp.fields {
                    let fspan = self.sp(f.span());
                    let name = match &f.member {
                        syn::Member::Named(n) => n.to_string(),
                        syn::Member::Unnamed(i) => i.index.to_string(),
                    };
                    match fields.iter().position(|x| x.0.as_deref() == Some(name.as_str())) {
                        Some(i) => {
                            if let (Ctor::Struct(id), false) = (ctor, true) {
                                let _ = id;
                            }
                            named.push((i as u32, &f.pat, fspan));
                        }
                        None => {
                            self.err(DiagKind::Type, fspan, format!("no field named `{name}`"));
                            self.declare_all(&f.pat, b);
                        }
                    }
                }
                if sp.rest.is_none() && named.len() != fields.len() {
                    self.err(DiagKind::Type, span, "pattern does not mention all fields; add `..`");
                }
                self.named_ctor_pat(ctor, targs, &named, expected, mode, b, span)
            }
            syn::Pat::Path(pp) => {
                if pp.qself.is_some() {
                    self.err(DiagKind::Unsupported, span, "qualified paths are not supported");
                    return err(expected);
                }
                let Some((ctor, targs)) = self.pat_ctor_path(&pp.path, Ns::Value, span) else { return err(expected) };
                if self.ctor_shape(ctor) != Shape::Unit {
                    self.err(DiagKind::Type, span, "expected a unit struct or unit variant; add the fields");
                    return err(expected);
                }
                self.ctor_pat(ctor, targs, &[], false, expected, mode, b, span)
            }
            syn::Pat::Slice(s) => self.slice_pat(s, expected, mode, b, span),
            syn::Pat::Or(o) => {
                let before = b.list.len();
                let mut alts = Vec::new();
                let mut it = o.cases.iter();
                if let Some(first) = it.next() {
                    alts.push(self.pattern(first, expected, mode, b));
                }
                let names0: Vec<(String, LocalId)> = b.list[before..].to_vec();
                for alt in it {
                    b.reuse.push((names0.clone(), vec![]));
                    let ap = self.pattern(alt, expected, mode, b);
                    let (_, seen) = b.reuse.pop().unwrap();
                    for (n, _) in &names0 {
                        if !seen.contains(n) {
                            let s = self.sp(alt.span());
                            self.err(DiagKind::Type, s, format!("variable `{n}` is not bound in all alternatives"));
                        }
                    }
                    alts.push(ap);
                }
                Pat { kind: PatKind::Or(alts), ty: expected.clone(), span }
            }
            syn::Pat::Type(_) => {
                self.err(DiagKind::Unsupported, span, "type ascriptions are only allowed on `let` and parameters");
                err(expected)
            }
            syn::Pat::Rest(_) => {
                self.err(DiagKind::Unsupported, span, "`..` is only allowed in tuple, struct and slice patterns");
                err(expected)
            }
            syn::Pat::Macro(_) => {
                self.err(DiagKind::Macro, span, "macros in patterns are not supported");
                err(expected)
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "unsupported pattern");
                err(expected)
            }
        }
    }

    /// Declares the bindings of a pattern that failed to check (error recovery).
    fn declare_all(&mut self, p: &syn::Pat, b: &mut Binds) {
        let span = self.sp(p.span());
        match p {
            syn::Pat::Ident(pi) if !(pi.subpat.is_none() && pi.ident == "None") => {
                let name = pi.ident.to_string();
                if !b.list.iter().any(|(n, _)| *n == name) {
                    let id = LocalId(self.locals.len() as u32);
                    let ghost = self.ghost;
                    self.locals.push(LocalDecl { name: name.clone(), ty: Ty::Error, mutable: true, ghost, span });
                    b.list.push((name, id));
                }
                if let Some((_, s)) = &pi.subpat {
                    self.declare_all(s, b);
                }
            }
            syn::Pat::Paren(pp) => self.declare_all(&pp.pat, b),
            syn::Pat::Reference(r) => self.declare_all(&r.pat, b),
            syn::Pat::Tuple(t) => t.elems.iter().for_each(|e| self.declare_all(e, b)),
            syn::Pat::TupleStruct(t) => t.elems.iter().for_each(|e| self.declare_all(e, b)),
            syn::Pat::Struct(s) => s.fields.iter().for_each(|f| self.declare_all(&f.pat, b)),
            syn::Pat::Slice(s) => s.elems.iter().for_each(|e| self.declare_all(e, b)),
            syn::Pat::Or(o) => {
                if let Some(f) = o.cases.first() {
                    self.declare_all(f, b)
                }
            }
            _ => {}
        }
    }

    fn lit_pat(&mut self, l: &syn::Lit, expected: &Ty, span: Span) -> Pat {
        let err = Pat { kind: PatKind::Wild, ty: expected.clone(), span };
        match (l, expected) {
            (syn::Lit::Bool(bv), Ty::Bool) => Pat { kind: PatKind::Lit(Lit::Bool(bv.value)), ty: Ty::Bool, span },
            (syn::Lit::Int(i), Ty::Uint(w)) => {
                let suffix = i.suffix();
                if !suffix.is_empty() && UintTy::from_name(suffix) != Some(*w) {
                    self.err(DiagKind::Type, span, format!("literal suffix `{suffix}` does not match the scrutinee type `{}`", w.name()));
                }
                match i.base10_parse::<u128>() {
                    Ok(v) if v <= w.max_value() => Pat { kind: PatKind::Lit(Lit::Int(v)), ty: expected.clone(), span },
                    _ => {
                        self.err(DiagKind::Literal, span, format!("literal out of range for `{}`", w.name()));
                        err
                    }
                }
            }
            (syn::Lit::Byte(bv), Ty::Uint(UintTy::U8)) => Pat { kind: PatKind::Lit(Lit::Int(bv.value() as u128)), ty: expected.clone(), span },
            (syn::Lit::Float(_), _) => {
                self.err(DiagKind::Float, span, "floating point patterns are not supported");
                err
            }
            _ => {
                let s = self.tys(expected);
                self.err(DiagKind::Type, span, format!("mismatched types: expected `{s}`, found this literal pattern"));
                err
            }
        }
    }

    fn pat_bound(&mut self, e: &syn::Expr, w: UintTy) -> Option<u128> {
        let span = self.sp(e.span());
        match e {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => match i.base10_parse::<u128>() {
                Ok(v) if v <= w.max_value() => Some(v),
                _ => {
                    self.err(DiagKind::Literal, span, format!("literal out of range for `{}`", w.name()));
                    None
                }
            },
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Byte(bv), .. }) if w == UintTy::U8 => Some(bv.value() as u128),
            syn::Expr::Path(p) if p.path.segments.len() == 2 => {
                // `u8::MAX`
                match (UintTy::from_name(&p.path.segments[0].ident.to_string()), p.path.segments[1].ident.to_string().as_str()) {
                    (Some(t), "MAX") if t == w => Some(w.max_value()),
                    (Some(t), "MIN") if t == w => Some(0),
                    _ => {
                        self.err(DiagKind::Unsupported, span, "range pattern bounds must be literals (or `uN::MIN`/`uN::MAX`)");
                        None
                    }
                }
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => {
                self.err(DiagKind::Signed, span, "negative literals are not supported");
                None
            }
            _ => {
                self.err(DiagKind::Unsupported, span, "range pattern bounds must be literals");
                None
            }
        }
    }

    /// Resolves the path of a constructor pattern.
    fn pat_ctor_path(&mut self, path: &syn::Path, ns: Ns, span: Span) -> Option<(Ctor, Option<Vec<Ty>>)> {
        let segs: Vec<(String, Span)> = path.segments.iter().map(|s| (s.ident.to_string(), self.sp(s.ident.span()))).collect();
        // Self / Self::Variant
        if segs[0].0 == "Self" {
            let st = self.g.self_ty.clone();
            return match (st, segs.len()) {
                (Some(Ty::Adt(id, args)), 1) if matches!(self.ck.res.items[id.0 as usize].tag, ItemTag::Struct { .. }) => Some((Ctor::Struct(id), Some(args))),
                (Some(Ty::Adt(id, args)), 2) => match &self.ck.res.items[id.0 as usize].tag {
                    ItemTag::Enum { variants, .. } => match variants.iter().position(|(v, _)| *v == segs[1].0) {
                        Some(i) => Some((Ctor::Variant(id, i as u32), Some(args))),
                        None => {
                            self.err(DiagKind::Resolve, span, format!("no variant `{}`", segs[1].0));
                            None
                        }
                    },
                    _ => None,
                },
                _ => {
                    self.err(DiagKind::Resolve, span, "`Self` is only available in inherent impls");
                    None
                }
            };
        }
        let mut targs: Option<Vec<Ty>> = None;
        for seg in &path.segments {
            if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
                let mut v = Vec::new();
                for arg in &a.args {
                    if let syn::GenericArgument::Type(t) = arg {
                        let g = self.g.clone();
                        let ghost = self.ghost;
                        v.push(self.ck.lower_ty(self.m, t, &g, ghost || self.lift));
                    }
                }
                targs = Some(v);
            }
        }
        let def = match self.ck.res.resolve_path_defs(self.m, &segs, ns, path.leading_colon.is_some(), self.ghost || self.lift) {
            Ok(d) => d,
            Err(d) => {
                if ns == Ns::Type {
                    // struct variants live in the type namespace; tuple ones in both
                    if let Ok(d2) = self.ck.res.resolve_path_defs(self.m, &segs, Ns::Value, path.leading_colon.is_some(), self.ghost || self.lift) {
                        return self.def_to_ctor(d2, targs, span);
                    }
                }
                self.push(d);
                return None;
            }
        };
        self.def_to_ctor(def, targs, span)
    }

    fn def_to_ctor(&mut self, def: Def, targs: Option<Vec<Ty>>, span: Span) -> Option<(Ctor, Option<Vec<Ty>>)> {
        match def {
            Def::Item(id) => {
                let it = &self.ck.res.items[id.0 as usize];
                if it.ghost && !self.ghost {
                    self.err(DiagKind::Ghost, span, "exec pattern refers to a ghost item");
                }
                match &self.ck.res.items[id.0 as usize].tag {
                    ItemTag::Struct { .. } => Some((Ctor::Struct(id), targs)),
                    ItemTag::Const => {
                        self.push(Diagnostic::error(DiagKind::Unsupported, span, "constant patterns are not supported").note("compare with `==` in a guard or an `if`"));
                        None
                    }
                    _ => {
                        self.err(DiagKind::Type, span, "expected a struct, variant or `Some`/`None`");
                        None
                    }
                }
            }
            Def::Variant(id, i) => {
                if self.ck.res.items[id.0 as usize].ghost && !self.ghost {
                    self.err(DiagKind::Ghost, span, "exec pattern refers to a ghost item");
                }
                Some((Ctor::Variant(id, i), targs))
            }
            Def::Ext(Ext::SomeCtor) => Some((Ctor::Some, targs)),
            Def::Ext(Ext::NoneCtor) => Some((Ctor::None, targs)),
            _ => {
                self.err(DiagKind::Type, span, "expected a struct, variant or `Some`/`None`");
                None
            }
        }
    }

    /// Field types of `ctor` instantiated for `expected`, or an error.
    fn ctor_field_tys(&mut self, ctor: Ctor, targs: Option<Vec<Ty>>, expected: &Ty, span: Span) -> Option<(Vec<Ty>, Vec<Ty>)> {
        let (fields, n, ret) = self.ctor_fields(ctor);
        let args: Vec<Ty> = match (expected, &ret) {
            (Ty::Adt(eid, eargs), Ty::Adt(rid, _)) if eid == rid => eargs.clone(),
            (Ty::Option(t), Ty::Option(_)) => vec![(**t).clone()],
            _ => {
                let (e, r) = (self.tys(expected), self.tys(&ret));
                self.err(DiagKind::Type, span, format!("mismatched types: expected `{e}`, found a pattern of type `{r}`"));
                return None;
            }
        };
        if let Some(t) = targs
            && t.len() == n && t != args {
                self.err(DiagKind::Type, span, "pattern type arguments do not match the scrutinee");
            }
        // a pattern reads fields: ghost code may read private fields anywhere
        // in the crate (DESIGN.md §15.3)
        if let (Ctor::Struct(id) | Ctor::Variant(id, _), false) = (ctor, self.ghost) {
            let m = self.ck.res.items[id.0 as usize].module;
            if fields.iter().any(|f| !self.ck.res.visible(f.2, m, self.m)) {
                self.err(DiagKind::Privacy, span, "pattern mentions a type with private fields");
            }
        }
        Some((fields.iter().map(|f| f.1.subst(&args)).collect(), args))
    }

    #[allow(clippy::too_many_arguments)]
    fn ctor_pat(&mut self, ctor: Ctor, targs: Option<Vec<Ty>>, elems: &[&syn::Pat], _named: bool, expected: &Ty, mode: Mode, b: &mut Binds, span: Span) -> Pat {
        let Some((ftys, args)) = self.ctor_field_tys(ctor, targs, expected, span) else {
            for e in elems {
                self.declare_all(e, b);
            }
            return Pat { kind: PatKind::Wild, ty: expected.clone(), span };
        };
        let fields = self.positional_fields(elems, &ftys, mode, b, span);
        Pat { kind: PatKind::Ctor { ctor, ty_args: args, fields }, ty: expected.clone(), span }
    }

    #[allow(clippy::too_many_arguments)]
    fn named_ctor_pat(&mut self, ctor: Ctor, targs: Option<Vec<Ty>>, named: &[(u32, &syn::Pat, Span)], expected: &Ty, mode: Mode, b: &mut Binds, span: Span) -> Pat {
        let Some((ftys, args)) = self.ctor_field_tys(ctor, targs, expected, span) else {
            for (_, p, _) in named {
                self.declare_all(p, b);
            }
            return Pat { kind: PatKind::Wild, ty: expected.clone(), span };
        };
        let mut fields = Vec::new();
        for (i, p, _) in named {
            let t = ftys[*i as usize].clone();
            fields.push((*i, self.pattern(p, &t, mode, b)));
        }
        fields.sort_by_key(|(i, _)| *i);
        Pat { kind: PatKind::Ctor { ctor, ty_args: args, fields }, ty: expected.clone(), span }
    }

    /// Positional sub-patterns with an optional `..`.
    fn positional_fields(&mut self, elems: &[&syn::Pat], tys: &[Ty], mode: Mode, b: &mut Binds, span: Span) -> Vec<(u32, Pat)> {
        let rest = elems.iter().position(|e| matches!(e, syn::Pat::Rest(_)));
        let mut out = Vec::new();
        match rest {
            None => {
                if elems.len() != tys.len() {
                    self.err(DiagKind::Type, span, format!("this pattern has {} field(s), but the type has {}", elems.len(), tys.len()));
                }
                for (i, e) in elems.iter().enumerate() {
                    let t = tys.get(i).cloned().unwrap_or(Ty::Error);
                    out.push((i as u32, self.pattern(e, &t, mode, b)));
                }
            }
            Some(r) => {
                let (pre, post) = (&elems[..r], &elems[r + 1..]);
                if post.iter().any(|e| matches!(e, syn::Pat::Rest(_))) {
                    self.err(DiagKind::Type, span, "`..` can only be used once per pattern");
                }
                if pre.len() + post.len() > tys.len() {
                    self.err(DiagKind::Type, span, "too many fields in pattern");
                }
                for (i, e) in pre.iter().enumerate() {
                    let t = tys.get(i).cloned().unwrap_or(Ty::Error);
                    out.push((i as u32, self.pattern(e, &t, mode, b)));
                }
                let base = tys.len().saturating_sub(post.len());
                for (j, e) in post.iter().enumerate() {
                    let t = tys.get(base + j).cloned().unwrap_or(Ty::Error);
                    out.push(((base + j) as u32, self.pattern(e, &t, mode, b)));
                }
            }
        }
        out
    }

    fn slice_pat(&mut self, s: &syn::PatSlice, expected: &Ty, mode: Mode, b: &mut Binds, span: Span) -> Pat {
        let is_seq = matches!(expected, Ty::Seq(_));
        let (elem, len) = match expected {
            Ty::Array(t, n) => ((**t).clone(), Some(*n)),
            Ty::Slice(t) | Ty::Seq(t) => ((**t).clone(), None),
            other => {
                let s2 = self.tys(other);
                self.err(DiagKind::Type, span, format!("expected an array or slice, found `{s2}`"));
                for e in &s.elems {
                    self.declare_all(e, b);
                }
                return Pat { kind: PatKind::Wild, ty: expected.clone(), span };
            }
        };
        let is_rest = |p: &syn::Pat| match p {
            syn::Pat::Rest(_) => true,
            syn::Pat::Ident(pi) => matches!(&pi.subpat, Some((_, sp)) if matches!(**sp, syn::Pat::Rest(_))),
            _ => false,
        };
        let elems: Vec<&syn::Pat> = s.elems.iter().collect();
        let rest_pos = elems.iter().position(|e| is_rest(e));
        let (pre, post): (&[&syn::Pat], &[&syn::Pat]) = match rest_pos {
            Some(r) => (&elems[..r], &elems[r + 1..]),
            None => (&elems[..], &[]),
        };
        if post.iter().any(|e| is_rest(e)) {
            self.err(DiagKind::Type, span, "`..` can only be used once per slice pattern");
        }
        if is_seq && !post.is_empty() {
            self.push(Diagnostic::error(DiagKind::Type, span, "a `Seq` pattern matches a prefix: `[]`, `[h, t @ ..]`, `[a, b]`").note("elements after `..` are not supported on `Seq<T>`; index from the end instead (`xs[xs.len() - 1]`)"));
        }
        let fixed = (pre.len() + post.len()) as u64;
        if let Some(n) = len {
            let bad = match rest_pos {
                Some(_) => fixed > n,
                None => fixed != n,
            };
            if bad {
                self.err(DiagKind::Type, span, format!("pattern requires {} element(s) but the array has {n}", fixed));
            }
        }
        let prefix: Vec<Pat> = pre.iter().map(|p| self.pattern(p, &elem, mode, b)).collect();
        let rest = rest_pos.map(|r| match elems[r] {
            syn::Pat::Ident(pi) => {
                let name = pi.ident.to_string();
                let rspan = self.sp(pi.span());
                if pi.by_ref.is_some() || pi.mutability.is_some() {
                    self.err(DiagKind::Unsupported, rspan, "`ref`/`mut` are not supported on sub-slice bindings");
                }
                if self.ck.res.pattern_hazard(&name) {
                    self.push(Diagnostic::error(DiagKind::IdentPattern, rspan, format!("identifier pattern `{name}` has the name of a constant, unit struct or unit variant")).note("DESIGN.md §3.3"));
                }
                let sub_ty = match len {
                    Some(n) => Ty::array(elem.clone(), n.saturating_sub(fixed)),
                    None if is_seq => Ty::Seq(Box::new(elem.clone())),
                    None => Ty::Slice(Box::new(elem.clone())),
                };
                let (bty, bm) = match mode {
                    Mode::Move => {
                        if len.is_none() && !is_seq {
                            self.push(Diagnostic::error(DiagKind::Type, rspan, "cannot bind a sub-slice by value").note("match on a reference to the slice (e.g. `match s { [h, t @ ..] => .. }` with `s: &[T]`)"));
                        }
                        (sub_ty.clone(), BindingMode::ByValue)
                    }
                    Mode::Ref => (Ty::reference(sub_ty.clone()), BindingMode::ByRef),
                };
                let local = self.bind(b, &name, bty, false, rspan);
                Some(Box::new(Pat { kind: PatKind::Binding { local, mode: bm, sub: None }, ty: sub_ty, span: rspan }))
            }
            _ => None,
        });
        let suffix: Vec<Pat> = post.iter().map(|p| self.pattern(p, &elem, mode, b)).collect();
        Pat { kind: PatKind::Slice { prefix, rest, suffix }, ty: expected.clone(), span }
    }
}
