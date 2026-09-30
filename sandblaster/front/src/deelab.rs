//! De-elaboration for the spec sheet and `SPEC.lock` (DESIGN.md §15.6,
//! §1.1 item 6): the typed HIR of a surface item printed back as a **fully
//! parenthesized** statement with **explicit binder types and casts** —
//! every compound expression in parentheses, every parameter, `let`,
//! quantifier and `ensures` binder with its type, every literal with its
//! type, and every implicit adjustment of the typechecker written out:
//!
//! | HIR | printed |
//! | --- | --- |
//! | `Coercion::View` (`u32 ↦ Nat`, `&[u8] ↦ Seq<u8>`, a `#[view]`) | `(x as Nat)` for numbers, `view::<Seq<u8>>(xs)` otherwise |
//! | `Coercion::BoolToProp` (`b` as a proposition) | `(b == true)` |
//! | `Coercion::Unsize` / `AutoRef` / `AutoDeref` | `(a as &[T])`, `(&x)`, `(*x)` |
//! | a literal | `5u32`, `(5: Nat)`, `(5: Int)` |
//! | a user item | its absolute path (`crate::spec::f`) |
//!
//! A reviewer reads this form next to the source text to see what the
//! elaborator made of the source (which coercion, which literal type, which
//! operator); the kernel statement is printed beside it. This module is
//! **untrusted** (a printer): the lock's Merkle hash is taken over the
//! kernel statement (`crate::surface`), not over this text.

use crate::hir::*;

/// Collapses runs of whitespace into single spaces.
pub fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The printer of one item (its locals).
pub struct DeElab<'a> {
    pub krate: &'a Crate,
    pub locals: &'a [LocalDecl],
}

impl<'a> DeElab<'a> {
    pub fn new(krate: &'a Crate, locals: &'a [LocalDecl]) -> DeElab<'a> {
        DeElab { krate, locals }
    }

    /// A type, ADTs by absolute path.
    pub fn ty(&self, t: &Ty) -> String {
        let k = self.krate;
        t.display(&|id| k.item(id).path.to_string()).to_string()
    }

    fn local(&self, l: LocalId) -> String {
        self.locals.get(l.0 as usize).map(|d| d.name.clone()).unwrap_or_else(|| format!("_l{}", l.0))
    }

    fn path(&self, id: ItemId) -> String {
        self.krate.item(id).path.to_string()
    }

    fn ty_args(&self, tys: &[Ty]) -> String {
        if tys.is_empty() { String::new() } else { format!("::<{}>", tys.iter().map(|t| self.ty(t)).collect::<Vec<_>>().join(", ")) }
    }

    fn args(&self, es: &[Expr]) -> String {
        es.iter().map(|e| self.expr(e)).collect::<Vec<_>>().join(", ")
    }

    fn lit(&self, l: &Lit, ty: &Ty) -> String {
        match (l, ty) {
            (Lit::Bool(b), _) => b.to_string(),
            (Lit::Int(n), Ty::Uint(u)) => format!("{n}{}", u.name()),
            (Lit::Int(n), Ty::I32) => format!("{n}i32"),
            (Lit::Int(n), t) => format!("({n}: {})", self.ty(t)),
        }
    }

    fn field_name(&self, adt: ItemId, variant: Option<u32>, index: u32) -> String {
        let fields = match (&self.krate.item(adt).kind, variant) {
            (ItemKind::Struct(s), _) => Some(&s.fields),
            (ItemKind::Enum(e), Some(v)) => e.variants.get(v as usize).map(|v| &v.fields),
            _ => None,
        };
        fields.and_then(|fs| fs.get(index as usize)).and_then(|f| f.name.clone()).unwrap_or_else(|| index.to_string())
    }

    fn ctor_head(&self, c: &Ctor, ty_args: &[Ty]) -> String {
        match c {
            Ctor::Struct(id) => format!("{}{}", self.path(*id), self.ty_args(ty_args)),
            Ctor::Variant(id, v) => {
                let name = match &self.krate.item(*id).kind {
                    ItemKind::Enum(e) => e.variants.get(*v as usize).map(|x| x.name.clone()).unwrap_or_else(|| v.to_string()),
                    _ => v.to_string(),
                };
                format!("{}{}::{name}", self.path(*id), self.ty_args(ty_args))
            }
            Ctor::Some => "Some".into(),
            Ctor::None => format!("None{}", self.ty_args(ty_args)),
        }
    }

    fn shape_of(&self, c: &Ctor) -> Shape {
        match c {
            Ctor::Struct(id) => match &self.krate.item(*id).kind {
                ItemKind::Struct(s) => s.shape,
                _ => Shape::Tuple,
            },
            Ctor::Variant(id, v) => match &self.krate.item(*id).kind {
                ItemKind::Enum(e) => e.variants.get(*v as usize).map(|x| x.shape).unwrap_or(Shape::Tuple),
                _ => Shape::Tuple,
            },
            Ctor::Some => Shape::Tuple,
            Ctor::None => Shape::Unit,
        }
    }

    fn variant_of(c: &Ctor) -> (Option<ItemId>, Option<u32>) {
        match c {
            Ctor::Struct(id) => (Some(*id), None),
            Ctor::Variant(id, v) => (Some(*id), Some(*v)),
            _ => (None, None),
        }
    }

    /// An expression, fully parenthesized.
    pub fn expr(&self, e: &Expr) -> String {
        match &e.kind {
            ExprKind::Lit(l) => self.lit(l, &e.ty),
            ExprKind::Local(l) => self.local(*l),
            ExprKind::Const(id) => self.path(*id),
            ExprKind::BuiltinConst(c) => match c {
                BuiltinConst::Max(u) => format!("{}::MAX", u.name()),
                BuiltinConst::Min(u) => format!("{}::MIN", u.name()),
                BuiltinConst::Bits(u) => format!("{}::BITS", u.name()),
                BuiltinConst::IsizeMax => "ISIZE_MAX".into(),
            },
            ExprKind::Call { callee, args } => match callee {
                Callee::Item(id, tys) => format!("{}{}({})", self.path(*id), self.ty_args(tys), self.args(args)),
                Callee::Builtin(b, tys) => {
                    if let (Some(op), [a, c]) = (b.infix(), args.as_slice()) {
                        return format!("({} {op} {})", self.expr(a), self.expr(c));
                    }
                    let printer = |t: &Ty| self.ty(t);
                    let name = b.path(tys, &printer).unwrap_or_else(|| b.prelude_name());
                    format!("{name}({})", self.args(args))
                }
                Callee::Intrinsic(i, imms) => {
                    let info = crate::intrinsics::get(*i);
                    let imm = if imms.is_empty() { String::new() } else { format!("::<{}>", imms.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")) };
                    format!("core::arch::{}::{}{imm}({})", info.arch.name(), info.name, self.args(args))
                }
                Callee::Helper(h) => {
                    let info = crate::intrinsics::helper(*h);
                    format!("sandblaster::arch::{}::{}({})", info.arch.name(), info.name, self.args(args))
                }
                Callee::Ghost(g, tys) => {
                    let extra = match g {
                        crate::builtins::GhostFn::SChunks(n) | crate::builtins::GhostFn::SToArray(n) => format!("<{n}>"),
                        crate::builtins::GhostFn::SFlatten(Some(n)) => format!("<{n}>"),
                        _ => String::new(),
                    };
                    format!("{}{extra}{}({})", g.name(), self.ty_args(tys), self.args(args))
                }
            },
            ExprKind::Adt { ctor, ty_args, fields, base } => {
                let head = self.ctor_head(ctor, ty_args);
                let (adt, variant) = Self::variant_of(ctor);
                match self.shape_of(ctor) {
                    Shape::Unit if fields.is_empty() && base.is_none() => head,
                    Shape::Named => {
                        let mut parts: Vec<String> = fields.iter().map(|(i, x)| format!("{}: {}", adt.map(|a| self.field_name(a, variant, *i)).unwrap_or_else(|| i.to_string()), self.expr(x))).collect();
                        if let Some(b) = base {
                            parts.push(format!("..{}", self.expr(b)));
                        }
                        format!("{head} {{ {} }}", parts.join(", "))
                    }
                    _ => {
                        let mut parts: Vec<String> = fields.iter().map(|(_, x)| self.expr(x)).collect();
                        if let Some(b) = base {
                            parts.push(format!("..{}", self.expr(b)));
                        }
                        format!("{head}({})", parts.join(", "))
                    }
                }
            }
            ExprKind::Tuple(es) if es.len() == 1 => format!("({},)", self.expr(&es[0])),
            ExprKind::Tuple(es) => format!("({})", self.args(es)),
            ExprKind::Array(es) => format!("[{}]", self.args(es)),
            ExprKind::Repeat { elem, count } => format!("[{}; {count}]", self.expr(elem)),
            ExprKind::Field { base, index, name } => format!("({}).{}", self.expr(base), name.clone().unwrap_or_else(|| index.to_string())),
            ExprKind::Index { base, index } => format!("({})[{}]", self.expr(base), self.expr(index)),
            ExprKind::SliceRange { base, lo, hi } => {
                let b = |x: &Option<Box<Expr>>| x.as_ref().map(|e| self.expr(e)).unwrap_or_default();
                format!("(&({})[{}..{}])", self.expr(base), b(lo), b(hi))
            }
            ExprKind::Unary(UnOp::Not, x) => format!("(!{})", self.expr(x)),
            ExprKind::Unary(UnOp::Neg, x) => format!("(-{})", self.expr(x)),
            ExprKind::Binary(op, a, b) => format!("({} {} {})", self.expr(a), op.symbol(), self.expr(b)),
            ExprKind::Cast(x, t) => format!("({} as {})", self.expr(x), self.ty(t)),
            ExprKind::Ref(x) => format!("(&{})", self.expr(x)),
            ExprKind::Deref(x) => format!("(*{})", self.expr(x)),
            ExprKind::Coerce(c, x) => match c {
                Coercion::Unsize => format!("({} as {})", self.expr(x), self.ty(&e.ty)),
                Coercion::AutoRef => format!("(&{})", self.expr(x)),
                Coercion::AutoDeref => format!("(*{})", self.expr(x)),
                Coercion::BoolToProp => format!("({} == true)", self.expr(x)),
                Coercion::View => {
                    let numeric = |t: &Ty| matches!(t.peel_refs(), Ty::Uint(_) | Ty::Nat | Ty::Int);
                    if numeric(&x.ty) && numeric(&e.ty) {
                        format!("({} as {})", self.expr(x), self.ty(&e.ty))
                    } else {
                        format!("view::<{}>({})", self.ty(&e.ty), self.expr(x))
                    }
                }
            },
            ExprKind::If { cond, then, els } => match els {
                Some(el) => format!("(if {} {} else {})", self.expr(cond), self.block_like(then), self.block_like(el)),
                None => format!("(if {} {})", self.expr(cond), self.block_like(then)),
            },
            ExprKind::Match { scrut, arms, .. } => {
                let arms: Vec<String> = arms
                    .iter()
                    .map(|a| {
                        let g = a.guard.as_ref().map(|g| format!(" if {}", self.expr(g))).unwrap_or_default();
                        format!("{}{g} => {}", self.pat(&a.pat), self.expr(&a.body))
                    })
                    .collect();
                format!("(match {} {{ {} }})", self.expr(scrut), arms.join(", "))
            }
            ExprKind::Block(b) => self.block(b),
            ExprKind::Return(x) => match x {
                Some(v) => format!("(return {})", self.expr(v)),
                None => "(return)".into(),
            },
            ExprKind::Try(x) => format!("({}?)", self.expr(x)),
            ExprKind::Unreachable => "unreachable!()".into(),
            ExprKind::Loop(_) => "(loop …)".into(),
            ExprKind::PropEq(a, b) => format!("({} == {})", self.expr(a), self.expr(b)),
            ExprKind::PropNe(a, b) => format!("({} != {})", self.expr(a), self.expr(b)),
            ExprKind::PropAnd(a, b) => format!("({} && {})", self.expr(a), self.expr(b)),
            ExprKind::PropOr(a, b) => format!("({} || {})", self.expr(a), self.expr(b)),
            ExprKind::PropNot(a) => format!("(!{})", self.expr(a)),
            ExprKind::Implies(a, b) => format!("implies({}, {})", self.expr(a), self.expr(b)),
            ExprKind::Iff(a, b) => format!("iff({}, {})", self.expr(a), self.expr(b)),
            ExprKind::Quant { quant, binders, body } => {
                let q = match quant {
                    Quant::Forall => "forall",
                    Quant::Exists => "exists",
                };
                let bs: Vec<String> = binders.iter().map(|b| format!("{}: {}", self.local(*b), self.locals.get(b.0 as usize).map(|d| self.ty(&d.ty)).unwrap_or_default())).collect();
                format!("{q}(|{}| {})", bs.join(", "), self.expr(body))
            }
            ExprKind::Lambda { params, body } => {
                let bs: Vec<String> = params.iter().map(|b| format!("{}: {}", self.local(*b), self.locals.get(b.0 as usize).map(|d| self.ty(&d.ty)).unwrap_or_default())).collect();
                format!("(|{}| {})", bs.join(", "), self.expr(body))
            }
            ExprKind::Apply { fun, args } => format!("{}({})", self.expr(fun), args.iter().map(|a| self.expr(a)).collect::<Vec<_>>().join(", ")),
        }
    }

    fn block_like(&self, e: &Expr) -> String {
        match &e.kind {
            ExprKind::Block(b) => self.block(b),
            _ => format!("{{ {} }}", self.expr(e)),
        }
    }

    fn block(&self, b: &Block) -> String {
        let mut parts: Vec<String> = Vec::new();
        for s in &b.stmts {
            match &s.kind {
                StmtKind::Let { pat, init, els } => {
                    let e = els.as_ref().map(|b| format!(" else {}", self.block(b))).unwrap_or_default();
                    parts.push(format!("let {}: {} = {}{e};", self.pat(pat), self.ty(&pat.ty), self.expr(init)));
                }
                StmtKind::Expr(e) => parts.push(format!("{};", self.expr(e))),
                StmtKind::Assign { place, value } => parts.push(format!("{} = {};", self.place(place), self.expr(value))),
                StmtKind::CompoundAssign { op, place, value } => parts.push(format!("{} {}= {};", self.place(place), op.symbol(), self.expr(value))),
                StmtKind::CopyFromSlice { dst, src, .. } => parts.push(format!("{}.copy_from_slice({});", self.local(*dst), self.expr(src))),
                // ghost scripts inside bodies are proofs, not part of a statement
                StmtKind::Proof(_) => {}
            }
        }
        if let Some(t) = &b.tail {
            parts.push(self.expr(t));
        }
        format!("{{ {} }}", parts.join(" "))
    }

    fn place(&self, p: &Place) -> String {
        let mut s = self.local(p.local);
        for pr in &p.projs {
            match pr {
                Proj::Field { index, name } => s = format!("({s}).{}", name.clone().unwrap_or_else(|| index.to_string())),
                Proj::Index(e) => s = format!("({s})[{}]", self.expr(e)),
            }
        }
        s
    }

    /// A pattern.
    pub fn pat(&self, p: &Pat) -> String {
        match &p.kind {
            PatKind::Wild => "_".into(),
            PatKind::Binding { local, mode, sub } => {
                let r = if *mode == BindingMode::ByRef { "ref " } else { "" };
                let m = if self.locals.get(local.0 as usize).is_some_and(|d| d.mutable) { "mut " } else { "" };
                match sub {
                    Some(s) => format!("{r}{m}{} @ {}", self.local(*local), self.pat(s)),
                    None => format!("{r}{m}{}", self.local(*local)),
                }
            }
            PatKind::Lit(l) => self.lit(l, &p.ty),
            PatKind::Range { lo, hi } => format!("{lo}..={hi}"),
            PatKind::Tuple(ps) if ps.len() == 1 => format!("({},)", self.pat(&ps[0])),
            PatKind::Tuple(ps) => format!("({})", ps.iter().map(|x| self.pat(x)).collect::<Vec<_>>().join(", ")),
            PatKind::Ctor { ctor, ty_args, fields } => {
                let head = self.ctor_head(ctor, ty_args);
                let (adt, variant) = Self::variant_of(ctor);
                match self.shape_of(ctor) {
                    Shape::Unit => head,
                    Shape::Named => format!("{head} {{ {}, .. }}", fields.iter().map(|(i, x)| format!("{}: {}", adt.map(|a| self.field_name(a, variant, *i)).unwrap_or_else(|| i.to_string()), self.pat(x))).collect::<Vec<_>>().join(", ")),
                    Shape::Tuple => format!("{head}({})", fields.iter().map(|(i, x)| format!("{i}: {}", self.pat(x))).collect::<Vec<_>>().join(", ")),
                }
            }
            PatKind::Deref { pat, implicit: true } => self.pat(pat),
            PatKind::Deref { pat, implicit: false } => format!("&{}", self.pat(pat)),
            PatKind::Slice { prefix, rest, suffix } => {
                let mut parts: Vec<String> = prefix.iter().map(|x| self.pat(x)).collect();
                match rest {
                    None => {}
                    Some(None) => parts.push("..".into()),
                    Some(Some(r)) => parts.push(format!("{} @ ..", self.pat(r))),
                }
                parts.extend(suffix.iter().map(|x| self.pat(x)));
                format!("[{}]", parts.join(", "))
            }
            PatKind::Or(alts) => format!("({})", alts.iter().map(|x| self.pat(x)).collect::<Vec<_>>().join(" | ")),
        }
    }

    /// The parameter list `(x: T, y: U)` of a function (receivers included).
    pub fn params(&self, f: &FnDef) -> String {
        let ps: Vec<String> = f.params.iter().map(|p| format!("{}{}: {}", if p.ghost { "#[ghost] " } else { "" }, self.pat(&p.pat), self.ty(&p.ty))).collect();
        format!("({})", ps.join(", "))
    }

    fn generics(&self, gs: &[TyParam]) -> String {
        if gs.is_empty() { String::new() } else { format!("<{}>", gs.iter().map(|g| format!("{}: Copy", g.name)).collect::<Vec<_>>().join(", ")) }
    }

    /// `fn path<T>(x: T) -> R` (the result type always written).
    pub fn signature(&self, word: &str, it: &Item, f: &FnDef) -> String {
        format!("{word} {}{}{} -> {}", it.path, self.generics(&f.generics), self.params(f), self.ty(&f.ret))
    }

    fn requires_ensures(&self, f: &FnDef) -> Vec<String> {
        let mut out: Vec<String> = f.requires.iter().map(|r| format!("requires {}", self.expr(r))).collect();
        if let Some(en) = &f.ensures {
            out.push(format!("ensures |{}: {}| {}", self.pat(&en.binder), self.ty(&en.binder.ty), self.expr(&en.prop)));
        }
        out
    }

    /// A law: its signature, `requires` and `ensures` (the proof is not part
    /// of the statement).
    pub fn law(&self, it: &Item, f: &FnDef) -> Vec<String> {
        let mut out = vec![format!("law {}{}{}", it.path, self.generics(&f.generics), self.params(f))];
        out.extend(f.requires.iter().map(|r| format!("  requires {}", self.expr(r))));
        if let Some(en) = &f.ensures {
            out.push(format!("  ensures {}", self.expr(&en.prop)));
        }
        out
    }

    /// The contract of an exec function: signature, `requires`, `ensures`,
    /// `#[refines]`, `#[decreases]` (the body is not part of it). The
    /// refinement is rendered from the HIR alone (its form derived from the
    /// owner's `#[represents]`); [`DeElab::contract_with`] also prints the
    /// elaborator's determinacy verdict.
    pub fn contract(&self, word: &str, it: &Item, f: &FnDef) -> Vec<String> {
        self.contract_with(word, it, f, None)
    }

    /// [`DeElab::contract`] with the refinement record of `f`, when the
    /// elaborator made one: its form (a simulation form through a
    /// `#[represents]` relation is printed as that implication, never as a
    /// view of `self`) and why it does not determine `f` ("up to
    /// view(T)", a domain, a representation relation, a spec that is not
    /// spec-closed). Every refinement is printed twice: the `refines s(..)`
    /// line as written (with the argument coercions made explicit) and its
    /// meaning — the kernel lemma's statement de-elaborated, result
    /// coercion included.
    pub fn contract_with(&self, word: &str, it: &Item, f: &FnDef, rec: Option<&crate::elab::refines::RefinesRecord>) -> Vec<String> {
        let mut out = vec![self.signature(word, it, f)];
        out.extend(self.requires_ensures(f).into_iter().map(|s| format!("  {s}")));
        if let Some(d) = &f.decreases {
            out.push(format!("  decreases {}{}", self.expr(&d.measure), d.max.map(|m| format!(" max {m}")).unwrap_or_default()));
        }
        if let Some(r) = &f.spec.refines {
            out.extend(self.refinement(it, f, r, rec));
        }
        out
    }

    /// `x as T`, `view::<T>(x)` or `x` (the view coercion from `from` to `to`
    /// written out; `x` is already printed).
    fn coerce(&self, x: String, from: &Ty, to: &Ty) -> String {
        let numeric = |t: &Ty| matches!(t.peel_refs(), Ty::Uint(_) | Ty::Nat | Ty::Int);
        if from == to || from.peel_refs() == to {
            x
        } else if numeric(from) && numeric(to) {
            format!("({x} as {})", self.ty(to))
        } else {
            format!("view::<{}>({x})", self.ty(to))
        }
    }

    /// The simulation form of a method of a `#[represents]` struct, from the
    /// HIR (the elaborator's `RefinesForm`, recomputed when no record is
    /// given): the owner, its relation and the form.
    fn rep_form(&self, f: &FnDef) -> Option<(ItemId, &'a Represents, crate::elab::refines::RefinesForm)> {
        use crate::elab::refines::RefinesForm;
        let owner = f.owner?;
        let ItemKind::Struct(sd) = &self.krate.item(owner).kind else { return None };
        let rep = sd.represents.as_ref()?;
        let is_s = |t: &Ty| matches!(t.peel_refs(), Ty::Adt(i, _) if *i == owner);
        let form = if f.receiver.is_some() {
            if is_s(&f.ret) {
                RefinesForm::RepPreserve
            } else if matches!(&f.ret, Ty::Tuple(ts) if ts.len() == 2 && is_s(&ts[0])) {
                RefinesForm::RepStatePassing
            } else {
                RefinesForm::RepObserver
            }
        } else if is_s(&f.ret) {
            RefinesForm::RepConstructor
        } else {
            return None;
        };
        Some((owner, rep, form))
    }

    fn refinement(&self, it: &Item, f: &FnDef, r: &Refines, rec: Option<&crate::elab::refines::RefinesRecord>) -> Vec<String> {
        use crate::elab::refines::RefinesForm;
        let spec = self.path(r.spec);
        let spec_f = self.krate.fn_def(r.spec);
        let to: Vec<Ty> = spec_f.map(|s| s.params.iter().map(|p| p.ty.clone()).collect()).unwrap_or_default();
        let spec_ret = spec_f.map(|s| s.ret.clone());
        let rep = self.rep_form(f);
        let form = match (rec, &rep) {
            (Some(x), _) => x.form.clone(),
            (None, Some((_, _, fm))) => fm.clone(),
            (None, None) => RefinesForm::Plain,
        };
        let through_rep = form != RefinesForm::Plain;
        // the abstract state and the receiver of a simulation form
        let first_param = usize::from(through_rep && f.receiver.is_some());
        let abs_name = "a";
        let args = match &r.args {
            Some(a) => self.args(a),
            None => {
                let mut ps: Vec<String> = Vec::new();
                if first_param == 1 {
                    ps.push(abs_name.to_string());
                }
                let off = ps.len();
                let params = &f.params[first_param.min(f.params.len())..];
                if to.len() == off + params.len() {
                    for (p, t) in params.iter().zip(&to[off..]) {
                        ps.push(self.coerce(self.pat(&p.pat), &p.ty, t));
                    }
                } else {
                    ps.push("(the arguments do not match the spec's parameters)".to_string());
                }
                ps.join(", ")
            }
        };
        let spec_call = format!("{spec}({args})");
        let call = format!("{}({})", it.path, f.params.iter().map(|p| self.pat(&p.pat)).collect::<Vec<_>>().join(", "));
        let dom = r.domain.as_ref().map(|d| format!(" WHEN {}", self.expr(d))).unwrap_or_default();
        let mut out = Vec::new();
        let result_eq = |from: &Ty, v: String, s: String| match &spec_ret {
            Some(sr) => format!("({} == {s})", self.coerce(v, from, sr)),
            None => format!("({v} == {s})"),
        };
        match (&form, &rep) {
            (RefinesForm::Plain, _) => {
                out.push(format!("  refines {spec_call}{dom}"));
                out.push(format!("    meaning: {}{dom}", result_eq(&f.ret, call.clone(), spec_call.clone())));
            }
            (_, Some((owner, rp, _))) => {
                let rel = format!("{}::represents", self.path(*owner));
                let a_ty = self.ty(&rp.abs_ty);
                out.push(format!("  refines {spec_call}{dom} through the representation relation {rel}"));
                let meaning = match form {
                    RefinesForm::RepConstructor => format!("{rel}({call}, {spec_call})"),
                    RefinesForm::RepPreserve => format!("for all {abs_name}: {a_ty}, ({rel}(self, {abs_name}) => {rel}({call}, {spec_call}))"),
                    RefinesForm::RepStatePassing => {
                        let (from1, to1) = match (&f.ret, &spec_ret) {
                            (Ty::Tuple(fr), Some(Ty::Tuple(sr))) if fr.len() == 2 && sr.len() == 2 => (fr[1].clone(), sr[1].clone()),
                            _ => (f.ret.clone(), f.ret.clone()),
                        };
                        format!("for all {abs_name}: {a_ty}, ({rel}(self, {abs_name}) => ({rel}({call}.0, {spec_call}.0) && ({} == {spec_call}.1)))", self.coerce(format!("{call}.1"), &from1, &to1))
                    }
                    _ => format!("for all {abs_name}: {a_ty}, ({rel}(self, {abs_name}) => {})", result_eq(&f.ret, call.clone(), spec_call.clone())),
                };
                out.push(format!("    meaning: {meaning}{dom}"));
            }
            (_, None) => {
                out.push(format!("  refines {spec_call}{dom} through a representation relation"));
            }
        }
        let verdict = match rec {
            // an unproven refinement determines nothing
            Some(x) if x.status != crate::elab::DefStatus::Checked => format!("NOT DETERMINING: the refinement is not proven ({})", crate::driver::def_status_str(&x.status)),
            Some(x) => match &x.up_to {
                Some(why) if through_rep && !why.contains("Abstract(T)") => format!("NOT DETERMINING: {why} (through a representation relation; determining needs `Abstract` and an established relation)"),
                Some(why) => format!("NOT DETERMINING: {why}"),
                None => format!("determines {} ({})", it.path, x.determined_by.as_deref().unwrap_or("identity or injective result view")),
            },
            None if through_rep => "NOT DETERMINING: through a representation relation; not determining until Abstract(T), S2".to_string(),
            None => "determinacy: not recorded".to_string(),
        };
        out.push(format!("    {verdict}"));
        out
    }

    /// A spec function or spec constant: its signature and its definition.
    pub fn spec_fn(&self, it: &Item, f: &FnDef) -> Vec<String> {
        let mut out = vec![self.signature("spec fn", it, f)];
        out.extend(self.requires_ensures(f).into_iter().map(|s| format!("  {s}")));
        if let Some(d) = &f.decreases {
            out.push(format!("  decreases {}", self.expr(&d.measure)));
        }
        if let FnBody::Spec(b) = &f.body {
            out.push(format!("  = {}", self.expr(b)));
        }
        out
    }
}

/// `const PATH: T = e` (spec or exec constant).
pub fn constant(krate: &Crate, it: &Item, c: &ConstDef) -> Vec<String> {
    let p = DeElab::new(krate, &c.locals);
    vec![format!("{} {}: {} = {}", if it.ghost { "spec const" } else { "const" }, it.path, p.ty(&c.ty), p.expr(&c.init))]
}

fn vis(v: Vis) -> &'static str {
    match v {
        Vis::Private => "",
        Vis::Super => "pub(super) ",
        Vis::Crate => "pub(crate) ",
        Vis::Public => "pub ",
    }
}

fn derives(d: &Derives) -> String {
    let mut v = Vec::new();
    for (on, n) in [(d.clone, "Clone"), (d.copy, "Copy"), (d.partial_eq, "PartialEq"), (d.eq, "Eq"), (d.debug, "Debug")] {
        if on {
            v.push(n);
        }
    }
    if v.is_empty() { String::new() } else { format!("#[derive({})] ", v.join(", ")) }
}

fn fields(p: &DeElab, shape: Shape, fs: &[FieldDef]) -> String {
    match shape {
        Shape::Unit => String::new(),
        Shape::Tuple => format!("({})", fs.iter().map(|f| format!("{}{}", vis(f.vis), p.ty(&f.ty))).collect::<Vec<_>>().join(", ")),
        Shape::Named => format!(" {{ {} }}", fs.iter().map(|f| format!("{}{}: {}", vis(f.vis), f.name.clone().unwrap_or_default(), p.ty(&f.ty))).collect::<Vec<_>>().join(", ")),
    }
}

/// The definition of a type (struct, enum or alias), with its derives and
/// visibilities.
pub fn type_def(krate: &Crate, it: &Item) -> Vec<String> {
    let p = DeElab::new(krate, &[]);
    let g = |gs: &[TyParam]| if gs.is_empty() { String::new() } else { format!("<{}>", gs.iter().map(|g| g.name.clone()).collect::<Vec<_>>().join(", ")) };
    match &it.kind {
        ItemKind::Struct(s) => vec![format!("{}{}struct {}{}{}", derives(&s.derives), vis(it.vis), it.path, g(&s.generics), fields(&p, s.shape, &s.fields))],
        ItemKind::Enum(e) => {
            let vs: Vec<String> = e.variants.iter().map(|v| format!("{}{}", v.name, fields(&p, v.shape, &v.fields))).collect();
            vec![format!("{}{}enum {}{} {{ {} }}", derives(&e.derives), vis(it.vis), it.path, g(&e.generics), vs.join(", "))]
        }
        ItemKind::TypeAlias(a) => vec![format!("{}type {} = {}", vis(it.vis), it.path, p.ty(&a.ty))],
        _ => vec![],
    }
}

/// A `#[view]` of a type.
pub fn view(krate: &Crate, it: &Item, v: &View) -> Vec<String> {
    match v {
        View::Struct { target, .. } => vec![format!("view of {}: structural onto {} (every field onto the same-named field)", it.path, krate.item(*target).path)],
        View::Fn { binder, body, locals, .. } => {
            let p = DeElab::new(krate, locals);
            let bty = locals.get(binder.0 as usize).map(|d| p.ty(&d.ty)).unwrap_or_default();
            vec![format!("view of {}: |{}: {bty}| -> {} {}", it.path, p.local(*binder), p.ty(&body.ty), p.expr(body))]
        }
    }
}

/// A `#[represents]` relation.
pub fn represents(krate: &Crate, it: &Item, r: &Represents) -> Vec<String> {
    let p = DeElab::new(krate, &r.locals);
    let rt = r.locals.get(r.repr.0 as usize).map(|d| p.ty(&d.ty)).unwrap_or_default();
    vec![format!("represents {}: |{}: {rt}, {}: {}| {}", it.path, p.local(r.repr), p.local(r.abs), p.ty(&r.abs_ty), p.expr(&r.prop))]
}

/// The invariants of a struct.
pub fn invariant(krate: &Crate, it: &Item, inv: &TypeInvariant) -> Vec<String> {
    let p = DeElab::new(krate, &inv.locals);
    inv.props.iter().map(|(e, _)| format!("invariant of {}: {}", it.path, p.expr(e))).collect()
}

/// One `#[example(e)]`.
pub fn example(krate: &Crate, it: &Item, k: usize, ex: &Example) -> Vec<String> {
    let p = DeElab::new(krate, &ex.locals);
    vec![format!("example #{k} of {}: {}", it.path, p.expr(&ex.expr))]
}

// ---------------------------------------------------------------------------
// Kernel terms in surface syntax (diagnostics)
// ---------------------------------------------------------------------------

/// A kernel goal or fact printed in the surface syntax a reviewer wrote
/// (DESIGN.md §15.10 `error[refines-unproven]`): `xs.len()`, `xs[i]`,
/// `(x as Int)`, `a + b`, `Some(..)`, `if c { .. } else { .. }`, calls by
/// path; proofs are dropped. The list of a slice or array `s` is printed as
/// `s` (the view the specification uses). Untrusted, bounded: past its node
/// budget the rest is `…`.
pub struct KernelShow<'e> {
    env: &'e sandblaster_kernel::api::Env,
    names: Vec<String>,
    budget: usize,
    /// The type head of each context variable (`Slice`, `Array`), by level:
    /// `fst(s)` is `s.len()` for a slice and the list `s` for an array.
    heads: Vec<Option<String>>,
}

impl<'e> KernelShow<'e> {
    /// `names`: the context's binder names in level order.
    pub fn new(env: &'e sandblaster_kernel::api::Env, names: Vec<String>) -> KernelShow<'e> {
        KernelShow { env, names, budget: 4000, heads: vec![] }
    }

    /// With the context's types (slices and arrays print as their views).
    pub fn with_ctx(mut self, ctx: &sandblaster_kernel::api::Ctx) -> KernelShow<'e> {
        use sandblaster_kernel::value::{Head, Neutral, Value};
        self.heads = ctx
            .entries
            .iter()
            .map(|e| match &*e.ty {
                Value::Neu(Neutral { head: Head::Global { def, .. }, .. }) => self.env.global_name(*def).map(|n| n.to_string()),
                // `Slice T = Σ(n : Usize). Σ(l : List T). ..`, `Array T N = Σ(l : List T). ..`
                Value::Sigma { fst, .. } => match &**fst {
                    Value::IntTy(sandblaster_kernel::term::Width::Usize) => Some("Slice".to_string()),
                    Value::Ind { .. } => Some("Array".to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        self
    }

    /// The type head of a context variable, if known.
    fn head_of(&self, t: &sandblaster_kernel::term::Tm, local: &[String]) -> Option<&str> {
        let sandblaster_kernel::term::Term::Var(i) = &**t else { return None };
        let j = (i.0 as usize).checked_sub(local.len())?;
        let l = self.heads.len().checked_sub(1 + j)?;
        self.heads.get(l)?.as_deref()
    }

    pub fn show(&mut self, t: &sandblaster_kernel::term::Tm) -> String {
        self.go(t, &mut Vec::new())
    }

    fn var(&self, i: u32, local: &[String]) -> String {
        let i = i as usize;
        if i < local.len() {
            return local[local.len() - 1 - i].clone();
        }
        let j = i - local.len();
        self.names.len().checked_sub(1 + j).and_then(|l| self.names.get(l)).cloned().unwrap_or_else(|| format!("_v{i}"))
    }

    fn global(&self, g: sandblaster_kernel::term::GlobalId) -> String {
        self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("#{}", g.0))
    }

    fn ctor_name(&self, ind: sandblaster_kernel::term::IndId, ctor: u32) -> String {
        self.env.inductive_decl(ind).and_then(|d| d.ctors.get(ctor as usize).map(|c| c.name.to_string())).unwrap_or_else(|| format!("C{ctor}"))
    }

    fn go(&mut self, t: &sandblaster_kernel::term::Tm, local: &mut Vec<String>) -> String {
        use sandblaster_kernel::term::{PrimOp::*, Rel, Term};
        if self.budget == 0 {
            return "…".into();
        }
        self.budget -= 1;
        match &**t {
            Term::Var(i) => self.var(i.0, local),
            Term::Global(g) => self.global(*g),
            Term::Sort(_) => "Type".into(),
            Term::IntTy(w) => sandblaster_kernel::prim::width_suffix(*w).to_string(),
            Term::Lit { w, n } => match w {
                sandblaster_kernel::term::Width::Int => n.to_string(),
                w => format!("{n}{}", sandblaster_kernel::prim::width_suffix(*w)),
            },
            Term::Erased => "_".into(),
            Term::Eq { ty, lhs, rhs } => {
                // `Eq(Bool, c, true)` is `c`; `.. false` its negation
                if let Term::Ind { ind, .. } = &**ty
                    && *ind == self.env.bool_ind()
                    && let Term::Ctor { ctor, .. } = &**rhs
                {
                    let c = self.go(lhs, local);
                    return if *ctor == 1 { c } else { format!("!{c}") };
                }
                format!("{} == {}", self.go(lhs, local), self.go(rhs, local))
            }
            Term::Prim { op, args, .. } => {
                let a: Vec<String> = args.iter().map(|x| self.go(x, local)).collect();
                let bin = |o: &str| format!("({} {o} {})", a[0], a[1]);
                match op {
                    IAdd | Add(_) => bin("+"),
                    ISub | Sub(_) => bin("-"),
                    IMul | Mul(_) => bin("*"),
                    IDiv | Div(_) => bin("/"),
                    IMod | Rem(_) => bin("%"),
                    INeg => format!("-{}", a[0]),
                    Eq(_) => bin("=="),
                    Ne(_) => bin("!="),
                    Lt(_) => bin("<"),
                    Le(_) => bin("<="),
                    Gt(_) => bin(">"),
                    Ge(_) => bin(">="),
                    And(_) => bin("&"),
                    Or(_) => bin("|"),
                    Xor(_) => bin("^"),
                    Shl(_) => bin("<<"),
                    Shr(_) => bin(">>"),
                    Not(_) => format!("!{}", a[0]),
                    Cast { to, .. } => {
                        let to = match to {
                            sandblaster_kernel::term::Width::Int => "Int".to_string(),
                            w => sandblaster_kernel::prim::width_suffix(*w).to_string(),
                        };
                        format!("({} as {to})", a[0])
                    }
                    OfInt(w) => format!("({} as {})", a[0], sandblaster_kernel::prim::width_suffix(*w)),
                    WAdd(_) => format!("{}.wrapping_add({})", a[0], a[1]),
                    WSub(_) => format!("{}.wrapping_sub({})", a[0], a[1]),
                    WMul(_) => format!("{}.wrapping_mul({})", a[0], a[1]),
                    WShl(_) => format!("{}.wrapping_shl({})", a[0], a[1]),
                    WShr(_) => format!("{}.wrapping_shr({})", a[0], a[1]),
                    Rotl(_) => format!("{}.rotate_left({})", a[0], a[1]),
                    Rotr(_) => format!("{}.rotate_right({})", a[0], a[1]),
                    op => format!("{}({})", sandblaster_kernel::prim::prim_name(*op), a.join(", ")),
                }
            }
            Term::Fst(p) => {
                // the list of a slice `fst(snd(s))` / an array `fst(a)` is
                // `s`; the length of a slice `fst(s)` is `s.len()`
                if let Term::Snd(q) = &**p {
                    return self.go(q, local);
                }
                match self.head_of(p, local) {
                    Some("Slice") => format!("{}.len()", self.go(p, local)),
                    Some("Array") => self.go(p, local),
                    _ => format!("{}.0", self.go(p, local)),
                }
            }
            Term::Snd(p) => format!("{}.1", self.go(p, local)),
            Term::Ctor { ind, ctor, args, .. } => {
                let name = self.ctor_name(*ind, *ctor);
                // lists: `seq![..]`
                if name == "Cons" || name == "Nil" {
                    let mut items = Vec::new();
                    let mut cur = t.clone();
                    loop {
                        match &*cur.clone() {
                            Term::Ctor { args, .. } if args.len() == 2 && items.len() < 16 => {
                                items.push(self.go(&args[0], local));
                                cur = args[1].clone();
                            }
                            Term::Ctor { args, .. } if args.is_empty() => return format!("seq![{}]", items.join(", ")),
                            _ => return format!("seq![{}] ++ {}", items.join(", "), self.go(&cur, local)),
                        }
                    }
                }
                let rels: Vec<Rel> = self.env.inductive_decl(*ind).and_then(|d| d.ctors.get(*ctor as usize).map(|c| c.fields.iter().map(|f| f.1).collect())).unwrap_or_default();
                let shown: Vec<String> = args.iter().enumerate().filter(|(i, _)| rels.get(*i) != Some(&Rel::Irr)).map(|(_, x)| self.go(x, local)).collect();
                if name.starts_with("tuple") {
                    return format!("({})", shown.join(", "));
                }
                match name.as_str() {
                    "true" | "false" => name,
                    _ if shown.is_empty() => name,
                    _ => format!("{name}({})", shown.join(", ")),
                }
            }
            Term::Pair { fst, .. } => self.go(fst, local),
            Term::App { .. } => {
                let mut args = Vec::new();
                let mut h = t;
                while let Term::App { rel, fun, arg } = &**h {
                    if *rel == Rel::Rel {
                        args.push(arg.clone());
                    }
                    h = fun;
                }
                args.reverse();
                if let Term::Global(g) = &**h {
                    let name = self.global(*g);
                    // the sequence vocabulary (the element type argument dropped)
                    let seq = |me: &mut Self, local: &mut Vec<String>, i: usize| me.go(&args[i], local);
                    match (name.as_str(), args.len()) {
                        ("seq::len", 2) => return format!("{}.len()", seq(self, local, 1)),
                        ("seq::index", 3) => return format!("{}[{}]", seq(self, local, 1), seq(self, local, 2)),
                        ("seq::take", 3) => return format!("{}.take({})", seq(self, local, 1), seq(self, local, 2)),
                        ("seq::drop", 3) => return format!("{}.skip({})", seq(self, local, 1), seq(self, local, 2)),
                        ("seq::append", 3) => return format!("{}.append({})", seq(self, local, 1), seq(self, local, 2)),
                        ("slice::index", 3) => return format!("{}[{}]", seq(self, local, 1), seq(self, local, 2)),
                        // `array::index(T, N, a, i)` (element type and length dropped)
                        ("array::index", 4) => return format!("{}[{}]", seq(self, local, 2), seq(self, local, 3)),
                        _ => {}
                    }
                    let shown: Vec<String> = args.iter().map(|a| self.go(a, local)).collect();
                    return format!("{name}({})", shown.join(", "));
                }
                let f = self.go(h, local);
                if args.is_empty() {
                    return f;
                }
                let shown: Vec<String> = args.iter().map(|a| self.go(a, local)).collect();
                format!("{f}({})", shown.join(", "))
            }
            Term::Match { ind, scrut, arms, .. } => {
                let s = self.go(scrut, local);
                if *ind == self.env.bool_ind() && arms.len() == 2 {
                    let (f, tr) = (self.arm(&arms[0], local), self.arm(&arms[1], local));
                    return format!("if {s} {{ {tr} }} else {{ {f} }}");
                }
                let shown: Vec<String> = arms
                    .iter()
                    .enumerate()
                    .map(|(ci, a)| {
                        let c = self.ctor_name(*ind, ci as u32);
                        let fields = if a.names.is_empty() { String::new() } else { format!("({})", a.names.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")) };
                        for n in &a.names {
                            local.push(n.to_string());
                        }
                        let b = self.arm_body(&a.body, local);
                        for _ in &a.names {
                            local.pop();
                        }
                        format!("{c}{fields} => {b}")
                    })
                    .collect();
                format!("match {s} {{ {} }}", shown.join(", "))
            }
            Term::Let { name, rel, val, body, .. } => {
                local.push(name.to_string());
                let b = self.go(body, local);
                local.pop();
                if *rel == Rel::Irr { b } else { format!("{{ let {name} = {}; {b} }}", self.go(val, local)) }
            }
            Term::Lam { name, rel, body, .. } => {
                local.push(name.to_string());
                let b = self.go(body, local);
                local.pop();
                if *rel == Rel::Irr { b } else { format!("|{name}| {b}") }
            }
            Term::Pi { name, rel, dom, cod } => {
                let d = self.go(dom, local);
                local.push(name.to_string());
                let c = self.go(cod, local);
                local.pop();
                if *rel == Rel::Irr { format!("({d}) => {c}") } else { format!("forall {name}, {c}") }
            }
            Term::Transport { val, .. } => self.go(val, local),
            Term::Refl { val, .. } => format!("refl({})", self.go(val, local)),
            // core syntax, in the whole scope: the context's names and the
            // binders crossed so far (a `let` of an `ensures` statement)
            Term::Sigma { .. } | Term::Ind { .. } => sandblaster_kernel::syntax::printer::print_term_bounded(self.env, &self.names.iter().chain(local.iter()).map(|s| std::rc::Rc::from(s.as_str())).collect::<Vec<_>>(), t, 200),
            _ => "_".into(),
        }
    }

    /// A `bool` match arm body (dependent arms are `λ(e). b`).
    fn arm(&mut self, a: &sandblaster_kernel::term::Arm, local: &mut Vec<String>) -> String {
        self.arm_body(&a.body, local)
    }

    fn arm_body(&mut self, b: &sandblaster_kernel::term::Tm, local: &mut Vec<String>) -> String {
        self.go(b, local)
    }
}
