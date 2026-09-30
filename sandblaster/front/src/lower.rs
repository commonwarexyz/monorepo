//! Lowering of optimized lifted code back to the host's Rust (DESIGN.md
//! §2.1 "The optimizer on lifted modules", §8.2; the lift of SEMANTICS.md §19
//! gives the printed text its meaning).
//!
//! A lifted module (`#[lift] mod m;`) is emitted as the source file. When
//! the always-on optimizer finds a cheaper residual for one of its
//! functions, the residual is **lowered**: printed as plain Rust in the
//! language the lift reads (the source's own dialect: method calls, plain
//! operators, the file's names), so that it can be placed in the source
//! file and read back by the same lift that gave the source its meaning.
//!
//! This printer is **untrusted**. Its output is accepted only after the
//! lifted round trip (`driver::lowered`): the emitted text is lifted
//! again, elaborated in generated mode and compared, in all relevant
//! positions, with the kernel-checked residual. A name printed here that
//! resolves to something else, a dropped operation or a wrong operator
//! fails that comparison, and the function keeps its source text. So the
//! printer may be optimistic (it names items by their simple names, as the
//! source does); it refuses only what it cannot print at all.
//!
//! What it prints (anything else is refused with a reason):
//!
//! * types: `bool`, unsigned integers, tuples, arrays, `&[T]`, `&T`,
//!   `Option<T>`, user types by their simple name (never a generic
//!   parameter or a ghost type); references are refused in a return type
//!   (rustc's lifetime elision could reject the signature);
//! * expressions: literals (suffixed), locals, operators (a checked
//!   operator prints as the plain operator: the proof slot of the residual
//!   is kernel-checked, so Rust's operator does not overflow either), casts,
//!   builtin methods as method calls, calls of the functions named by the
//!   caller ([`Names`]), constructors, fields, indexing, ranges, `if`,
//!   `match`, blocks, `let`, assignments, `return`, `?`, `unreachable!()`;
//! * in state mode ([`lower_fn_state`]), a `Seq<u8>` state (the lift's
//!   reading of `buf: &mut impl BufMut`) as the parameter `&mut impl
//!   BufMut` and the buffer model's `put_u8`/`put_slice` as calls on it,
//!   through `let`, `if` and `match`, each state value used once and in
//!   order;
//! * never loops, recursion, ghost code, intrinsics or load/store helpers
//!   (a residual with any of them keeps the source text).
//!
//! Parentheses: compound operands are parenthesized; the positions rustc's
//! `unused_parens` lint checks (a `let` initializer, an argument, a
//! condition, a scrutinee, a block tail, a `return` value) are printed
//! without outer parentheses, so the lowered code is lint-clean.

use std::collections::HashMap;

use crate::builtins::{ArrayMethod, Builtin, OptionMethod};
use crate::hir::*;

/// How the lowered code names the functions it calls: optimizer helpers
/// get the emitted helper names, source functions of the lifted module
/// their names in the file. A callee outside the map is refused.
#[derive(Clone, Debug, Default)]
pub struct Names {
    pub fns: HashMap<ItemId, String>,
}

type R<T> = Result<T, String>;

/// A lowered function item: `attrs` (printed before `fn`), the name, and
/// the text of the whole item.
pub struct LoweredFn {
    pub name: String,
    pub text: String,
}

/// Lowers function `id` of the print view `pv` (its printed body: the
/// residual for a specialized function) as a private item named `name`
/// with its own parameter names. `#[inline(always)]` and a lint `allow`
/// for what printed code may trigger are prepended (both semantics-free;
/// the lift keeps only `allow` and `doc`).
pub fn lower_fn(pv: &Crate, id: ItemId, name: &str, names: &Names) -> R<LoweredFn> {
    lower_fn_with(pv, id, name, names, None)
}

/// [`lower_fn`] for a function with one `BufMut` state (DESIGN.md §2.1:
/// the lift reads `buf: &mut impl BufMut` as a `Seq<u8>` parameter
/// returned as the function's value): parameter `state` of the lifted
/// function is printed as `&mut impl BufMut`, and the body — a `Seq<u8>`
/// expression — as the buffer calls that produce it. Every state value
/// must be used exactly once, in order (the old state is never read again);
/// the only state operations are the buffer model's `put_u8`/`put_slice`,
/// `if` and `match` on non-state values, and `let` of a new state.
pub fn lower_fn_state(pv: &Crate, id: ItemId, name: &str, names: &Names, state: usize) -> R<LoweredFn> {
    lower_fn_with(pv, id, name, names, Some(state))
}

/// [`lower_fn`] for a reader: parameter `state` is the lift's reading of
/// `buf: &mut impl Buf` (a `Seq<u8>`, the bytes not yet read), returned as
/// the function's value — alone, or first beside the result when
/// `has_result`. The body is printed as statements on the original
/// `&mut impl Buf` parameter (`buf.try_get_u8()`) and the result as the
/// value: every state value is used once, in order (the old state is never
/// read again); the only state operation is the buffer model's
/// `try_get_u8`, bound by `let` or matched, and `if`/`match` on non-state
/// values carry the state through their arms.
pub fn lower_fn_reader(pv: &Crate, id: ItemId, name: &str, names: &Names, state: usize, has_result: bool) -> R<LoweredFn> {
    let f = pv.fn_def(id).ok_or_else(|| format!("`{}` is not a function", pv.item(id).path))?;
    check_lowerable(pv, id, f)?;
    let body = match &f.body {
        FnBody::Exec(e) => e,
        _ => return Err("not an exec body".into()),
    };
    let prm = f.params.get(state).ok_or("no state parameter")?;
    let PatKind::Binding { local, .. } = &prm.pat.kind else { return Err("a state parameter with a pattern".into()) };
    let ret_ok = match (&f.ret, has_result) {
        (Ty::Tuple(ts), true) => ts.len() == 2 && is_state_ty(&ts[0]),
        (t, false) => is_state_ty(t),
        _ => false,
    };
    if !is_state_ty(&prm.ty) || !ret_ok {
        return Err("the state is not a `Buf` buffer returned first".into());
    }
    let p = Printer { pv, f, names, state: std::cell::RefCell::new(Some((*local, String::new()))), reader: Default::default() };
    let mut params = Vec::new();
    for (k, prm) in f.params.iter().enumerate() {
        let PatKind::Binding { local, mode: BindingMode::ByValue, sub: None } = &prm.pat.kind else {
            return Err("a parameter with a destructuring pattern".into());
        };
        if k == state {
            let n = p.local(*local);
            *p.state.borrow_mut() = Some((*local, n.clone()));
            params.push(format!("{n}: &mut impl Buf"));
            continue;
        }
        let m = if f.local(*local).mutable { "mut " } else { "" };
        params.push(format!("{m}{}: {}", p.local(*local), p.ty(&prm.ty)?));
    }
    let ret = match &f.ret {
        Ty::Tuple(ts) if has_result => {
            if contains_ref(&ts[1]) {
                return Err("a reference in the return type".into());
            }
            format!(" -> {}", p.ty(&ts[1])?)
        }
        _ => String::new(),
    };
    let mut out = Vec::new();
    let v = p.reader_expr(body, 1, &mut out, has_result)?;
    let mut text = String::from("{\n");
    for l in out {
        text.push_str(&l);
        text.push('\n');
    }
    if let Some(v) = v {
        text.push_str(&format!("{}{v}\n", ind(1)));
    }
    text.push('}');
    let text = format!(
        "#[inline(always)]\n#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]\nfn {name}({}){ret} {text}\n",
        params.join(", ")
    );
    Ok(LoweredFn { name: name.to_string(), text })
}

/// The shape conditions every lowered function meets.
fn check_lowerable(pv: &Crate, id: ItemId, f: &FnDef) -> R<()> {
    if f.kind != FnKind::Exec {
        return Err("not an exec function".into());
    }
    if f.recursion != Recursion::None {
        return Err("a recursive function (lowered code has no loops or recursion yet)".into());
    }
    // an associated function without a receiver is lowered as a free
    // helper (it is called by name, never as a method)
    if f.receiver.is_some() {
        return Err("a method with a receiver (lowered helpers are free functions)".into());
    }
    if !f.generics.is_empty() || !f.lifetimes.is_empty() {
        return Err("a generic function".into());
    }
    if f.params.iter().any(|p| p.ghost) {
        return Err("a ghost parameter".into());
    }
    if f.decreases.is_some() {
        return Err("a `decreases` clause (lowered code is not recursive)".into());
    }
    let _ = (pv, id);
    Ok(())
}

fn lower_fn_with(pv: &Crate, id: ItemId, name: &str, names: &Names, state: Option<usize>) -> R<LoweredFn> {
    let f = pv.fn_def(id).ok_or_else(|| format!("`{}` is not a function", pv.item(id).path))?;
    check_lowerable(pv, id, f)?;
    let body = match &f.body {
        FnBody::Exec(e) => e,
        _ => return Err("not an exec body".into()),
    };
    let mut state_local = None;
    if let Some(k) = state {
        let prm = f.params.get(k).ok_or("no state parameter")?;
        let PatKind::Binding { local, .. } = &prm.pat.kind else { return Err("a state parameter with a pattern".into()) };
        if !is_state_ty(&prm.ty) || !is_state_ty(&f.ret) {
            return Err("the state is not a `BufMut` buffer returned as the value".into());
        }
        state_local = Some(*local);
    }
    let p = Printer { pv, f, names, state: std::cell::RefCell::new(state_local.map(|l| (l, String::new()))), reader: Default::default() };
    let mut params = Vec::new();
    for (k, prm) in f.params.iter().enumerate() {
        let PatKind::Binding { local, mode: BindingMode::ByValue, sub: None } = &prm.pat.kind else {
            return Err("a parameter with a destructuring pattern".into());
        };
        if Some(k) == state {
            let n = p.local(*local);
            *p.state.borrow_mut() = Some((*local, n.clone()));
            params.push(format!("{n}: &mut impl BufMut"));
            continue;
        }
        let m = if f.local(*local).mutable { "mut " } else { "" };
        params.push(format!("{m}{}: {}", p.local(*local), p.ty(&prm.ty)?));
    }
    if state.is_none() && contains_ref(&f.ret) {
        return Err("a reference in the return type".into());
    }
    let ret = if f.ret.is_unit() || state.is_some() { String::new() } else { format!(" -> {}", p.ty(&f.ret)?) };
    let body_text = if state.is_some() {
        let mut out = Vec::new();
        p.state_expr(body, 1, &mut out)?;
        format!("{{\n{}}}", out.into_iter().map(|l| format!("{l}\n")).collect::<String>())
    } else {
        p.block_expr(body, 0)?
    };
    let text = format!(
        "#[inline(always)]\n#[allow(non_snake_case, unused_parens, unused_mut, unused_variables, unused_braces, clippy::all)]\nfn {name}({}){ret} {body_text}\n",
        params.join(", ")
    );
    Ok(LoweredFn { name: name.to_string(), text })
}

/// Whether a type contains a reference anywhere.
fn contains_ref(t: &Ty) -> bool {
    let mut r = false;
    t.walk(&mut |x| r |= matches!(x, Ty::Ref(_)));
    r
}

/// Every function item the printed body of `id` calls (for the helper
/// closure), in first-call order.
pub fn callees(pv: &Crate, id: ItemId) -> Vec<ItemId> {
    struct C(Vec<ItemId>);
    impl crate::visit::Visitor for C {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(i, _), .. } = &e.kind
                && !self.0.contains(i)
            {
                self.0.push(*i);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut c = C(vec![]);
    if let Some(FnBody::Exec(e)) = pv.fn_def(id).map(|f| &f.body) {
        crate::visit::Visitor::expr(&mut c, e);
    }
    c.0
}

struct Printer<'a> {
    pv: &'a Crate,
    f: &'a FnDef,
    names: &'a Names,
    /// State mode ([`lower_fn_state`]): the current state local and the
    /// name of the `&mut impl BufMut` parameter.
    state: std::cell::RefCell<Option<(LocalId, String)>>,
    /// Reader mode: the pair local (`let p = try_get_u8(..)`) whose `.0` is
    /// the current state, a local its tuple pattern bound to that state,
    /// and each pair's result variable in the printed code.
    reader: std::cell::RefCell<ReaderState>,
}

#[derive(Clone, Default)]
struct ReaderState {
    pair: Option<LocalId>,
    alias: Option<LocalId>,
    results: HashMap<LocalId, String>,
}

/// The lifted type of a buffer state: `Seq<u8>`.
fn is_state_ty(t: &Ty) -> bool {
    matches!(t, Ty::Seq(e) if **e == Ty::u8())
}

/// Whether a type holds a buffer state anywhere.
fn has_state(t: &Ty) -> bool {
    let mut r = false;
    t.walk(&mut |x| r |= is_state_ty(x));
    r
}

/// The buffer model's operations the lowering prints back as `BufMut`
/// calls (`drive::KEPT_LIFT_MODEL`).
fn model_op(pv: &Crate, id: ItemId) -> Option<&'static str> {
    match pv.item(id).path.to_string().as_str() {
        "crate::__lift_model::bufmut_put_u8" => Some("put_u8"),
        "crate::__lift_model::bufmut_put_slice" => Some("put_slice"),
        _ => None,
    }
}

/// Whether `e` is the buffer model's `try_get_u8` on a state (reader mode).
fn is_try_get<'e>(pv: &Crate, e: &'e Expr) -> Option<&'e Expr> {
    match &e.kind {
        ExprKind::Call { callee: Callee::Item(id, tys), args } if tys.is_empty() && args.len() == 1 && pv.item(*id).path.to_string() == "crate::__lift_model::buf_try_get_u8" => Some(&args[0]),
        _ => None,
    }
}

/// Where an expression is printed: `Top` positions are the ones rustc's
/// `unused_parens` lint checks (printed without outer parentheses);
/// `Operand` positions parenthesize compound expressions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pos {
    Top,
    Operand,
}

fn ind(n: usize) -> String {
    "    ".repeat(n)
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !s.starts_with(|c: char| c.is_ascii_digit())
}

impl Printer<'_> {
    fn local(&self, l: LocalId) -> String {
        let d = self.f.local(l);
        let base = if ident_ok(&d.name) { d.name.as_str() } else { "v" };
        format!("l{}_{}", l.0, base.trim_start_matches('_'))
    }

    fn ty(&self, t: &Ty) -> R<String> {
        Ok(match t {
            Ty::Bool => "bool".into(),
            Ty::Uint(u) => u.name().into(),
            Ty::Tuple(ts) if ts.len() == 1 => format!("({},)", self.ty(&ts[0])?),
            Ty::Tuple(ts) => format!("({})", ts.iter().map(|x| self.ty(x)).collect::<R<Vec<_>>>()?.join(", ")),
            Ty::Array(e, n) => format!("[{}; {n}]", self.ty(e)?),
            Ty::Ref(inner) => match &**inner {
                Ty::Slice(e) => format!("&[{}]", self.ty(e)?),
                other => format!("&{}", self.ty(other)?),
            },
            Ty::Option(e) => format!("Option<{}>", self.ty(e)?),
            Ty::Adt(id, args) => {
                let it = self.pv.item(*id);
                // the lift's models (`I16`, `TryGetError`, ...) have no host
                // spelling (the host writes `i16`, `bytes::TryGetError`),
                // except core's `Result` (in every Rust prelude)
                if it.path.0.first().is_some_and(|m| m == "__lift" || m == "__lift_model") && it.path.to_string() != "crate::__lift::Result" {
                    return Err(format!("the lift prelude type `{}` has no host spelling", it.path));
                }
                if args.is_empty() {
                    it.name.clone()
                } else {
                    format!("{}<{}>", it.name, args.iter().map(|x| self.ty(x)).collect::<R<Vec<_>>>()?.join(", "))
                }
            }
            other => return Err(format!("the type `{}` has no host spelling", other.display(&|i| self.pv.item(i).name.clone()))),
        })
    }

    fn lit(&self, l: &Lit, t: &Ty) -> R<String> {
        Ok(match (l, t) {
            (Lit::Bool(b), _) => b.to_string(),
            (Lit::Int(n), Ty::Uint(u)) => format!("{n}{}", u.name()),
            (Lit::Int(_), other) => return Err(format!("an integer literal of type `{}`", other.display(&|i| self.pv.item(i).name.clone()))),
        })
    }

    /// A block-shaped expression (function body, `if` arm): `{ .. }`.
    fn block_expr(&self, e: &Expr, i: usize) -> R<String> {
        match &e.kind {
            ExprKind::Block(b) => self.block(b, i),
            _ => Ok(format!("{{\n{}{}\n{}}}", ind(i + 1), self.expr(e, i + 1, Pos::Top)?, ind(i))),
        }
    }

    fn block(&self, b: &Block, i: usize) -> R<String> {
        let mut s = String::from("{\n");
        for st in &b.stmts {
            if let Some(t) = self.stmt(st, i + 1)? {
                s.push_str(&ind(i + 1));
                s.push_str(&t);
                s.push('\n');
            }
        }
        if let Some(t) = &b.tail {
            s.push_str(&ind(i + 1));
            s.push_str(&self.expr(t, i + 1, Pos::Top)?);
            s.push('\n');
        }
        s.push_str(&ind(i));
        s.push('}');
        Ok(s)
    }

    fn stmt(&self, st: &Stmt, i: usize) -> R<Option<String>> {
        Ok(Some(match &st.kind {
            StmtKind::Let { pat, init, els: None } => format!("let {}: {} = {};", self.pat(pat)?, self.ty(&pat.ty)?, self.expr(init, i, Pos::Top)?),
            StmtKind::Let { els: Some(_), .. } => return Err("`let .. else`".into()),
            StmtKind::Expr(e) => {
                let t = self.expr(e, i, Pos::Top)?;
                if matches!(e.kind, ExprKind::If { .. } | ExprKind::Match { .. } | ExprKind::Block(_)) { t } else { format!("{t};") }
            }
            StmtKind::Assign { place, value } => format!("{} = {};", self.place(place, i)?, self.expr(value, i, Pos::Top)?),
            StmtKind::CompoundAssign { op, place, value } => format!("{} {}= {};", self.place(place, i)?, op.symbol(), self.expr(value, i, Pos::Top)?),
            StmtKind::CopyFromSlice { .. } => return Err("`copy_from_slice`".into()),
            // ghost blocks are never printed (they have no relevant content)
            StmtKind::Proof(_) => return Ok(None),
        }))
    }

    fn place(&self, p: &Place, i: usize) -> R<String> {
        let mut s = self.local(p.local);
        for pr in &p.projs {
            match pr {
                Proj::Field { index, name } => s = format!("{s}.{}", name.clone().unwrap_or_else(|| index.to_string())),
                Proj::Index(e) => s = format!("{s}[{}]", self.expr(e, i, Pos::Top)?),
            }
        }
        Ok(s)
    }

    fn pat(&self, p: &Pat) -> R<String> {
        Ok(match &p.kind {
            PatKind::Wild => "_".into(),
            PatKind::Binding { local, mode, sub } => {
                let m = match mode {
                    BindingMode::ByRef => "ref ",
                    BindingMode::ByValue if self.f.local(*local).mutable => "mut ",
                    BindingMode::ByValue => "",
                };
                let b = format!("{m}{}", self.local(*local));
                match sub {
                    Some(s) => format!("{b} @ {}", self.pat(s)?),
                    None => b,
                }
            }
            PatKind::Lit(l) => self.lit(l, &p.ty)?,
            PatKind::Range { lo, hi } => {
                let u = p.ty.as_uint().ok_or("a range pattern of a non-integer type")?;
                format!("{lo}{}..={hi}{}", u.name(), u.name())
            }
            PatKind::Tuple(ps) if ps.len() == 1 => format!("({},)", self.pat(&ps[0])?),
            PatKind::Tuple(ps) => format!("({})", ps.iter().map(|x| self.pat(x)).collect::<R<Vec<_>>>()?.join(", ")),
            PatKind::Ctor { ctor, fields, .. } => self.ctor_pat(*ctor, fields)?,
            PatKind::Deref { pat, implicit: false } => format!("&{}", self.pat(pat)?),
            PatKind::Deref { pat, implicit: true } => format!("&{}", self.pat(pat)?),
            PatKind::Slice { prefix, rest, suffix } => {
                let mut parts: Vec<String> = prefix.iter().map(|x| self.pat(x)).collect::<R<_>>()?;
                match rest {
                    None => {}
                    Some(None) => parts.push("..".into()),
                    Some(Some(r)) => parts.push(format!("{} @ ..", self.pat(r)?)),
                }
                for x in suffix {
                    parts.push(self.pat(x)?);
                }
                format!("[{}]", parts.join(", "))
            }
            PatKind::Or(ps) => ps.iter().map(|x| self.pat(x)).collect::<R<Vec<_>>>()?.join(" | "),
        })
    }

    fn ctor_head(&self, ctor: Ctor) -> R<(String, Shape, Vec<Option<String>>)> {
        Ok(match ctor {
            Ctor::Some => ("Some".into(), Shape::Tuple, vec![None]),
            Ctor::None => ("None".into(), Shape::Unit, vec![]),
            Ctor::Struct(id) => match &self.pv.item(id).kind {
                ItemKind::Struct(s) => (self.pv.item(id).name.clone(), s.shape, s.fields.iter().map(|f| f.name.clone()).collect()),
                _ => return Err("a struct constructor of a non-struct".into()),
            },
            Ctor::Variant(id, k) => match &self.pv.item(id).kind {
                ItemKind::Enum(e) => {
                    let v = e.variants.get(k as usize).ok_or("a variant index out of range")?;
                    (format!("{}::{}", self.pv.item(id).name, v.name), v.shape, v.fields.iter().map(|f| f.name.clone()).collect())
                }
                _ => return Err("a variant of a non-enum".into()),
            },
        })
    }

    fn ctor_pat(&self, ctor: Ctor, fields: &[(u32, Pat)]) -> R<String> {
        let (head, shape, names) = self.ctor_head(ctor)?;
        Ok(match shape {
            Shape::Unit => head,
            Shape::Tuple => {
                let mut parts = vec!["_".to_string(); names.len()];
                for (k, p) in fields {
                    *parts.get_mut(*k as usize).ok_or("a field index out of range")? = self.pat(p)?;
                }
                format!("{head}({})", parts.join(", "))
            }
            Shape::Named => {
                let mut parts = Vec::new();
                for (k, p) in fields {
                    let n = names.get(*k as usize).cloned().flatten().ok_or("a named field without a name")?;
                    parts.push(format!("{n}: {}", self.pat(p)?));
                }
                if fields.len() < names.len() {
                    parts.push("..".into());
                }
                format!("{head} {{ {} }}", parts.join(", "))
            }
        })
    }

    fn paren(&self, s: String, e: &Expr, pos: Pos) -> String {
        let atomic = matches!(e.kind, ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Call { .. } | ExprKind::Adt { .. } | ExprKind::Tuple(_) | ExprKind::Array(_) | ExprKind::Repeat { .. } | ExprKind::Field { .. } | ExprKind::Index { .. } | ExprKind::Unreachable | ExprKind::Block(_));
        let call_like_method = matches!(&e.kind, ExprKind::Call { callee: Callee::Builtin(b, _), .. } if b.infix().is_some());
        if pos == Pos::Operand && (!atomic || call_like_method) { format!("({s})") } else { s }
    }

    fn args(&self, args: &[Expr], i: usize) -> R<String> {
        Ok(args.iter().map(|a| self.expr(a, i, Pos::Top)).collect::<R<Vec<_>>>()?.join(", "))
    }

    fn expr(&self, e: &Expr, i: usize, pos: Pos) -> R<String> {
        let s = match &e.kind {
            ExprKind::Lit(l) => self.lit(l, &e.ty)?,
            ExprKind::Local(l) if has_state(&self.f.local(*l).ty) => return Err("a buffer state used as a value".into()),
            ExprKind::Local(l) => self.local(*l),
            ExprKind::Const(id) => self.pv.item(*id).name.clone(),
            ExprKind::BuiltinConst(c) => match c {
                BuiltinConst::Max(u) => format!("{}::MAX", u.name()),
                BuiltinConst::Min(u) => format!("{}::MIN", u.name()),
                BuiltinConst::Bits(u) => format!("{}::BITS", u.name()),
                BuiltinConst::IsizeMax => return Err("ghost `ISIZE_MAX`".into()),
            },
            ExprKind::Call { callee, args } => self.call(callee, args, i)?,
            ExprKind::Adt { ctor, fields, base, .. } => {
                if base.is_some() {
                    return Err("a struct update `..base`".into());
                }
                let (head, shape, names) = self.ctor_head(*ctor)?;
                match shape {
                    Shape::Unit => head,
                    Shape::Tuple => {
                        let mut parts: Vec<Option<String>> = vec![None; names.len()];
                        for (k, x) in fields {
                            *parts.get_mut(*k as usize).ok_or("a field index out of range")? = Some(self.expr(x, i, Pos::Top)?);
                        }
                        let parts: Vec<String> = parts.into_iter().collect::<Option<_>>().ok_or("a tuple constructor with a missing field")?;
                        format!("{head}({})", parts.join(", "))
                    }
                    Shape::Named => {
                        let mut parts = Vec::new();
                        for (k, x) in fields {
                            let n = names.get(*k as usize).cloned().flatten().ok_or("a named field without a name")?;
                            parts.push(format!("{n}: {}", self.expr(x, i, Pos::Top)?));
                        }
                        format!("{head} {{ {} }}", parts.join(", "))
                    }
                }
            }
            ExprKind::Tuple(xs) if xs.len() == 1 => format!("({},)", self.expr(&xs[0], i, Pos::Top)?),
            ExprKind::Tuple(xs) => format!("({})", self.args(xs, i)?),
            ExprKind::Array(xs) => format!("[{}]", self.args(xs, i)?),
            ExprKind::Repeat { elem, count } => format!("[{}; {count}]", self.expr(elem, i, Pos::Top)?),
            ExprKind::Field { base, index, .. } if matches!(&base.kind, ExprKind::Local(p) if self.reader.borrow().results.contains_key(p)) => {
                let ExprKind::Local(p) = &base.kind else { unreachable!() };
                if *index != 1 {
                    return Err("a buffer state used as a value".into());
                }
                self.reader.borrow().results[p].clone()
            }
            ExprKind::Field { base, index, name } => format!("{}.{}", self.expr(base, i, Pos::Operand)?, name.clone().unwrap_or_else(|| index.to_string())),
            ExprKind::Index { base, index } => format!("{}[{}]", self.expr(base, i, Pos::Operand)?, self.expr(index, i, Pos::Top)?),
            ExprKind::SliceRange { base, lo, hi } => {
                let lo = lo.as_ref().map(|x| self.expr(x, i, Pos::Operand)).transpose()?.unwrap_or_default();
                let hi = hi.as_ref().map(|x| self.expr(x, i, Pos::Operand)).transpose()?.unwrap_or_default();
                format!("&{}[{lo}..{hi}]", self.expr(base, i, Pos::Operand)?)
            }
            ExprKind::Unary(UnOp::Not, x) => format!("!{}", self.expr(x, i, Pos::Operand)?),
            ExprKind::Unary(UnOp::Neg, _) => return Err("ghost negation".into()),
            ExprKind::Binary(op, a, b) => format!("{} {} {}", self.expr(a, i, Pos::Operand)?, op.symbol(), self.expr(b, i, Pos::Operand)?),
            ExprKind::Cast(x, t) => format!("{} as {}", self.expr(x, i, Pos::Operand)?, self.ty(t)?),
            ExprKind::Ref(x) => format!("&{}", self.expr(x, i, Pos::Operand)?),
            ExprKind::Deref(x) => format!("*{}", self.expr(x, i, Pos::Operand)?),
            // adjustments are re-inserted by the front end when the lowered
            // text is read back (each is the identity in the model)
            ExprKind::Coerce(Coercion::Unsize | Coercion::AutoRef | Coercion::AutoDeref, x) => return self.expr(x, i, pos),
            ExprKind::Coerce(..) => return Err("a ghost coercion".into()),
            ExprKind::If { cond, then, els } => {
                let mut s = format!("if {} {}", self.expr(cond, i, Pos::Top)?, self.block_expr(then, i)?);
                if let Some(x) = els {
                    let t = match &x.kind {
                        ExprKind::If { .. } => self.expr(x, i, Pos::Top)?,
                        _ => self.block_expr(x, i)?,
                    };
                    s.push_str(&format!(" else {t}"));
                }
                s
            }
            ExprKind::Match { scrut, arms, .. } => {
                let mut s = format!("match {} {{\n", self.expr(scrut, i, Pos::Top)?);
                for a in arms {
                    let g = match &a.guard {
                        Some(g) => format!(" if {}", self.expr(g, i + 1, Pos::Top)?),
                        None => String::new(),
                    };
                    s.push_str(&format!("{}{}{g} => {},\n", ind(i + 1), self.pat(&a.pat)?, self.block_expr(&a.body, i + 1)?));
                }
                s.push_str(&ind(i));
                s.push('}');
                s
            }
            ExprKind::Block(b) => self.block(b, i)?,
            ExprKind::Return(None) => "return".into(),
            ExprKind::Return(Some(x)) => format!("return {}", self.expr(x, i, Pos::Top)?),
            ExprKind::Try(x) => format!("{}?", self.expr(x, i, Pos::Operand)?),
            ExprKind::Unreachable => "unreachable!()".into(),
            ExprKind::Loop(_) => return Err("a loop (lowered code has no loops yet)".into()),
            _ => return Err("ghost code".into()),
        };
        Ok(self.paren(s, e, pos))
    }

    /// Reader mode ([`lower_fn_reader`]): statements in `out` (indent `i`)
    /// that turn the current state into the state of `e`, and the text of
    /// `e`'s result when `res` (`e : (Seq<u8>, R)`; else `e : Seq<u8>`).
    fn reader_expr(&self, e: &Expr, i: usize, out: &mut Vec<String>, res: bool) -> R<Option<String>> {
        let (cur, name) = self.state.borrow().clone().ok_or("reader mode without a state")?;
        if let Some(arg) = match &e.kind {
            ExprKind::Match { scrut, .. } => is_try_get(self.pv, scrut),
            _ => None,
        } {
            let ExprKind::Match { arms, .. } = &e.kind else { unreachable!() };
            // `match try_get_u8(cur) { (t, p) => .. }`
            self.reader_is_current(arg)?;
            let mut s = format!("match {name}.try_get_u8() {{\n");
            for a in arms {
                if a.guard.is_some() {
                    return Err("a guarded arm in reader mode".into());
                }
                let PatKind::Tuple(ps) = &a.pat.kind else { return Err("a `try_get_u8` matched without a tuple pattern".into()) };
                let [pt, pr] = ps.as_slice() else { return Err("a `try_get_u8` pattern of another arity".into()) };
                let PatKind::Binding { local: t, sub: None, .. } = &pt.kind else { return Err("the state of `try_get_u8` is not bound to a name".into()) };
                *self.state.borrow_mut() = Some((*t, name.clone()));
                let arm = self.reader_block(&a.body, i + 1, res)?;
                s.push_str(&format!("{}{} => {arm},\n", ind(i + 1), self.pat(pr)?));
            }
            s.push_str(&ind(i));
            s.push('}');
            *self.state.borrow_mut() = Some((LocalId(u32::MAX), name));
            return if res {
                Ok(Some(s))
            } else {
                out.push(format!("{}{s}", ind(i)));
                Ok(None)
            };
        }
        // `match p { (t, r) => body }` on a pair of `try_get_u8`
        let pair_res = match &e.kind {
            ExprKind::Match { scrut, .. } => match &scrut.kind {
                ExprKind::Local(p) => self.reader.borrow().results.get(p).cloned(),
                _ => None,
            },
            _ => None,
        };
        if let ExprKind::Match { scrut, arms, .. } = &e.kind
            && let ExprKind::Local(p) = &scrut.kind
            && let Some(resv) = pair_res
        {
            if Some(*p) != self.reader.borrow().pair {
                return Err("an old buffer state used again".into());
            }
            let [a] = arms.as_slice() else { return Err("a `try_get_u8` pair matched with more than one arm".into()) };
            if a.guard.is_some() {
                return Err("a guarded arm in reader mode".into());
            }
            let PatKind::Tuple(ps) = &a.pat.kind else { return Err("a `try_get_u8` pair matched without a tuple pattern".into()) };
            let [pt, pr] = ps.as_slice() else { return Err("a `try_get_u8` pattern of another arity".into()) };
            let alias = match &pt.kind {
                PatKind::Binding { local, sub: None, .. } => Some(*local),
                PatKind::Wild => None,
                _ => return Err("the state of `try_get_u8` is not bound to a name".into()),
            };
            self.reader_set(LocalId(u32::MAX), Some(*p), alias);
            let arm = self.reader_block(&a.body, i + 1, res)?;
            let s = format!("match {resv} {{\n{}{} => {arm},\n{}}}", ind(i + 1), self.pat(pr)?, ind(i));
            self.reader_set(LocalId(u32::MAX), None, None);
            return if res {
                Ok(Some(s))
            } else {
                out.push(format!("{}{s}", ind(i)));
                Ok(None)
            };
        }
        match &e.kind {
            ExprKind::Tuple(xs) if res && xs.len() == 2 => {
                self.reader_is_current(&xs[0])?;
                Ok(Some(self.expr(&xs[1], i, Pos::Top)?))
            }
            ExprKind::Local(_) if !res => {
                self.reader_is_current(e)?;
                Ok(None)
            }
            ExprKind::Block(b) => {
                for st in &b.stmts {
                    let tg = match &st.kind {
                        StmtKind::Let { init, els: None, .. } => is_try_get(self.pv, init),
                        _ => None,
                    };
                    match (&st.kind, tg) {
                        // `let (t, r) = try_get_u8(cur);`
                        // `let p = try_get_u8(cur);`: `p.0` is the new state,
                        // `p.1` (or `p`'s tuple pattern) the result
                        (StmtKind::Let { pat, .. }, Some(arg)) if matches!(&pat.kind, PatKind::Binding { sub: None, .. }) => {
                            self.reader_is_current(arg)?;
                            let PatKind::Binding { local: p, .. } = &pat.kind else { unreachable!() };
                            let res = format!("{}_r", self.local(*p));
                            out.push(format!("{}let {res} = {name}.try_get_u8();", ind(i)));
                            self.reader.borrow_mut().results.insert(*p, res);
                            self.reader_set(LocalId(u32::MAX), Some(*p), None);
                        }
                        (StmtKind::Let { pat, .. }, Some(arg)) => {
                            self.reader_is_current(arg)?;
                            let PatKind::Tuple(ps) = &pat.kind else { return Err(format!("a `try_get_u8` bound without a tuple pattern ({})", format!("{:?}", pat.kind).chars().take(300).collect::<String>())) };
                            let [pt, pr] = ps.as_slice() else { return Err("a `try_get_u8` pattern of another arity".into()) };
                            let PatKind::Binding { local: t, sub: None, .. } = &pt.kind else { return Err("the state of `try_get_u8` is not bound to a name".into()) };
                            out.push(format!("{}let {} = {name}.try_get_u8();", ind(i), self.pat(pr)?));
                            *self.state.borrow_mut() = Some((*t, name.clone()));
                        }
                        // `let s = cur;`: another name of the current state
                        (StmtKind::Let { pat, init, .. }, None) if is_state_ty(&pat.ty) && matches!(&pat.kind, PatKind::Binding { sub: None, .. }) && self.reader_is_current(init).is_ok() => {
                            let PatKind::Binding { local, .. } = &pat.kind else { unreachable!() };
                            let (pair, alias) = {
                                let r = self.reader.borrow();
                                (r.pair, r.alias)
                            };
                            self.reader_set(*local, pair, alias);
                        }
                        (StmtKind::Let { pat, .. }, None) if has_state(&pat.ty) => return Err("a buffer state bound other than from `try_get_u8`".into()),
                        _ => {
                            if let Some(t) = self.stmt(st, i)? {
                                out.push(format!("{}{t}", ind(i)));
                            }
                        }
                    }
                }
                match &b.tail {
                    Some(t) => self.reader_expr(t, i, out, res),
                    None => Err("a state block without a value".into()),
                }
            }
            ExprKind::If { cond, then, els: Some(els) } => {
                let c = self.expr(cond, i, Pos::Top)?;
                let saved = self.reader.borrow().clone();
                let a = self.reader_block(then, i, res)?;
                *self.state.borrow_mut() = Some((cur, name.clone()));
                *self.reader.borrow_mut() = saved;
                let b = self.reader_block(els, i, res)?;
                *self.state.borrow_mut() = Some((LocalId(u32::MAX), name));
                let s = format!("if {c} {a} else {b}");
                if res {
                    Ok(Some(s))
                } else {
                    out.push(format!("{}{s}", ind(i)));
                    Ok(None)
                }
            }
            ExprKind::Match { scrut, arms, .. } if !has_state(&scrut.ty) => {
                let mut s = format!("match {} {{\n", self.expr(scrut, i, Pos::Top)?);
                let saved = self.reader.borrow().clone();
                for a in arms {
                    if a.guard.is_some() {
                        return Err("a guarded arm in reader mode".into());
                    }
                    *self.state.borrow_mut() = Some((cur, name.clone()));
                    *self.reader.borrow_mut() = saved.clone();
                    let arm = self.reader_block(&a.body, i + 1, res)?;
                    s.push_str(&format!("{}{} => {arm},\n", ind(i + 1), self.pat(&a.pat)?));
                }
                s.push_str(&ind(i));
                s.push('}');
                *self.state.borrow_mut() = Some((LocalId(u32::MAX), name));
                if res {
                    Ok(Some(s))
                } else {
                    out.push(format!("{}{s}", ind(i)));
                    Ok(None)
                }
            }
            _ => Err("a buffer state operation the lowering does not print (reader mode)".into()),
        }
    }

    /// A reader-mode arm or branch as a block: its statements and value.
    fn reader_block(&self, e: &Expr, i: usize, res: bool) -> R<String> {
        let mut out = Vec::new();
        let v = self.reader_expr(e, i + 1, &mut out, res)?;
        let mut s = String::from("{\n");
        for l in out {
            s.push_str(&l);
            s.push('\n');
        }
        if let Some(v) = v {
            s.push_str(&format!("{}{v}\n", ind(i + 1)));
        }
        s.push_str(&ind(i));
        s.push('}');
        Ok(s)
    }

    /// `s` is the current reader state (never an old one, never computed).
    fn reader_is_current(&self, s: &Expr) -> R<()> {
        let cur = self.state.borrow().as_ref().map(|x| x.0).ok_or("reader mode without a state")?;
        let r = self.reader.borrow();
        match &s.kind {
            ExprKind::Local(l) if *l == cur || Some(*l) == r.alias => Ok(()),
            ExprKind::Field { base, index: 0, .. } if matches!(&base.kind, ExprKind::Local(p) if Some(*p) == r.pair) => Ok(()),
            ExprKind::Local(_) | ExprKind::Field { .. } => Err("an old buffer state used again".into()),
            _ => Err("a buffer state expression the lowering does not print".into()),
        }
    }

    /// A new current state: the local `l` (or none, after a pair).
    fn reader_set(&self, l: LocalId, pair: Option<LocalId>, alias: Option<LocalId>) {
        let name = self.state.borrow().as_ref().map(|x| x.1.clone()).unwrap_or_default();
        *self.state.borrow_mut() = Some((l, name));
        let mut r = self.reader.borrow_mut();
        r.pair = pair;
        r.alias = alias;
    }

    /// The statements that turn the current state into the state value
    /// `e` (state mode), in `out` at indent `i`.
    fn state_expr(&self, e: &Expr, i: usize, out: &mut Vec<String>) -> R<()> {
        if !is_state_ty(&e.ty) {
            return Err("a non-state expression where the buffer state is expected".into());
        }
        let (cur, name) = self.state.borrow().clone().ok_or("state mode without a state")?;
        match &e.kind {
            ExprKind::Local(l) if *l == cur => Ok(()),
            ExprKind::Local(_) => Err("an old buffer state used again".into()),
            ExprKind::Call { callee: Callee::Item(id, tys), args } if tys.is_empty() && model_op(self.pv, *id).is_some() => {
                let op = model_op(self.pv, *id).unwrap();
                let [st, v] = args.as_slice() else { return Err("a buffer call with an unexpected arity".into()) };
                self.state_expr(st, i, out)?;
                out.push(format!("{}{name}.{op}({});", ind(i), self.expr(v, i, Pos::Top)?));
                Ok(())
            }
            ExprKind::Block(b) => {
                for st in &b.stmts {
                    match &st.kind {
                        StmtKind::Let { pat, init, els: None } if is_state_ty(&pat.ty) => {
                            let PatKind::Binding { local, .. } = &pat.kind else { return Err("a state bound by a pattern".into()) };
                            self.state_expr(init, i, out)?;
                            *self.state.borrow_mut() = Some((*local, name.clone()));
                        }
                        StmtKind::Expr(x) | StmtKind::Let { init: x, .. } if is_state_ty(&x.ty) => {
                            let _ = x;
                            return Err("a state statement that is not a `let`".into());
                        }
                        _ => {
                            if let Some(t) = self.stmt(st, i)? {
                                out.push(format!("{}{t}", ind(i)));
                            }
                        }
                    }
                }
                match &b.tail {
                    Some(t) => self.state_expr(t, i, out),
                    None => Err("a state block without a value".into()),
                }
            }
            ExprKind::If { cond, then, els: Some(els) } => {
                out.push(format!("{}if {} {{", ind(i), self.expr(cond, i, Pos::Top)?));
                self.state_expr(then, i + 1, out)?;
                *self.state.borrow_mut() = Some((cur, name.clone()));
                out.push(format!("{}}} else {{", ind(i)));
                self.state_expr(els, i + 1, out)?;
                out.push(format!("{}}}", ind(i)));
                // after the `if`, the state is its value: a fresh current
                // state no local names (an `if` is only a tail or a `let`
                // initializer, whose binding becomes current)
                *self.state.borrow_mut() = Some((LocalId(u32::MAX), name));
                Ok(())
            }
            ExprKind::Match { scrut, arms, .. } if !is_state_ty(&scrut.ty) => {
                out.push(format!("{}match {} {{", ind(i), self.expr(scrut, i, Pos::Top)?));
                for a in arms {
                    if a.guard.is_some() {
                        return Err("a guarded arm in state mode".into());
                    }
                    *self.state.borrow_mut() = Some((cur, name.clone()));
                    out.push(format!("{}{} => {{", ind(i + 1), self.pat(&a.pat)?));
                    self.state_expr(&a.body, i + 2, out)?;
                    out.push(format!("{}}}", ind(i + 1)));
                }
                out.push(format!("{}}}", ind(i)));
                *self.state.borrow_mut() = Some((LocalId(u32::MAX), name));
                Ok(())
            }
            _ => Err("a buffer state operation the lowering does not print".into()),
        }
    }

    fn call(&self, callee: &Callee, args: &[Expr], i: usize) -> R<String> {
        match callee {
            Callee::Item(id, tys) => {
                if !tys.is_empty() {
                    return Err(format!("a generic call of `{}`", self.pv.item(*id).path));
                }
                let n = self.names.fns.get(id).ok_or_else(|| format!("a call of `{}`, which the lowered code cannot name", self.pv.item(*id).path))?;
                Ok(format!("{n}({})", self.args(args, i)?))
            }
            Callee::Builtin(b, _) => self.builtin(b, args, i),
            Callee::Intrinsic(..) => Err("a target intrinsic".into()),
            Callee::Helper(_) => Err("a load/store helper".into()),
            Callee::Ghost(..) => Err("a ghost function".into()),
        }
    }

    fn method(&self, recv: &Expr, name: &str, rest: &[Expr], i: usize) -> R<String> {
        Ok(format!("{}.{name}({})", self.expr(recv, i, Pos::Operand)?, self.args(rest, i)?))
    }

    fn builtin(&self, b: &Builtin, args: &[Expr], i: usize) -> R<String> {
        let need = |n: usize| if args.len() == n { Ok(()) } else { Err(format!("a builtin call with {} argument(s)", args.len())) };
        match *b {
            Builtin::Int(m, w) if m.is_assoc() => {
                need(1)?;
                Ok(format!("{}::{}({})", w.name(), m.name(), self.expr(&args[0], i, Pos::Top)?))
            }
            Builtin::Int(m, _) => {
                let (recv, rest) = args.split_first().ok_or("a method without a receiver")?;
                self.method(recv, m.name(), rest, i)
            }
            Builtin::Slice(m) => {
                let (recv, rest) = args.split_first().ok_or("a method without a receiver")?;
                use crate::builtins::SliceMethod::*;
                let name = match m {
                    SplitFirstChunk(n) | SplitLastChunk(n) | FirstChunk(n) | AsChunks(n) => format!("{}::<{n}>", m.name()),
                    _ => m.name().to_string(),
                };
                self.method(recv, &name, rest, i)
            }
            Builtin::Array(ArrayMethod::AsSlice(_)) => {
                need(1)?;
                self.method(&args[0], "as_slice", &[], i)
            }
            Builtin::Option(m) => {
                let (recv, rest) = args.split_first().ok_or("a method without a receiver")?;
                let name = match m {
                    OptionMethod::IsSome => "is_some",
                    OptionMethod::IsNone => "is_none",
                    OptionMethod::UnwrapOr => "unwrap_or",
                };
                self.method(recv, name, rest, i)
            }
            Builtin::Bin(op, _) | Builtin::Shift { op, .. } => {
                need(2)?;
                Ok(format!("{} {} {}", self.expr(&args[0], i, Pos::Operand)?, op.symbol(), self.expr(&args[1], i, Pos::Operand)?))
            }
            Builtin::StructEq { ne } => {
                need(2)?;
                Ok(format!("{} {} {}", self.expr(&args[0], i, Pos::Operand)?, if ne { "!=" } else { "==" }, self.expr(&args[1], i, Pos::Operand)?))
            }
            Builtin::Not(_) => {
                need(1)?;
                Ok(format!("!{}", self.expr(&args[0], i, Pos::Operand)?))
            }
            Builtin::Cast { to: crate::builtins::CastDst::Uint(u), .. } => {
                need(1)?;
                Ok(format!("{} as {}", self.expr(&args[0], i, Pos::Operand)?, u.name()))
            }
            Builtin::Index { .. } => {
                need(2)?;
                Ok(format!("{}[{}]", self.expr(&args[0], i, Pos::Operand)?, self.expr(&args[1], i, Pos::Top)?))
            }
            _ => Err("a ghost or statement builtin".into()),
        }
    }
}
