//! Mutation operators on the typed HIR (DESIGN.md §15.9 item 1).
//!
//! A mutation site is a node of a function body (or of a constant's
//! initializer) in a fixed pre-order ([`walk_mut`]) plus an [`Op`]; the
//! same walk finds the node again to apply the operator to a copy of the
//! body, so a site is just its node index. Only behaviour is mutated:
//! `proof!` blocks, loop invariants and `decreases` measures are skipped
//! (they are proof annotations, not code).
//!
//! Every operator keeps the HIR well typed:
//!
//! | operator | sites | replacements |
//! | --- | --- | --- |
//! | arithmetic | `+ - * / %`, `op=` | `+`↔`-`, `*`→`+ /`, `/`→`* %`, `%`→`/` |
//! | bitwise | `& \| ^ << >>` | `&`→`\| ^`, `\|`→`& ^`, `^`→`\| &`, `<<`↔`>>` |
//! | comparison | `< <= > >= == !=` | `<`→`<= >`, `<=`→`< >=`, …, `==`↔`!=` |
//! | boolean | `&&`, `\|\|`, propositional `&&`/`\|\|`/`==`/`!=` | `&&`↔`\|\|`, each operand alone (check deletion) |
//! | method | `wrapping_add`, `rotate_left`, `min`, `to_be_bytes`, … | the dual method |
//! | constant | integer and `bool` literals | `n+1`, `n-1`, `0`, a middle-bit flip; `!b` |
//! | negation | `if` conditions, `!e` | `!(c)`; `e` |
//! | guard deletion | `if` conditions | `true`, `false` (a check that never / always fires) |
//! | return value | the whole body | each default of the result type (`false`, `true`, `0`, `None`, …): the `λ_. false` mutant |
//! | loop bound | `for i in lo..hi` | `hi ± 1`, `lo + 1`, `..` ↔ `..=` |
//! | index | `a[i]` | `a[i ± 1]` |
//! | argument swap | calls with two arguments of one type; `a - b`, `a / b`, `a % b` | swapped |

use crate::builtins::{Builtin, IntMethod};
use crate::hir::*;
use crate::span::Span;

/// A mutation operator applied at one node.
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    /// `a op b` → `a to b`.
    BinOp { from: BinOp, to: BinOp },
    /// `place op= v` → `place to= v`.
    Compound { from: BinOp, to: BinOp },
    /// Propositional connectives: `&&`↔`||` (`and: true` means the node is
    /// a `&&`), `==`↔`!=`.
    PropAndOr { and: bool },
    PropEqNe { eq: bool },
    /// `a && b` / `a || b` → one operand (check deletion).
    Operand { left: bool },
    /// `a op b` → `b op a` (non-commutative operators).
    SwapOperands,
    /// An integer literal.
    Lit { from: u128, to: u128 },
    /// A `bool` literal → its negation.
    Bool { to: bool },
    /// `if c` → `if !(c)`.
    Negate,
    /// `if c` → `if true` / `if false`.
    CondConst(bool),
    /// `!e` → `e`.
    DropNot,
    /// The whole body → a constant of the result type (index into
    /// [`defaults`]).
    Return(usize),
    /// `for _ in lo..hi`: `hi + 1` / `hi - 1` / `lo + 1`.
    LoopHi(i8),
    LoopLo,
    /// `..` ↔ `..=`.
    LoopInclusive,
    /// `a[i]` → `a[i ± 1]`.
    Index(i8),
    /// Swap arguments `i` and `j` of a call.
    ArgSwap(usize, usize),
    /// An integer method → its dual.
    Method { from: IntMethod, to: IntMethod },
}

impl Op {
    /// The operator family (for the report).
    pub fn family(&self) -> &'static str {
        match self {
            Op::BinOp { from, .. } | Op::Compound { from, .. } => match from {
                BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Rem => "arithmetic",
                BinOp::BitAnd | BinOp::BitOr | BinOp::BitXor | BinOp::Shl | BinOp::Shr => "bitwise",
                BinOp::And | BinOp::Or => "boolean",
                _ => "comparison",
            },
            Op::PropAndOr { .. } | Op::PropEqNe { .. } | Op::Operand { .. } => "boolean",
            Op::SwapOperands | Op::ArgSwap(..) => "argument-swap",
            Op::Lit { .. } | Op::Bool { .. } => "constant",
            Op::Negate | Op::DropNot => "negation",
            Op::CondConst(_) => "guard-deletion",
            Op::Return(_) => "return-value",
            Op::LoopHi(_) | Op::LoopLo | Op::LoopInclusive => "loop-bound",
            Op::Index(_) => "index",
            Op::Method { .. } => "method",
        }
    }
}

/// One mutation site.
#[derive(Clone, Debug)]
pub struct Site {
    /// Pre-order node index ([`walk_mut`]); `usize::MAX` for the whole body.
    pub node: usize,
    pub op: Op,
    /// The mutated node's span.
    pub span: Span,
    /// What the mutation does, in words (`` `+` → `-` ``).
    pub desc: String,
}

/// A node of the walk.
pub enum Node<'a> {
    Expr(&'a mut Expr),
    Stmt(&'a mut Stmt),
}

/// What the walk does after visiting a node.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// Do not visit the node's children.
    Skip,
    /// Stop the whole walk.
    Stop,
}

/// Pre-order walk over the behaviour of an expression (see the module
/// docs): every expression and statement gets the next index. Returns
/// `true` when stopped.
pub fn walk_mut(e: &mut Expr, n: &mut usize, f: &mut dyn FnMut(usize, Node<'_>) -> Flow) -> bool {
    let idx = *n;
    *n += 1;
    match f(idx, Node::Expr(e)) {
        Flow::Stop => return true,
        Flow::Skip => return false,
        Flow::Continue => {}
    }
    macro_rules! go {
        ($x:expr) => {
            if walk_mut($x, n, f) {
                return true;
            }
        };
    }
    match &mut e.kind {
        ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => {}
        ExprKind::Call { args, .. } => {
            for a in args {
                go!(a);
            }
        }
        ExprKind::Adt { fields, base, .. } => {
            for (_, x) in fields {
                go!(x);
            }
            if let Some(b) = base {
                go!(b);
            }
        }
        ExprKind::Tuple(es) | ExprKind::Array(es) => {
            for x in es {
                go!(x);
            }
        }
        ExprKind::Repeat { elem, .. } => go!(elem),
        ExprKind::Field { base, .. } => go!(base),
        ExprKind::Index { base, index } => {
            go!(base);
            go!(index);
        }
        ExprKind::SliceRange { base, lo, hi } => {
            go!(base);
            if let Some(l) = lo {
                go!(l);
            }
            if let Some(h) = hi {
                go!(h);
            }
        }
        ExprKind::Unary(_, x) | ExprKind::Cast(x, _) | ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(_, x) | ExprKind::Try(x) | ExprKind::PropNot(x) => go!(x),
        ExprKind::Binary(_, a, b) | ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) | ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Implies(a, b) | ExprKind::Iff(a, b) => {
            go!(a);
            go!(b);
        }
        ExprKind::If { cond, then, els } => {
            go!(cond);
            go!(then);
            if let Some(x) = els {
                go!(x);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            go!(scrut);
            for a in arms {
                if let Some(g) = &mut a.guard {
                    go!(g);
                }
                go!(&mut a.body);
            }
        }
        ExprKind::Block(b) => {
            if walk_block(b, n, f) {
                return true;
            }
        }
        ExprKind::Return(x) => {
            if let Some(x) = x {
                go!(x);
            }
        }
        ExprKind::Loop(l) => {
            match &mut l.kind {
                LoopKind::ForRange { lo, hi, .. } => {
                    go!(lo);
                    go!(hi);
                }
                LoopKind::While { cond } => go!(cond),
            }
            if walk_block(&mut l.body, n, f) {
                return true;
            }
        }
        ExprKind::Quant { body, .. } | ExprKind::Lambda { body, .. } => go!(body),
        ExprKind::Apply { fun, args } => {
            go!(fun);
            for a in args {
                go!(a);
            }
        }
    }
    false
}

fn walk_block(b: &mut Block, n: &mut usize, f: &mut dyn FnMut(usize, Node<'_>) -> Flow) -> bool {
    for s in &mut b.stmts {
        let idx = *n;
        *n += 1;
        match f(idx, Node::Stmt(s)) {
            Flow::Stop => return true,
            Flow::Skip => continue,
            Flow::Continue => {}
        }
        match &mut s.kind {
            StmtKind::Let { init, els, .. } => {
                if walk_mut(init, n, f) {
                    return true;
                }
                if let Some(b) = els
                    && walk_block(b, n, f)
                {
                    return true;
                }
            }
            StmtKind::Expr(e) => {
                if walk_mut(e, n, f) {
                    return true;
                }
            }
            StmtKind::Assign { place, value } | StmtKind::CompoundAssign { place, value, .. } => {
                if walk_mut(value, n, f) {
                    return true;
                }
                for p in &mut place.projs {
                    if let Proj::Index(x) = p
                        && walk_mut(x, n, f)
                    {
                        return true;
                    }
                }
            }
            StmtKind::CopyFromSlice { range, src, .. } => {
                if let Some((a, b)) = range {
                    if let Some(a) = a
                        && walk_mut(a, n, f)
                    {
                        return true;
                    }
                    if let Some(b) = b
                        && walk_mut(b, n, f)
                    {
                        return true;
                    }
                }
                if walk_mut(src, n, f) {
                    return true;
                }
            }
            StmtKind::Proof(_) => {}
        }
    }
    if let Some(t) = &mut b.tail
        && walk_mut(t, n, f)
    {
        return true;
    }
    false
}

fn is_int(t: &Ty) -> bool {
    matches!(t.peel_refs(), Ty::Uint(_) | Ty::Int | Ty::Nat)
}

/// Replacements of a binary operator at operand type `t` (`ghost`: `Int`
/// and `Nat` operands allowed).
fn binop_replacements(op: BinOp, t: &Ty) -> Vec<BinOp> {
    use BinOp::*;
    let int = is_int(t);
    let uint = matches!(t.peel_refs(), Ty::Uint(_));
    let boolean = matches!(t.peel_refs(), Ty::Bool);
    match op {
        Add if int => vec![Sub],
        Sub if int => vec![Add],
        Mul if int => vec![Add, Div],
        Div if int => vec![Mul, Rem],
        Rem if int => vec![Div],
        BitAnd if uint || boolean => vec![BitOr, BitXor],
        BitOr if uint || boolean => vec![BitAnd, BitXor],
        BitXor if uint || boolean => vec![BitOr, BitAnd],
        Shl if uint => vec![Shr],
        Shr if uint => vec![Shl],
        Lt if int => vec![Le, Gt],
        Le if int => vec![Lt, Ge],
        Gt if int => vec![Ge, Lt],
        Ge if int => vec![Gt, Le],
        Eq => vec![Ne],
        Ne => vec![Eq],
        And => vec![Or],
        Or => vec![And],
        _ => vec![],
    }
}

/// The dual of an integer method (same signature).
fn method_dual(m: IntMethod) -> Option<IntMethod> {
    use IntMethod::*;
    Some(match m {
        WrappingAdd => WrappingSub,
        WrappingSub => WrappingAdd,
        WrappingShl => WrappingShr,
        WrappingShr => WrappingShl,
        CheckedAdd => CheckedSub,
        CheckedSub => CheckedAdd,
        SaturatingAdd => SaturatingSub,
        SaturatingSub => SaturatingAdd,
        RotateLeft => RotateRight,
        RotateRight => RotateLeft,
        Min => Max,
        Max => Min,
        ToBeBytes => ToLeBytes,
        ToLeBytes => ToBeBytes,
        FromBeBytes => FromLeBytes,
        FromLeBytes => FromBeBytes,
        LeadingZeros => TrailingZeros,
        TrailingZeros => LeadingZeros,
        _ => return None,
    })
}

/// Perturbations of an integer literal of type `t`.
fn lit_replacements(n: u128, t: &Ty) -> Vec<u128> {
    let (max, bits) = match t.peel_refs() {
        Ty::Uint(u) => (u.max_value(), u.bits()),
        Ty::Int | Ty::Nat => (u128::MAX >> 1, 0),
        _ => return vec![],
    };
    let mut v = Vec::new();
    let mut push = |x: u128| {
        if x != n && x <= max && !v.contains(&x) {
            v.push(x);
        }
    };
    if n < max {
        push(n + 1);
    }
    if n > 0 {
        push(n - 1);
        push(0);
    }
    if bits >= 8 {
        push(n ^ (1u128 << (bits / 2)));
    }
    v
}

/// The constants a function body may be replaced by (the return-value
/// operator): each a closed HIR expression of type `t`.
pub fn defaults(t: &Ty, span: Span) -> Vec<(Expr, String)> {
    let e = |k: ExprKind, ty: Ty| Expr::new(k, ty, span);
    match t {
        Ty::Bool => vec![(e(ExprKind::Lit(Lit::Bool(false)), Ty::Bool), "false".into()), (e(ExprKind::Lit(Lit::Bool(true)), Ty::Bool), "true".into())],
        Ty::Uint(u) => vec![(e(ExprKind::Lit(Lit::Int(0)), t.clone()), format!("0{}", u.name()))],
        Ty::Int | Ty::Nat => vec![(e(ExprKind::Lit(Lit::Int(0)), t.clone()), "0".into())],
        Ty::Option(inner) => vec![(e(ExprKind::Adt { ctor: Ctor::None, ty_args: vec![(**inner).clone()], fields: vec![], base: None }, t.clone()), "None".into())],
        Ty::Prop => ["false", "true"]
            .iter()
            .map(|s| {
                let b = e(ExprKind::Lit(Lit::Bool(*s == "true")), Ty::Bool);
                (e(ExprKind::Coerce(Coercion::BoolToProp, Box::new(b)), Ty::Prop), s.to_string())
            })
            .collect(),
        Ty::Tuple(ts) if !ts.is_empty() => {
            let parts: Option<Vec<(Expr, String)>> = ts.iter().map(|x| defaults(x, span).into_iter().next()).collect();
            match parts {
                Some(ps) => {
                    let text = format!("({})", ps.iter().map(|p| p.1.clone()).collect::<Vec<_>>().join(", "));
                    vec![(e(ExprKind::Tuple(ps.into_iter().map(|p| p.0).collect()), t.clone()), text)]
                }
                None => vec![],
            }
        }
        Ty::Array(el, n) => match defaults(el, span).into_iter().next() {
            Some((d, text)) => vec![(e(ExprKind::Repeat { elem: Box::new(d), count: *n }, t.clone()), format!("[{text}; {n}]"))],
            None => vec![],
        },
        _ => vec![],
    }
}

/// Whether `e` is (a block around) exactly the constant `d`.
fn same_constant(e: &Expr, d: &Expr) -> bool {
    match (&e.kind, &d.kind) {
        (ExprKind::Block(b), _) if b.stmts.is_empty() => b.tail.as_ref().is_some_and(|t| same_constant(t, d)),
        (ExprKind::Lit(a), ExprKind::Lit(b)) => a == b,
        (ExprKind::Adt { ctor: Ctor::None, .. }, ExprKind::Adt { ctor: Ctor::None, .. }) => true,
        (ExprKind::Coerce(Coercion::BoolToProp, a), ExprKind::Coerce(Coercion::BoolToProp, b)) => same_constant(a, b),
        _ => false,
    }
}

fn plus(k: i8) -> &'static str {
    if k > 0 { "+ 1" } else { "- 1" }
}

/// The mutation sites of a body (the root operators first, then the nodes
/// in pre-order). `ret` is the function's result type (`None` for a
/// constant's initializer: no return-value operator).
pub fn sites(body: &Expr, ret: Option<&Ty>) -> Vec<Site> {
    let mut out = Vec::new();
    if let Some(t) = ret {
        for (k, (d, text)) in defaults(t, body.span).into_iter().enumerate() {
            if !same_constant(body, &d) {
                out.push(Site { node: usize::MAX, op: Op::Return(k), span: body.span, desc: format!("the whole body returns `{text}` (return-value replacement)") });
            }
        }
    }
    let mut copy = body.clone();
    let mut n = 0usize;
    walk_mut(&mut copy, &mut n, &mut |idx, node| {
        match node {
            Node::Expr(e) => node_sites(idx, e, &mut out),
            Node::Stmt(s) => {
                if let StmtKind::CompoundAssign { op, place, .. } = &s.kind {
                    for to in binop_replacements(*op, &place.ty) {
                        if matches!(to, BinOp::And | BinOp::Or) {
                            continue;
                        }
                        out.push(Site { node: idx, op: Op::Compound { from: *op, to }, span: s.span, desc: format!("`{}=` → `{}=`", op.symbol(), to.symbol()) });
                    }
                }
            }
        }
        Flow::Continue
    });
    out
}

fn node_sites(idx: usize, e: &Expr, out: &mut Vec<Site>) {
    let mut push = |op: Op, span: Span, desc: String| out.push(Site { node: idx, op, span, desc });
    match &e.kind {
        ExprKind::Binary(op, a, b) => {
            for to in binop_replacements(*op, &a.ty) {
                // shifts keep independent operand widths; the others need
                // equal operand types (already so in the HIR)
                push(Op::BinOp { from: *op, to }, e.span, format!("`{}` → `{}`", op.symbol(), to.symbol()));
            }
            if matches!(op, BinOp::And | BinOp::Or) {
                push(Op::Operand { left: true }, e.span, format!("`a {} b` → `a` (check deletion)", op.symbol()));
                push(Op::Operand { left: false }, e.span, format!("`a {} b` → `b` (check deletion)", op.symbol()));
            }
            if matches!(op, BinOp::Sub | BinOp::Div | BinOp::Rem) && a.ty == b.ty {
                push(Op::SwapOperands, e.span, format!("`a {0} b` → `b {0} a`", op.symbol()));
            }
        }
        ExprKind::PropAnd(..) => push(Op::PropAndOr { and: true }, e.span, "propositional `&&` → `||`".into()),
        ExprKind::PropOr(..) => push(Op::PropAndOr { and: false }, e.span, "propositional `||` → `&&`".into()),
        ExprKind::PropEq(..) => push(Op::PropEqNe { eq: true }, e.span, "`==` → `!=`".into()),
        ExprKind::PropNe(..) => push(Op::PropEqNe { eq: false }, e.span, "`!=` → `==`".into()),
        ExprKind::Unary(UnOp::Not, x) if x.ty == Ty::Bool => push(Op::DropNot, e.span, "`!e` → `e`".into()),
        ExprKind::Lit(Lit::Int(n)) => {
            for to in lit_replacements(*n, &e.ty) {
                push(Op::Lit { from: *n, to }, e.span, format!("constant `{n}` → `{to}`"));
            }
        }
        ExprKind::Lit(Lit::Bool(b)) => push(Op::Bool { to: !b }, e.span, format!("`{b}` → `{}`", !b)),
        ExprKind::If { cond, .. } => {
            push(Op::Negate, cond.span, "negate the `if` condition".into());
            push(Op::CondConst(false), cond.span, "the `if` condition → `false` (guard deletion: the branch never runs)".into());
            push(Op::CondConst(true), cond.span, "the `if` condition → `true` (guard deletion: the branch always runs)".into());
        }
        ExprKind::Index { index, .. } if is_int(&index.ty) => {
            push(Op::Index(1), index.span, "index `i` → `i + 1`".into());
            push(Op::Index(-1), index.span, "index `i` → `i - 1`".into());
        }
        ExprKind::Loop(l) => {
            if let LoopKind::ForRange { lo, hi, inclusive, .. } = &l.kind {
                push(Op::LoopHi(1), hi.span, "loop bound `hi` → `hi + 1`".into());
                push(Op::LoopHi(-1), hi.span, "loop bound `hi` → `hi - 1`".into());
                push(Op::LoopLo, lo.span, "loop start `lo` → `lo + 1`".into());
                push(Op::LoopInclusive, l.span, if *inclusive { "`..=` → `..`".into() } else { "`..` → `..=`".into() });
            }
        }
        ExprKind::Call { callee, args } => {
            if let Callee::Builtin(Builtin::Int(m, _), _) = callee
                && let Some(to) = method_dual(*m)
            {
                push(Op::Method { from: *m, to }, e.span, format!("`{}` → `{}`", m.name(), to.name()));
            }
            if matches!(callee, Callee::Item(..) | Callee::Builtin(Builtin::Int(..), _)) {
                let mut pairs = 0;
                for i in 0..args.len() {
                    for j in i + 1..args.len() {
                        if pairs < 3 && args[i].ty == args[j].ty {
                            pairs += 1;
                            push(Op::ArgSwap(i, j), e.span, format!("swap arguments {} and {}", i + 1, j + 1));
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn one(t: &Ty, span: Span) -> Expr {
    Expr::new(ExprKind::Lit(Lit::Int(1)), t.clone(), span)
}

fn shifted(x: Expr, k: i8) -> Expr {
    let t = x.ty.clone();
    let span = x.span;
    let op = if k > 0 { BinOp::Add } else { BinOp::Sub };
    let o = one(&t, span);
    Expr::new(ExprKind::Binary(op, Box::new(x), Box::new(o)), t, span)
}

/// Applies `op` at node `node` of `body` (a copy). `ret` as for [`sites`].
/// Returns `false` when the site was not found (a bug).
pub fn apply(body: &mut Expr, site: &Site, ret: Option<&Ty>) -> bool {
    if site.node == usize::MAX {
        let Op::Return(k) = site.op else { return false };
        let Some(t) = ret else { return false };
        let Some((d, _)) = defaults(t, body.span).into_iter().nth(k) else { return false };
        let span = body.span;
        *body = Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(d)), span }), t.clone(), span);
        return true;
    }
    let mut done = false;
    let mut n = 0usize;
    walk_mut(body, &mut n, &mut |idx, node| {
        if idx != site.node {
            return Flow::Continue;
        }
        done = apply_at(node, &site.op);
        Flow::Stop
    });
    done
}

fn apply_at(node: Node<'_>, op: &Op) -> bool {
    match node {
        Node::Stmt(s) => match (&mut s.kind, op) {
            (StmtKind::CompoundAssign { op: o, .. }, Op::Compound { from, to }) if o == from => {
                *o = *to;
                true
            }
            _ => false,
        },
        Node::Expr(e) => {
            let span = e.span;
            match op {
                Op::BinOp { from, to } => match &mut e.kind {
                    ExprKind::Binary(o, _, _) if o == from => {
                        *o = *to;
                        true
                    }
                    _ => false,
                },
                Op::PropAndOr { and } => {
                    let k = std::mem::replace(&mut e.kind, ExprKind::Unreachable);
                    let (ok, k) = match (k, and) {
                        (ExprKind::PropAnd(a, b), true) => (true, ExprKind::PropOr(a, b)),
                        (ExprKind::PropOr(a, b), false) => (true, ExprKind::PropAnd(a, b)),
                        (k, _) => (false, k),
                    };
                    e.kind = k;
                    ok
                }
                Op::PropEqNe { eq } => {
                    let k = std::mem::replace(&mut e.kind, ExprKind::Unreachable);
                    let (ok, k) = match (k, eq) {
                        (ExprKind::PropEq(a, b), true) => (true, ExprKind::PropNe(a, b)),
                        (ExprKind::PropNe(a, b), false) => (true, ExprKind::PropEq(a, b)),
                        (k, _) => (false, k),
                    };
                    e.kind = k;
                    ok
                }
                Op::Operand { left } => match std::mem::replace(&mut e.kind, ExprKind::Unreachable) {
                    ExprKind::Binary(BinOp::And | BinOp::Or, a, b) => {
                        *e = if *left { *a } else { *b };
                        true
                    }
                    k => {
                        e.kind = k;
                        false
                    }
                },
                Op::SwapOperands => match &mut e.kind {
                    ExprKind::Binary(_, a, b) => {
                        std::mem::swap(a, b);
                        true
                    }
                    _ => false,
                },
                Op::Lit { from, to } => match &mut e.kind {
                    ExprKind::Lit(Lit::Int(n)) if n == from => {
                        *n = *to;
                        true
                    }
                    _ => false,
                },
                Op::Bool { to } => match &mut e.kind {
                    ExprKind::Lit(Lit::Bool(b)) => {
                        *b = *to;
                        true
                    }
                    _ => false,
                },
                Op::Negate => match &mut e.kind {
                    ExprKind::If { cond, .. } => {
                        let c = std::mem::replace(&mut **cond, Expr::new(ExprKind::Unreachable, Ty::Bool, span));
                        let cs = c.span;
                        **cond = Expr::new(ExprKind::Unary(UnOp::Not, Box::new(c)), Ty::Bool, cs);
                        true
                    }
                    _ => false,
                },
                Op::CondConst(b) => match &mut e.kind {
                    ExprKind::If { cond, .. } => {
                        let cs = cond.span;
                        **cond = Expr::new(ExprKind::Lit(Lit::Bool(*b)), Ty::Bool, cs);
                        true
                    }
                    _ => false,
                },
                Op::DropNot => match std::mem::replace(&mut e.kind, ExprKind::Unreachable) {
                    ExprKind::Unary(UnOp::Not, x) => {
                        *e = *x;
                        true
                    }
                    k => {
                        e.kind = k;
                        false
                    }
                },
                Op::Index(k) => match &mut e.kind {
                    ExprKind::Index { index, .. } => {
                        let i = std::mem::replace(&mut **index, Expr::new(ExprKind::Unreachable, Ty::usize(), span));
                        **index = shifted(i, *k);
                        true
                    }
                    _ => false,
                },
                Op::LoopHi(_) | Op::LoopLo => {
                    let ExprKind::Loop(l) = &mut e.kind else { return false };
                    let LoopKind::ForRange { lo, hi, .. } = &mut l.kind else { return false };
                    let (slot, k) = if let Op::LoopHi(k) = op { (hi, *k) } else { (lo, 1) };
                    let x = std::mem::replace(slot, Expr::new(ExprKind::Unreachable, Ty::usize(), span));
                    *slot = shifted(x, k);
                    true
                }
                Op::LoopInclusive => match &mut e.kind {
                    ExprKind::Loop(l) => match &mut l.kind {
                        LoopKind::ForRange { inclusive, .. } => {
                            *inclusive = !*inclusive;
                            true
                        }
                        _ => false,
                    },
                    _ => false,
                },
                Op::ArgSwap(i, j) => match &mut e.kind {
                    ExprKind::Call { args, .. } if *j < args.len() => {
                        args.swap(*i, *j);
                        true
                    }
                    _ => false,
                },
                Op::Method { from, to } => match &mut e.kind {
                    ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, _), _), .. } if m == from => {
                        *m = *to;
                        true
                    }
                    _ => false,
                },
                _ => false,
            }
        }
    }
}


// ---------------------------------------------------------------------------
// Source diffs
// ---------------------------------------------------------------------------
//
// A mutant is printed back as an edit of the original text. An edit that
// changes an operator's binding power (`^` → `|`, `&&` → `||`, `a - b` →
// `b - a`, an operand replacing its operator node) is parenthesized where
// Rust would otherwise parse the printed line differently from the mutant
// the engine evaluated: the new node when its parent binds tighter, and its
// operands when they bind looser than the new operator. The typechecker
// lowers `( e )` to `e` with `e`'s own span, so the parentheses of the
// source sit between an operator and its operands' spans and are kept.

/// Rust's binding power of a binary operator (higher binds tighter; all
/// left-associative, comparisons non-associative).
pub fn prec(op: BinOp) -> u8 {
    use BinOp::*;
    match op {
        Mul | Div | Rem => 10,
        Add | Sub => 9,
        Shl | Shr => 8,
        BitAnd => 7,
        BitXor => 6,
        BitOr => 5,
        Eq | Ne | Lt | Le | Gt | Ge => 4,
        And => 3,
        Or => 2,
    }
}

const PREC_CMP: u8 = 4;
const PREC_AND: u8 = 3;
const PREC_OR: u8 = 2;
const PREC_CAST: u8 = 11;
const PREC_PREFIX: u8 = 12;
/// Postfix positions (method receivers, field and index bases) and atoms.
const PREC_ATOM: u8 = 20;

/// The implicit adjustments the typechecker wraps around a node, with the
/// node's own span.
fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(_, x) if x.span == e.span || e.span.is_dummy() => peel(x),
        _ => e,
    }
}

/// The binding power of an expression as written (atoms: [`PREC_ATOM`]).
pub fn expr_prec(e: &Expr) -> u8 {
    let e = peel(e);
    match &e.kind {
        ExprKind::Binary(op, ..) => prec(*op),
        ExprKind::PropEq(..) | ExprKind::PropNe(..) => PREC_CMP,
        ExprKind::PropAnd(..) => PREC_AND,
        ExprKind::PropOr(..) => PREC_OR,
        ExprKind::Cast(..) => PREC_CAST,
        ExprKind::Unary(..) | ExprKind::PropNot(..) | ExprKind::Deref(..) | ExprKind::Ref(..) => PREC_PREFIX,
        _ => PREC_ATOM,
    }
}

/// The binding power of the operator `target` is an operand of in `body`,
/// and whether it is the right operand: `None` when `target` is not an
/// operand (a body, argument, condition, `let` initializer: delimited).
pub fn parent_prec(body: &Expr, target: Span) -> Option<(u8, bool)> {
    struct F {
        target: Span,
        found: Option<(u8, bool)>,
    }
    impl F {
        fn hit(&self, x: &Expr) -> bool {
            x.span == self.target || peel(x).span == self.target
        }
    }
    impl crate::visit::Visitor for F {
        fn expr(&mut self, e: &Expr) {
            if self.found.is_some() {
                return;
            }
            let pair = |p: u8, a: &Expr, b: &Expr, me: &F| if me.hit(a) { Some((p, false)) } else if me.hit(b) { Some((p, true)) } else { None };
            let r = match &e.kind {
                ExprKind::Binary(op, a, b) => pair(prec(*op), a, b, self),
                ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) => pair(PREC_CMP, a, b, self),
                ExprKind::PropAnd(a, b) => pair(PREC_AND, a, b, self),
                ExprKind::PropOr(a, b) => pair(PREC_OR, a, b, self),
                ExprKind::Unary(_, x) | ExprKind::PropNot(x) | ExprKind::Deref(x) | ExprKind::Ref(x) if self.hit(x) && x.span != e.span => Some((PREC_PREFIX, true)),
                ExprKind::Cast(x, _) if self.hit(x) && x.span != e.span => Some((PREC_CAST, false)),
                ExprKind::Field { base, .. } | ExprKind::Index { base, .. } if self.hit(base) && base.span != e.span => Some((PREC_ATOM, false)),
                // a method call's receiver (`(a | b).rotate_left(3)`; the
                // arguments of `u32::f(x)` are delimited)
                ExprKind::Call { callee: Callee::Builtin(..), args } if args.first().is_some_and(|a| self.hit(a) && a.span.lo == e.span.lo && a.span != e.span) => Some((PREC_ATOM, false)),
                _ => None,
            };
            if r.is_some() {
                self.found = r;
                return;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut f = F { target, found: None };
    crate::visit::Visitor::expr(&mut f, body);
    f.found
}

/// Whether the source has `(` right before `span` and `)` right after it
/// (on the same lines): the node is already delimited.
fn delimited(span: Span, snip: &dyn Fn(Span) -> Option<String>) -> bool {
    if span.is_dummy() || span.lo.1 == 0 {
        return false;
    }
    let before = snip(Span { file: span.file, lo: (span.lo.0, 0), hi: span.lo });
    // the rest of the line (a column past its end means its end)
    let after = snip(Span { file: span.file, lo: span.hi, hi: (span.hi.0, u32::MAX) });
    matches!((before, after), (Some(b), Some(a)) if b.trim_end().ends_with('(') && a.trim_start().starts_with(')'))
}

fn paren(t: String, yes: bool) -> String {
    if yes { format!("({t})") } else { t }
}

/// The new source text of a site: `(span, replacement)` edits of the
/// original file (applied right to left), or `None` when the source is not
/// available (dummy spans).
pub fn source_edits(body: &Expr, site: &Site, sm: &crate::span::SourceMap, ret: Option<&Ty>) -> Option<Vec<(Span, String)>> {
    let snip = |sp: Span| sm.snippet(sp);
    if site.node == usize::MAX {
        let Op::Return(k) = site.op else { return None };
        let (_, text) = defaults(ret?, body.span).into_iter().nth(k)?;
        return Some(vec![(body.span, format!("{{ {text} }}"))]);
    }
    let mut copy = body.clone();
    let mut n = 0usize;
    let mut edits: Option<Vec<(Span, String)>> = None;
    walk_mut(&mut copy, &mut n, &mut |idx, node| {
        if idx != site.node {
            return Flow::Continue;
        }
        edits = edits_at(body, node, &site.op, &snip);
        Flow::Stop
    });
    edits
}

/// Replaces the first occurrence of `from` by `to` in the source between
/// two spans (the operator token between two operands).
fn gap_edit(a: Span, b: Span, from: &str, to: &str, snip: &dyn Fn(Span) -> Option<String>) -> Option<(Span, String)> {
    if a.is_dummy() || b.is_dummy() || a.file != b.file || a.hi > b.lo {
        return None;
    }
    let gap = Span { file: a.file, lo: a.hi, hi: b.lo };
    let text = snip(gap)?;
    let i = text.find(from)?;
    Some((gap, format!("{}{}{}", &text[..i], to, &text[i + from.len()..])))
}

/// `a op b` with a new operator of binding power `p` (`to` replacing `from`
/// between the operands): the gap edit when the printed text parses as the
/// mutant, otherwise the whole node rebuilt with parentheses (see the
/// section docs).
#[allow(clippy::too_many_arguments)]
fn binop_edit(body: &Expr, e: &Expr, a: &Expr, b: &Expr, from: &str, to: &str, p: u8, snip: &dyn Fn(Span) -> Option<String>) -> Option<Vec<(Span, String)>> {
    let (gap_sp, gap) = gap_edit(a.span, b.span, from, to, snip)?;
    let gap_text = gap.clone();
    // source parentheses around an operand sit in the gap (`(a ^ b) | c`)
    let a_paren = gap_text.trim_start().starts_with(')');
    let b_paren = gap_text.trim_end().ends_with('(');
    let wrap_a = !a_paren && expr_prec(a) < p;
    let wrap_b = !b_paren && expr_prec(b) <= p;
    let wrap_e = match parent_prec(body, e.span) {
        Some((pp, right)) => (pp > p || pp == p && (right || p == PREC_CMP)) && !delimited(e.span, snip),
        None => false,
    };
    if !wrap_a && !wrap_b && !wrap_e {
        return Some(vec![(gap_sp, gap)]);
    }
    let file = e.span.file;
    let pre = snip(Span { file, lo: e.span.lo, hi: a.span.lo })?;
    let post = snip(Span { file, lo: b.span.hi, hi: e.span.hi })?;
    let text = format!("{pre}{}{gap}{}{post}", paren(snip(a.span)?, wrap_a), paren(snip(b.span)?, wrap_b));
    Some(vec![(e.span, paren(text, wrap_e))])
}

/// A node replaced by the text of `x` (an operand of it): parenthesized
/// when the node's parent binds tighter than `x`.
fn operand_edit(body: &Expr, e: &Expr, x: &Expr, snip: &dyn Fn(Span) -> Option<String>) -> Option<Vec<(Span, String)>> {
    let px = expr_prec(x);
    let wrap = match parent_prec(body, e.span) {
        Some((pp, right)) => (pp > px || pp == px && (right || px == PREC_CMP)) && !delimited(e.span, snip),
        None => false,
    };
    Some(vec![(e.span, paren(snip(x.span)?, wrap))])
}

/// A literal printed like the original (radix prefix and type suffix).
pub fn relit(orig: &str, v: u128) -> String {
    let t = orig.trim();
    let (prefix, rest, radix) = if let Some(r) = t.strip_prefix("0x") {
        ("0x", r, 16)
    } else if let Some(r) = t.strip_prefix("0b") {
        ("0b", r, 2)
    } else if let Some(r) = t.strip_prefix("0o") {
        ("0o", r, 8)
    } else {
        ("", t, 10)
    };
    // the digits (with `_` separators), then the type suffix (`u8`, `usize`)
    let end = rest.find(|c: char| c != '_' && !c.is_digit(radix)).unwrap_or(rest.len());
    let suffix = &rest[end..];
    let body = match radix {
        16 => format!("{v:x}"),
        2 => format!("{v:b}"),
        8 => format!("{v:o}"),
        _ => v.to_string(),
    };
    format!("{prefix}{body}{suffix}")
}

fn edits_at(body: &Expr, node: Node<'_>, op: &Op, snip: &dyn Fn(Span) -> Option<String>) -> Option<Vec<(Span, String)>> {
    match node {
        Node::Stmt(s) => {
            let StmtKind::CompoundAssign { place, value, .. } = &s.kind else { return None };
            let Op::Compound { from, to } = op else { return None };
            Some(vec![gap_edit(place.span, value.span, &format!("{}=", from.symbol()), &format!("{}=", to.symbol()), snip)?])
        }
        Node::Expr(e) => {
            let whole = |t: String| Some(vec![(e.span, t)]);
            match (op, &e.kind) {
                (Op::BinOp { from, to }, ExprKind::Binary(_, a, b)) => match binop_edit(body, e, a, b, from.symbol(), to.symbol(), prec(*to), snip) {
                    Some(x) => Some(x),
                    None => whole(format!("({}) {} ({})", snip(a.span)?, to.symbol(), snip(b.span)?)),
                },
                (Op::PropAndOr { and }, ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b)) => {
                    let (f, t, p) = if *and { ("&&", "||", PREC_OR) } else { ("||", "&&", PREC_AND) };
                    binop_edit(body, e, a, b, f, t, p, snip)
                }
                (Op::PropEqNe { eq }, ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b)) => {
                    let (f, t) = if *eq { ("==", "!=") } else { ("!=", "==") };
                    Some(vec![gap_edit(a.span, b.span, f, t, snip)?])
                }
                (Op::Operand { left }, ExprKind::Binary(_, a, b)) => operand_edit(body, e, if *left { a } else { b }, snip),
                (Op::SwapOperands, ExprKind::Binary(o, a, b)) => {
                    // `a op b` → `b op a`: the new left operand may bind
                    // looser than `op`, the new right one no tighter
                    let p = prec(*o);
                    whole(format!("{} {} {}", paren(snip(b.span)?, expr_prec(b) < p), o.symbol(), paren(snip(a.span)?, expr_prec(a) <= p)))
                }
                (Op::Lit { to, .. }, ExprKind::Lit(_)) => whole(relit(&snip(e.span)?, *to)),
                (Op::Bool { to }, ExprKind::Lit(_)) => whole(to.to_string()),
                (Op::Negate, ExprKind::If { cond, .. }) => Some(vec![(cond.span, format!("!({})", snip(cond.span)?))]),
                (Op::CondConst(b), ExprKind::If { cond, .. }) => Some(vec![(cond.span, b.to_string())]),
                (Op::DropNot, ExprKind::Unary(_, x)) => operand_edit(body, e, x, snip),
                (Op::Index(k), ExprKind::Index { index, .. }) => Some(vec![(index.span, format!("{} {}", paren(snip(index.span)?, expr_prec(index) < prec(BinOp::Add)), plus(*k)))]),
                (Op::LoopHi(k), ExprKind::Loop(l)) => match &l.kind {
                    LoopKind::ForRange { hi, .. } => Some(vec![(hi.span, format!("({}) {}", snip(hi.span)?, plus(*k)))]),
                    _ => None,
                },
                (Op::LoopLo, ExprKind::Loop(l)) => match &l.kind {
                    LoopKind::ForRange { lo, .. } => Some(vec![(lo.span, format!("({}) + 1", snip(lo.span)?))]),
                    _ => None,
                },
                (Op::LoopInclusive, ExprKind::Loop(l)) => match &l.kind {
                    LoopKind::ForRange { lo, hi, inclusive, .. } => {
                        let (f, t) = if *inclusive { ("..=", "..") } else { ("..", "..=") };
                        Some(vec![gap_edit(lo.span, hi.span, f, t, snip)?])
                    }
                    _ => None,
                },
                (Op::ArgSwap(i, j), ExprKind::Call { args, .. }) => {
                    let (a, b) = (args.get(*i)?, args.get(*j)?);
                    let (ta, tb) = (snip(a.span)?, snip(b.span)?);
                    Some(vec![(a.span, tb), (b.span, ta)])
                }
                (Op::Method { from, to }, ExprKind::Call { .. }) => {
                    let text = snip(e.span)?;
                    let i = text.find(from.name())?;
                    whole(format!("{}{}{}", &text[..i], to.name(), &text[i + from.name().len()..]))
                }
                _ => None,
            }
        }
    }
}
