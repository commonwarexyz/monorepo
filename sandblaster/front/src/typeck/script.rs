//! Ghost code: propositions (DESIGN.md §4.1) and proof scripts (§4.3, §4.4).
//!
//! * [`Cx::prop`] types an expression in a **proposition position**:
//!   `a == b` / `a != b` are propositional (dis)equality (their operands are
//!   ordinary expressions), `p && q` is the dependent conjunction, `p || q`,
//!   `!p` are ∨ and ¬, `implies`, `iff`, `forall(|x: T| p)`,
//!   `exists(|x: T| p)` are connectives, and a `bool` expression `b` means
//!   `b == true` ([`Coercion::BoolToProp`]). Conditionals, matches and
//!   blocks propagate the proposition position to their branches.
//! * Script statements are parsed from `#[lemma]`/`#[law]`/`#[proof]` bodies
//!   and from `proof! { .. }` token streams. The script keywords (`assert`,
//!   `witness`, `unfold`, `rewrite`, `rewrite_rev`, `exact`, `bv`, `show`,
//!   `todo`, `cases`, `requires`, `ensures`, `invariant`, `decreases`) are
//!   reserved in statement position. `cases(k in a..b) { .. }` is not Rust
//!   syntax, so it is accepted inside `proof! { .. }` (token-level parse) and,
//!   everywhere, as `cases(k, a..b, { .. })`.
//! * A lemma/law applied as a statement (`lemma(args);`, `let h =
//!   lemma(args);`) becomes [`ScriptKind::Apply`]; its binder has type
//!   [`Ty::Proof`].
//! * `rewrite` motives must annotate their binder: `rewrite(h, |x: T| p)`.
//! * Engineer-facing statements (docs/PROOF-GUIDE.md), lowered here:
//!   - **Closing statements** say why the remaining goal holds; each must be
//!     the last statement of its block ([`CLOSING`]):
//!     `follows();` ([`ScriptKind::Follows`]: the automation's general
//!     reasoning), `by_computation();` ([`ScriptKind::Compute`]),
//!     `by_arithmetic();` ([`ScriptKind::Arithmetic`]), `by_unfolding(f,
//!     ..);` ([`ScriptKind::Unfolding`]; the names resolve like `unfold`'s)
//!     and `by_contradiction();` ([`ScriptKind::Contradiction`]). An
//!     **empty** proof body, case arm or branch (or a missing `else`) is
//!     accepted with a warning that suggests `follows();`; a block that ends
//!     after other statements is checked by the elaborator (it warns unless
//!     the goal is closed by conversion or by a fact in scope). The former
//!     `by_auto();` and `follows_from_facts();` are errors that say what to
//!     write instead.
//!   - `by_cases(x);` / `by_cases(a, b, ..);` split on every constructor of
//!     a `bool` (an `if`), an `Option` or an enum (a `match` with wildcard
//!     fields); `by_cases(k, lo..hi);` (and `by_cases(k in lo..hi);` inside
//!     `proof! { .. }`) enumerates an integer ([`ScriptKind::Cases`], like
//!     `cases`). The statements **after** a `by_cases` run in every case,
//!     then the prover closes each case.
//!   - `#[induction(x)]` on a lemma/proof is checked here: every recursive
//!     application (`ih(args)` or the lemma's own name) passes a
//!     structurally smaller `x` (a rest binding of a `match` on the slice
//!     `x`, or `x - k` with a literal `k >= 1`). `ih(args)` is the recursive
//!     application ([`ScriptKind::Apply`]); outside an `#[induction]` proof it
//!     is an error.
//!   - `apply(lemma);` / `let h = apply(lemma);` is [`ScriptKind::Apply`]
//!     with `infer` (arguments inferred by the elaborator).
//!   - `calc! { e0 == e1 by { steps }; == e2; .. }` is [`ScriptKind::Calc`]:
//!     each link's proposition is typed from the written terms (the macro
//!     body is parsed here, [`CalcSyn`]).

use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;

use super::expr::{is_macro, strip_parens, Cx, Exp, VRes};
use super::parse_decreases_args;
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::resolve::GhostKw;
use crate::span::Span;

/// A syntactic script step.
pub enum SynStep {
    Stmt(syn::Stmt),
    /// `cases(k in a..b) { steps }` (token form).
    Cases { var: syn::Ident, range: syn::Expr, body: Vec<SynStep>, span: proc_macro2::Span },
    /// `by_cases(k in a..b);` (token form).
    ByCases { var: syn::Ident, range: syn::Expr, span: proc_macro2::Span },
}

/// `kw(ident in ..)` at the head of `input` (the token forms of `cases` and
/// `by_cases`).
fn peek_in_form(input: ParseStream, kw: &str) -> bool {
    fn go(fork: ParseStream, kw: &str) -> syn::Result<bool> {
        let id: syn::Ident = fork.parse()?;
        if id != kw || !fork.peek(syn::token::Paren) {
            return Ok(false);
        }
        let content;
        syn::parenthesized!(content in fork);
        Ok(content.peek(syn::Ident) && content.peek2(syn::Token![in]))
    }
    go(&input.fork(), kw).unwrap_or(false)
}

/// A sequence of script steps parsed from tokens.
pub struct Steps(pub Vec<SynStep>);

impl Parse for Steps {
    fn parse(input: ParseStream) -> syn::Result<Steps> {
        let mut v = Vec::new();
        while !input.is_empty() {
            if input.peek(syn::Token![;]) {
                input.parse::<syn::Token![;]>()?;
                continue;
            }
            if peek_in_form(input, "by_cases") {
                let kw: syn::Ident = input.parse()?;
                let content;
                syn::parenthesized!(content in input);
                let var: syn::Ident = content.parse()?;
                content.parse::<syn::Token![in]>()?;
                let range: syn::Expr = content.parse()?;
                v.push(SynStep::ByCases { var, range, span: kw.span() });
                continue;
            }
            if peek_in_form(input, "cases") {
                let kw: syn::Ident = input.parse()?;
                let content;
                syn::parenthesized!(content in input);
                let var: syn::Ident = content.parse()?;
                content.parse::<syn::Token![in]>()?;
                let range: syn::Expr = content.parse()?;
                let body_content;
                syn::braced!(body_content in input);
                let body: Steps = body_content.parse()?;
                v.push(SynStep::Cases { var, range, body: body.0, span: kw.span() });
                continue;
            }
            let s: syn::Stmt = input.parse()?;
            v.push(SynStep::Stmt(s));
        }
        Ok(Steps(v))
    }
}

const KEYWORDS: &[&str] = &[
    "assert",
    "witness",
    "use_hyp",
    "unfold",
    "rewrite",
    "rewrite_rev",
    "exact",
    "bv",
    "show",
    "todo",
    "cases",
    "requires",
    "ensures",
    "invariant",
    "decreases",
    "follows",
    "by_computation",
    "by_lockstep",
    "by_arithmetic",
    "by_unfolding",
    "by_contradiction",
    "by_cases",
    "ih",
    "apply",
    "by_induction",
    "using",
    // the attempted induction hypotheses and lemma instances `by_induction(..)` generates
    "__try_ih",
    "__try",
    // removed (errors that say what to write instead)
    "by_auto",
    "follows_from_facts",
];

/// Statements that close the goal and say why it holds: nothing may follow
/// them in a block.
pub const CLOSING: &[&str] = &["follows", "by_computation", "by_lockstep", "by_arithmetic", "by_unfolding", "by_contradiction", "by_induction"];

/// How a closing statement is written in messages.
fn closing_call(kw: &str) -> String {
    if kw == "by_unfolding" || kw == "by_induction" { format!("{kw}(..)") } else { format!("{kw}()") }
}

/// The note of the empty-block warnings (and of the elaborator's warning at
/// a block end without a closing statement): which closing statement says
/// what.
pub const CLOSERS_NOTE: &str = "say why the goal holds: `by_computation()` (evaluation alone), `by_arithmetic()` (arithmetic on the facts in scope), `by_unfolding(f, ..)` (arithmetic after unfolding the named definitions), `by_contradiction()` (the facts in scope are contradictory), or `follows()` (the automation's general reasoning) — docs/PROOF-GUIDE.md";

/// The note of the `by_auto()` error: the closing statements, and which one
/// does what `by_auto()` did.
pub const BY_AUTO_NOTE: &str = "say why the goal holds: `by_computation()` (evaluation alone), `by_arithmetic()` (arithmetic on the facts in scope), `by_unfolding(f, ..)` (arithmetic after unfolding the named definitions), `by_contradiction()` (the facts in scope are contradictory), or `follows()` (the automation's general reasoning: what `by_auto()` did) — docs/PROOF-GUIDE.md";

/// `calc! { e0 R e1 by { steps }; R e2; .. }` (the body of the macro, parsed
/// by the front end: ghost code is never compiled by rustc).
pub struct CalcSyn {
    pub first: syn::Expr,
    pub links: Vec<CalcSynLink>,
}

pub struct CalcSynLink {
    pub rel: CalcRel,
    pub rhs: syn::Expr,
    pub by: Option<Vec<SynStep>>,
    pub span: proc_macro2::Span,
}

fn calc_by(input: ParseStream) -> syn::Result<Option<Vec<SynStep>>> {
    let fork = input.fork();
    if matches!(fork.parse::<syn::Ident>(), Ok(id) if id == "by") {
        input.parse::<syn::Ident>()?;
        let content;
        syn::braced!(content in input);
        let steps: Steps = content.parse()?;
        return Ok(Some(steps.0));
    }
    Ok(None)
}

impl Parse for CalcSyn {
    fn parse(input: ParseStream) -> syn::Result<CalcSyn> {
        let e: syn::Expr = input.parse()?;
        let (first, rel, rhs, span) = match strip_parens(&e) {
            syn::Expr::Binary(b) => match b.op {
                syn::BinOp::Eq(t) => ((*b.left).clone(), CalcRel::Eq, (*b.right).clone(), t.spans[0]),
                syn::BinOp::Le(t) => ((*b.left).clone(), CalcRel::Le, (*b.right).clone(), t.spans[0]),
                syn::BinOp::Lt(t) => ((*b.left).clone(), CalcRel::Lt, (*b.right).clone(), t.span),
                _ => return Err(syn::Error::new(e.span(), "a `calc!` chain starts with `e0 == e1` (or `e0 <= e1`, `e0 < e1`)")),
            },
            _ => return Err(syn::Error::new(e.span(), "a `calc!` chain starts with `e0 == e1` (or `e0 <= e1`, `e0 < e1`)")),
        };
        let by = calc_by(input)?;
        let mut links = vec![CalcSynLink { rel, rhs, by, span }];
        loop {
            while input.peek(syn::Token![;]) {
                input.parse::<syn::Token![;]>()?;
            }
            if input.is_empty() {
                break;
            }
            let (rel, span) = if input.peek(syn::Token![==]) {
                let t: syn::Token![==] = input.parse()?;
                (CalcRel::Eq, t.spans[0])
            } else if input.peek(syn::Token![<=]) {
                let t: syn::Token![<=] = input.parse()?;
                (CalcRel::Le, t.spans[0])
            } else if input.peek(syn::Token![<]) {
                let t: syn::Token![<] = input.parse()?;
                (CalcRel::Lt, t.span)
            } else {
                return Err(input.error("expected the next link of the chain: `== e`, `<= e` or `< e` (links are separated by `;` or a `by { .. }` block)"));
            };
            let rhs: syn::Expr = input.parse()?;
            let by = calc_by(input)?;
            links.push(CalcSynLink { rel, rhs, by, span });
        }
        Ok(CalcSyn { first, links })
    }
}

/// The keyword of a statement that closes the goal (`by_arithmetic()`, ..).
fn closing_step(s: &SynStep) -> Option<String> {
    let SynStep::Stmt(syn::Stmt::Expr(e, _)) = s else { return None };
    let (kw, _) = keyword_call(e)?;
    CLOSING.contains(&kw.as_str()).then_some(kw)
}

/// `by_cases(..)` as a statement.
fn by_cases_call(s: &SynStep) -> Option<&syn::ExprCall> {
    let SynStep::Stmt(syn::Stmt::Expr(e, _)) = s else { return None };
    match keyword_call(e) {
        Some((kw, c)) if kw == "by_cases" => Some(c),
        _ => None,
    }
}

/// Whether a block is written empty (`{}`).
fn empty_block(e: &syn::Expr) -> bool {
    matches!(e, syn::Expr::Block(b) if b.block.stmts.is_empty())
}

/// The keyword a call statement starts with, if any.
fn keyword_call(e: &syn::Expr) -> Option<(String, &syn::ExprCall)> {
    if let syn::Expr::Call(c) = strip_parens(e)
        && let syn::Expr::Path(p) = strip_parens(&c.func)
            && p.qself.is_none() && p.path.segments.len() == 1 && matches!(p.path.segments[0].arguments, syn::PathArguments::None) {
                let n = p.path.segments[0].ident.to_string();
                if KEYWORDS.contains(&n.as_str()) {
                    return Some((n, c));
                }
            }
    None
}

impl<'c, 'a> Cx<'c, 'a> {
    /// Types a proposition (ghost context).
    pub fn prop(&mut self, e: &syn::Expr) -> Expr {
        let saved = self.ghost;
        self.ghost = true;
        let x = self.prop_expr(e);
        self.ghost = saved;
        x
    }

    /// Proposition-position typing (see module docs).
    pub fn prop_expr(&mut self, e: &syn::Expr) -> Expr {
        let span = self.sp(e.span());
        match e {
            syn::Expr::Paren(p) => self.prop_expr(&p.expr),
            syn::Expr::Group(g) => self.prop_expr(&g.expr),
            syn::Expr::Binary(b) => match b.op {
                syn::BinOp::Eq(_) | syn::BinOp::Ne(_) => {
                    let (l, r) = self.prop_operands(&b.left, &b.right);
                    if l.ty != r.ty && !l.ty.is_error() && !r.ty.is_error() && !l.ty.is_never() && !r.ty.is_never() {
                        let (x, y) = (self.tys(&l.ty), self.tys(&r.ty));
                        self.err(DiagKind::Type, span, format!("propositional equality between different types `{x}` and `{y}`"));
                    }
                    let k = if matches!(b.op, syn::BinOp::Eq(_)) { ExprKind::PropEq(Box::new(l), Box::new(r)) } else { ExprKind::PropNe(Box::new(l), Box::new(r)) };
                    Expr::new(k, Ty::Prop, span)
                }
                syn::BinOp::And(_) => {
                    let l = self.prop_expr(&b.left);
                    let r = self.prop_expr(&b.right);
                    Expr::new(ExprKind::PropAnd(Box::new(l), Box::new(r)), Ty::Prop, span)
                }
                syn::BinOp::Or(_) => {
                    let l = self.prop_expr(&b.left);
                    let r = self.prop_expr(&b.right);
                    Expr::new(ExprKind::PropOr(Box::new(l), Box::new(r)), Ty::Prop, span)
                }
                _ => self.value_as_prop(e),
            },
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => {
                let inner = self.prop_expr(&u.expr);
                Expr::new(ExprKind::PropNot(Box::new(inner)), Ty::Prop, span)
            }
            syn::Expr::If(_) | syn::Expr::Match(_) | syn::Expr::Block(_) => {
                let x = self.expr_prop_branches(e);
                match x.ty {
                    Ty::Bool => Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(x)), Ty::Prop, span),
                    _ => x,
                }
            }
            _ => self.value_as_prop(e),
        }
    }

    /// `if`/`match`/blocks whose branches are propositions.
    fn expr_prop_branches(&mut self, e: &syn::Expr) -> Expr {
        let span = self.sp(e.span());
        match e {
            syn::Expr::Block(b) => self.block_expr(&b.block, &Exp::Prop, span),
            syn::Expr::If(i) => {
                if matches!(strip_parens(&i.cond), syn::Expr::Let(_)) {
                    // `if let` in a proposition: typed like a match
                    let x = self.expr_inner_if_let(i, span);
                    return x;
                }
                let cond = self.check(&i.cond, &Ty::Bool);
                let then = self.block_expr(&i.then_branch, &Exp::Prop, span);
                let els = match &i.else_branch {
                    Some((_, e)) => self.prop_expr(e),
                    None => {
                        self.err(DiagKind::Type, span, "a proposition `if` needs an `else` branch");
                        Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Prop, span)
                    }
                };
                Expr::new(ExprKind::If { cond: Box::new(cond), then: Box::new(then), els: Some(Box::new(els)) }, Ty::Prop, span)
            }
            syn::Expr::Match(m) => {
                let scrut = self.infer(&m.expr);
                let mut arms = Vec::new();
                for a in &m.arms {
                    let aspan = self.sp(a.span());
                    self.push_scope();
                    let pat = self.refutable_pat(&a.pat, &scrut.ty);
                    let guard = a.guard.as_ref().map(|(_, g)| self.check(g, &Ty::Bool));
                    let body = self.prop_expr(&a.body);
                    self.pop_scope();
                    arms.push(Arm { pat, guard, body, span: aspan });
                }
                self.check_exhaustive(&scrut.ty, &arms.iter().filter(|a| a.guard.is_none()).map(|a| &a.pat).collect::<Vec<_>>(), span, "match");
                Expr::new(ExprKind::Match { scrut: Box::new(scrut), arms, source: MatchSource::Match }, Ty::Prop, span)
            }
            _ => self.value_as_prop(e),
        }
    }

    fn expr_inner_if_let(&mut self, i: &syn::ExprIf, span: Span) -> Expr {
        let syn::Expr::Let(l) = strip_parens(&i.cond) else { unreachable!() };
        let scrut = self.infer(&l.expr);
        self.push_scope();
        let pat = self.refutable_pat(&l.pat, &scrut.ty);
        let then = self.block_expr(&i.then_branch, &Exp::Prop, span);
        self.pop_scope();
        let els = match &i.else_branch {
            Some((_, e)) => self.prop_expr(e),
            None => {
                self.err(DiagKind::Type, span, "a proposition `if let` needs an `else` branch");
                Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Prop, span)
            }
        };
        let wild = Pat { kind: PatKind::Wild, ty: scrut.ty.clone(), span };
        let arms = vec![Arm { pat, guard: None, body: then, span }, Arm { pat: wild, guard: None, body: els, span }];
        Expr::new(ExprKind::Match { scrut: Box::new(scrut), arms, source: MatchSource::IfLet }, Ty::Prop, span)
    }

    /// Operands of a propositional (dis)equality: the second is checked
    /// against the type of the first (or vice versa).
    fn prop_operands(&mut self, l: &syn::Expr, r: &syn::Expr) -> (Expr, Expr) {
        use super::expr::branch_needs_exp;
        // the second operand is typed against the first's type; operands of
        // different types that view-coerce (`u64` vs `Nat`, `&[u8]` vs
        // `Seq<u8>`, DESIGN.md §15.3) are joined before the final coercion
        let joined = |cx: &mut Self, a: Expr, b: Expr, a_first: bool| -> (Expr, Expr) {
            let (x, y) = if a_first { (a, b) } else { (b, a) };
            let (x, y) = cx.numeric_join(x, y);
            let (x, y) = cx.view_join(x, y);
            let (a, b) = if a_first { (x, y) } else { (y, x) };
            let t = a.ty.clone();
            let b = if b.ty == t || t.is_error() || t.is_never() { b } else { cx.coerce(b, &t) };
            if a_first { (a, b) } else { (b, a) }
        };
        if !branch_needs_exp(l) {
            let l2 = self.infer(l);
            let t = l2.ty.clone();
            if t.is_error() || t.is_never() {
                return (l2, self.infer(r));
            }
            let r2 = self.expr(r, &Exp::Ty(t));
            joined(self, l2, r2, true)
        } else if !branch_needs_exp(r) {
            let r2 = self.infer(r);
            let t = r2.ty.clone();
            if t.is_error() || t.is_never() {
                return (self.infer(l), r2);
            }
            let l2 = self.expr(l, &Exp::Ty(t));
            let (r2, l2) = joined(self, r2, l2, true);
            (l2, r2)
        } else {
            (self.infer(l), self.infer(r))
        }
    }

    /// An ordinary expression used as a proposition.
    fn value_as_prop(&mut self, e: &syn::Expr) -> Expr {
        let span = self.sp(e.span());
        let x = self.expr(e, &Exp::Ty(Ty::Prop));
        match &x.ty {
            Ty::Prop | Ty::Error | Ty::Never => x,
            Ty::Bool => Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(x)), Ty::Prop, span),
            other => {
                let s = self.tys(other);
                self.err(DiagKind::Type, span, format!("expected a proposition, found `{s}`"));
                Expr { ty: Ty::Prop, ..x }
            }
        }
    }

    /// `forall`, `exists`, `implies`, `iff`.
    pub fn ghost_kw(&mut self, k: GhostKw, args: &[syn::Expr], span: Span) -> Expr {
        if !self.ghost {
            self.err(DiagKind::Ghost, span, "logical connectives are only allowed in ghost code");
        }
        let saved = self.ghost;
        self.ghost = true;
        let r = match k {
            GhostKw::Implies | GhostKw::Iff => {
                if args.len() != 2 {
                    self.err(DiagKind::Type, span, "expected two propositions");
                    self.ghost = saved;
                    return Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Prop, span);
                }
                let p = self.prop_expr(&args[0]);
                let q = self.prop_expr(&args[1]);
                let kind = if k == GhostKw::Implies { ExprKind::Implies(Box::new(p), Box::new(q)) } else { ExprKind::Iff(Box::new(p), Box::new(q)) };
                Expr::new(kind, Ty::Prop, span)
            }
            GhostKw::Forall | GhostKw::Exists => {
                let quant = if k == GhostKw::Forall { Quant::Forall } else { Quant::Exists };
                match args {
                    [syn::Expr::Closure(c)] => {
                        self.push_scope();
                        let mut binders = Vec::new();
                        for input in &c.inputs {
                            let ispan = self.sp(input.span());
                            match input {
                                syn::Pat::Type(pt) => {
                                    let g = self.g.clone();
                                    let t = self.ck.lower_ty(self.m, &pt.ty, &g, true);
                                    match &*pt.pat {
                                        syn::Pat::Ident(pi) if pi.subpat.is_none() && pi.by_ref.is_none() && pi.mutability.is_none() => {
                                            binders.push(self.new_local(&pi.ident.to_string(), t, false, true, ispan));
                                        }
                                        _ => self.err(DiagKind::Script, ispan, "quantifier binders must be plain names"),
                                    }
                                }
                                _ => self.err(DiagKind::Script, ispan, "annotate quantifier binders: `|x: T| ..`"),
                            }
                        }
                        let body = self.prop_expr(&c.body);
                        self.pop_scope();
                        Expr::new(ExprKind::Quant { quant, binders, body: Box::new(body) }, Ty::Prop, span)
                    }
                    _ => {
                        self.err(DiagKind::Script, span, "expected a closure: `forall(|x: T| p)`");
                        Expr::new(ExprKind::Lit(Lit::Bool(true)), Ty::Prop, span)
                    }
                }
            }
        };
        self.ghost = saved;
        r
    }

    // ------------------------------------------------------------------
    // scripts
    // ------------------------------------------------------------------

    /// Lowers the body of a lemma/law/proof: `requires(..); ensures(..);`
    /// header, then script steps.
    /// The contract and script of a lemma, law or proof body: its
    /// `requires`, its `ensures`, the script (starting with the header
    /// `let`s, replayed) and the number of those replayed header `let`s (a
    /// law whose script is only its header `let`s has no inline proof).
    pub fn fn_script(&mut self, block: &syn::Block, kind: FnKind) -> (Vec<Expr>, Option<Expr>, Vec<ScriptStmt>, usize) {
        let saved = self.ghost;
        self.ghost = true;
        let steps: Vec<SynStep> = block.stmts.iter().cloned().map(SynStep::Stmt).collect();
        let mut requires = Vec::new();
        let mut ensures: Option<Expr> = None;
        // `let x = e;` among the header statements (before a `requires` or
        // `ensures`): an abbreviation — each later contract statement is
        // `{ let x = e; p }`, and the script starts with the same `let`
        let contract = |st: &SynStep| matches!(st, SynStep::Stmt(syn::Stmt::Expr(e, _)) if keyword_call(e).is_some_and(|(kw, _)| kw == "requires" || kw == "ensures"));
        let mut header_lets: Vec<ScriptStmt> = Vec::new();
        let mut i = 0;
        while i < steps.len() {
            if let SynStep::Stmt(st @ syn::Stmt::Local(_)) = &steps[i] {
                let more = steps[i + 1..].iter().take_while(|s| contract(s) || matches!(s, SynStep::Stmt(syn::Stmt::Local(_)))).any(&contract);
                if !more {
                    break;
                }
                let n0 = header_lets.len();
                self.step(st, &mut header_lets);
                // only a value `let` abbreviates (not a lemma application)
                if header_lets[n0..].iter().any(|h| !matches!(h.kind, ScriptKind::Let { .. })) {
                    let span = self.sp(st.span());
                    self.err(DiagKind::Contract, span, "a `let` before `requires`/`ensures` abbreviates a value; apply lemmas in the proof");
                    header_lets.truncate(n0);
                }
                i += 1;
                continue;
            }
            let SynStep::Stmt(syn::Stmt::Expr(e, _)) = &steps[i] else { break };
            let Some((kw, c)) = keyword_call(e) else { break };
            let span = self.sp(c.span());
            match kw.as_str() {
                "requires" | "ensures" => {
                    if kind == FnKind::Proof {
                        self.push(Diagnostic::error(DiagKind::Law, span, "a `#[proof]` takes its contract from its law; remove `requires`/`ensures`"));
                    }
                    if c.args.len() != 1 {
                        self.err(DiagKind::Contract, span, format!("`{kw}` takes one proposition"));
                    } else if kw == "requires" {
                        let p = self.prop(&c.args[0]);
                        requires.push(abbreviated(&header_lets, p));
                    } else {
                        if ensures.is_some() {
                            self.err(DiagKind::Contract, span, "at most one `ensures`");
                        }
                        let p = self.prop(&c.args[0]);
                        ensures = Some(abbreviated(&header_lets, p));
                    }
                    i += 1;
                }
                _ => break,
            }
        }
        // an empty proof: the automation closes the goal by itself (a law
        // without steps is a claim, proven by its `#[proof]` item)
        if i == steps.len() && matches!(kind, FnKind::Lemma | FnKind::Proof) && !self.prelude_lemma() {
            let bspan = self.sp(block.span());
            self.push(Diagnostic::warning(DiagKind::Script, bspan, format!("empty `#[{}]` body: the automation must close the goal by itself", kind.name())).note("write `follows();` to say so, or a closing statement that says why the goal holds").note(CLOSERS_NOTE));
        }
        let n_header = header_lets.len();
        let mut out = header_lets;
        out.extend(self.steps(&steps[i..]));
        if matches!(kind, FnKind::Lemma | FnKind::Proof | FnKind::Law) {
            self.check_induction(&out);
        }
        self.ghost = saved;
        (requires, ensures, out, n_header)
    }

    /// Whether the current item is a synthesized prelude lemma
    /// (`sandblaster::lemmas::..`, declared without a proof).
    pub(super) fn prelude_lemma(&self) -> bool {
        self.item.is_some_and(|id| {
            let it = &self.ck.res.items[id.0 as usize];
            crate::resolve::prelude_lemma_kernel_name(&it.path).is_some()
        })
    }

    /// The syntactic attributes of the current item.
    fn item_attrs(&self) -> Vec<syn::Attribute> {
        let Some(id) = self.item else { return vec![] };
        match &self.ck.res.items[id.0 as usize].src {
            crate::resolve::ItemSrc::Fn(f) => f.attrs.clone(),
            crate::resolve::ItemSrc::ImplFn { f, .. } => f.attrs.clone(),
            _ => vec![],
        }
    }

    /// The parameter names of the current item, in order.
    fn item_param_names(&self) -> Vec<String> {
        let Some(id) = self.item else { return vec![] };
        let inputs: Vec<syn::FnArg> = match &self.ck.res.items[id.0 as usize].src {
            crate::resolve::ItemSrc::Fn(f) => f.sig.inputs.iter().cloned().collect(),
            crate::resolve::ItemSrc::ImplFn { f, .. } => f.sig.inputs.iter().cloned().collect(),
            _ => vec![],
        };
        inputs
            .iter()
            .map(|a| match a {
                syn::FnArg::Typed(pt) => match &*pt.pat {
                    syn::Pat::Ident(pi) => pi.ident.to_string(),
                    _ => "_".into(),
                },
                syn::FnArg::Receiver(_) => "self".into(),
            })
            .collect()
    }

    /// `#[induction(x)]` of the current item: the variable and the
    /// attribute's span.
    fn induction_attr(&mut self) -> Option<(String, Span)> {
        let attrs = self.item_attrs();
        let a = attrs.iter().find(|a| matches!(super::annotation_of(a.path()), Some((crate::resolve::Annot::Induction, _))))?;
        let span = self.sp(a.span());
        match a.parse_args::<syn::Ident>() {
            Ok(id) => Some((id.to_string(), span)),
            Err(_) => {
                self.err(DiagKind::Attribute, span, "expected `#[induction(x)]` naming a parameter");
                None
            }
        }
    }

    /// Checks `#[induction(x)]`: the proof applies its induction hypothesis
    /// (`ih(..)` or a recursive application) and every application passes a
    /// structurally smaller `x`.
    fn check_induction(&mut self, steps: &[ScriptStmt]) {
        let Some((x, aspan)) = self.induction_attr() else { return };
        let Some(me) = self.item else { return };
        let names = self.item_param_names();
        let Some(pos) = names.iter().position(|n| *n == x) else {
            self.err(DiagKind::Attribute, aspan, format!("`#[induction({x})]`: `{x}` is not a parameter"));
            return;
        };
        let Some(xl) = self.lookup_local(&x) else { return };
        let xty = self.local_ty(xl);
        // `#[decreases(e)]`, or a `Nat`/`Int` `x` (whose own value is the
        // measure)
        let measured = self.ck.sigs.get(&me).is_some_and(|s| s.contracts.decreases.is_some()) || matches!(xty, Ty::Nat | Ty::Int);
        let mut apps: Vec<(&[Expr], Span)> = Vec::new();
        recursive_apps(steps, me, &mut apps);
        if apps.is_empty() {
            self.push(Diagnostic::error(DiagKind::Script, aspan, format!("`#[induction({x})]`, but the proof never applies its induction hypothesis")).note("apply it with `ih(args);` on a smaller `x`, or remove the attribute"));
            return;
        }
        if measured {
            // `#[decreases(e)]`: the measure is checked by the elaborator
            return;
        }
        let mut rest_of = std::collections::HashMap::new();
        rest_bindings(steps, &mut rest_of);
        // the recursive fields of a recursive spec type (SEMANTICS.md §13.9)
        let rec_ty = matches!(xty.peel_refs(), Ty::Adt(id, _) if self.ck.is_recursive_adt(*id));
        let fields_of = if rec_ty { crate::elab::recursive::script_field_bindings(steps, &|t| matches!(t.peel_refs(), Ty::Adt(id, _) if self.ck.is_recursive_adt(*id))) } else { Default::default() };
        for (args, sp) in apps {
            let Some(a) = args.get(pos) else { continue };
            let field = rec_ty && matches!(&peel_expr(a).kind, ExprKind::Local(t) if fields_of.get(&xl).is_some_and(|s| s.contains(t)));
            if !field && !structurally_smaller(a, xl, &xty, &rest_of) {
                let d = Diagnostic::error(DiagKind::Script, a.span, format!("the induction hypothesis must be applied to a structurally smaller `{x}`"))
                    .note_at(sp, "induction hypothesis applied here")
                    .note(match xty.peel_refs() {
                        Ty::Slice(_) | Ty::Array(..) | Ty::Seq(_) => format!("pass the rest of a `match {x} {{ [head, tail @ ..] => .. }}` (e.g. `tail`)"),
                        Ty::Uint(_) => format!("pass `{x} - k` for a literal `k >= 1`"),
                        _ if rec_ty => format!("pass a field of `{x}` bound by a pattern (e.g. `l` in `match {x} {{ Tree::Cat(l, r) => .. }}`)"),
                        _ => format!("structural induction needs a slice, an unsigned integer or a recursive spec type `{x}`; or add `#[decreases(e)]`"),
                    });
                self.push(d);
            }
        }
    }

    /// Lowers a `proof! { .. }` block; with `head`, leading `invariant(..);`
    /// and `decreases(..);` statements go to the loop.
    pub fn proof_block(&mut self, mac: &syn::Macro, head: Option<&mut LoopInfo>, span: Span) -> Vec<ScriptStmt> {
        if !self.ghost && !self.ck.res.mods[self.m.0 as usize].ghost && !mac.path.segments.first().is_some_and(|s| s.ident == "sandblaster") && !self.ck.res.annotation_in_scope(self.m, "proof") {
            self.push(Diagnostic::error(DiagKind::Resolve, span, "macro `proof!` is not in scope").note("add `use sandblaster::prelude::*;`"));
        }
        let steps: Steps = match mac.parse_body() {
            Ok(s) => s,
            Err(e) => {
                let es = self.sp(e.span());
                self.err(DiagKind::Parse, es, format!("cannot parse proof script: {e}"));
                return vec![];
            }
        };
        let saved = self.ghost;
        self.ghost = true;
        let mut i = 0;
        if let Some(h) = head {
            while i < steps.0.len() {
                let SynStep::Stmt(syn::Stmt::Expr(e, _)) = &steps.0[i] else { break };
                let Some((kw, c)) = keyword_call(e) else { break };
                let cspan = self.sp(c.span());
                match kw.as_str() {
                    "invariant" => {
                        if c.args.len() != 1 {
                            self.err(DiagKind::Script, cspan, "`invariant` takes one proposition");
                        } else {
                            h.invariants.push(self.prop(&c.args[0]));
                        }
                    }
                    "decreases" => {
                        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                        match parse_decreases_args(&args) {
                            Ok((e, None)) => {
                                if h.decreases.is_some() {
                                    self.err(DiagKind::Script, cspan, "at most one `decreases` per loop");
                                }
                                h.decreases = Some(self.measure(&e));
                            }
                            Ok((_, Some(_))) => self.err(DiagKind::Script, cspan, "`max` is not allowed on loop measures"),
                            Err(m) => self.err(DiagKind::Script, cspan, m),
                        }
                    }
                    _ => break,
                }
                i += 1;
            }
        }
        let out = self.steps(&steps.0[i..]);
        self.ghost = saved;
        out
    }

    fn steps(&mut self, steps: &[SynStep]) -> Vec<ScriptStmt> {
        let mut out = Vec::new();
        for (i, s) in steps.iter().enumerate() {
            match s {
                SynStep::Cases { var, range, body, span } => {
                    let span = self.sp(*span);
                    if let Some(c) = self.cases(var, range, CasesBody::Steps(body), span) {
                        out.push(c);
                    }
                }
                // `by_cases(..)`: the rest of the block runs in every case
                SynStep::ByCases { var, range, span } => {
                    let span = self.sp(*span);
                    let rest = self.steps(&steps[i + 1..]);
                    if let Some(c) = self.cases(var, range, CasesBody::Lowered(rest), span) {
                        out.push(c);
                    }
                    return out;
                }
                SynStep::Stmt(st) => {
                    if let Some(c) = by_cases_call(s) {
                        let span = self.sp(st.span());
                        let rest = self.steps(&steps[i + 1..]);
                        self.by_cases(c, rest, span, &mut out);
                        return out;
                    }
                    if let Some(kw) = closing_step(s)
                        && i + 1 < steps.len()
                    {
                        let next = match &steps[i + 1] {
                            SynStep::Stmt(n) => self.sp(n.span()),
                            SynStep::Cases { span, .. } | SynStep::ByCases { span, .. } => self.sp(*span),
                        };
                        let call = closing_call(&kw);
                        self.push(Diagnostic::error(DiagKind::Script, next, format!("unreachable proof step: `{call}` already closes the goal")).note(format!("`{call}` must be the last statement of its block")));
                    }
                    let n = out.len();
                    self.step(st, &mut out);
                    // a `calc!` followed by statements is a fact for them
                    if out.len() > n
                        && i + 1 < steps.len()
                        && let Some(ScriptStmt { kind: ScriptKind::Calc { goal, .. }, .. }) = out.last_mut()
                    {
                        *goal = false;
                    }
                }
            }
        }
        out
    }

    fn block_steps(&mut self, b: &syn::Block) -> Vec<ScriptStmt> {
        self.push_scope();
        let steps: Vec<SynStep> = b.stmts.iter().cloned().map(SynStep::Stmt).collect();
        let r = self.steps(&steps);
        self.pop_scope();
        r
    }

    fn step(&mut self, st: &syn::Stmt, out: &mut Vec<ScriptStmt>) {
        let span = self.sp(st.span());
        match st {
            syn::Stmt::Local(l) => {
                let (pat, ann) = match &l.pat {
                    syn::Pat::Type(pt) => (&*pt.pat, Some(&*pt.ty)),
                    p => (p, None),
                };
                let Some(init) = &l.init else {
                    self.err(DiagKind::Script, span, "ghost `let` needs an initializer");
                    return;
                };
                if init.diverge.is_some() {
                    self.err(DiagKind::Script, span, "`let .. else` is not a script statement");
                }
                // `let h = apply(lemma);` / `let h = ih(args);`
                let special = match keyword_call(&init.expr) {
                    Some((kw, c)) if kw == "apply" || kw == "ih" => Some((kw, c.clone())),
                    _ => None,
                };
                let app = match special {
                    Some((kw, c)) => {
                        let cspan = self.sp(c.span());
                        let r = if kw == "apply" { self.apply_app(&c, cspan) } else { self.ih_app(&c, cspan) };
                        match r {
                            Some(r) => Some(r),
                            None => return,
                        }
                    }
                    None => self.try_lemma_app(&init.expr).map(|a| (a, false)),
                };
                if let Some((app, infer)) = app {
                    let name = match pat {
                        syn::Pat::Ident(pi) => pi.ident.to_string(),
                        _ => {
                            self.err(DiagKind::Script, span, "bind a lemma application to a plain name");
                            "_h".into()
                        }
                    };
                    let pspan = self.sp(pat.span());
                    let l = self.new_local(&name, Ty::Proof, false, true, pspan);
                    out.push(ScriptStmt { kind: ScriptKind::Apply { binder: Some(l), app, infer, optional: false }, span });
                    return;
                }
                let value = match ann {
                    Some(t) => {
                        let g = self.g.clone();
                        let ty = self.ck.lower_ty(self.m, t, &g, true);
                        self.check(&init.expr, &ty)
                    }
                    None => self.infer(&init.expr),
                };
                let ty = value.ty.clone();
                let pat = self.irrefutable_pat(pat, &ty, "ghost `let`");
                out.push(ScriptStmt { kind: ScriptKind::Let { pat, value }, span });
            }
            syn::Stmt::Item(_) => self.err(DiagKind::Script, span, "items are not script statements"),
            syn::Stmt::Macro(m) => {
                if is_macro(&m.mac.path, "proof") {
                    match m.mac.parse_body::<Steps>() {
                        Ok(s) => out.extend(self.steps(&s.0)),
                        Err(e) => self.err(DiagKind::Parse, span, format!("cannot parse proof script: {e}")),
                    }
                } else if is_macro(&m.mac.path, "calc") {
                    if let Some(c) = self.calc(&m.mac, span) {
                        out.push(c);
                    }
                } else {
                    self.err(DiagKind::Script, span, "macros are not script statements");
                }
            }
            syn::Stmt::Expr(e, _) => self.expr_step(e, span, out),
        }
    }

    fn expr_step(&mut self, e: &syn::Expr, span: Span, out: &mut Vec<ScriptStmt>) {
        if let Some((kw, c)) = keyword_call(e) {
            let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
            let kind = match kw.as_str() {
                "assert" => match args.as_slice() {
                    [p] => ScriptKind::Assert { prop: self.prop(p), steps: None },
                    [p, syn::Expr::Block(b)] => {
                        let prop = self.prop(p);
                        ScriptKind::Assert { prop, steps: Some(self.block_steps(&b.block)) }
                    }
                    _ => {
                        self.err(DiagKind::Script, span, "expected `assert(p);` or `assert(p, { steps });`");
                        return;
                    }
                },
                "witness" => ScriptKind::Witness(args.iter().map(|a| self.infer(a)).collect()),
                "use_hyp" => {
                    let index = match args.first().map(strip_parens) {
                        Some(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(l), .. })) if l.suffix().is_empty() => l.base10_parse::<u32>().ok(),
                        _ => None,
                    };
                    let Some(index) = index else {
                        self.err(DiagKind::Script, span, "expected `use_hyp(i, e1, .., en);`: `i` is the index of a hypothesis of the completeness statement (a literal)");
                        return;
                    };
                    ScriptKind::UseHyp { index, args: args[1..].iter().map(|a| self.infer(a)).collect() }
                }
                "unfold" => match args.as_slice() {
                    [syn::Expr::Path(p)] => match self.unfold_target(p, "unfold") {
                        Some(t) => ScriptKind::Unfold(t),
                        None => return,
                    },
                    _ => {
                        self.err(DiagKind::Script, span, "expected `unfold(f);`");
                        return;
                    }
                },
                "by_unfolding" => {
                    if args.is_empty() {
                        self.push(Diagnostic::error(DiagKind::Script, span, "`by_unfolding` names the definitions the step unfolds: `by_unfolding(f, g);`").note("a step that needs no definition is `by_arithmetic();`"));
                        return;
                    }
                    let mut ts: Vec<UnfoldTarget> = Vec::new();
                    for a in &args {
                        let syn::Expr::Path(p) = strip_parens(a) else {
                            let aspan = self.sp(a.span());
                            self.err(DiagKind::Script, aspan, "`by_unfolding` takes function names: `by_unfolding(f, g);`");
                            return;
                        };
                        let Some(t) = self.unfold_target(p, "by_unfolding") else { return };
                        if ts.contains(&t) {
                            let aspan = self.sp(a.span());
                            self.push(Diagnostic::warning(DiagKind::Script, aspan, "this definition is already named"));
                            continue;
                        }
                        ts.push(t);
                    }
                    ScriptKind::Unfolding(ts)
                }
                "by_auto" => {
                    self.push(Diagnostic::error(DiagKind::Script, span, "`by_auto()` was removed: a closing statement says why the goal holds").note(BY_AUTO_NOTE));
                    return;
                }
                "follows_from_facts" => {
                    self.push(Diagnostic::error(DiagKind::Script, span, "`follows_from_facts()` is spelled `follows()`").note("write `follows();`: the goal follows from the facts in scope by the automation's general reasoning (the build fails if it does not)"));
                    return;
                }
                "rewrite" | "rewrite_rev" => {
                    let rev = kw == "rewrite_rev";
                    match args.as_slice() {
                        // `rewrite(a == b)`: an equation to prove first
                        [h] if matches!(strip_parens(h), syn::Expr::Binary(b) if matches!(b.op, syn::BinOp::Eq(_))) => ScriptKind::Rewrite { eq: self.prop(h), rev, motive: None },
                        [h] => ScriptKind::Rewrite { eq: self.proof_term(h), rev, motive: None },
                        [h, syn::Expr::Closure(c)] if !rev => {
                            let eq = self.proof_term(h);
                            self.push_scope();
                            let motive = match c.inputs.first() {
                                Some(syn::Pat::Type(pt)) if c.inputs.len() == 1 => {
                                    let g = self.g.clone();
                                    let t = self.ck.lower_ty(self.m, &pt.ty, &g, true);
                                    let ispan = self.sp(pt.span());
                                    let name = match &*pt.pat {
                                        syn::Pat::Ident(pi) => pi.ident.to_string(),
                                        _ => "_".into(),
                                    };
                                    let l = self.new_local(&name, t, false, true, ispan);
                                    let body = self.prop(&c.body);
                                    Some((l, body))
                                }
                                _ => {
                                    self.err(DiagKind::Script, span, "the rewrite motive must be `|x: T| p`");
                                    None
                                }
                            };
                            self.pop_scope();
                            ScriptKind::Rewrite { eq, rev, motive }
                        }
                        _ => {
                            self.err(DiagKind::Script, span, "expected `rewrite(h);`, `rewrite(a == b);`, `rewrite_rev(h);` or `rewrite(h, |x: T| p);`");
                            return;
                        }
                    }
                }
                "exact" => match args.as_slice() {
                    [t] => ScriptKind::Exact(self.proof_term(t)),
                    _ => {
                        self.err(DiagKind::Script, span, "expected `exact(term);`");
                        return;
                    }
                },
                "bv" | "show" | "todo" | "follows" | "by_computation" | "by_lockstep" | "by_arithmetic" | "by_contradiction" => {
                    if !args.is_empty() {
                        self.err(DiagKind::Script, span, format!("`{kw}()` takes no arguments"));
                    }
                    match kw.as_str() {
                        "bv" => ScriptKind::Bv,
                        "show" => ScriptKind::Show,
                        "by_computation" => ScriptKind::Compute,
                        "by_lockstep" => ScriptKind::Lockstep,
                        "by_arithmetic" => ScriptKind::Arithmetic,
                        "by_contradiction" => ScriptKind::Contradiction,
                        "follows" => ScriptKind::Follows,
                        _ => ScriptKind::Todo,
                    }
                }
                "by_cases" => {
                    // as an arm body (`Some(v) => by_cases(v),`): no rest
                    self.by_cases(c, vec![], span, out);
                    return;
                }
                "by_induction" => {
                    self.by_induction(&args, span, out);
                    return;
                }
                "using" => {
                    let usage = "`using(f, g);` names lemmas or laws: the statements after it may instantiate them";
                    let mut ids = Vec::new();
                    for a in &args {
                        let syn::Expr::Path(p) = strip_parens(a) else {
                            self.push(Diagnostic::error(DiagKind::Script, span, "`using` takes lemma names").note(usage));
                            return;
                        };
                        let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
                        let name = quote::ToTokens::to_token_stream(&p.path).to_string().replace(' ', "");
                        match self.ck.res.resolve_path_defs(self.m, &segs, crate::resolve::Ns::Value, p.path.leading_colon.is_some(), true).ok() {
                            Some(crate::resolve::Def::Item(id)) if self.ck.sigs.get(&id).is_some_and(|s| matches!(s.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof)) => ids.push(id),
                            _ => {
                                self.push(Diagnostic::error(DiagKind::Script, span, format!("`{name}` is not a lemma or law")).note(usage));
                                return;
                            }
                        }
                    }
                    if ids.is_empty() {
                        self.push(Diagnostic::error(DiagKind::Script, span, "`using` needs lemma names").note(usage));
                        return;
                    }
                    ScriptKind::Using(ids)
                }
                "__try" => {
                    let Some(app) = args.first().and_then(|a| self.try_lemma_app(a)) else { return };
                    ScriptKind::Apply { binder: None, app, infer: false, optional: true }
                }
                "__try_ih" => {
                    let Some(me) = self.item else { return };
                    let Some(sig) = self.ck.sigs.get(&me).cloned() else { return };
                    let app = self.lemma_call(me, &sig, &syn::PathArguments::None, &args, span);
                    ScriptKind::Apply { binder: None, app, infer: false, optional: true }
                }
                "ih" | "apply" => {
                    let r = if kw == "apply" { self.apply_app(c, span) } else { self.ih_app(c, span) };
                    match r {
                        Some((app, infer)) => ScriptKind::Apply { binder: None, app, infer, optional: false },
                        None => return,
                    }
                }
                "cases" => match args.as_slice() {
                    [syn::Expr::Path(v), range, syn::Expr::Block(b)] if v.path.segments.len() == 1 => {
                        let var = v.path.segments[0].ident.clone();
                        if b.block.stmts.is_empty() {
                            self.push(Diagnostic::warning(DiagKind::Script, span, "empty `cases` body: every case is closed by the automation").note(format!("write `by_cases({var}, ..);` (docs/PROOF-GUIDE.md)")));
                        }
                        if let Some(c) = self.cases(&var, range, CasesBody::Block(&b.block), span) {
                            out.push(c);
                        }
                        return;
                    }
                    _ => {
                        self.err(DiagKind::Script, span, "expected `cases(k, a..b, { steps });` (or `cases(k in a..b) { .. }` inside `proof!`)");
                        return;
                    }
                },
                "requires" | "ensures" => {
                    self.err(DiagKind::Script, span, format!("`{kw}(..)` is only allowed at the start of a lemma or law"));
                    return;
                }
                "invariant" | "decreases" => {
                    self.err(DiagKind::Script, span, format!("`{kw}(..)` is only allowed in a `proof!` block at the start of a loop body"));
                    return;
                }
                _ => unreachable!(),
            };
            out.push(ScriptStmt { kind, span });
            return;
        }
        match strip_parens(e) {
            syn::Expr::Match(m) => {
                let scrut = self.infer(&m.expr);
                let mut arms = Vec::new();
                for a in &m.arms {
                    let aspan = self.sp(a.span());
                    if a.guard.is_some() {
                        self.err(DiagKind::Script, aspan, "script `match` arms cannot have guards");
                    }
                    self.push_scope();
                    let pat = self.refutable_pat(&a.pat, &scrut.ty);
                    if empty_block(&a.body) {
                        self.empty_case_warning(aspan, "case");
                    }
                    let steps = match &*a.body {
                        syn::Expr::Block(b) => self.block_steps(&b.block),
                        other => {
                            let mut v = Vec::new();
                            let s = self.sp(other.span());
                            self.expr_step(other, s, &mut v);
                            v
                        }
                    };
                    self.pop_scope();
                    arms.push(ScriptArm { pat, steps, span: aspan });
                }
                self.check_exhaustive(&scrut.ty, &arms.iter().map(|a| &a.pat).collect::<Vec<_>>(), span, "match");
                out.push(ScriptStmt { kind: ScriptKind::Match { scrut, arms }, span });
            }
            syn::Expr::If(i) => {
                if matches!(strip_parens(&i.cond), syn::Expr::Let(_)) {
                    self.err(DiagKind::Script, span, "use a script `match` instead of `if let`");
                    return;
                }
                let cond = self.check(&i.cond, &Ty::Bool);
                if i.then_branch.stmts.is_empty() {
                    let s = self.sp(i.then_branch.span());
                    self.empty_case_warning(s, "branch");
                }
                if let Some((_, e)) = &i.else_branch
                    && empty_block(e)
                {
                    let s = self.sp(e.span());
                    self.empty_case_warning(s, "branch");
                }
                if i.else_branch.is_none() {
                    let s = self.sp(i.span());
                    self.push(
                        Diagnostic::warning(DiagKind::Script, s, "script `if` without `else`: the automation must close the `else` case by itself")
                            .note("write `else { follows(); }` to say so, or a closing statement that says why that case holds")
                            .note(CLOSERS_NOTE),
                    );
                }
                let then = self.block_steps(&i.then_branch);
                let els = match &i.else_branch {
                    Some((_, e)) => match &**e {
                        syn::Expr::Block(b) => self.block_steps(&b.block),
                        other => {
                            let mut v = Vec::new();
                            let s = self.sp(other.span());
                            self.expr_step(other, s, &mut v);
                            v
                        }
                    },
                    None => vec![],
                };
                out.push(ScriptStmt { kind: ScriptKind::If { cond, then, els }, span });
            }
            syn::Expr::Block(b) => {
                let steps = self.block_steps(&b.block);
                out.extend(steps);
            }
            syn::Expr::Macro(m) if is_macro(&m.mac.path, "proof") => match m.mac.parse_body::<Steps>() {
                Ok(s) => out.extend(self.steps(&s.0)),
                Err(err) => self.err(DiagKind::Parse, span, format!("cannot parse proof script: {err}")),
            },
            syn::Expr::Macro(m) if is_macro(&m.mac.path, "calc") => {
                if let Some(c) = self.calc(&m.mac, span) {
                    out.push(c);
                }
            }
            other => {
                if let Some(app) = self.try_lemma_app(other) {
                    out.push(ScriptStmt { kind: ScriptKind::Apply { binder: None, app, infer: false, optional: false }, span });
                } else if let Some(call) = self.try_step_app(other) {
                    out.push(ScriptStmt { kind: ScriptKind::Step { call }, span });
                } else if let syn::Expr::Call(c) = other {
                    let name = match strip_parens(&c.func) {
                        syn::Expr::Path(p) => quote::ToTokens::to_token_stream(&p.path).to_string().replace(' ', ""),
                        _ => "<expr>".into(),
                    };
                    let resolves = match strip_parens(&c.func) {
                        syn::Expr::Path(p) => {
                            let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
                            self.ck.res.resolve_path_defs(self.m, &segs, crate::resolve::Ns::Value, p.path.leading_colon.is_some(), true).is_ok()
                        }
                        _ => false,
                    };
                    if resolves {
                        self.push(Diagnostic::error(DiagKind::Script, span, format!("`{name}` is not a lemma or law")).note("calls in scripts must apply a `#[lemma]` or `#[law]` (DESIGN.md §4.4)"));
                    } else {
                        self.push(Diagnostic::error(DiagKind::Resolve, span, format!("cannot find lemma `{name}` in this scope")).note("apply a `#[lemma]`/`#[law]` of the crate, or a prelude lemma as `sandblaster::lemmas::<module>::<name>` (DESIGN.md §4.4, §4.5, §6)"));
                    }
                } else {
                    self.push(Diagnostic::error(DiagKind::Script, span, "expected a script statement").note("see DESIGN.md §4.4"));
                }
            }
        }
    }

    /// `f::step(args)`: the one-step unfolding of the spec or exec function
    /// `f` (generated, never written: a function's `step` is its defining
    /// equation). The typed call `f(args)`, if `e` has that form and `f`
    /// resolves to a function that is not a lemma or law.
    fn try_step_app(&mut self, e: &syn::Expr) -> Option<Expr> {
        let syn::Expr::Call(c) = strip_parens(e) else { return None };
        let syn::Expr::Path(p) = strip_parens(&c.func) else { return None };
        if p.qself.is_some() || p.path.segments.len() < 2 || p.path.segments.last()?.ident != "step" {
            return None;
        }
        let mut fp = p.clone();
        let _ = fp.path.segments.pop();
        // `f::` → `f` (the trailing separator is part of the popped pair)
        if let Some(last) = fp.path.segments.pop() {
            fp.path.segments.push_value(last.into_value());
        }
        let segs: Vec<(String, Span)> = fp.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
        let def = match self.ck.res.resolve_path_defs(self.m, &segs, crate::resolve::Ns::Value, fp.path.leading_colon.is_some(), true) {
            Ok(d) => d,
            Err(_) => self.ck.res.resolve_path_defs_ghost(self.m, &segs, crate::resolve::Ns::Value, fp.path.leading_colon.is_some()).ok()?,
        };
        let crate::resolve::Def::Item(id) = def else { return None };
        let sig = self.ck.sigs.get(&id)?;
        if !matches!(sig.kind, FnKind::Spec | FnKind::Exec) {
            return None;
        }
        let mut call = c.clone();
        call.func = Box::new(syn::Expr::Path(fp));
        let typed = self.infer(&syn::Expr::Call(call));
        match &typed.kind {
            ExprKind::Call { callee: Callee::Item(c2, _), .. } if *c2 == id => Some(typed),
            _ => {
                let span = self.sp(c.span());
                self.err(DiagKind::Script, span, "`f::step(args)` needs a call of a spec or exec function `f` with all its arguments");
                None
            }
        }
    }

    /// `lemma(args)` as a proof term, if `e` is a call to a lemma or law.
    fn try_lemma_app(&mut self, e: &syn::Expr) -> Option<Expr> {
        let syn::Expr::Call(c) = strip_parens(e) else { return None };
        let syn::Expr::Path(p) = strip_parens(&c.func) else { return None };
        if p.qself.is_some() {
            return None;
        }
        // do not report resolution errors here: fall back to normal typing
        let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
        if segs.len() == 1 && self.lookup_local(&segs[0].0).is_some() {
            return None;
        }
        // a lemma of PROOF.rs named in a `proof!` block of exec code: ghost
        // code (never compiled by rustc), so its visibility does not matter
        let def = match self.ck.res.resolve_path_defs(self.m, &segs, crate::resolve::Ns::Value, p.path.leading_colon.is_some(), true) {
            Ok(d) => d,
            Err(_) if self.in_proof_block() => match self.ck.res.resolve_path_defs_ghost(self.m, &segs, crate::resolve::Ns::Value, p.path.leading_colon.is_some()) {
                Ok(d @ crate::resolve::Def::Item(id)) if self.ck.sigs.get(&id).is_some_and(|s| matches!(s.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof)) => d,
                _ => return None,
            },
            Err(_) => return None,
        };
        let crate::resolve::Def::Item(id) = def else { return None };
        let sig = self.ck.sigs.get(&id)?.clone();
        // a `#[proof]` item stands for its law (in PROOF.rs the law's name
        // resolves to the proof of the same name); `validate` rewrites the
        // callee to the law, except for the proof's own recursive calls
        // (induction hypotheses)
        if !matches!(sig.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof) {
            return None;
        }
        let span = self.sp(c.span());
        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
        Some(self.lemma_call(id, &sig, &p.path.segments.last().unwrap().arguments, &args, span))
    }

    /// A typed call of the lemma/law `id` (explicit arguments).
    fn lemma_call(&mut self, id: ItemId, sig: &super::FnSig, generic_args: &syn::PathArguments, args: &[syn::Expr], span: Span) -> Expr {
        let own = match generic_args {
            syn::PathArguments::AngleBracketed(a) => a
                .args
                .iter()
                .filter_map(|x| match x {
                    syn::GenericArgument::Type(t) => {
                        let g = self.g.clone();
                        Some(self.ck.lower_ty(self.m, t, &g, true))
                    }
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        let n = sig.generics.len();
        let mut explicit: Vec<Option<Ty>> = vec![None; n];
        for (i, t) in own.into_iter().enumerate().take(n) {
            explicit[i] = Some(t);
        }
        let (es, ty_args, _) = self.generic_call(n, explicit, &sig.params, &Ty::unit(), args, &Exp::None, span);
        Expr::new(ExprKind::Call { callee: Callee::Item(id, ty_args), args: es }, Ty::Proof, span)
    }

    /// `ih(args)`: the recursive application of the enclosing inductive
    /// proof (`#[induction(x)]`).
    fn ih_app(&mut self, c: &syn::ExprCall, span: Span) -> Option<(Expr, bool)> {
        let me = match (self.item, self.kind) {
            (Some(id), FnKind::Lemma | FnKind::Proof | FnKind::Law) if !self.in_proof_block() => id,
            _ => {
                self.push(Diagnostic::error(DiagKind::Script, span, "`ih(..)` outside an inductive proof").note("the induction hypothesis exists only in a `#[lemma]`/`#[proof]` marked `#[induction(x)]`"));
                return None;
            }
        };
        if self.induction_attr().is_none() {
            let name = self.ck.res.items[me.0 as usize].name.clone();
            self.push(Diagnostic::error(DiagKind::Script, span, "`ih(..)` outside an inductive proof").note(format!("mark `{name}` with `#[induction(x)]`, naming the parameter it recurses on")));
            return None;
        }
        let sig = self.ck.sigs.get(&me)?.clone();
        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
        Some((self.lemma_call(me, &sig, &syn::PathArguments::None, &args, span), false))
    }

    /// Whether the statements being lowered are a `proof!` block of exec
    /// code (not a ghost item's script).
    fn in_proof_block(&self) -> bool {
        self.kind == FnKind::Exec || self.kind == FnKind::Spec
    }

    /// `apply(lemma)`: the lemma, arguments to infer.
    fn apply_app(&mut self, c: &syn::ExprCall, span: Span) -> Option<(Expr, bool)> {
        let usage = "expected `apply(lemma);` naming a `#[lemma]` or `#[law]` (its arguments are inferred from the facts in scope)";
        let [syn::Expr::Path(p)] = c.args.iter().collect::<Vec<_>>().as_slice() else {
            self.push(Diagnostic::error(DiagKind::Script, span, usage).note("to pass arguments, call the lemma directly: `lemma(a, b);`"));
            return None;
        };
        let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::DUMMY)).collect();
        let name = quote::ToTokens::to_token_stream(&p.path).to_string().replace(' ', "");
        let def = self.ck.res.resolve_path_defs(self.m, &segs, crate::resolve::Ns::Value, p.path.leading_colon.is_some(), true).ok();
        let id = match def {
            Some(crate::resolve::Def::Item(id)) if self.ck.sigs.get(&id).is_some_and(|s| matches!(s.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof)) => id,
            Some(_) => {
                self.push(Diagnostic::error(DiagKind::Script, span, format!("`{name}` is not a lemma or law")).note(usage));
                return None;
            }
            None => {
                self.push(Diagnostic::error(DiagKind::Resolve, span, format!("cannot find lemma `{name}` in this scope")).note(usage));
                return None;
            }
        };
        if Some(id) == self.item {
            self.push(Diagnostic::error(DiagKind::Script, span, "`apply` of the enclosing proof").note("apply the induction hypothesis with `ih(args);` (its arguments are explicit)"));
            return None;
        }
        let sig = self.ck.sigs.get(&id)?.clone();
        let own: Vec<Ty> = match &p.path.segments.last().unwrap().arguments {
            syn::PathArguments::AngleBracketed(a) => a
                .args
                .iter()
                .filter_map(|x| match x {
                    syn::GenericArgument::Type(t) => {
                        let g = self.g.clone();
                        Some(self.ck.lower_ty(self.m, t, &g, true))
                    }
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        // type arguments: all of them, or none (inferred by matching too)
        if !own.is_empty() && own.len() != sig.generics.len() {
            self.push(Diagnostic::error(DiagKind::Script, span, format!("`{name}` takes {} type argument(s)", sig.generics.len())).note(format!("write all of them, or none: `apply({name});`")));
            return None;
        }
        Some((Expr::new(ExprKind::Call { callee: Callee::Item(id, own), args: vec![] }, Ty::Proof, span), true))
    }

    fn empty_case_warning(&mut self, span: Span, what: &str) {
        self.push(
            Diagnostic::warning(DiagKind::Script, span, format!("empty {what}: the automation must close it by itself"))
                .note("write `follows();` to say so (or a closing statement that says why the case holds), or `by_cases(..)` for a split whose every case is automatic")
                .note(CLOSERS_NOTE),
        );
    }

    /// The definition named by `unfold(f)` / `by_unfolding(f, ..)`: a
    /// function (exec or spec), an integer method or a `Nat` prelude
    /// function (`pow2`, `log2`, `popcount`); errors otherwise.
    fn unfold_target(&mut self, p: &syn::ExprPath, stmt: &str) -> Option<UnfoldTarget> {
        let pspan = self.sp(p.span());
        match self.value_path(&p.path, pspan) {
            Some(VRes::Fn(id, _, _)) => {
                if stmt == "by_unfolding" && self.ck.sigs.get(&id).is_some_and(|s| matches!(s.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof)) {
                    self.err(DiagKind::Script, pspan, format!("`{stmt}` takes a function definition, not a lemma or law"));
                    return None;
                }
                Some(UnfoldTarget::Item(id))
            }
            Some(VRes::IntAssoc(w, m)) => Some(UnfoldTarget::Builtin(crate::builtins::Builtin::Int(m, w))),
            Some(VRes::Ghost(g, _)) if g.nat_def().is_some() => Some(UnfoldTarget::Ghost(g)),
            Some(_) => {
                self.err(DiagKind::Script, pspan, format!("`{stmt}` takes a function"));
                None
            }
            None => None,
        }
    }

    /// `by_cases(x)`, `by_cases(a, b, ..)`, `by_cases(k, lo..hi)`: a split on
    /// every constructor (every value in the range); `rest` runs in each
    /// case.
    fn by_cases(&mut self, c: &syn::ExprCall, rest: Vec<ScriptStmt>, span: Span, out: &mut Vec<ScriptStmt>) {
        let args: Vec<syn::Expr> = c.args.iter().cloned().collect();
        match args.as_slice() {
            [] => self.push(Diagnostic::error(DiagKind::Script, span, "`by_cases` needs what to split on").note("`by_cases(x);`, `by_cases(a, b);` or `by_cases(k, lo..hi);`")),
            [syn::Expr::Path(v), range] if matches!(strip_parens(range), syn::Expr::Range(_)) => {
                let Some(var) = v.path.get_ident().cloned() else {
                    self.err(DiagKind::Script, span, "`by_cases(k, lo..hi)` enumerates a variable");
                    return;
                };
                if let Some(c) = self.cases(&var, range, CasesBody::Lowered(rest), span) {
                    out.push(c);
                }
            }
            _ => {
                if let Some(r) = args.iter().find(|a| matches!(strip_parens(a), syn::Expr::Range(_))) {
                    let rs = self.sp(r.span());
                    self.push(Diagnostic::error(DiagKind::Script, rs, "an integer range goes with one variable: `by_cases(k, lo..hi);`"));
                    return;
                }
                let mut scruts = Vec::new();
                for a in &args {
                    scruts.push(self.infer(a));
                }
                if let Some(s) = self.split(&scruts, rest, span) {
                    out.push(s);
                }
            }
        }
    }

    /// `by_induction(x)`, `by_induction(x, y, ..)`: structural induction on
    /// `x` (a recursive enum, or a `Seq`/slice), closed by the automation.
    /// Lowered to a `match` on `x` (with `y, ..` of the same type split in
    /// parallel: `(C(x1, ..), C(y1, ..))`, other pairs in one last arm): in
    /// each case, the induction hypothesis at every recursive field (`x`
    /// replaced by the field, `y` by the matching field of `y`, the other
    /// parameters unchanged) is **attempted** (`__try_ih`: kept when its
    /// `requires` are proven, else dropped without an obligation), then
    /// `follows()`. Every hypothesis is the recursive application of the
    /// enclosing lemma, so the kernel checks it like a written `ih(..)`.
    fn by_induction(&mut self, args: &[syn::Expr], span: Span, out: &mut Vec<ScriptStmt>) {
        let usage = "`by_induction(x);` or `by_induction(x, y);`: `x` is the parameter the induction is on (a recursive enum or a `Seq`), `y` a parameter of the same type split with it";
        if !matches!(self.kind, FnKind::Lemma | FnKind::Proof) || self.item.is_none() || self.in_proof_block() {
            self.push(Diagnostic::error(DiagKind::Script, span, "`by_induction` outside a lemma or proof").note(usage));
            return;
        }
        let mut vars: Vec<String> = Vec::new();
        for a in args {
            match strip_parens(a) {
                syn::Expr::Path(p) if p.path.get_ident().is_some() => vars.push(p.path.get_ident().unwrap().to_string()),
                _ => {
                    let aspan = self.sp(a.span());
                    self.push(Diagnostic::error(DiagKind::Script, aspan, "`by_induction` takes parameter names").note(usage));
                    return;
                }
            }
        }
        if vars.is_empty() {
            match self.induction_attr() {
                Some((x, _)) => vars.push(x),
                None => {
                    self.push(Diagnostic::error(DiagKind::Script, span, "`by_induction()` needs the variable to induct on").note(usage));
                    return;
                }
            }
        }
        let names = self.item_param_names();
        let mut ty0: Option<Ty> = None;
        for v in &vars {
            if !names.contains(v) || self.lookup_local(v).is_none() {
                self.push(Diagnostic::error(DiagKind::Script, span, format!("`by_induction`: `{v}` is not a parameter of this proof")).note(usage));
                return;
            }
            let t = self.local_ty(self.lookup_local(v).unwrap()).peel_refs().clone();
            match &ty0 {
                None => ty0 = Some(t),
                Some(t0) if *t0 == t => {}
                Some(_) => {
                    self.push(Diagnostic::error(DiagKind::Script, span, format!("`by_induction`: `{v}` does not have the type of `{}`", vars[0])).note(usage));
                    return;
                }
            }
        }
        let ty = ty0.unwrap();
        // the constructors: (pattern of var `v`'s fields, recursive field names)
        type Ctor = Box<dyn Fn(&str) -> (String, Vec<String>)>;
        let ctors: Vec<Ctor> = match &ty {
            Ty::Seq(_) | Ty::Slice(_) => vec![
                Box::new(|_v: &str| ("[]".to_string(), vec![])),
                Box::new(|v: &str| (format!("[__ih_{v}_h, __ih_{v}_t @ ..]"), vec![format!("__ih_{v}_t")])),
            ],
            Ty::Adt(id, _) if matches!(self.ck.hir_items.get(id.0 as usize), Some(Some(ItemKind::Enum(_)))) => {
                let Some(Some(ItemKind::Enum(e))) = self.ck.hir_items.get(id.0 as usize) else { unreachable!() };
                let path = self.ck.res.items[id.0 as usize].path.to_string();
                let mut v: Vec<Ctor> = Vec::new();
                for var in &e.variants {
                    let (path, name, shape) = (path.clone(), var.name.clone(), var.shape);
                    let fields: Vec<(Option<String>, bool)> = var.fields.iter().map(|f| (f.name.clone(), f.ty.peel_refs() == &ty)).collect();
                    v.push(Box::new(move |x: &str| {
                        let binds: Vec<String> = (0..fields.len()).map(|j| format!("__ih_{x}_{j}")).collect();
                        let rec: Vec<String> = fields.iter().enumerate().filter(|(_, f)| f.1).map(|(j, _)| binds[j].clone()).collect();
                        let pat = match shape {
                            Shape::Unit => format!("{path}::{name}"),
                            Shape::Tuple => format!("{path}::{name}({})", binds.join(", ")),
                            Shape::Named => format!("{path}::{name} {{ {} }}", fields.iter().zip(&binds).map(|(f, b)| format!("{}: {b}", f.0.clone().unwrap_or_default())).collect::<Vec<_>>().join(", ")),
                        };
                        (pat, rec)
                    }));
                }
                v
            }
            other => {
                let s = self.tys(other);
                self.push(Diagnostic::error(DiagKind::Script, span, format!("`by_induction` inducts on a recursive enum or a `Seq`, not `{s}`")).note(usage));
                return;
            }
        };
        // the lemmas of a `using(..)` right before: those whose parameters
        // are the induction variables' type, one per variable, are attempted
        // at every recursive field too
        // (a lemma of fewer parameters is attempted at every ordered choice
        // of that many variables)
        let mut used: Vec<(String, Vec<Vec<usize>>)> = Vec::new();
        if let Some(ScriptStmt { kind: ScriptKind::Using(ids), .. }) = out.last() {
            for id in ids {
                if let Some(sig) = self.ck.sigs.get(id)
                    && !sig.params.is_empty()
                    && sig.params.len() <= vars.len()
                    && sig.params.iter().all(|t| t.peel_refs() == &ty)
                {
                    let k = sig.params.len();
                    let mut picks: Vec<Vec<usize>> = vec![vec![]];
                    for _ in 0..k {
                        picks = picks.into_iter().flat_map(|p| (p.last().map_or(0, |l| l + 1)..vars.len()).map(move |i| { let mut q = p.clone(); q.push(i); q })).collect();
                    }
                    used.push((self.ck.res.items[id.0 as usize].path.to_string(), picks));
                }
            }
        }
        let heads_of: Vec<String> = match &ty {
            Ty::Seq(e) | Ty::Slice(e) => {
                let elem = e.peel_refs().clone();
                let hs: Vec<String> = names.iter().filter(|n| !vars.contains(n)).filter(|n| self.lookup_local(n).is_some_and(|l| self.local_ty(l).peel_refs() == &elem)).cloned().collect();
                if hs.len() == vars.len() { hs } else { vec![] }
            }
            _ => vec![],
        };
        let mut arms: Vec<String> = Vec::new();
        for c in &ctors {
            let parts: Vec<(String, Vec<String>)> = vars.iter().map(|v| c(v)).collect();
            let pat = if vars.len() == 1 { parts[0].0.clone() } else { format!("({})", parts.iter().map(|p| p.0.clone()).collect::<Vec<_>>().join(", ")) };
            let mut body = String::new();
            for j in 0..parts[0].1.len() {
                let args: Vec<String> = names.iter().map(|n| match vars.iter().position(|v| v == n) {
                    Some(k) => parts[k].1[j].clone(),
                    None => n.clone(),
                }).collect();
                body.push_str(&format!("__try_ih({}); ", args.join(", ")));
                // a `Seq` induction whose other parameters include one of the
                // element type per variable (`fold_right(a, [x, ..xs])` recurses
                // at `fold_right(x, xs)`): those parameters get the heads too
                if !heads_of.is_empty() {
                    let args: Vec<String> = names.iter().map(|n| match (vars.iter().position(|v| v == n), heads_of.iter().position(|h| h == n)) {
                        (Some(k), _) => parts[k].1[j].clone(),
                        (None, Some(k)) => format!("__ih_{}_h", vars[k]),
                        (None, None) => n.clone(),
                    }).collect();
                    body.push_str(&format!("__try_ih({}); ", args.join(", ")));
                }
                let fields: Vec<String> = parts.iter().map(|p| p.1[j].clone()).collect();
                for (l, picks) in &used {
                    for pick in picks {
                        let args: Vec<String> = pick.iter().map(|&i| fields[i].clone()).collect();
                        body.push_str(&format!("__try({l}({})); ", args.join(", ")));
                    }
                }
            }
            body.push_str("follows();");
            arms.push(format!("{pat} => {{ {body} }}"));
        }
        if vars.len() > 1 {
            arms.push("_ => { follows(); }".into());
        }
        let scrut = if vars.len() == 1 { vars[0].clone() } else { format!("({})", vars.join(", ")) };
        let src = format!("match {scrut} {{ {} }}", arms.join(" "));
        let e: syn::Expr = match syn::parse_str(&src) {
            Ok(e) => e,
            Err(err) => {
                self.push(Diagnostic::error(DiagKind::Script, span, format!("`by_induction`: cannot build the case split: {err}")));
                return;
            }
        };
        let n = out.len();
        self.expr_step(&e, span, out);
        // the generated statements are the `by_induction` statement's
        for st in &mut out[n..] {
            respan_script(st, span);
        }
    }

    /// Nested splits on `scruts` (outermost first), `rest` at the leaves.
    fn split(&mut self, scruts: &[Expr], rest: Vec<ScriptStmt>, span: Span) -> Option<ScriptStmt> {
        let (scrut, more) = scruts.split_first()?;
        let leaf = |me: &mut Self| -> Vec<ScriptStmt> {
            match me.split(more, rest.clone(), span) {
                Some(s) => vec![s],
                None => rest.clone(),
            }
        };
        let ty = scrut.ty.clone();
        // constructors of the (dereferenced) type, as patterns
        let mut derefs = 0;
        let mut t = &ty;
        while let Ty::Ref(inner) = t {
            derefs += 1;
            t = inner;
        }
        let ctor_pats: Vec<Pat> = match t {
            Ty::Bool if derefs == 0 => {
                let then = leaf(self);
                let els = leaf(self);
                return Some(ScriptStmt { kind: ScriptKind::If { cond: scrut.clone(), then, els }, span });
            }
            Ty::Bool => vec![true, false].into_iter().map(|b| Pat { kind: PatKind::Lit(Lit::Bool(b)), ty: Ty::Bool, span }).collect(),
            Ty::Option(inner) => vec![
                Pat { kind: PatKind::Ctor { ctor: Ctor::None, ty_args: vec![(**inner).clone()], fields: vec![] }, ty: t.clone(), span },
                Pat { kind: PatKind::Ctor { ctor: Ctor::Some, ty_args: vec![(**inner).clone()], fields: vec![] }, ty: t.clone(), span },
            ],
            Ty::Adt(id, targs) if matches!(self.ck.hir_items.get(id.0 as usize), Some(Some(ItemKind::Enum(_)))) => {
                let Some(Some(ItemKind::Enum(e))) = self.ck.hir_items.get(id.0 as usize) else { unreachable!() };
                (0..e.variants.len() as u32).map(|i| Pat { kind: PatKind::Ctor { ctor: Ctor::Variant(*id, i), ty_args: targs.clone(), fields: vec![] }, ty: t.clone(), span }).collect()
            }
            Ty::Error => return None,
            Ty::Uint(_) | Ty::Int | Ty::Nat => {
                self.push(Diagnostic::error(DiagKind::Script, scrut.span, "`by_cases` on an integer needs its range").note("write `by_cases(k, lo..hi);`"));
                return None;
            }
            other => {
                let s = self.tys(other);
                self.push(Diagnostic::error(DiagKind::Script, scrut.span, format!("`by_cases` splits a `bool`, an `Option` or an enum, not `{s}`")).note("use a script `match` to split other values (slices: `[]` / `[head, tail @ ..]`)"));
                return None;
            }
        };
        // wrap the patterns in the dereferences (default binding modes)
        let arms: Vec<ScriptArm> = ctor_pats
            .into_iter()
            .map(|mut p| {
                let mut pty = t.clone();
                for _ in 0..derefs {
                    pty = Ty::Ref(Box::new(pty));
                    p = Pat { kind: PatKind::Deref { pat: Box::new(p), implicit: true }, ty: pty.clone(), span };
                }
                ScriptArm { pat: p, steps: leaf(self), span }
            })
            .collect();
        Some(ScriptStmt { kind: ScriptKind::Match { scrut: scrut.clone(), arms }, span })
    }

    /// `calc! { e0 R e1 by { steps }; R e2; .. }`.
    fn calc(&mut self, mac: &syn::Macro, span: Span) -> Option<ScriptStmt> {
        let cs: CalcSyn = match mac.parse_body() {
            Ok(c) => c,
            Err(e) => {
                let es = self.sp(e.span());
                self.push(Diagnostic::error(DiagKind::Parse, es, format!("cannot parse `calc!`: {e}")).note("`calc! { e0 == e1 by { steps }; == e2; <= e3 by { steps }; }`"));
                return None;
            }
        };
        let mut terms: Vec<&syn::Expr> = vec![&cs.first];
        terms.extend(cs.links.iter().map(|l| &l.rhs));
        let bin = |l: &syn::Expr, rel: CalcRel, r: &syn::Expr, sp: proc_macro2::Span| -> syn::Expr {
            let op = match rel {
                CalcRel::Eq => syn::BinOp::Eq(syn::Token![==](sp)),
                CalcRel::Le => syn::BinOp::Le(syn::Token![<=](sp)),
                CalcRel::Lt => syn::BinOp::Lt(syn::Token![<](sp)),
            };
            let paren = |e: &syn::Expr| syn::Expr::Paren(syn::ExprParen { attrs: vec![], paren_token: syn::token::Paren(sp), expr: Box::new(e.clone()) });
            syn::Expr::Binary(syn::ExprBinary { attrs: vec![], left: Box::new(paren(l)), op, right: Box::new(paren(r)) })
        };
        let mut links = Vec::new();
        let mut rel = CalcRel::Eq;
        for (i, l) in cs.links.iter().enumerate() {
            // the link: its relation through its right-hand side
            let lspan = if i == 0 { self.sp(cs.first.span()).to(self.sp(l.rhs.span())) } else { self.sp(l.span).to(self.sp(l.rhs.span())) };
            let prop = self.prop(&bin(terms[i], l.rel, terms[i + 1], l.span));
            let steps = l.by.as_ref().map(|b| {
                self.push_scope();
                let r = self.steps(b);
                self.pop_scope();
                r
            });
            rel = rel.compose(l.rel);
            links.push(CalcLink { prop, rel: l.rel, steps, span: lspan });
        }
        let concl = self.prop(&bin(terms[0], rel, terms[terms.len() - 1], mac.path.span()));
        Some(ScriptStmt { kind: ScriptKind::Calc { links, concl, rel, goal: true }, span })
    }

    /// A proof term: a lemma application or a ghost expression (e.g. a
    /// `let h = lemma(..)` binder).
    fn proof_term(&mut self, e: &syn::Expr) -> Expr {
        match self.try_lemma_app(e) {
            Some(a) => a,
            None => self.infer(e),
        }
    }

    fn cases(&mut self, var: &syn::Ident, range: &syn::Expr, body: CasesBody, span: Span) -> Option<ScriptStmt> {
        let syn::Expr::Range(r) = strip_parens(range) else {
            self.err(DiagKind::Script, span, "`cases` needs an integer range `a..b` or `a..=b`");
            return None;
        };
        let (Some(lo), Some(hi)) = (&r.start, &r.end) else {
            self.err(DiagKind::Script, span, "`cases` ranges need both bounds");
            return None;
        };
        let inclusive = matches!(r.limits, syn::RangeLimits::Closed(_));
        let name = var.to_string();
        // `k` names an integer variable in scope; each case adds `k == v`
        let Some(l) = self.lookup_local(&name) else {
            let vspan = self.sp(var.span());
            self.err(DiagKind::Script, vspan, format!("`cases` enumerates a variable in scope; `{name}` is not one"));
            return None;
        };
        let ty = self.local_ty(l);
        if !matches!(ty, Ty::Uint(_) | Ty::Int | Ty::Nat | Ty::Error) {
            let s = self.tys(&ty);
            self.err(DiagKind::Script, span, format!("`cases` needs an integer variable, found `{s}`"));
        }
        let (lo_e, hi_e) = (self.check(lo, &ty), self.check(hi, &ty));
        self.push_scope();
        let steps = match body {
            CasesBody::Steps(s) => self.steps(s),
            CasesBody::Block(b) => self.block_steps(b),
            CasesBody::Lowered(s) => s,
        };
        self.pop_scope();
        Some(ScriptStmt { kind: ScriptKind::Cases { var: l, lo: lo_e, hi: hi_e, inclusive, steps }, span })
    }
}

enum CasesBody<'x> {
    Steps(&'x [SynStep]),
    Block(&'x syn::Block),
    /// Already lowered (the statements after a `by_cases`).
    Lowered(Vec<ScriptStmt>),
}

/// The applications of `me` (induction hypotheses) in a script, with their
/// spans.
fn recursive_apps<'x>(steps: &'x [ScriptStmt], me: ItemId, out: &mut Vec<(&'x [Expr], Span)>) {
    for s in steps {
        match &s.kind {
            ScriptKind::Apply { app, .. } | ScriptKind::Exact(app) | ScriptKind::Rewrite { eq: app, .. } => {
                if let ExprKind::Call { callee: Callee::Item(c, _), args } = &app.kind
                    && *c == me
                {
                    out.push((args, s.span));
                }
            }
            ScriptKind::Assert { steps: Some(ss), .. } | ScriptKind::Cases { steps: ss, .. } => recursive_apps(ss, me, out),
            ScriptKind::Match { arms, .. } => arms.iter().for_each(|a| recursive_apps(&a.steps, me, out)),
            ScriptKind::If { then, els, .. } => {
                recursive_apps(then, me, out);
                recursive_apps(els, me, out);
            }
            ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|ss| recursive_apps(ss, me, out)),
            _ => {}
        }
    }
}

fn peel_expr(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(_, x) | ExprKind::Deref(x) | ExprKind::Ref(x) => peel_expr(x),
        _ => e,
    }
}

/// Rest bindings of script `match`es on slice variables: `tail ↦ xs` for
/// `match xs { [head, tail @ ..] => .. }`.
fn rest_bindings(steps: &[ScriptStmt], out: &mut std::collections::HashMap<LocalId, LocalId>) {
    fn pat_rest(p: &Pat, scrut: LocalId, out: &mut std::collections::HashMap<LocalId, LocalId>) {
        match &p.kind {
            PatKind::Deref { pat, .. } => pat_rest(pat, scrut, out),
            PatKind::Slice { prefix, rest: Some(Some(r)), suffix } if prefix.len() + suffix.len() >= 1 => {
                if let PatKind::Binding { local, .. } = &r.kind {
                    out.insert(*local, scrut);
                }
            }
            PatKind::Or(ps) => ps.iter().for_each(|q| pat_rest(q, scrut, out)),
            _ => {}
        }
    }
    for s in steps {
        match &s.kind {
            ScriptKind::Match { scrut, arms } => {
                // a local, or a tuple of locals matched by tuple patterns
                let scruts = crate::elab::recursive::scrut_locals(scrut);
                for a in arms {
                    match (&a.pat.kind, scruts.as_slice()) {
                        (_, [Some(x)]) => pat_rest(&a.pat, *x, out),
                        (PatKind::Tuple(ps), _) if ps.len() == scruts.len() => {
                            for (p, x) in ps.iter().zip(&scruts) {
                                if let Some(x) = x {
                                    pat_rest(p, *x, out);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                arms.iter().for_each(|a| rest_bindings(&a.steps, out));
            }
            ScriptKind::If { then, els, .. } => {
                rest_bindings(then, out);
                rest_bindings(els, out);
            }
            ScriptKind::Assert { steps: Some(ss), .. } | ScriptKind::Cases { steps: ss, .. } => rest_bindings(ss, out),
            ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|ss| rest_bindings(ss, out)),
            _ => {}
        }
    }
}

/// Whether `a` (an argument for the induction variable `x`) is structurally
/// smaller than `x`.
/// A contract statement `p` under the header abbreviations `lets` (script
/// `let` statements): `{ let x = e; ..; p }`.
fn abbreviated(lets: &[ScriptStmt], p: Expr) -> Expr {
    if lets.is_empty() {
        return p;
    }
    let stmts = lets
        .iter()
        .filter_map(|h| match &h.kind {
            ScriptKind::Let { pat, value } => Some(Stmt { kind: StmtKind::Let { pat: pat.clone(), init: value.clone(), els: None }, span: h.span }),
            _ => None,
        })
        .collect();
    let (ty, span) = (p.ty.clone(), p.span);
    Expr::new(ExprKind::Block(Block { stmts, tail: Some(Box::new(p)), span }), ty, span)
}

fn structurally_smaller(a: &Expr, x: LocalId, xty: &Ty, rest_of: &std::collections::HashMap<LocalId, LocalId>) -> bool {
    let a = peel_expr(a);
    match (xty.peel_refs(), &a.kind) {
        (Ty::Slice(_) | Ty::Array(..) | Ty::Seq(_), ExprKind::Local(t)) => {
            // a rest of `x`, or a rest of a rest of `x`, ..
            let mut cur = *t;
            for _ in 0..64 {
                match rest_of.get(&cur) {
                    Some(s) if *s == x => return true,
                    Some(s) => cur = *s,
                    None => return false,
                }
            }
            false
        }
        (Ty::Uint(_), ExprKind::Binary(BinOp::Sub, l, r)) => matches!(&peel_expr(l).kind, ExprKind::Local(v) if *v == x) && matches!(&peel_expr(r).kind, ExprKind::Lit(Lit::Int(k)) if *k >= 1),
        _ => false,
    }
}

/// Gives a generated statement (and its arms and nested statements) the
/// span of the statement that generated it.
fn respan_script(st: &mut ScriptStmt, span: Span) {
    st.span = span;
    match &mut st.kind {
        ScriptKind::Match { arms, scrut } => {
            scrut.span = span;
            for a in arms {
                a.span = span;
                for s in &mut a.steps {
                    respan_script(s, span);
                }
            }
        }
        ScriptKind::Apply { app, .. } => app.span = span,
        _ => {}
    }
}
