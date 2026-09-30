//! Printer for the core text syntax (DESIGN.md §5.12). Output parses back
//! (with [`super::parser`]) to the same term: binder names are kept unless
//! they would clash with a name in scope, a global/inductive/constructor
//! name or a keyword, in which case a numeric suffix is added. Derived forms
//! (`using`, `if`) are printed in their expanded form.

use num_traits::One;

use super::parser::is_keyword;
use crate::api::Env;
use crate::term::{DefDecl, DefKind, GlobalId, IndId, Name, Recursion, Rel, Term, Tm, Width};
use crate::util::occurs;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Prec {
    /// Anything (binder forms allowed).
    Top,
    /// Application level (binder forms and arrows parenthesized).
    App,
    /// Atom level (applications parenthesized too).
    Atom,
}

struct P<'e> {
    env: &'e Env,
    out: String,
    /// Relevances of the telescope of the definition being printed (`rec`).
    rec_rels: Vec<Rel>,
    /// Stop printing once the output exceeds this length (diagnostics).
    max_len: usize,
}

fn valid_ident(s: &str) -> bool {
    let mut segs = s.split("::");
    segs.all(|seg| {
        let mut cs = seg.chars();
        matches!(cs.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && cs.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '\'')
    })
}

fn width_name(w: Width) -> &'static str {
    match w {
        Width::U8 => "U8",
        Width::U16 => "U16",
        Width::U32 => "U32",
        Width::U64 => "U64",
        Width::Usize => "Usize",
        Width::Int => "Int",
    }
}

/// Name of a definition kind in the core syntax.
pub fn kind_name(k: DefKind) -> &'static str {
    match k {
        DefKind::Exec => "exec",
        DefKind::Spec => "spec",
        DefKind::Lemma => "lemma",
        DefKind::Law => "law",
        DefKind::LoopHelper => "loop_helper",
        DefKind::Ensures => "ensures",
        DefKind::Prelude => "prelude",
        DefKind::Intrinsic => "intrinsic",
    }
}

impl<'e> P<'e> {
    fn w(&mut self, s: &str) {
        self.out.push_str(s);
    }

    fn global_taken(&self, s: &str) -> bool {
        self.env.lookup_global(s).is_some() || self.env.lookup_ind(s).is_some() || self.env.ctor_names.contains_key(s)
    }

    /// Choose a printable, non-clashing name for a binder.
    fn fresh(&self, scope: &[String], base: &str, used: bool) -> String {
        if base == "_" && !used {
            return "_".into();
        }
        let base = if base == "_" || !valid_ident(base) || base.contains("::") { "x" } else { base };
        let ok = |n: &str| !is_keyword(n) && !scope.iter().any(|s| s == n) && !self.global_taken(n);
        if ok(base) {
            return base.to_string();
        }
        (1..).map(|i| format!("{base}{i}")).find(|n| ok(n)).unwrap()
    }

    fn global(&mut self, scope: &[String], g: GlobalId) {
        match self.env.global_name(g) {
            Some(n)
                if valid_ident(&n)
                    && !is_keyword(&n)
                    && self.env.lookup_global(&n) == Some(g)
                    && !scope.iter().any(|s| **s == *n)
                    && self.env.lookup_ind(&n).is_none()
                    && !self.env.ctor_names.contains_key(&*n) =>
            {
                self.w(&n)
            }
            _ => self.w(&format!("@{}", g.0)),
        }
    }

    fn ind_name(&self, ind: IndId) -> String {
        self.env.inds.get(ind.0 as usize).map(|i| i.name.to_string()).unwrap_or_else(|| format!("?ind{}", ind.0))
    }

    fn ctor_name(&self, ind: IndId, k: u32) -> String {
        let Some(info) = self.env.inds.get(ind.0 as usize) else { return format!("?ctor{k}") };
        let Some(c) = info.ctors.get(k as usize) else { return format!("?ctor{k}") };
        if self.env.lookup_ctor(&c.name) == Some((ind, k)) { c.name.to_string() } else { format!("{}::{}", info.name, c.name) }
    }

    fn list(&mut self, scope: &mut Vec<String>, ts: &[Tm], rels: &[Rel]) {
        for (i, t) in ts.iter().enumerate() {
            if i > 0 {
                self.w(", ");
            }
            if rels.get(i) == Some(&Rel::Irr) {
                self.w(".");
                self.term(scope, t, Prec::Atom);
            } else {
                self.term(scope, t, Prec::Top);
            }
        }
    }

    fn open(&mut self, need: bool) {
        if need {
            self.w("(");
        }
    }
    fn close(&mut self, need: bool) {
        if need {
            self.w(")");
        }
    }

    fn term(&mut self, scope: &mut Vec<String>, t: &Tm, prec: Prec) {
        use Term::*;
        if self.out.len() > self.max_len {
            return;
        }
        match &**t {
            Var(i) => {
                let n = scope.len();
                match n.checked_sub(1 + i.0 as usize) {
                    Some(k) => {
                        let s = scope[k].clone();
                        self.w(&s)
                    }
                    None => self.w(&format!("?v{}", i.0)),
                }
            }
            Global(g) => self.global(scope, *g),
            Term::Sort(crate::term::Sort::Type) => self.w("Type"),
            Term::Sort(crate::term::Sort::Kind) => self.w("Kind"),
            IntTy(w) => self.w(width_name(*w)),
            Lit { w, n } => self.w(&format!("{n}{}", crate::prim::width_suffix(*w))),
            Erased => self.w("_"),
            Pi { name, rel, dom, cod } => {
                let paren = prec > Prec::Top;
                self.open(paren);
                if *rel == Rel::Rel && !occurs(cod, 0) {
                    self.term(scope, dom, Prec::App);
                    self.w(" -> ");
                    scope.push("_".into());
                    self.term(scope, cod, Prec::Top);
                    scope.pop();
                } else {
                    let base = scope.len();
                    let (mut name, mut rel, mut dom, mut cod) = (name.clone(), *rel, dom.clone(), cod.clone());
                    loop {
                        let n = self.fresh(scope, &name, occurs(&cod, 0));
                        self.w(&format!("({}{n} : ", if rel == Rel::Irr { "." } else { "" }));
                        self.term(scope, &dom, Prec::Top);
                        self.w(") ");
                        scope.push(n);
                        match &*cod.clone() {
                            Pi { name: n2, rel: r2, dom: d2, cod: c2 } if !(*r2 == Rel::Rel && !occurs(c2, 0)) => {
                                name = n2.clone();
                                rel = *r2;
                                dom = d2.clone();
                                cod = c2.clone();
                            }
                            _ => break,
                        }
                    }
                    self.w("-> ");
                    self.term(scope, &cod, Prec::Top);
                    scope.truncate(base);
                }
                self.close(paren);
            }
            Lam { .. } => {
                let paren = prec > Prec::Top;
                self.open(paren);
                self.w("fun");
                let base = scope.len();
                let mut cur = t.clone();
                while let Lam { name, rel, dom, body } = &*cur.clone() {
                    let n = self.fresh(scope, name, occurs(body, 0));
                    self.w(&format!(" ({}{n} : ", if *rel == Rel::Irr { "." } else { "" }));
                    self.term(scope, dom, Prec::Top);
                    self.w(")");
                    scope.push(n);
                    cur = body.clone();
                }
                self.w(" => ");
                self.term(scope, &cur, Prec::Top);
                scope.truncate(base);
                self.close(paren);
            }
            App { .. } => {
                let paren = prec > Prec::App;
                self.open(paren);
                let mut spine = Vec::new();
                let mut cur = t.clone();
                while let App { rel, fun, arg } = &*cur.clone() {
                    spine.push((*rel, arg.clone()));
                    cur = fun.clone();
                }
                self.term(scope, &cur, Prec::Atom);
                for (rel, a) in spine.into_iter().rev() {
                    self.w(if rel == Rel::Irr { " ." } else { " " });
                    self.term(scope, &a, Prec::Atom);
                }
                self.close(paren);
            }
            Let { name, rel, ty, val, body } => {
                let paren = prec > Prec::Top;
                self.open(paren);
                let n = self.fresh(scope, name, occurs(body, 0));
                self.w(&format!("let {}{n} : ", if *rel == Rel::Irr { "." } else { "" }));
                self.term(scope, ty, Prec::Top);
                self.w(" = ");
                self.term(scope, val, Prec::Top);
                self.w("; ");
                scope.push(n);
                self.term(scope, body, Prec::Top);
                scope.pop();
                self.close(paren);
            }
            Sigma { name, snd_rel, fst, snd } => {
                let paren = prec > Prec::Top;
                self.open(paren);
                let n = self.fresh(scope, name, occurs(snd, 0));
                self.w(&format!("Sigma ({n} : "));
                self.term(scope, fst, Prec::Top);
                self.w(if *snd_rel == Rel::Irr { "), ." } else { "), " });
                scope.push(n);
                self.term(scope, snd, if *snd_rel == Rel::Irr { Prec::Atom } else { Prec::Top });
                scope.pop();
                self.close(paren);
            }
            Pair { ty, fst, snd } => {
                self.w("pair(");
                self.list(scope, &[ty.clone(), fst.clone(), snd.clone()], &[]);
                self.w(")");
            }
            Fst(p) | Snd(p) => {
                self.w(if matches!(&**t, Fst(_)) { "fst(" } else { "snd(" });
                self.term(scope, p, Prec::Top);
                self.w(")");
            }
            Eq { ty, lhs, rhs } => {
                self.w("Eq(");
                self.list(scope, &[ty.clone(), lhs.clone(), rhs.clone()], &[]);
                self.w(")");
            }
            Refl { ty, val } => {
                self.w("refl(");
                self.list(scope, &[ty.clone(), val.clone()], &[]);
                self.w(")");
            }
            Transport { ty, lhs, rhs, eq, motive, val } => {
                self.w("transport(");
                self.list(scope, &[ty.clone(), lhs.clone(), rhs.clone(), eq.clone()], &[]);
                let y = self.fresh(scope, "y", true);
                self.w(&format!(", {y}. "));
                scope.push(y);
                self.term(scope, motive, Prec::Top);
                scope.pop();
                self.w(", ");
                self.term(scope, val, Prec::Top);
                self.w(")");
            }
            Ind { ind, params } => {
                self.w(&self.ind_name(*ind));
                if !params.is_empty() {
                    self.w("(");
                    self.list(scope, params, &[]);
                    self.w(")");
                }
            }
            Ctor { ind, ctor, params, args } => {
                self.w(&self.ctor_name(*ind, *ctor));
                if !params.is_empty() {
                    self.w("[");
                    self.list(scope, params, &[]);
                    self.w("]");
                }
                if !args.is_empty() {
                    let rels = self.env.ctor_rels(*ind, *ctor).unwrap_or_default();
                    self.w("(");
                    self.list(scope, args, &rels);
                    self.w(")");
                }
            }
            Match { ind, params, scrut, motive, arms } => {
                let paren = prec > Prec::Top;
                self.open(paren);
                self.w("match ");
                self.term(scope, scrut, Prec::App);
                self.w(" : ");
                self.term(scope, &std::rc::Rc::new(Ind { ind: *ind, params: params.clone() }), Prec::App);
                let y = self.fresh(scope, "y", occurs(motive, 0));
                self.w(&format!(" as {y} return "));
                scope.push(y);
                self.term(scope, motive, Prec::Top);
                scope.pop();
                self.w(" with");
                let rels_of = |k: usize| self.env.ctor_rels(*ind, k as u32).unwrap_or_default();
                for (k, arm) in arms.iter().enumerate() {
                    let rels = rels_of(k);
                    self.w(&format!(" | {}", self.ctor_name(*ind, k as u32)));
                    let base = scope.len();
                    if !arm.names.is_empty() {
                        self.w("(");
                        let nf = arm.names.len() as u32;
                        for (j, n) in arm.names.iter().enumerate() {
                            if j > 0 {
                                self.w(", ");
                            }
                            let used = occurs(&arm.body, nf - 1 - j as u32);
                            let n = self.fresh(scope, n, used);
                            self.w(&format!("{}{n}", if rels.get(j) == Some(&Rel::Irr) { "." } else { "" }));
                            scope.push(n);
                        }
                        self.w(")");
                    }
                    self.w(" => ");
                    self.term(scope, &arm.body, Prec::Top);
                    scope.truncate(base);
                }
                self.w(" end");
                self.close(paren);
            }
            Prim { op, args, proofs } => {
                self.w(&format!("#{}(", crate::prim::prim_name(*op)));
                self.list(scope, args, &[]);
                if !proofs.is_empty() {
                    self.w("; ");
                    self.list(scope, proofs, &[]);
                }
                self.w(")");
            }
            Rec { args, proof } => {
                self.w("rec(");
                let rels = self.rec_rels.clone();
                self.list(scope, args, &rels);
                if let Some(p) = proof {
                    self.w("; ");
                    self.term(scope, p, Prec::Top);
                }
                self.w(")");
            }
            Delta { def, args } | Unfold { def, args, .. } => {
                let is_delta = matches!(&**t, Delta { .. });
                self.w(if is_delta { "delta(" } else { "unfold(" });
                self.global(scope, *def);
                self.w("; ");
                let rels = self.env.global_param_rels(*def).unwrap_or_default();
                self.list(scope, args, &rels);
                if let Unfold { to_body, val, .. } = &**t {
                    self.w(if *to_body { "; to_body; " } else { "; from_body; " });
                    self.term(scope, val, Prec::Top);
                }
                self.w(")");
            }
            Linarith { hyps, goal, cert } => {
                self.w("linarith([");
                for (i, (p, s)) in hyps.iter().enumerate() {
                    if i > 0 {
                        self.w(", ");
                    }
                    self.term(scope, p, Prec::Top);
                    self.w(" : ");
                    self.term(scope, s, Prec::Top);
                }
                self.w("]; ");
                self.term(scope, goal, Prec::Top);
                self.w("; [");
                for (i, r) in cert.iter().enumerate() {
                    if i > 0 {
                        self.w(", ");
                    }
                    if r.den.is_one() {
                        self.w(&r.num.to_string());
                    } else {
                        self.w(&format!("{}/{}", r.num, r.den));
                    }
                }
                self.w("])");
            }
            BvRefl { ty, lhs, rhs } => {
                self.w("bvrefl(");
                self.list(scope, &[ty.clone(), lhs.clone(), rhs.clone()], &[]);
                self.w(")");
            }
            Absurd { ty, proof } => {
                self.w("absurd(");
                self.list(scope, &[ty.clone(), proof.clone()], &[]);
                self.w(")");
            }
            Axiom { ax, args } => {
                self.w(&format!("axiom[{}](", crate::axioms::axiom_name(*ax)));
                let rels = crate::axioms::axiom_param_rels(*ax);
                self.list(scope, args, &rels);
                self.w(")");
            }
        }
    }
}

/// Print a term in a context with the given variable names (level order).
pub fn print_term(env: &Env, names: &[Name], t: &Tm) -> String {
    let mut p = P { env, out: String::new(), rec_rels: Vec::new(), max_len: usize::MAX };
    let mut scope: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    p.term(&mut scope, t, Prec::Top);
    p.out
}

/// [`print_term`] for diagnostics: stops (with `…`) once the output exceeds
/// about `max_len` bytes, so terms that share subterms heavily (a quoted
/// value DAG is a tree only in print) are rendered in bounded time. The
/// result does not parse back when truncated.
pub fn print_term_bounded(env: &Env, names: &[Name], t: &Tm, max_len: usize) -> String {
    let mut p = P { env, out: String::new(), rec_rels: Vec::new(), max_len };
    let mut scope: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    p.term(&mut scope, t, Prec::Top);
    if p.out.len() > max_len {
        p.out.push('…');
    }
    p.out
}

/// Print an inductive declaration.
pub fn print_inductive(env: &Env, ind: IndId) -> Option<String> {
    let info = env.inds.get(ind.0 as usize)?;
    let mut p = P { env, out: String::new(), rec_rels: Vec::new(), max_len: usize::MAX };
    let mut scope: Vec<String> = Vec::new();
    p.w(&format!("inductive {}", info.name));
    for (n, t) in &info.params {
        let n = p.fresh(&scope, n, true);
        p.w(&format!(" ({n} : "));
        p.term(&mut scope, t, Prec::Top);
        p.w(")");
        scope.push(n);
    }
    p.w(" {");
    for c in &info.ctors {
        p.w(&format!("\n  | {}", c.name));
        let base = scope.len();
        if !c.fields.is_empty() {
            p.w("(");
            for (j, (n, rel, t)) in c.fields.iter().enumerate() {
                if j > 0 {
                    p.w(", ");
                }
                let n = p.fresh(&scope, n, true);
                p.w(&format!("{}{n} : ", if *rel == Rel::Irr { "." } else { "" }));
                // The inductive itself prints by name (it is in the env now).
                p.term(&mut scope, t, Prec::Top);
                scope.push(n);
            }
            p.w(")");
        }
        scope.truncate(base);
    }
    p.w("\n}");
    Some(p.out)
}

/// Print a definition declaration (with `rec` terms, as submitted).
pub fn print_def(env: &Env, d: &DefDecl) -> String {
    let mut p = P { env, out: String::new(), rec_rels: Vec::new(), max_len: usize::MAX };
    let rels = {
        let mut out = Vec::new();
        let mut t = d.ty.clone();
        while let Term::Pi { rel, cod, .. } = &*t.clone() {
            out.push(*rel);
            t = cod.clone();
        }
        out
    };
    p.rec_rels = rels;
    let default_arity = {
        let mut n = 0u32;
        let mut t = d.body.clone();
        while let Term::Lam { body, .. } = &*t.clone() {
            n += 1;
            t = body.clone();
        }
        n
    };
    p.w(&format!("def[{}", kind_name(d.kind)));
    if d.opaque {
        p.w(", opaque");
    }
    if default_arity != d.arity {
        p.w(&format!(", arity = {}", d.arity));
    }
    p.w(&format!("] {} : ", d.name));
    let mut scope = Vec::new();
    p.term(&mut scope, &d.ty, Prec::Top);
    p.w(" := ");
    p.term(&mut scope, &d.body, Prec::Top);
    match &d.recursion {
        Recursion::None => {}
        Recursion::Structural { param } => p.w(&format!(" structural {param}")),
        Recursion::Measure { measure } => {
            // The measure is in the scope of the first `arity` λ names, chosen
            // exactly as the printer chose them for the body.
            let mut names = Vec::new();
            let mut t = d.body.clone();
            for _ in 0..d.arity {
                let next = match &*t {
                    Term::Lam { name, body, .. } => {
                        let n = p.fresh(&names, name, occurs(body, 0));
                        names.push(n);
                        body.clone()
                    }
                    _ => break,
                };
                t = next;
            }
            p.w(" measure (");
            p.term(&mut names, measure, Prec::Top);
            p.w(")");
        }
    }
    p.out
}
