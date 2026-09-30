//! Parser for the core text syntax (DESIGN.md §5.12; grammar in
//! `CORE_SYNTAX.md`). Named binders are resolved to de Bruijn indices;
//! globals, inductives and constructors are resolved against the
//! environment. Two derived forms are expanded here (the printer prints the
//! expansion): `match … using .e with …` (the dependent-match idiom of
//! DESIGN.md §7.2: each arm receives the path equation as an `Irr` binder)
//! and `if c [as .h] return R then a else b` (a match on `Bool`).

use std::rc::Rc;

use num_traits::{One, Signed};

use super::lexer::{Tok, Token, lex};
use crate::api::{Env, KernelError, KernelErrorKind};
use crate::term::{
    Arm, BigInt, CtorDecl, DefDecl, DefKind, GlobalId, IndId, InductiveDecl, Name, Rat, Recursion, Rel, Sort, Term, Tm, Width,
};
use crate::util::shift;

pub(crate) type PR<T> = Result<T, String>;

/// A parsed top-level item.
pub enum Item {
    Ind(InductiveDecl),
    Def(DefDecl),
}

const KEYWORDS: &[&str] = &[
    "fun",
    "let",
    "if",
    "then",
    "else",
    "as",
    "return",
    "match",
    "with",
    "using",
    "end",
    "Sigma",
    "Type",
    "Kind",
    "U8",
    "U16",
    "U32",
    "U64",
    "Usize",
    "Int",
    "Eq",
    "refl",
    "transport",
    "pair",
    "fst",
    "snd",
    "rec",
    "delta",
    "unfold",
    "to_body",
    "from_body",
    "linarith",
    "bvrefl",
    "absurd",
    "axiom",
    "inductive",
    "def",
    "structural",
    "measure",
    "arity",
    "_",
];

/// Is `s` a reserved word of the core syntax?
pub fn is_keyword(s: &str) -> bool {
    KEYWORDS.contains(&s)
}

/// Parse `DefKind` names (`exec spec lemma law loop_helper ensures prelude
/// intrinsic`).
pub fn parse_kind(s: &str) -> Option<DefKind> {
    Some(match s {
        "exec" => DefKind::Exec,
        "spec" => DefKind::Spec,
        "lemma" => DefKind::Lemma,
        "law" => DefKind::Law,
        "loop_helper" => DefKind::LoopHelper,
        "ensures" => DefKind::Ensures,
        "prelude" => DefKind::Prelude,
        "intrinsic" => DefKind::Intrinsic,
        _ => return None,
    })
}

pub struct Parser<'a> {
    env: &'a Env,
    toks: Vec<Token>,
    pos: usize,
    scope: Vec<String>,
    /// Relevances of the telescope of the definition being parsed (`rec`).
    rec_rels: Option<Vec<Rel>>,
    /// The inductive being declared (name, future id, #params).
    self_ind: Option<(String, IndId, usize)>,
}

fn width_kw(s: &str) -> Option<Width> {
    Some(match s {
        "U8" => Width::U8,
        "U16" => Width::U16,
        "U32" => Width::U32,
        "U64" => Width::U64,
        "Usize" => Width::Usize,
        "Int" => Width::Int,
        _ => return None,
    })
}

impl<'a> Parser<'a> {
    pub fn new(env: &'a Env, src: &str) -> PR<Self> {
        Ok(Parser { env, toks: lex(src)?, pos: 0, scope: Vec::new(), rec_rels: None, self_ind: None })
    }

    /// A parser over already-lexed tokens, starting at `pos`.
    pub(crate) fn with_tokens(env: &'a Env, toks: Vec<Token>, pos: usize) -> Self {
        Parser { env, toks, pos, scope: Vec::new(), rec_rels: None, self_ind: None }
    }

    /// Give back the tokens and the current position.
    pub(crate) fn into_parts(self) -> (Vec<Token>, usize) {
        (self.toks, self.pos)
    }

    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }
    fn peek_at(&self, k: usize) -> &Tok {
        &self.toks[(self.pos + k).min(self.toks.len() - 1)].tok
    }
    fn bump(&mut self) -> Tok {
        let t = self.toks[self.pos].tok.clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn err<T>(&self, msg: impl std::fmt::Display) -> PR<T> {
        let t = &self.toks[self.pos];
        Err(format!("{}:{}: {msg} (at {:?})", t.line, t.col, t.tok))
    }
    fn is_sym(&self, s: &str) -> bool {
        matches!(self.peek(), Tok::Sym(x) if *x == s)
    }
    fn is_kw(&self, s: &str) -> bool {
        matches!(self.peek(), Tok::Ident(x) if x == s)
    }
    fn eat_sym(&mut self, s: &str) -> bool {
        if self.is_sym(s) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn eat_kw(&mut self, s: &str) -> bool {
        if self.is_kw(s) {
            self.bump();
            true
        } else {
            false
        }
    }
    fn expect_sym(&mut self, s: &str) -> PR<()> {
        if self.eat_sym(s) { Ok(()) } else { self.err(format!("expected `{s}`")) }
    }
    fn expect_kw(&mut self, s: &str) -> PR<()> {
        if self.eat_kw(s) { Ok(()) } else { self.err(format!("expected `{s}`")) }
    }
    /// An identifier that is not a keyword (or `_` if `allow_underscore`).
    fn name(&mut self, allow_underscore: bool) -> PR<String> {
        match self.peek().clone() {
            Tok::Ident(s) if s == "_" && allow_underscore => {
                self.bump();
                Ok(s)
            }
            Tok::Ident(s) if !is_keyword(&s) => {
                self.bump();
                Ok(s)
            }
            _ => self.err("expected a name"),
        }
    }
    fn num(&mut self) -> PR<BigInt> {
        match self.bump() {
            Tok::Num(n, None) => Ok(n),
            _ => self.err("expected an unsuffixed number"),
        }
    }
    pub fn at_eof(&self) -> bool {
        matches!(self.peek(), Tok::Eof)
    }

    fn with_scope<T>(&mut self, names: &[String], f: impl FnOnce(&mut Self) -> PR<T>) -> PR<T> {
        let n = self.scope.len();
        self.scope.extend(names.iter().cloned());
        let r = f(self);
        self.scope.truncate(n);
        r
    }

    // -----------------------------------------------------------------------
    // Items.
    // -----------------------------------------------------------------------

    /// Parse the next item (`None` at end of input).
    pub fn item(&mut self) -> PR<Option<Item>> {
        if self.at_eof() {
            return Ok(None);
        }
        if self.eat_kw("inductive") {
            return self.inductive().map(|d| Some(Item::Ind(d)));
        }
        if self.eat_kw("def") {
            return self.def().map(|d| Some(Item::Def(d)));
        }
        self.err("expected `inductive` or `def`")
    }

    fn inductive(&mut self) -> PR<InductiveDecl> {
        let name = self.name(false)?;
        let mut params: Vec<(Name, Tm)> = Vec::new();
        let saved = std::mem::take(&mut self.scope);
        let r = (|| {
            while self.is_sym("(") {
                self.bump();
                let p = self.name(true)?;
                self.expect_sym(":")?;
                let t = self.term()?;
                self.expect_sym(")")?;
                params.push((Rc::from(p.as_str()), t));
                self.scope.push(p);
            }
            let id = IndId(self.env.inds.len() as u32);
            self.self_ind = Some((name.clone(), id, params.len()));
            self.expect_sym("{")?;
            let mut ctors = Vec::new();
            while self.eat_sym("|") {
                let cname = self.name(false)?;
                let mut fields = Vec::new();
                let base = self.scope.len();
                if self.eat_sym("(") {
                    loop {
                        let rel = if self.eat_sym(".") { Rel::Irr } else { Rel::Rel };
                        let f = self.name(true)?;
                        self.expect_sym(":")?;
                        let t = self.term()?;
                        fields.push((Rc::from(f.as_str()), rel, t));
                        self.scope.push(f);
                        if !self.eat_sym(",") {
                            break;
                        }
                    }
                    self.expect_sym(")")?;
                }
                self.scope.truncate(base);
                ctors.push(CtorDecl { name: Rc::from(cname.as_str()), fields });
            }
            self.expect_sym("}")?;
            Ok(InductiveDecl { name: Rc::from(name.as_str()), params: params.clone(), ctors })
        })();
        self.scope = saved;
        self.self_ind = None;
        r
    }

    /// `def[<attrs>] name : ty := body [structural p | measure (m)]` where
    /// the optional attribute list holds, in any order and at most once
    /// each, a definition kind, `opaque` and `arity = n`.
    fn def(&mut self) -> PR<DefDecl> {
        let mut kind: Option<DefKind> = None;
        let mut arity: Option<u32> = None;
        let mut opaque = false;
        if self.eat_sym("[") {
            loop {
                if self.eat_kw("arity") {
                    if arity.is_some() {
                        return self.err("duplicate `arity`");
                    }
                    self.expect_sym("=")?;
                    let n = self.num()?;
                    arity = Some(n.try_into().map_err(|_| "arity out of range".to_string())?);
                } else {
                    let k = self.name(false)?;
                    if k == "opaque" {
                        if opaque {
                            return self.err("duplicate `opaque`");
                        }
                        opaque = true;
                    } else {
                        let Some(pk) = parse_kind(&k) else { return self.err(format!("unknown definition attribute `{k}`")) };
                        if kind.is_some() {
                            return self.err(format!("duplicate definition kind `{k}`"));
                        }
                        kind = Some(pk);
                    }
                }
                if !self.eat_sym(",") {
                    break;
                }
            }
            self.expect_sym("]")?;
        }
        let kind = kind.unwrap_or(DefKind::Prelude);
        let name = self.name(false)?;
        self.expect_sym(":")?;
        let saved = std::mem::take(&mut self.scope);
        let r = (|| {
            let ty = self.term()?;
            self.rec_rels = Some(pi_rels(&ty));
            self.expect_sym(":=")?;
            let body = self.term()?;
            let lams = lam_names(&body);
            let arity = arity.unwrap_or(lams.len() as u32);
            if lams.len() < arity as usize {
                return self.err(format!("`{name}`: the body has fewer than {arity} leading λ binders"));
            }
            let params: Vec<String> = lams[..arity as usize].to_vec();
            let recursion = if self.eat_kw("structural") {
                let param = match self.peek().clone() {
                    Tok::Num(n, None) => {
                        self.bump();
                        n.try_into().map_err(|_| "structural parameter out of range".to_string())?
                    }
                    Tok::Ident(p) => {
                        self.bump();
                        match params.iter().position(|x| *x == p) {
                            Some(i) => i as u32,
                            None => return self.err(format!("`{p}` is not a parameter of `{name}`")),
                        }
                    }
                    _ => return self.err("expected a parameter name or index"),
                };
                Recursion::Structural { param }
            } else if self.eat_kw("measure") {
                self.expect_sym("(")?;
                let m = self.with_scope(&params, |p| p.term())?;
                self.expect_sym(")")?;
                Recursion::Measure { measure: m }
            } else {
                Recursion::None
            };
            Ok(DefDecl { name: Rc::from(name.as_str()), kind, ty, body, recursion, arity, opaque })
        })();
        self.scope = saved;
        self.rec_rels = None;
        r
    }

    // -----------------------------------------------------------------------
    // Terms.
    // -----------------------------------------------------------------------

    /// Lookahead: `(` [`.`] name `:`.
    fn binder_ahead(&self) -> bool {
        if !self.is_sym("(") {
            return false;
        }
        let k = if matches!(self.peek_at(1), Tok::Sym(".")) { 2 } else { 1 };
        matches!(self.peek_at(k), Tok::Ident(s) if s == "_" || !is_keyword(s)) && matches!(self.peek_at(k + 1), Tok::Sym(":"))
    }

    /// `(` [`.`] name `:` term `)`.
    fn binder(&mut self) -> PR<(String, Rel, Tm)> {
        self.expect_sym("(")?;
        let rel = if self.eat_sym(".") { Rel::Irr } else { Rel::Rel };
        let n = self.name(true)?;
        self.expect_sym(":")?;
        let t = self.term()?;
        self.expect_sym(")")?;
        Ok((n, rel, t))
    }

    /// Parse binders, each type in the scope of the previous ones; the names
    /// are left in scope.
    fn binders(&mut self) -> PR<Vec<(String, Rel, Tm)>> {
        let mut out = Vec::new();
        while self.binder_ahead() {
            let b = self.binder()?;
            self.scope.push(b.0.clone());
            out.push(b);
        }
        Ok(out)
    }

    pub fn term(&mut self) -> PR<Tm> {
        if self.eat_kw("fun") {
            let base = self.scope.len();
            let bs = self.binders()?;
            if bs.is_empty() {
                return self.err("expected binders after `fun`");
            }
            let r = (|| {
                self.expect_sym("=>")?;
                self.term()
            })();
            self.scope.truncate(base);
            let body = r?;
            return Ok(bs
                .into_iter()
                .rev()
                .fold(body, |acc, (n, rel, dom)| Rc::new(Term::Lam { name: Rc::from(n.as_str()), rel, dom, body: acc })));
        }
        if self.eat_kw("let") {
            let rel = if self.eat_sym(".") { Rel::Irr } else { Rel::Rel };
            let n = self.name(true)?;
            self.expect_sym(":")?;
            let ty = self.term()?;
            self.expect_sym("=")?;
            let val = self.term()?;
            self.expect_sym(";")?;
            let body = self.with_scope(std::slice::from_ref(&n), |p| p.term())?;
            return Ok(Rc::new(Term::Let { name: Rc::from(n.as_str()), rel, ty, val, body }));
        }
        if self.eat_kw("if") {
            return self.if_term();
        }
        if self.eat_kw("match") {
            return self.match_term();
        }
        if self.eat_kw("Sigma") {
            self.expect_sym("(")?;
            let n = self.name(true)?;
            self.expect_sym(":")?;
            let fst = self.term()?;
            self.expect_sym(")")?;
            self.expect_sym(",")?;
            let snd_rel = if self.eat_sym(".") { Rel::Irr } else { Rel::Rel };
            let snd = self.with_scope(std::slice::from_ref(&n), |p| p.term())?;
            return Ok(Rc::new(Term::Sigma { name: Rc::from(n.as_str()), snd_rel, fst, snd }));
        }
        if self.binder_ahead() {
            let base = self.scope.len();
            let bs = self.binders()?;
            let r = (|| {
                self.expect_sym("->")?;
                self.term()
            })();
            self.scope.truncate(base);
            let cod = r?;
            return Ok(bs
                .into_iter()
                .rev()
                .fold(cod, |acc, (n, rel, dom)| Rc::new(Term::Pi { name: Rc::from(n.as_str()), rel, dom, cod: acc })));
        }
        let a = self.app()?;
        if self.eat_sym("->") {
            let cod = self.with_scope(&["_".to_string()], |p| p.term())?;
            return Ok(Rc::new(Term::Pi { name: Rc::from("_"), rel: Rel::Rel, dom: a, cod }));
        }
        Ok(a)
    }

    fn if_term(&mut self) -> PR<Tm> {
        let c = self.app()?;
        let eq = if self.eat_kw("as") {
            if !self.eat_sym(".") {
                return self.err("the equation of `if … as` is irrelevant: write `as .h`");
            }
            Some(self.name(true)?)
        } else {
            None
        };
        self.expect_kw("return")?;
        let r = self.term()?;
        self.expect_kw("then")?;
        let names: Vec<String> = eq.iter().cloned().collect();
        let a = self.with_scope(&names, |p| p.term())?;
        self.expect_kw("else")?;
        let b = self.with_scope(&names, |p| p.term())?;
        let bi = self.env.bool_id;
        let bool_ty = Rc::new(Term::Ind { ind: bi, params: vec![] });
        let arms = vec![(vec![], b), (vec![], a)];
        Ok(build_match(bi, vec![], bool_ty, c, shift(&r, 1), eq, arms))
    }

    fn match_term(&mut self) -> PR<Tm> {
        let scrut = self.app()?;
        self.expect_sym(":")?;
        let ity = self.app()?;
        let (ind, params) = match &*ity {
            Term::Ind { ind, params } => (*ind, params.clone()),
            _ => return self.err("the type annotation of a match must be an inductive type"),
        };
        self.expect_kw("as")?;
        let y = self.name(true)?;
        self.expect_kw("return")?;
        let motive = self.with_scope(std::slice::from_ref(&y), |p| p.term())?;
        let eq = if self.eat_kw("using") {
            if !self.eat_sym(".") {
                return self.err("the equation of `using` is irrelevant: write `using .e`");
            }
            Some(self.name(true)?)
        } else {
            None
        };
        self.expect_kw("with")?;
        let info = self.env.inds.get(ind.0 as usize).ok_or("unknown inductive")?;
        let ctors: Vec<(String, Vec<Rel>)> =
            info.ctors.iter().map(|c| (c.name.to_string(), c.fields.iter().map(|f| f.1).collect())).collect();
        let iname = info.name.to_string();
        let mut arms = Vec::new();
        for (cname, rels) in &ctors {
            self.expect_sym("|")?;
            let got = self.name(false)?;
            if got != *cname && got != format!("{iname}::{cname}") {
                return self.err(format!("expected the arm for constructor `{cname}`"));
            }
            let mut fields = Vec::new();
            if self.eat_sym("(") {
                loop {
                    let rel = if self.eat_sym(".") { Rel::Irr } else { Rel::Rel };
                    let f = self.name(true)?;
                    fields.push((f, rel));
                    if !self.eat_sym(",") {
                        break;
                    }
                }
                self.expect_sym(")")?;
            }
            if fields.len() != rels.len() {
                return self.err(format!("constructor `{cname}` has {} fields", rels.len()));
            }
            if fields.iter().zip(rels).any(|((_, r1), r2)| r1 != r2) {
                return self.err(format!("relevance markers of `{cname}`'s fields do not match its declaration"));
            }
            self.expect_sym("=>")?;
            let mut names: Vec<String> = fields.iter().map(|f| f.0.clone()).collect();
            names.extend(eq.iter().cloned());
            let body = self.with_scope(&names, |p| p.term())?;
            arms.push((fields.into_iter().map(|f| f.0).collect::<Vec<_>>(), body));
        }
        self.expect_kw("end")?;
        Ok(build_match(ind, params, ity, scrut, motive, eq, arms))
    }

    fn atom_start(&self) -> bool {
        match self.peek() {
            Tok::Ident(s) => {
                !is_keyword(s)
                    || matches!(
                        s.as_str(),
                        "Type"
                            | "Kind"
                            | "U8"
                            | "U16"
                            | "U32"
                            | "U64"
                            | "Usize"
                            | "Int"
                            | "Eq"
                            | "refl"
                            | "transport"
                            | "pair"
                            | "fst"
                            | "snd"
                            | "rec"
                            | "delta"
                            | "unfold"
                            | "linarith"
                            | "bvrefl"
                            | "absurd"
                            | "axiom"
                            | "_"
                    )
            }
            Tok::Num(..) => true,
            Tok::Sym(s) => matches!(*s, "(" | "@" | "#"),
            Tok::Eof => false,
        }
    }

    fn app(&mut self) -> PR<Tm> {
        let mut f = self.atom()?;
        loop {
            if self.is_sym(".") {
                // Irrelevant argument.
                self.bump();
                let a = self.atom()?;
                f = Rc::new(Term::App { rel: Rel::Irr, fun: f, arg: a });
            } else if self.atom_start() {
                let a = self.atom()?;
                f = Rc::new(Term::App { rel: Rel::Rel, fun: f, arg: a });
            } else {
                return Ok(f);
            }
        }
    }

    /// Comma-separated terms until `close` (not consumed).
    fn terms_until(&mut self, close: &str) -> PR<Vec<Tm>> {
        let mut out = Vec::new();
        if self.is_sym(close) {
            return Ok(out);
        }
        loop {
            out.push(self.term()?);
            if !self.eat_sym(",") {
                return Ok(out);
            }
        }
    }

    /// Comma-separated arguments with optional `.` markers, checked against
    /// `rels` when known.
    fn rel_args(&mut self, close: &[&str], rels: Option<&[Rel]>, what: &str) -> PR<Vec<Tm>> {
        let mut out = Vec::new();
        if close.iter().any(|c| self.is_sym(c)) {
            return Ok(out);
        }
        loop {
            let irr = self.eat_sym(".");
            let t = self.term()?;
            if let Some(rels) = rels {
                let want = rels.get(out.len()).copied().unwrap_or(Rel::Rel);
                if (want == Rel::Irr) != irr {
                    return self.err(format!(
                        "argument {} of {what} must {}be marked irrelevant (`.`)",
                        out.len(),
                        if irr { "not " } else { "" }
                    ));
                }
            }
            out.push(t);
            if !self.eat_sym(",") {
                return Ok(out);
            }
        }
    }

    fn global_ref(&mut self) -> PR<GlobalId> {
        if self.eat_sym("@") {
            let n = self.num()?;
            return Ok(GlobalId(n.try_into().map_err(|_| "global id out of range".to_string())?));
        }
        let n = self.name(false)?;
        match self.env.lookup_global(&n) {
            Some(g) => Ok(g),
            None => self.err(format!("unknown global `{n}`")),
        }
    }

    fn atom(&mut self) -> PR<Tm> {
        let tok = self.peek().clone();
        match tok {
            Tok::Num(n, w) => {
                self.bump();
                match w {
                    Some(w) => Ok(Rc::new(Term::Lit { w, n })),
                    None => self.err("integer literals need a width suffix (e.g. `3u32`, `-1int`)"),
                }
            }
            Tok::Sym("(") => {
                self.bump();
                let t = self.term()?;
                self.expect_sym(")")?;
                Ok(t)
            }
            Tok::Sym("@") => Ok(Rc::new(Term::Global(self.global_ref()?))),
            Tok::Sym("#") => {
                self.bump();
                let n = self.name(false)?;
                let Some(op) = crate::prim::parse_prim_name(&n) else { return self.err(format!("unknown primitive `#{n}`")) };
                self.expect_sym("(")?;
                let args = self.terms_until(")")?;
                let proofs = if self.eat_sym(";") { self.terms_until(")")? } else { vec![] };
                self.expect_sym(")")?;
                Ok(Rc::new(Term::Prim { op, args, proofs }))
            }
            Tok::Ident(s) => {
                self.bump();
                self.ident_atom(&s)
            }
            _ => self.err("expected a term"),
        }
    }

    fn ident_atom(&mut self, s: &str) -> PR<Tm> {
        if let Some(w) = width_kw(s) {
            return Ok(Rc::new(Term::IntTy(w)));
        }
        match s {
            "Type" => return Ok(Rc::new(Term::Sort(Sort::Type))),
            "Kind" => return Ok(Rc::new(Term::Sort(Sort::Kind))),
            "_" => return Ok(Rc::new(Term::Erased)),
            "Eq" | "refl" | "pair" | "fst" | "snd" | "bvrefl" | "absurd" | "transport" | "rec" | "delta" | "unfold" | "linarith"
            | "axiom" => return self.special(s),
            _ => {}
        }
        // Locals (innermost first; `_` binders are never referenced).
        if let Some(i) = self.scope.iter().rev().position(|n| n == s && n != "_") {
            return Ok(Rc::new(Term::Var(crate::term::Idx(i as u32))));
        }
        if let Some((name, id, np)) = self.self_ind.clone()
            && name == s
        {
            let params = if np > 0 {
                self.expect_sym("(")?;
                let ps = self.terms_until(")")?;
                self.expect_sym(")")?;
                ps
            } else {
                vec![]
            };
            return Ok(Rc::new(Term::Ind { ind: id, params }));
        }
        if let Some(ind) = self.env.lookup_ind(s) {
            let np = self.env.inds[ind.0 as usize].params.len();
            let params = if np > 0 {
                self.expect_sym("(")?;
                let ps = self.terms_until(")")?;
                self.expect_sym(")")?;
                ps
            } else {
                vec![]
            };
            return Ok(Rc::new(Term::Ind { ind, params }));
        }
        if let Some((ind, k)) = self.env.lookup_ctor(s) {
            let info = &self.env.inds[ind.0 as usize];
            let np = info.params.len();
            let rels: Vec<Rel> = info.ctors[k as usize].fields.iter().map(|f| f.1).collect();
            let params = if np > 0 {
                self.expect_sym("[")?;
                let ps = self.terms_until("]")?;
                self.expect_sym("]")?;
                ps
            } else {
                vec![]
            };
            let args = if !rels.is_empty() {
                self.expect_sym("(")?;
                let a = self.rel_args(&[")"], Some(&rels), &format!("constructor `{s}`"))?;
                if a.len() != rels.len() {
                    return self.err(format!("constructor `{s}` takes {} fields", rels.len()));
                }
                self.expect_sym(")")?;
                a
            } else {
                vec![]
            };
            return Ok(Rc::new(Term::Ctor { ind, ctor: k, params, args }));
        }
        if let Some(g) = self.env.lookup_global(s) {
            return Ok(Rc::new(Term::Global(g)));
        }
        self.err(format!("unknown name `{s}`"))
    }

    fn special(&mut self, s: &str) -> PR<Tm> {
        if s == "axiom" {
            self.expect_sym("[")?;
            let n = self.name(false)?;
            self.expect_sym("]")?;
            let Some(ax) = crate::axioms::axiom_by_name(&n) else { return self.err(format!("unknown axiom `{n}`")) };
            self.expect_sym("(")?;
            let rels = crate::axioms::axiom_param_rels(ax);
            let args = self.rel_args(&[")"], Some(&rels), &format!("axiom `{n}`"))?;
            self.expect_sym(")")?;
            return Ok(Rc::new(Term::Axiom { ax, args }));
        }
        self.expect_sym("(")?;
        let t = match s {
            "Eq" => {
                let v = self.terms_until(")")?;
                if v.len() != 3 {
                    return self.err("Eq takes 3 arguments");
                }
                Term::Eq { ty: v[0].clone(), lhs: v[1].clone(), rhs: v[2].clone() }
            }
            "refl" => {
                let v = self.terms_until(")")?;
                if v.len() != 2 {
                    return self.err("refl takes 2 arguments");
                }
                Term::Refl { ty: v[0].clone(), val: v[1].clone() }
            }
            "pair" => {
                let v = self.terms_until(")")?;
                if v.len() != 3 {
                    return self.err("pair takes 3 arguments");
                }
                Term::Pair { ty: v[0].clone(), fst: v[1].clone(), snd: v[2].clone() }
            }
            "fst" | "snd" => {
                let p = self.term()?;
                if s == "fst" { Term::Fst(p) } else { Term::Snd(p) }
            }
            "bvrefl" => {
                let v = self.terms_until(")")?;
                if v.len() != 3 {
                    return self.err("bvrefl takes 3 arguments");
                }
                Term::BvRefl { ty: v[0].clone(), lhs: v[1].clone(), rhs: v[2].clone() }
            }
            "absurd" => {
                let v = self.terms_until(")")?;
                if v.len() != 2 {
                    return self.err("absurd takes 2 arguments");
                }
                Term::Absurd { ty: v[0].clone(), proof: v[1].clone() }
            }
            "transport" => {
                let ty = self.term()?;
                self.expect_sym(",")?;
                let lhs = self.term()?;
                self.expect_sym(",")?;
                let rhs = self.term()?;
                self.expect_sym(",")?;
                let eq = self.term()?;
                self.expect_sym(",")?;
                let y = self.name(true)?;
                self.expect_sym(".")?;
                let motive = self.with_scope(&[y], |p| p.term())?;
                self.expect_sym(",")?;
                let val = self.term()?;
                Term::Transport { ty, lhs, rhs, eq, motive, val }
            }
            "rec" => {
                let rels = self.rec_rels.clone();
                let args = self.rel_args(&[")", ";"], rels.as_deref(), "rec")?;
                let proof = if self.eat_sym(";") { Some(self.term()?) } else { None };
                Term::Rec { args, proof }
            }
            "delta" | "unfold" => {
                let def = self.global_ref()?;
                self.expect_sym(";")?;
                let rels = self.env.defs.get(def.0 as usize).map(|d| d.param_rels.clone());
                let args = self.rel_args(&[")", ";"], rels.as_deref(), s)?;
                if s == "delta" {
                    Term::Delta { def, args }
                } else {
                    self.expect_sym(";")?;
                    let to_body = if self.eat_kw("to_body") {
                        true
                    } else if self.eat_kw("from_body") {
                        false
                    } else {
                        return self.err("expected `to_body` or `from_body`");
                    };
                    self.expect_sym(";")?;
                    let val = self.term()?;
                    Term::Unfold { def, args, to_body, val }
                }
            }
            "linarith" => {
                self.expect_sym("[")?;
                let mut hyps = Vec::new();
                if !self.is_sym("]") {
                    loop {
                        let p = self.term()?;
                        self.expect_sym(":")?;
                        let st = self.term()?;
                        hyps.push((p, st));
                        if !self.eat_sym(",") {
                            break;
                        }
                    }
                }
                self.expect_sym("]")?;
                self.expect_sym(";")?;
                let goal = self.term()?;
                self.expect_sym(";")?;
                self.expect_sym("[")?;
                let mut cert = Vec::new();
                if !self.is_sym("]") {
                    loop {
                        let num = match self.bump() {
                            Tok::Num(n, None) => n,
                            _ => return self.err("expected a rational"),
                        };
                        let den = if self.eat_sym("/") { self.num()? } else { BigInt::one() };
                        if !den.is_positive() {
                            return self.err("rational denominators must be positive");
                        }
                        cert.push(Rat { num, den });
                        if !self.eat_sym(",") {
                            break;
                        }
                    }
                }
                self.expect_sym("]")?;
                Term::Linarith { hyps, goal, cert }
            }
            _ => return self.err("internal: unknown special form"),
        };
        self.expect_sym(")")?;
        Ok(Rc::new(t))
    }
}

/// Relevances of the leading Π binders of a type.
fn pi_rels(t: &Tm) -> Vec<Rel> {
    let mut out = Vec::new();
    let mut t = t.clone();
    while let Term::Pi { rel, cod, .. } = &*t.clone() {
        out.push(*rel);
        t = cod.clone();
    }
    out
}

/// Names of the leading λ binders of a term.
fn lam_names(t: &Tm) -> Vec<String> {
    let mut out = Vec::new();
    let mut t = t.clone();
    while let Term::Lam { name, body, .. } = &*t.clone() {
        out.push(name.to_string());
        t = body.clone();
    }
    out
}

/// Build a match, expanding the `using .e` idiom: the motive becomes
/// `Π(e :Irr Eq(D(ps), s, y)). P`, each arm `λ(e :Irr Eq(D(ps), s,
/// C_k(ps; fields))). body`, and the match is applied to `refl(D(ps), s)`.
#[allow(clippy::too_many_arguments)]
fn build_match(ind: IndId, params: Vec<Tm>, ity: Tm, scrut: Tm, motive: Tm, eq: Option<String>, arms: Vec<(Vec<String>, Tm)>) -> Tm {
    let Some(e) = eq else {
        let arms =
            arms.into_iter().map(|(names, body)| Arm { names: names.iter().map(|n| Rc::from(n.as_str())).collect(), body }).collect();
        return Rc::new(Term::Match { ind, params, scrut, motive, arms });
    };
    let en: Name = Rc::from(e.as_str());
    // Motive, in scope Γ, y: Π(e :Irr Eq(D(ps)↑1, s↑1, y)). P↑1.
    let motive = Rc::new(Term::Pi {
        name: en.clone(),
        rel: Rel::Irr,
        dom: Rc::new(Term::Eq { ty: shift(&ity, 1), lhs: shift(&scrut, 1), rhs: Rc::new(Term::Var(crate::term::Idx(0))) }),
        cod: shift(&motive, 1),
    });
    let arms = arms
        .into_iter()
        .enumerate()
        .map(|(k, (names, body))| {
            let nf = names.len() as u32;
            let fields = (0..nf).map(|j| Rc::new(Term::Var(crate::term::Idx(nf - 1 - j)))).collect();
            let c = Rc::new(Term::Ctor { ind, ctor: k as u32, params: params.iter().map(|p| shift(p, nf as i64)).collect(), args: fields });
            let dom = Rc::new(Term::Eq { ty: shift(&ity, nf as i64), lhs: shift(&scrut, nf as i64), rhs: c });
            Arm {
                names: names.iter().map(|n| Rc::from(n.as_str())).collect(),
                body: Rc::new(Term::Lam { name: en.clone(), rel: Rel::Irr, dom, body }),
            }
        })
        .collect();
    let m = Rc::new(Term::Match { ind, params, scrut: scrut.clone(), motive, arms });
    Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: Rc::new(Term::Refl { ty: ity, val: scrut }) })
}

fn to_kernel(e: String) -> KernelError {
    KernelError { kind: KernelErrorKind::IllFormed, message: format!("parse error: {e}") }
}

/// Parse a single term in a context with the given variable names (level
/// order).
pub fn parse_term(env: &Env, names: &[&str], src: &str) -> Result<Tm, KernelError> {
    let mut p = Parser::new(env, src).map_err(to_kernel)?;
    p.scope = names.iter().map(|s| s.to_string()).collect();
    let t = p.term().map_err(to_kernel)?;
    if !p.at_eof() {
        return Err(to_kernel(p.err::<()>("unexpected trailing input").unwrap_err()));
    }
    Ok(t)
}

/// Parse all items of a source text without adding them (items may only
/// refer to what is already in `env`).
pub fn parse_items(env: &Env, src: &str) -> Result<Vec<Item>, KernelError> {
    let mut p = Parser::new(env, src).map_err(to_kernel)?;
    let mut out = Vec::new();
    while let Some(it) = p.item().map_err(to_kernel)? {
        out.push(it);
    }
    Ok(out)
}
