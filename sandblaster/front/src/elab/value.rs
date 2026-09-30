//! Values at the boundary of the reference semantics (DESIGN.md §10.2
//! `sandblaster eval`, §10.3 differential testing): JSON ↔ closed core terms
//! and values, by HIR type.
//!
//! | type | JSON |
//! | --- | --- |
//! | `bool` | `true` / `false` |
//! | `uN`, `usize`, `Int` | a number (any size), or a string (`"123"`, `"0xff"`) |
//! | `()` | `null` or `[]` |
//! | tuples | arrays |
//! | `[T; N]`, `&[T]` | arrays; byte arrays/slices also as `"0x…"` hex strings |
//! | `Seq<T>` (lifted buffers) | arrays; byte sequences also as `"0x…"` hex strings |
//! | `Option<T>` | `null` for `None`, `{"Some": v}` for `Some(v)` |
//! | structs | objects by field name (tuple structs: arrays) |
//! | enums | `"Variant"` for unit variants, `{"Variant": [fields]}` / `{"Variant": {..}}` |
//!
//! Output uses the same format (byte arrays/slices as arrays of numbers).

use std::collections::BTreeMap;

use num_bigint::BigInt;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{IndId, Rel, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Value, V};

use crate::hir::{Crate, ItemId, ItemKind, Shape, Ty};

/// A parsed JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    /// Numbers keep their text (arbitrary precision integers).
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    /// Parses JSON text.
    pub fn parse(s: &str) -> Result<J, String> {
        let mut p = Parser { b: s.as_bytes(), i: 0 };
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing characters at {}", p.i));
        }
        Ok(v)
    }

    /// Renders compact JSON.
    pub fn render(&self) -> String {
        match self {
            J::Null => "null".into(),
            J::Bool(b) => b.to_string(),
            J::Num(n) => n.clone(),
            J::Str(s) => format!("{s:?}"),
            J::Arr(xs) => format!("[{}]", xs.iter().map(J::render).collect::<Vec<_>>().join(",")),
            J::Obj(kv) => format!("{{{}}}", kv.iter().map(|(k, v)| format!("{k:?}:{}", v.render())).collect::<Vec<_>>().join(",")),
        }
    }
}

struct Parser<'s> {
    b: &'s [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && (self.b[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<J, String> {
        self.ws();
        let Some(&c) = self.b.get(self.i) else { return Err("unexpected end".into()) };
        match c {
            b'n' => self.lit("null", J::Null),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'"' => Ok(J::Str(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(J::Arr(v));
                }
                loop {
                    v.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(v));
                        }
                        _ => return Err(format!("expected `,` or `]` at {}", self.i)),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(J::Obj(v));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(format!("expected `:` at {}", self.i));
                    }
                    self.i += 1;
                    let x = self.value()?;
                    v.push((k, x));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(v));
                        }
                        _ => return Err(format!("expected `,` or `}}` at {}", self.i)),
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let st = self.i;
                self.i += 1;
                while self.i < self.b.len() && (self.b[self.i].is_ascii_alphanumeric() || matches!(self.b[self.i], b'.' | b'+' | b'-')) {
                    self.i += 1;
                }
                Ok(J::Num(String::from_utf8_lossy(&self.b[st..self.i]).into_owned()))
            }
            _ => Err(format!("unexpected `{}` at {}", c as char, self.i)),
        }
    }
    fn lit(&mut self, w: &str, v: J) -> Result<J, String> {
        if self.b[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Ok(v)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }
    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err(format!("expected a string at {}", self.i));
        }
        self.i += 1;
        let mut out = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("bad escape")?;
                    self.i += 1;
                    out.push(match e {
                        b'n' => '\n',
                        b't' => '\t',
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        _ => return Err("unsupported escape".into()),
                    });
                }
                _ => out.push(c as char),
            }
        }
        Err("unterminated string".into())
    }
}

/// Context for conversions: the environment and the crate's type table.
pub struct Conv<'e> {
    pub env: &'e Env,
    pub krate: &'e Crate,
    pub adts: &'e std::collections::HashMap<ItemId, IndId>,
}

fn parse_int(j: &J) -> Result<BigInt, String> {
    let s = match j {
        J::Num(s) | J::Str(s) => s.trim(),
        other => return Err(format!("expected an integer, found {}", other.render())),
    };
    let r = if let Some(h) = s.strip_prefix("0x") { BigInt::parse_bytes(h.replace('_', "").as_bytes(), 16) } else { BigInt::parse_bytes(s.replace('_', "").as_bytes(), 10) };
    r.ok_or_else(|| format!("bad integer `{s}`"))
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let h = s.strip_prefix("0x")?;
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok()).collect()
}

impl Conv<'_> {
    fn g(&self, n: &str) -> Result<Tm, String> {
        self.env.lookup_global(n).map(mk::global).ok_or_else(|| format!("missing prelude `{n}`"))
    }

    /// The closed core type of a (closed) HIR type.
    pub fn ty(&self, t: &Ty) -> Result<Tm, String> {
        Ok(match t {
            Ty::Bool => mk::bool_ty(self.env.bool_ind()),
            Ty::Uint(u) => mk::int_ty(u.width()),
            Ty::Int => mk::int_ty(Width::Int),
            Ty::Tuple(ts) if ts.is_empty() => mk::ind(self.ind("Unit")?, vec![]),
            Ty::Tuple(ts) => mk::ind(self.ind(&format!("Tuple{}", ts.len()))?, ts.iter().map(|x| self.ty(x)).collect::<Result<_, _>>()?),
            Ty::Array(e, n) => mk::apps(self.g("Array")?, [(Rel::Rel, self.ty(e)?), (Rel::Rel, mk::lit(Width::Usize, *n))]),
            Ty::Slice(e) => mk::app(self.g("Slice")?, self.ty(e)?),
            Ty::Ref(e) => self.ty(e)?,
            Ty::Option(e) => mk::ind(self.ind("Option")?, vec![self.ty(e)?]),
            Ty::Seq(e) => mk::ind(self.ind("List")?, vec![self.ty(e)?]),
            Ty::Adt(id, args) => mk::ind(*self.adts.get(id).ok_or("unknown type")?, args.iter().map(|x| self.ty(x)).collect::<Result<_, _>>()?),
            Ty::Vector(v) => {
                let (lane, n) = v.lanes();
                mk::apps(self.g("Array")?, [(Rel::Rel, mk::int_ty(lane.width())), (Rel::Rel, mk::lit(Width::Usize, n))])
            }
            other => return Err(format!("type `{other:?}` has no values here")),
        })
    }

    fn ind(&self, n: &str) -> Result<IndId, String> {
        self.env.lookup_ind(n).ok_or_else(|| format!("missing prelude inductive `{n}`"))
    }

    fn list(&self, et: &Tm, elems: Vec<Tm>) -> Result<Tm, String> {
        let list = self.ind("List")?;
        let mut l = mk::ctor(list, 0, vec![et.clone()], vec![]);
        for e in elems.into_iter().rev() {
            l = mk::ctor(list, 1, vec![et.clone()], vec![e, l]);
        }
        Ok(l)
    }

    fn elems(&self, e: &Ty, j: &J) -> Result<Vec<Tm>, String> {
        match j {
            J::Arr(xs) => xs.iter().map(|x| self.term(e, x)).collect(),
            J::Str(s) if matches!(e, Ty::Uint(crate::hir::UintTy::U8)) => {
                let bs = hex_bytes(s).ok_or_else(|| format!("bad hex string `{s}`"))?;
                Ok(bs.into_iter().map(|b| mk::lit(Width::U8, b)).collect())
            }
            other => Err(format!("expected an array, found {}", other.render())),
        }
    }

    /// A closed core term of type `t` for the JSON value `j`.
    pub fn term(&self, t: &Ty, j: &J) -> Result<Tm, String> {
        let bool_ = self.env.bool_ind();
        Ok(match t.peel_refs() {
            Ty::Bool => match j {
                J::Bool(b) => mk::bool_lit(bool_, *b),
                _ => return Err(format!("expected a bool, found {}", j.render())),
            },
            Ty::Uint(u) => {
                let n = parse_int(j)?;
                if n < BigInt::from(0) || n > BigInt::from(u.max_value()) {
                    return Err(format!("{n} is out of range for {}", u.name()));
                }
                mk::lit(u.width(), n)
            }
            Ty::Int => mk::lit(Width::Int, parse_int(j)?),
            Ty::Tuple(ts) if ts.is_empty() => mk::ctor(self.ind("Unit")?, 0, vec![], vec![]),
            Ty::Tuple(ts) => {
                let J::Arr(xs) = j else { return Err(format!("expected a tuple array, found {}", j.render())) };
                if xs.len() != ts.len() {
                    return Err("tuple arity mismatch".into());
                }
                let ps = ts.iter().map(|x| self.ty(x)).collect::<Result<Vec<_>, _>>()?;
                let vs = ts.iter().zip(xs).map(|(t, x)| self.term(t, x)).collect::<Result<Vec<_>, _>>()?;
                mk::ctor(self.ind(&format!("Tuple{}", ts.len()))?, 0, ps, vs)
            }
            Ty::Array(e, n) => {
                let et = self.ty(e)?;
                let es = self.elems(e, j)?;
                if es.len() as u64 != *n {
                    return Err(format!("expected {n} elements, found {}", es.len()));
                }
                let l = self.list(&et, es)?;
                mk::pair(self.ty(&Ty::Array(e.clone(), *n))?, l, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, *n)))
            }
            Ty::Slice(e) => {
                let et = self.ty(e)?;
                let es = self.elems(e, j)?;
                let n = es.len();
                let l = self.list(&et, es)?;
                let ok_ty = mk::apps(self.g("SliceOk")?, [(Rel::Rel, et.clone()), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, l.clone())]);
                let ok = mk::pair(ok_ty, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, n)), mk::refl(mk::bool_ty(bool_), mk::bool_lit(bool_, true)));
                mk::apps(self.g("slice::mk")?, [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, l), (Rel::Irr, ok)])
            }
            Ty::Seq(e) => {
                let et = self.ty(e)?;
                let es = self.elems(e, j)?;
                self.list(&et, es)?
            }
            Ty::Option(e) => {
                let et = self.ty(e)?;
                let opt = self.ind("Option")?;
                match j {
                    J::Null => mk::ctor(opt, 0, vec![et], vec![]),
                    J::Obj(kv) if kv.len() == 1 && kv[0].0 == "Some" => mk::ctor(opt, 1, vec![et], vec![self.term(e, &kv[0].1)?]),
                    _ => return Err(format!("expected null or {{\"Some\": v}}, found {}", j.render())),
                }
            }
            Ty::Adt(id, args) => {
                let ind = *self.adts.get(id).ok_or("unknown type")?;
                let ps = args.iter().map(|x| self.ty(x)).collect::<Result<Vec<_>, _>>()?;
                match &self.krate.item(*id).kind {
                    ItemKind::Struct(s) => {
                        let ftys: Vec<Ty> = s.fields.iter().map(|f| f.ty.subst(args)).collect();
                        let vs = self.fields(&ftys, s.fields.iter().map(|f| f.name.clone()).collect(), s.shape, j)?;
                        self.checked_struct(*id, ind, ps, vs)?
                    }
                    ItemKind::Enum(e) => {
                        let (vname, payload) = match j {
                            J::Str(n) => (n.clone(), J::Arr(vec![])),
                            J::Obj(kv) if kv.len() == 1 => (kv[0].0.clone(), kv[0].1.clone()),
                            _ => return Err(format!("expected an enum variant, found {}", j.render())),
                        };
                        let (vi, v) = e.variants.iter().enumerate().find(|(_, v)| v.name == vname).ok_or_else(|| format!("no variant `{vname}`"))?;
                        let ftys: Vec<Ty> = v.fields.iter().map(|f| f.ty.subst(args)).collect();
                        let vs = self.fields(&ftys, v.fields.iter().map(|f| f.name.clone()).collect(), v.shape, &payload)?;
                        mk::ctor(ind, vi as u32, ps, vs)
                    }
                    _ => return Err("not a type".into()),
                }
            }
            other => return Err(format!("unsupported argument type {other:?}")),
        })
    }

    /// A struct value from its relevant fields: the invariant's `Irr`
    /// fields (DESIGN.md §15.3) are erased slots, and every conjunct must
    /// evaluate to `true` on the input (a value violating the invariant is
    /// rejected: no code path may form it).
    fn checked_struct(&self, id: ItemId, ind: IndId, ps: Vec<Tm>, vs: Vec<Tm>) -> Result<Tm, String> {
        use sandblaster_kernel::term::{Lvl, Term};
        use sandblaster_kernel::value::{Budget, VEnv};
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(mk::ctor(ind, 0, ps, vs)) };
        let c = &decl.ctors[0];
        if c.fields.iter().all(|f| f.1 == Rel::Rel) {
            return Ok(mk::ctor(ind, 0, ps, vs));
        }
        let path = self.krate.item(id).path.to_string();
        let erased: Tm = std::rc::Rc::new(Term::Erased);
        let mut all = ps.clone();
        let mut args = Vec::new();
        let mut rel = vs.into_iter();
        for (k, (_, r, fty)) in c.fields.iter().enumerate() {
            match r {
                Rel::Rel => {
                    let a = rel.next().ok_or("field count mismatch")?;
                    all.push(a.clone());
                    args.push(a);
                }
                Rel::Irr => {
                    let t = super::tm::subst_closed(fty, &all);
                    let Term::Eq { lhs, rhs, .. } = &*t else { return Err(format!("the invariant of `{path}` is a proposition that cannot be checked on an input")) };
                    let mut b = Budget { steps: 1_000_000_000 };
                    let ev = |x: &Tm, b: &mut Budget| self.env.eval_opaque(&VEnv::default(), Lvl(0), x, &|_| false, b).map_err(|e| format!("evaluating the invariant of `{path}` failed: {e:?}"));
                    let (l, r) = (ev(lhs, &mut b)?, ev(rhs, &mut b)?);
                    let bool_ = self.env.bool_ind();
                    let lit = |v: &V| match &**v {
                        Value::Ctor { ind, ctor, .. } if *ind == bool_ => Some(*ctor == 1),
                        _ => None,
                    };
                    match (lit(&l), lit(&r)) {
                        (Some(x), Some(y)) if x == y => {}
                        (Some(_), Some(_)) => return Err(format!("the input violates the invariant of `{path}` (conjunct {})", k - c.fields.iter().filter(|f| f.1 == Rel::Rel).count())),
                        _ => return Err(format!("the invariant of `{path}` could not be decided on the input")),
                    }
                    all.push(erased.clone());
                    args.push(erased.clone());
                }
            }
        }
        Ok(mk::ctor(ind, 0, ps, args))
    }

    fn fields(&self, ftys: &[Ty], names: Vec<Option<String>>, shape: Shape, j: &J) -> Result<Vec<Tm>, String> {
        match (shape, j) {
            (Shape::Named, J::Obj(kv)) => {
                let m: BTreeMap<&str, &J> = kv.iter().map(|(k, v)| (k.as_str(), v)).collect();
                ftys.iter().zip(&names).map(|(t, n)| {
                    let n = n.clone().unwrap_or_default();
                    let v = m.get(n.as_str()).ok_or_else(|| format!("missing field `{n}`"))?;
                    self.term(t, v)
                }).collect()
            }
            (_, J::Arr(xs)) if xs.len() == ftys.len() => ftys.iter().zip(xs).map(|(t, x)| self.term(t, x)).collect(),
            (Shape::Unit, J::Null) => Ok(vec![]),
            _ => Err(format!("bad fields {}", j.render())),
        }
    }

    /// Reads a (normal-form) value of type `t` back as JSON.
    pub fn json(&self, t: &Ty, v: &V) -> Result<J, String> {
        let bool_ = self.env.bool_ind();
        let stuck = |v: &V| format!("the value is stuck (not a normal form): {}", self.show(v));
        Ok(match t.peel_refs() {
            Ty::Bool => match &**v {
                Value::Ctor { ind, ctor, .. } if *ind == bool_ => J::Bool(*ctor == 1),
                _ => return Err(stuck(v)),
            },
            Ty::Uint(_) | Ty::Int => match &**v {
                Value::Lit { n, .. } => J::Num(n.to_string()),
                _ => return Err(stuck(v)),
            },
            Ty::Tuple(ts) if ts.is_empty() => J::Null,
            Ty::Tuple(ts) => match &**v {
                Value::Ctor { args, .. } => J::Arr(ts.iter().zip(args).map(|(t, a)| self.arg(t, a)).collect::<Result<_, _>>()?),
                _ => return Err(stuck(v)),
            },
            Ty::Array(e, _) => match &**v {
                Value::Pair { fst, .. } => J::Arr(self.list_elems(e, fst)?),
                _ => return Err(stuck(v)),
            },
            Ty::Slice(e) => match &**v {
                Value::Pair { snd: Arg::Rel(inner), .. } => match &**inner {
                    Value::Pair { fst, .. } => J::Arr(self.list_elems(e, fst)?),
                    _ => return Err(stuck(v)),
                },
                _ => return Err(stuck(v)),
            },
            Ty::Seq(e) => J::Arr(self.list_elems(e, v)?),
            Ty::Option(e) => match &**v {
                Value::Ctor { ctor: 0, .. } => J::Null,
                Value::Ctor { ctor: 1, args, .. } => J::Obj(vec![("Some".into(), self.arg(e, &args[0])?)]),
                _ => return Err(stuck(v)),
            },
            Ty::Adt(id, targs) => match (&self.krate.item(*id).kind, &**v) {
                (ItemKind::Struct(s), Value::Ctor { args, .. }) => {
                    let ftys: Vec<Ty> = s.fields.iter().map(|f| f.ty.subst(targs)).collect();
                    let vals = ftys.iter().zip(args).map(|(t, a)| self.arg(t, a)).collect::<Result<Vec<_>, _>>()?;
                    match s.shape {
                        Shape::Named => J::Obj(s.fields.iter().zip(vals).map(|(f, x)| (f.name.clone().unwrap_or_default(), x)).collect()),
                        Shape::Tuple => J::Arr(vals),
                        Shape::Unit => J::Null,
                    }
                }
                (ItemKind::Enum(e), Value::Ctor { ctor, args, .. }) => {
                    let var = &e.variants[*ctor as usize];
                    let ftys: Vec<Ty> = var.fields.iter().map(|f| f.ty.subst(targs)).collect();
                    let vals = ftys.iter().zip(args).map(|(t, a)| self.arg(t, a)).collect::<Result<Vec<_>, _>>()?;
                    match var.shape {
                        Shape::Unit => J::Str(var.name.clone()),
                        Shape::Tuple => J::Obj(vec![(var.name.clone(), J::Arr(vals))]),
                        Shape::Named => J::Obj(vec![(var.name.clone(), J::Obj(var.fields.iter().zip(vals).map(|(f, x)| (f.name.clone().unwrap_or_default(), x)).collect()))]),
                    }
                }
                _ => return Err(stuck(v)),
            },
            other => return Err(format!("cannot print a value of type {other:?}")),
        })
    }

    fn arg(&self, t: &Ty, a: &Arg) -> Result<J, String> {
        match a {
            Arg::Rel(v) => self.json(t, v),
            Arg::Irr(_) => Err("irrelevant field".into()),
        }
    }

    fn list_elems(&self, e: &Ty, l: &V) -> Result<Vec<J>, String> {
        let mut out = Vec::new();
        let mut cur = l.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ctor: 0, .. } => return Ok(out),
                Value::Ctor { ctor: 1, args, .. } if args.len() == 2 => {
                    out.push(self.arg(e, &args[0])?);
                    match &args[1] {
                        Arg::Rel(t) => t.clone(),
                        Arg::Irr(_) => return Err("bad list".into()),
                    }
                }
                _ => return Err(format!("list is stuck: {}", self.show(&cur))),
            };
            cur = next;
        }
    }

    /// A short description of a (stuck) value: its head, not a quote of
    /// the whole value (which can be huge: quoting closures re-quotes their
    /// environments).
    fn show(&self, v: &V) -> String {
        match &**v {
            Value::Neu(n) => {
                use sandblaster_kernel::value::Head;
                let head = match &n.head {
                    Head::Global { def, .. } => self.env.global_name(*def).map(|n| format!("`{n}`")).unwrap_or_else(|| "a global".into()),
                    Head::Var(l) => format!("variable #{}", l.0),
                    Head::Prim { op, .. } => format!("primitive {op:?} (out of its domain or on symbolic arguments)"),
                    Head::Absurd { .. } => "`absurd`".into(),
                    Head::Transport { .. } => "a `transport` with non-convertible endpoints".into(),
                    _ => "an axiom or another neutral head".into(),
                };
                format!("a neutral term headed by {head} with {} eliminator(s)", n.spine.len())
            }
            _ => "a value of an unexpected shape".into(),
        }
    }
}
