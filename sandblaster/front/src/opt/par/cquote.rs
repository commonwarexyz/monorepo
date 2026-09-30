//! Checkable core text of the scalar values the lane functor copies into
//! its kernels and proofs (the lane leaves, the site's lane arguments).
//!
//! `Env::quote` leaves the Σ types of pairs and some irrelevant proofs as
//! `Erased` (values do not store them), so a quoted term cannot be checked
//! again. The lane functor needs only a few value shapes — parameters,
//! element reads at literal indices, `uN::from_le_bytes` of a byte array
//! literal, word primitives, literals — and writes them back here with
//! their types and literal-index proofs (`.refl(Bool, true)`). Any other
//! shape is refused (the site is then not liftable).

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{PrimOp, Width};
use sandblaster_kernel::value::{Arg, Elim, Head, V, Value};

/// The shape of a parameter or value type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    Word(Width),
    Array(Box<Shape>, u64),
}

impl Shape {
    /// Core text of the type.
    pub fn text(&self) -> String {
        match self {
            Shape::Word(w) => wname(*w).to_string(),
            Shape::Array(e, n) => {
                let et = e.text();
                let et = if et.contains(' ') { format!("({et})") } else { et };
                format!("Array {et} {n}usize")
            }
        }
    }

    /// Parses the printed core type (`Array (Array U8 64usize) 16usize`).
    pub fn parse(s: &str) -> Option<Shape> {
        let toks: Vec<String> = s.replace('(', " ( ").replace(')', " ) ").split_whitespace().map(|t| t.to_string()).collect();
        let mut i = 0;
        let r = parse_shape(&toks, &mut i)?;
        (i == toks.len()).then_some(r)
    }
}

fn parse_shape(t: &[String], i: &mut usize) -> Option<Shape> {
    let tok = t.get(*i)?.as_str();
    *i += 1;
    match tok {
        "(" => {
            let s = parse_shape(t, i)?;
            (t.get(*i)?.as_str() == ")").then_some(())?;
            *i += 1;
            Some(s)
        }
        "Array" => {
            let e = parse_shape(t, i)?;
            let n: u64 = t.get(*i)?.strip_suffix("usize")?.parse().ok()?;
            *i += 1;
            Some(Shape::Array(Box::new(e), n))
        }
        w => Some(Shape::Word(width(w)?)),
    }
}

fn width(s: &str) -> Option<Width> {
    Some(match s {
        "U8" => Width::U8,
        "U16" => Width::U16,
        "U32" => Width::U32,
        "U64" => Width::U64,
        "Usize" => Width::Usize,
        _ => return None,
    })
}

pub fn wname(w: Width) -> &'static str {
    match w {
        Width::U8 => "U8",
        Width::U16 => "U16",
        Width::U32 => "U32",
        Width::U64 => "U64",
        Width::Usize => "Usize",
        Width::Int => "Int",
    }
}

pub fn wsuffix(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        Width::Usize => "usize",
        Width::Int => "int",
    }
}

/// The checkable quoter over a context of named, shaped variables
/// (levels `0..`).
pub struct CQuote<'a> {
    pub env: &'a Env,
    pub vars: Vec<(String, Shape)>,
}

impl CQuote<'_> {
    /// `(text, shape)` of a value.
    pub fn quote(&self, v: &V) -> Result<(String, Shape), String> {
        match &**v {
            Value::Lit { w, n } if *w != Width::Int => Ok((format!("{}{}", n, wsuffix(*w)), Shape::Word(*w))),
            Value::Neu(n) => match (&n.head, n.spine.as_slice()) {
                (Head::Var(l), []) => self.vars.get(l.0 as usize).map(|(n, s)| (n.clone(), s.clone())).ok_or_else(|| "a variable outside the context".to_string()),
                (Head::Global { def, args }, []) => {
                    let name = self.env.global_name(*def).map(|s| s.to_string()).unwrap_or_default();
                    let rel: Vec<&V> = args.iter().filter_map(|a| if let Arg::Rel(x) = a { Some(x) } else { None }).collect();
                    match name.as_str() {
                        "seq::index" if rel.len() == 3 => {
                            let k = match &**rel[2] {
                                Value::Lit { n, .. } => n.to_u64().ok_or("a negative index")?,
                                _ => return Err("an element read at a symbolic index".into()),
                            };
                            let (base, shape) = self.list_base(rel[1])?;
                            let Shape::Array(e, len) = shape else { return Err("an element read of a non-array".into()) };
                            Ok((format!("array::index {} {len}usize ({base}) {k}usize .refl(Bool, true)", elem_text(&e)), *e))
                        }
                        "u16::from_le_bytes" | "u32::from_le_bytes" | "u64::from_le_bytes" if rel.len() == 1 => {
                            let w = match name.as_str() {
                                "u16::from_le_bytes" => Width::U16,
                                "u32::from_le_bytes" => Width::U32,
                                _ => Width::U64,
                            };
                            let (a, _) = self.array_lit(rel[0], &Shape::Word(Width::U8))?;
                            Ok((format!("{name} ({a})"), Shape::Word(w)))
                        }
                        _ => Err(format!("a stuck application of `{name}`")),
                    }
                }
                (Head::Prim { op, args, .. }, []) => {
                    let (opn, res) = prim(*op).ok_or_else(|| format!("primitive {op:?}"))?;
                    let parts: Vec<String> = args.iter().map(|a| self.quote(a).map(|(t, _)| t)).collect::<Result<_, _>>()?;
                    Ok((format!("#{opn}({})", parts.join(", ")), Shape::Word(res)))
                }
                _ => Err("an unsupported neutral".into()),
            },
            Value::Pair { .. } => Err("an array value outside a known position".into()),
            _ => Err("an unsupported value".into()),
        }
    }

    /// `fst x` of an array-typed neutral `x`: `x`'s text and shape.
    fn list_base(&self, lv: &V) -> Result<(String, Shape), String> {
        let Value::Neu(n) = &**lv else { return Err("an element read of a literal list".into()) };
        let [Elim::Fst] = n.spine.as_slice() else { return Err("an element read of an unexpected list".into()) };
        let inner = std::rc::Rc::new(Value::Neu(sandblaster_kernel::value::Neutral { head: clone_head(&n.head), spine: vec![] }));
        self.quote(&inner)
    }

    /// An array literal value with elements of shape `e`.
    fn array_lit(&self, v: &V, e: &Shape) -> Result<(String, Shape), String> {
        let Value::Pair { fst, .. } = &**v else { return Err("not an array literal".into()) };
        let mut xs = Vec::new();
        let mut cur = fst.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ctor: 0, args, .. } if args.is_empty() => break,
                Value::Ctor { ctor: 1, args, .. } if args.len() == 2 => match (&args[0], &args[1]) {
                    (Arg::Rel(h), Arg::Rel(t)) => {
                        xs.push(self.quote(h)?.0);
                        t.clone()
                    }
                    _ => return Err("an irrelevant list element".into()),
                },
                _ => return Err("not a literal list".into()),
            };
            cur = next;
        }
        let et = elem_text(e);
        let mut list = format!("Nil[{et}]");
        for x in xs.iter().rev() {
            list = format!("Cons[{et}]({x}, {list})");
        }
        let n = xs.len() as u64;
        Ok((format!("pair(Array {et} {n}usize, {list}, refl(Int, {n}int))"), Shape::Array(Box::new(e.clone()), n)))
    }
}

fn elem_text(e: &Shape) -> String {
    let t = e.text();
    if t.contains(' ') { format!("({t})") } else { t }
}

/// A shallow copy of a neutral head (values are immutable; the head is
/// rebuilt with shared children).
fn clone_head(h: &Head) -> Head {
    match h {
        Head::Var(l) => Head::Var(*l),
        Head::Global { def, args } => Head::Global { def: *def, args: args.clone() },
        Head::Prim { op, args, proofs } => Head::Prim { op: *op, args: args.clone(), proofs: proofs.clone() },
        Head::Absurd { ty } => Head::Absurd { ty: ty.clone() },
        Head::Transport { ty, lhs, rhs, motive, val } => Head::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), motive: motive.clone(), val: val.clone() },
        Head::Axiom { ax, args } => Head::Axiom { ax: *ax, args: args.clone() },
    }
}

/// The name and result width of a total primitive (checked shifts are
/// written as the wrapping ones: the same function, §5.7).
fn prim(op: PrimOp) -> Option<(String, Width)> {
    use PrimOp::*;
    let s = |n: &str, w: Width| (format!("{n}_{}", wsuffix(w)), w);
    Some(match op {
        WAdd(w) => s("wadd", w),
        WSub(w) => s("wsub", w),
        WMul(w) => s("wmul", w),
        And(w) => s("and", w),
        Or(w) => s("or", w),
        Xor(w) => s("xor", w),
        Not(w) => s("not", w),
        WShl(w) | Shl(w) => s("wshl", w),
        WShr(w) | Shr(w) => s("wshr", w),
        Rotl(w) => s("rotl", w),
        Rotr(w) => s("rotr", w),
        Cast { from, to } if from != Width::Int && to != Width::Int => (format!("cast_{}_{}", wsuffix(from), wsuffix(to)), to),
        _ => return None,
    })
}
