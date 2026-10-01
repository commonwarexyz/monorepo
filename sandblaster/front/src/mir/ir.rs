//! The MIR of a `.sbmir` file as data (untrusted parsing of what
//! `sandblaster-mirx` printed; anything malformed is an error).

use std::collections::BTreeMap;

use super::sexp::Sx;

/// A type as rustc printed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Bool,
    Char,
    /// `(signed, bits)`; `bits` 0 for `usize`/`isize`.
    Int(bool, u32),
    Str,
    Never,
    Unit,
    Tuple(Vec<Ty>),
    Array(Box<Ty>, u64),
    Slice(Box<Ty>),
    /// `(mutable, pointee)`.
    Ref(bool, Box<Ty>),
    /// An ADT by the key of its `adt-def`.
    Adt(String),
    /// A closure: its definition path and the tuple of its captures.
    Closure(String, Box<Ty>),
    /// A function item (zero-sized).
    FnDef(String, Vec<Ty>),
    Unsupported(String),
}

impl Ty {
    pub fn is_int(&self) -> bool {
        matches!(self, Ty::Int(..))
    }
    pub fn signed(&self) -> bool {
        matches!(self, Ty::Int(true, _))
    }
    /// The width in bits (`usize`/`isize`: 64, the only pointer width the
    /// toolchain accepts, DESIGN.md §2).
    pub fn bits(&self) -> Option<u32> {
        match self {
            Ty::Int(_, 0) => Some(64),
            Ty::Int(_, b) => Some(*b),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Variant {
    pub idx: usize,
    pub name: String,
    pub discr: i128,
    pub fields: Vec<(String, Ty)>,
    /// Dropping a value of this variant runs no code (the printer's
    /// `(no-glue)`: no `Drop` impl of the type, no field with drop glue).
    pub no_glue: bool,
}

#[derive(Clone, Debug)]
pub struct AdtDef {
    pub key: String,
    pub path: String,
    pub is_enum: bool,
    pub args: Vec<Ty>,
    pub variants: Vec<Variant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proj {
    Deref,
    Field(usize, Ty),
    Index(usize),
    Downcast(usize),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    pub local: usize,
    pub proj: Vec<Proj>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Const {
    Int(Ty, i128),
    Zst(Ty),
    /// An aggregate constant: its type, variant and fields.
    Agg(Ty, usize, Vec<Const>),
    /// A shared reference to a constant: the pointee.
    Ref(Box<Const>),
    /// A named constant item: the self type of the impl defining it (`None`:
    /// a free item), its name, and its value as rustc evaluated it.
    Item(Option<Ty>, String, Box<Const>),
    Unsupported(String),
}

impl Const {
    /// The value (a named constant item's value; other constants as they are).
    pub fn value(&self) -> &Const {
        match self {
            Const::Item(_, _, v) => v.value(),
            c => c,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Copy(Place),
    Move(Place),
    Const(Const),
    RuntimeChecks(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AggKind {
    Tuple,
    Array(Ty),
    Adt(Ty, usize),
    Closure(Ty),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rvalue {
    Use(Operand),
    Bin(String, Operand, Operand),
    Checked(String, Operand, Operand),
    Un(String, Operand),
    Cast(String, Operand, Ty),
    /// `(kind, place)`: `shared`, `mut` or `fake`.
    Ref(String, Place),
    Discr(Place),
    Len(Place),
    Repeat(Operand, u64),
    Agg(AggKind, Vec<Operand>),
    Unsupported(String),
}

/// A source position `(file, line, col)`.
pub type Loc = Option<(String, usize, usize)>;

#[derive(Clone, Debug)]
pub enum Stmt {
    Assign(Place, Rvalue, Loc),
    Assume(Operand, Loc),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    Fn(String),
    Leaf(String, Vec<Ty>),
    Intrinsic(String, Vec<Ty>),
    Diverge(String),
    Unextracted(String),
    Unsupported(String),
}

#[derive(Clone, Debug)]
pub enum Term {
    Goto(usize),
    Switch(Operand, Vec<(u128, usize)>, usize),
    Return,
    Unreachable,
    Resume,
    Abort,
    /// `(place, has drop glue, target)`.
    Drop(Place, bool, usize),
    /// `(condition, expected, kind, target)`.
    Assert(Operand, bool, String, usize),
    /// `(callee, arguments, destination, target)`.
    Call(Callee, Vec<Operand>, Place, Option<usize>),
    Unsupported(String),
}

#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub term: Term,
    pub term_loc: Loc,
}

/// What an instance is in the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Fn(String),
    Inherent(Ty, String),
    /// `(self type, trait name, trait arguments, method)`.
    Impl(Ty, String, Vec<Ty>, String),
    Closure,
    Shim,
}

#[derive(Clone, Debug)]
pub struct Fn {
    pub key: String,
    pub kind: String,
    pub def: String,
    pub args: Vec<Ty>,
    pub item: Item,
    pub span: Loc,
    pub argc: usize,
    pub spread_arg: Option<usize>,
    /// Type and mutability of every local (`0` is the return place).
    pub locals: Vec<(Ty, bool)>,
    /// User variable names (`(name, local)`, argument index when a parameter).
    pub debug: Vec<(String, usize)>,
    pub blocks: Vec<Block>,
    pub has_body: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Sbmir {
    pub rustc: String,
    pub krate: String,
    pub module: String,
    pub overflow_checks: bool,
    pub exclude: Vec<String>,
    pub sources: Vec<(String, String)>,
    pub roots: Vec<String>,
    pub adts: BTreeMap<String, AdtDef>,
    pub fns: BTreeMap<String, Fn>,
}

fn err(what: &str, e: &Sx) -> String {
    let s = e.to_string();
    let s = if s.len() > 200 { format!("{}..", &s[..200]) } else { s };
    format!("malformed .sbmir: {what}: {s}")
}

pub fn ty(e: &Sx) -> Result<Ty, String> {
    if let Some(a) = e.atom() {
        return Ok(match a {
            "bool" => Ty::Bool,
            "char" => Ty::Char,
            "str" => Ty::Str,
            "never" => Ty::Never,
            "unit" => Ty::Unit,
            "usize" => Ty::Int(false, 0),
            "isize" => Ty::Int(true, 0),
            // a const generic argument (`Arguments::new::<14, 1>`)
            _ if a.chars().all(|c| c.is_ascii_digit()) => Ty::Unsupported(format!("const {a}")),
            _ if a.starts_with('u') || a.starts_with('i') => {
                let bits: u32 = a[1..].parse().map_err(|_| err("type", e))?;
                Ty::Int(a.starts_with('i'), bits)
            }
            _ => return Err(err("type", e)),
        });
    }
    let t = e.tail();
    Ok(match e.head() {
        Some("tuple") => Ty::Tuple(t.iter().map(ty).collect::<Result<_, _>>()?),
        Some("array") => Ty::Array(Box::new(ty(&t[0])?), t.get(1).and_then(Sx::num).ok_or_else(|| err("array length", e))? as u64),
        Some("slice") => Ty::Slice(Box::new(ty(&t[0])?)),
        Some("ref") => Ty::Ref(t.first().and_then(Sx::atom) == Some("mut"), Box::new(ty(t.get(1).ok_or_else(|| err("ref", e))?)?)),
        Some("adt") => Ty::Adt(t.first().and_then(Sx::str).ok_or_else(|| err("adt", e))?.to_string()),
        Some("closure") => Ty::Closure(t.first().and_then(Sx::str).ok_or_else(|| err("closure", e))?.to_string(), Box::new(t.get(1).map(ty).transpose()?.unwrap_or(Ty::Unit))),
        Some("fndef") => Ty::FnDef(t.first().and_then(Sx::str).ok_or_else(|| err("fndef", e))?.to_string(), t.get(1).map(|a| a.tail_all().iter().map(ty).collect::<Result<Vec<_>, _>>()).transpose()?.unwrap_or_default()),
        Some("unsupported") => Ty::Unsupported(t.first().and_then(Sx::str).unwrap_or("?").to_string()),
        _ => return Err(err("type", e)),
    })
}

impl Sx {
    /// All elements of a list (a list whose head is not a word: `(u16 usize)`).
    pub fn tail_all(&self) -> &[Sx] {
        match self {
            Sx::List(v) => v,
            _ => &[],
        }
    }
}

fn place(e: &Sx) -> Result<Place, String> {
    if e.head() != Some("p") {
        return Err(err("place", e));
    }
    let t = e.tail();
    let local = t.first().and_then(Sx::num).ok_or_else(|| err("place local", e))? as usize;
    let mut proj = Vec::new();
    for p in &t[1..] {
        proj.push(match (p.atom(), p.head()) {
            (Some("deref"), _) => Proj::Deref,
            (_, Some("field")) => Proj::Field(p.tail()[0].num().ok_or_else(|| err("field", p))? as usize, ty(&p.tail()[1])?),
            (_, Some("index")) => Proj::Index(p.tail()[0].num().ok_or_else(|| err("index", p))? as usize),
            (_, Some("downcast")) => Proj::Downcast(p.tail()[0].num().ok_or_else(|| err("downcast", p))? as usize),
            _ => Proj::Unsupported(p.to_string()),
        });
    }
    Ok(Place { local, proj })
}

fn int_value(e: &Sx) -> Result<i128, String> {
    let a = e.atom().ok_or_else(|| err("integer", e))?;
    if let Ok(v) = a.parse::<i128>() {
        return Ok(v);
    }
    // an unsigned value above i128::MAX is out of the kernel's widths anyway
    Err(err("integer", e))
}

fn konst(e: &Sx) -> Result<Const, String> {
    let t = e.tail();
    Ok(match e.head() {
        Some("int") => {
            let tt = ty(&t[0])?;
            let v = if tt == Ty::Bool { int_value(&t[1])? } else { int_value(&t[1])? };
            Const::Int(tt, v)
        }
        Some("zst") => Const::Zst(ty(&t[0])?),
        Some("const-ref") => Const::Ref(Box::new(konst(&t[0])?)),
        Some("const-item") => Const::Item(if t[0].atom() == Some("none") { None } else { Some(ty(&t[0])?) }, t[1].str().ok_or_else(|| err("constant item", e))?.to_string(), Box::new(konst(&t[2])?)),
        Some("const-agg") => Const::Agg(ty(&t[0])?, t[1].num().ok_or_else(|| err("variant", e))? as usize, t[2..].iter().map(konst).collect::<Result<_, _>>()?),
        Some("bytes") => Const::Unsupported(format!("constant bytes of {}", t[0])),
        Some("unsupported") => Const::Unsupported(t.first().and_then(Sx::str).unwrap_or("?").to_string()),
        _ => return Err(err("constant", e)),
    })
}

fn operand(e: &Sx) -> Result<Operand, String> {
    let t = e.tail();
    Ok(match e.head() {
        Some("copy") => Operand::Copy(place(&t[0])?),
        Some("move") => Operand::Move(place(&t[0])?),
        Some("runtime-checks") => Operand::RuntimeChecks(t[0].atom().unwrap_or("?").to_string()),
        _ => Operand::Const(konst(e)?),
    })
}

fn rvalue(e: &Sx) -> Result<Rvalue, String> {
    let t = e.tail();
    let w = |i: usize| t.get(i).and_then(Sx::atom).map(str::to_string).ok_or_else(|| err("rvalue", e));
    Ok(match e.head() {
        Some("use") => Rvalue::Use(operand(&t[0])?),
        Some("bin") => Rvalue::Bin(w(0)?, operand(&t[1])?, operand(&t[2])?),
        Some("checked") => Rvalue::Checked(w(0)?, operand(&t[1])?, operand(&t[2])?),
        Some("un") => Rvalue::Un(w(0)?, operand(&t[1])?),
        Some("cast") => Rvalue::Cast(t[0].atom().map(str::to_string).unwrap_or_else(|| t[0].to_string()), operand(&t[1])?, ty(&t[2])?),
        Some("ref") => Rvalue::Ref(w(0)?, place(&t[1])?),
        Some("discr") => Rvalue::Discr(place(&t[0])?),
        Some("len") => Rvalue::Len(place(&t[0])?),
        Some("repeat") => Rvalue::Repeat(operand(&t[0])?, t[1].num().ok_or_else(|| err("repeat", e))? as u64),
        Some("agg") => {
            let k = &t[0];
            let kind = match k.head() {
                Some("tuple") => AggKind::Tuple,
                Some("array") => AggKind::Array(ty(&k.tail()[0])?),
                Some("adt") => AggKind::Adt(ty(&k.tail()[0])?, k.tail()[1].num().ok_or_else(|| err("variant", k))? as usize),
                Some("closure") => AggKind::Closure(ty(&k.tail()[0])?),
                _ => return Ok(Rvalue::Unsupported(k.to_string())),
            };
            Rvalue::Agg(kind, t[1..].iter().map(operand).collect::<Result<_, _>>()?)
        }
        _ => Rvalue::Unsupported(e.to_string()),
    })
}

fn loc(items: &[Sx]) -> Loc {
    items.iter().find(|x| x.head() == Some("at")).map(|a| {
        let t = a.tail();
        (t[0].str().unwrap_or("").to_string(), t[1].num().unwrap_or(0) as usize, t[2].num().unwrap_or(0) as usize)
    })
}

fn callee(e: &Sx) -> Result<Callee, String> {
    let t = e.tail();
    let s0 = || t.first().and_then(Sx::str).map(str::to_string).ok_or_else(|| err("callee", e));
    let tys = |i: usize| -> Result<Vec<Ty>, String> { t.get(i).map(|a| a.tail_all().iter().map(ty).collect()).transpose().map(Option::unwrap_or_default) };
    Ok(match e.head() {
        Some("fn") => Callee::Fn(s0()?),
        Some("leaf") => Callee::Leaf(s0()?, tys(1)?),
        Some("intrinsic") => Callee::Intrinsic(s0()?, tys(1)?),
        Some("diverge") => Callee::Diverge(s0()?),
        Some("unextracted") => Callee::Unextracted(s0()?),
        _ => Callee::Unsupported(e.to_string()),
    })
}

fn term(e: &Sx) -> Result<Term, String> {
    let t = e.tail();
    let n = |i: usize| t.get(i).and_then(Sx::num).map(|v| v as usize).ok_or_else(|| err("block number", e));
    Ok(match e.head() {
        Some("goto") => Term::Goto(n(0)?),
        Some("switch") => {
            let d = operand(&t[0])?;
            let mut arms = Vec::new();
            let mut otherwise = None;
            for a in &t[1..] {
                if a.head() == Some("otherwise") {
                    otherwise = a.tail()[0].num().map(|v| v as usize);
                } else if a.head() == Some("at") {
                } else {
                    let v = a.tail_all();
                    arms.push((v[0].num().ok_or_else(|| err("switch value", a))?, v[1].num().ok_or_else(|| err("switch target", a))? as usize));
                }
            }
            Term::Switch(d, arms, otherwise.ok_or_else(|| err("switch otherwise", e))?)
        }
        Some("return") => Term::Return,
        Some("unreachable") => Term::Unreachable,
        Some("resume") => Term::Resume,
        Some("abort") => Term::Abort,
        Some("drop") => Term::Drop(place(&t[0])?, t[1].atom() != Some("no-glue"), n(2)?),
        Some("assert") => Term::Assert(operand(&t[0])?, t[1].atom() == Some("true"), t[2].atom().unwrap_or("?").to_string(), n(3)?),
        Some("call") => {
            let c = callee(&t[0])?;
            let args = t[1].tail().iter().map(operand).collect::<Result<_, _>>()?;
            let dest = place(&t[2])?;
            let tgt = t[3].num().map(|v| v as usize);
            Term::Call(c, args, dest, tgt)
        }
        _ => Term::Unsupported(e.to_string()),
    })
}

fn item(e: &Sx) -> Result<Item, String> {
    let t = e.tail();
    Ok(match t.first().and_then(Sx::atom) {
        Some("fn") => Item::Fn(t[1].str().unwrap_or("").to_string()),
        Some("inherent") => Item::Inherent(ty(&t[1])?, t[2].str().unwrap_or("").to_string()),
        // a trait's provided method at a self type reads like that type's
        // impl of the method (the lift names both `Self::m`)
        Some("impl") | Some("provided") => Item::Impl(ty(&t[1])?, t[2].str().unwrap_or("").to_string(), t[3].tail_all().iter().map(ty).collect::<Result<_, _>>()?, t[4].str().unwrap_or("").to_string()),
        Some("closure") => Item::Closure,
        _ => Item::Shim,
    })
}

fn function(e: &Sx) -> Result<Fn, String> {
    let t = e.tail();
    let key = t.first().and_then(Sx::str).ok_or_else(|| err("fn key", e))?.to_string();
    let mut f = Fn { key, kind: String::new(), def: String::new(), args: vec![], item: Item::Shim, span: None, argc: 0, spread_arg: None, locals: vec![], debug: vec![], blocks: vec![], has_body: true };
    for x in &t[1..] {
        match x.head() {
            Some("kind") => f.kind = x.tail()[0].atom().unwrap_or("").to_string(),
            Some("def") => f.def = x.tail()[0].str().unwrap_or("").to_string(),
            Some("args") => f.args = x.tail().first().map(|a| a.tail_all().iter().map(ty).collect::<Result<Vec<_>, _>>()).transpose()?.unwrap_or_default(),
            Some("item") => f.item = item(x)?,
            Some("span") => f.span = Some((x.tail()[0].str().unwrap_or("").to_string(), x.tail()[1].num().unwrap_or(0) as usize, x.tail()[2].num().unwrap_or(0) as usize)),
            Some("argc") => f.argc = x.tail()[0].num().unwrap_or(0) as usize,
            Some("spread-arg") => f.spread_arg = x.tail()[0].num().map(|v| v as usize),
            Some("nobody") => f.has_body = false,
            Some("locals") => {
                for l in x.tail() {
                    let v = l.tail_all();
                    f.locals.push((ty(&v[1])?, v.get(2).and_then(Sx::atom) == Some("mut")));
                }
            }
            Some("debug") => {
                let name = x.tail()[0].str().unwrap_or("").to_string();
                let p = place(&x.tail()[1])?;
                if p.proj.is_empty() {
                    f.debug.push((name, p.local));
                }
            }
            Some("debug-other") => {}
            Some("bb") => {
                let bt = x.tail();
                if bt.first().and_then(Sx::num) != Some(f.blocks.len() as u128) {
                    return Err(err("blocks out of order", x));
                }
                let mut stmts = Vec::new();
                for s in &bt[1..bt.len() - 1] {
                    stmts.push(match s.head() {
                        Some("assign") => Stmt::Assign(place(&s.tail()[0])?, rvalue(&s.tail()[1])?, loc(s.tail())),
                        Some("assume") => Stmt::Assume(operand(&s.tail()[0])?, loc(s.tail())),
                        _ => Stmt::Unsupported(s.to_string()),
                    });
                }
                let te = bt.last().ok_or_else(|| err("block", x))?;
                f.blocks.push(Block { stmts, term: term(te)?, term_loc: loc(te.tail()) });
            }
            _ => {}
        }
    }
    Ok(f)
}

/// Parses a `.sbmir` file.
pub fn parse(text: &str) -> Result<Sbmir, String> {
    let top = super::sexp::parse(text)?;
    let mut m = Sbmir::default();
    let mut version = None;
    for e in &top {
        let t = e.tail();
        match e.head() {
            Some("sbmir") => version = t.first().and_then(Sx::num),
            Some("rustc") => m.rustc = t[0].str().unwrap_or("").to_string(),
            Some("crate") => m.krate = t[0].str().unwrap_or("").to_string(),
            Some("module") => m.module = t[0].str().unwrap_or("").to_string(),
            Some("overflow-checks") => m.overflow_checks = t[0].atom() == Some("on"),
            Some("exclude") => m.exclude = t.iter().filter_map(Sx::str).map(str::to_string).collect(),
            Some("source") => m.sources.push((t[0].str().unwrap_or("").to_string(), t[1].str().unwrap_or("").to_string())),
            Some("root") => m.roots.push(t[0].str().unwrap_or("").to_string()),
            Some("note") => {}
            Some("adt-def") => {
                let key = t[0].str().unwrap_or("").to_string();
                let mut d = AdtDef { key: key.clone(), path: String::new(), is_enum: false, args: vec![], variants: vec![] };
                for x in &t[1..] {
                    match x.head() {
                        Some("path") => d.path = x.tail()[0].str().unwrap_or("").to_string(),
                        Some("kind") => d.is_enum = x.tail()[0].atom() == Some("enum"),
                        Some("args") => d.args = x.tail().first().map(|a| a.tail_all().iter().map(ty).collect::<Result<Vec<_>, _>>()).transpose()?.unwrap_or_default(),
                        Some("variant") => {
                            let v = x.tail();
                            let mut var = Variant { idx: v[0].num().unwrap_or(0) as usize, name: v[1].str().unwrap_or("").to_string(), discr: v[2].atom().and_then(|a| a.parse().ok()).unwrap_or(0), fields: vec![], no_glue: false };
                            for f in &v[3..] {
                                match f.head() {
                                    Some("field") => var.fields.push((f.tail()[0].str().unwrap_or("").to_string(), ty(&f.tail()[1])?)),
                                    Some("no-glue") => var.no_glue = true,
                                    _ => return Err(err("variant", f)),
                                }
                            }
                            d.variants.push(var);
                        }
                        _ => {}
                    }
                }
                m.adts.insert(key, d);
            }
            Some("fn") => {
                let f = function(e)?;
                m.fns.insert(f.key.clone(), f);
            }
            _ => return Err(err("top-level form", e)),
        }
    }
    if version != Some(1) {
        return Err(format!(".sbmir format version {version:?}; this reader reads version 1"));
    }
    Ok(m)
}
