//! The MIR of a `.sbmir` file as data: the parse of what
//! `sandblaster-mirx` printed. TRUSTED (`docs/checked-structuring.md`,
//! amendment (d)): the literal reading L ([`super::literal`]) reads bodies
//! from this parse, so a misparse changes what L means. Anything malformed
//! is an error, never a guess (no defaults for indices, discriminants or
//! the expected value of an assertion).

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
    /// A `#[repr(simd)]` vector of `core::arch` (`docs/mir-lift.md` §20.9):
    /// its public path (`core::arch::aarch64::uint8x16_t`), and its lane
    /// type and lane count as rustc lays it out (`__m128i` is two `i64`s).
    Simd(String, Box<Ty>, u64),
    /// A raw pointer `(mutable, pointee)` (`*mut T`, `*const T`;
    /// docs/DESIGN-UNSAFE-SIMD.md §1.2: read in crate code only).
    Ptr(bool, Box<Ty>),
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
    /// A union (`(kind union)`): its fields overlap, so it is never read as
    /// the struct its variant lists ([`refuse_union_access`]).
    pub is_union: bool,
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
    /// `&raw mut place` (`true`) / `&raw const place`: a pointer formation
    /// (docs/DESIGN-UNSAFE-SIMD.md §1.3).
    AddrOf(bool, Place),
    Unsupported(String),
}

/// A source position `(file, line, col)`.
pub type Loc = Option<(String, usize, usize)>;

#[derive(Clone, Debug)]
pub enum Stmt {
    Assign(Place, Rvalue, Loc),
    Assume(Operand, Loc),
    /// `StorageLive(l)` (`true`) / `StorageDead(l)`: no meaning for the
    /// readings; printed in the unoptimized window extraction, where the
    /// window rule reads a local's death inside a pointer's window
    /// (docs/DESIGN-UNSAFE-SIMD.md §2.6).
    Storage(bool, usize),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Callee {
    Fn(String),
    Leaf(String, Vec<Ty>),
    Intrinsic(String, Vec<Ty>),
    /// A call of a `core::arch` intrinsic (`docs/mir-lift.md` §20.9).
    Arch(ArchCall),
    Diverge(String),
    Unextracted(String),
    Unsupported(String),
}

/// A call of a `core::arch` intrinsic as `sandblaster-mirx` printed it:
/// never followed into its body, read as the target model of its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchCall {
    /// Its public path (`core::arch::aarch64::vshrq_n_u8`).
    pub path: String,
    /// Its const generic immediates (stdarch's `const N: i32`), by value.
    pub imms: Vec<i128>,
    /// The target features rustc compiles the intrinsic with (its own and
    /// the features they imply).
    pub features: Vec<String>,
    /// Declared safe (a value intrinsic); `false`: an `unsafe fn`.
    pub safe: bool,
    /// A parameter or the result is a raw pointer (a load or a store).
    pub pointer: bool,
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
    /// The target features rustc compiles the body with (`#[target_feature]`
    /// and what it implies; empty: none).
    pub target_features: Vec<String>,
    /// A function of the extracted crate (`(local)`): the narrow reading of
    /// raw pointers applies to crate code only.
    pub local: bool,
    /// A declared `unsafe fn` (`(unsafe)`; a safe `#[target_feature]`
    /// function is not).
    pub unsafe_fn: bool,
    /// The window rule's verdict on each pointer formation of the function
    /// (by the formation's source position and what it calls), set by
    /// `mir::load_window` from the unoptimized extraction (`None`: no window
    /// extraction; every formation is then refused).
    pub window: Option<Vec<super::window::Verdict>>,
}

#[derive(Clone, Debug, Default)]
pub struct Sbmir {
    pub rustc: String,
    pub krate: String,
    pub module: String,
    pub overflow_checks: bool,
    /// rustc's MIR optimization level the MIR was built at
    /// (`-Zmir-opt-level`; `None`: an extraction older than the record).
    pub mir_opt_level: Option<u32>,
    pub exclude: Vec<String>,
    pub sources: Vec<(String, String)>,
    pub roots: Vec<String>,
    pub adts: BTreeMap<String, AdtDef>,
    pub fns: BTreeMap<String, Fn>,
    /// The target the MIR was built for: (LLVM triple, `target_arch`);
    /// `None` for an extraction older than the record (no `core::arch` code
    /// is read from it).
    pub target: Option<(String, String)>,
    /// The extraction prints raw pointers, `&raw`, pointer casts, each
    /// function's locality and `unsafe`, and the target's static facts
    /// (`(unsafe-reading 1)`): the narrow reading of existing `unsafe`
    /// applies to it (an extraction without it is read with the blanket
    /// refusal of `unsafe`).
    pub unsafe_reading: bool,
    /// The statically enabled (stable) target features of the extraction
    /// (`(target-static-features ..)`), its byte order, `-C target-cpu` (as
    /// given, `None`: the target's default) with the target's default CPU,
    /// and `-C target-feature`.
    pub static_features: Option<Vec<String>>,
    pub endian: Option<String>,
    pub target_cpu: Option<(Option<String>, String)>,
    pub target_feature_flags: Option<String>,
    /// The extra rustc flags the crate was compiled with (`(rustflags
    /// "..")`: `extract.sh --rustflags`, for a negative twin only; `None`: an
    /// extraction older than the record).
    pub rustflags: Option<String>,
    /// The extraction's cfg set, read from rustc's session (`(cfg ("name")
    /// ("name" "value") ..)`: the target's, the profile's, the crate's
    /// features and every `--cfg`); `None`: an extraction older than the
    /// record. `mir::load` binds it to the build's.
    pub cfg: Option<Vec<(String, Option<String>)>>,
    /// Every header record (each top-level record but the functions and
    /// the type definitions), as `(its head, its text)`, in order:
    /// `mir::load_window` compares them all but the optimization level.
    pub header: Vec<(String, String)>,
    /// The static features the readings count as facts: the extraction's,
    /// once `mir::load` has checked them equal to the build's own
    /// (`CARGO_CFG_TARGET_FEATURE`) and the flags they come from default
    /// (DESIGN-UNSAFE-SIMD amendment A-S3); `None`: not bound, none count.
    pub static_facts: Option<Vec<String>>,
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
        Some("simd") => {
            let path = t.first().and_then(Sx::str).ok_or_else(|| err("simd", e))?.to_string();
            let lane = ty(t.get(1).ok_or_else(|| err("simd lane type", e))?)?;
            let n = t.get(2).and_then(Sx::num).ok_or_else(|| err("simd lane count", e))? as u64;
            Ty::Simd(path, Box::new(lane), n)
        }
        Some("ptr") => {
            let m = match t.first().and_then(Sx::atom) {
                Some("mut") => true,
                Some("const") => false,
                _ => return Err(err("pointer", e)),
            };
            Ty::Ptr(m, Box::new(ty(t.get(1).ok_or_else(|| err("pointee", e))?)?))
        }
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
            let v = int_value(&t[1])?;
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

/// Statement `i` of `body` is `t = &raw const (fake) P` and the next one but
/// storage markers is `d = PtrMetadata(move t)`, `t` a local: `(d, P)`, and
/// `fused` the index of the second, which the caller skips (TRUSTED: the two
/// are the length of the slice place `P`, `Len(P)`; the fake raw pointer
/// has no other use there, and it is not read again in borrow-checked MIR
/// after its move).
fn fake_metadata(body: &[Sx], i: usize, fused: &mut Option<usize>) -> Result<Option<(Place, Place)>, String> {
    let s = &body[i];
    let (Some("assign"), [t, rv, ..]) = (s.head(), s.tail()) else { return Ok(None) };
    if rv.head() != Some("addr-of") || rv.tail().first().and_then(Sx::atom) != Some("fake") {
        return Ok(None);
    }
    let (t, p) = (place(t)?, place(rv.tail().get(1).ok_or_else(|| err("addr-of place", rv))?)?);
    if !t.proj.is_empty() {
        return Ok(None);
    }
    for (j, n) in body.iter().enumerate().skip(i + 1) {
        match (n.head(), n.tail()) {
            (Some("storage-live" | "storage-dead"), _) => continue,
            (Some("assign"), [d, rv2, ..]) if rv2.head() == Some("un") && rv2.tail().first().and_then(Sx::atom) == Some("ptr-metadata") => {
                return Ok(match rv2.tail().get(1).map(operand).transpose()? {
                    Some(Operand::Move(q)) if q.local == t.local && q.proj.is_empty() => {
                        *fused = Some(j);
                        Some((place(d)?, p))
                    }
                    _ => None,
                });
            }
            _ => return Ok(None),
        }
    }
    Ok(None)
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
        Some("addr-of") => {
            let m = match t.first().and_then(Sx::atom) {
                Some("mut") => true,
                Some("const") => false,
                // (read only fused with the `PtrMetadata` that is its one use:
                // `block_stmts`)
                Some("fake") => return Ok(Rvalue::Unsupported(format!("a raw borrow for its metadata {e} (not followed by its `PtrMetadata`)"))),
                _ => return Err(err("addr-of", e)),
            };
            Rvalue::AddrOf(m, place(t.get(1).ok_or_else(|| err("addr-of place", e))?)?)
        }
        Some("agg") => {
            let k = &t[0];
            let kind = match k.head() {
                Some("tuple") => AggKind::Tuple,
                Some("array") => AggKind::Array(ty(&k.tail()[0])?),
                // a union's aggregate writes one field (`(union-field f)`): not read
                Some("adt") if k.tail().iter().any(|x| x.head() == Some("union-field")) => return Ok(Rvalue::Unsupported(format!("an aggregate of a union {k}"))),
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
        Some("arch") => {
            // `(arch PATH (imms v..) (features "f"..) safe|unsafe value|pointer)`:
            // anything else (an immediate rustc_public could not read) is unsupported
            let path = s0()?;
            let list = |head: &str| t.iter().find(|x| x.head() == Some(head)).map(|x| x.tail().to_vec());
            let (Some(imms), Some(feats)) = (list("imms"), list("features")) else { return Ok(Callee::Unsupported(e.to_string())) };
            let imms: Option<Vec<i128>> = imms.iter().map(|x| x.atom().and_then(|a| a.parse::<i128>().ok())).collect();
            let feats: Option<Vec<String>> = feats.iter().map(|x| x.str().map(str::to_string)).collect();
            let word = |w: &str| t.iter().any(|x| x.atom() == Some(w));
            let safe = match (word("safe"), word("unsafe")) {
                (true, false) => true,
                (false, true) => false,
                _ => return Ok(Callee::Unsupported(e.to_string())),
            };
            let pointer = match (word("pointer"), word("value")) {
                (true, false) => true,
                (false, true) => false,
                _ => return Ok(Callee::Unsupported(e.to_string())),
            };
            match (imms, feats) {
                (Some(imms), Some(features)) => Callee::Arch(ArchCall { path, imms, features, safe, pointer }),
                _ => Callee::Unsupported(e.to_string()),
            }
        }
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
        Some("assert") => {
            // the expected value is `true` or `false`, nothing else (L guards on it)
            let expected = match t[1].atom() {
                Some("true") => true,
                Some("false") => false,
                _ => return Err(err("assert's expected value", e)),
            };
            Term::Assert(operand(&t[0])?, expected, t[2].atom().unwrap_or("?").to_string(), n(3)?)
        }
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
    let mut f = Fn { key, kind: String::new(), def: String::new(), args: vec![], item: Item::Shim, span: None, argc: 0, spread_arg: None, locals: vec![], debug: vec![], blocks: vec![], has_body: true, target_features: vec![], local: false, unsafe_fn: false, window: None };
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
            Some("local") => f.local = true,
            Some("unsafe") => f.unsafe_fn = true,
            Some("target-features") => {
                f.target_features = x.tail().iter().map(|a| a.str().map(str::to_string).ok_or_else(|| err("target feature", x))).collect::<Result<_, _>>()?;
            }
            Some("locals") => {
                for l in x.tail() {
                    let v = l.tail_all();
                    // locals are listed in order (L's slot `i` is local `i`)
                    if v.first().and_then(Sx::num) != Some(f.locals.len() as u128) || v.len() < 2 {
                        return Err(err("locals out of order", l));
                    }
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
                if bt.len() < 2 || bt.first().and_then(Sx::num) != Some(f.blocks.len() as u128) {
                    return Err(err("blocks out of order", x));
                }
                let body = &bt[1..bt.len() - 1];
                let mut stmts = Vec::new();
                // (the statement a fusion replaces the pair with, at the second's index)
                let mut fused: Option<(usize, Stmt)> = None;
                for (i, s) in body.iter().enumerate() {
                    if let Some((j, _)) = &fused
                        && *j == i
                    {
                        stmts.push(fused.take().map(|f| f.1).unwrap());
                        continue;
                    }
                    // `t = &raw const (fake) P; .. d = PtrMetadata(move t)` (only
                    // storage markers between): rustc's length of the slice
                    // place `P` (`s.len()` of a `&mut [T]`, read without a
                    // reborrow): `d = Len(P)`; `t` holds a pointer used for
                    // its metadata only, and is not read again
                    let mut at = None;
                    if let Some((d, p)) = fake_metadata(body, i, &mut at)? {
                        fused = at.map(|j| (j, Stmt::Assign(d, Rvalue::Len(p), loc(s.tail()))));
                        continue;
                    }
                    stmts.push(match s.head() {
                        Some("assign") => Stmt::Assign(place(&s.tail()[0])?, rvalue(&s.tail()[1])?, loc(s.tail())),
                        Some("assume") => Stmt::Assume(operand(&s.tail()[0])?, loc(s.tail())),
                        Some(k @ ("storage-live" | "storage-dead")) => Stmt::Storage(k == "storage-live", s.tail().first().and_then(Sx::num).ok_or_else(|| err("storage marker", s))? as usize),
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
        if !matches!(e.head(), Some("fn" | "adt-def")) {
            m.header.push((e.head().unwrap_or("").to_string(), e.to_string()));
        }
        match e.head() {
            Some("sbmir") => version = t.first().and_then(Sx::num),
            Some("rustc") => m.rustc = t[0].str().unwrap_or("").to_string(),
            Some("crate") => m.krate = t[0].str().unwrap_or("").to_string(),
            Some("module") => m.module = t[0].str().unwrap_or("").to_string(),
            Some("overflow-checks") => m.overflow_checks = t[0].atom() == Some("on"),
            Some("mir-opt-level") => m.mir_opt_level = Some(t.first().and_then(Sx::num).ok_or_else(|| err("mir-opt-level", e))? as u32),
            Some("target") => {
                let (Some(triple), Some(arch)) = (t.first().and_then(Sx::str), t.get(1).and_then(Sx::str)) else { return Err(err("target", e)) };
                m.target = Some((triple.to_string(), arch.to_string()));
            }
            Some("unsafe-reading") => {
                if t.first().and_then(Sx::num) != Some(1) {
                    return Err(err("unsafe-reading version", e));
                }
                m.unsafe_reading = true;
            }
            Some("target-static-features") => m.static_features = Some(t.iter().map(|x| x.str().map(str::to_string).ok_or_else(|| err("static feature", e))).collect::<Result<_, _>>()?),
            Some("endian") => m.endian = Some(t.first().and_then(Sx::atom).ok_or_else(|| err("endian", e))?.to_string()),
            Some("target-cpu") => {
                let given = match t.first() {
                    Some(x) if x.atom() == Some("default") => None,
                    Some(x) => Some(x.str().ok_or_else(|| err("target-cpu", e))?.to_string()),
                    None => return Err(err("target-cpu", e)),
                };
                m.target_cpu = Some((given, t.get(1).and_then(Sx::str).ok_or_else(|| err("target-cpu default", e))?.to_string()));
            }
            Some("target-feature-flags") => m.target_feature_flags = Some(t.first().and_then(Sx::str).ok_or_else(|| err("target-feature-flags", e))?.to_string()),
            Some("rustflags") => m.rustflags = Some(t.first().and_then(Sx::str).ok_or_else(|| err("rustflags", e))?.to_string()),
            Some("cfg") => {
                let entry = |x: &Sx| match x.tail_all() {
                    [Sx::Str(n)] => Ok((n.clone(), None)),
                    [Sx::Str(n), Sx::Str(v)] => Ok((n.clone(), Some(v.clone()))),
                    _ => Err(err("cfg entry", x)),
                };
                m.cfg = Some(t.iter().map(entry).collect::<Result<_, _>>()?);
            }
            Some("exclude") => m.exclude = t.iter().filter_map(Sx::str).map(str::to_string).collect(),
            Some("source") => m.sources.push((t[0].str().unwrap_or("").to_string(), t[1].str().unwrap_or("").to_string())),
            Some("root") => m.roots.push(t[0].str().unwrap_or("").to_string()),
            Some("note") => {}
            Some("adt-def") => {
                let key = t[0].str().unwrap_or("").to_string();
                let mut d = AdtDef { key: key.clone(), path: String::new(), is_enum: false, is_union: false, args: vec![], variants: vec![] };
                for x in &t[1..] {
                    match x.head() {
                        Some("path") => d.path = x.tail()[0].str().unwrap_or("").to_string(),
                        Some("kind") => match x.tail().first().and_then(Sx::atom) {
                            Some("struct") => {}
                            Some("enum") => d.is_enum = true,
                            Some("union") => d.is_union = true,
                            _ => return Err(err("adt kind", x)),
                        },
                        Some("args") => d.args = x.tail().first().map(|a| a.tail_all().iter().map(ty).collect::<Result<Vec<_>, _>>()).transpose()?.unwrap_or_default(),
                        Some("variant") => {
                            let v = x.tail();
                            // variants are listed in order (MIR's variant index is
                            // the position), each with its discriminant
                            let idx = v.first().and_then(Sx::num).ok_or_else(|| err("variant index", x))? as usize;
                            if idx != d.variants.len() {
                                return Err(err("variants out of order", x));
                            }
                            let discr = v.get(2).and_then(Sx::atom).and_then(|a| a.parse().ok()).ok_or_else(|| err("variant discriminant", x))?;
                            let mut var = Variant { idx, name: v.get(1).and_then(Sx::str).ok_or_else(|| err("variant name", x))?.to_string(), discr, fields: vec![], no_glue: false };
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
    // the narrow reading's printer records the rustflags and the cfg set
    // (through `extract.sh`): without them a window extraction or a build
    // of another configuration could not be told apart
    if m.unsafe_reading && (m.rustflags.is_none() || m.cfg.is_none()) {
        return Err("malformed .sbmir: an extraction with `(unsafe-reading 1)` records its rustflags and its cfg set, `(rustflags ..)` and `(cfg ..)` (an extraction older than the records, or made without `extract.sh`: extract it again with `sandblaster/mirx/extract.sh`)".into());
    }
    refuse_union_access(&mut m);
    Ok(m)
}

/// Every access to a union's fields made unsupported, in both readings
/// (stuck in L, refused by S): a field projection of a place of union type
/// (a read, a write or a borrow of the field), a union's aggregate and a
/// constant of union type. A union's fields overlap, so reading one is a
/// type pun (`unsafe` in Rust, possibly in followed library MIR, where the
/// lift's `unsafe` refusal never looks); read as the struct the adt-def
/// lists, it would be a wrong value. A union value moved or copied whole is
/// read as before. A place behind a `Deref` of anything but a reference has
/// no type here: both readings refuse that `Deref` already.
fn refuse_union_access(m: &mut Sbmir) {
    let adts = &m.adts;
    let union = |t: &Ty| matches!(t, Ty::Adt(k) if adts.get(k).is_some_and(|d| d.is_union));
    let place = |locals: &[(Ty, bool)], p: &mut Place| {
        let mut t = locals.get(p.local).map(|l| l.0.clone());
        for pr in p.proj.iter_mut() {
            let Some(cur) = t.take() else { return };
            if union(&cur) && matches!(pr, Proj::Field(..) | Proj::Downcast(_)) {
                *pr = Proj::Unsupported(format!("{pr:?} of a union {cur:?}"));
                return;
            }
            t = match (&*pr, cur) {
                (Proj::Deref, Ty::Ref(_, inner)) => Some(*inner),
                (Proj::Field(_, ft), _) => Some(ft.clone()),
                (Proj::Index(_), Ty::Array(e, _) | Ty::Slice(e)) => Some(*e),
                (Proj::Downcast(_), cur) => Some(cur),
                _ => None,
            };
        }
    };
    fn konst(union: &dyn std::ops::Fn(&Ty) -> bool, c: &mut Const) {
        match c {
            Const::Agg(t, ..) | Const::Zst(t) if union(t) => *c = Const::Unsupported(format!("a constant of a union {t:?}")),
            Const::Agg(_, _, fs) => fs.iter_mut().for_each(|f| konst(union, f)),
            Const::Ref(inner) | Const::Item(_, _, inner) => konst(union, inner),
            _ => {}
        }
    }
    let operand = |locals: &[(Ty, bool)], o: &mut Operand| match o {
        Operand::Copy(p) | Operand::Move(p) => place(locals, p),
        Operand::Const(c) => konst(&union, c),
        Operand::RuntimeChecks(_) => {}
    };
    for f in m.fns.values_mut() {
        let locals = &f.locals;
        for b in f.blocks.iter_mut() {
            for s in b.stmts.iter_mut() {
                match s {
                    Stmt::Assign(p, rv, _) => {
                        place(locals, p);
                        if let Rvalue::Agg(AggKind::Adt(t, _), _) = rv
                            && union(t)
                        {
                            *rv = Rvalue::Unsupported(format!("an aggregate of a union {t:?}"));
                        }
                        match rv {
                            Rvalue::Use(o) | Rvalue::Un(_, o) | Rvalue::Cast(_, o, _) | Rvalue::Repeat(o, _) => operand(locals, o),
                            Rvalue::Bin(_, a, b) | Rvalue::Checked(_, a, b) => {
                                operand(locals, a);
                                operand(locals, b);
                            }
                            Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) | Rvalue::AddrOf(_, p) => place(locals, p),
                            Rvalue::Agg(_, os) => os.iter_mut().for_each(|o| operand(locals, o)),
                            Rvalue::Unsupported(_) => {}
                        }
                    }
                    Stmt::Assume(o, _) => operand(locals, o),
                    Stmt::Storage(..) | Stmt::Unsupported(_) => {}
                }
            }
            match &mut b.term {
                Term::Switch(o, ..) | Term::Assert(o, ..) => operand(locals, o),
                Term::Drop(p, ..) => place(locals, p),
                Term::Call(_, args, dest, _) => {
                    args.iter_mut().for_each(|o| operand(locals, o));
                    place(locals, dest);
                }
                Term::Goto(_) | Term::Return | Term::Unreachable | Term::Resume | Term::Abort | Term::Unsupported(_) => {}
            }
        }
    }
}
