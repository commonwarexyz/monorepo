//! The structured reading S of a MIR body (UNTRUSTED since
//! `docs/checked-structuring.md`; `docs/mir-lift.md` §20.3): one
//! monomorphized MIR body to exec-subset Rust. It only proposes S: every
//! verified build checks, for each lifted function, the kernel theorem
//! `L::thm::f` that the literal reading L of the same MIR (`literal.rs`,
//! trusted) returns S's value (`driver::gates::theorem_gate`). A bug here
//! makes a theorem unprovable and the build fail; it cannot change what a
//! verified module means. It cannot reach the function's contract either:
//! it sees the signature only, and the theorem's preconditions are the
//! declared contract's (`stmt.rs`).
//!
//! The reading is a walk of the control-flow graph from the entry block
//! that follows its edges exactly:
//!
//! * **statements** become `let`s and assignments in order; a value that is
//!   pure and total (a variable, a constant, a comparison, a bit operation,
//!   an unsigned cast, a constructor of such values) is carried forward as an
//!   expression instead of being bound (it has no obligation, so where it is
//!   evaluated does not matter); a variable it reads is never reassigned
//!   while it is carried (the value is bound first);
//! * **checked arithmetic** (`CheckedAdd` and the `assert` of its overflow
//!   flag) is the subset's operator, whose obligation is exactly that flag
//!   being false; `Assert` terminators are `if !c { unreachable!() }`
//!   obligations, except the index, shift and division checks that the next
//!   operation's own obligation states word for word;
//! * **switches** become `if`/`match`; a switch on the discriminant of a
//!   value whose constructor is known on this path takes that arm;
//! * **calls** of lifted functions of the module are calls by name with
//!   state passing (`&mut` arguments are passed by value and assigned back);
//!   calls of library functions and closures are **inlined** (their MIR,
//!   extracted from the same compiler, read the same way, with their return
//!   continuing the caller); the buffer traits, array and slice indexing,
//!   and a short list of integer methods are **leaves** read as the buffer
//!   model and the subset's builtins; a function returning `!` is
//!   `unreachable!()`;
//! * **references**: `&x` is the value of `x` (rustc's borrow checker keeps
//!   `x` unchanged while the shared borrow lives); `&mut x` is `x` as a place:
//!   writes through it assign `x`;
//! * **loops** (back edges): a loop whose header only computes a condition
//!   and whose only exit is that test becomes `while c { .. }`; any other
//!   loop becomes a tail-recursive helper over the variables live at its
//!   header; a loop attachment places its measure, invariant, summary and
//!   proof steps as SEMANTICS.md §19.2 and §19.9 place them.
//!
//! The structure (where an `if` rejoins) comes from post-dominators
//! (`cfg.rs`), which only decide the shape; the reading of every edge is
//! the edge's own. Anything else is refused with a message.

use std::collections::{BTreeSet, HashMap};

use proc_macro2::{Span as PSpan, TokenStream};
use quote::{format_ident, quote, ToTokens};

use super::cfg::Cfg;
use super::ir::*;

/// A module function called by name (`write__u16`, `Decoder__u16::feed`).
#[derive(Clone, Debug)]
pub struct LiftedCallee {
    pub path: syn::Expr,
    /// Argument positions passed as states (`&mut` parameters).
    pub states: Vec<usize>,
    pub has_ret: bool,
    /// No precondition: a call without states is a total expression (the
    /// callee's own obligations are proven in the callee), carried like any
    /// pure value.
    pub total: bool,
    /// Argument positions the lifted callee takes by value although MIR
    /// passes `&T` (a `&self` receiver).
    pub by_value: Vec<usize>,
}

/// How a constructor is written.
#[derive(Clone, Debug)]
pub struct Ctor {
    pub path: syn::Path,
    /// Field names (`0`, `1`, .. for tuple-like).
    pub fields: Vec<String>,
    pub named: bool,
}

/// The names of the module and its dependencies in the subset.
pub trait Names {
    fn ty(&self, m: &Sbmir, t: &Ty) -> Result<syn::Type, String>;
    fn ctor(&self, m: &Sbmir, adt: &str, variant: usize) -> Result<Ctor, String>;
    /// A module function's lifted callee (`None`: not a lifted function).
    fn lifted(&self, m: &Sbmir, f: &Fn) -> Option<LiftedCallee>;
    /// The lifted constant a named constant item stands for (the constant
    /// function `Family__MAX_NODES()` of an impl's associated constant),
    /// `None`: read its value.
    fn const_item(&self, _m: &Sbmir, _owner: Option<&Ty>, _name: &str) -> Option<syn::Expr> {
        None
    }
    /// Whether a module struct carries an invariant (SEMANTICS.md §15.3).
    fn has_invariant(&self, _m: &Sbmir, _adt: &str) -> bool {
        false
    }
    /// Whether a library newtype is read as its one field (a host model
    /// `pub type T = ..;`, SEMANTICS.md §19.10).
    fn transparent(&self, _m: &Sbmir, _adt: &str) -> bool {
        false
    }
    /// The host model's method `m` at a library type (the instance of an
    /// open trait whose instance is a host model): `crate::..::Sha256::hash`.
    fn host_method(&self, _m: &Sbmir, _self_ty: &Ty, _method: &str) -> Option<syn::Expr> {
        None
    }
}

/// `Option<&mut T>` (a state of §19.10's table): `T`.
pub fn opt_mut(m: &Sbmir, t: &Ty) -> Option<Ty> {
    let Ty::Adt(k) = t else { return None };
    let d = m.adts.get(k)?;
    match d.args.as_slice() {
        [Ty::Ref(true, inner)] if d.path.ends_with("option::Option") => Some((**inner).clone()),
        _ => None,
    }
}

/// A processed loop attachment (the lift's ghost reading of it).
#[derive(Clone, Debug, Default)]
pub struct LoopAttach {
    pub decreases: Option<syn::Expr>,
    pub invariants: Vec<syn::Expr>,
    pub ensures: Vec<syn::Expr>,
    pub at_start: Vec<syn::Stmt>,
    pub steps: Vec<syn::Stmt>,
    pub at_end: Vec<syn::Stmt>,
    pub after: Vec<syn::Stmt>,
}

/// What the lift knows about the function being read.
pub struct Spec<'a> {
    pub key: &'a str,
    pub lifted_name: &'a str,
    /// The lifted parameters' names, in order (receiver first).
    pub params: Vec<String>,
    /// Parameter positions that are states, in the lift's order.
    pub states: Vec<usize>,
    pub has_ret: bool,
    /// The lifted function's result type.
    pub out_ty: syn::Type,
    /// Loop attachments by loop number (source order).
    pub loops: HashMap<usize, LoopAttach>,
    /// Parameter positions the lift keeps as `&T` (the others of MIR type
    /// `&T` — a `&self` receiver — the lift takes by value).
    pub ref_params: Vec<usize>,
}

pub struct ReadOut {
    pub body: syn::Block,
    pub helpers: Vec<syn::Item>,
    /// `(loop number, form)`.
    pub loops: Vec<(usize, String)>,
    /// Parameters the body assigns (`mut` in the signature).
    pub assigned_params: Vec<usize>,
    /// Each loop helper (innermost first): what its loop lemma is stated
    /// over (`crate::mir::checked`; a hint, never trusted).
    pub helper_info: Vec<HelperInfo>,
}

/// A loop helper as the reading built it: its name, whether it is a method
/// of the impl, the loop header's block and the MIR locals its parameters
/// carry (in order). A `while` loop (the elaborator's helper `loop#k`, `k`
/// its index among the function's `while` loops) has no parameters here:
/// the elaborator's helper names its parameters by the source names, which
/// `local_names` gives per MIR local.
#[derive(Clone, Debug)]
pub struct HelperInfo {
    pub name: String,
    pub method: bool,
    pub header: usize,
    pub params: Vec<usize>,
    pub while_loop: bool,
    pub local_names: Vec<String>,
}

/// The names and subset types of the root function's locals (the lift
/// binds them to read attachments).
pub fn root_locals(m: &Sbmir, nm: &dyn Names, key: &str, params: &[String]) -> Result<Vec<(String, Option<syn::Type>)>, String> {
    let f = m.fns.get(key).ok_or_else(|| format!("no MIR for `{key}`"))?;
    let names = local_names(f, params, true);
    Ok(names.iter().enumerate().map(|(i, n)| (n.clone(), value_ty(&f.locals[i].0).and_then(|t| nm.ty(m, &t).ok()))).collect())
}

/// For each loop (in source order), the reading's name of the variable that
/// a source name denotes at the loop's header, where a user variable
/// shadows a parameter or another variable of the same name (`let size =
/// *size;`: `size` → `size_2`): loop attachments are written against the
/// source's scopes. The variable of that name live at the header is the one
/// in scope there. (Attachments are proof steps and checked contracts of the
/// helper, so this choice cannot change what is proven about the code.)
pub fn loop_scopes(m: &Sbmir, key: &str, params: &[String]) -> Result<Vec<HashMap<String, String>>, String> {
    let f = m.fns.get(key).ok_or_else(|| format!("no MIR for `{key}`"))?;
    let names = local_names(f, params, true);
    let cfg = Cfg::new(f);
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, p) in params.iter().enumerate().take(f.argc) {
        by_name.entry(p.clone()).or_default().push(i + 1);
    }
    for (n, l) in &f.debug {
        if *l > f.argc && !by_name.get(n).is_some_and(|v| v.contains(l)) {
            by_name.entry(n.clone()).or_default().push(*l);
        }
    }
    Ok(cfg
        .headers
        .iter()
        .map(|h| {
            let mut map = HashMap::new();
            for (n, ls) in &by_name {
                let live: Vec<usize> = ls.iter().copied().filter(|l| cfg.live_in[*h].contains(l)).collect();
                if ls.len() > 1 && live.len() == 1 && names[live[0]] != *n {
                    map.insert(n.clone(), names[live[0]].clone());
                }
            }
            map
        })
        .collect())
}

/// The value type of a local (`&T` is `T`).
fn value_ty(t: &Ty) -> Option<Ty> {
    match t {
        Ty::Ref(true, _) => None,
        other => Some(other.clone()),
    }
}

fn local_names(f: &Fn, params: &[String], root: bool) -> Vec<String> {
    let mut count: HashMap<&str, usize> = HashMap::new();
    for (n, l) in &f.debug {
        if *l > f.argc {
            *count.entry(n.as_str()).or_default() += 1;
        }
    }
    (0..f.locals.len())
        .map(|i| {
            if i >= 1 && i <= f.argc && root {
                return params.get(i - 1).cloned().unwrap_or_else(|| format!("_{i}"));
            }
            if root && i > f.argc {
                let named: Vec<&String> = f.debug.iter().filter(|(_, l)| *l == i).map(|(n, _)| n).collect();
                if let Some(n) = named.first() {
                    // a name shared with a parameter or another local gets the
                    // local's number (`let pos = *pos;` reads as `pos_2`)
                    let clash = params.iter().any(|p| p == *n) || n.as_str() == "self";
                    return if count.get(n.as_str()).copied().unwrap_or(0) == 1 && !clash { (*n).clone() } else { format!("{n}_{i}") };
                }
            }
            format!("_{i}")
        })
        .collect()
}

type Key = (usize, usize);

/// A value on the current path.
#[derive(Clone, Debug)]
enum Val {
    /// A pure, total expression.
    E(syn::Expr),
    /// A constructor (a tuple, a struct or an enum variant) of values.
    C(Ty, usize, Vec<Val>),
    /// A zero-sized value (unit, a function item, a closure without captures).
    Z(Ty),
    /// A shared reference to a value (`&x`: `*` of it is `x`).
    R(Box<Val>),
    /// A known integer that has no subset type (a discriminant of a known
    /// constructor): only compared with constants.
    K(i128),
    /// A constant the reading has no expression for (a panic message):
    /// fine to pass along to what never reads it, refused as data.
    Opaque(String),
}

/// A `&mut` place: the lvalue expression it stands for.
#[derive(Clone, Debug)]
struct LRef {
    lv: syn::Expr,
    buf: Option<&'static str>,
    /// A state of a struct type with an invariant, held field by field in
    /// variables while the body runs (`__self_two_h`): its field writes
    /// break the invariant between them, so the value is only built whole
    /// where it leaves (a return, a call, a loop helper's call), as the
    /// source lift does. `(struct ADT key, field variables)`.
    fields: Option<(String, Vec<String>)>,
    /// The place is a field of type `&mut T` of an optional state, held as
    /// the `T` it points to ([`Env::writeback`]): `*r` of a reference to it
    /// is that same `T`.
    inner: bool,
}

#[derive(Clone, Default)]
struct Env {
    vals: HashMap<Key, Val>,
    refs: HashMap<Key, LRef>,
    discr: HashMap<Key, (usize, Place)>,
    declared: BTreeSet<String>,
    /// Root variables whose known constructor has a field held in its own
    /// mutable variable (a `&mut` into the field of a matched enum, `if let
    /// Some(ref mut v) = o`): the variable is assigned the rebuilt value
    /// where the path leaves the arm.
    writeback: BTreeSet<Key>,
    /// Named variables that hold their current value in their own name
    /// although it is carried as a known constructor (bound by `let x = C;`
    /// and not assigned since): the value is in its name already.
    holds: BTreeSet<Key>,
}

enum Flow {
    Diverge,
    Fall(Env),
    /// The condition of a probed loop header: `(cond, target when true,
    /// target when false, env)`.
    Cond(syn::Expr, usize, usize, Env),
}

#[derive(Clone)]
enum K {
    Ret,
    Back { caller: usize, dest: Place, target: Option<usize>, stop: Option<usize>, next: Box<K> },
}

/// The locals an rvalue reads.
fn rv_locals(r: &Rvalue, out: &mut Vec<usize>) {
    let op = |o: &Operand, out: &mut Vec<usize>| {
        if let Operand::Copy(p) | Operand::Move(p) = o {
            out.push(p.local);
        }
    };
    match r {
        Rvalue::Use(o) | Rvalue::Un(_, o) | Rvalue::Cast(_, o, _) | Rvalue::Repeat(o, _) => op(o, out),
        Rvalue::Bin(_, a, b) | Rvalue::Checked(_, a, b) => {
            op(a, out);
            op(b, out);
        }
        Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) => out.push(p.local),
        Rvalue::Agg(_, ops) => ops.iter().for_each(|o| op(o, out)),
        Rvalue::Unsupported(_) => {}
    }
}

fn kdepth(k: &K) -> usize {
    match k {
        K::Ret => 0,
        K::Back { next, .. } => 1 + kdepth(next),
    }
}

#[derive(Clone)]
enum LoopForm {
    While,
    /// The helper as called (`f__loop0`, `Self::m__loop0`) and its parameters.
    Helper(syn::Expr, Vec<usize>),
}

#[derive(Clone)]
struct Cx {
    k: K,
    stop: Option<usize>,
    loops: Vec<(usize, LoopForm)>,
    probe: bool,
}

struct Frame<'m> {
    f: &'m Fn,
    names: Vec<String>,
    root: bool,
    /// Assignment sites per local (a named variable assigned more than once is `mut`).
    assigns: Vec<usize>,
}

struct Reader<'m> {
    m: &'m Sbmir,
    nm: &'m dyn Names,
    spec: &'m Spec<'m>,
    frames: Vec<Frame<'m>>,
    cfg: Cfg,
    fresh: usize,
    helpers: Vec<syn::Item>,
    loop_forms: Vec<(usize, String)>,
    assigned_params: BTreeSet<usize>,
    helper_info: Vec<HelperInfo>,
}

fn ident(s: &str) -> syn::Ident {
    if s == "self" {
        return syn::Ident::new("self", PSpan::call_site());
    }
    syn::Ident::new(s, PSpan::call_site())
}

fn var(s: &str) -> syn::Expr {
    let i = ident(s);
    syn::parse_quote!(#i)
}

fn lit_uint(v: u128, t: &str) -> syn::Expr {
    let l = syn::LitInt::new(&format!("{v}{t}"), PSpan::call_site());
    syn::parse_quote!(#l)
}

fn uint_name(bits: u32) -> &'static str {
    match bits {
        0 | 64 => "u64",
        8 => "u8",
        16 => "u16",
        32 => "u32",
        _ => "u128",
    }
}

fn int_ty_name(t: &Ty) -> Option<String> {
    match t {
        Ty::Int(false, 0) => Some("usize".into()),
        Ty::Int(false, b) => Some(format!("u{b}")),
        Ty::Int(true, b) if matches!(b, 16 | 32 | 64) => Some(format!("i{b}")),
        _ => None,
    }
}

/// The lift prelude's signed type (`crate::__lift::I16`) of `iN`.
fn signed_path(bits: u32) -> syn::Path {
    let i = format_ident!("I{}", bits);
    syn::parse_quote!(crate::__lift::#i)
}

/// `e` as an operand: parenthesized unless atomic (a path, a literal, a
/// call, a method call, a field, an index, a tuple, a constructor).
fn paren(e: syn::Expr) -> syn::Expr {
    match &e {
        syn::Expr::Path(_) | syn::Expr::Lit(_) | syn::Expr::Call(_) | syn::Expr::MethodCall(_) | syn::Expr::Field(_) | syn::Expr::Index(_) | syn::Expr::Paren(_) | syn::Expr::Tuple(_) | syn::Expr::Struct(_) | syn::Expr::Array(_) | syn::Expr::Repeat(_) => e,
        _ => syn::parse_quote!((#e)),
    }
}

/// The integer a pure expression denotes when it is a literal (`5u16`) or
/// a signed constant (`crate::__lift::I32(5u32)`, its bits).
fn lit_value(e: &syn::Expr) -> Option<u128> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.base10_parse::<u128>().ok(),
        syn::Expr::Call(c) if c.args.len() == 1 && matches!(&*c.func, syn::Expr::Path(p) if p.path.segments.last().is_some_and(|s| matches!(s.ident.to_string().as_str(), "I16" | "I32" | "I64"))) => lit_value(&c.args[0]),
        syn::Expr::Paren(p) => lit_value(&p.expr),
        _ => None,
    }
}

fn ts_mentions(ts: TokenStream, name: &str) -> bool {
    ts.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Ident(i) => i == name,
        proc_macro2::TokenTree::Group(g) => ts_mentions(g.stream(), name),
        _ => false,
    })
}

fn mentions(e: &syn::Expr, name: &str) -> bool {
    ts_mentions(e.to_token_stream(), name)
}

fn val_mentions(v: &Val, name: &str) -> bool {
    match v {
        Val::E(e) => mentions(e, name),
        Val::C(_, _, fs) => fs.iter().any(|f| val_mentions(f, name)),
        Val::R(inner) => val_mentions(inner, name),
        _ => false,
    }
}

impl<'m> Reader<'m> {
    fn err<T>(&self, fr: usize, what: impl std::fmt::Display) -> Result<T, String> {
        Err(format!("MIR reading of `{}` (in `{}`): {what}", self.spec.lifted_name, self.frames[fr].f.key))
    }

    fn fresh(&mut self, base: &str) -> String {
        self.fresh += 1;
        format!("__{base}{}", self.fresh)
    }

    fn new_frame(&mut self, f: &'m Fn, root: bool) -> usize {
        let names = if root {
            local_names(f, &self.spec.params, true)
        } else {
            self.fresh += 1;
            let n = self.fresh;
            (0..f.locals.len()).map(|i| format!("__i{n}_{i}")).collect()
        };
        let mut assigns = vec![0usize; f.locals.len()];
        for b in &f.blocks {
            for s in &b.stmts {
                if let Stmt::Assign(p, r, _) = s {
                    assigns[p.local] += 1;
                    if let Rvalue::Ref(k, q) = r
                        && k == "mut"
                    {
                        assigns[q.local] += 1;
                    }
                }
            }
            if let Term::Call(_, _, d, _) = &b.term {
                assigns[d.local] += 1;
            }
        }
        self.frames.push(Frame { f, names, root, assigns });
        self.frames.len() - 1
    }

    fn named(&self, fr: usize, l: usize) -> bool {
        let f = self.frames[fr].f;
        self.frames[fr].root && l > f.argc && f.debug.iter().any(|(_, x)| *x == l)
    }

    fn is_param(&self, fr: usize, l: usize) -> bool {
        self.frames[fr].root && l >= 1 && l <= self.frames[fr].f.argc
    }

    // ----- types -----------------------------------------------------------

    fn place_ty(&self, fr: usize, p: &Place) -> Result<Ty, String> {
        let mut t = self.frames[fr].f.locals.get(p.local).map(|l| l.0.clone()).ok_or("place local out of range")?;
        for pr in &p.proj {
            t = match (pr, t) {
                (Proj::Deref, Ty::Ref(_, inner)) => *inner,
                (Proj::Field(_, ft), _) => ft.clone(),
                (Proj::Index(_), Ty::Array(e, _)) | (Proj::Index(_), Ty::Slice(e)) => *e,
                (Proj::Downcast(_), t) => t,
                (pr, t) => return Err(format!("projection {pr:?} of {t:?}")),
            };
        }
        Ok(t)
    }

    fn op_ty(&self, fr: usize, o: &Operand) -> Result<Ty, String> {
        match o {
            Operand::Copy(p) | Operand::Move(p) => self.place_ty(fr, p),
            Operand::Const(c) => match c.value() {
                Const::Int(t, _) | Const::Zst(t) | Const::Agg(t, _, _) => Ok(t.clone()),
                Const::Ref(inner) => {
                    let it = self.op_ty(fr, &Operand::Const((**inner).clone()))?;
                    Ok(Ty::Ref(false, Box::new(it)))
                }
                Const::Unsupported(s) => Err(format!("constant: {s}")),
                Const::Item(..) => unreachable!("`value` strips items"),
            },
            Operand::RuntimeChecks(_) => Ok(Ty::Bool),
        }
    }

    /// An integer constant operand's type and value (a named item's value).
    fn int_const<'o>(o: &'o Operand) -> Option<(&'o Ty, i128)> {
        match o {
            Operand::Const(c) => match c.value() {
                Const::Int(t, v) => Some((t, *v)),
                _ => None,
            },
            _ => None,
        }
    }

    // ----- values ----------------------------------------------------------

    fn konst(&self, fr: usize, c: &Const) -> Result<Val, String> {
        Ok(match c {
            Const::Int(Ty::Bool, v) => Val::E(if *v != 0 { syn::parse_quote!(true) } else { syn::parse_quote!(false) }),
            Const::Int(t @ Ty::Int(false, _), v) => Val::E(lit_uint(*v as u128, &int_ty_name(t).unwrap())),
            Const::Int(Ty::Int(true, b), v) if matches!(b, 16 | 32 | 64) => {
                let bits = (*v as u128) & ((1u128 << b) - 1);
                let p = signed_path(*b);
                let l = lit_uint(bits, uint_name(*b));
                Val::E(syn::parse_quote!(#p(#l)))
            }
            // a width the subset lacks (`isize` discriminants): only folded
            Const::Int(Ty::Int(..), v) => Val::K(*v),
            Const::Zst(t) => Val::Z(t.clone()),
            Const::Agg(t, v, fs) => Val::C(t.clone(), *v, fs.iter().map(|f| self.konst(fr, f)).collect::<Result<_, _>>()?),
            // `&c`: a shared reference to the value of `c`
            Const::Ref(inner) => Val::R(Box::new(self.konst(fr, inner)?)),
            // a named constant: the lifted constant it stands for (the same
            // item's lifted reading), else its value as rustc evaluated it
            Const::Item(owner, name, v) => match self.nm.const_item(self.m, owner.as_ref(), name) {
                Some(e) if matches!(**v, Const::Ref(_)) => Val::R(Box::new(Val::E(e))),
                Some(e) => Val::E(e),
                None => self.konst(fr, v)?,
            },
            Const::Unsupported(what) => Val::Opaque(what.clone()),
            other => return self.err(fr, format!("constant {other:?}")),
        })
    }

    fn materialize(&self, fr: usize, v: &Val) -> Result<syn::Expr, String> {
        Ok(match v {
            Val::E(e) => e.clone(),
            Val::Z(Ty::Unit) => syn::parse_quote!(()),
            Val::Z(Ty::Adt(k)) => {
                // a unit-like struct (`PhantomData`, a marker type): its constructor
                let d = self.m.adts.get(k).ok_or_else(|| format!("no ADT `{k}`"))?;
                if d.is_enum || d.variants.len() != 1 || !d.variants[0].fields.is_empty() {
                    return self.err(fr, format!("a zero-sized value of type {k} used as data"));
                }
                let c = self.nm.ctor(self.m, k, 0)?;
                let p = &c.path;
                syn::parse_quote!(#p)
            }
            Val::Z(t) => return self.err(fr, format!("a zero-sized value of type {t:?} used as data")),
            Val::K(v) => return self.err(fr, format!("the discriminant value {v} used as data")),
            Val::Opaque(what) => return self.err(fr, format!("constant {what}")),
            Val::R(inner) => {
                let e = paren(self.materialize(fr, inner)?);
                syn::parse_quote!(&#e)
            }
            Val::C(Ty::Tuple(_), _, fs) => {
                let es: Vec<syn::Expr> = fs.iter().map(|f| self.materialize(fr, f)).collect::<Result<_, _>>()?;
                if es.len() == 1 {
                    let e = &es[0];
                    syn::parse_quote!((#e,))
                } else {
                    syn::parse_quote!((#(#es),*))
                }
            }
            Val::C(Ty::Adt(key), 0, fs) if fs.len() == 1 && self.nm.transparent(self.m, key) => self.materialize(fr, &fs[0])?,
            Val::C(Ty::Adt(key), var_idx, fs) => {
                let c = self.nm.ctor(self.m, key, *var_idx)?;
                let es: Vec<syn::Expr> = fs.iter().map(|f| self.materialize(fr, f)).collect::<Result<_, _>>()?;
                let p = &c.path;
                if es.is_empty() {
                    syn::parse_quote!(#p)
                } else if c.named {
                    let fields: Vec<syn::Ident> = c.fields.iter().map(|f| ident(f)).collect();
                    syn::parse_quote!(#p { #(#fields: #es),* })
                } else {
                    syn::parse_quote!(#p(#(#es),*))
                }
            }
            Val::C(Ty::Array(..), _, fs) => {
                let es: Vec<syn::Expr> = fs.iter().map(|f| self.materialize(fr, f)).collect::<Result<_, _>>()?;
                syn::parse_quote!([#(#es),*])
            }
            Val::C(t, _, _) => return self.err(fr, format!("a constructed value of type {t:?}")),
        })
    }

    /// The field access `e.f` of a value of type `t`.
    fn field_expr(&self, fr: usize, e: syn::Expr, t: &Ty, variant: usize, i: usize) -> Result<syn::Expr, String> {
        let e = paren(e);
        match t {
            Ty::Tuple(_) => {
                let idx = syn::Index::from(i);
                Ok(syn::parse_quote!(#e.#idx))
            }
            // a newtype read as its field (a host model, SEMANTICS.md §19.10)
            Ty::Adt(key) if i == 0 && self.nm.transparent(self.m, key) => Ok(e),
            Ty::Adt(key) => {
                let adt = self.m.adts.get(key).ok_or_else(|| format!("no ADT `{key}`"))?;
                if adt.is_enum {
                    return self.err(fr, format!("a field of enum `{key}` read without a match"));
                }
                let name = adt.variants.get(variant).and_then(|v| v.fields.get(i)).map(|f| f.0.clone()).ok_or("field out of range")?;
                if name.chars().all(|c| c.is_ascii_digit()) {
                    let idx = syn::Index::from(i);
                    Ok(syn::parse_quote!(#e.#idx))
                } else {
                    let f = ident(&name);
                    Ok(syn::parse_quote!(#e.#f))
                }
            }
            other => self.err(fr, format!("field of {other:?}")),
        }
    }

    /// Reads a place: `(value, pure)`.
    fn read(&mut self, fr: usize, p: &Place, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<(Val, bool), String> {
        let key = (fr, p.local);
        let mut t = self.frames[fr].f.locals[p.local].0.clone();
        let mut projs = p.proj.iter().peekable();
        let mut cur: Val = if let Some(r) = env.refs.get(&key) {
            // `*r` of a `&mut` place: the place
            match projs.peek() {
                Some(Proj::Deref) => {
                    projs.next();
                    if let Ty::Ref(_, inner) = t {
                        t = *inner;
                    }
                    match (&r.fields, projs.peek()) {
                        // a field of an exploded state: its variable
                        (Some((_, fs)), Some(Proj::Field(i, ft))) => {
                            let v = Val::E(var(fs.get(*i).ok_or("field out of range")?));
                            t = ft.clone();
                            projs.next();
                            v
                        }
                        (Some(_), _) => Val::E(self.state_value(r)?),
                        (None, _) => Val::E(r.lv.clone()),
                    }
                }
                _ => return self.err(fr, format!("the `&mut` local `_{}` used as a value", p.local)),
            }
        } else if let Some(v) = env.vals.get(&key) {
            v.clone()
        } else if let Some((sf, sp)) = env.discr.get(&key).cloned() {
            // the discriminant of a value whose constructor is known here
            let (sv, _) = self.read(sf, &sp, env, out)?;
            let st = self.place_ty(sf, &sp)?;
            match (&sv, &st) {
                (Val::C(_, v, _), Ty::Adt(k)) => Val::K(discr_value(self.m.adts.get(k).and_then(|d| d.variants.get(*v)).map(|x| x.discr).unwrap_or(0), &self.frames[fr].f.locals[p.local].0)),
                _ => return self.err(fr, "a discriminant used as a value of a constructor not known here"),
            }
        } else if self.frames[fr].f.locals[p.local].0 == Ty::Unit || (self.frames[fr].names[p.local] == "_" && matches!(&self.frames[fr].f.locals[p.local].0, Ty::Ref(false, t) if **t == Ty::Unit)) {
            Val::Z(Ty::Unit)
        } else if let Ty::Adt(k) = &self.frames[fr].f.locals[p.local].0
            && self.m.adts.get(k).is_some_and(|d| !d.is_enum && d.variants.len() == 1 && d.variants[0].fields.is_empty())
        {
            // a unit-like struct needs no assignment to exist (rustc elides it)
            Val::Z(Ty::Adt(k.clone()))
        } else if let Ty::Closure(_, up) = &self.frames[fr].f.locals[p.local].0
            && **up == Ty::Unit
        {
            // nor does a closure that captures nothing
            Val::Z(self.frames[fr].f.locals[p.local].0.clone())
        } else if self.is_param(fr, p.local) || env.declared.contains(&self.frames[fr].names[p.local]) {
            Val::E(var(&self.frames[fr].names[p.local]))
        } else {
            return self.err(fr, format!("read of `_{}` before it is set", p.local));
        };
        let mut pure = true;
        let mut variant = 0usize;
        while let Some(pr) = projs.next() {
            match pr {
                Proj::Deref => {
                    if let Ty::Ref(_, inner) = t {
                        t = *inner;
                    } else {
                        return self.err(fr, "deref of a non-reference");
                    }
                    // `*&x` is `x`; `*r` of a reference-typed variable is `*r`
                    cur = match cur {
                        Val::R(inner) => *inner,
                        Val::E(e) => {
                            let e = paren(e);
                            Val::E(syn::parse_quote!(*#e))
                        }
                        other => return self.err(fr, format!("deref of {other:?}")),
                    };
                }
                Proj::Downcast(v) => {
                    variant = *v;
                    match &cur {
                        Val::C(_, cv, _) if cv == v => {}
                        Val::C(..) => return self.err(fr, "a downcast to a variant the value does not have (an unreachable path)"),
                        _ => return self.err(fr, "a downcast of a value whose variant is not known here"),
                    }
                }
                Proj::Field(i, ft) => {
                    cur = match cur {
                        Val::C(_, _, fs) => fs.get(*i).cloned().ok_or("field out of range")?,
                        Val::E(e) => Val::E(self.field_expr(fr, e, &t, variant, *i)?),
                        other => return self.err(fr, format!("field of {other:?}")),
                    };
                    t = ft.clone();
                    variant = 0;
                }
                Proj::Index(l) => {
                    let e = paren(self.materialize(fr, &cur)?);
                    let (iv, _) = self.read(fr, &Place { local: *l, proj: vec![] }, env, out)?;
                    let ie = self.materialize(fr, &iv)?;
                    cur = Val::E(syn::parse_quote!(#e[#ie]));
                    pure = false;
                    t = match t {
                        Ty::Array(e, _) | Ty::Slice(e) => *e,
                        other => return self.err(fr, format!("index of {other:?}")),
                    };
                }
                Proj::Unsupported(s) => return self.err(fr, format!("projection {s}")),
            }
        }
        Ok((cur, pure))
    }

    fn operand(&mut self, fr: usize, o: &Operand, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<(Val, bool), String> {
        match o {
            Operand::Copy(p) | Operand::Move(p) => self.read(fr, p, env, out),
            Operand::Const(c) => Ok((self.konst(fr, c)?, true)),
            Operand::RuntimeChecks(k) if k == "overflow" => Ok((Val::E(if self.m.overflow_checks { syn::parse_quote!(true) } else { syn::parse_quote!(false) }), true)),
            // `cfg!(ub_checks)` guards precondition checks of library code;
            // read as false, the unchecked operation that follows carries the
            // precondition as its obligation (so the check could never fire)
            Operand::RuntimeChecks(k) if k == "ub" => Ok((Val::E(syn::parse_quote!(false)), true)),
            Operand::RuntimeChecks(k) => self.err(fr, format!("the runtime check `{k}` (its value depends on the build's flags)")),
        }
    }

    fn operand_expr(&mut self, fr: usize, o: &Operand, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<(syn::Expr, bool), String> {
        let (v, p) = self.operand(fr, o, env, out)?;
        Ok((self.materialize(fr, &v)?, p))
    }

    /// A comparison of the discriminant of an enum value whose variant is
    /// not known here with a constant (`<Ordering as ..>::le` compares
    /// `discriminant(x) <= 0`): per variant the comparison is a known
    /// boolean, so it is the `match` of the value yielding them.
    fn discr_compare(&mut self, fr: usize, op: &str, a: &Operand, b: &Operand, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<Option<(syn::Expr, bool)>, String> {
        let dl = |o: &Operand| match o {
            Operand::Copy(p) | Operand::Move(p) if p.proj.is_empty() => env.discr.get(&(fr, p.local)).cloned().map(|d| (d, p.local)),
            _ => None,
        };
        let ((sf, sp), dlocal, c, flip) = match (dl(a), Self::int_const(b), dl(b), Self::int_const(a)) {
            (Some((d, l)), Some((_, c)), _, _) => (d, l, c, false),
            (_, _, Some((d, l)), Some((_, c))) => (d, l, c, true),
            _ => return Ok(None),
        };
        let (cur, pure) = self.read(sf, &sp, env, out)?;
        if matches!(cur, Val::C(..)) {
            return Ok(None);
        }
        let Ty::Adt(key) = self.place_ty(sf, &sp)? else { return Ok(None) };
        let Some(adt) = self.m.adts.get(&key).cloned() else { return Ok(None) };
        if !adt.is_enum {
            return Ok(None);
        }
        let dty = self.frames[fr].f.locals[dlocal].0.clone();
        let cmp = |x: i128, y: i128| -> Option<bool> {
            Some(match op {
                "eq" => x == y,
                "ne" => x != y,
                "lt" => x < y,
                "le" => x <= y,
                "gt" => x > y,
                "ge" => x >= y,
                _ => return None,
            })
        };
        let scrut = self.materialize(sf, &cur)?;
        let mut arms: Vec<TokenStream> = Vec::new();
        let mut results: Vec<bool> = Vec::new();
        for v in &adt.variants {
            let d = discr_value(v.discr, &dty);
            let Some(r) = (if flip { cmp(c, d) } else { cmp(d, c) }) else { return self.err(fr, format!("`{op}` on a discriminant")) };
            let ctor = self.nm.ctor(self.m, &key, v.idx)?;
            let p = &ctor.path;
            let pat: syn::Pat = if v.fields.is_empty() {
                syn::parse_quote!(#p)
            } else if ctor.named {
                let fs: Vec<syn::Ident> = ctor.fields.iter().map(|f| ident(f)).collect();
                syn::parse_quote!(#p { #(#fs: _),* })
            } else {
                let us: Vec<TokenStream> = v.fields.iter().map(|_| quote!(_)).collect();
                syn::parse_quote!(#p(#(#us),*))
            };
            let rl: syn::Expr = if r { syn::parse_quote!(true) } else { syn::parse_quote!(false) };
            arms.push(quote!(#pat => #rl,));
            results.push(r);
        }
        if results.iter().all(|r| *r == results[0]) && !results.is_empty() {
            return Ok(Some((if results[0] { syn::parse_quote!(true) } else { syn::parse_quote!(false) }, true)));
        }
        Ok(Some((syn::parse_quote!(match #scrut { #(#arms)* }), pure)))
    }

    /// A binary operation on integers or booleans: `(expr, pure)`.
    fn binop(&mut self, fr: usize, op: &str, a: &Operand, b: &Operand, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<(syn::Expr, bool), String> {
        if let Some(r) = self.discr_compare(fr, op, a, b, env, out)? {
            return Ok(r);
        }
        // comparisons of known integers (discriminants) fold
        {
            let (va, _) = self.operand(fr, a, env, out)?;
            let (vb, _) = self.operand(fr, b, env, out)?;
            let known = |v: &Val| -> Option<i128> {
                match v {
                    Val::K(k) => Some(*k),
                    Val::E(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. })) => i.base10_parse::<i128>().ok(),
                    _ => None,
                }
            };
            if matches!(va, Val::K(_)) || matches!(vb, Val::K(_)) {
                let (Some(x), Some(y)) = (known(&va), known(&vb)) else { return self.err(fr, "a discriminant compared with a value not known here") };
                let r = match op {
                    "eq" => x == y,
                    "ne" => x != y,
                    "lt" => x < y,
                    "le" => x <= y,
                    "gt" => x > y,
                    "ge" => x >= y,
                    _ => return self.err(fr, format!("`{op}` on a discriminant")),
                };
                return Ok((if r { syn::parse_quote!(true) } else { syn::parse_quote!(false) }, true));
            }
        }
        let ta = self.op_ty(fr, a)?;
        let mut tb = self.op_ty(fr, b)?;
        let (ea, pa) = self.operand_expr(fr, a, env, out)?;
        let (mut eb, pb) = self.operand_expr(fr, b, env, out)?;
        let ea = paren(ea);
        eb = paren(eb);
        // a non-negative signed constant shift amount: its value (a shift
        // means the same for any amount type)
        if matches!(op, "shl" | "shr" | "shl-unchecked" | "shr-unchecked")
            && tb.signed()
            && let Some(v) = lit_value(&eb)
            && tb.bits().is_some_and(|bits| v < (1u128 << (bits - 1)))
        {
            eb = lit_uint(v, "u32");
            tb = Ty::Int(false, 32);
        }
        let pure_ops = pa && pb;
        // a comparison of two unsigned literals (a shift's constant amount
        // against the width): its value
        if !ta.signed()
            && !tb.signed()
            && ta.is_int()
            && let (Some(x), Some(y)) = (lit_value(&ea), lit_value(&eb))
            && let Some(r) = match op {
                "eq" => Some(x == y),
                "ne" => Some(x != y),
                "lt" => Some(x < y),
                "le" => Some(x <= y),
                "gt" => Some(x > y),
                "ge" => Some(x >= y),
                _ => None,
            }
        {
            return Ok((if r { syn::parse_quote!(true) } else { syn::parse_quote!(false) }, true));
        }
        if ta == Ty::Bool {
            let e: syn::Expr = match op {
                "and" => syn::parse_quote!(#ea & #eb),
                "or" => syn::parse_quote!(#ea | #eb),
                "xor" => syn::parse_quote!(#ea ^ #eb),
                "eq" => syn::parse_quote!(#ea == #eb),
                "ne" => syn::parse_quote!(#ea != #eb),
                _ => return self.err(fr, format!("`{op}` on booleans")),
            };
            return Ok((e, pure_ops));
        }
        match &ta {
            Ty::Int(false, _) => {
                // unsigned: the subset's operators (checked ones carry the
                // obligation rustc's panic or undefined behavior states)
                let shift_amount = |eb: syn::Expr| -> syn::Expr { if tb.signed() { syn::parse_quote!(#eb.0) } else { eb } };
                let (e, pure): (syn::Expr, bool) = match op {
                    "add-unchecked" => (syn::parse_quote!(#ea + #eb), false),
                    "sub-unchecked" => (syn::parse_quote!(#ea - #eb), false),
                    "mul-unchecked" => (syn::parse_quote!(#ea * #eb), false),
                    // MIR's plain `Add`/`Sub`/`Mul` wrap
                    "add" => (syn::parse_quote!(#ea.wrapping_add(#eb)), true),
                    "sub" => (syn::parse_quote!(#ea.wrapping_sub(#eb)), true),
                    "mul" => (syn::parse_quote!(#ea.wrapping_mul(#eb)), true),
                    // division by zero is undefined behavior in MIR (rustc
                    // asserts before it): the subset's obligation
                    "div" => (syn::parse_quote!(#ea / #eb), false),
                    "rem" => (syn::parse_quote!(#ea % #eb), false),
                    // MIR's `Shl`/`Shr` mask the amount; the subset's shift
                    // requires it below the width, where the two agree
                    "shl" | "shl-unchecked" => {
                        let eb = shift_amount(eb);
                        (syn::parse_quote!(#ea << #eb), false)
                    }
                    "shr" | "shr-unchecked" => {
                        let eb = shift_amount(eb);
                        (syn::parse_quote!(#ea >> #eb), false)
                    }
                    "and" => (syn::parse_quote!(#ea & #eb), true),
                    "or" => (syn::parse_quote!(#ea | #eb), true),
                    "xor" => (syn::parse_quote!(#ea ^ #eb), true),
                    "eq" => (syn::parse_quote!(#ea == #eb), true),
                    "ne" => (syn::parse_quote!(#ea != #eb), true),
                    "lt" => (syn::parse_quote!(#ea < #eb), true),
                    "le" => (syn::parse_quote!(#ea <= #eb), true),
                    "gt" => (syn::parse_quote!(#ea > #eb), true),
                    "ge" => (syn::parse_quote!(#ea >= #eb), true),
                    // three-way comparison: core's `Ordering`, the lift prelude's
                    "cmp" => (syn::parse_quote!(if #ea < #eb { crate::__lift::Ordering::Less } else if #ea == #eb { crate::__lift::Ordering::Equal } else { crate::__lift::Ordering::Greater }), true),
                    _ => return self.err(fr, format!("the unsigned operation `{op}`")),
                };
                Ok((e, pure && pure_ops))
            }
            Ty::Int(true, bits) if matches!(bits, 16 | 32 | 64) => {
                // signed: two's complement bits (SEMANTICS.md §19.3)
                let sp = signed_path(*bits);
                let shr = format_ident!("i{}_shr", bits);
                let amount: syn::Expr = if tb.signed() { syn::parse_quote!(#eb.0) } else { eb.clone() };
                let (e, pure): (syn::Expr, bool) = match op {
                    "xor" => (syn::parse_quote!(#sp(#ea.0 ^ #eb.0)), true),
                    "and" => (syn::parse_quote!(#sp(#ea.0 & #eb.0)), true),
                    "or" => (syn::parse_quote!(#sp(#ea.0 | #eb.0)), true),
                    "eq" => (syn::parse_quote!(#ea == #eb), true),
                    "ne" => (syn::parse_quote!(#ea != #eb), true),
                    "shl" | "shl-unchecked" => (syn::parse_quote!(#sp(#ea.0 << #amount)), false),
                    // (`lift::test_hook`: a deliberately wrong logical shift)
                    "shr" | "shr-unchecked" if crate::lift::test_hook::get() == Some(crate::lift::test_hook::WrongRule::SignedShrLogical) => (syn::parse_quote!(#sp(#ea.0 >> #amount)), false),
                    "shr" | "shr-unchecked" => (syn::parse_quote!(crate::__lift::#shr(#ea, (#amount) as usize)), false),
                    _ => return self.err(fr, format!("the signed operation `{op}` (SEMANTICS.md §19.3 reads bit operations, shifts, negation and truncating casts only)")),
                };
                Ok((e, pure && pure_ops))
            }
            other => self.err(fr, format!("`{op}` on {other:?}")),
        }
    }

    fn cast(&mut self, fr: usize, kind: &str, a: &Operand, to: &Ty, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<(syn::Expr, bool), String> {
        // `&[T; N]` as `&[T]`: the whole array as a slice
        if kind == "unsize"
            && matches!(self.op_ty(fr, a)?, Ty::Ref(false, ref t) if matches!(**t, Ty::Array(..)))
            && matches!(to, Ty::Ref(false, t) if matches!(**t, Ty::Slice(_)))
        {
            let (e, _) = self.operand_expr(fr, a, env, out)?;
            let e = paren(e);
            return Ok((syn::parse_quote!(&#e[..]), false));
        }
        if kind != "int-to-int" {
            return self.err(fr, format!("the cast `{kind}`"));
        }
        let from = self.op_ty(fr, a)?;
        // a constant: Rust's `as` on the value (two's complement truncation)
        if let Some((_, v)) = Self::int_const(a)
            && let (Some(tb), false) = (to.bits(), to.signed())
            && from.is_int()
        {
            let mask: u128 = if tb >= 128 { u128::MAX } else { (1u128 << tb) - 1 };
            let tn = int_ty_name(to).ok_or_else(|| format!("cast to {to:?}"))?;
            return Ok((lit_uint((v as u128) & mask, &tn), true));
        }
        let (e, pu) = self.operand_expr(fr, a, env, out)?;
        if let (Some(v), Some(tb), false) = (lit_value(&e), to.bits(), to.signed())
            && from.is_int()
            && (!from.signed() || from.bits().is_some_and(|fb| tb <= fb))
        {
            let mask: u128 = if tb >= 128 { u128::MAX } else { (1u128 << tb) - 1 };
            let tn = int_ty_name(to).ok_or_else(|| format!("cast to {to:?}"))?;
            return Ok((lit_uint(v & mask, &tn), true));
        }
        let e = paren(e);
        let fb = from.bits().unwrap_or(1);
        let tb = to.bits().unwrap_or(1);
        let tn = int_ty_name(to).ok_or_else(|| format!("cast to {to:?}"))?;
        let tu = format_ident!("{}", if to.signed() { uint_name(tb).to_string() } else { tn.clone() });
        let e: syn::Expr = match (&from, to.signed()) {
            (Ty::Bool, false) => syn::parse_quote!(#e as #tu),
            (Ty::Int(false, _), false) => syn::parse_quote!(#e as #tu),
            (Ty::Int(false, _), true) => {
                let sp = signed_path(tb);
                syn::parse_quote!(#sp(#e as #tu))
            }
            (Ty::Int(true, _), false) if tb <= fb => syn::parse_quote!(#e.0 as #tu),
            (Ty::Int(true, _), true) if tb <= fb => {
                let sp = signed_path(tb);
                syn::parse_quote!(#sp(#e.0 as #tu))
            }
            _ => return self.err(fr, format!("the cast {from:?} as {to:?} (sign extension is not read)")),
        };
        Ok((e, pu))
    }

    /// Binds an impure expression to a fresh `let` (a pure one is kept).
    fn bind(&mut self, e: syn::Expr, pure: bool, ty: Option<syn::Type>, out: &mut Vec<syn::Stmt>) -> Val {
        if pure {
            return Val::E(e);
        }
        let n = ident(&self.fresh("t"));
        out.push(match ty {
            Some(t) => syn::parse_quote!(let #n: #t = #e;),
            None => syn::parse_quote!(let #n = #e;),
        });
        Val::E(syn::parse_quote!(#n))
    }

    /// Before variable `name` changes: carried values that read it are bound.
    fn invalidate(&mut self, fr: usize, name: &str, except: Option<Key>, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        // (`lift::test_hook` re-injects the two historical bugs of this step,
        // for the theorems to catch; never set by a build)
        let hook = crate::lift::test_hook::get();
        // a variable's own entry (its value is itself) stays: it still is
        let own = |k: &Key, v: &Val| -> bool { hook != Some(crate::lift::test_hook::WrongRule::SnapshotOwnValue) && matches!(v, Val::E(syn::Expr::Path(pp)) if pp.path.is_ident(&self.frames[k.0].names[k.1])) };
        // (a variable of `Env::writeback` holds its field variable as a place,
        // not as a value: it is rebuilt from the field's current value)
        let wb = |k: &Key| hook != Some(crate::lift::test_hook::WrongRule::WritebackSnapshot) && env.writeback.contains(k);
        let keys: Vec<Key> = env.vals.iter().filter(|(k, v)| Some(**k) != except && !own(k, v) && !wb(k) && val_mentions(v, name)).map(|(k, _)| *k).collect();
        for k in keys {
            let v = env.vals[&k].clone();
            let e = self.materialize(fr, &v)?;
            let n = ident(&self.fresh("v"));
            out.push(syn::parse_quote!(let #n = #e;));
            env.vals.insert(k, Val::E(syn::parse_quote!(#n)));
        }
        env.discr.retain(|_, (f2, p)| !(self.frames[*f2].names[p.local] == name));
        Ok(())
    }

    /// The lvalue expression of a place (for an assignment).
    fn lvalue(&mut self, fr: usize, p: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(syn::Expr, String), String> {
        let key = (fr, p.local);
        let mut t = self.frames[fr].f.locals[p.local].0.clone();
        let mut projs = p.proj.iter().peekable();
        let (mut e, base) = if let Some(r) = env.refs.get(&key).cloned() {
            if !matches!(projs.next(), Some(Proj::Deref)) {
                return self.err(fr, "assignment to a `&mut` local itself");
            }
            if let Ty::Ref(_, inner) = t {
                t = *inner;
            }
            match (&r.fields, projs.peek()) {
                (Some((_, fs)), Some(Proj::Field(i, ft))) => {
                    let fv = fs.get(*i).ok_or("field out of range")?.clone();
                    t = ft.clone();
                    projs.next();
                    (var(&fv), fv)
                }
                (Some(_), _) => return self.err(fr, "a write of a whole exploded state through a projection"),
                (None, _) => {
                    let base = r.lv.to_token_stream().into_iter().next().map(|t| t.to_string()).unwrap_or_default();
                    (r.lv.clone(), base)
                }
            }
        } else {
            // a carried value becomes a variable before a part of it changes
            let name = self.frames[fr].names[p.local].clone();
            if let Some(v) = env.vals.get(&key).cloned() {
                let is_self_var = matches!(&v, Val::E(syn::Expr::Path(pp)) if pp.path.is_ident(&name));
                if !is_self_var && env.holds.remove(&key) {
                    env.vals.insert(key, Val::E(var(&name)));
                } else if !is_self_var {
                    let ex = self.materialize(fr, &v)?;
                    let id = ident(&name);
                    if env.declared.contains(&name) || self.is_param(fr, p.local) {
                        out.push(syn::parse_quote!(#id = #ex;));
                    } else {
                        out.push(syn::parse_quote!(let mut #id = #ex;));
                        env.declared.insert(name.clone());
                    }
                    env.vals.insert(key, Val::E(var(&name)));
                }
            } else if !self.is_param(fr, p.local) && !env.declared.contains(&name) {
                return self.err(fr, format!("assignment into a part of `_{}` before it is set", p.local));
            }
            if self.is_param(fr, p.local) {
                self.assigned_params.insert(p.local - 1);
            }
            (var(&name), name)
        };
        let mut variant = 0usize;
        for pr in projs {
            match pr {
                Proj::Deref => {
                    if let Ty::Ref(_, inner) = t {
                        t = *inner;
                    }
                }
                Proj::Field(i, ft) => {
                    e = self.field_expr(fr, e, &t, variant, *i)?;
                    t = ft.clone();
                    variant = 0;
                }
                Proj::Index(l) => {
                    let (iv, _) = self.read(fr, &Place { local: *l, proj: vec![] }, env, out)?;
                    let ie = self.materialize(fr, &iv)?;
                    e = syn::parse_quote!(#e[#ie]);
                    t = match t {
                        Ty::Array(e, _) | Ty::Slice(e) => *e,
                        other => return self.err(fr, format!("index of {other:?}")),
                    };
                }
                Proj::Downcast(v) => variant = *v,
                Proj::Unsupported(s) => return self.err(fr, format!("projection {s}")),
            }
        }
        Ok((e, base))
    }

    /// `place = v`.
    fn assign(&mut self, fr: usize, p: &Place, v: Val, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let key = (fr, p.local);
        if p.proj.is_empty() && !env.refs.contains_key(&key) {
            let name = self.frames[fr].names[p.local].clone();
            self.invalidate(fr, &name, Some(key), env, out)?;
            env.discr.remove(&key);
            env.holds.remove(&key);
            let named = self.named(fr, p.local) || self.is_param(fr, p.local) || env.declared.contains(&name);
            if !named {
                // a temporary: carried
                env.vals.insert(key, v);
                return Ok(());
            }
            let e = self.materialize(fr, &v)?;
            let id = ident(&name);
            if self.is_param(fr, p.local) {
                self.assigned_params.insert(p.local - 1);
                out.push(syn::parse_quote!(#id = #e;));
            } else if env.declared.contains(&name) {
                out.push(syn::parse_quote!(#id = #e;));
            } else {
                let lt = value_ty(&self.frames[fr].f.locals[p.local].0).and_then(|t| self.nm.ty(self.m, &t).ok());
                if lt.is_none() && matches!(v, Val::C(..)) {
                    // a compiler-introduced variable of a type the subset
                    // lacks (`?`'s residual): its constructor is carried
                    env.vals.insert(key, v);
                    return Ok(());
                }
                let mutable = self.frames[fr].assigns[p.local] > 1;
                out.push(match (lt, mutable) {
                    (Some(t), true) => syn::parse_quote!(let mut #id: #t = #e;),
                    (Some(t), false) => syn::parse_quote!(let #id: #t = #e;),
                    (None, true) => syn::parse_quote!(let mut #id = #e;),
                    (None, false) => syn::parse_quote!(let #id = #e;),
                });
                env.declared.insert(name.clone());
            }
            // a constructor stays known (the variable holds the same value)
            let known = matches!(&v, Val::C(..)) && !self.is_param(fr, p.local);
            if known {
                env.holds.insert(key);
            }
            env.vals.insert(key, if known { v } else { Val::E(var(&name)) });
            return Ok(());
        }
        // `*s = v` of an exploded state: every field variable
        if p.proj == [Proj::Deref]
            && let Some(r) = env.refs.get(&key).cloned()
            && r.fields.is_some()
        {
            let e = self.materialize(fr, &v)?;
            return self.state_store(fr, &r, e, env, out);
        }
        let e = self.materialize(fr, &v)?;
        let (lv, base) = self.lvalue(fr, p, env, out)?;
        self.invalidate(fr, &base, None, env, out)?;
        out.push(syn::parse_quote!(#lv = #e;));
        Ok(())
    }

    /// A state's whole value: its place, or the constructor of an exploded
    /// state's field variables.
    fn state_value(&self, r: &LRef) -> Result<syn::Expr, String> {
        let Some((k, fs)) = &r.fields else { return Ok(r.lv.clone()) };
        let c = self.nm.ctor(self.m, k, 0)?;
        let p = &c.path;
        let es: Vec<syn::Expr> = fs.iter().map(|f| var(f)).collect();
        Ok(if c.named {
            let names: Vec<syn::Ident> = c.fields.iter().map(|f| ident(f)).collect();
            syn::parse_quote!(#p { #(#names: #es),* })
        } else {
            syn::parse_quote!(#p(#(#es),*))
        })
    }

    /// Stores a whole value into a state: its place, or each field variable
    /// of an exploded state.
    fn state_store(&mut self, fr: usize, r: &LRef, e: syn::Expr, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let Some((k, fs)) = r.fields.clone() else {
            let lv = r.lv.clone();
            let base = lv.to_token_stream().into_iter().next().map(|t| t.to_string()).unwrap_or_default();
            self.invalidate(fr, &base, None, env, out)?;
            out.push(syn::parse_quote!(#lv = #e;));
            return Ok(());
        };
        let tmp = ident(&self.fresh("w"));
        out.push(syn::parse_quote!(let #tmp = #e;));
        for (i, f) in fs.iter().enumerate() {
            self.invalidate(fr, f, None, env, out)?;
            let fe = self.field_expr(fr, syn::parse_quote!(#tmp), &Ty::Adt(k.clone()), 0, i)?;
            let id = ident(f);
            out.push(syn::parse_quote!(#id = #fe;));
        }
        Ok(())
    }

    /// Whether the state parameter at local `l` (named `name`) is exploded:
    /// a `&mut` of a struct with an invariant.
    fn explode(&self, l: usize, name: &str) -> Option<(String, Vec<String>)> {
        let Ty::Ref(true, inner) = &self.frames[0].f.locals[l].0 else { return None };
        let Ty::Adt(k) = &**inner else { return None };
        let d = self.m.adts.get(k)?;
        if d.is_enum || d.variants.len() != 1 || !self.nm.has_invariant(self.m, k) {
            return None;
        }
        let base = name.trim_start_matches('_');
        Some((k.clone(), d.variants[0].fields.iter().map(|(f, _)| format!("__{base}_{f}")).collect()))
    }

    // ----- statements ------------------------------------------------------

    fn stmt(&mut self, fr: usize, s: &Stmt, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        match s {
            Stmt::Assume(o, _) => {
                // `assume(c)` is undefined behavior when `c` is false: an obligation
                let (v, _) = self.operand(fr, o, env, out)?;
                if let Val::E(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(b), .. })) = &v {
                    if !b.value {
                        out.push(syn::parse_quote!(unreachable!();));
                    }
                    return Ok(());
                }
                let e = self.materialize(fr, &v)?;
                out.push(syn::parse_quote!(if !(#e) { unreachable!() }));
                Ok(())
            }
            Stmt::Unsupported(x) => self.err(fr, format!("statement {x}")),
            Stmt::Assign(p, r, _) => {
                let key = (fr, p.local);
                match r {
                    Rvalue::Ref(k, q) if k == "mut" => {
                        if !p.proj.is_empty() {
                            return self.err(fr, "a `&mut` stored into a place");
                        }
                        let lr = self.mut_ref(fr, q, env, out)?;
                        env.refs.insert(key, lr);
                        return Ok(());
                    }
                    Rvalue::Ref(k, _) if k == "fake" => return Ok(()),
                    // a `&mut` copied or moved out of a `&mut` local, or out
                    // of the place one points to (`copy (*r)` of a `&mut &mut
                    // T` whose inner reference is held in a state's field):
                    // the same place
                    Rvalue::Use(Operand::Copy(q) | Operand::Move(q))
                        if p.proj.is_empty()
                            && matches!(self.frames[fr].f.locals[p.local].0, Ty::Ref(true, _))
                            && env.refs.get(&(fr, q.local)).is_some_and(|r| q.proj.is_empty() || (q.proj == [Proj::Deref] && r.inner)) =>
                    {
                        let mut r = env.refs[&(fr, q.local)].clone();
                        // (`*r` points to the `T` itself)
                        r.inner &= q.proj.is_empty();
                        env.refs.insert(key, r);
                        return Ok(());
                    }
                    Rvalue::Discr(q) => {
                        if !p.proj.is_empty() {
                            return self.err(fr, "a discriminant stored into a place");
                        }
                        env.discr.insert(key, (fr, q.clone()));
                        env.vals.remove(&key);
                        return Ok(());
                    }
                    _ => {}
                }
                let dest_ty = self.place_ty(fr, p)?;
                // checked arithmetic whose overflow flag is tested, not
                // asserted (core's `checked_add`): the pair (wrapped result,
                // overflowed), exactly
                if let Rvalue::Checked(op, a, b) = r
                    && !self.flag_asserted(fr, s, p)
                {
                    let v = self.checked_pair(fr, op, a, b, &dest_ty, env, out)?;
                    return self.assign(fr, p, v, env, out);
                }
                let v = self.rvalue(fr, r, &dest_ty, env, out)?;
                self.assign(fr, p, v, env, out)
            }
        }
    }

    /// Whether the overflow flag of the checked operation `s` (into `p`) is
    /// asserted false by its block's terminator (`a + b` with overflow
    /// checks): the operator reading, whose obligation is that assertion.
    fn flag_asserted(&self, fr: usize, s: &Stmt, p: &Place) -> bool {
        let f = self.frames[fr].f;
        let Some(bl) = f.blocks.iter().find(|bl| bl.stmts.iter().any(|x| std::ptr::eq(x, s))) else { return false };
        let later = bl.stmts.iter().skip_while(|x| !std::ptr::eq(*x, s)).skip(1);
        // nothing after it in the block reads or changes the pair
        let mut touched = false;
        for x in later {
            if let Stmt::Assign(q, r, _) = x {
                let mut u = Vec::new();
                rv_locals(r, &mut u);
                touched |= q.local == p.local || u.contains(&p.local);
            }
        }
        let flag = Place { local: p.local, proj: vec![Proj::Field(1, Ty::Bool)] };
        !touched && p.proj.is_empty() && matches!(&bl.term, Term::Assert(Operand::Move(q) | Operand::Copy(q), false, k, _) if *q == flag && k == "overflow")
    }

    /// `(a op b, overflowed)` of unsigned `a`, `b`: `wrapping_op` and
    /// `checked_op(..).is_none()` (both total).
    #[allow(clippy::too_many_arguments)]
    fn checked_pair(&mut self, fr: usize, op: &str, a: &Operand, b: &Operand, dest_ty: &Ty, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<Val, String> {
        if self.op_ty(fr, a)?.signed() || !self.op_ty(fr, a)?.is_int() {
            return self.err(fr, format!("checked `{op}` of a signed or non-integer type with a tested flag"));
        }
        let (ea, pa) = self.operand_expr(fr, a, env, out)?;
        let (eb, pb) = self.operand_expr(fr, b, env, out)?;
        let (ea, eb) = (paren(ea), paren(eb));
        let (w, c): (syn::Expr, syn::Expr) = match op {
            "add" => (syn::parse_quote!(#ea.wrapping_add(#eb)), syn::parse_quote!(#ea.checked_add(#eb).is_none())),
            "sub" => (syn::parse_quote!(#ea.wrapping_sub(#eb)), syn::parse_quote!(#ea.checked_sub(#eb).is_none())),
            "mul" => (syn::parse_quote!(#ea.wrapping_mul(#eb)), syn::parse_quote!(#ea.checked_mul(#eb).is_none())),
            _ => return self.err(fr, format!("checked `{op}`")),
        };
        let wv = self.bind(w, pa && pb, None, out);
        let cv = self.bind(c, pa && pb, None, out);
        Ok(Val::C(dest_ty.clone(), 0, vec![wv, cv]))
    }

    fn mut_ref(&mut self, fr: usize, q: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<LRef, String> {
        let key = (fr, q.local);
        // a reborrow `&mut *r`
        if let Some(r) = env.refs.get(&key).cloned() {
            if q.proj == [Proj::Deref] {
                return Ok(r);
            }
        }
        // `&mut (x as V).i` of a variable whose constructor is known here (a
        // matched arm): the field in its own mutable variable, assigned back
        // into `x` where the path leaves the arm (`Env::writeback`)
        if let [Proj::Downcast(v), Proj::Field(i, _)] = q.proj.as_slice()
            && self.frames[fr].root
            && let Some(Val::C(t, cv, fs)) = env.vals.get(&key).cloned()
            && cv == *v
            && (self.is_param(fr, q.local) || env.declared.contains(&self.frames[fr].names[q.local]))
        {
            let cur = fs.get(*i).cloned().ok_or("field out of range")?;
            let n = self.fresh("m");
            let e = self.materialize(fr, &cur)?;
            let id = ident(&n);
            out.push(syn::parse_quote!(let mut #id = #e;));
            env.declared.insert(n.clone());
            let mut fs2 = fs.clone();
            fs2[*i] = Val::E(var(&n));
            env.vals.insert(key, Val::C(t, cv, fs2));
            env.writeback.insert(key);
            env.holds.remove(&key);
            return Ok(LRef { lv: var(&n), buf: None, fields: None, inner: true });
        }
        let (lv, _) = self.lvalue(fr, q, env, out)?;
        let t = self.place_ty(fr, q)?;
        let buf = match &t {
            Ty::Ref(true, inner) if matches!(**inner, Ty::Slice(ref e) if **e == Ty::Int(false, 8)) => Some("bufmut"),
            Ty::Ref(false, inner) if matches!(**inner, Ty::Slice(ref e) if **e == Ty::Int(false, 8)) => Some("buf"),
            _ => None,
        };
        Ok(LRef { lv, buf, fields: None, inner: false })
    }

    fn rvalue(&mut self, fr: usize, r: &Rvalue, dest_ty: &Ty, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<Val, String> {
        let t = value_ty(dest_ty).and_then(|t| self.nm.ty(self.m, &t).ok());
        match r {
            Rvalue::Use(o) => {
                let (v, p) = self.operand(fr, o, env, out)?;
                if p {
                    Ok(v)
                } else {
                    let e = self.materialize(fr, &v)?;
                    Ok(self.bind(e, false, t, out))
                }
            }
            Rvalue::Bin(op, a, b) => {
                let (e, p) = self.binop(fr, op, a, b, env, out)?;
                Ok(self.bind(e, p, t, out))
            }
            Rvalue::Checked(op, a, b) => {
                // `(a op b, overflowed)`: the subset's checked operator, whose
                // obligation is that it does not overflow (so the flag is false)
                let ta = self.op_ty(fr, a)?;
                if ta.signed() {
                    return self.err(fr, format!("signed checked `{op}` (SEMANTICS.md §19.3)"));
                }
                let (ea, _) = self.operand_expr(fr, a, env, out)?;
                let (eb, _) = self.operand_expr(fr, b, env, out)?;
                let (ea, eb) = (paren(ea), paren(eb));
                let e: syn::Expr = match op.as_str() {
                    "add" => syn::parse_quote!(#ea + #eb),
                    "sub" => syn::parse_quote!(#ea - #eb),
                    "mul" => syn::parse_quote!(#ea * #eb),
                    _ => return self.err(fr, format!("checked `{op}`")),
                };
                let inner = self.nm.ty(self.m, &ta).ok();
                let v = self.bind(e, false, inner, out);
                Ok(Val::C(dest_ty.clone(), 0, vec![v, Val::E(syn::parse_quote!(false))]))
            }
            Rvalue::Un(op, a) => {
                let ta = self.op_ty(fr, a)?;
                let (ea, pu) = self.operand_expr(fr, a, env, out)?;
                let ea = paren(ea);
                match (op.as_str(), &ta) {
                    ("not", Ty::Bool) | ("not", Ty::Int(false, _)) => Ok(self.bind(syn::parse_quote!(!#ea), pu, t, out)),
                    ("not", Ty::Int(true, b)) => {
                        let sp = signed_path(*b);
                        Ok(self.bind(syn::parse_quote!(#sp(!#ea.0)), pu, t, out))
                    }
                    ("neg", Ty::Int(true, b)) if matches!(b, 16 | 32 | 64) => {
                        let f = format_ident!("i{}_neg", b);
                        Ok(self.bind(syn::parse_quote!(crate::__lift::#f(#ea)), false, t, out))
                    }
                    // a slice reference's metadata is its length (`s.len()`)
                    ("ptr-metadata", Ty::Ref(_, inner)) if matches!(**inner, Ty::Slice(_)) => Ok(self.bind(syn::parse_quote!(#ea.len()), pu, t, out)),
                    _ => self.err(fr, format!("the unary `{op}` on {ta:?}")),
                }
            }
            Rvalue::Cast(k, a, to) => {
                let (e, p) = self.cast(fr, k, a, to, env, out)?;
                Ok(self.bind(e, p, t, out))
            }
            Rvalue::Ref(_, q) => {
                // `&q`: a reference to the value of `q` (unchanged while the
                // borrow lives: rustc's borrow checker)
                let (v, p) = self.read(fr, q, env, out)?;
                if p {
                    Ok(Val::R(Box::new(v)))
                } else {
                    let e = self.materialize(fr, &v)?;
                    let v2 = self.bind(e, false, None, out);
                    Ok(Val::R(Box::new(v2)))
                }
            }
            Rvalue::Repeat(o, n) => {
                let (e, p) = self.operand_expr(fr, o, env, out)?;
                let n = lit_uint(*n as u128, "usize");
                Ok(self.bind(syn::parse_quote!([#e; #n]), p, t, out))
            }
            Rvalue::Agg(kind, ops) => {
                let mut vals = Vec::new();
                for o in ops {
                    let (v, p) = self.operand(fr, o, env, out)?;
                    vals.push(if p {
                        v
                    } else {
                        let e = self.materialize(fr, &v)?;
                        self.bind(e, false, None, out)
                    });
                }
                match kind {
                    AggKind::Tuple => Ok(Val::C(dest_ty.clone(), 0, vals)),
                    AggKind::Adt(ty, v) => Ok(Val::C(ty.clone(), *v, vals)),
                    AggKind::Array(_) => Ok(Val::C(dest_ty.clone(), 0, vals)),
                    AggKind::Closure(ty) => {
                        if vals.is_empty() {
                            Ok(Val::Z(ty.clone()))
                        } else {
                            Ok(Val::C(Ty::Tuple(vec![]), 0, vals))
                        }
                    }
                }
            }
            Rvalue::Len(_) => self.err(fr, "`Len`"),
            Rvalue::Discr(_) => self.err(fr, "a discriminant used as a value"),
            Rvalue::Unsupported(s) => self.err(fr, format!("rvalue {s}")),
        }
    }

    // ----- the walk --------------------------------------------------------

    /// Assigns every variable of [`Env::writeback`] its rebuilt constructor
    /// (where a path leaves the arm that matched it).
    fn flush_writeback(&mut self, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let keys: Vec<Key> = std::mem::take(&mut env.writeback).into_iter().collect();
        for k in keys {
            let Some(v) = env.vals.get(&k).cloned() else { continue };
            let name = self.frames[k.0].names[k.1].clone();
            let e = self.materialize(k.0, &v)?;
            let id = ident(&name);
            if self.is_param(k.0, k.1) {
                self.assigned_params.insert(k.1 - 1);
            }
            out.push(syn::parse_quote!(#id = #e;));
            env.vals.insert(k, Val::E(var(&name)));
        }
        Ok(())
    }

    /// Every root local live at `b` is in its own variable (at joins, loop
    /// heads and recursive calls).
    fn normalize(&mut self, live: &BTreeSet<usize>, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let fr = 0;
        for &l in live {
            if l == 0 || self.is_param(fr, l) && !env.vals.contains_key(&(fr, l)) {
                continue;
            }
            if env.refs.contains_key(&(fr, l)) {
                continue;
            }
            let name = self.frames[fr].names[l].clone();
            let v = match env.vals.get(&(fr, l)) {
                Some(v) => v.clone(),
                None if env.declared.contains(&name) => continue,
                None => continue,
            };
            if matches!(&v, Val::E(syn::Expr::Path(pp)) if pp.path.is_ident(&name)) {
                continue;
            }
            if matches!(v, Val::Z(_)) {
                continue;
            }
            // the variable already holds the value (bound, not assigned since)
            if env.holds.contains(&(fr, l)) && env.declared.contains(&name) {
                env.vals.insert((fr, l), Val::E(var(&name)));
                continue;
            }
            let e = self.materialize(fr, &v)?;
            let id = ident(&name);
            if env.declared.contains(&name) || self.is_param(fr, l) {
                out.push(syn::parse_quote!(#id = #e;));
            } else {
                let lt = value_ty(&self.frames[fr].f.locals[l].0).and_then(|t| self.nm.ty(self.m, &t).ok());
                out.push(match lt {
                    Some(t) => syn::parse_quote!(let mut #id: #t = #e;),
                    None => syn::parse_quote!(let mut #id = #e;),
                });
                env.declared.insert(name.clone());
            }
            env.vals.insert((fr, l), Val::E(var(&name)));
        }
        Ok(())
    }

    fn live_at(&self, b: usize) -> BTreeSet<usize> {
        self.cfg.live_in[b].iter().copied().collect()
    }

    fn ret_expr(&mut self, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<syn::Expr, String> {
        let mut parts: Vec<syn::Expr> = Vec::new();
        for &i in &self.spec.states {
            let key = (0, i + 1);
            let lv = match env.refs.get(&key) {
                Some(r) => self.state_value(r)?,
                None => var(&self.spec.params[i]),
            };
            parts.push(lv);
        }
        if self.spec.has_ret {
            let (v, _) = self.read(0, &Place { local: 0, proj: vec![] }, env, out)?;
            parts.push(self.materialize(0, &v)?);
        }
        Ok(match parts.len() {
            0 => syn::parse_quote!(()),
            1 => parts.remove(0),
            _ => syn::parse_quote!((#(#parts),*)),
        })
    }

    fn go(&mut self, fr: usize, b: usize, mut env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        let root = self.frames[fr].root;
        if root {
            if cx.stop == Some(b) {
                return Ok(Flow::Fall(env));
            }
            if let Some((_, form)) = cx.loops.iter().find(|(h, _)| *h == b).cloned() {
                // a back edge
                match form {
                    LoopForm::While => return Ok(Flow::Fall(env)),
                    LoopForm::Helper(name, params) => {
                        let live = self.live_at(b);
                        self.normalize(&live, &mut env, out)?;
                        let args: Vec<syn::Expr> = params.iter().map(|l| self.state_or_var(&env, *l)).collect::<Result<_, _>>()?;
                        out.push(syn::parse_quote!(return #name(#(#args),*);));
                        return Ok(Flow::Diverge);
                    }
                }
            }
            if self.cfg.headers.contains(&b) && !cx.probe {
                return self.enter_loop(b, env, cx, out);
            }
        }
        if root {
            // root temporaries dead here are dropped (never read again)
            let live = &self.cfg.live_in[b];
            let names = &self.frames[0].names;
            let keep: Vec<Key> = env.vals.keys().copied().filter(|k| k.0 != 0 || live.contains(&k.1) || env.declared.contains(&names[k.1]) || k.1 <= self.frames[0].f.argc).collect();
            env.vals.retain(|k, _| keep.contains(k));
        }
        let f = self.frames[fr].f;
        let bl = f.blocks.get(b).ok_or("block out of range")?;
        if !cx.probe && must_diverge(f, b, &mut Vec::new()) {
            out.push(syn::parse_quote!(unreachable!();));
            return Ok(Flow::Diverge);
        }
        for s in &bl.stmts {
            let before = out.len();
            self.stmt(fr, s, &mut env, out)?;
            if cx.probe && out.len() != before {
                return Err("probe: not a pure loop condition".into());
            }
        }
        match &bl.term {
            Term::Goto(t) => self.go(fr, *t, env, cx, out),
            Term::Return => match &cx.k {
                K::Ret => {
                    if cx.probe {
                        return Err("probe: return".into());
                    }
                    self.flush_writeback(&mut env, out)?;
                    let e = self.ret_expr(&env, out)?;
                    out.push(syn::parse_quote!(return #e;));
                    Ok(Flow::Diverge)
                }
                K::Back { caller, dest, target, stop, next } => {
                    let (v, _) = self.read(fr, &Place { local: 0, proj: vec![] }, &env, out)?;
                    let (caller, dest, target, stop, next) = (*caller, dest.clone(), *target, *stop, (**next).clone());
                    // the callee's locals are dead
                    env.vals.retain(|k, _| k.0 != fr);
                    env.refs.retain(|k, _| k.0 != fr);
                    env.discr.retain(|k, _| k.0 != fr);
                    let before = out.len();
                    self.assign(caller, &dest, v, &mut env, out)?;
                    if cx.probe && out.len() != before {
                        return Err("probe: not a pure loop condition".into());
                    }
                    let Some(t) = target else {
                        out.push(syn::parse_quote!(unreachable!();));
                        return Ok(Flow::Diverge);
                    };
                    let cx2 = Cx { k: next, stop, loops: cx.loops.clone(), probe: cx.probe };
                    self.go(caller, t, env, &cx2, out)
                }
            },
            Term::Unreachable | Term::Resume | Term::Abort => {
                if cx.probe {
                    return Err("probe: diverges".into());
                }
                out.push(syn::parse_quote!(unreachable!();));
                Ok(Flow::Diverge)
            }
            Term::Drop(p, glue, t) => {
                if *glue {
                    // a value whose variant is known here and runs no code
                    // when dropped (no `Drop` impl, no field with glue)
                    let mut scratch = Vec::new();
                    let known = match self.read(fr, p, &env, &mut scratch) {
                        Ok((Val::C(Ty::Adt(k), v, _), _)) if scratch.is_empty() => self.m.adts.get(&k).and_then(|d| d.variants.get(v)).is_some_and(|x| x.no_glue),
                        _ => false,
                    };
                    if !known {
                        return self.err(fr, "a drop with drop glue (only values without destructors are read)");
                    }
                }
                self.go(fr, *t, env, cx, out)
            }
            Term::Assert(c, expected, kind, t) => {
                let (v, _) = self.operand(fr, c, &env, out)?;
                if let Val::E(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(bv), .. })) = &v {
                    if bv.value == *expected {
                        return self.go(fr, *t, env, cx, out);
                    }
                    if cx.probe {
                        return Err("probe: failing assert".into());
                    }
                    out.push(syn::parse_quote!(unreachable!();));
                    return Ok(Flow::Diverge);
                }
                if self.assert_subsumed(fr, c, *expected, kind, *t) {
                    return self.go(fr, *t, env, cx, out);
                }
                if cx.probe {
                    return Err("probe: assert".into());
                }
                let e = self.materialize(fr, &v)?;
                out.push(if *expected { syn::parse_quote!(if !(#e) { unreachable!() }) } else { syn::parse_quote!(if #e { unreachable!() }) });
                self.go(fr, *t, env, cx, out)
            }
            Term::Call(callee, args, dest, target) => self.call(fr, callee, args, dest, *target, env, cx, out),
            Term::Switch(d, arms, otherwise) => self.switch(fr, b, d, arms, *otherwise, env, cx, out),
            Term::Unsupported(s) => self.err(fr, format!("terminator {s}")),
        }
    }

    fn state_or_var(&self, env: &Env, l: usize) -> Result<syn::Expr, String> {
        if let Some(r) = env.refs.get(&(0, l)) {
            return self.state_value(r);
        }
        Ok(var(&self.frames[0].names[l]))
    }

    /// An `Assert` whose condition is word for word the obligation of the
    /// operation at the start of its target (an index `a[i]` of an array of
    /// length `n` after `i < n`; a shift by `s` of a `w`-bit value after
    /// `s < w`; a division or remainder by `d` after `d == 0` is false; a
    /// signed negation of `x` after `x == MIN` is false): the operation's own
    /// obligation is that check.
    fn assert_subsumed(&self, fr: usize, c: &Operand, expected: bool, kind: &str, target: usize) -> bool {
        let f = self.frames[fr].f;
        let (Operand::Copy(cp) | Operand::Move(cp)) = c else { return false };
        if !cp.proj.is_empty() {
            return false;
        }
        // the condition's definition in the same block as the assert
        let def = f.blocks.iter().find_map(|bl| {
            if !matches!(&bl.term, Term::Assert(o, ..) if o == c) {
                return None;
            }
            bl.stmts.iter().rev().find_map(|s| match s {
                Stmt::Assign(p, r, _) if p.local == cp.local && p.proj.is_empty() => Some(r.clone()),
                _ => None,
            })
        });
        let Some(def) = def else { return false };
        let Some(Stmt::Assign(_, first, _)) = f.blocks.get(target).and_then(|b| b.stmts.first()) else { return false };
        let same = |a: &Operand, b: &Operand| -> bool {
            let pl = |o: &Operand| match o {
                Operand::Copy(p) | Operand::Move(p) => Some(p.clone()),
                _ => None,
            };
            a == b || (pl(a).is_some() && pl(a) == pl(b))
        };
        match (kind, expected, &def) {
            ("bounds", true, Rvalue::Bin(op, Operand::Copy(ip) | Operand::Move(ip), n)) if op == "lt" && ip.proj.is_empty() => {
                // the target's first statement indexes an array of length `n` by `i`
                let Some((_, nv)) = Self::int_const(n) else { return false };
                let uses_index = |p: &Place| -> bool {
                    p.proj.iter().any(|pr| matches!(pr, Proj::Index(l) if *l == ip.local)) && {
                        let base = Place { local: p.local, proj: p.proj.iter().take_while(|pr| !matches!(pr, Proj::Index(_))).cloned().collect() };
                        matches!(self.place_ty(fr, &base), Ok(Ty::Array(_, len)) if len as i128 == nv)
                    }
                };
                match first {
                    Rvalue::Use(Operand::Copy(p) | Operand::Move(p)) if uses_index(p) => true,
                    _ => {
                        if let Some(Stmt::Assign(dst, _, _)) = f.blocks.get(target).and_then(|b| b.stmts.first()) { uses_index(dst) } else { false }
                    }
                }
            }
            ("overflow", true, Rvalue::Bin(op, s, w)) if op == "lt" => {
                let Some((_, wv)) = Self::int_const(w) else { return false };
                match first {
                    Rvalue::Bin(sop, x, s2) if (sop == "shl" || sop == "shr") && same(s, s2) => self.op_ty(fr, x).ok().and_then(|t| t.bits()).is_some_and(|bits| bits as i128 == wv),
                    _ => false,
                }
            }
            ("div-zero" | "rem-zero", false, Rvalue::Bin(op, d, z)) if op == "eq" && Self::int_const(z).is_some_and(|(_, v)| v == 0) => matches!(first, Rvalue::Bin(o, _, d2) if (o == "div" || o == "rem") && same(d, d2)),
            ("overflow-neg", false, Rvalue::Bin(op, x, _)) if op == "eq" => matches!(first, Rvalue::Un(o, x2) if o == "neg" && same(x, x2)),
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn call(&mut self, fr: usize, callee: &Callee, args: &[Operand], dest: &Place, target: Option<usize>, mut env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        let cont = |me: &mut Self, env: Env, out: &mut Vec<syn::Stmt>| -> Result<Flow, String> {
            match target {
                Some(t) => me.go(fr, t, env, cx, out),
                None => {
                    out.push(syn::parse_quote!(unreachable!();));
                    Ok(Flow::Diverge)
                }
            }
        };
        match callee {
            Callee::Diverge(_) => {
                if cx.probe {
                    return Err("probe: diverges".into());
                }
                out.push(syn::parse_quote!(unreachable!();));
                Ok(Flow::Diverge)
            }
            Callee::Intrinsic(name, _) if name == "ctlz" && args.len() == 1 => {
                let (e, pu) = self.operand_expr(fr, &args[0], &env, out)?;
                let e = paren(e);
                let v = self.bind(syn::parse_quote!(#e.leading_zeros()), pu, None, out);
                self.assign(fr, dest, v, &mut env, out)?;
                cont(self, env, out)
            }
            Callee::Intrinsic(name, _) if name == "cold_path" => {
                self.assign(fr, dest, Val::Z(Ty::Unit), &mut env, out)?;
                cont(self, env, out)
            }
            Callee::Intrinsic(name, _) if matches!(name.as_str(), "ctpop" | "cttz" | "saturating_add" | "saturating_sub" | "add_with_overflow" | "sub_with_overflow" | "mul_with_overflow") => {
                let mut es = Vec::new();
                for a in args {
                    es.push(paren(self.operand_expr(fr, a, &env, out)?.0));
                }
                let v = match (name.as_str(), es.as_slice()) {
                    ("ctpop", [x]) => Val::E(syn::parse_quote!(#x.count_ones())),
                    ("cttz", [x]) => Val::E(syn::parse_quote!(#x.trailing_zeros())),
                    ("saturating_add", [x, y]) => Val::E(syn::parse_quote!(#x.saturating_add(#y))),
                    ("saturating_sub", [x, y]) => Val::E(syn::parse_quote!(#x.saturating_sub(#y))),
                    // `(wrapped, overflowed)`
                    ("add_with_overflow", [x, y]) => Val::C(self.place_ty(fr, dest)?, 0, vec![Val::E(syn::parse_quote!(#x.wrapping_add(#y))), Val::E(syn::parse_quote!(#x.checked_add(#y).is_none()))]),
                    ("sub_with_overflow", [x, y]) => Val::C(self.place_ty(fr, dest)?, 0, vec![Val::E(syn::parse_quote!(#x.wrapping_sub(#y))), Val::E(syn::parse_quote!(#x.checked_sub(#y).is_none()))]),
                    ("mul_with_overflow", [x, y]) => Val::C(self.place_ty(fr, dest)?, 0, vec![Val::E(syn::parse_quote!(#x.wrapping_mul(#y))), Val::E(syn::parse_quote!(#x.checked_mul(#y).is_none()))]),
                    _ => return self.err(fr, format!("the intrinsic `{name}` with {} arguments", es.len())),
                };
                if self.op_ty(fr, &args[0]).map(|t| t.signed()).unwrap_or(true) {
                    return self.err(fr, format!("the intrinsic `{name}` on a signed or unknown type"));
                }
                self.assign(fr, dest, v, &mut env, out)?;
                cont(self, env, out)
            }
            Callee::Intrinsic(name, _) => self.err(fr, format!("the intrinsic `{name}`")),
            Callee::Leaf(path, tys) => {
                if cx.probe {
                    return Err("probe: leaf call".into());
                }
                self.leaf(fr, path, tys, args, dest, &mut env, out)?;
                cont(self, env, out)
            }
            Callee::Unextracted(k) | Callee::Unsupported(k) => self.err(fr, format!("a call of `{k}` (not extracted)")),
            Callee::Fn(key) => {
                let f2 = self.m.fns.get(key).ok_or_else(|| format!("no MIR for the callee `{key}`"))?;
                // `o.as_deref_mut()` of an optional state `o: Option<&mut T>`
                // (`&mut o`): the same optional place (§19.10's state table;
                // rustc's borrow checker makes the reborrow exclusive)
                if matches!(f2.def.as_str(), "std::option::Option::<T>::as_deref_mut" | "core::option::Option::<T>::as_deref_mut")
                    && let [Operand::Copy(a) | Operand::Move(a)] = args
                    && a.proj.is_empty()
                    && let Some(r) = env.refs.get(&(fr, a.local)).cloned()
                    && matches!(self.op_ty(fr, &args[0]), Ok(Ty::Ref(true, ref o)) if opt_mut(self.m, o).is_some())
                    && dest.proj.is_empty()
                {
                    env.refs.insert((fr, dest.local), r);
                    return cont(self, env, out);
                }
                if let Some(b) = builtin_leaf(f2) {
                    let mut es = Vec::new();
                    for a in args {
                        es.push(paren(self.operand_expr(fr, a, &env, out)?.0));
                    }
                    let (e, pure) = b(&es);
                    let v = self.bind(e, pure, None, out);
                    self.assign(fr, dest, v, &mut env, out)?;
                    return cont(self, env, out);
                }
                if let Some(lc) = self.nm.lifted(self.m, f2) {
                    if cx.probe {
                        return Err("probe: call".into());
                    }
                    return self.lifted_call(fr, &lc, args, dest, target, env, cx, out);
                }
                // `PartialOrd`'s provided comparison at a module type whose
                // `partial_cmp` is lifted: `ord_lt(partial_cmp(a, b))`, core's
                // definition (the lift prelude's `ord_*`, as the ghost
                // language reads `<` over such a type)
                if let Some((pred, lc)) = self.provided_cmp(f2) {
                    if cx.probe {
                        return Err("probe: call".into());
                    }
                    let call = self.lifted_expr(fr, &lc, args, &env, out)?;
                    let v = self.bind(syn::parse_quote!(crate::__lift::#pred(#call)), lc.total, None, out);
                    self.assign(fr, dest, v, &mut env, out)?;
                    return cont(self, env, out);
                }
                // `Deref::deref` of a library newtype read as its field (a
                // host model whose `Deref` is that field, SEMANTICS.md
                // §19.10; its MIR is not exported): the field as a slice
                if !f2.has_body
                    && let Item::Impl(Ty::Adt(k), tr, _, mname) = &f2.item
                    && tr == "Deref"
                    && mname == "deref"
                    && self.nm.transparent(self.m, k)
                    && args.len() == 1
                {
                    let (e, _) = self.operand_expr(fr, &args[0], &env, out)?;
                    let e = paren(e);
                    let v = self.bind(syn::parse_quote!(&#e[..]), false, None, out);
                    self.assign(fr, dest, v, &mut env, out)?;
                    return cont(self, env, out);
                }
                // inline
                if !f2.has_body {
                    return self.err(fr, format!("the callee `{key}` has no MIR body"));
                }
                if kdepth(&cx.k) > 24 {
                    return self.err(fr, "inlining deeper than 24 calls");
                }
                let c2 = Cfg::new(f2);
                if !c2.headers.is_empty() {
                    return self.err(fr, format!("the library function `{key}` has a loop (library loops are not inlined)"));
                }
                let nf = self.new_frame(f2, false);
                // parameters: a closure's call passes its arguments as one tuple
                let mut actual: Vec<(Operand, Option<Val>)> = args.iter().cloned().map(|a| (a, None)).collect();
                let is_closure = matches!(f2.item, Item::Closure);
                if is_closure && !actual.is_empty() {
                    let (last, _) = actual.pop().unwrap();
                    let (tv, _) = self.operand(fr, &last, &env, out)?;
                    match tv {
                        Val::C(Ty::Tuple(_), _, fs) => {
                            for fv in fs {
                                actual.push((Operand::Const(Const::Zst(Ty::Unit)), Some(fv)));
                            }
                        }
                        Val::Z(Ty::Unit) => {}
                        other => return self.err(fr, format!("a closure called with {other:?}")),
                    }
                }
                if actual.len() != f2.argc {
                    return self.err(fr, format!("`{key}` takes {} arguments, called with {}", f2.argc, actual.len()));
                }
                for (j, (a, pre)) in actual.iter().enumerate() {
                    let pk = (nf, j + 1);
                    if let Some(v) = pre {
                        env.vals.insert(pk, v.clone());
                        continue;
                    }
                    // a `&mut` argument: the callee's parameter is the same place
                    if let Operand::Copy(p) | Operand::Move(p) = a
                        && p.proj.is_empty()
                        && let Some(r) = env.refs.get(&(fr, p.local)).cloned()
                    {
                        env.refs.insert(pk, r);
                        continue;
                    }
                    if let Operand::Copy(p) | Operand::Move(p) = a
                        && matches!(self.op_ty(fr, a), Ok(Ty::Ref(true, _)))
                    {
                        let lr = if p.proj.first() == Some(&Proj::Deref) && env.refs.contains_key(&(fr, p.local)) { env.refs[&(fr, p.local)].clone() } else { self.mut_ref(fr, p, &mut env, out)? };
                        env.refs.insert(pk, lr);
                        continue;
                    }
                    let (v, pure) = self.operand(fr, a, &env, out)?;
                    let v = if pure {
                        v
                    } else {
                        let e = self.materialize(fr, &v)?;
                        self.bind(e, false, None, out)
                    };
                    env.vals.insert(pk, v);
                }
                let k = K::Back { caller: fr, dest: dest.clone(), target, stop: cx.stop, next: Box::new(cx.k.clone()) };
                let cx2 = Cx { k, stop: None, loops: cx.loops.clone(), probe: cx.probe };
                self.go(nf, 0, env, &cx2, out)
            }
        }
    }

    /// `PartialOrd::lt/le/gt/ge` as provided by core (not overridden) whose
    /// body starts by calling a lifted `partial_cmp` on its own two
    /// parameters: the prelude predicate and that callee.
    fn provided_cmp(&self, f2: &Fn) -> Option<(syn::Ident, LiftedCallee)> {
        let m = f2.def.strip_prefix("std::cmp::PartialOrd::").or_else(|| f2.def.strip_prefix("core::cmp::PartialOrd::"))?;
        if !matches!(f2.item, Item::Fn(_)) || !matches!(m, "lt" | "le" | "gt" | "ge") || f2.argc != 2 {
            return None;
        }
        let Term::Call(Callee::Fn(pc), a, _, _) = &f2.blocks.first()?.term else { return None };
        let own = |o: &Operand, l: usize| matches!(o, Operand::Copy(p) | Operand::Move(p) if p.local == l && p.proj.is_empty());
        if !f2.blocks[0].stmts.is_empty() || a.len() != 2 || !own(&a[0], 1) || !own(&a[1], 2) {
            return None;
        }
        let pcf = self.m.fns.get(pc)?;
        if !matches!(&pcf.item, Item::Impl(_, t, _, n) if t == "PartialOrd" && n == "partial_cmp") {
            return None;
        }
        let lc = self.nm.lifted(self.m, pcf)?;
        if !lc.states.is_empty() {
            return None;
        }
        Some((format_ident!("ord_{}", m), lc))
    }

    /// The call expression of a lifted callee without states.
    fn lifted_expr(&mut self, fr: usize, lc: &LiftedCallee, args: &[Operand], env: &Env, out: &mut Vec<syn::Stmt>) -> Result<syn::Expr, String> {
        let mut es: Vec<syn::Expr> = Vec::new();
        for (i, a) in args.iter().enumerate() {
            let (v, _) = self.operand(fr, a, env, out)?;
            let v = match v {
                Val::R(inner) if lc.by_value.contains(&i) => *inner,
                Val::E(e) if lc.by_value.contains(&i) => {
                    let e = paren(e);
                    Val::E(syn::parse_quote!(*#e))
                }
                other => other,
            };
            es.push(self.materialize(fr, &v)?);
        }
        let path = &lc.path;
        Ok(syn::parse_quote!(#path(#(#es),*)))
    }

    #[allow(clippy::too_many_arguments)]
    fn lifted_call(&mut self, fr: usize, lc: &LiftedCallee, args: &[Operand], dest: &Place, target: Option<usize>, mut env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        let mut es: Vec<syn::Expr> = Vec::new();
        let mut state_lvs: Vec<LRef> = Vec::new();
        for (i, a) in args.iter().enumerate() {
            if lc.states.contains(&i) {
                let (Operand::Copy(p) | Operand::Move(p)) = a else { return self.err(fr, "a state argument that is not a place") };
                let lr = if let Some(r) = env.refs.get(&(fr, p.local)).cloned() {
                    r
                } else {
                    return self.err(fr, "a state argument that is not a `&mut` place");
                };
                es.push(self.state_value(&lr)?);
                state_lvs.push(lr);
                continue;
            }
            let (v, _) = self.operand(fr, a, &env, out)?;
            // a `&self` receiver the lift takes by value: the pointee
            let v = match v {
                Val::R(inner) if lc.by_value.contains(&i) => *inner,
                Val::E(e) if lc.by_value.contains(&i) => {
                    let e = paren(e);
                    Val::E(syn::parse_quote!(*#e))
                }
                other => other,
            };
            es.push(self.materialize(fr, &v)?);
        }
        let path = &lc.path;
        let call: syn::Expr = syn::parse_quote!(#path(#(#es),*));
        if state_lvs.is_empty() {
            let v = self.bind(call, lc.total, None, out);
            self.assign(fr, dest, v, &mut env, out)?;
        } else {
            let sn: Vec<syn::Ident> = state_lvs.iter().map(|_| ident(&self.fresh("s"))).collect();
            let rn = ident(&self.fresh("r"));
            if lc.has_ret {
                out.push(syn::parse_quote!(let (#(#sn,)* #rn) = #call;));
            } else if sn.len() == 1 {
                let s0 = &sn[0];
                out.push(syn::parse_quote!(let #s0 = #call;));
            } else {
                out.push(syn::parse_quote!(let (#(#sn),*) = #call;));
            }
            for (lr, s) in state_lvs.iter().zip(sn.iter()) {
                self.state_store(fr, lr, syn::parse_quote!(#s), &mut env, out)?;
            }
            let v = if lc.has_ret { Val::E(syn::parse_quote!(#rn)) } else { Val::Z(Ty::Unit) };
            self.assign(fr, dest, v, &mut env, out)?;
        }
        match target {
            Some(t) => self.go(fr, t, env, cx, out),
            None => {
                out.push(syn::parse_quote!(unreachable!();));
                Ok(Flow::Diverge)
            }
        }
    }

    /// The leaves: the buffer model and array/slice indexing.
    #[allow(clippy::too_many_arguments)]
    fn leaf(&mut self, fr: usize, path: &str, tys: &[Ty], args: &[Operand], dest: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let method = path.rsplit("::").next().unwrap_or("");
        let buf_ref = |me: &mut Self, env: &mut Env, o: &Operand, out: &mut Vec<syn::Stmt>| -> Result<LRef, String> {
            let (Operand::Copy(p) | Operand::Move(p)) = o else { return me.err(fr, "a buffer that is not a place") };
            if p.proj.is_empty()
                && let Some(r) = env.refs.get(&(fr, p.local))
            {
                return Ok(r.clone());
            }
            me.mut_ref(fr, p, env, out)
        };
        if path.starts_with("bytes::BufMut::") || path.starts_with("bytes::buf::buf_mut::BufMut::") {
            let r = buf_ref(self, env, &args[0], out)?;
            if r.buf != Some("bufmut") {
                return self.err(fr, "a `BufMut` call on something that is not the buffer state");
            }
            let lv = r.lv.clone();
            let (x, _) = self.operand_expr(fr, &args[1], env, out)?;
            let e: syn::Expr = match method {
                "put_u8" => syn::parse_quote!(crate::__lift_model::bufmut_put_u8(#lv, #x)),
                "put_slice" => syn::parse_quote!(crate::__lift_model::bufmut_put_slice(#lv, #x)),
                _ => return self.err(fr, format!("the buffer method `{method}`")),
            };
            self.invalidate(fr, &lv.to_token_stream().to_string(), None, env, out)?;
            out.push(syn::parse_quote!(#lv = #e;));
            return self.assign(fr, dest, Val::Z(Ty::Unit), env, out);
        }
        if path.starts_with("bytes::Buf::") || path.starts_with("bytes::buf::buf_impl::Buf::") {
            let r = buf_ref(self, env, &args[0], out)?;
            if r.buf != Some("buf") {
                return self.err(fr, "a `Buf` call on something that is not the buffer state");
            }
            let lv = r.lv.clone();
            match method {
                "try_get_u8" => {
                    let b = ident(&self.fresh("b"));
                    let rr = ident(&self.fresh("r"));
                    out.push(syn::parse_quote!(let (#b, #rr) = crate::__lift_model::buf_try_get_u8(#lv);));
                    self.invalidate(fr, &lv.to_token_stream().to_string(), None, env, out)?;
                    out.push(syn::parse_quote!(#lv = #b;));
                    return self.assign(fr, dest, Val::E(syn::parse_quote!(#rr)), env, out);
                }
                _ => return self.err(fr, format!("the buffer method `{method}`")),
            }
        }
        if method == "index" && args.len() == 2 {
            // `<[T; N] as Index<R>>::index(&a, r)` / `[T]`: the subset's slice
            let (a, _) = self.operand_expr(fr, &args[0], env, out)?;
            let a = paren(a);
            let (rv, _) = self.operand(fr, &args[1], env, out)?;
            let rt = self.op_ty(fr, &args[1])?;
            let rpath = match &rt {
                Ty::Adt(k) => self.m.adts.get(k).map(|d| d.path.clone()).unwrap_or_default(),
                _ => String::new(),
            };
            let fields = match rv {
                Val::C(_, _, fs) => fs,
                _ => return self.err(fr, "an index range whose fields are not known here"),
            };
            let fe: Vec<syn::Expr> = fields.iter().map(|f| self.materialize(fr, f).map(paren)).collect::<Result<_, _>>()?;
            let e: syn::Expr = match rpath.rsplit("::").next().unwrap_or("") {
                // `&a[..=j]` panics exactly when `j + 1` overflows or exceeds
                // the length, as `&a[..j + 1]` does
                "RangeToInclusive" => {
                    let j = &fe[0];
                    // (a deliberately wrong reading for the conformance check's
                    // own tests, `lift::test_hook`; never set by a build)
                    if crate::lift::test_hook::get() == Some(crate::lift::test_hook::WrongRule::InclusiveRangeAsExclusive) {
                        syn::parse_quote!(&#a[..#j])
                    } else {
                        syn::parse_quote!(&#a[..#j + 1usize])
                    }
                }
                "RangeTo" => {
                    let j = &fe[0];
                    syn::parse_quote!(&#a[..#j])
                }
                "RangeFrom" => {
                    let i = &fe[0];
                    syn::parse_quote!(&#a[#i..])
                }
                "Range" => {
                    let (i, j) = (&fe[0], &fe[1]);
                    syn::parse_quote!(&#a[#i..#j])
                }
                other => return self.err(fr, format!("indexing by `{other}`")),
            };
            let v = self.bind(e, false, None, out);
            return self.assign(fr, dest, v, env, out);
        }
        // `Vec::push(v, x)` of a `Vec` place: the model `vec_push` (§19.10)
        if matches!(path, "std::vec::Vec::<T, A>::push" | "alloc::vec::Vec::<T, A>::push") && args.len() == 2 {
            let r = buf_ref(self, env, &args[0], out)?;
            let lv = r.lv.clone();
            let (x, _) = self.operand_expr(fr, &args[1], env, out)?;
            let base = lv.to_token_stream().into_iter().next().map(|t| t.to_string()).unwrap_or_default();
            self.invalidate(fr, &base, None, env, out)?;
            out.push(syn::parse_quote!(#lv = crate::__lift_model::vec_push(#lv, #x);));
            return self.assign(fr, dest, Val::Z(Ty::Unit), env, out);
        }
        // a method of an open trait at its declared library instance
        let self_ty = match tys.first() {
            Some(t) => t.clone(),
            None => return self.err(fr, format!("the leaf `{path}`")),
        };
        // `Iterator::next` of the byte-string iterator model: the lift
        // prelude's `bytes_iter_next` on the byte strings not yet yielded
        if matches!(path, "std::iter::Iterator::next" | "core::iter::Iterator::next") && args.len() == 1 && super::bytes_iter_model(self.m, &self_ty) {
            let r = buf_ref(self, env, &args[0], out)?;
            let lv = r.lv.clone();
            let it = ident(&self.fresh("it"));
            let rr = ident(&self.fresh("r"));
            out.push(syn::parse_quote!(let (#it, #rr) = crate::__lift::bytes_iter_next(#lv);));
            let base = lv.to_token_stream().into_iter().next().map(|t| t.to_string()).unwrap_or_default();
            self.invalidate(fr, &base, None, env, out)?;
            out.push(syn::parse_quote!(#lv = #it;));
            return self.assign(fr, dest, Val::E(syn::parse_quote!(#rr)), env, out);
        }
        // a host model's method (`<Sha256 as Hasher>::hash(parts)`)
        if let Some(callee) = self.nm.host_method(self.m, &self_ty, method) {
            let mut es = Vec::new();
            for a in args {
                es.push(self.operand_expr(fr, a, env, out)?.0);
            }
            let v = self.bind(syn::parse_quote!(#callee(#(#es),*)), false, None, out);
            return self.assign(fr, dest, v, env, out);
        }
        self.err(fr, format!("the leaf `{path}`"))
    }

    #[allow(clippy::too_many_arguments)]
    fn switch(&mut self, fr: usize, b: usize, d: &Operand, arms: &[(u128, usize)], otherwise: usize, env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        // which value: a discriminant, or an integer/boolean
        let discr_of = match d {
            Operand::Copy(p) | Operand::Move(p) if p.proj.is_empty() => env.discr.get(&(fr, p.local)).cloned(),
            _ => None,
        };
        // arm list: (pattern or None for `_`, target, env for the arm)
        let mut plan: Vec<(Option<syn::Pat>, usize, Env)> = Vec::new();
        let scrut: syn::Expr;
        let mut is_bool = false;
        if let Some((sf, sp)) = discr_of {
            let t = self.place_ty(sf, &sp)?;
            let Ty::Adt(key) = &t else { return self.err(fr, format!("the discriminant of {t:?}")) };
            let adt = self.m.adts.get(key).cloned().ok_or_else(|| format!("no ADT `{key}`"))?;
            let target_of = |discr: i128| -> usize { arms.iter().find(|(v, _)| *v as i128 == discr).map(|a| a.1).unwrap_or(otherwise) };
            // a known constructor: its arm
            let (cur, _) = self.read(sf, &sp, &env, out)?;
            if let Val::C(_, v, _) = &cur {
                let discr = adt.variants.get(*v).map(|x| x.discr).unwrap_or(0);
                return self.go(fr, target_of(discr), env, cx, out);
            }
            if cx.probe {
                return Err("probe: match".into());
            }
            scrut = self.materialize(sf, &cur)?;
            for var_def in &adt.variants {
                let c = self.nm.ctor(self.m, key, var_def.idx)?;
                let binders: Vec<String> = var_def.fields.iter().map(|_| self.fresh("f")).collect();
                let p = &c.path;
                let bids: Vec<syn::Ident> = binders.iter().map(|x| ident(x)).collect();
                let pat: syn::Pat = if bids.is_empty() {
                    syn::parse_quote!(#p)
                } else if c.named {
                    let fields: Vec<syn::Ident> = c.fields.iter().map(|f| ident(f)).collect();
                    syn::parse_quote!(#p { #(#fields: #bids),* })
                } else {
                    syn::parse_quote!(#p(#(#bids),*))
                };
                let mut e2 = env.clone();
                let fvals: Vec<Val> = binders.iter().map(|x| Val::E(var(x))).collect();
                if sp.proj.is_empty() {
                    e2.vals.insert((sf, sp.local), Val::C(t.clone(), var_def.idx, fvals));
                    for x in &binders {
                        e2.declared.insert(x.clone());
                    }
                }
                plan.push((Some(pat), target_of(var_def.discr), e2));
            }
        } else {
            let t = self.op_ty(fr, d)?;
            let (v, _) = self.operand(fr, d, &env, out)?;
            // a known value: its arm
            let known: Option<u128> = match &v {
                Val::E(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Bool(bv), .. })) => Some(bv.value as u128),
                Val::E(syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(iv), .. })) => iv.base10_parse::<u128>().ok(),
                _ => None,
            };
            if let Some(k) = known {
                let tgt = arms.iter().find(|(v, _)| *v == k).map(|a| a.1).unwrap_or(otherwise);
                return self.go(fr, tgt, env, cx, out);
            }
            scrut = self.materialize(fr, &v)?;
            if t == Ty::Bool {
                is_bool = true;
                if cx.probe {
                    // a loop condition
                    let f_t = arms.iter().find(|(v, _)| *v == 0).map(|a| a.1).unwrap_or(otherwise);
                    let t_t = arms.iter().find(|(v, _)| *v == 1).map(|a| a.1).unwrap_or(otherwise);
                    return Ok(Flow::Cond(scrut, t_t, f_t, env));
                }
                let f_t = arms.iter().find(|(v, _)| *v == 0).map(|a| a.1).unwrap_or(otherwise);
                let t_t = arms.iter().find(|(v, _)| *v == 1).map(|a| a.1).unwrap_or(otherwise);
                plan.push((Some(syn::parse_quote!(true)), t_t, env.clone()));
                plan.push((Some(syn::parse_quote!(false)), f_t, env.clone()));
            } else if let Some(tn) = int_ty_name(&t).filter(|_| !t.signed()) {
                if cx.probe {
                    return Err("probe: integer switch".into());
                }
                for (v, tgt) in arms {
                    let l = lit_uint(*v, &tn);
                    plan.push((Some(syn::parse_quote!(#l)), *tgt, env.clone()));
                }
                plan.push((None, otherwise, env.clone()));
            } else {
                return self.err(fr, format!("a switch on {t:?}"));
            }
        }
        // where the arms rejoin (root frame only)
        let join = if self.frames[fr].root { self.cfg.ipdom[b] } else { None };
        let join = join.filter(|p| Some(*p) != cx.stop && !cx.loops.iter().any(|(h, _)| h == p));
        let arm_stop = join.or(cx.stop);
        let mut arms_out: Vec<(Option<syn::Pat>, Vec<syn::Stmt>, Option<Env>)> = Vec::new();
        for (pat, tgt, e2) in plan {
            let mut o = Vec::new();
            let cx2 = Cx { k: cx.k.clone(), stop: arm_stop, loops: cx.loops.clone(), probe: cx.probe };
            let flow = self.go(fr, tgt, e2, &cx2, &mut o)?;
            match flow {
                Flow::Diverge => arms_out.push((pat, o, None)),
                Flow::Fall(e) => arms_out.push((pat, o, Some(e))),
                Flow::Cond(..) => return Err("probe: nested condition".into()),
            }
        }
        // the variables that cross the join: set in an arm, live after it
        let fall_to = arm_stop;
        let live: BTreeSet<usize> = match fall_to {
            Some(p) => self.live_at(p),
            None => BTreeSet::new(),
        };
        let mut crossing: Vec<usize> = Vec::new();
        let mut merged: Option<Env> = None;
        for (_, o, e) in arms_out.iter_mut() {
            let Some(e) = e else { continue };
            self.flush_writeback(e, o)?;
            self.normalize(&live, e, o)?;
            for &l in &live {
                let name = &self.frames[0].names[l];
                if e.declared.contains(name) && !env.declared.contains(name) && !crossing.contains(&l) && !self.is_param(0, l) {
                    crossing.push(l);
                }
            }
        }
        crossing.sort();
        for (_, o, e) in arms_out.iter_mut() {
            let Some(e) = e else { continue };
            if !crossing.is_empty() {
                let es: Vec<syn::Expr> = crossing.iter().map(|l| var(&self.frames[0].names[*l])).collect();
                for l in &crossing {
                    if !e.declared.contains(&self.frames[0].names[*l]) {
                        return self.err(fr, format!("`{}` is set on some paths to a join only", self.frames[0].names[*l]));
                    }
                }
                o.push(syn::Stmt::Expr(if es.len() == 1 { es[0].clone() } else { syn::parse_quote!((#(#es),*)) }, None));
            }
            // the environment after the join: the root's live variables in
            // their own names, nothing carried from one arm only
            let mut m2 = env.clone();
            for &l in &live {
                let name = self.frames[0].names[l].clone();
                if e.declared.contains(&name) || env.declared.contains(&name) || self.is_param(0, l) {
                    if let Some(v) = e.vals.get(&(0, l)) {
                        m2.vals.insert((0, l), v.clone());
                    }
                }
            }
            for (k, r) in &e.refs {
                m2.refs.entry(*k).or_insert_with(|| r.clone());
            }
            m2.holds = e.holds.clone();
            // a discriminant read before the switch is still that value only
            // where no arm changed its place
            m2.discr.retain(|k, _| e.discr.contains_key(k));
            merged = Some(match merged {
                None => m2,
                Some(mut acc) => {
                    // keep only what every arm agrees on
                    acc.vals.retain(|k, v| m2.vals.get(k).is_some_and(|w| format!("{w:?}") == format!("{v:?}")));
                    acc.holds.retain(|k| m2.holds.contains(k));
                    acc.discr.retain(|k, _| m2.discr.contains_key(k));
                    acc
                }
            });
        }
        let arm_blocks: Vec<(Option<syn::Pat>, syn::Block)> = arms_out.into_iter().map(|(p, o, _)| (p, syn::Block { brace_token: Default::default(), stmts: o })).collect();
        let construct: syn::Expr = if is_bool {
            let tb = &arm_blocks[0].1;
            let fb = &arm_blocks[1].1;
            syn::parse_quote!(if #scrut #tb else #fb)
        } else {
            let arms_ts: Vec<TokenStream> = arm_blocks
                .iter()
                .map(|(p, bl)| match p {
                    Some(p) => quote!(#p => #bl,),
                    None => quote!(_ => #bl,),
                })
                .collect();
            syn::parse_quote!(match #scrut { #(#arms_ts)* })
        };
        let Some(mut m2) = merged else {
            out.push(syn::Stmt::Expr(construct, Some(Default::default())));
            return Ok(Flow::Diverge);
        };
        if crossing.is_empty() {
            out.push(syn::Stmt::Expr(construct, Some(Default::default())));
        } else {
            let ids: Vec<syn::Ident> = crossing.iter().map(|l| ident(&self.frames[0].names[*l])).collect();
            let mutable: Vec<bool> = crossing.iter().map(|l| self.frames[0].assigns[*l] > 1).collect();
            let pats: Vec<TokenStream> = ids.iter().zip(mutable.iter()).map(|(i, m)| if *m { quote!(mut #i) } else { quote!(#i) }).collect();
            if ids.len() == 1 {
                let p0 = &pats[0];
                out.push(syn::parse_quote!(let #p0 = #construct;));
            } else {
                out.push(syn::parse_quote!(let (#(#pats),*) = #construct;));
            }
            for l in &crossing {
                let name = self.frames[0].names[*l].clone();
                m2.declared.insert(name.clone());
                m2.vals.insert((0, *l), Val::E(var(&name)));
            }
        }
        match join {
            Some(p) => self.go(fr, p, m2, cx, out),
            None => Ok(Flow::Fall(m2)),
        }
    }

    fn enter_loop(&mut self, h: usize, mut env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        let k = self.cfg.headers.iter().position(|x| *x == h).unwrap_or(0);
        let at = self.spec.loops.get(&k).cloned().unwrap_or_default();
        // every live variable is in its own name; nothing else is carried in
        let live = self.live_at(h);
        self.normalize(&live, &mut env, out)?;
        env.vals.retain(|k, _| k.0 == 0 && live.contains(&k.1));
        env.discr.clear();
        let body = self.cfg.body[h].clone();
        // while-shaped: the header computes a condition, the loop's only exit is its test
        let mut probe_out = Vec::new();
        let probe_cx = Cx { k: K::Ret, stop: None, loops: vec![], probe: true };
        let probe = self.go(0, h, env.clone(), &probe_cx, &mut probe_out);
        let while_ok = at.ensures.is_empty()
            && matches!(&probe, Ok(Flow::Cond(..)))
            && probe_out.is_empty()
            && {
                let exits: Vec<(usize, usize)> = body.iter().flat_map(|b| self.cfg.succ[*b].iter().filter(|s| !body.contains(s)).map(move |s| (*b, *s))).collect();
                exits.len() == 1
            };
        if while_ok {
            let Ok(Flow::Cond(cond, t_t, f_t, env_c)) = probe else { unreachable!() };
            let (cond, body_entry, exit): (syn::Expr, usize, usize) = if body.contains(&t_t) && !body.contains(&f_t) {
                (cond, t_t, f_t)
            } else if body.contains(&f_t) && !body.contains(&t_t) {
                (syn::parse_quote!(!(#cond)), f_t, t_t)
            } else {
                return self.err(0, "a loop test with both targets in the loop");
            };
            let widx = self.loop_forms.iter().filter(|x| x.1 == "while").count();
            self.loop_forms.push((k, "while".into()));
            self.helper_info.push(HelperInfo { name: format!("loop#{widx}"), method: false, header: h, params: vec![], while_loop: true, local_names: self.frames[0].names.clone() });
            let mut bo: Vec<syn::Stmt> = Vec::new();
            let mut head: Vec<syn::Stmt> = Vec::new();
            for i in &at.invariants {
                head.push(syn::parse_quote!(invariant(#i);));
            }
            if let Some(d) = &at.decreases {
                head.push(syn::parse_quote!(decreases(#d);));
            }
            head.extend(at.steps.iter().cloned());
            if !head.is_empty() {
                bo.push(syn::parse_quote!(proof! { #(#head)* }));
            }
            if !at.at_start.is_empty() {
                let s = &at.at_start;
                bo.push(syn::parse_quote!(proof! { #(#s)* }));
            }
            let mut loops = cx.loops.clone();
            loops.push((h, LoopForm::While));
            let cx_body = Cx { k: K::Ret, stop: Some(h), loops, probe: false };
            let flow = self.go(0, body_entry, env_c.clone(), &cx_body, &mut bo)?;
            if let Flow::Fall(mut e) = flow {
                self.normalize(&live, &mut e, &mut bo)?;
            }
            if !at.at_end.is_empty() {
                let s = &at.at_end;
                bo.push(syn::parse_quote!(proof! { #(#s)* }));
            }
            out.push(syn::parse_quote!(while #cond { #(#bo)* }));
            if !at.after.is_empty() {
                let s = &at.after;
                out.push(syn::parse_quote!(proof! { #(#s)* }));
            }
            // after the loop: the header's values (of the loop variables,
            // in their own names) as its last test computed them
            let mut e_after = env_c;
            e_after.vals.retain(|k, _| k.0 == 0);
            return self.go(0, exit, e_after, cx, out);
        }
        // a tail-recursive helper over the variables live at the header (and
        // those the attachment names)
        // a method's loop over its receiver (`&mut self`, `self`): a method
        // helper of the impl, `Self::m__loopK(self, ..)` (as the source lift's)
        let receiver = self.spec.params.first().is_some_and(|p| p == "self");
        let mut params: Vec<usize> = live.iter().copied().filter(|l| *l != 0).collect();
        let method = receiver && params.contains(&1);
        let name = if method {
            format_ident!("{}__loop{}", self.spec.lifted_name.rsplit("::").next().unwrap_or(""), k)
        } else {
            format_ident!("{}__loop{}", self.spec.lifted_name.replace("::", "__"), k)
        };
        let callee: syn::Expr = if method { syn::parse_quote!(Self::#name) } else { syn::parse_quote!(#name) };
        let mentioned = |e: &TokenStream, n: &str| -> bool { ts_mentions(e.clone(), n) };
        let mut attach_ts = TokenStream::new();
        for e in at.invariants.iter().chain(at.ensures.iter()).chain(at.decreases.iter()) {
            attach_ts.extend(e.to_token_stream());
        }
        for s in &at.at_start {
            attach_ts.extend(s.to_token_stream());
        }
        for l in 1..self.frames[0].f.locals.len() {
            let n = self.frames[0].names[l].clone();
            if !params.contains(&l) && (self.is_param(0, l) || env.declared.contains(&n)) && mentioned(&attach_ts, &n) {
                params.push(l);
            }
        }
        // the order of first use in the loop (block order), states last
        let mut order: Vec<usize> = Vec::new();
        {
            let f = self.frames[0].f;
            let note = |l: usize, order: &mut Vec<usize>| {
                if !order.contains(&l) {
                    order.push(l);
                }
            };
            for b in body.iter() {
                let bl = &f.blocks[*b];
                for st in &bl.stmts {
                    if let Stmt::Assign(pl, r, _) = st {
                        let mut u = Vec::new();
                        rv_locals(r, &mut u);
                        for l in u {
                            note(l, &mut order);
                        }
                        note(pl.local, &mut order);
                    }
                }
                if let Term::Call(_, args, d, _) = &bl.term {
                    for a in args {
                        if let Operand::Copy(pl) | Operand::Move(pl) = a {
                            note(pl.local, &mut order);
                        }
                    }
                    note(d.local, &mut order);
                }
                if let Term::Switch(Operand::Copy(pl) | Operand::Move(pl), ..) = &bl.term {
                    note(pl.local, &mut order);
                }
            }
        }
        // a `&mut` temporary counts as the place it borrows
        let first_use = |l: usize| -> usize {
            let direct = order.iter().position(|x| *x == l);
            let via_ref = self.frames[0].f.blocks.iter().flat_map(|bl| bl.stmts.iter()).filter_map(|st| match st {
                Stmt::Assign(pl, Rvalue::Ref(_, q), _) if q.local == l => order.iter().position(|x| *x == pl.local),
                _ => None,
            }).min();
            direct.into_iter().chain(via_ref).min().unwrap_or(usize::MAX)
        };
        let is_state = |l: usize| self.spec.states.iter().any(|s| *s + 1 == l);
        params.sort_by_key(|l| (!(method && *l == 1), is_state(*l), first_use(*l), *l));
        self.loop_forms.push((k, "helper".into()));
        let args: Vec<syn::Expr> = params.iter().map(|l| self.state_or_var(&env, *l)).collect::<Result<_, _>>()?;
        out.push(syn::parse_quote!(return #callee(#(#args),*);));
        // the helper
        let mut henv = Env::default();
        for &l in &params {
            let n = self.frames[0].names[l].clone();
            henv.declared.insert(n.clone());
            if let Some(r) = env.refs.get(&(0, l)) {
                henv.refs.insert((0, l), r.clone());
            }
        }
        let mut inputs: Vec<TokenStream> = Vec::new();
        for &l in &params {
            let id = ident(&self.frames[0].names[l]);
            if method && l == 1 {
                inputs.push(quote!(mut self));
                continue;
            }
            let t = if self.spec.states.iter().any(|s| *s + 1 == l) {
                self.state_ty(l)?
            } else {
                let vt = value_ty(&self.frames[0].f.locals[l].0).ok_or_else(|| format!("a `&mut` local `{id}` live at a loop header"))?;
                self.nm.ty(self.m, &vt)?
            };
            inputs.push(quote!(mut #id: #t));
        }
        let mut hb: Vec<syn::Stmt> = Vec::new();
        // an exploded state is whole in the helper's parameters: explode it again
        for &l in &params {
            if let Some(r) = env.refs.get(&(0, l))
                && let Some((k, fs)) = &r.fields
            {
                let whole = r.lv.clone();
                for (i, f) in fs.iter().enumerate() {
                    let fe = self.field_expr(0, whole.clone(), &Ty::Adt(k.clone()), 0, i)?;
                    let id = ident(f);
                    hb.push(syn::parse_quote!(let mut #id = #fe;));
                    henv.declared.insert(f.clone());
                }
            }
        }
        if !at.at_start.is_empty() {
            let s = &at.at_start;
            hb.push(syn::parse_quote!(proof! { #(#s)* }));
        }
        let mut loops = cx.loops.clone();
        loops.push((h, LoopForm::Helper(callee.clone(), params.clone())));
        // the header's own statements run first in each call
        let cx_h = Cx { k: K::Ret, stop: None, loops: loops.clone(), probe: false };
        let flow = self.go_header(h, henv, &cx_h, &mut hb)?;
        if let Flow::Fall(_) = flow {
            return self.err(0, "a loop helper that falls through");
        }
        let mut attrs: Vec<syn::Attribute> = Vec::new();
        for i in &at.invariants {
            attrs.push(syn::parse_quote!(#[requires(#i)]));
        }
        if let Some(d) = &at.decreases {
            attrs.push(syn::parse_quote!(#[decreases(#d)]));
        }
        for e in &at.ensures {
            attrs.push(syn::parse_quote!(#[ensures(#e)]));
        }
        if method {
            // the lift places it in the impl (`lift::Ctx`)
            attrs.push(syn::parse_quote!(#[lift_method]));
        }
        let out_ty = &self.spec.out_ty;
        let item: syn::ItemFn = syn::parse_quote!(
            #(#attrs)*
            fn #name(#(#inputs),*) -> #out_ty { #(#hb)* }
        );
        self.helpers.push(syn::Item::Fn(item));
        self.helper_info.push(HelperInfo { name: name.to_string(), method, header: h, params: params.clone(), while_loop: false, local_names: vec![] });
        Ok(Flow::Diverge)
    }

    /// The header block of a helper (not a back edge: its first run).
    fn go_header(&mut self, h: usize, env: Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Flow, String> {
        // `go` treats `h` as a back edge while the helper is on the loop
        // stack; the header's body is walked here once
        let f = self.frames[0].f;
        let bl = &f.blocks[h];
        let mut env = env;
        for s in &bl.stmts {
            self.stmt(0, s, &mut env, out)?;
        }
        match &bl.term {
            Term::Goto(t) => self.go(0, *t, env, cx, out),
            Term::Call(callee, args, dest, target) => self.call(0, callee, args, dest, *target, env, cx, out),
            Term::Switch(d, arms, o) => self.switch(0, h, d, arms, *o, env, cx, out),
            Term::Assert(..) | Term::Drop(..) => {
                // rare: re-walk through `go` from a copy without the stack entry
                self.err(0, "a loop header ending in an assert or a drop")
            }
            other => self.err(0, format!("a loop header ending in {other:?}")),
        }
    }

    fn state_ty(&self, l: usize) -> Result<syn::Type, String> {
        let t = &self.frames[0].f.locals[l].0;
        match t {
            Ty::Ref(true, inner) => match &**inner {
                Ty::Ref(_, s) if matches!(**s, Ty::Slice(_)) => Ok(syn::parse_quote!(Seq<u8>)),
                other => self.nm.ty(self.m, other),
            },
            other => self.nm.ty(self.m, other),
        }
    }
}


/// A discriminant as the value of its type: rustc prints the bits of a
/// negative one (`Ordering::Less` is `-1i8`, printed `255`).
fn discr_value(bits: i128, t: &Ty) -> i128 {
    match t {
        Ty::Int(true, w) => {
            let w = if *w == 0 { 64 } else { *w };
            if w >= 128 {
                return bits;
            }
            let m = (bits as u128) & ((1u128 << w) - 1);
            if m >> (w - 1) == 1 { (m as i128) - (1i128 << w) } else { m as i128 }
        }
        _ => bits,
    }
}

/// Whether every path from block `b` ends in a panic or another end that
/// never returns (a diverging call, `unreachable`, an abort) without
/// returning or looping: such a path is one obligation, `unreachable!()`,
/// whatever it computes on the way (a panic's message, `assert_eq!`'s
/// operands and `AssertKind`, `fmt::Arguments`: none of it is observable,
/// as the call never returns). Reading such a block as `unreachable!()` is
/// never weaker than reading its statements: the obligation is that the
/// path is not taken at all.
fn must_diverge(f: &Fn, b: usize, visiting: &mut Vec<usize>) -> bool {
    if visiting.contains(&b) {
        return false;
    }
    let Some(bl) = f.blocks.get(b) else { return false };
    match &bl.term {
        Term::Unreachable | Term::Abort | Term::Resume => true,
        Term::Call(Callee::Diverge(_), ..) | Term::Call(_, _, _, None) => true,
        Term::Return | Term::Unsupported(_) => false,
        t => {
            visiting.push(b);
            let ss = super::cfg::succs(t);
            let r = !ss.is_empty() && ss.iter().all(|x| must_diverge(f, *x, visiting));
            visiting.pop();
            r
        }
    }
}

/// Integer methods read as the subset's builtins (their documented meaning
/// is the builtin's; `tests/mir.rs` compares each with core natively).
fn builtin_leaf(f: &Fn) -> Option<fn(&[syn::Expr]) -> (syn::Expr, bool)> {
    match (&f.item, f.def.as_str()) {
        (_, "std::cmp::Ord::max") | (_, "core::cmp::Ord::max") if f.args.first().is_some_and(|t| matches!(t, Ty::Int(false, _))) => Some(|a| {
            let (x, y) = (&a[0], &a[1]);
            (syn::parse_quote!(#x.max(#y)), true)
        }),
        (_, "std::cmp::Ord::min") | (_, "core::cmp::Ord::min") if f.args.first().is_some_and(|t| matches!(t, Ty::Int(false, _))) => Some(|a| {
            let (x, y) = (&a[0], &a[1]);
            (syn::parse_quote!(#x.min(#y)), true)
        }),
        (Item::Inherent(Ty::Int(false, _), m), _) if m == "div_ceil" => Some(|a| {
            let (x, y) = (&a[0], &a[1]);
            (syn::parse_quote!(#x.div_ceil(#y)), false)
        }),
        // core's iterators as the lift prelude's models (§19.9)
        (_, "std::ops::RangeInclusive::<Idx>::new" | "core::ops::RangeInclusive::<Idx>::new") if f.args.first() == Some(&Ty::Int(false, 32)) => Some(|a| {
            let (x, y) = (&a[0], &a[1]);
            (syn::parse_quote!(crate::__lift::range_inclusive_u32(#x, #y)), true)
        }),
        (_, "std::ops::RangeInclusive::<Idx>::new" | "core::ops::RangeInclusive::<Idx>::new") if f.args.first() == Some(&Ty::Int(false, 64)) => Some(|a| {
            let (x, y) = (&a[0], &a[1]);
            (syn::parse_quote!(crate::__lift::range_inclusive_u64(#x, #y)), true)
        }),
        // `uN::to_be_bytes`: the builtin (its bytes, most significant first)
        (Item::Inherent(Ty::Int(false, b), m), _) if m == "to_be_bytes" && *b != 0 => Some(|a| {
            let x = &a[0];
            (syn::parse_quote!(#x.to_be_bytes()), true)
        }),
        // `<[T]>::get(s, i)` by a `usize`: the subset's `get` (`None` past the end)
        (Item::Inherent(Ty::Slice(_), m), _) if m == "get" && f.args.get(1) == Some(&Ty::Int(false, 0)) => Some(|a| {
            let (s, i) = (&a[0], &a[1]);
            (syn::parse_quote!(#s.get(#i)), true)
        }),
        (_, "std::iter::once" | "core::iter::once") => Some(|a| {
            let x = &a[0];
            (syn::parse_quote!(crate::__lift::once(#x)), true)
        }),
        _ => None,
    }
}

/// Reads the function `spec.key` of `m`.
pub fn read(m: &Sbmir, nm: &dyn Names, spec: &Spec<'_>) -> Result<ReadOut, String> {
    let f = m.fns.get(spec.key).ok_or_else(|| format!("no MIR for `{}` (re-run the extraction)", spec.key))?;
    if !f.has_body {
        return Err(format!("`{}` has no MIR body", spec.key));
    }
    if f.argc != spec.params.len() {
        return Err(format!("`{}`: rustc's MIR has {} parameters, the lifted signature {}", spec.lifted_name, f.argc, spec.params.len()));
    }
    let cfg = Cfg::new(f);
    let mut r = Reader { m, nm, spec, frames: Vec::new(), cfg, fresh: 0, helpers: Vec::new(), loop_forms: Vec::new(), assigned_params: BTreeSet::new(), helper_info: Vec::new() };
    let fr = r.new_frame(f, true);
    let mut env = Env::default();
    let mut out = Vec::new();
    // parameters: states are places, the rest values
    for i in 0..f.argc {
        let l = i + 1;
        let t = &f.locals[l].0;
        let name = spec.params[i].clone();
        if spec.states.contains(&i) && opt_mut(m, t).is_some() {
            // `Option<&mut T>`: the optional place's value, a variable of
            // type `Option<T>` (its writes go through the matched field,
            // `Env::writeback`; it is returned like any state)
        } else if spec.states.contains(&i) {
            let buf = match t {
                Ty::Ref(true, inner) => match &**inner {
                    Ty::Ref(true, s) if matches!(**s, Ty::Slice(_)) => Some("bufmut"),
                    Ty::Ref(false, s) if matches!(**s, Ty::Slice(_)) => Some("buf"),
                    _ => None,
                },
                _ => return Err(format!("`{}`: the lifted state parameter `{name}` is not `&mut` in rustc's MIR", spec.lifted_name)),
            };
            let fields = r.explode(l, &name);
            if let Some((adt, fs)) = &fields {
                for (k, fv) in fs.iter().enumerate() {
                    let fe = r.field_expr(fr, var(&name), &Ty::Adt(adt.clone()), 0, k)?;
                    let id = ident(fv);
                    out.push(syn::parse_quote!(let mut #id = #fe;));
                    env.declared.insert(fv.clone());
                }
            }
            env.refs.insert((fr, l), LRef { lv: var(&name), buf, fields, inner: false });
        } else if matches!(t, Ty::Ref(true, _)) {
            return Err(format!("`{}`: rustc's MIR parameter `{name}` is `&mut` but the lift does not pass it as a state", spec.lifted_name));
        } else if matches!(t, Ty::Ref(false, _)) && !spec.ref_params.contains(&i) && name != "_" {
            // a `&self` the lift takes by value: the MIR's reference is to it
            env.vals.insert((fr, l), Val::R(Box::new(Val::E(var(&name)))));
        }
        env.declared.insert(name);
    }
    let cx = Cx { k: K::Ret, stop: None, loops: vec![], probe: false };
    let flow = r.go(fr, 0, env, &cx, &mut out)?;
    if let Flow::Fall(_) = flow {
        return Err(format!("`{}`: the reading fell off the end", spec.lifted_name));
    }
    Ok(ReadOut { body: syn::Block { brace_token: Default::default(), stmts: out }, helpers: r.helpers, loops: r.loop_forms, assigned_params: r.assigned_params.into_iter().collect(), helper_info: r.helper_info })
}
