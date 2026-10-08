//! The structured reading S of a MIR body (UNTRUSTED since
//! `docs/checked-structuring.md`; `docs/mir-lift.md` §20.3): one
//! monomorphized MIR body to exec-subset Rust. It only proposes S: every
//! verified build checks, for each lifted function, the kernel theorem
//! `L::thm::f` that the literal reading L of the same MIR (`literal.rs`,
//! trusted) returns S's value (`driver::gates::theorem_gate`). A bug here
//! makes a theorem unprovable and the build fail; it cannot change what a
//! verified module means. It cannot reach the function's contract either:
//! it sees the signature only, and the elaborator checks that the
//! function's preconditions are its declared contract's (`elab::items`).
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
    /// `requires(..)`: only an element attachment's (its function's
    /// precondition); the lift refuses it on a loop.
    pub requires: Vec<syn::Expr>,
    pub at_start: Vec<syn::Stmt>,
    pub steps: Vec<syn::Stmt>,
    pub at_end: Vec<syn::Stmt>,
    pub after: Vec<syn::Stmt>,
    /// An element attachment (`#[lift_attach(path, loop_nr = k, element)]`):
    /// the loop's body on one element of a slice (the element an `IterMut`
    /// yields, or the one a loop inside another loop's body works on
    /// through references into it) is read as a function of that element
    /// ([`Reader::extract_element`]), opaque, with this contract.
    pub element: Option<ElementAttach>,
}

/// An element attachment's contract and proof steps.
#[derive(Clone, Debug, Default)]
pub struct ElementAttach {
    pub ensures: Vec<syn::Expr>,
    /// `requires(..)`: what the body needs of the variables it reads (its
    /// callers, the loop's iterations, prove it).
    pub requires: Vec<syn::Expr>,
    /// `at_start! { .. }`: proof steps before the body (facts about the
    /// element and the variables it reads).
    pub at_start: Vec<syn::Stmt>,
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
    /// The element functions built ([`Reader::extract_element`]), by name:
    /// the walk unfolds them where a loop helper calls them.
    pub elements: Vec<String>,
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
    /// A helper of a loop inside another loop's body: the positions (among
    /// `params`) of the parameters it returns at the loop's exit; its lemma
    /// is a `while` loop's (from the header to the exit), `local_names`
    /// naming its parameters' locals.
    pub returns: Option<Vec<usize>>,
    /// The loop helper whose body holds this loop (`None`: the lifted
    /// function's own body), and whether it is a method helper.
    pub owner: Option<(String, bool)>,
    /// The helper's parameters that are core's `IterMut` over the referent
    /// of a `&mut [T]` parameter: (their position among `params`, that
    /// parameter's local). At the header the literal reading holds such an
    /// iterator as (the parameter's code, the index).
    pub iters: Vec<(usize, usize)>,
    /// A returning helper's references into an element of a state, which
    /// it rebuilds rather than takes: (the reference's local, the state's
    /// position among `params`, the position of the element's index among
    /// the helper's parameters (one of `extra`), the range of the element
    /// it refers to as the literal reading's `PRange(lo, hi)`, if any). At
    /// the header the literal reading holds such a reference as the
    /// state's code with `PIndex(index)` (then `PRange(lo, hi)`).
    pub derived: Vec<(usize, usize, usize, Option<(u128, u128)>)>,
    /// The helper's parameters after `params` that carry no local (an
    /// element's index, `derived`), by name.
    pub extra: Vec<String>,
}

/// [`root_locals`], with a `&mut T` local typed as the `T` it refers to (an
/// element attachment names a loop's element by its variable, as a value).
pub fn root_locals_deref(m: &Sbmir, nm: &dyn Names, key: &str, params: &[String]) -> Result<Vec<(String, Option<syn::Type>)>, String> {
    let f = m.fns.get(key).ok_or_else(|| format!("no MIR for `{key}`"))?;
    let names = local_names(f, params, true);
    Ok(names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let t = match &f.locals[i].0 {
                Ty::Ref(true, inner) => Some((**inner).clone()),
                other => value_ty(other),
            };
            (n.clone(), t.and_then(|t| nm.ty(m, &t).ok()))
        })
        .collect())
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
/// *size;`: `size` → `size_2`; the iterator rustc names `iter` in every
/// `for` loop: `iter` → `iter_24` in an inner loop): loop attachments are
/// written against the source's scopes. The variable of that name live at
/// the header is the one in scope there; when several are live (an outer
/// loop's iterator, still needed after the inner loop), the innermost
/// binding is: the one whose definition comes after every other one's on
/// every path (its definition is dominated by theirs), as a later `let` of
/// the same name shadows an earlier one. Two bindings neither of which
/// comes first stay unresolved. (Attachments are proof steps and checked
/// contracts of the helper, so this choice cannot change what is proven
/// about the code.)
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
    let idom = dominators(&cfg);
    let sites = def_sites(f, &cfg);
    Ok(cfg
        .headers
        .iter()
        .map(|h| {
            let mut map = HashMap::new();
            for (n, ls) in &by_name {
                let live: Vec<usize> = ls.iter().copied().filter(|l| cfg.live_in[*h].contains(l)).collect();
                if ls.len() < 2 || live.is_empty() {
                    continue;
                }
                let chosen = if live.len() == 1 { Some(live[0]) } else { innermost(&live, &sites, &idom, f.argc) };
                if let Some(c) = chosen
                    && names[c] != *n
                {
                    map.insert(n.clone(), names[c].clone());
                }
            }
            map
        })
        .collect())
}

/// The immediate dominator of every reachable block (`None` for the entry
/// and unreachable blocks), by the iterative algorithm of Cooper, Harvey and
/// Kennedy on a reverse post-order.
fn dominators(cfg: &Cfg) -> Vec<Option<usize>> {
    let n = cfg.n;
    if n == 0 {
        return vec![];
    }
    // reverse post-order from the entry
    let mut post: Vec<usize> = Vec::new();
    let mut seen = vec![false; n];
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    seen[0] = true;
    while let Some((b, i)) = stack.pop() {
        if let Some(&s) = cfg.succ[b].get(i) {
            stack.push((b, i + 1));
            if !seen[s] {
                seen[s] = true;
                stack.push((s, 0));
            }
        } else {
            post.push(b);
        }
    }
    let mut order = vec![usize::MAX; n];
    for (i, b) in post.iter().enumerate() {
        order[*b] = i;
    }
    let rpo: Vec<usize> = post.iter().rev().copied().collect();
    let mut idom: Vec<Option<usize>> = vec![None; n];
    idom[0] = Some(0);
    let intersect = |idom: &[Option<usize>], mut a: usize, mut b: usize| -> usize {
        while a != b {
            while order[a] < order[b] {
                a = idom[a].unwrap_or(0);
            }
            while order[b] < order[a] {
                b = idom[b].unwrap_or(0);
            }
        }
        a
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let mut new: Option<usize> = None;
            for &p in &cfg.pred[b] {
                if idom[p].is_none() {
                    continue;
                }
                new = Some(match new {
                    None => p,
                    Some(x) => intersect(&idom, p, x),
                });
            }
            if new.is_some() && idom[b] != new {
                idom[b] = new;
                changed = true;
            }
        }
    }
    idom[0] = None;
    idom
}

/// Whether block `a` dominates block `b`.
fn dominates(idom: &[Option<usize>], a: usize, b: usize) -> bool {
    let mut x = b;
    for _ in 0..idom.len() + 1 {
        if x == a {
            return true;
        }
        match idom.get(x).copied().flatten() {
            Some(p) => x = p,
            None => return false,
        }
    }
    false
}

/// Where each local is first defined: the block and statement index of its
/// first whole assignment (a call's result is its block's last
/// "statement"), in reverse post-order of the reachable blocks.
fn def_sites(f: &Fn, cfg: &Cfg) -> HashMap<usize, (usize, usize)> {
    let mut sites: HashMap<usize, (usize, usize)> = HashMap::new();
    let mut order: Vec<usize> = (0..f.blocks.len()).filter(|b| cfg.reach.get(*b).copied().unwrap_or(false)).collect();
    let (post, _) = super::cfg::dfs_order(f);
    order.sort_by_key(|b| std::cmp::Reverse(post.get(*b).copied().unwrap_or(0)));
    for b in order {
        let bl = &f.blocks[b];
        for (i, s) in bl.stmts.iter().enumerate() {
            if let Stmt::Assign(p, _, _) = s
                && p.proj.is_empty()
            {
                sites.entry(p.local).or_insert((b, i));
            }
        }
        if let Term::Call(_, _, dest, _) = &bl.term
            && dest.proj.is_empty()
        {
            sites.entry(dest.local).or_insert((b, bl.stmts.len()));
        }
    }
    sites
}

/// The innermost of several live locals of one name: the one whose
/// definition every other one's precedes (dominates); a parameter's
/// definition is the entry. `None` when no single one is innermost.
fn innermost(live: &[usize], sites: &HashMap<usize, (usize, usize)>, idom: &[Option<usize>], argc: usize) -> Option<usize> {
    let site = |l: usize| -> Option<(usize, i64)> {
        if l >= 1 && l <= argc {
            return Some((0, -1));
        }
        sites.get(&l).map(|(b, i)| (*b, *i as i64))
    };
    // `a`'s definition precedes `b`'s on every path
    let before = |a: (usize, i64), b: (usize, i64)| -> bool { if a.0 == b.0 { a.1 < b.1 } else { dominates(idom, a.0, b.0) } };
    let mut found = None;
    for &c in live {
        let Some(sc) = site(c) else { return None };
        let mut inner = true;
        for &o in live {
            if o == c {
                continue;
            }
            let Some(so) = site(o) else { return None };
            if !before(so, sc) {
                inner = false;
                break;
            }
        }
        if inner {
            if found.is_some() {
                return None;
            }
            found = Some(c);
        }
    }
    found
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
    /// A raw pointer of crate code (docs/mir-lift.md §20.10): it has no
    /// value in the subset; its loads and stores read and write its base.
    Ptr(Box<PtrVal>),
    /// `IterMut::next`'s result before its discriminant is tested: `Some`
    /// of the place (the slice's element at the index stepped over) when
    /// `cond` (a variable) holds, else `None`; with the iterator's local and
    /// its value one further, which the `Some` arm sets.
    Next(syn::Expr, LRef, Key, syn::Expr),
    /// A `&mut` to a place, held in a constructor's field (`Some(&mut x[i])`).
    Place(LRef),
}

/// A raw pointer as the structured reading holds it: its base (the place a
/// mutable formation's reference names, or a shared formation's base
/// value), the base's MIR type, and the byte offset (a literal).
#[derive(Clone, Debug)]
struct PtrVal {
    base: PBase,
    base_ty: Ty,
    off: u64,
    mutable: bool,
}

#[derive(Clone, Debug)]
enum PBase {
    Mut(LRef),
    Shr(syn::Expr),
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
    /// A subslice of the place (`split_at_mut`'s halves): its first element's
    /// index in the place and its length. `(*r)[i]` is the place's element
    /// `off.wrapping_add(i)` (the literal reading's `PRange` then `PIndex`,
    /// `mir::range_index`, after the bounds check `i < len`).
    range: Option<(syn::Expr, syn::Expr)>,
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
    /// core's `IterMut` locals (their value: the index of the element they
    /// yield next) and the slice place each walks; a `&mut` to one, the
    /// local it points to.
    iters: HashMap<Key, LRef>,
    iter_refs: HashMap<Key, Key>,
    /// A pointer family's window over a byte array (§20.10): the base's
    /// bytes as the stores so far left them (`c[j]` of the value before the
    /// first store, else the byte a store wrote), by the base's place. The
    /// window rule (W2) has the family alone on the base meanwhile, so a
    /// load or store reads these instead of reading the state back.
    windows: HashMap<String, Vec<syn::Expr>>,
}

enum Flow {
    Diverge,
    Fall(Env),
    /// The condition of a probed loop header: `(cond, target when true,
    /// target when false, env, the frame and block of the test)`.
    Cond(syn::Expr, usize, usize, Env, usize, usize),
}

/// The tests without effects that decide a `while` loop's condition
/// (`a || b`): leaves are the body's entry (`true`) or the exit (`false`).
#[derive(Clone)]
enum CondTree {
    Leaf(bool, usize, Env),
    /// A test: its condition, its block, and the trees when true and false.
    Test(syn::Expr, usize, Box<CondTree>, Box<CondTree>),
}

impl CondTree {
    fn exits(&self) -> bool {
        match self {
            CondTree::Leaf(b, ..) => !b,
            CondTree::Test(_, _, t, f) => t.exits() || f.exits(),
        }
    }

    fn leaves(&self, out: &mut Vec<(bool, usize, Env)>) {
        match self {
            CondTree::Leaf(b, k, e) => out.push((*b, *k, e.clone())),
            CondTree::Test(_, _, t, f) => {
                t.leaves(out);
                f.leaves(out);
            }
        }
    }

    /// The condition under which the body runs. The tests have no effects
    /// and no obligations, so they are joined without short circuit (`|`,
    /// `&`: one test of each in the structured reading, not a `match` on
    /// the first).
    fn expr(&self) -> syn::Expr {
        use CondTree::{Leaf, Test};
        match self {
            Leaf(true, ..) => syn::parse_quote!(true),
            Leaf(false, ..) => syn::parse_quote!(false),
            Test(c, _, t, f) => match (&**t, &**f) {
                (Leaf(true, ..), Leaf(false, ..)) => c.clone(),
                (Leaf(false, ..), Leaf(true, ..)) => syn::parse_quote!(!(#c)),
                (Leaf(true, ..), g) => {
                    let g = g.expr();
                    syn::parse_quote!((#c) | (#g))
                }
                (Leaf(false, ..), g) => {
                    let g = g.expr();
                    syn::parse_quote!(!(#c) & (#g))
                }
                (g, Leaf(true, ..)) => {
                    let g = g.expr();
                    syn::parse_quote!(!(#c) | (#g))
                }
                (g, Leaf(false, ..)) => {
                    let g = g.expr();
                    syn::parse_quote!((#c) & (#g))
                }
                (g, h) => {
                    let (g, h) = (g.expr(), h.expr());
                    syn::parse_quote!(((#c) & (#g)) | (!(#c) & (#h)))
                }
            },
        }
    }
}

/// The locals the blocks `body` assign (whole or in part), borrow mutably
/// or receive a call's result in.
fn loop_assigns(f: &Fn, body: &BTreeSet<usize>) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for b in body {
        let bl = &f.blocks[*b];
        for s in &bl.stmts {
            if let Stmt::Assign(p, r, _) = s {
                out.insert(p.local);
                if let Rvalue::Ref(k, q) = r
                    && k == "mut"
                {
                    out.insert(q.local);
                }
            }
        }
        if let Term::Call(_, _, d, _) = &bl.term {
            out.insert(d.local);
        }
    }
    out
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
        Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) | Rvalue::AddrOf(_, p) => out.push(p.local),
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
    /// The helper as called (`f__loop0`, `Self::m__loop0`), its parameters,
    /// and its parameters that carry no local (an element's index: the
    /// same in every call, `returning_helper`).
    Helper(syn::Expr, Vec<usize>, Vec<String>),
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
    /// The bodies of the library functions read as models ([`model_body`]).
    models: &'m std::collections::BTreeMap<String, Fn>,
    spec: &'m Spec<'m>,
    frames: Vec<Frame<'m>>,
    cfg: Cfg,
    fresh: usize,
    helpers: Vec<syn::Item>,
    loop_forms: Vec<(usize, String)>,
    assigned_params: BTreeSet<usize>,
    helper_info: Vec<HelperInfo>,
    /// The loop helper being written (`None`: the lifted function's body),
    /// and the `while` loops written so far per function.
    owner: Option<(String, bool)>,
    whiles: std::collections::BTreeMap<String, usize>,
    /// core's `IterMut` locals of the lifted function: the slice they walk
    /// (its place, for a loop's measure) and, when it is a `&mut [T]`
    /// parameter's referent, that parameter's local (for the loop lemma).
    iter_slices: HashMap<usize, syn::Expr>,
    iter_params: HashMap<usize, usize>,
    /// The name of the variable an `IterMut`'s element is bound to (the
    /// source's loop variable), by the index variable the element's place
    /// is indexed with (`chunk` for `x[__i2]`).
    elem_names: HashMap<String, String>,
    /// [`ReadOut::elements`].
    elements: Vec<String>,
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

/// The names a `let` pattern binds.
fn pat_names(p: &syn::Pat, out: &mut Vec<String>) {
    match p {
        syn::Pat::Ident(pi) => out.push(pi.ident.to_string()),
        syn::Pat::Type(pt) => pat_names(&pt.pat, out),
        syn::Pat::Tuple(t) => t.elems.iter().for_each(|q| pat_names(q, out)),
        syn::Pat::TupleStruct(t) => t.elems.iter().for_each(|q| pat_names(q, out)),
        _ => {}
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
    // (a mutable pointer names a place, not a value: what it reads is the
    // place's current value)
    if let Val::Ptr(p) = v {
        return matches!(&p.base, PBase::Shr(e) if mentions(e, name));
    }
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
            // the one value of an enum whose other variants are empty
            // (`Option<Infallible>`'s `None`, `?`'s residual): its constructor
            Const::Zst(Ty::Adt(k)) if let Some(v) = single_value(self.m, k) => Val::C(Ty::Adt(k.clone()), v, vec![]),
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
            Val::Ptr(_) => return self.err(fr, "a raw pointer used as a value (it has none in the subset: only its loads and stores are read, docs/mir-lift.md §20.10)"),
            Val::Next(..) | Val::Place(_) => return self.err(fr, "a `&mut` to a place used as a value (an `IterMut` element)"),
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
                        // an element of a subslice: the place's element `off + i`
                        (None, Some(Proj::Index(l))) if r.range.is_some() => {
                            let (off, _) = r.range.clone().unwrap_or_else(|| unreachable!());
                            let l = *l;
                            projs.next();
                            let (iv, _) = self.read(fr, &Place { local: l, proj: vec![] }, env, out)?;
                            let ie = self.materialize(fr, &iv)?;
                            let (lv, off) = (paren(r.lv.clone()), paren(off));
                            t = match t {
                                Ty::Array(e, _) | Ty::Slice(e) => *e,
                                other => return self.err(fr, format!("index of {other:?}")),
                            };
                            Val::E(syn::parse_quote!(#lv[#off.wrapping_add(#ie)]))
                        }
                        (None, _) if r.range.is_some() => return self.err(fr, "a subslice read whole (only its elements are read)"),
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
        } else if let Ty::Adt(k) = &self.frames[fr].f.locals[p.local].0
            && let Some(v) = single_value(self.m, k)
        {
            // nor the one value of an enum whose other variants are empty
            // (`Option<Infallible>`, `?`'s residual: rustc drops its assignment)
            Val::C(Ty::Adt(k.clone()), v, vec![])
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
                // an order comparison: the bits with the sign bit flipped, compared
                // unsigned (the literal reading's `mir::slt_*`/`mir::sle_*`)
                let sb = lit_uint(1u128 << (bits - 1), uint_name(*bits));
                let (e, pure): (syn::Expr, bool) = match op {
                    // MIR's plain `Add`/`Sub`/`Mul` wrap: the same on the bits
                    "add" => (syn::parse_quote!(#sp(#ea.0.wrapping_add(#eb.0))), true),
                    "sub" => (syn::parse_quote!(#sp(#ea.0.wrapping_sub(#eb.0))), true),
                    "mul" => (syn::parse_quote!(#sp(#ea.0.wrapping_mul(#eb.0))), true),
                    "lt" => (syn::parse_quote!((#ea.0 ^ #sb) < (#eb.0 ^ #sb)), true),
                    "le" => (syn::parse_quote!((#ea.0 ^ #sb) <= (#eb.0 ^ #sb)), true),
                    "gt" => (syn::parse_quote!((#eb.0 ^ #sb) < (#ea.0 ^ #sb)), true),
                    "ge" => (syn::parse_quote!((#eb.0 ^ #sb) <= (#ea.0 ^ #sb)), true),
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
        // `transmute` between `[u8; n]` and an unsigned word of `n` bytes: its
        // little-endian bytes (the targets are little-endian, SEMANTICS.md §19)
        if kind == "transmute" {
            let from = self.op_ty(fr, a)?;
            let byte_array = |t: &Ty, w: u32| matches!(t, Ty::Array(e, n) if **e == Ty::Int(false, 8) && 8 * *n == w as u64);
            let word = |t: &Ty| match t {
                Ty::Int(false, b @ (16 | 32 | 64)) => Some(*b),
                _ => None,
            };
            let (e, pu) = self.operand_expr(fr, a, env, out)?;
            let e = paren(e);
            if let Some(w) = word(to)
                && byte_array(&from, w)
            {
                let tn = format_ident!("u{}", w);
                return Ok((syn::parse_quote!(#tn::from_le_bytes(#e)), pu));
            }
            if let Some(w) = word(&from)
                && byte_array(to, w)
            {
                return Ok((syn::parse_quote!(#e.to_le_bytes()), pu));
            }
            return self.err(fr, format!("the cast `transmute` of {from:?} to {to:?}"));
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
            // sign extension of the bits (the literal reading's `mir::sext_*`):
            // the wider word with the high bits set when the sign bit is
            // (to `usize` through `u64`, as the literal reading does)
            (Ty::Int(true, f @ (16 | 32)), _) if tb > fb && (to.signed() || matches!(to, Ty::Int(false, _))) => {
                let tw = if matches!(to, Ty::Int(false, 0)) { 64 } else { tb };
                let wu = format_ident!("{}", uint_name(tw));
                let sign = lit_uint(1u128 << (f - 1), uint_name(*f));
                let high = lit_uint(((1u128 << tw) - 1) ^ ((1u128 << f) - 1), uint_name(tw));
                let ext: syn::Expr = syn::parse_quote!(if #e.0 < #sign { #e.0 as #wu } else { (#e.0 as #wu) | #high });
                match (to.signed(), to) {
                    (true, _) => {
                        let sp = signed_path(tb);
                        syn::parse_quote!(#sp(#ext))
                    }
                    (false, Ty::Int(false, 0)) => syn::parse_quote!((#ext) as usize),
                    _ => ext,
                }
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
                // an element of a subslice: the place's element `off + i`
                (None, Some(Proj::Index(l))) if r.range.is_some() => {
                    let (off, _) = r.range.clone().unwrap_or_else(|| unreachable!());
                    let l = *l;
                    projs.next();
                    let (iv, _) = self.read(fr, &Place { local: l, proj: vec![] }, env, out)?;
                    let ie = self.materialize(fr, &iv)?;
                    let base = r.lv.to_token_stream().into_iter().next().map(|t| t.to_string()).unwrap_or_default();
                    let (lv, off) = (paren(r.lv.clone()), paren(off));
                    t = match t {
                        Ty::Array(e, _) | Ty::Slice(e) => *e,
                        other => return self.err(fr, format!("index of {other:?}")),
                    };
                    (syn::parse_quote!(#lv[#off.wrapping_add(#ie)]), base)
                }
                (None, _) if r.range.is_some() => return self.err(fr, "a subslice written whole (only its elements are written)"),
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
        // a `&mut` to a place (an `IterMut` element moved out of its `Some`):
        // the same place
        if let Val::Place(r) = &v
            && p.proj.is_empty()
        {
            // (the element's variable, for an element function's parameter)
            if fr == 0
                && self.named(fr, p.local)
                && r.range.is_none()
                && let syn::Expr::Index(ix) = &r.lv
                && let syn::Expr::Path(ip) = &*ix.index
                && let Some(i) = ip.path.get_ident()
            {
                self.elem_names.entry(i.to_string()).or_insert_with(|| self.frames[fr].names[p.local].clone());
            }
            env.refs.insert(key, r.clone());
            return Ok(());
        }
        // a raw pointer is carried (it has no value in the subset)
        if matches!(v, Val::Ptr(_) | Val::Next(..)) {
            if !p.proj.is_empty() {
                return self.err(fr, "a raw pointer stored into a place (it goes through memory)");
            }
            env.vals.insert(key, v);
            return Ok(());
        }
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
            // storage markers have no meaning
            Stmt::Storage(..) => Ok(()),
            Stmt::Assign(p, r, _) => {
                let key = (fr, p.local);
                match r {
                    Rvalue::Ref(k, q) if k == "mut" => {
                        if !p.proj.is_empty() {
                            return self.err(fr, "a `&mut` stored into a place");
                        }
                        // (a `&mut` to an `IterMut` local, for its `next`)
                        if q.proj.is_empty() && env.iters.contains_key(&(fr, q.local)) {
                            env.iter_refs.insert(key, (fr, q.local));
                        }
                        let lr = self.mut_ref(fr, q, env, out)?;
                        env.refs.insert(key, lr);
                        return Ok(());
                    }
                    // an `IterMut` moved or copied: the same iterator
                    Rvalue::Use(Operand::Copy(q) | Operand::Move(q)) if p.proj.is_empty() && q.proj.is_empty() && env.iters.contains_key(&(fr, q.local)) => {
                        let r = env.iters[&(fr, q.local)].clone();
                        env.iters.insert(key, r);
                        self.iter_moved(fr, q.local, p.local);
                    }
                    Rvalue::Ref(k, _) if k == "fake" => return Ok(()),
                    // `&mut [T; N]` as `&mut [T]`: the same place (a pointer
                    // formation looks through it, `ptr::bases`)
                    Rvalue::Cast(k, Operand::Copy(q) | Operand::Move(q), Ty::Ref(true, _)) if k == "unsize" && p.proj.is_empty() && q.proj.is_empty() && env.refs.contains_key(&(fr, q.local)) => {
                        let r = env.refs[&(fr, q.local)].clone();
                        env.refs.insert(key, r);
                        return Ok(());
                    }
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
                // asserted (core's `checked_add`), or of a signed type (the
                // subset has no signed operator with an overflow obligation):
                // the pair (wrapped result, overflowed), exactly; an assert
                // of the flag is then its own obligation
                if let Rvalue::Checked(op, a, b) = r
                    && (!self.flag_asserted(fr, s, p) || self.op_ty(fr, a)?.signed())
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
        let ta = self.op_ty(fr, a)?;
        // signed `add`/`sub`: the wrapped bits, and the overflow flag as the
        // sign bit of `(a ^ r) & (b ^ r)` (`(a ^ b) & (a ^ r)`), the literal
        // reading's `mir::scheck_*` (both total)
        if let Ty::Int(true, bits @ (16 | 32 | 64)) = ta
            && matches!(op, "add" | "sub")
        {
            let (ea, pa) = self.operand_expr(fr, a, env, out)?;
            let (eb, pb) = self.operand_expr(fr, b, env, out)?;
            let (ea, eb) = (paren(ea), paren(eb));
            let (sp, sb) = (signed_path(bits), lit_uint(1u128 << (bits - 1), uint_name(bits)));
            let (r, flag): (syn::Expr, syn::Expr) = if op == "add" {
                let r: syn::Expr = syn::parse_quote!(#ea.0.wrapping_add(#eb.0));
                (r.clone(), syn::parse_quote!(((#ea.0 ^ #r) & (#eb.0 ^ #r)) >= #sb))
            } else {
                let r: syn::Expr = syn::parse_quote!(#ea.0.wrapping_sub(#eb.0));
                (r.clone(), syn::parse_quote!(((#ea.0 ^ #eb.0) & (#ea.0 ^ #r)) >= #sb))
            };
            let wv = self.bind(syn::parse_quote!(#sp(#r)), pa && pb, None, out);
            let cv = self.bind(flag, pa && pb, None, out);
            return Ok(Val::C(dest_ty.clone(), 0, vec![wv, cv]));
        }
        if ta.signed() || !ta.is_int() {
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
            return Ok(LRef { lv: var(&n), buf: None, fields: None, inner: true, range: None });
        }
        let (lv, _) = self.lvalue(fr, q, env, out)?;
        let t = self.place_ty(fr, q)?;
        let buf = match &t {
            Ty::Ref(true, inner) if matches!(**inner, Ty::Slice(ref e) if **e == Ty::Int(false, 8)) => Some("bufmut"),
            Ty::Ref(false, inner) if matches!(**inner, Ty::Slice(ref e) if **e == Ty::Int(false, 8)) => Some("buf"),
            _ => None,
        };
        Ok(LRef { lv, buf, fields: None, inner: false, range: None })
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
            // between raw pointers: the same pointer
            Rvalue::Cast(k, a, _) if k == "ptr-to-ptr" => match self.operand(fr, a, env, out)? {
                (v @ Val::Ptr(_), _) => Ok(v),
                _ => self.err(fr, "a pointer cast of something that is no pointer of an admitted formation"),
            },
            // `Offset(p, k)`: `p` moved by `k` elements
            Rvalue::Bin(op, a, b) if op == "offset" => {
                let Ty::Ptr(_, pointee) = self.op_ty(fr, a)? else { return self.err(fr, "`Offset` of something that is no pointer") };
                let signed = self.op_ty(fr, b)?.signed();
                self.ptr_moved(fr, a, b, false, signed, &pointee, env, out).map(|p| Val::Ptr(Box::new(p)))
            }
            // a division or remainder of two unsigned literals by a divisor
            // that is not zero (`SHARD_CHUNK_BYTES / 2`): its value (a
            // constant length or offset)
            Rvalue::Bin(op, a, b)
                if matches!(op.as_str(), "div" | "rem")
                    && let (Ok(Ty::Int(false, _)), Some((ta, x)), Some((_, y))) = (self.op_ty(fr, a), Self::int_const(a), Self::int_const(b))
                    && x >= 0
                    && y > 0 =>
            {
                let r = if op == "div" { x / y } else { x % y };
                Ok(Val::E(lit_uint(r as u128, &int_ty_name(ta).unwrap_or_default())))
            }
            Rvalue::Bin(op, a, b) => {
                let (e, p) = self.binop(fr, op, a, b, env, out)?;
                Ok(self.bind(e, p, t, out))
            }
            // checked arithmetic on two unsigned literals that does not
            // overflow (`16 * 2`): its value (a constant offset)
            Rvalue::Checked(op, a, b)
                if let (Ok(Ty::Int(false, bits)), Some((_, x)), Some((_, y))) = (self.op_ty(fr, a), Self::int_const(a), Self::int_const(b))
                    && let Some(r) = match op.as_str() {
                        "add" => (x as u128).checked_add(y as u128),
                        "sub" => (x as u128).checked_sub(y as u128),
                        "mul" => (x as u128).checked_mul(y as u128),
                        _ => None,
                    }
                    && r <= (if bits == 0 { u64::MAX as u128 } else { (1u128 << bits) - 1 }) =>
            {
                let tn = int_ty_name(&Ty::Int(false, bits)).unwrap_or_default();
                Ok(Val::C(dest_ty.clone(), 0, vec![Val::E(lit_uint(r, &tn)), Val::E(syn::parse_quote!(false))]))
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
            // the length of a slice place (the parse's `Len` of rustc's
            // `PtrMetadata(&raw const (fake) *r)`): a subslice's own, an
            // array's `N`, else the place's `len()`
            Rvalue::Len(q) => {
                // (only of a slice or an array, as the literal reading reads it)
                if !matches!(self.place_ty(fr, q)?, Ty::Slice(_) | Ty::Array(..)) {
                    return self.err(fr, "a length of a place that is no slice or array");
                }
                if let [Proj::Deref] = q.proj.as_slice()
                    && let Some(r) = env.refs.get(&(fr, q.local)).cloned()
                {
                    if let Some((_, len)) = &r.range {
                        return Ok(Val::E(len.clone()));
                    }
                    if let Some(n) = self.array_len_through(fr, q.local) {
                        return Ok(Val::E(lit_uint(n as u128, "usize")));
                    }
                    let lv = paren(r.lv.clone());
                    return Ok(Val::E(syn::parse_quote!(#lv.len())));
                }
                let (v, _) = self.read(fr, q, env, out)?;
                let e = paren(self.materialize(fr, &v)?);
                Ok(Val::E(syn::parse_quote!(#e.len())))
            }
            Rvalue::AddrOf(..) => self.err(fr, "`&raw` (a pointer formation the structured reading does not read here)"),
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
                    LoopForm::Helper(name, params, extra) => {
                        // (a loop with an element attachment: where its
                        // body on the element ends, `extract_element`)
                        if self.element_loop(b) {
                            out.push(syn::parse_quote!(__sb_element_end!();));
                        }
                        let live = self.live_at(b);
                        self.normalize(&live, &mut env, out)?;
                        let mut args: Vec<syn::Expr> = params.iter().map(|l| self.state_or_var(&env, *l)).collect::<Result<_, _>>()?;
                        args.extend(extra.iter().map(|n| var(n)));
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
            Callee::Intrinsic(name, _) if matches!(name.as_str(), "ctpop" | "cttz" | "saturating_add" | "saturating_sub" | "add_with_overflow" | "sub_with_overflow" | "mul_with_overflow" | "rotate_left" | "rotate_right" | "bswap") => {
                let mut es = Vec::new();
                for a in args {
                    es.push(paren(self.operand_expr(fr, a, &env, out)?.0));
                }
                // the byte swap by shifts and masks, as the literal reading's `mir::bswap_*`
                let bswap = |x: &syn::Expr, bits: u32| -> Option<syn::Expr> {
                    let l = |v: u128, t: &str| lit_uint(v, t);
                    Some(match bits {
                        16 => {
                            let (a, b) = (l(8, "u32"), l(8, "u32"));
                            syn::parse_quote!(#x.wrapping_shl(#a) | #x.wrapping_shr(#b))
                        }
                        32 => {
                            let (m0, m1, s8, s24) = (l(255, "u32"), l(65280, "u32"), l(8, "u32"), l(24, "u32"));
                            syn::parse_quote!(((#x & #m0).wrapping_shl(#s24) | (#x & #m1).wrapping_shl(#s8)) | ((#x.wrapping_shr(#s8) & #m1) | #x.wrapping_shr(#s24)))
                        }
                        64 => {
                            let m = |v: u128| l(v, "u64");
                            let s = |v: u128| l(v, "u32");
                            let (m0, m1, m2, m3) = (m(255), m(65280), m(16711680), m(4278190080));
                            let (s8, s24, s40, s56) = (s(8), s(24), s(40), s(56));
                            syn::parse_quote!((((#x & #m0).wrapping_shl(#s56) | (#x & #m1).wrapping_shl(#s40)) | ((#x & #m2).wrapping_shl(#s24) | (#x & #m3).wrapping_shl(#s8)))
                                | (((#x.wrapping_shr(#s8) & #m3) | (#x.wrapping_shr(#s24) & #m2)) | ((#x.wrapping_shr(#s40) & #m1) | #x.wrapping_shr(#s56))))
                        }
                        _ => return None,
                    })
                };
                let v = match (name.as_str(), es.as_slice()) {
                    ("rotate_left", [x, n]) => Val::E(syn::parse_quote!(#x.rotate_left(#n))),
                    ("rotate_right", [x, n]) => Val::E(syn::parse_quote!(#x.rotate_right(#n))),
                    ("bswap", [x]) => match self.op_ty(fr, &args[0])? {
                        Ty::Int(false, b @ (16 | 32 | 64)) => Val::E(bswap(x, b).ok_or("bswap")?),
                        other => return self.err(fr, format!("the intrinsic `bswap` on {other:?}")),
                    },
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
            // a load or store through a pointer of crate code (§20.10): the
            // intrinsic's model on the base's bytes
            Callee::Arch(a) if a.pointer => {
                if cx.probe {
                    return Err("probe: a load or store".into());
                }
                self.mem_access(fr, a, args, dest, &mut env, out)?;
                cont(self, env, out)
            }
            // a `core::arch` intrinsic (§20.9): the same call in the subset,
            // which the front end elaborates to the intrinsic's target model;
            // the pointer loads and stores, and `unsafe` intrinsics, refused
            Callee::Arch(a) => {
                if cx.probe {
                    return Err("probe: arch call".into());
                }
                if !a.safe || a.pointer {
                    return self.err(fr, format!("the intrinsic `{}` takes or returns a raw pointer or is an `unsafe fn`: refused (verified code is safe Rust; whether shipped `unsafe` SIMD code may be split into safe vector arithmetic and unverified loads and stores is the user's open decision, DESIGN.md §16.4, §18 decision 9)", a.path));
                }
                let mut es = Vec::new();
                for x in args {
                    es.push(self.operand_expr(fr, x, &env, out)?.0);
                }
                let path: syn::Path = syn::parse_str(&a.path).map_err(|e| format!("the intrinsic path `{}`: {e}", a.path))?;
                let imms: Vec<syn::LitInt> = a.imms.iter().map(|v| syn::LitInt::new(&v.to_string(), proc_macro2::Span::call_site())).collect();
                let e: syn::Expr = if imms.is_empty() { syn::parse_quote!(#path(#(#es),*)) } else { syn::parse_quote!(#path::<#(#imms),*>(#(#es),*)) };
                let v = self.bind(e, false, None, out);
                self.assign(fr, dest, v, &mut env, out)?;
                cont(self, env, out)
            }
            Callee::Leaf(path, _) if super::arch::detection(path).is_some() => self.err(fr, super::arch::detection(path).unwrap_or_default()),
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
                // a library function read as a model (core's slice iterator, a
                // slice's `get` by a range): the model's body
                let f2: &'m Fn = self.models.get(key).unwrap_or(f2);
                // core's `IterMut` (A-S4): the index it yields next, over the
                // slice place it walks
                if let Some((model @ (super::Model::IterMutNew | super::Model::IterMutNext | super::Model::IterMutIntoIter), _)) = super::model_of(f2) {
                    if cx.probe {
                        return Err("probe: an `IterMut`".into());
                    }
                    self.iter_mut_call(fr, model, args, dest, &mut env, out)?;
                    return cont(self, env, out);
                }
                // `<[T]>::split_at_mut` (raw pointers inside): the two
                // halves of the place, as subslices of it
                if let Some((super::Model::SplitAtMut, _)) = super::model_of(f2) {
                    if cx.probe {
                        return Err("probe: a `split_at_mut`".into());
                    }
                    self.split_at_mut_call(fr, args, dest, &mut env, out)?;
                    return cont(self, env, out);
                }
                // an admitted pointer helper (`ptr::helper`, by exact path and
                // signature): a formation, a cast, an offset (§20.10)
                if let Some(h) = super::ptr::helper(f2) {
                    if cx.probe {
                        return Err("probe: a pointer helper".into());
                    }
                    self.ptr_helper(fr, h, args, dest, &mut env, out)?;
                    return cont(self, env, out);
                }
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

    /// An `IterMut` local moved from `from` to `to` (the root frame's records).
    fn iter_moved(&mut self, fr: usize, from: usize, to: usize) {
        if fr != 0 {
            return;
        }
        if let Some(e) = self.iter_slices.get(&from).cloned() {
            self.iter_slices.insert(to, e);
        }
        if let Some(p) = self.iter_params.get(&from).copied() {
            self.iter_params.insert(to, p);
        }
    }

    /// core's `IterMut` (docs/DESIGN-UNSAFE-SIMD.md A-S4): `iter_mut(s)` is
    /// index 0 over the place `s` names; `next(&mut it)` binds the index `i`,
    /// steps it when `i < s.len()` and yields `Some(&mut s[i])` then, else
    /// `None` (the literal reading's model, element for element).
    fn iter_mut_call(&mut self, fr: usize, model: super::Model, args: &[Operand], dest: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let Some(Operand::Copy(a) | Operand::Move(a)) = args.first() else { return self.err(fr, "an `IterMut` call without its argument") };
        if !a.proj.is_empty() || !dest.proj.is_empty() {
            return self.err(fr, "an `IterMut` through a projection");
        }
        let dkey = (fr, dest.local);
        match model {
            super::Model::IterMutNew => {
                let Some(r) = env.refs.get(&(fr, a.local)).cloned() else { return self.err(fr, "`iter_mut` of a slice the reading holds no place for") };
                if fr == 0 {
                    self.iter_slices.insert(dest.local, r.lv.clone());
                    if self.is_param(0, a.local) {
                        self.iter_params.insert(dest.local, a.local);
                    }
                }
                env.iters.insert(dkey, r);
                self.assign(fr, dest, Val::E(lit_uint(0, "usize")), env, out)
            }
            super::Model::IterMutIntoIter => {
                let Some(r) = env.iters.get(&(fr, a.local)).cloned() else { return self.err(fr, "`into_iter` of an `IterMut` the reading does not hold") };
                let (v, _) = self.read(fr, a, env, out)?;
                env.iters.insert(dkey, r);
                self.iter_moved(fr, a.local, dest.local);
                self.assign(fr, dest, v, env, out)
            }
            super::Model::IterMutNext => {
                let Some(ik) = env.iter_refs.get(&(fr, a.local)).copied() else { return self.err(fr, "`next` of an `IterMut` the reading does not hold") };
                let Some(sl) = env.iters.get(&ik).cloned() else { return self.err(fr, "`next` of an `IterMut` without its slice") };
                let (iv, _) = self.read(ik.0, &Place { local: ik.1, proj: vec![] }, env, out)?;
                let ie = self.materialize(ik.0, &iv)?;
                let (i0, c0) = (ident(&self.fresh("i")), ident(&self.fresh("c")));
                let se = paren(self.state_value(&sl)?);
                out.push(syn::parse_quote!(let #i0: usize = #ie;));
                out.push(syn::parse_quote!(let #c0: bool = #i0 < #se.len();));
                env.declared.insert(i0.to_string());
                env.declared.insert(c0.to_string());
                // (the iterator moves one further on the `Some` arm of the
                // switch on the result, which follows: set there, so the
                // condition is tested once)
                let one = lit_uint(1, "usize");
                let elem = LRef { lv: syn::parse_quote!(#se[#i0]), buf: None, fields: None, inner: false, range: None };
                self.assign(fr, dest, Val::Next(syn::parse_quote!(#c0), elem, ik, syn::parse_quote!(#i0.wrapping_add(#one))), env, out)
            }
            _ => self.err(fr, "an `IterMut` model"),
        }
    }

    /// The literal value of an unsigned operand (a constant, or a value the
    /// reading carries as a literal).
    fn lit_operand(&mut self, fr: usize, o: &Operand, env: &Env, out: &mut Vec<syn::Stmt>) -> Option<u128> {
        if let Some((_, v)) = Self::int_const(o) {
            return u128::try_from(v).ok();
        }
        match self.operand(fr, o, env, out).ok()? {
            (Val::E(e), _) => lit_value(&e),
            _ => None,
        }
    }

    /// The pointer `p` moved by the literal count `k` of `pointee` elements
    /// (`add`; `sub` back; `offset` by an `isize`), within its base.
    #[allow(clippy::too_many_arguments)]
    fn ptr_moved(&mut self, fr: usize, p: &Operand, k: &Operand, neg: bool, signed: bool, pointee: &Ty, env: &Env, out: &mut Vec<syn::Stmt>) -> Result<PtrVal, String> {
        let Val::Ptr(pv) = self.operand(fr, p, env, out)?.0 else { return self.err(fr, "an offset of something that is no pointer of an admitted formation") };
        let Some(kv) = self.lit_operand(fr, k, env, out) else { return self.err(fr, "a pointer offset by a count that is not a constant (the structured reading reads constant offsets)") };
        let t = super::ptr::size_of(pointee).ok_or("a pointee without a size")? as i128;
        let kv = if signed { kv as u64 as i64 as i128 } else { kv as i128 };
        let off = pv.off as i128 + if neg { -kv * t } else { kv * t };
        let size = super::ptr::size_of(&pv.base_ty).map(|n| n as i128);
        if off < 0 || size.is_some_and(|n| off > n) {
            return self.err(fr, format!("a pointer offset to byte {off}, outside its base's {} bytes", size.unwrap_or(-1)));
        }
        Ok(PtrVal { off: off as u64, ..*pv })
    }

    /// A call of an admitted pointer helper (§20.10): a formation (the
    /// place its `&mut` names, or the value its `&` reads), a cast (the same
    /// pointer), an offset.
    fn ptr_helper(&mut self, fr: usize, h: Result<(super::ptr::Helper, Ty), String>, args: &[Operand], dest: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let (h, pointee) = match h {
            Ok(x) => x,
            Err(e) => return self.err(fr, e),
        };
        let v = match h {
            super::ptr::Helper::Form { mutable, slice } => {
                let Some(Operand::Copy(q) | Operand::Move(q)) = args.first() else { return self.err(fr, "a formation without its reference") };
                if !q.proj.is_empty() {
                    return self.err(fr, "a formation from a projection");
                }
                let base_ty = match super::ptr::bases(self.m, self.frames[fr].f).get(&dest.local) {
                    Some(Ok(b)) => b.ty.clone(),
                    Some(Err(e)) => return self.err(fr, e.clone()),
                    None => return self.err(fr, "a formation without a base"),
                };
                let base = if mutable {
                    match env.refs.get(&(fr, q.local)) {
                        Some(r) => {
                            // (a new family: its window starts)
                            env.windows.remove(&r.lv.to_token_stream().to_string());
                            PBase::Mut(r.clone())
                        }
                        None => return self.err(fr, "a mutable formation from a reference the reading holds no place for"),
                    }
                } else {
                    // the referent's value: through the `unsize` the base's
                    // type looks through (an array's), else the reference's own
                    let src = if slice && matches!(base_ty, Ty::Array(..)) { self.unsize_source(fr, q.local).unwrap_or(q.local) } else { q.local };
                    let (v, _) = self.read(fr, &Place { local: src, proj: vec![Proj::Deref] }, env, out)?;
                    PBase::Shr(self.materialize(fr, &v)?)
                };
                PtrVal { base, base_ty, off: 0, mutable }
            }
            super::ptr::Helper::Cast => match self.operand(fr, args.first().ok_or("a cast without its pointer")?, env, out)?.0 {
                Val::Ptr(p) => *p,
                _ => return self.err(fr, "a pointer cast of something that is no pointer of an admitted formation"),
            },
            super::ptr::Helper::Move { neg, signed } => {
                let [p, k] = args else { return self.err(fr, "an offset without its two arguments") };
                self.ptr_moved(fr, p, k, neg, signed, &pointee, env, out)?
            }
        };
        self.assign(fr, dest, Val::Ptr(Box::new(v)), env, out)
    }

    /// `<[T]>::split_at_mut(s, mid)`: the halves of the place `s` names, as
    /// subslices (`0..mid` and `mid..len`; the literal reading's `PRange`
    /// codes), with the split's own panic (`mid > len`) an obligation. A
    /// subslice is not split again (the literal reading does not read a
    /// range of a range).
    fn split_at_mut_call(&mut self, fr: usize, args: &[Operand], dest: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let [Operand::Copy(a) | Operand::Move(a), mid] = args else { return self.err(fr, "`split_at_mut` without its two arguments") };
        if !a.proj.is_empty() || !dest.proj.is_empty() {
            return self.err(fr, "a `split_at_mut` through a projection");
        }
        let Some(r) = env.refs.get(&(fr, a.local)).cloned() else { return self.err(fr, "`split_at_mut` of a slice the reading holds no place for") };
        if r.range.is_some() || r.fields.is_some() || r.buf.is_some() || r.inner {
            return self.err(fr, "`split_at_mut` of a subslice or a state (a range of a range is not read)");
        }
        let (mv, _) = self.operand_expr(fr, mid, env, out)?;
        let lv = paren(r.lv.clone());
        let n = self.array_len_through(fr, a.local);
        let len: syn::Expr = match n {
            Some(n) => lit_uint(n as u128, "usize"),
            None => syn::parse_quote!(#lv.len()),
        };
        let rest: syn::Expr = match (n, lit_value(&mv)) {
            (Some(n), Some(m)) if m <= n as u128 => lit_uint(n as u128 - m, "usize"),
            _ => {
                // (core panics past the slice's end: not taken)
                out.push(syn::parse_quote!(if !(#mv <= #len) { unreachable!() }));
                syn::parse_quote!(#len - #mv)
            }
        };
        let lo = LRef { range: Some((lit_uint(0, "usize"), mv.clone())), ..r.clone() };
        let hi = LRef { range: Some((mv, rest)), ..r };
        let dt = self.frames[fr].f.locals[dest.local].0.clone();
        self.assign(fr, dest, Val::C(dt, 0, vec![Val::Place(lo), Val::Place(hi)]), env, out)
    }

    /// The length `N` of the array a `&mut [T]` local refers to, when it is
    /// an unsized `&mut [T; N]` (its one assignment an `unsize` of one).
    fn array_len_through(&self, fr: usize, l: usize) -> Option<u64> {
        let f = self.frames[fr].f;
        let pointee = |t: &Ty| match t {
            Ty::Ref(_, inner) => match &**inner {
                Ty::Array(_, n) => Some(*n),
                _ => None,
            },
            _ => None,
        };
        pointee(&f.locals[l].0).or_else(|| self.unsize_source(fr, l).and_then(|s| pointee(&f.locals[s].0)))
    }

    /// The local an `unsize` cast into `l` reads (its one assignment).
    fn unsize_source(&self, fr: usize, l: usize) -> Option<usize> {
        let f = self.frames[fr].f;
        let mut found = None;
        for bl in &f.blocks {
            for st in &bl.stmts {
                if let Stmt::Assign(d, rv, _) = st
                    && d.local == l
                {
                    match rv {
                        Rvalue::Cast(k, Operand::Copy(q) | Operand::Move(q), _) if k == "unsize" && q.proj.is_empty() && found.is_none() => found = Some(q.local),
                        _ => return None,
                    }
                }
            }
        }
        found
    }

    /// A load or a store through a pointer (§20.10): a load is the
    /// intrinsic's model on the `n` bytes at the pointer's offset in its base
    /// (`vld1q_u8([b[o], .., b[o + 15]])`); a store writes the bytes its
    /// model gives into the base, through the place a mutable formation
    /// names (`b = [b[0], .., w[0], .., w[15], .., b[63]]`). Byte arrays only
    /// here, at constant offsets.
    fn mem_access(&mut self, fr: usize, a: &ArchCall, args: &[Operand], dest: &Place, env: &mut Env, out: &mut Vec<syn::Stmt>) -> Result<(), String> {
        let Some(row) = super::ptr::mem_intrinsic(&a.path) else { return self.err(fr, format!("the intrinsic `{}` is no admitted load or store", a.path)) };
        let Some(p) = args.first() else { return self.err(fr, "a load or store without its pointer") };
        let Val::Ptr(pv) = self.operand(fr, p, env, out)?.0 else { return self.err(fr, "a load or store through something that is no pointer of an admitted formation") };
        // (a `u128` base, loaded only: its little-endian bytes, the low
        // word's first: `t.0.to_le_bytes()[k]`, `t.1.to_le_bytes()[k - 8]`)
        let wide = pv.base_ty == Ty::Int(false, 128);
        let n = match &pv.base_ty {
            Ty::Array(e, n) if **e == Ty::Int(false, 8) => *n,
            Ty::Int(false, 128) if !row.store => 16,
            other => return self.err(fr, format!("a load or store in a base of {other:?} (the structured reading reads byte arrays, and loads from a `u128`)")),
        };
        if pv.off + row.bytes > n {
            return self.err(fr, format!("bytes {}..{} of a {n}-byte base", pv.off, pv.off + row.bytes));
        }
        let path: syn::Path = syn::parse_str(&a.path).map_err(|e| format!("the intrinsic path `{}`: {e}", a.path))?;
        let base: syn::Expr = match &pv.base {
            PBase::Mut(r) => paren(self.state_value(r)?),
            PBase::Shr(e) => paren(e.clone()),
        };
        let at = |e: &syn::Expr, k: u64| -> syn::Expr {
            if wide {
                let (w, k) = (syn::Index::from((k / 8) as usize), lit_uint((k % 8) as u128, "usize"));
                return syn::parse_quote!(#e.#w.to_le_bytes()[#k]);
            }
            let k = lit_uint(k as u128, "usize");
            syn::parse_quote!(#e[#k])
        };
        // (the family's window over a mutable base: the bytes its stores
        // left, never the state read back)
        let key = match &pv.base {
            PBase::Mut(r) => Some(r.lv.to_token_stream().to_string()),
            PBase::Shr(_) => None,
        };
        if !row.store {
            let elems: Vec<syn::Expr> = match key.as_ref().and_then(|k| env.windows.get(k)) {
                Some(win) => win[pv.off as usize..(pv.off + row.bytes) as usize].to_vec(),
                None => (pv.off..pv.off + row.bytes).map(|k| at(&base, k)).collect(),
            };
            let v = self.bind(syn::parse_quote!(#path([#(#elems),*])), false, None, out);
            return self.assign(fr, dest, v, env, out);
        }
        let (true, PBase::Mut(r)) = (pv.mutable, &pv.base) else { return self.err(fr, format!("the store `{}` through a pointer formed from a shared reference", a.path)) };
        let Some(x) = args.get(1) else { return self.err(fr, "a store without its vector") };
        let (xv, _) = self.operand_expr(fr, x, env, out)?;
        let w = ident(&self.fresh("w"));
        let wn = syn::LitInt::new(&format!("{}usize", row.bytes), PSpan::call_site());
        out.push(syn::parse_quote!(let #w: [u8; #wn] = #path(#xv);));
        let we: syn::Expr = syn::parse_quote!(#w);
        let key = key.unwrap_or_default();
        let mut win = match env.windows.get(&key) {
            Some(win) => win.clone(),
            None => {
                // (the window's first store: the base's value before it)
                let c = ident(&self.fresh("c"));
                let nn = syn::LitInt::new(&format!("{n}usize"), PSpan::call_site());
                out.push(syn::parse_quote!(let #c: [u8; #nn] = #base;));
                let ce: syn::Expr = syn::parse_quote!(#c);
                (0..n).map(|j| at(&ce, j)).collect()
            }
        };
        for j in pv.off..pv.off + row.bytes {
            win[j as usize] = at(&we, j - pv.off);
        }
        let elems = win.clone();
        let r = r.clone();
        self.state_store(fr, &r, syn::parse_quote!([#(#elems),*]), env, out)?;
        env.windows.insert(key, win);
        self.assign(fr, dest, Val::Z(Ty::Unit), env, out)
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
            // `IterMut::next`'s result: `Some(&mut s[i])` exactly when its
            // condition holds
            let next = match &cur {
                Val::Next(c, r, ik, adv) => Some((c.clone(), r.clone(), *ik, adv.clone())),
                _ => None,
            };
            scrut = match &next {
                Some((c, ..)) => c.clone(),
                None => self.materialize(sf, &cur)?,
            };
            if let Some((_, place, ik, adv)) = next {
                let var_of = |n: &str| adt.variants.iter().find(|v| v.name == n).map(|v| (v.idx, v.discr));
                let (Some((si, sd)), Some((ni, nd))) = (var_of("Some"), var_of("None")) else { return self.err(fr, "`IterMut::next`'s result is no `Option`") };
                let mut e_some = env.clone();
                e_some.vals.insert((sf, sp.local), Val::C(t.clone(), si, vec![Val::Place(place)]));
                e_some.vals.insert(ik, Val::E(adv));
                let mut e_none = env.clone();
                e_none.vals.insert((sf, sp.local), Val::C(t.clone(), ni, vec![]));
                plan.push((Some(syn::parse_quote!(true)), target_of(sd), e_some));
                plan.push((Some(syn::parse_quote!(false)), target_of(nd), e_none));
                is_bool = true;
            }
            for var_def in adt.variants.iter().filter(|_| !is_bool) {
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
                } else if sp.proj == [Proj::Deref]
                    && matches!(self.frames[sf].f.locals[sp.local].0, Ty::Ref(false, _))
                    && !env.refs.contains_key(&(sf, sp.local))
                {
                    // `*r` of a shared reference (`PartialEq::eq(&self, &other)`
                    // of an enum): `r` refers to the constructor in the arm (a
                    // shared reference is a snapshot of its referent)
                    e2.vals.insert((sf, sp.local), Val::R(Box::new(Val::C(t.clone(), var_def.idx, fvals))));
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
                    return Ok(Flow::Cond(scrut, t_t, f_t, env, fr, b));
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
        // while-shaped: the header computes a condition without effects (one
        // test, or tests joined by `&&`/`||`), the loop's only exits are its tests
        let inferred = !self.spec.loops.contains_key(&k);
        let wc = self.while_cond(h, &env, &body, at.ensures.is_empty())?;
        if let Some((cond, body_entry, exit, env_c, env_x, tree)) = wc {
            let widx = self.next_while();
            self.loop_forms.push((k, "while".into()));
            let info = HelperInfo { name: format!("loop#{widx}"), method: false, header: h, params: vec![], while_loop: true, local_names: self.frames[0].names.clone(), returns: None, owner: self.owner.clone(), iters: vec![], derived: vec![], extra: vec![] };
            let mut bo: Vec<syn::Stmt> = Vec::new();
            let mut head: Vec<syn::Stmt> = Vec::new();
            for i in &at.invariants {
                head.push(syn::parse_quote!(invariant(#i);));
            }
            // the attachment's measure, else (no attachment) an untrusted guess
            if let Some(d) = at.decreases.clone().or_else(|| if inferred { self.guess_measure(h, &body, tree.as_ref()) } else { None }) {
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
            let flow = self.go(0, body_entry, env_c, &cx_body, &mut bo)?;
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
            // (innermost first: a `while` loop's lemma uses its inner loops')
            self.helper_info.push(info);
            // after the loop: the header's values (of the loop variables,
            // in their own names) as its last test computed them
            let mut e_after = env_x;
            e_after.vals.retain(|k, _| k.0 == 0);
            return self.go(0, exit, e_after, cx, out);
        }
        // a loop inside another loop's body, not while-shaped: a helper from
        // the header to the loop's one exit, which returns the variables the
        // loop assigns; its caller goes on after it (a tail-recursive helper
        // would go on into the outer loop and call it: mutual recursion).
        // An attachment's `ensures` is then about what the helper returns,
        // when the loop leaves into the outer loop's body (its caller's).
        if !cx.loops.is_empty()
            && let Some(x) = self.loop_exit_block(&body)
            && (at.ensures.is_empty() || cx.loops.last().is_some_and(|(oh, _)| *oh == x || self.cfg.body[*oh].contains(&x)))
            && let Some(flow) = self.returning_helper(h, k, &at, x, &live, &body, &env, cx, out)?
        {
            return Ok(flow);
        }
        // a tail-recursive helper over the variables live at the header (and
        // those the attachment names)
        // a method's loop over its receiver (`&mut self`, `self`): a method
        // helper of the impl, `Self::m__loopK(self, ..)` (as the source lift's)
        let receiver = self.spec.params.first().is_some_and(|p| p == "self");
        let method = receiver && live.contains(&1);
        let mut params = self.loop_params(&live, &at, &env);
        let name = if method {
            format_ident!("{}__loop{}", self.spec.lifted_name.rsplit("::").next().unwrap_or(""), k)
        } else {
            format_ident!("{}__loop{}", self.spec.lifted_name.replace("::", "__"), k)
        };
        let callee: syn::Expr = if method { syn::parse_quote!(Self::#name) } else { syn::parse_quote!(#name) };
        self.order_params(&mut params, &body, method);
        self.loop_forms.push((k, "helper".into()));
        let args: Vec<syn::Expr> = params.iter().map(|l| self.state_or_var(&env, *l)).collect::<Result<_, _>>()?;
        out.push(syn::parse_quote!(return #callee(#(#args),*);));
        // the helper
        let (henv, inputs, mut hb) = self.helper_head(&params, &env, method)?;
        if !at.at_start.is_empty() {
            let s = &at.at_start;
            hb.push(syn::parse_quote!(proof! { #(#s)* }));
        }
        let mut loops = cx.loops.clone();
        loops.push((h, LoopForm::Helper(callee.clone(), params.clone(), vec![])));
        // the header's own statements run first in each call
        let cx_h = Cx { k: K::Ret, stop: None, loops: loops.clone(), probe: false };
        let saved = self.owner.replace((name.to_string(), method));
        let flow = self.go_header(h, henv, &cx_h, &mut hb);
        self.owner = saved;
        if let Flow::Fall(_) = flow? {
            return self.err(0, "a loop helper that falls through");
        }
        // an element attachment: the body on the element, a function of it
        if let Some(ens) = &at.element {
            if method {
                return self.err(0, format!("the element attachment of loop {k}: the loop is read as a method helper (its body reads `self`)"));
            }
            let item = match self.extract_element(&name.to_string(), &inputs, &mut hb, &ens.ensures, &ens.requires, &ens.at_start) {
                Ok(item) => item,
                Err(e) => return self.err(0, format!("the element attachment of loop {k}: {e}")),
            };
            self.elements.push(item.sig.ident.to_string());
            self.helpers.push(syn::Item::Fn(item));
        }
        let mut attrs = self.helper_attrs(h, &body, &at, inferred);
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
        let iters: Vec<(usize, usize)> = params.iter().enumerate().filter_map(|(i, l)| self.iter_params.get(l).map(|p| (i, *p))).collect();
        self.helper_info.push(HelperInfo { name: name.to_string(), method, header: h, params: params.clone(), while_loop: false, local_names: vec![], returns: None, owner: self.owner.clone(), iters, derived: vec![], extra: vec![] });
        Ok(Flow::Diverge)
    }

    /// Whether the loop at header `h` has an element attachment.
    fn element_loop(&self, h: usize) -> bool {
        self.cfg.headers.iter().position(|x| *x == h).and_then(|k| self.spec.loops.get(&k)).is_some_and(|a| a.element.is_some())
    }

    /// A loop's body on one element (an element attachment): the helper's
    /// body `hb` holds, in the `then` block of its iteration test, the
    /// statements of one iteration up to the back edge's marker. From the
    /// first that names the slice `xs` on (those before it stay in the
    /// helper: an iterator's step, an index, checks on it), when they touch
    /// `xs` only as one element `xs[i]` (`i` bound before: the index an
    /// `IterMut` yields, or a returning helper's element index), read and
    /// write it (whole or in part: `xs[i][j] = v`), assign no variable bound
    /// before them, and neither leave nor loop, they are the body of the
    /// element function `<helper>__element(v̄, <elem>)` (`v̄` the variables
    /// bound before that they read, `<elem>` the variable that held the
    /// element: `xs[i]` read as it), opaque, with the attachment's contract;
    /// it returns the element after each of its writes, in order, and the
    /// helper calls it and writes them back in that order: `let e =
    /// <helper>__element(v̄, xs[i]); xs[i] = e.0; xs[i] = e.1; ..`, as the
    /// literal reading's stores leave the element. The walk unfolds the
    /// call (`delta`), so the loop's theorem is as before; the loop's
    /// contract sees the element's contract only.
    #[allow(clippy::too_many_arguments)]
    fn extract_element(&mut self, helper: &str, inputs: &[TokenStream], hb: &mut [syn::Stmt], ens: &[syn::Expr], req: &[syn::Expr], at_start: &[syn::Stmt]) -> Result<syn::ItemFn, String> {
        use syn::visit::Visit;
        use syn::visit_mut::VisitMut;
        fn is_marker(st: &syn::Stmt) -> bool {
            matches!(st, syn::Stmt::Macro(m) if m.mac.path.is_ident("__sb_element_end"))
        }
        // every marker (one back edge: one)
        struct Markers(usize);
        impl<'a> Visit<'a> for Markers {
            fn visit_stmt(&mut self, st: &'a syn::Stmt) {
                if is_marker(st) {
                    self.0 += 1;
                }
                syn::visit::visit_stmt(self, st);
            }
        }
        let mut mk = Markers(0);
        for st in hb.iter() {
            mk.visit_stmt(st);
        }
        if mk.0 != 1 {
            return Err(format!("the body reaches the next iteration on {} paths (an element body is one straight path)", mk.0));
        }
        let pos = hb
            .iter()
            .position(|st| matches!(st, syn::Stmt::Expr(syn::Expr::If(ei), _) if ei.then_branch.stmts.iter().any(is_marker)))
            .ok_or("the next iteration is not reached at the end of the iteration test's branch")?;
        // the parameters' types, by name
        let mut ptys: HashMap<String, syn::Type> = HashMap::new();
        for i in inputs {
            if let Ok(syn::FnArg::Typed(pt)) = syn::parse2::<syn::FnArg>(i.clone())
                && let syn::Pat::Ident(pi) = &*pt.pat
            {
                ptys.insert(pi.ident.to_string(), (*pt.ty).clone());
            }
        }
        // the variables bound before the test (`let v: T = ..;`), by name
        let mut before: HashMap<String, Option<syn::Type>> = HashMap::new();
        for st in &hb[..pos] {
            if let syn::Stmt::Local(l) = st {
                match &l.pat {
                    syn::Pat::Type(pt) => {
                        if let syn::Pat::Ident(pi) = &*pt.pat {
                            before.insert(pi.ident.to_string(), Some((*pt.ty).clone()));
                        }
                    }
                    syn::Pat::Ident(pi) => {
                        before.insert(pi.ident.to_string(), None);
                    }
                    _ => {}
                }
            }
        }
        let syn::Stmt::Expr(syn::Expr::If(ei), _) = &mut hb[pos] else { unreachable!() };
        let m = ei.then_branch.stmts.iter().position(is_marker).ok_or("the marker")?;
        let body: Vec<syn::Stmt> = ei.then_branch.stmts[..m].to_vec();
        // the element's place: `xs[i]`, one slice parameter, one index
        struct Places {
            slices: Vec<String>,
            found: Vec<(String, String)>,
        }
        impl<'a> Visit<'a> for Places {
            fn visit_expr_index(&mut self, e: &'a syn::ExprIndex) {
                if let (syn::Expr::Path(a), syn::Expr::Path(b)) = (&*e.expr, &*e.index)
                    && let (Some(a), Some(b)) = (a.path.get_ident(), b.path.get_ident())
                    && self.slices.contains(&a.to_string())
                {
                    let p = (a.to_string(), b.to_string());
                    if !self.found.contains(&p) {
                        self.found.push(p);
                    }
                }
                syn::visit::visit_expr_index(self, e);
            }
        }
        let slices: Vec<String> = ptys.iter().filter(|(_, t)| matches!(t, syn::Type::Reference(r) if matches!(&*r.elem, syn::Type::Slice(_)))).map(|(n, _)| n.clone()).collect();
        let mut pl = Places { slices, found: Vec::new() };
        for st in &body {
            pl.visit_stmt(st);
        }
        let (xs, idx) = match pl.found.as_slice() {
            [p] => p.clone(),
            [] => return Err("the body does not touch an element of the slice the loop walks".into()),
            _ => return Err(format!("the body touches more than one element place ({})", pl.found.iter().map(|(a, b)| format!("`{a}[{b}]`")).collect::<Vec<_>>().join(", "))),
        };
        let ety: syn::Type = match &ptys[&xs] {
            syn::Type::Reference(r) => match &*r.elem {
                syn::Type::Slice(sl) => (*sl.elem).clone(),
                _ => return Err("the slice's type".into()),
            },
            _ => return Err("the slice's type".into()),
        };
        let elem = self.elem_names.get(&idx).cloned().ok_or_else(|| format!("no variable holds the element `{xs}[{idx}]`"))?;
        // the statements before the first that names the slice stay in the
        // helper, before the call; what they bind is bound before the body
        let first = body.iter().position(|st| ts_mentions(st.to_token_stream(), &xs)).unwrap_or(body.len());
        let mut prefix: Vec<syn::Stmt> = body[..first].to_vec();
        // (a check of the body, `if !(c) { unreachable!() }`, on variables
        // bound before it only is made before the call too: it reads
        // nothing the body computes, and the helper knows what the loop
        // knows of them)
        let mut kept: Vec<syn::Stmt> = Vec::new();
        let mut bound_in: Vec<String> = Vec::new();
        for st in &body[first..] {
            let unreachable = |b: &syn::Block| match b.stmts.as_slice() {
                [syn::Stmt::Macro(m)] => m.mac.path.is_ident("unreachable"),
                [syn::Stmt::Expr(syn::Expr::Macro(m), _)] => m.mac.path.is_ident("unreachable"),
                _ => false,
            };
            let is_check = matches!(st, syn::Stmt::Expr(syn::Expr::If(ci), _) if ci.else_branch.is_none()
                && unreachable(&ci.then_branch)
                && matches!(&*ci.cond, syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_))));
            if is_check {
                let ts = st.to_token_stream();
                if !ts_mentions(ts.clone(), &xs) && !bound_in.iter().any(|n| ts_mentions(ts.clone(), n)) {
                    prefix.push(st.clone());
                    continue;
                }
            }
            if let syn::Stmt::Local(l) = st {
                let mut ns = Vec::new();
                pat_names(&l.pat, &mut ns);
                bound_in.extend(ns);
            }
            kept.push(st.clone());
        }
        let body: Vec<syn::Stmt> = kept;
        for st in &prefix {
            if let syn::Stmt::Local(l) = st {
                match &l.pat {
                    syn::Pat::Type(pt) => {
                        if let syn::Pat::Ident(pi) = &*pt.pat {
                            before.insert(pi.ident.to_string(), Some((*pt.ty).clone()));
                        }
                    }
                    syn::Pat::Ident(pi) => {
                        before.insert(pi.ident.to_string(), None);
                    }
                    _ => {}
                }
            }
        }
        // a place rooted at the element `xs[i]` (the element, or a part of it)
        fn rooted(e: &syn::Expr, xs: &str, idx: &str) -> bool {
            match e {
                syn::Expr::Index(ix) if matches!((&*ix.expr, &*ix.index), (syn::Expr::Path(x), syn::Expr::Path(i)) if x.path.is_ident(xs) && i.path.is_ident(idx)) => true,
                syn::Expr::Index(ix) => rooted(&ix.expr, xs, idx),
                syn::Expr::Field(f) => rooted(&f.base, xs, idx),
                syn::Expr::Paren(p) => rooted(&p.expr, xs, idx),
                _ => false,
            }
        }
        // a place rooted at the variable `v` (once the element is it)
        fn rooted_var(e: &syn::Expr, v: &str) -> bool {
            match e {
                syn::Expr::Path(p) => p.path.is_ident(v),
                syn::Expr::Index(ix) => rooted_var(&ix.expr, v),
                syn::Expr::Field(f) => rooted_var(&f.base, v),
                syn::Expr::Paren(p) => rooted_var(&p.expr, v),
                _ => false,
            }
        }
        // what the body may do: read and write the element, read the
        // variables bound before, bind its own; no exit, loop or closure
        struct Check<'s> {
            xs: &'s str,
            idx: &'s str,
            elem: &'s str,
            bound: BTreeSet<String>,
            used: Vec<String>,
            xs_uses: usize,
            place_uses: usize,
            err: Option<String>,
        }
        impl Check<'_> {
            fn note_pat(&mut self, p: &syn::Pat) {
                match p {
                    syn::Pat::Ident(pi) => {
                        self.bound.insert(pi.ident.to_string());
                    }
                    syn::Pat::Type(pt) => self.note_pat(&pt.pat),
                    syn::Pat::Tuple(t) => t.elems.iter().for_each(|q| self.note_pat(q)),
                    syn::Pat::TupleStruct(t) => t.elems.iter().for_each(|q| self.note_pat(q)),
                    syn::Pat::Wild(_) => {}
                    _ => self.err = Some("a pattern the element body cannot bind".into()),
                }
            }
        }
        impl<'a> Visit<'a> for Check<'_> {
            fn visit_local(&mut self, l: &'a syn::Local) {
                if let Some(init) = &l.init {
                    self.visit_expr(&init.expr);
                }
                self.note_pat(&l.pat);
            }
            fn visit_expr(&mut self, e: &'a syn::Expr) {
                match e {
                    syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_) | syn::Expr::Try(_) | syn::Expr::While(_) | syn::Expr::Loop(_) | syn::Expr::ForLoop(_) | syn::Expr::Closure(_) | syn::Expr::Async(_) | syn::Expr::Await(_) | syn::Expr::Yield(_) => {
                        self.err = Some("the body leaves, loops or holds a closure".into());
                    }
                    syn::Expr::Assign(a) => {
                        match &*a.left {
                            l if rooted(l, self.xs, self.idx) => {}
                            syn::Expr::Path(p) if p.path.get_ident().is_some_and(|i| self.bound.contains(&i.to_string())) => {}
                            other => self.err = Some(format!("the body assigns `{}`, bound before it", other.to_token_stream())),
                        }
                        self.visit_expr(&a.left);
                        self.visit_expr(&a.right);
                        return;
                    }
                    syn::Expr::Index(ix) if matches!((&*ix.expr, &*ix.index), (syn::Expr::Path(x), syn::Expr::Path(i)) if x.path.is_ident(self.xs) && i.path.is_ident(self.idx)) => {
                        self.place_uses += 1;
                    }
                    syn::Expr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => {
                        let n = p.path.segments[0].ident.to_string();
                        if n == self.xs {
                            self.xs_uses += 1;
                        }
                        if n == self.elem {
                            self.err = Some(format!("the body names `{n}`, the element's variable"));
                        }
                        if !self.bound.contains(&n) && !self.used.contains(&n) {
                            self.used.push(n);
                        }
                    }
                    syn::Expr::Macro(m) if !m.mac.path.is_ident("unreachable") => {
                        self.err = Some(format!("the body holds `{}!`", m.mac.path.to_token_stream()));
                    }
                    _ => {}
                }
                syn::visit::visit_expr(self, e);
            }
            fn visit_stmt_macro(&mut self, m: &'a syn::StmtMacro) {
                if !m.mac.path.is_ident("proof") && !m.mac.path.is_ident("unreachable") {
                    self.err = Some(format!("the body holds `{}!`", m.mac.path.to_token_stream()));
                }
            }
            fn visit_item(&mut self, _: &'a syn::Item) {
                self.err = Some("the body holds an item".into());
            }
        }
        let mut ck = Check { xs: &xs, idx: &idx, elem: &elem, bound: BTreeSet::new(), used: Vec::new(), xs_uses: 0, place_uses: 0, err: None };
        for st in &body {
            ck.visit_stmt(st);
            if ck.err.is_some() {
                break;
            }
        }
        if let Some(e) = ck.err {
            return Err(e);
        }
        if ck.xs_uses != ck.place_uses {
            return Err(format!("the body uses `{xs}` other than as its element `{xs}[{idx}]`"));
        }
        // the element function's parameters: the variables bound before
        // that the body reads (globals named by one segment stay as they are)
        let mut params: Vec<(String, syn::Type)> = Vec::new();
        for n in &ck.used {
            if *n == xs || *n == idx {
                continue;
            }
            if n == "self" {
                return Err("the body reads `self`".into());
            }
            if let Some(t) = ptys.get(n) {
                params.push((n.clone(), t.clone()));
            } else if let Some(t) = before.get(n) {
                let t = t.clone().ok_or_else(|| format!("the type of `{n}`, bound before the body"))?;
                params.push((n.clone(), t));
            }
        }
        // the body on the element: `xs[i]` is the element's variable
        struct Subst<'s> {
            xs: &'s str,
            idx: &'s str,
            to: syn::Expr,
        }
        impl VisitMut for Subst<'_> {
            fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
                if let syn::Expr::Index(ix) = e
                    && matches!((&*ix.expr, &*ix.index), (syn::Expr::Path(x), syn::Expr::Path(i)) if x.path.is_ident(self.xs) && i.path.is_ident(self.idx))
                {
                    *e = self.to.clone();
                    return;
                }
                syn::visit_mut::visit_expr_mut(self, e);
            }
        }
        let ev = var(&elem);
        let mut sb = Subst { xs: &xs, idx: &idx, to: ev.clone() };
        let mut ebody = body.clone();
        for st in ebody.iter_mut() {
            sb.visit_stmt_mut(st);
        }
        // each write of the element (`xs[i] = e;` at the body's top level):
        // the function returns them in order, and the helper writes them
        // back in that order, as the literal reading's stores leave the
        // element (a write only in a branch is no element body)
        let mut writes: Vec<syn::Ident> = Vec::new();
        let mut nb: Vec<syn::Stmt> = Vec::new();
        for st in ebody.into_iter() {
            let is_write = matches!(&st, syn::Stmt::Expr(syn::Expr::Assign(a), _) if rooted_var(&a.left, &elem));
            nb.push(st);
            if is_write {
                let w = ident(&self.fresh("w"));
                nb.push(syn::parse_quote!(let #w: #ety = #ev;));
                writes.push(w);
            }
        }
        let mut ebody = nb;
        {
            struct Nested<'s> {
                elem: &'s str,
                depth: usize,
                found: bool,
            }
            impl<'a> Visit<'a> for Nested<'_> {
                fn visit_block(&mut self, b: &'a syn::Block) {
                    self.depth += 1;
                    syn::visit::visit_block(self, b);
                    self.depth -= 1;
                }
                fn visit_expr_assign(&mut self, a: &'a syn::ExprAssign) {
                    if self.depth > 0 && rooted_var(&a.left, self.elem) {
                        self.found = true;
                    }
                    syn::visit::visit_expr_assign(self, a);
                }
            }
            let mut nv = Nested { elem: &elem, depth: 0, found: false };
            for st in &ebody {
                nv.visit_stmt(st);
            }
            if nv.found {
                return Err("the body writes its element in a branch".into());
            }
        }
        if writes.is_empty() {
            return Err("the body does not write its element".into());
        }
        let n = writes.len();
        let ret_ty: syn::Type = if n == 1 { ety.clone() } else { let ts = vec![ety.clone(); n]; syn::parse_quote!((#(#ts),*)) };
        let ret_e: syn::Expr = if n == 1 { let w = &writes[0]; syn::parse_quote!(#w) } else { syn::parse_quote!((#(#writes),*)) };
        // the contract is about the element as the body leaves it: the
        // last write (`|ret: T| P` is `|r: (T, ..)| P[ret := r.(n-1)]`)
        let mut ens2: Vec<syn::Expr> = Vec::new();
        for e in ens {
            let syn::Expr::Closure(c) = e else { return Err("an element attachment's `ensures` is a closure `|ret: T| ..`".into()) };
            let [syn::Pat::Type(pt)] = c.inputs.iter().collect::<Vec<_>>()[..] else { return Err("an element attachment's `ensures` names its result: `|ret: T| ..`".into()) };
            let syn::Pat::Ident(pi) = &*pt.pat else { return Err("an element attachment's `ensures` names its result: `|ret: T| ..`".into()) };
            if n == 1 {
                ens2.push(e.clone());
                continue;
            }
            let rn = pi.ident.to_string();
            let r = ident(&self.fresh("r"));
            let last = syn::Index::from(n - 1);
            struct Rename<'s> {
                from: &'s str,
                to: syn::Expr,
            }
            impl VisitMut for Rename<'_> {
                fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
                    if let syn::Expr::Path(p) = e
                        && p.path.is_ident(self.from)
                    {
                        *e = self.to.clone();
                        return;
                    }
                    syn::visit_mut::visit_expr_mut(self, e);
                }
            }
            let mut body = (*c.body).clone();
            Rename { from: &rn, to: syn::parse_quote!(#r.#last) }.visit_expr_mut(&mut body);
            ens2.push(syn::parse_quote!(|#r: #ret_ty| #body));
        }
        let fname = format_ident!("{}__element", helper);
        let eid = ident(&elem);
        let pins: Vec<TokenStream> = params.iter().map(|(n, t)| {
            let id = ident(n);
            quote!(mut #id: #t)
        }).chain(std::iter::once(quote!(mut #eid: #ety))).collect();
        let attrs: Vec<syn::Attribute> = std::iter::once(syn::parse_quote!(#[opaque])).chain(req.iter().map(|e| syn::parse_quote!(#[requires(#e)]))).chain(ens2.iter().map(|e| syn::parse_quote!(#[ensures(#e)]))).collect();
        if !at_start.is_empty() {
            ebody.insert(0, syn::parse_quote!(proof! { #(#at_start)* }));
        }
        let item: syn::ItemFn = syn::parse_quote!(
            #(#attrs)*
            fn #fname(#(#pins),*) -> #ret_ty { #(#ebody)* return #ret_e; }
        );
        // the helper: the call, and its writes of the element in order
        let args: Vec<syn::Expr> = params.iter().map(|(n, _)| var(n)).collect();
        let e_tmp = ident(&self.fresh("e"));
        let (xsi, idxi) = (ident(&xs), ident(&idx));
        let mut rest: Vec<syn::Stmt> = prefix;
        rest.push(syn::parse_quote!(let #e_tmp: #ret_ty = #fname(#(#args,)* #xsi[#idxi]);));
        for k in 0..n {
            if n == 1 {
                rest.push(syn::parse_quote!(#xsi[#idxi] = #e_tmp;));
            } else {
                let kk = syn::Index::from(k);
                rest.push(syn::parse_quote!(#xsi[#idxi] = #e_tmp.#kk;));
            }
        }
        rest.extend(ei.then_branch.stmts[m + 1..].iter().cloned());
        ei.then_branch.stmts = rest;
        Ok(item)
    }

    /// The index of the next `while` loop of the function being written (the
    /// lifted function, or the loop helper whose body holds it): the
    /// elaborator numbers its helpers `loop#k` in that order.
    fn next_while(&mut self) -> usize {
        let key = self.owner.as_ref().map(|o| o.0.clone()).unwrap_or_default();
        let n = self.whiles.entry(key).or_insert(0);
        *n += 1;
        *n - 1
    }

    /// A loop helper's parameters: the variables live at the header, and
    /// those its attachment names.
    fn loop_params(&self, live: &BTreeSet<usize>, at: &LoopAttach, env: &Env) -> Vec<usize> {
        let mut params: Vec<usize> = live.iter().copied().filter(|l| *l != 0).collect();
        // the `&mut [T]` parameter a live `IterMut` walks: its state is read
        // and written through the iterator's elements
        for l in live {
            if let Some(p) = self.iter_params.get(l)
                && !params.contains(p)
            {
                params.push(*p);
            }
        }
        let mut attach_ts = TokenStream::new();
        for e in at.invariants.iter().chain(at.ensures.iter()).chain(at.decreases.iter()) {
            attach_ts.extend(e.to_token_stream());
        }
        for s in &at.at_start {
            attach_ts.extend(s.to_token_stream());
        }
        for l in 1..self.frames[0].f.locals.len() {
            let n = self.frames[0].names[l].clone();
            if !params.contains(&l) && (self.is_param(0, l) || env.declared.contains(&n)) && ts_mentions(attach_ts.clone(), &n) {
                params.push(l);
            }
        }
        params
    }

    /// The order of a loop helper's parameters: the receiver of a method
    /// helper first, states last, otherwise by first use in the loop (block
    /// order; a `&mut` temporary counts as the place it borrows).
    fn order_params(&self, params: &mut [usize], body: &BTreeSet<usize>, method: bool) {
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
    }

    /// A loop helper's environment, inputs and first statements (an exploded
    /// state is whole in the parameters: exploded again).
    #[allow(clippy::type_complexity)]
    fn helper_head(&mut self, params: &[usize], env: &Env, method: bool) -> Result<(Env, Vec<TokenStream>, Vec<syn::Stmt>), String> {
        let mut henv = Env::default();
        for &l in params {
            let n = self.frames[0].names[l].clone();
            henv.declared.insert(n.clone());
            if let Some(r) = env.refs.get(&(0, l)) {
                henv.refs.insert((0, l), r.clone());
            }
            if let Some(r) = env.iters.get(&(0, l)) {
                henv.iters.insert((0, l), r.clone());
            }
        }
        let mut inputs: Vec<TokenStream> = Vec::new();
        for &l in params {
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
        for &l in params {
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
        Ok((henv, inputs, hb))
    }

    /// A loop helper's contract: the attachment's invariants as preconditions
    /// and its measure, else (`inferred`: the loop has no attachment) an
    /// untrusted guess of the measure.
    fn helper_attrs(&self, h: usize, body: &BTreeSet<usize>, at: &LoopAttach, inferred: bool) -> Vec<syn::Attribute> {
        let mut attrs: Vec<syn::Attribute> = Vec::new();
        for i in &at.invariants {
            attrs.push(syn::parse_quote!(#[requires(#i)]));
        }
        if let Some(d) = at.decreases.clone().or_else(|| if inferred { self.guess_measure(h, body, None) } else { None }) {
            attrs.push(syn::parse_quote!(#[decreases(#d)]));
        }
        attrs
    }

    /// The condition of a while-shaped loop at header `h` (the condition,
    /// the body's entry, the exit, and the environment each starts with):
    /// the header computes it without effects, as one test or as tests
    /// joined by `&&`/`||` whose leaves are the body's entry and the exit,
    /// and the loop leaves only by those tests.
    /// `allow`: the loop may be a `while` (no attachment summary). The
    /// header is probed as before the widening (the probe names temporaries:
    /// a failed probe of more tests restores the name counter, so a loop
    /// read before reads the same).
    #[allow(clippy::type_complexity)]
    fn while_cond(&mut self, h: usize, env: &Env, body: &BTreeSet<usize>, allow: bool) -> Result<Option<(syn::Expr, usize, usize, Env, Env, Option<CondTree>)>, String> {
        let probe_cx = Cx { k: K::Ret, stop: None, loops: vec![], probe: true };
        let mut probe_out = Vec::new();
        let probe = self.go(0, h, env.clone(), &probe_cx, &mut probe_out);
        let Ok(Flow::Cond(cond, t_t, f_t, env_c, 0, cb)) = probe else { return Ok(None) };
        if !allow || !probe_out.is_empty() {
            return Ok(None);
        }
        let exits: Vec<(usize, usize)> = body.iter().flat_map(|b| self.cfg.succ[*b].iter().filter(|s| !body.contains(s)).map(move |s| (*b, *s))).collect();
        // one test
        if exits.len() == 1 {
            if body.contains(&t_t) && !body.contains(&f_t) {
                return Ok(Some((cond, t_t, f_t, env_c.clone(), env_c, None)));
            }
            if body.contains(&f_t) && !body.contains(&t_t) {
                return Ok(Some((syn::parse_quote!(!(#cond)), f_t, t_t, env_c.clone(), env_c, None)));
            }
        }
        // several tests (`a || b || c`, `a && b`): a tree of tests without effects
        let saved = self.fresh;
        let mut sw = vec![cb];
        let tt = self.cond_tree(t_t, env_c.clone(), h, body, &mut sw, 1);
        let ft = self.cond_tree(f_t, env_c, h, body, &mut sw, 1);
        let tree = CondTree::Test(cond, cb, Box::new(tt), Box::new(ft));
        let mut leaves = Vec::new();
        tree.leaves(&mut leaves);
        let (ins, outs): (Vec<_>, Vec<_>) = leaves.into_iter().partition(|l| l.0);
        // the body and the exit start from the same values on every path
        let same = |ls: &[(bool, usize, Env)]| -> bool {
            let live = self.live_at(ls[0].1);
            let key = |e: &Env| live.iter().map(|l| format!("{:?}", e.vals.get(&(0, *l)))).collect::<Vec<_>>();
            ls.iter().all(|l| l.1 == ls[0].1 && key(&l.2) == key(&ls[0].2))
        };
        let ok = !ins.is_empty() && !outs.is_empty() && same(&ins) && same(&outs) && exits.iter().all(|(b, s)| sw.contains(b) && *s == outs[0].1);
        if !ok {
            self.fresh = saved;
            return Ok(None);
        }
        let (bi, xo) = (ins[0].clone(), outs[0].clone());
        Ok(Some((tree.expr(), bi.1, xo.1, bi.2, xo.2, Some(tree))))
    }

    /// The tests without effects from block `b` (inside the loop at header
    /// `h`): a leaf at the exit or at a block that is not such a test; a test
    /// none of whose paths leaves the loop belongs to the body (a leaf).
    fn cond_tree(&mut self, b: usize, env: Env, h: usize, body: &BTreeSet<usize>, sw: &mut Vec<usize>, depth: usize) -> CondTree {
        if !body.contains(&b) {
            return CondTree::Leaf(false, b, env);
        }
        if b == h || depth > 8 || self.cfg.headers.contains(&b) {
            return CondTree::Leaf(true, b, env);
        }
        let probe_cx = Cx { k: K::Ret, stop: None, loops: vec![], probe: true };
        let mut o = Vec::new();
        match self.go(0, b, env.clone(), &probe_cx, &mut o) {
            Ok(Flow::Cond(c, t, f, e2, 0, cb)) if o.is_empty() => {
                let n = sw.len();
                sw.push(cb);
                let tt = self.cond_tree(t, e2.clone(), h, body, sw, depth + 1);
                let ft = self.cond_tree(f, e2, h, body, sw, depth + 1);
                if !tt.exits() && !ft.exits() {
                    sw.truncate(n);
                    return CondTree::Leaf(true, b, env);
                }
                CondTree::Test(c, cb, Box::new(tt), Box::new(ft))
            }
            _ => CondTree::Leaf(true, b, env),
        }
    }

    /// The one block the loop with body `body` leaves to (edges to blocks
    /// every path from which panics aside), when no block of the loop returns.
    fn loop_exit_block(&self, body: &BTreeSet<usize>) -> Option<usize> {
        let f = self.frames[0].f;
        let mut exits = BTreeSet::new();
        for &b in body {
            if matches!(f.blocks[b].term, Term::Return) {
                return None;
            }
            for &s in &self.cfg.succ[b] {
                if !body.contains(&s) && !must_diverge(f, s, &mut Vec::new()) {
                    exits.insert(s);
                }
            }
        }
        (exits.len() == 1).then(|| *exits.iter().next().unwrap())
    }

    /// A loop inside another loop's body read as a helper from its header
    /// `h` to its one exit `x`, which returns the parameters the loop
    /// assigns (in parameter order, the value itself when there is one):
    /// `let r = f__loopK(..); a = r.0; ..`, then the walk goes on from `x`.
    /// A state is a parameter like any other, returned when the loop writes
    /// it (itself or through a reference into it). A `&mut` live at the
    /// header that refers to an element of a state, or to a literal range of
    /// one (an `IterMut`'s element, `split_at_mut`'s halves of it), is no
    /// parameter: the helper rebuilds it from the state and the element's
    /// index, an extra parameter after the others (`<elem>_index`, `elem`
    /// the variable that held the element; one per index), which the
    /// walker reads as the reference's code (`HelperInfo::derived`).
    /// `None` (nothing written) when it does not apply: another `&mut` or a
    /// state held otherwise than as its place among the parameters, the
    /// receiver of a method, a variable live at the exit that is no
    /// parameter, or a loop that assigns none of them.
    #[allow(clippy::too_many_arguments)]
    fn returning_helper(&mut self, h: usize, k: usize, at: &LoopAttach, x: usize, live: &BTreeSet<usize>, body: &BTreeSet<usize>, env: &Env, cx: &Cx, out: &mut Vec<syn::Stmt>) -> Result<Option<Flow>, String> {
        let f = self.frames[0].f;
        let receiver = self.spec.params.first().is_some_and(|p| p == "self");
        let all = self.loop_params(live, at, env);
        let is_state = |l: usize| self.spec.states.iter().any(|s| *s + 1 == l);
        // a state held as its place (not field by field, not a buffer, not
        // an optional one's)
        let plain_state = |l: usize| is_state(l) && env.refs.get(&(0, l)).is_some_and(|r| r.fields.is_none() && r.buf.is_none() && !r.inner && r.range.is_none());
        if receiver && all.contains(&1) {
            return Ok(None);
        }
        let mut params: Vec<usize> = Vec::new();
        // (the reference's local, the state's local, the index, the range)
        let mut derived: Vec<(usize, usize, syn::Expr, Option<(u128, u128)>)> = Vec::new();
        for &l in &all {
            if is_state(l) {
                if !plain_state(l) {
                    return Ok(None);
                }
                params.push(l);
            } else if let Some(r) = env.refs.get(&(0, l)) {
                let Some((s, ie, range)) = self.element_ref(r, env) else { return Ok(None) };
                derived.push((l, s, ie, range));
            } else if value_ty(&f.locals[l].0).is_none() {
                return Ok(None);
            } else {
                params.push(l);
            }
        }
        for (_, s, _, _) in &derived {
            if !params.contains(s) {
                params.push(*s);
            }
        }
        let live_x = self.live_at(x);
        if live_x.iter().any(|l| *l != 0 && !params.contains(l) && !derived.iter().any(|d| d.0 == *l)) {
            return Ok(None);
        }
        self.order_params(&mut params, body, false);
        let assigned = loop_assigns(f, body);
        // (a state the loop writes through a reference into it)
        let written_through = |l: usize| derived.iter().any(|d| d.1 == l && assigned.contains(&d.0));
        // (with a contract, only what the caller reads after it: a state, or
        // a variable live at the exit)
        let wanted = |l: usize| at.ensures.is_empty() || is_state(l) || live_x.contains(&l);
        let returned: Vec<usize> = params.iter().copied().filter(|l| (assigned.contains(l) || written_through(*l)) && wanted(*l)).collect();
        if returned.is_empty() {
            return Ok(None);
        }
        // the elements' indices: one parameter each, after the others
        let mut indices: Vec<(String, syn::Expr)> = Vec::new();
        for (_, _, ie, _) in &derived {
            let key = ie.to_token_stream().to_string();
            if indices.iter().any(|(_, e)| e.to_token_stream().to_string() == key) {
                continue;
            }
            let stem = match ie {
                syn::Expr::Path(p) => p.path.get_ident().and_then(|i| self.elem_names.get(&i.to_string()).cloned()),
                _ => None,
            };
            let mut name = format!("{}_index", stem.clone().unwrap_or_else(|| "__elem".to_string()));
            while self.frames[0].names.contains(&name) || indices.iter().any(|(n, _)| *n == name) {
                name.push('_');
            }
            // (the element's variable, for an element function's parameter)
            if let Some(st) = stem {
                self.elem_names.insert(name.clone(), st);
            }
            indices.push((name, ie.clone()));
        }
        let tys: Vec<syn::Type> = returned
            .iter()
            .map(|l| {
                if is_state(*l) {
                    return self.state_ty(*l);
                }
                value_ty(&f.locals[*l].0).ok_or_else(|| "a `&mut` result".to_string()).and_then(|t| self.nm.ty(self.m, &t).map_err(|_| "a result type".to_string()))
            })
            .collect::<Result<_, _>>()?;
        let out_ty: syn::Type = if tys.len() == 1 { tys[0].clone() } else { syn::parse_quote!((#(#tys),*)) };
        let name = format_ident!("{}__loop{}", self.spec.lifted_name.replace("::", "__"), k);
        let callee: syn::Expr = syn::parse_quote!(#name);
        // the call, and the results in their variables
        let mut args: Vec<syn::Expr> = params.iter().map(|l| self.state_or_var(env, *l)).collect::<Result<_, _>>()?;
        args.extend(indices.iter().map(|(_, e)| e.clone()));
        let r = ident(&self.fresh("l"));
        out.push(syn::parse_quote!(let #r = #callee(#(#args),*);));
        let mut env2 = env.clone();
        for (i, l) in returned.iter().enumerate() {
            let n = self.frames[0].names[*l].clone();
            let v: syn::Expr = if returned.len() == 1 {
                syn::parse_quote!(#r)
            } else {
                let ix = syn::Index::from(i);
                syn::parse_quote!(#r.#ix)
            };
            if is_state(*l) {
                // (its place, the parameter: what was read of it is read before)
                let sr = env2.refs.get(&(0, *l)).cloned().ok_or("a state without its place")?;
                self.state_store(0, &sr, v, &mut env2, out)?;
                self.assigned_params.insert(*l - 1);
                continue;
            }
            let id = ident(&n);
            out.push(syn::parse_quote!(#id = #v;));
            if self.is_param(0, *l) {
                self.assigned_params.insert(*l - 1);
            }
            env2.vals.insert((0, *l), Val::E(var(&n)));
        }
        // the helper: the header's statements first, `return h(..)` at the
        // back edge, the results where the loop leaves to `x`
        let (mut henv, mut inputs, mut hb) = self.helper_head(&params, env, false)?;
        for (n, _) in &indices {
            let id = ident(n);
            inputs.push(quote!(mut #id: usize));
            henv.declared.insert(n.clone());
        }
        for (l, s, ie, range) in &derived {
            let sr = env.refs.get(&(0, *s)).ok_or("a state without its place")?;
            let base = paren(self.state_value(sr)?);
            let key = ie.to_token_stream().to_string();
            let iname = ident(&indices.iter().find(|(_, e)| e.to_token_stream().to_string() == key).ok_or("an element's index")?.0);
            let range = range.map(|(lo, hi)| (lit_uint(lo, "usize"), lit_uint(hi - lo, "usize")));
            henv.refs.insert((0, *l), LRef { lv: syn::parse_quote!(#base[#iname]), buf: None, fields: None, inner: false, range });
        }
        if !at.at_start.is_empty() {
            let s = &at.at_start;
            hb.push(syn::parse_quote!(proof! { #(#s)* }));
        }
        let mut loops = cx.loops.clone();
        loops.push((h, LoopForm::Helper(callee.clone(), params.clone(), indices.iter().map(|(n, _)| n.clone()).collect())));
        let cx_h = Cx { k: K::Ret, stop: Some(x), loops, probe: false };
        let saved = self.owner.replace((name.to_string(), false));
        let flow = self.go_header(h, henv, &cx_h, &mut hb);
        self.owner = saved;
        if let Flow::Fall(mut e) = flow? {
            let rset: BTreeSet<usize> = returned.iter().copied().collect();
            self.normalize(&rset, &mut e, &mut hb)?;
            let rs: Vec<syn::Expr> = returned.iter().map(|l| self.state_or_var(&e, *l)).collect::<Result<_, _>>()?;
            hb.push(if rs.len() == 1 {
                let r0 = &rs[0];
                syn::parse_quote!(return #r0;)
            } else {
                syn::parse_quote!(return (#(#rs),*);)
            });
        }
        // an element attachment: the body on the element, a function of it
        if let Some(ens) = &at.element {
            let item = match self.extract_element(&name.to_string(), &inputs, &mut hb, &ens.ensures, &ens.requires, &ens.at_start) {
                Ok(item) => item,
                Err(e) => return self.err(0, format!("the element attachment of loop {k}: {e}")),
            };
            self.elements.push(item.sig.ident.to_string());
            self.helpers.push(syn::Item::Fn(item));
        }
        let mut attrs = self.helper_attrs(h, body, at, !self.spec.loops.contains_key(&k));
        for e in &at.ensures {
            attrs.push(syn::parse_quote!(#[ensures(#e)]));
        }
        let item: syn::ItemFn = syn::parse_quote!(
            #(#attrs)*
            fn #name(#(#inputs),*) -> #out_ty { #(#hb)* }
        );
        self.helpers.push(syn::Item::Fn(item));
        self.loop_forms.push((k, "returning".into()));
        let positions: Vec<usize> = returned.iter().filter_map(|l| params.iter().position(|p| p == l)).collect();
        let iters: Vec<(usize, usize)> = params.iter().enumerate().filter_map(|(i, l)| self.iter_params.get(l).map(|p| (i, *p))).collect();
        let derived_info: Vec<(usize, usize, usize, Option<(u128, u128)>)> = derived
            .iter()
            .map(|(l, s, ie, range)| {
                let key = ie.to_token_stream().to_string();
                let sp = params.iter().position(|p| p == s).unwrap_or(usize::MAX);
                let ip = params.len() + indices.iter().position(|(_, e)| e.to_token_stream().to_string() == key).unwrap_or(usize::MAX - params.len());
                (*l, sp, ip, *range)
            })
            .collect();
        let extra: Vec<String> = indices.iter().map(|(n, _)| n.clone()).collect();
        self.helper_info.push(HelperInfo { name: name.to_string(), method: false, header: h, params: params.clone(), while_loop: false, local_names: self.frames[0].names.clone(), returns: Some(positions), owner: self.owner.clone(), iters, derived: derived_info, extra });
        Ok(Some(self.go(0, x, env2, cx, out)?))
    }

    /// A `&mut` that refers to an element of a state held as its place, or
    /// to a literal range of one (`&mut xs[i]`, `&mut xs[i][lo..hi]`): (the
    /// state's local, the element's index, the range as the literal
    /// reading's `PRange(lo, hi)`).
    fn element_ref(&self, r: &LRef, env: &Env) -> Option<(usize, syn::Expr, Option<(u128, u128)>)> {
        if r.buf.is_some() || r.fields.is_some() || r.inner {
            return None;
        }
        let syn::Expr::Index(ix) = &r.lv else { return None };
        let base = ix.expr.to_token_stream().to_string();
        let s = self.spec.states.iter().map(|s| s + 1).find(|l| env.refs.get(&(0, *l)).is_some_and(|sr| sr.fields.is_none() && sr.buf.is_none() && !sr.inner && sr.range.is_none() && sr.lv.to_token_stream().to_string() == base))?;
        let range = match &r.range {
            None => None,
            Some((off, len)) => {
                let (o, n) = (lit_value(off)?, lit_value(len)?);
                Some((o, o.checked_add(n)?))
            }
        };
        Some((s, (*ix.index).clone(), range))
    }

    /// An untrusted guess of the measure of the loop at header `h` whose
    /// attachment states none: the elaborator proves its decrease at every
    /// step and the kernel checks those proofs, so a wrong guess only makes
    /// the loop fail to elaborate. The remaining length of an iterator live
    /// at the header (core's range over an unsigned type, `RangeInclusive<
    /// u32/u64>`, the slice iterator), else from a test that leaves the
    /// loop, over unsigned variables live at the header and constants: a
    /// counter moving up to a bound (`i < n`: `n - i`), a value moving down
    /// (`x > b`, `x != 0`, `x & m == c`: `x`).
    fn guess_measure(&self, h: usize, body: &BTreeSet<usize>, tree: Option<&CondTree>) -> Option<syn::Expr> {
        let f = self.frames[0].f;
        let live = &self.cfg.live_in[h];
        // (an iterator the loop steps: borrowed mutably in it, for its `next`;
        // an outer loop's iterator passes through an inner loop unchanged)
        let stepped = loop_assigns(f, body);
        let mut ls: Vec<usize> = live.iter().copied().filter(|l| *l != 0 && stepped.contains(l)).collect();
        ls.sort();
        for &l in &ls {
            let t = &f.locals[l].0;
            let x = var(&self.frames[0].names[l]);
            if super::slice_iter_elem(self.m, t).is_some() {
                return Some(syn::parse_quote!((#x.0.len() as Int) - (#x.1 as Int)));
            }
            // core's `IterMut`: the index over the slice it walks
            if super::iter_mut_elem(self.m, t).is_some()
                && let Some(sl) = self.iter_slices.get(&l)
            {
                let sl = paren(sl.clone());
                return Some(syn::parse_quote!((#sl.len() as Int) - (#x as Int)));
            }
            if let Ty::Adt(k) = t
                && let Some(d) = self.m.adts.get(k)
            {
                match (d.path.as_str(), d.args.first()) {
                    ("std::ops::Range" | "core::ops::Range", Some(Ty::Int(false, _))) => return Some(syn::parse_quote!((#x.end as Int) - (#x.start as Int))),
                    ("std::ops::RangeInclusive" | "core::ops::RangeInclusive", Some(Ty::Int(false, 32 | 64))) => return Some(syn::parse_quote!((#x.end as Int) - (#x.start as Int) + ((!#x.exhausted) as u64 as Int))),
                    _ => {}
                }
            }
        }
        // a condition of several tests: the measures of the tests that let the
        // loop go on, summed (`a > 0 || b > 0`: `a + b`), the first of a conjunction
        if let Some(t) = tree {
            return self.tree_measure(t, h);
        }
        // a test that leaves the loop
        for &b in body {
            let Term::Switch(_, arms, otherwise) = &f.blocks[b].term else { continue };
            let on = |v: u128| arms.iter().find(|a| a.0 == v).map(|a| a.1).unwrap_or(*otherwise);
            let stay = match (body.contains(&on(1)), body.contains(&on(0))) {
                (true, false) => true,
                (false, true) => false,
                _ => continue,
            };
            if let Some(m) = self.test_measure(b, stay, h) {
                return Some(m);
            }
        }
        None
    }

    /// The measure of a tree of tests ([`Self::guess_measure`]).
    fn tree_measure(&self, t: &CondTree, h: usize) -> Option<syn::Expr> {
        use CondTree::{Leaf, Test};
        let sum = |a: syn::Expr, b: syn::Expr| -> syn::Expr { syn::parse_quote!(#a + #b) };
        let Test(_, b, l, r) = t else { return None };
        match (&**l, &**r) {
            (Leaf(true, ..), Leaf(false, ..)) => self.test_measure(*b, true, h),
            (Leaf(false, ..), Leaf(true, ..)) => self.test_measure(*b, false, h),
            (Leaf(true, ..), rest) => Some(sum(self.test_measure(*b, true, h)?, self.tree_measure(rest, h)?)),
            (rest, Leaf(true, ..)) => Some(sum(self.test_measure(*b, false, h)?, self.tree_measure(rest, h)?)),
            (rest, Leaf(false, ..)) => self.test_measure(*b, true, h).or_else(|| self.tree_measure(rest, h)),
            (Leaf(false, ..), rest) => self.test_measure(*b, false, h).or_else(|| self.tree_measure(rest, h)),
            _ => None,
        }
    }

    /// The measure a loop test in block `b` gives when the loop goes on
    /// while its condition is `stay`: from a comparison of an unsigned
    /// variable live at the header `h` (copied into a temporary in the
    /// block, or a bit mask or shift of it) with another or a constant.
    fn test_measure(&self, b: usize, stay: bool, h: usize) -> Option<syn::Expr> {
        let f = self.frames[0].f;
        let live = &self.cfg.live_in[h];
        let bl = &f.blocks[b];
        let Term::Switch(Operand::Copy(cp) | Operand::Move(cp), _, _) = &bl.term else { return None };
        if !cp.proj.is_empty() || f.locals[cp.local].0 != Ty::Bool {
            return None;
        }
        let def = |l: usize| {
            bl.stmts.iter().rev().find_map(|s| match s {
                Stmt::Assign(p, r, _) if p.local == l && p.proj.is_empty() => Some(r.clone()),
                _ => None,
            })
        };
        let Some(Rvalue::Bin(op, a, c)) = def(cp.local) else { return None };
        let name = |l: usize| var(&self.frames[0].names[l]);
        let unsigned = |l: usize| matches!(f.locals[l].0, Ty::Int(false, _));
        // (the expression, the variable, whether it is a mask or shift of it)
        // (a variable live at the header, through the block's copies of it:
        // rustc copies a variable into a temporary before operating on it)
        let live_var = |o: &Operand| -> Option<usize> {
            let (Operand::Copy(q) | Operand::Move(q)) = o else { return None };
            let mut l = q.local;
            if !q.proj.is_empty() {
                return None;
            }
            for _ in 0..4 {
                if live.contains(&l) {
                    return unsigned(l).then_some(l);
                }
                match def(l)? {
                    Rvalue::Use(Operand::Copy(r) | Operand::Move(r)) if r.proj.is_empty() => l = r.local,
                    _ => return None,
                }
            }
            None
        };
        let operand = |o: &Operand| -> Option<(syn::Expr, Option<usize>, bool)> {
            match o {
                Operand::Const(k) => match k.value() {
                    Const::Int(t @ Ty::Int(false, _), v) => Some((lit_uint(*v as u128, &int_ty_name(t)?), None, false)),
                    _ => None,
                },
                Operand::Copy(p) | Operand::Move(p) if p.proj.is_empty() => {
                    if let Some(l) = live_var(o) {
                        return Some((name(l), Some(l), false));
                    }
                    match def(p.local)? {
                        Rvalue::Bin(o2, q, _) if matches!(o2.as_str(), "and" | "shr" | "rem") => live_var(&q).map(|l| (name(l), Some(l), true)),
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        let ((xe, xl, xd), (ye, yl, yd)) = (operand(&a)?, operand(&c)?);
        let op = match (op.as_str(), stay) {
            (o, true) => o,
            ("lt", false) => "ge",
            ("le", false) => "gt",
            ("gt", false) => "le",
            ("ge", false) => "lt",
            ("eq", false) => "ne",
            ("ne", false) => "eq",
            _ => return None,
        };
        let zero = |e: &syn::Expr| lit_value(e) == Some(0);
        Some(match (op, xl, yl) {
            // a mask or shift of a variable against a constant: the variable goes down
            (_, Some(_), None) if xd => syn::parse_quote!((#xe as Int)),
            (_, None, Some(_)) if yd => syn::parse_quote!((#ye as Int)),
            // a counter moving up to a bound, or a bound moving down to it
            ("lt", Some(_), _) => syn::parse_quote!((#ye as Int) - (#xe as Int)),
            ("le", Some(_), _) => syn::parse_quote!((#ye as Int) - (#xe as Int) + 1),
            ("lt" | "le", None, Some(_)) => syn::parse_quote!((#ye as Int)),
            // a value moving down to a bound, or a counter moving up to it
            ("gt" | "ge", Some(_), _) => syn::parse_quote!((#xe as Int)),
            ("gt", None, Some(_)) => syn::parse_quote!((#xe as Int) - (#ye as Int)),
            ("ge", None, Some(_)) => syn::parse_quote!((#xe as Int) - (#ye as Int) + 1),
            ("ne", Some(_), None) if zero(&ye) => syn::parse_quote!((#xe as Int)),
            ("ne", None, Some(_)) if zero(&xe) => syn::parse_quote!((#ye as Int)),
            _ => return None,
        })
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
                // `&mut [T]`: the state `&[T]` (docs/mir-lift.md §20.10)
                Ty::Slice(_) => self.nm.ty(self.m, &Ty::Ref(false, inner.clone())),
                other => self.nm.ty(self.m, other),
            },
            other => self.nm.ty(self.m, other),
        }
    }
}


/// The structured reading of a library function read as a model
/// ([`super::Model`]; the literal reading's `leaf::slice_*`): a small MIR
/// body over the model's types, inlined like the function's own MIR would
/// be (its tests become the reading's splits, its paths do not join). A
/// slice iterator is the pair `(slice, index)`.
pub fn model_body(m: &Sbmir, f: &Fn) -> Option<Fn> {
    let (model, elem) = super::model_of(f)?;
    let us = Ty::Int(false, 0);
    let slice = Ty::Ref(false, Box::new(Ty::Slice(Box::new(elem.clone()))));
    let iter = Ty::Tuple(vec![slice.clone(), us.clone()]);
    let p = |l: usize, proj: Vec<Proj>| Place { local: l, proj };
    let cp = |l: usize, proj: Vec<Proj>| Operand::Copy(p(l, proj));
    let int = |v: i128| Operand::Const(Const::Int(Ty::Int(false, 0), v));
    let asg = |l: usize, proj: Vec<Proj>, r: Rvalue| Stmt::Assign(p(l, proj), r, None);
    let blk = |stmts: Vec<Stmt>, term: Term| Block { stmts, term, term_loc: None };
    let ret = f.locals.first()?.0.clone();
    // the result's `Option` variants, by name
    let opt = |name: &str| -> Option<usize> {
        let Ty::Adt(k) = &ret else { return None };
        m.adts.get(k)?.variants.iter().find(|v| v.name == name).map(|v| v.idx)
    };
    let (locals, blocks): (Vec<Ty>, Vec<Block>) = match model {
        // `(s, 0)`
        super::Model::SliceIterNew => (vec![iter.clone(), slice.clone()], vec![blk(vec![asg(0, vec![], Rvalue::Agg(AggKind::Tuple, vec![cp(1, vec![]), int(0)]))], Term::Return)]),
        // `let i = it.1; let s = it.0; if i < s.len() { let x = &s[i]; it.1 = i + 1; Some(x) } else { None }`
        super::Model::SliceIterNext => {
            let (some, none) = (opt("Some")?, opt("None")?);
            let it = |i: usize, t: &Ty| vec![Proj::Deref, Proj::Field(i, t.clone())];
            let locals = vec![ret.clone(), Ty::Ref(true, Box::new(iter.clone())), us.clone(), slice.clone(), us.clone(), Ty::Bool, Ty::Ref(false, Box::new(elem.clone())), Ty::Tuple(vec![us.clone(), Ty::Bool])];
            let b0 = blk(
                vec![asg(2, vec![], Rvalue::Use(cp(1, it(1, &us)))), asg(3, vec![], Rvalue::Use(cp(1, it(0, &slice)))), asg(4, vec![], Rvalue::Un("ptr-metadata".into(), cp(3, vec![]))), asg(5, vec![], Rvalue::Bin("lt".into(), cp(2, vec![]), cp(4, vec![])))],
                Term::Switch(Operand::Move(p(5, vec![])), vec![(0, 2)], 1),
            );
            let b1 = blk(vec![asg(6, vec![], Rvalue::Ref("shared".into(), p(3, vec![Proj::Deref, Proj::Index(2)]))), asg(7, vec![], Rvalue::Checked("add".into(), cp(2, vec![]), int(1)))], Term::Assert(Operand::Move(p(7, vec![Proj::Field(1, Ty::Bool)])), false, "overflow".into(), 3));
            let b2 = blk(vec![asg(0, vec![], Rvalue::Agg(AggKind::Adt(ret.clone(), none), vec![]))], Term::Return);
            let b3 = blk(vec![asg(1, it(1, &us), Rvalue::Use(Operand::Move(p(7, vec![Proj::Field(0, us.clone())])))), asg(0, vec![], Rvalue::Agg(AggKind::Adt(ret.clone(), some), vec![cp(6, vec![])]))], Term::Return);
            (locals, vec![b0, b1, b2, b3])
        }
        // `if r.start <= r.end { if r.end <= s.len() { Some(&s[r.start..r.end]) } else { None } } else { None }`
        super::Model::SliceGetRange => {
            let (some, none) = (opt("Some")?, opt("None")?);
            let range = f.locals.get(1)?.0.clone();
            let index = Callee::Leaf("core::ops::Index::index".into(), vec![Ty::Slice(Box::new(elem.clone())), range.clone()]);
            let locals = vec![ret.clone(), range.clone(), slice.clone(), us.clone(), us.clone(), Ty::Bool, us.clone(), Ty::Bool, slice.clone(), range.clone()];
            let b0 = blk(vec![asg(3, vec![], Rvalue::Use(cp(1, vec![Proj::Field(0, us.clone())]))), asg(4, vec![], Rvalue::Use(cp(1, vec![Proj::Field(1, us.clone())]))), asg(5, vec![], Rvalue::Bin("le".into(), cp(3, vec![]), cp(4, vec![])))], Term::Switch(Operand::Move(p(5, vec![])), vec![(0, 3)], 1));
            let b1 = blk(vec![asg(6, vec![], Rvalue::Un("ptr-metadata".into(), cp(2, vec![]))), asg(7, vec![], Rvalue::Bin("le".into(), cp(4, vec![]), cp(6, vec![])))], Term::Switch(Operand::Move(p(7, vec![])), vec![(0, 3)], 2));
            let b2 = blk(vec![asg(9, vec![], Rvalue::Agg(AggKind::Adt(range, 0), vec![cp(3, vec![]), cp(4, vec![])]))], Term::Call(index, vec![cp(2, vec![]), Operand::Move(p(9, vec![]))], p(8, vec![]), Some(4)));
            let b3 = blk(vec![asg(0, vec![], Rvalue::Agg(AggKind::Adt(ret.clone(), none), vec![]))], Term::Return);
            let b4 = blk(vec![asg(0, vec![], Rvalue::Agg(AggKind::Adt(ret.clone(), some), vec![cp(8, vec![])]))], Term::Return);
            (locals, vec![b0, b1, b2, b3, b4])
        }
        // (core's `IterMut` holds a `&mut` the subset cannot hold in a
        // value: the reading reads its loop itself, `Reader::call`)
        super::Model::IterMutNew | super::Model::IterMutNext | super::Model::IterMutIntoIter | super::Model::SplitAtMut => return None,
    };
    let mut g = f.clone();
    g.locals = locals.into_iter().map(|t| (t, true)).collect();
    g.blocks = blocks;
    g.debug = vec![];
    Some(g)
}

/// The variant of the one value of an enum all of whose variants but one
/// have a field of an empty type (`!`, an enum without variants), that one
/// without fields (`Option<Infallible>`: `None`).
fn single_value(m: &Sbmir, k: &str) -> Option<usize> {
    let d = m.adts.get(k)?;
    let empty = |t: &Ty| matches!(t, Ty::Never) || matches!(t, Ty::Adt(e) if m.adts.get(e).is_some_and(|de| de.is_enum && de.variants.is_empty()));
    let live: Vec<&Variant> = d.variants.iter().filter(|v| !v.fields.iter().any(|f| empty(&f.1))).collect();
    match live.as_slice() {
        [v] if d.variants.len() > 1 && v.fields.is_empty() => Some(v.idx),
        _ => None,
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
    let models: std::collections::BTreeMap<String, Fn> = m.fns.iter().filter_map(|(k, g)| model_body(m, g).map(|b| (k.clone(), b))).collect();
    let mut r = Reader { m, nm, spec, models: &models, frames: Vec::new(), cfg, fresh: 0, helpers: Vec::new(), loop_forms: Vec::new(), assigned_params: BTreeSet::new(), helper_info: Vec::new(), owner: None, whiles: Default::default(), iter_slices: HashMap::new(), iter_params: HashMap::new(), elem_names: HashMap::new(), elements: Vec::new() };
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
            env.refs.insert((fr, l), LRef { lv: var(&name), buf, fields, inner: false, range: None });
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
    Ok(ReadOut { body: syn::Block { brace_token: Default::default(), stmts: out }, helpers: r.helpers, loops: r.loop_forms, assigned_params: r.assigned_params.into_iter().collect(), helper_info: r.helper_info, elements: r.elements })
}
