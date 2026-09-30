//! Surface signatures of the prelude lemmas (DESIGN.md §4.5: "prelude
//! lemmas are addressable from ghost code as `sandblaster::lemmas::<name>`").
//!
//! Every kernel lemma loaded with the prelude and the lemma files
//! ([`super::lemmas::load`]) whose telescope has a surface reading gets a
//! ghost `#[lemma]` signature: the kernel lemma `slice::first_chunk_exact :
//! (T : Type) (s : Slice T) (N : Usize) (k : Array T N) (.hn : ..) (.e : ..)
//! -> ..` is `sandblaster::lemmas::slice::first_chunk_exact(s, N, k)` with
//! `s: &[T]`, `N: usize` and `k` of any (array) type. The reading of each
//! kernel binder ([`Role`]):
//!
//! * `T : Type` — a generic parameter `<T: Copy>` (inferred or turbofish);
//! * a relevant binder of a surface type — a parameter: `IntTy` ↦ `uN` /
//!   `Int`, `Bool` ↦ `bool`, `Slice T` ↦ `&[T]`, `Array T n` ↦ `[T; n]`
//!   (literal `n`), `Option`, tuples, `Unit`; `List T` ↦ `Seq<T>` (slices
//!   and arrays coerce to it); an array
//!   whose length is an earlier parameter ↦ a fresh generic type (the kernel
//!   checks the instantiation);
//! * an irrelevant binder, or a relevant proposition (`Eq`, `Empty`, `Σ`,
//!   `Not`/`And`/`Or`/`Iff`/`Exists`) — a hypothesis proven by `auto` at the
//!   application, like a `requires`.
//!
//! Lemmas with other binders (function-typed parameters such as
//! `array::eq_sound`'s element equality) have no surface form. The table is
//! computed once per process ([`table`]) from a fresh environment; the
//! elaborator recomputes the roles on its own environment ([`sig`]).

use std::sync::OnceLock;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefKind, GlobalId, Rel, Sort, Term, Tm, Width};

/// How a kernel binder of a prelude lemma is supplied at a surface
/// application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// The `i`-th generic type argument.
    Type(usize),
    /// The `i`-th surface argument; with `list`, the kernel binder is a
    /// `List T` and receives the argument slice's list.
    Value { index: usize, list: bool },
    /// A hypothesis, proven by the prover at the application.
    Hyp,
}

/// The surface reading of a prelude lemma.
#[derive(Clone, Debug)]
pub struct Sig {
    /// One role per kernel binder, in telescope order.
    pub roles: Vec<Role>,
    /// Generic parameter names (type binders first come in order; fresh
    /// generics for dependent array types are interleaved where they occur).
    pub generics: Vec<String>,
    /// Surface parameters: `(name, Rust type)`.
    pub params: Vec<(String, String)>,
    /// Index of the generic of each type binder (in `roles` order).
    pub type_generics: Vec<usize>,
}

/// A prelude lemma with a surface signature.
#[derive(Clone, Debug)]
pub struct SurfaceLemma {
    /// Kernel name (`slice::first_chunk_exact`).
    pub kernel: String,
    /// Surface path below `sandblaster::lemmas` (`["slice", "first_chunk_exact"]`).
    pub path: Vec<String>,
    /// The ghost item: `#[lemma] fn name<..>(..) {}`.
    pub src: String,
}

#[derive(Clone)]
enum B {
    /// A type binder (generic index).
    Ty(usize),
    /// A value binder (surface parameter index).
    Val,
    /// A hypothesis.
    Hyp,
}

fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !s.chars().next().unwrap().is_ascii_digit()
}

/// Rust spelling of a kernel type in a binder context, if it has one.
/// `list_top`: a top-level `List T` is read as a slice.
fn rust_ty(env: &Env, t: &Tm, bs: &[B], gen_names: &[String], fresh: &mut dyn FnMut() -> String, list_top: bool) -> Option<(String, bool)> {
    let var_binder = |i: u32| -> Option<&B> { bs.len().checked_sub(1 + i as usize).and_then(|k| bs.get(k)) };
    match &**t {
        Term::Var(i) => match var_binder(i.0)? {
            B::Ty(g) => Some((gen_names[*g].clone(), false)),
            _ => None,
        },
        Term::IntTy(w) => Some((
            match w {
                Width::U8 => "u8",
                Width::U16 => "u16",
                Width::U32 => "u32",
                Width::U64 => "u64",
                Width::Usize => "usize",
                Width::Int => "::sandblaster::prelude::Int",
            }
            .to_string(),
            false,
        )),
        Term::Ind { ind, params } => {
            let decl = env.inductive_decl(*ind)?;
            let name = decl.name.to_string();
            let args: Option<Vec<String>> = params.iter().map(|p| rust_ty(env, p, bs, gen_names, fresh, false).map(|x| x.0)).collect();
            let args = args?;
            if *ind == env.bool_ind() {
                return Some(("bool".into(), false));
            }
            match name.as_str() {
                "Unit" => Some(("()".into(), false)),
                "Option" => Some((format!("::core::option::Option<{}>", args[0]), false)),
                // a `Seq<T>` (§15 S5: spec code works on sequences); slices
                // and arrays coerce to it in ghost code
                "List" if list_top => Some((format!("Seq<{}>", args[0]), false)),
                n if n.starts_with("Tuple") && args.len() >= 2 => Some((format!("({})", args.join(", ")), false)),
                _ => None,
            }
        }
        Term::App { .. } => {
            let (h, args) = crate::elab::items::spine(t);
            let Term::Global(g) = &*h else { return None };
            let gname = env.global_name(*g)?.to_string();
            match (gname.as_str(), args.len()) {
                ("Slice", 1) => Some((format!("&[{}]", rust_ty(env, &args[0], bs, gen_names, fresh, false)?.0), false)),
                ("Array", 2) => {
                    let e = rust_ty(env, &args[0], bs, gen_names, fresh, false)?.0;
                    match &*args[1] {
                        Term::Lit { n, .. } => Some((format!("[{e}; {n}]"), false)),
                        Term::Var(i) if matches!(var_binder(i.0), Some(B::Val)) => Some((fresh(), false)),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether a (relevant) binder type is a proposition.
fn is_prop(env: &Env, t: &Tm) -> bool {
    match &**t {
        Term::Eq { .. } | Term::Sigma { .. } => true,
        Term::Ind { ind, .. } => *ind == env.empty_ind(),
        Term::App { .. } => {
            let (h, _) = crate::elab::items::spine(t);
            matches!(&*h, Term::Global(g) if env.global_name(*g).is_some_and(|n| matches!(&*n, "Not" | "And" | "Or" | "Iff" | "Exists")))
        }
        _ => false,
    }
}

/// The surface reading of lemma `g` (see the module docs).
pub fn sig(env: &Env, g: GlobalId) -> Option<Sig> {
    if env.global_kind(g)? != DefKind::Lemma {
        return None;
    }
    let mut t = env.global_type(g)?;
    let mut bs: Vec<B> = Vec::new();
    let mut roles = Vec::new();
    let mut generics: Vec<String> = Vec::new();
    let mut type_generics = Vec::new();
    let mut params: Vec<(String, String)> = Vec::new();
    let mut used_names: Vec<String> = Vec::new();
    loop {
        let Term::Pi { name, rel, dom, cod } = &*t.clone() else { break };
        if *rel == Rel::Irr || is_prop(env, dom) {
            bs.push(B::Hyp);
            roles.push(Role::Hyp);
        } else if matches!(&**dom, Term::Sort(Sort::Type)) {
            let gi = generics.len();
            let mut n = format!("T{gi}");
            if ident_ok(name) && name.chars().next().is_some_and(|c| c.is_ascii_uppercase()) && !used_names.contains(&name.to_string()) {
                n = name.to_string();
            }
            used_names.push(n.clone());
            generics.push(n);
            type_generics.push(gi);
            bs.push(B::Ty(gi));
            roles.push(Role::Type(gi));
        } else {
            let mut extra: Vec<String> = Vec::new();
            let base = generics.len();
            let gen_snapshot = generics.clone();
            let mut fresh = || {
                let n = format!("A{}", base + extra.len());
                extra.push(n.clone());
                n
            };
            let (ty, list) = rust_ty(env, dom, &bs, &gen_snapshot, &mut fresh, true)?;
            generics.extend(extra);
            let mut pn = if ident_ok(name) && name.as_ref() != "_" { name.to_string() } else { format!("x{}", params.len()) };
            if used_names.contains(&pn) || generics.contains(&pn) || matches!(pn.as_str(), "self" | "crate" | "super" | "Self" | "fn" | "let" | "match" | "type" | "ref" | "mut" | "move" | "in" | "as" | "use" | "mod" | "impl" | "loop" | "where" | "for" | "if" | "else" | "true" | "false") {
                pn = format!("x{}", params.len());
            }
            used_names.push(pn.clone());
            let index = params.len();
            params.push((pn, ty));
            bs.push(B::Val);
            roles.push(Role::Value { index, list });
        }
        t = cod.clone();
    }
    Some(Sig { roles, generics, params, type_generics })
}

/// The ghost `#[lemma]` item for a surface signature.
fn item_src(name: &str, s: &Sig) -> String {
    let gens = if s.generics.is_empty() { String::new() } else { format!("<{}>", s.generics.iter().map(|g| format!("{g}: Copy")).collect::<Vec<_>>().join(", ")) };
    let ps = s.params.iter().map(|(n, t)| format!("{n}: {t}")).collect::<Vec<_>>().join(", ");
    format!("#[lemma] fn {name}{gens}({ps}) {{}}")
}

/// Every prelude lemma of `env` with a surface signature.
pub fn lemmas_of(env: &Env) -> Vec<SurfaceLemma> {
    let mut out = Vec::new();
    for i in 0..env.num_globals() {
        let g = GlobalId(i);
        let Some(name) = env.global_name(g) else { continue };
        let path: Vec<String> = name.split("::").map(|x| x.to_string()).collect();
        if !path.iter().all(|p| ident_ok(p)) {
            continue;
        }
        let Some(s) = sig(env, g) else { continue };
        // the most recent definition of a name wins (like `lookup_global`)
        out.retain(|l: &SurfaceLemma| l.kernel != *name);
        out.push(SurfaceLemma { kernel: name.to_string(), src: item_src(path.last().unwrap(), &s), path });
    }
    out
}

/// Surface forms of per-literal bit-family lemmas ([`super::bitlib`]) named
/// in the sources (`lz_ge_u16_9`): generated on a fresh environment and
/// kernel-checked there; the elaborator generates the same lemmas in the
/// crate's environment ([`super::bitlib::ensure`]).
pub fn family_lemmas(names: &[String]) -> Vec<SurfaceLemma> {
    let names: Vec<String> = names.iter().filter(|n| super::bitlib::parse_lemma_name(n).is_some()).cloned().collect();
    if names.is_empty() {
        return Vec::new();
    }
    std::thread::Builder::new()
        .name("sandblaster-family-lemmas".into())
        .stack_size(256 << 20)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit((256 << 20) - (16 << 20));
            let mut env = Env::with_prelude();
            if super::lemmas::load(&mut env).is_err() {
                return Vec::new();
            }
            let mut wanted = Vec::new();
            for n in &names {
                let Some((f, w, k)) = super::bitlib::parse_lemma_name(n) else { continue };
                let mut b = sandblaster_kernel::value::Budget { steps: 2_000_000_000 };
                if super::bitlib::ensure(&mut env, f, w, k, &mut b).is_ok() {
                    wanted.push(super::bitlib::lemma_name(f, w, k));
                }
            }
            lemmas_of(&env).into_iter().filter(|l| wanted.contains(&l.kernel)).collect()
        })
        .ok()
        .and_then(|h| h.join().ok())
        .unwrap_or_default()
}

/// The prelude lemma table (computed once per process from the prelude and
/// the lemma files; empty if they fail to load, which the elaborator
/// reports as an internal error).
pub fn table() -> &'static [SurfaceLemma] {
    static TABLE: OnceLock<Vec<SurfaceLemma>> = OnceLock::new();
    TABLE.get_or_init(|| {
        // the kernel is recursive: load on a thread with a large stack
        std::thread::Builder::new()
            .name("sandblaster-lemma-table".into())
            .stack_size(256 << 20)
            .spawn(|| {
                sandblaster_kernel::util::set_stack_limit((256 << 20) - (16 << 20));
                let mut env = Env::with_prelude();
                if super::lemmas::load(&mut env).is_err() {
                    return Vec::new();
                }
                lemmas_of(&env)
            })
            .ok()
            .and_then(|h| h.join().ok())
            .unwrap_or_default()
    })
}
