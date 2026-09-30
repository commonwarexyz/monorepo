//! The codegen round trip (DESIGN.md §8.3).
//!
//! The printed file is what `rustc` compiles, so it is read back and given
//! its meaning by the **same elaboration semantics** as the source:
//!
//! 1. **Parse** the file with `syn` and account for every item: the fixed
//!    guard and module attributes, the `pub use` exports, every module, the
//!    trusted glue (load/store helpers, dispatchers, runtime detection),
//!    compared token for token with the fixed templates, and every type,
//!    constant and function of the print view — nothing else may appear.
//!    The source's re-exports ([`crate::canon::ReExport`]) are compared the
//!    same way, each in its module (the root's with the top-level exports):
//!    every one is printed exactly once, so the generated crate's public API
//!    is the source's. A re-export the generated crate cannot have is a
//!    failure; one whose target is not emitted (the §9.2 evidence gate) is
//!    an API difference ([`Stats::api_differences`]), like the target.
//! 2. **Lower** the canonical dialect to HIR ([`Lower`]): the dialect is
//!    fully explicit (absolute paths, suffixed literals, typed `let`s, UFCS
//!    builtins, explicit `&`/`*`/unsizing, `l{id}_{name}` locals), so the
//!    lowering is a direct translation with types computed bottom-up — no
//!    inference. Generated-mode constructs are accepted here and nowhere
//!    else: `unsafe { *<[T]>::get_unchecked(s, i) }` (an index), `unsafe {
//!    <[T]>::get_unchecked(s, a..b) }` (a range), unchecked mutable places
//!    in assignments and `copy_from_slice`, `unsafe fn` for functions with
//!    `requires`, `unsafe { f(..) }` calls of them, and the canonical `loop
//!    { … continue … }` of tail-recursive functions (lowered back to the
//!    recursive calls). Ghost parts that are not printed (contracts, loop
//!    invariants, `proof!` blocks) come from the print view; a loop's
//!    assigned locals must equal the print view's and its reads must be
//!    among them (the ghost reads are extra helper parameters).
//! 3. **Elaborate** the lowered crate in generated mode
//!    ([`crate::elab::generated::generated`]): every proof slot is
//!    `Erased`, definitions are recorded, not added.
//! 4. **Compare** every recorded definition (functions, their loop helpers,
//!    constants) with its optimized core definition — the residual for a
//!    specialized function, the clone for a multiversioned one, the source
//!    definition otherwise — with `Env::alpha_eq_relevant` after erasing
//!    irrelevant binders on both sides (irrelevant λ/let/application/Π:
//!    facts, path equations, `requires`, proofs), so every relevant
//!    position must be identical: hoisting an unchecked read out of its
//!    guard, dropping, duplicating or swapping an operation fails.
//! 5. **Skeleton**: the binding/scope skeleton (`let`s with their
//!    mutability, assignments, blocks, loops, match arms) of every lowered
//!    function equals the print view's.
//!
//! # Name resolution
//!
//! The lowering gives every identifier of the printed text rustc's meaning,
//! from the module scopes it reads back from the printed text itself
//! ([`read_scopes`]: every item and every `use` binding, renames included,
//! resolved against the printed modules; `::core` paths classified; a glob
//! or macro item poisons its module) and rustc's prelude — not from the
//! printer's naming rule (`canon`, *Generated names*), whose spelling it
//! checks separately:
//!
//! * an identifier pattern (parameters, `let`s, match arms, `for`
//!   variables, slice rests, tail-loop arguments and temporaries) that names
//!   a constant, static, unit or tuple constructor in scope — declared in
//!   the module, bound by a `use`/`pub use`, or in the prelude (`None`) — is
//!   not a binding: a failure (a *capture*: `l1_y if l1_y > 3 => l1_y` with
//!   a constant `l1_y` in scope matches only that constant);
//! * a single-segment expression path is a local binding in scope (rustc:
//!   locals shadow items), anything else fails;
//! * a primitive type written unqualified (`u32`, `u32::MAX`, `<u32>::f`)
//!   must not be shadowed by a generic parameter or a module-scope name;
//! * separately ([`shadow_failures`]), no identifier pattern anywhere in the
//!   printed text — glue included — has the name of a module-scope name of
//!   its module (any namespace) or of a prelude name, and no module-scope
//!   name is a primitive type name;
//! * a method call `<E>::name(..)` on an enum `E` with a variant `name`
//!   fails: rustc resolves the type-relative path to the variant (variants
//!   come before associated functions);
//! * no name is bound twice in one namespace of one printed module or of
//!   the top level (items, `use` bindings, glue modules, exports: rustc
//!   E0428/E0255/E0252), so every printed binding is the only one of its
//!   name ([`PrintedScopes::duplicates`], [`top_level_duplicates`]);
//! * every identifier of the printed text is ASCII, not raw and not a
//!   reserved keyword `syn` accepts (`gen`) ([`identifier_failures`]):
//!   rustc NFC-normalizes identifiers and reads `r#x` as `x`, so only then
//!   is the reader's spelling equality rustc's identifier equality.
//!
//! Any failure is a build error (a printer or elaborator bug).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::Instant;

use quote::ToTokens;
use sandblaster_kernel::term::{GlobalId, Rel, Term, Tm};

use crate::builtins::{ArrayMethod, Builtin, IntMethod, OptionMethod, SliceMethod};
use crate::canon::ChkHelper;
use crate::elab::Output;
use crate::hir::*;
use crate::intrinsics;
use crate::opt::Optimized;
use crate::span::{SourceMap, Span};

/// Round-trip statistics and failures.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Definitions compared (functions, loop helpers, constants).
    pub compared: usize,
    /// Functions whose skeleton was compared.
    pub skeletons: usize,
    /// Trusted-glue items compared verbatim (helpers, dispatchers,
    /// detection module, guard, exports).
    pub glue: usize,
    /// Re-exports of the source compared verbatim (inside modules and at
    /// the top level; the boundary exports count as glue).
    pub reexports: usize,
    /// Public items of the source that the generated crate does not have
    /// and why (not failures: re-exports whose target is not emitted).
    pub api_differences: Vec<String>,
    /// The value of the printed `SANDBLASTER_SPEC_ROOT` (the last top-level
    /// item, compared token for token with its template; the driver checks
    /// the value against the lock, DESIGN.md §15.6).
    pub spec_root: Option<[u8; 32]>,
    pub failures: Vec<String>,
    pub millis: u128,
}

fn toks(t: &impl ToTokens) -> String {
    t.to_token_stream().to_string()
}

/// Token text of a source snippet parsed as a file (for template
/// comparison).
fn file_toks(src: &str) -> Result<String, String> {
    let f = syn::parse_file(src).map_err(|e| format!("template does not parse: {e}"))?;
    Ok(toks(&f))
}

/// The token text of a printed lane kernel (plan O10) that its evidence
/// record names: the item without its doc comments and visibility (neither
/// changes the code rustc generates; ordinary comments are not tokens).
pub fn lane_item_tokens(f: &syn::ItemFn) -> String {
    let mut f = f.clone();
    f.attrs.retain(|a| !a.path().is_ident("doc"));
    f.vis = syn::Visibility::Inherited;
    toks(&f)
}

/// [`lane_item_tokens`] of the printed function `src`.
pub fn lane_kernel_tokens(src: &str) -> Result<String, String> {
    let f: syn::ItemFn = syn::parse_str(src).map_err(|e| format!("the printed lane kernel does not parse: {e}"))?;
    Ok(lane_item_tokens(&f))
}

/// [`file_toks`] for the lane kernels' fingerprint (`opt::par`).
pub(crate) fn template_tokens(src: &str) -> Result<String, String> {
    file_toks(src)
}

/// The printed function `path` (`crate::m::f`) inside `mod __sandblaster`.
fn printed_fn<'a>(content: &'a [syn::Item], path: &str) -> Option<&'a syn::ItemFn> {
    let segs: Vec<&str> = path.split("::").skip(1).collect();
    let (name, mods) = segs.split_last()?;
    let mut items = content;
    for m in mods {
        items = items.iter().find_map(|it| match it {
            syn::Item::Mod(x) if x.ident == m => x.content.as_ref().map(|(_, c)| c.as_slice()),
            _ => None,
        })?;
    }
    items.iter().find_map(|it| match it {
        syn::Item::Fn(f) if f.sig.ident == name => Some(f),
        _ => None,
    })
}

/// Every printed lane kernel must be, token for token, the text its
/// evidence record was computed from (`opt::par::lane_fingerprint`): its
/// host run covers only that code (plan O10, §9.2).
fn lane_kernel_failures(content: &[syn::Item], o: &Optimized) -> Vec<String> {
    let mut failures = Vec::new();
    for l in &o.lanes {
        let Some(f) = printed_fn(content, &l.kernel) else { continue };
        let got = hex_sha256(&lane_item_tokens(f));
        if l.kernel_tokens.is_empty() || got != l.kernel_tokens {
            failures.push(format!(
                "lane kernel `{}` is printed differently from the text its evidence record `{}` names (tokens sha256 {} printed, {} named): a host run of the named kernel says nothing about the emitted one",
                l.kernel,
                l.lane_set,
                &got[..16],
                if l.kernel_tokens.is_empty() { "none" } else { &l.kernel_tokens[..16] }
            ));
        }
    }
    failures
}

/// The round trip's lane-kernel check alone ([`check`] runs it) on the
/// printed `code`: the failures, one per printed lane kernel whose tokens
/// are not the ones its evidence record names.
pub fn lane_kernel_check(code: &str, o: &Optimized) -> Result<Vec<String>, String> {
    let file = syn::parse_file(code).map_err(|e| format!("round trip: the generated file does not parse: {e}"))?;
    match file.items.get(1) {
        Some(syn::Item::Mod(m)) if m.ident == "__sandblaster" => Ok(m.content.as_ref().map(|(_, c)| lane_kernel_failures(c, o)).unwrap_or_default()),
        _ => Err("round trip: `mod __sandblaster` expected after the guard".into()),
    }
}

fn hex_sha256(s: &str) -> String {
    sandblaster_targets::fips::hex(&sandblaster_targets::fips::sha256(s.as_bytes()))
}

/// Runs the round trip (see the module docs) on the printed `code`;
/// `reexports` are the source's re-exports outside the boundary
/// ([`crate::canon::source_reexports`], `driver::Checked::reexports`).
pub fn check(code: &str, o: &Optimized, out: &mut Output, sm: &SourceMap, reexports: &[crate::canon::ReExport]) -> Result<Stats, String> {
    let t0 = Instant::now();
    let mut st = Stats::default();
    let file = syn::parse_file(code).map_err(|e| format!("round trip: the generated file does not parse: {e}"))?;
    let pv = &o.print;
    let mut lk = pv.clone();
    // every identifier compares as rustc compares it (ASCII, never raw)
    st.failures.extend(identifier_failures(&file));
    // the module scopes of the printed text, read back independently of the
    // printer (items, `use` bindings): names bound twice in a namespace (the
    // top level included), and the shadowing check
    let scopes = match file.items.get(1) {
        Some(syn::Item::Mod(m)) if m.ident == "__sandblaster" => match &m.content {
            Some((_, content)) => {
                let mut ps = read_scopes(content, &pv.target.arch);
                st.failures.append(&mut ps.duplicates);
                st.failures.extend(top_level_duplicates(&file.items, &ps, &pv.target.arch));
                st.failures.extend(shadow_failures(content, &ps.mods));
                ps
            }
            None => PrintedScopes::default(),
        },
        _ => PrintedScopes::default(),
    };
    let mut lw = Lower::new(pv, reexports, &o.dispatchers, scopes);
    let mut lowered: Vec<ItemId> = Vec::new();

    // ---- re-exports the generated crate cannot have, or has not ----
    for r in reexports {
        let site = crate::canon::reexport_site(pv, r);
        match crate::canon::reexport_target(pv, r) {
            Err(why) => st.failures.push(format!("public API: the source re-exports `{site}`, which the generated crate cannot have: {why}")),
            Ok(target) if crate::canon::reexport_text(pv, &o.dispatchers, &lw.exported_mods, r, 0).is_none() => {
                st.api_differences.push(format!("`{site}` (a `pub use` of the source) is not emitted: its target `{target}` is not emitted"));
            }
            Ok(_) => {}
        }
    }

    // ---- top level: guard, `mod __sandblaster`, exports ----
    let mut items = file.items.iter();
    let guard = items.next().ok_or("round trip: empty file")?;
    if toks(guard) != file_toks(crate::canon::GUARD_ITEM)? {
        st.failures.push("the 64-bit guard differs from the template".into());
    }
    st.glue += 1;
    let Some(syn::Item::Mod(m)) = items.next() else { return Err("round trip: `mod __sandblaster` expected after the guard".into()) };
    if m.ident != "__sandblaster" || m.content.is_none() {
        return Err("round trip: `mod __sandblaster { .. }` expected".into());
    }
    let attrs: String = m.attrs.iter().map(toks).collect::<Vec<_>>().join(" ");
    let want = file_toks(&format!("{}\nmod x {{}}", crate::canon::MOD_ATTRS))?;
    let want = want.trim_end_matches("mod x { }").trim().to_string();
    if attrs != want {
        st.failures.push("the attributes of `mod __sandblaster` differ from the template".into());
    }
    // the checked-arithmetic glue module, right after `mod __sandblaster`
    // (compared after the lowering, with the helpers the code calls)
    let mut rest: Vec<&syn::Item> = items.collect();
    let rt = match rest.first() {
        Some(syn::Item::Mod(r)) if r.ident == "__rt" => Some(rest.remove(0)),
        _ => None,
    };
    // the `SANDBLASTER_SPEC_ROOT` glue item, last (DESIGN.md §15.6)
    match rest.last() {
        Some(syn::Item::Const(c)) if c.ident == crate::canon::SPEC_ROOT_NAME => {
            let item = rest.pop().unwrap();
            let bytes: Option<Vec<u8>> = match &*c.expr {
                syn::Expr::Array(a) => a
                    .elems
                    .iter()
                    .map(|e| match e {
                        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) if i.suffix() == "u8" => i.base10_parse::<u8>().ok(),
                        _ => None,
                    })
                    .collect(),
                _ => None,
            };
            match bytes.and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(root) if toks(item) == file_toks(&crate::canon::spec_root_item(&root))? => {
                    st.spec_root = Some(root);
                    st.glue += 1;
                }
                _ => st.failures.push(format!("the `{}` item differs from its template", crate::canon::SPEC_ROOT_NAME)),
            }
        }
        _ => st.failures.push(format!("the generated crate does not end with `pub const {}` (DESIGN.md §15.6)", crate::canon::SPEC_ROOT_NAME)),
    }
    let exports: Vec<String> = rest.into_iter().map(toks).collect();
    let want_exports: Vec<String> = crate::canon::export_lines(pv, &o.dispatchers, reexports).iter().map(|l| file_toks(l)).collect::<Result<_, _>>()?;
    if exports != want_exports {
        st.failures.push(format!("the exports differ from the boundary and the root's re-exports: printed {exports:?}, expected {want_exports:?}"));
    } else {
        st.reexports += reexports.iter().filter(|r| r.module == pv.root && crate::canon::reexport_text(pv, &o.dispatchers, &lw.exported_mods, r, 0).is_some()).count();
    }
    st.glue += 1;

    // ---- the module tree ----
    let content = &m.content.as_ref().unwrap().1;
    // ---- lane kernels: the printed text is the one their evidence names ----
    st.failures.extend(lane_kernel_failures(content, o));
    lw.module(pv.root, content, &mut lk, &mut lowered, o, sm, &mut st, true);

    // ---- the checked-arithmetic helpers (E0): exactly the template of
    // the helpers the lowered code calls ----
    match rt {
        None if !lw.chk.is_empty() => st.failures.push(format!("the code calls the checked-arithmetic helpers {}, but the glue module `__rt` is not printed", chk_list(&lw.chk))),
        None => {}
        // a lowering failure (reported below) may have left helpers
        // unrecorded: the comparison would only repeat it
        Some(_) if !lw.failures.is_empty() => {}
        Some(_) if lw.chk.is_empty() => st.failures.push("the glue module `__rt` is printed, but the code calls no checked-arithmetic helper".into()),
        Some(r) => {
            if toks(r) == file_toks(&crate::canon::rt_module(&lw.chk))? {
                st.glue += 1;
            } else {
                st.failures.push(format!("the checked-arithmetic module `__rt` differs from its template (the helpers the code calls: {})", chk_list(&lw.chk)));
            }
        }
    }

    // ---- generated-mode elaboration ----
    let mut targets: HashMap<String, (GlobalId, GlobalId)> = HashMap::new();
    let mut expected_defs: Vec<(String, GlobalId)> = Vec::new();
    for id in &lowered {
        let Some((g, c)) = o.targets.get(id).copied() else {
            st.failures.push(format!("`{}` is printed but has no optimized definition", pv.item(*id).path));
            continue;
        };
        let name = pv.item(*id).path.to_string();
        targets.insert(name.clone(), (g, c));
        expected_defs.push((name.clone(), c));
        // loop helpers, matched by the deterministic names
        let cname = out.env.global_name(c).map(|s| s.to_string()).unwrap_or_default();
        for d in &out.defs {
            if let Some(g2) = d.global
                && let Some(k) = d.name.strip_prefix(&format!("{cname}::loop#"))
            {
                let n = format!("{name}::loop#{k}");
                targets.insert(n.clone(), (g2, g2));
                expected_defs.push((n, g2));
            }
        }
    }
    let (defs, errors) = crate::elab::generated::generated(out, &lk, &lowered, targets).map_err(|e| format!("round trip: generated-mode elaboration: {e}"))?;
    for (id, e) in errors {
        let what = if id.0 == u32::MAX { String::new() } else { format!("`{}`: ", pv.item(id).path) };
        st.failures.push(format!("generated-mode elaboration: {what}{e}"));
    }
    // ---- comparison ----
    let got: HashMap<String, &crate::elab::generated::GenDef> = defs.iter().map(|d| (d.name.clone(), d)).collect();
    for (name, c) in &expected_defs {
        let Some(d) = got.get(name) else {
            st.failures.push(format!("`{name}`: the printed code does not define it"));
            continue;
        };
        match compare(out, d, *c) {
            Ok(()) => st.compared += 1,
            Err(e) => st.failures.push(format!("`{name}` does not match its optimized core: {e}")),
        }
    }
    let known: HashSet<&String> = expected_defs.iter().map(|(n, _)| n).collect();
    for d in &defs {
        if !known.contains(&d.name) && d.kind != sandblaster_kernel::term::DefKind::Ensures {
            st.failures.push(format!("the printed code defines `{}`, which the optimized core does not have", d.name));
        }
    }
    // ---- skeletons ----
    for id in &lowered {
        if let (Some(a), Some(b)) = (lk.fn_def(*id), pv.fn_def(*id)) {
            let (sa, sb) = (skeleton_fn(a), skeleton_fn(b));
            if sa != sb {
                st.failures.push(format!("`{}`: the binding/scope skeleton differs:\n  printed:    {sa}\n  print view: {sb}", pv.item(*id).path));
            }
            st.skeletons += 1;
        }
    }
    st.reexports += lw.reexports_compared;
    st.failures.extend(lw.failures);
    st.millis = t0.elapsed().as_millis();
    Ok(st)
}

/// `add_u64, shr_u32` (for failure messages).
fn chk_list(hs: &std::collections::BTreeSet<ChkHelper>) -> String {
    hs.iter().map(|h| format!("`{}`", h.name())).collect::<Vec<_>>().join(", ")
}

/// Compares a generated-mode definition with the optimized core
/// definition `c` (see the module docs).
pub(crate) fn compare(out: &Output, d: &crate::elab::generated::GenDef, c: GlobalId) -> Result<(), String> {
    compare_with(out, d, c, &|t| t.clone())
}

/// [`compare`] after applying `norm` to both stripped bodies (the lifted
/// round trip's `let x = v; x` ≡ `v`, `driver::lowered`).
pub(crate) fn compare_with(out: &Output, d: &crate::elab::generated::GenDef, c: GlobalId, norm: &dyn Fn(&Tm) -> Tm) -> Result<(), String> {
    let env = &out.env;
    let rels = env.global_param_rels(c).ok_or("no parameter list")?;
    let body = replace_rec(&d.body, c, &rels);
    let cb = env.global_body(c).ok_or("no body")?;
    let ct = env.global_type(c).ok_or("no type")?;
    let id = |a: GlobalId, b: GlobalId| a == b;
    let (ta, tb) = (strip(&d.ty), strip(&ct));
    if !env.alpha_eq_relevant(&ta, &tb, &id) {
        return Err("the types differ".into());
    }
    let (ba, bb) = (norm(&strip(&body)), norm(&strip(&cb)));
    if !env.alpha_eq_relevant(&ba, &bb, &id) {
        return Err(first_difference(env, &ba, &bb));
    }
    Ok(())
}

/// `Rec(args)` → `g args` (the kernel's commit step, relevances from the
/// telescope).
fn replace_rec(t: &Tm, g: GlobalId, rels: &[Rel]) -> Tm {
    crate::elab::tm::map_post(t, 0, &mut |n, _| match &*n {
        Term::Rec { args, .. } => Some(sandblaster_kernel::util::mk::apps(sandblaster_kernel::util::mk::global(g), args.iter().enumerate().map(|(i, a)| (rels.get(i).copied().unwrap_or(Rel::Rel), a.clone())))),
        _ => Some(n),
    })
    .unwrap_or_else(|| t.clone())
}

/// Erases every irrelevant binder and application (see the module docs):
/// irrelevant `λ`, `let`, `Π` binders disappear (their variables occur only
/// in irrelevant positions, which become `Erased`), irrelevant applications
/// are dropped, and every other irrelevant position (proof slots, `Rec`
/// proofs, transport equations, absurd proofs) is `Erased`.
pub fn strip(t: &Tm) -> Tm {
    // `map[k]` = new index of the variable bound `k` binders up, or None
    fn go(t: &Tm, map: &mut Vec<Option<u32>>, memo: &mut HashMap<(*const Term, usize), Tm>) -> Tm {
        let key = (Rc::as_ptr(t), map.len());
        if map.is_empty()
            && let Some(r) = memo.get(&key)
        {
            return r.clone();
        }
        let erased = || Rc::new(Term::Erased);
        let r: Tm = match &**t {
            Term::Var(i) => {
                let k = i.0 as usize;
                match map.len().checked_sub(k + 1).and_then(|p| map.get(p).copied()) {
                    Some(Some(_)) => {
                        // new index: relevant binders between here and it
                        let n = map[map.len() - k..].iter().filter(|x| x.is_some()).count();
                        Rc::new(Term::Var(sandblaster_kernel::term::Idx(n as u32)))
                    }
                    Some(None) => erased(),
                    None => t.clone(), // free (never happens in closed definitions)
                }
            }
            Term::Pi { name, rel, dom, cod } | Term::Lam { name, rel, dom, body: cod } => {
                let is_pi = matches!(&**t, Term::Pi { .. });
                if *rel == Rel::Irr {
                    map.push(None);
                    let c = go(cod, map, memo);
                    map.pop();
                    c
                } else {
                    let d = go(dom, map, memo);
                    map.push(Some(0));
                    let c = go(cod, map, memo);
                    map.pop();
                    if is_pi { Rc::new(Term::Pi { name: name.clone(), rel: *rel, dom: d, cod: c }) } else { Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: d, body: c }) }
                }
            }
            Term::Let { name, rel, ty, val, body } => {
                if *rel == Rel::Irr {
                    map.push(None);
                    let b = go(body, map, memo);
                    map.pop();
                    b
                } else {
                    let (ty2, val2) = (go(ty, map, memo), go(val, map, memo));
                    map.push(Some(0));
                    let b = go(body, map, memo);
                    map.pop();
                    Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty2, val: val2, body: b })
                }
            }
            Term::App { rel: Rel::Irr, fun, .. } => go(fun, map, memo),
            Term::App { rel, fun, arg } => Rc::new(Term::App { rel: *rel, fun: go(fun, map, memo), arg: go(arg, map, memo) }),
            Term::Sigma { name, snd_rel, fst, snd } => {
                let f = go(fst, map, memo);
                map.push(Some(0));
                let s = go(snd, map, memo);
                map.pop();
                Rc::new(Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: f, snd: s })
            }
            Term::Pair { ty, fst, snd } => {
                let irr = matches!(&**ty, Term::Sigma { snd_rel: Rel::Irr, .. });
                Rc::new(Term::Pair { ty: go(ty, map, memo), fst: go(fst, map, memo), snd: if irr { erased() } else { go(snd, map, memo) } })
            }
            Term::Fst(p) => Rc::new(Term::Fst(go(p, map, memo))),
            Term::Snd(p) => Rc::new(Term::Snd(go(p, map, memo))),
            Term::Eq { ty, lhs, rhs } => Rc::new(Term::Eq { ty: go(ty, map, memo), lhs: go(lhs, map, memo), rhs: go(rhs, map, memo) }),
            Term::Refl { ty, val } => Rc::new(Term::Refl { ty: go(ty, map, memo), val: go(val, map, memo) }),
            Term::Transport { ty, lhs, rhs, motive, val, .. } => {
                let (a, l, r) = (go(ty, map, memo), go(lhs, map, memo), go(rhs, map, memo));
                map.push(Some(0));
                let m = go(motive, map, memo);
                map.pop();
                Rc::new(Term::Transport { ty: a, lhs: l, rhs: r, eq: erased(), motive: m, val: go(val, map, memo) })
            }
            Term::Ind { ind, params } => Rc::new(Term::Ind { ind: *ind, params: params.iter().map(|p| go(p, map, memo)).collect() }),
            Term::Ctor { ind, ctor, params, args } => Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|p| go(p, map, memo)).collect(), args: args.iter().map(|a| go(a, map, memo)).collect() }),
            Term::Match { ind, params, scrut, motive, arms } => {
                let ps: Vec<Tm> = params.iter().map(|p| go(p, map, memo)).collect();
                let s = go(scrut, map, memo);
                map.push(Some(0));
                let m = go(motive, map, memo);
                map.pop();
                let arms2 = arms
                    .iter()
                    .map(|a| {
                        for _ in 0..a.names.len() {
                            map.push(Some(0));
                        }
                        let b = go(&a.body, map, memo);
                        for _ in 0..a.names.len() {
                            map.pop();
                        }
                        sandblaster_kernel::term::Arm { names: a.names.clone(), body: b }
                    })
                    .collect();
                Rc::new(Term::Match { ind: *ind, params: ps, scrut: s, motive: m, arms: arms2 })
            }
            Term::Prim { op, args, proofs } => Rc::new(Term::Prim { op: *op, args: args.iter().map(|a| go(a, map, memo)).collect(), proofs: proofs.iter().map(|_| erased()).collect() }),
            Term::Rec { args, proof } => Rc::new(Term::Rec { args: args.iter().map(|a| go(a, map, memo)).collect(), proof: proof.as_ref().map(|_| erased()) }),
            Term::Absurd { ty, .. } => Rc::new(Term::Absurd { ty: go(ty, map, memo), proof: erased() }),
            // proof terms: their content is irrelevant
            Term::Delta { .. } | Term::Unfold { .. } | Term::Linarith { .. } | Term::BvRefl { .. } | Term::Axiom { .. } => erased(),
            Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => t.clone(),
        };
        if map.is_empty() {
            memo.insert(key, r.clone());
        }
        r
    }
    let mut memo = HashMap::new();
    go(t, &mut Vec::new(), &mut memo)
}

/// A description of where two stripped terms first differ (diagnostics).
fn first_difference(env: &sandblaster_kernel::api::Env, a: &Tm, b: &Tm) -> String {
    let pa = sandblaster_kernel::syntax::printer::print_term_bounded(env, &[], a, 4000);
    let pb = sandblaster_kernel::syntax::printer::print_term_bounded(env, &[], b, 4000);
    let n = pa.chars().zip(pb.chars()).take_while(|(x, y)| x == y).count();
    let ctx = |s: &str| s.chars().skip(n.saturating_sub(120)).take(300).collect::<String>();
    format!("relevant structure differs\n    printed:   …{}\n    optimized: …{}", ctx(&pa), ctx(&pb))
}

// ---------------------------------------------------------------------------
// skeletons
// ---------------------------------------------------------------------------

/// The binding/scope skeleton of a function body (DESIGN.md §8.3, §13.1).
pub fn skeleton_fn(f: &FnDef) -> String {
    let mut s = String::new();
    for p in &f.params {
        skel_pat(&p.pat, f, &mut s);
    }
    s.push('|');
    if let FnBody::Exec(b) = &f.body {
        skel_expr(b, f, &mut s);
    }
    s
}

fn skel_pat(p: &Pat, f: &FnDef, s: &mut String) {
    for l in p.bindings() {
        let m = if f.locals.get(l.0 as usize).is_some_and(|d| d.mutable) { "mut " } else { "" };
        s.push_str(&format!("b({m}{})", l.0));
    }
}

fn skel_block(b: &Block, f: &FnDef, s: &mut String) {
    s.push('{');
    for st in &b.stmts {
        match &st.kind {
            StmtKind::Let { pat, init, els } => {
                skel_expr(init, f, s);
                s.push_str("let");
                skel_pat(pat, f, s);
                if let Some(e) = els {
                    s.push_str("else");
                    skel_block(e, f, s);
                }
                s.push(';');
            }
            StmtKind::Expr(e) => {
                skel_expr(e, f, s);
                s.push(';');
            }
            StmtKind::Assign { place, value } => {
                skel_expr(value, f, s);
                s.push_str(&format!("set({});", place.local.0));
            }
            StmtKind::CompoundAssign { place, value, .. } => {
                skel_expr(value, f, s);
                s.push_str(&format!("op=({});", place.local.0));
            }
            StmtKind::CopyFromSlice { dst, src, .. } => {
                skel_expr(src, f, s);
                s.push_str(&format!("copy({});", dst.0));
            }
            StmtKind::Proof(_) => {}
        }
    }
    if let Some(t) = &b.tail {
        skel_expr(t, f, s);
    }
    s.push('}');
}

fn skel_expr(e: &Expr, f: &FnDef, s: &mut String) {
    match &e.kind {
        ExprKind::Block(b) => skel_block(b, f, s),
        ExprKind::If { cond, then, els } => {
            skel_expr(cond, f, s);
            s.push_str("if");
            skel_expr(then, f, s);
            if let Some(x) = els {
                s.push_str("else");
                skel_expr(x, f, s);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            skel_expr(scrut, f, s);
            s.push_str("match[");
            // or-patterns are printed expanded (the normative expansion)
            for a in &crate::canon::expand_or_arms(arms) {
                s.push_str("arm");
                skel_pat(&a.pat, f, s);
                skel_expr(&a.body, f, s);
            }
            s.push(']');
        }
        ExprKind::Loop(l) => {
            s.push_str("loop");
            if let LoopKind::ForRange { var: Some(v), .. } = &l.kind {
                s.push_str(&format!("({})", v.0));
            }
            skel_block(&l.body, f, s);
        }
        _ => {
            // sub-blocks inside expressions
            struct V<'s, 'f>(&'s mut String, &'f FnDef);
            impl crate::visit::Visitor for V<'_, '_> {
                fn expr(&mut self, e: &Expr) {
                    match &e.kind {
                        ExprKind::Block(_) | ExprKind::If { .. } | ExprKind::Match { .. } | ExprKind::Loop(_) => skel_expr(e, self.1, self.0),
                        _ => crate::visit::walk_expr(self, e),
                    }
                }
            }
            crate::visit::walk_expr(&mut V(s, f), e);
        }
    }
}

// ---------------------------------------------------------------------------
// name resolution of the printed text (independent of the printer)
// ---------------------------------------------------------------------------

/// What a name denotes in the value namespace of a printed module, as rustc
/// resolves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ValueDef {
    /// A `const`: an identifier pattern naming it is a constant pattern.
    Const,
    /// A `static` (an identifier pattern naming it is an error).
    Static,
    /// A unit struct or unit variant: an identifier pattern naming it is a
    /// constructor pattern.
    UnitCtor,
    /// A tuple struct or tuple variant constructor (an error in patterns).
    TupleCtor,
    /// A function: a binding of the same name shadows it.
    Fn,
    /// Something this reader does not classify (conservatively a capture).
    Unknown,
}

impl ValueDef {
    /// Whether an identifier pattern naming this is not a fresh binding.
    fn captures_patterns(self) -> bool {
        !matches!(self, ValueDef::Fn)
    }

    fn pattern_reading(self) -> &'static str {
        match self {
            ValueDef::Const => "a constant pattern",
            ValueDef::UnitCtor => "a unit constructor pattern",
            ValueDef::Static | ValueDef::TupleCtor => "an error (bindings cannot shadow statics and tuple constructors)",
            ValueDef::Fn | ValueDef::Unknown => "a pattern of an unresolved definition",
        }
    }

    fn what(self) -> &'static str {
        match self {
            ValueDef::Const => "the constant",
            ValueDef::Static => "the static",
            ValueDef::UnitCtor => "the unit constructor",
            ValueDef::TupleCtor => "the tuple constructor",
            ValueDef::Fn => "the function",
            ValueDef::Unknown => "the definition",
        }
    }
}

/// rustc's std/core prelude (editions 2021 and 2024), value namespace:
/// names in scope in every module that does not declare them. (The
/// reader's own table, deliberately independent of the printer's
/// `canon::PRELUDE_NAMES`.)
const PRELUDE_VALUES: &[(&str, ValueDef)] = &[
    ("None", ValueDef::UnitCtor),
    ("Some", ValueDef::TupleCtor),
    ("Ok", ValueDef::TupleCtor),
    ("Err", ValueDef::TupleCtor),
    ("drop", ValueDef::Fn),
    ("size_of", ValueDef::Fn),
    ("size_of_val", ValueDef::Fn),
    ("align_of", ValueDef::Fn),
    ("align_of_val", ValueDef::Fn),
];

/// rustc's std/core prelude, type namespace, and the extern prelude crates
/// (`core`, `std`, `alloc`).
const PRELUDE_TYPES: &[&str] = &[
    "Option", "Result", "Vec", "String", "Box", "ToOwned", "ToString", "Clone", "Copy", "Send", "Sized", "Sync", "Unpin", "Drop", "Fn", "FnMut", "FnOnce", "AsyncFn", "AsyncFnMut", "AsyncFnOnce", "AsRef", "AsMut", "Into", "From", "Default", "Iterator", "Extend", "IntoIterator", "DoubleEndedIterator", "ExactSizeIterator", "Eq", "PartialEq", "Ord", "PartialOrd", "TryFrom", "TryInto", "FromIterator", "Future", "IntoFuture", "core", "std", "alloc",
];

/// The primitive types the canonical dialect writes unqualified.
const DIALECT_PRIMITIVES: &[&str] = &["bool", "i32", "u8", "u16", "u32", "u64", "u128", "usize"];

/// A printed module's scope as rustc sees it: the names its items and
/// `use` declarations bind, per namespace, with a description.
#[derive(Clone, Debug, Default)]
struct ModScope {
    values: HashMap<String, (ValueDef, String)>,
    types: HashMap<String, String>,
    /// A glob import or a macro item (never printed): any name may be bound.
    glob: bool,
}

impl ModScope {
    /// Binds `name` in the value namespace; a second binding of the name is
    /// a duplicate (rustc E0428/E0255/E0252: the first is kept, the failure
    /// recorded in `dups`).
    fn bind_value(&mut self, name: &str, d: ValueDef, how: String, here: &str, dups: &mut Vec<String>) {
        match self.values.get(name) {
            Some((_, prev)) => dups.push(format!("{here}: `{name}` is defined twice in the value namespace: {prev} and {how} (rustc E0428/E0255/E0252)")),
            None => {
                self.values.insert(name.to_string(), (d, how));
            }
        }
    }

    /// Binds `name` in the type namespace (duplicates as in
    /// [`ModScope::bind_value`]).
    fn bind_type(&mut self, name: &str, how: String, here: &str, dups: &mut Vec<String>) {
        match self.types.get(name) {
            Some(prev) => dups.push(format!("{here}: `{name}` is defined twice in the type namespace: {prev} and {how} (rustc E0428/E0255/E0252)")),
            None => {
                self.types.insert(name.to_string(), how);
            }
        }
    }

    /// Binds what a resolved `use` names ([`Resolved`]); an unresolved one
    /// binds "unknown" in both namespaces.
    fn bind_use(&mut self, name: &str, r: Option<Resolved>, unresolved: impl FnOnce() -> String, here: &str, dups: &mut Vec<String>) {
        match r {
            Some((v, t)) => {
                if let Some((d, how)) = v {
                    self.bind_value(name, d, how, here, dups);
                }
                if let Some(how) = t {
                    self.bind_type(name, how, here, dups);
                }
            }
            None => {
                let how = unresolved();
                self.bind_value(name, ValueDef::Unknown, how.clone(), here, dups);
                self.bind_type(name, how, here, dups);
            }
        }
    }

    /// What `name` denotes in the value namespace: the module's own names,
    /// then the prelude.
    fn value(&self, name: &str) -> Option<(ValueDef, String)> {
        if let Some((d, how)) = self.values.get(name) {
            return Some((*d, how.clone()));
        }
        if self.glob {
            return Some((ValueDef::Unknown, format!("whatever a glob import or macro binds as `{name}`")));
        }
        PRELUDE_VALUES.iter().find(|(n, _)| *n == name).map(|(_, d)| (*d, format!("{} `{name}` of the prelude", d.what())))
    }

    /// What the module itself binds as `name` in the type namespace.
    fn ty(&self, name: &str) -> Option<String> {
        if let Some(how) = self.types.get(name) {
            return Some(how.clone());
        }
        self.glob.then(|| format!("whatever a glob import or macro binds as `{name}`"))
    }

    /// Any module-level or prelude name `name` (every namespace).
    fn any(&self, name: &str) -> Option<String> {
        if let Some((_, how)) = self.values.get(name) {
            return Some(how.clone());
        }
        if let Some(how) = self.ty(name) {
            return Some(how);
        }
        if let Some((_, how)) = self.value(name) {
            return Some(how);
        }
        PRELUDE_TYPES.contains(&name).then(|| format!("the prelude's `{name}`"))
    }
}

fn module_display(path: &[String]) -> String {
    if path.is_empty() { "crate::__sandblaster".into() } else { format!("crate::__sandblaster::{}", path.join("::")) }
}

/// A variant's shape (its constructor in the value namespace).
#[derive(Clone, Copy, PartialEq, Eq)]
enum VShape {
    Unit,
    Tuple,
    Named,
}

/// The variants of every printed enum, by (module path, enum name).
type Enums = HashMap<(Vec<String>, String), Vec<(String, VShape)>>;

/// One `use` binding: the module it is in, the path it names (`crate`,
/// `self`, `super` or an extern prelude crate first, or a `::` path) and the
/// name it binds.
struct UseBinding {
    module: Vec<String>,
    leading_colon: bool,
    path: Vec<String>,
    name: String,
}

/// What a `use` binding denotes: its value-namespace and type-namespace
/// meanings (either may be absent), with descriptions.
type Resolved = (Option<(ValueDef, String)>, Option<String>);

/// The module scopes of the printed text ([`read_scopes`]).
#[derive(Default)]
struct PrintedScopes {
    /// By module path under `__sandblaster` (the root is `[]`).
    mods: HashMap<Vec<String>, ModScope>,
    /// The variants of every printed enum.
    enums: Enums,
    /// Names bound twice in one namespace of one module (failures).
    duplicates: Vec<String>,
}

/// Flattens a `use` tree into `(path, bound name)` pairs (`None`: a glob;
/// `as _` binds nothing).
fn flatten_use(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Option<String>)>) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten_use(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let id = n.ident.to_string();
            if id == "self" {
                out.push((prefix.clone(), prefix.last().cloned()));
            } else {
                let mut p = prefix.clone();
                p.push(id.clone());
                out.push((p, Some(id)));
            }
        }
        syn::UseTree::Rename(r) => {
            let id = r.ident.to_string();
            let mut p = prefix.clone();
            if id != "self" {
                p.push(id);
            }
            let rename = r.rename.to_string();
            if rename != "_" {
                out.push((p, Some(rename)));
            }
        }
        syn::UseTree::Glob(_) => out.push((prefix.clone(), None)),
        syn::UseTree::Group(g) => g.items.iter().for_each(|t| flatten_use(t, prefix, out)),
    }
}

/// What the `use` binding `u` names, resolved against the printed modules
/// (`scopes`, `enums`) or, for paths outside the crate, classified; `None`
/// when the path does not resolve (yet: `use` chains resolve in rounds).
fn resolve_use(scopes: &HashMap<Vec<String>, ModScope>, enums: &Enums, arch: &crate::target::Arch, u: &UseBinding) -> Option<Resolved> {
    let mut segs: Vec<String> = u.path.clone();
    let shown = format!("{}{}", if u.leading_colon { "::" } else { "" }, segs.join("::"));
    // the module the path starts from
    let mut base: Vec<String> = if u.leading_colon {
        return Some(classify_external(&segs, arch, &shown));
    } else {
        match segs.first().map(String::as_str) {
            Some("crate") if segs.get(1).map(String::as_str) == Some("__sandblaster") => {
                segs.drain(..2);
                vec![]
            }
            Some("self") => {
                segs.remove(0);
                u.module.clone()
            }
            Some("super") => {
                let mut m = u.module.clone();
                while segs.first().map(String::as_str) == Some("super") {
                    segs.remove(0);
                    m.pop()?;
                }
                m
            }
            Some("core" | "std" | "alloc") if !scopes.get(&u.module).is_some_and(|s| s.types.contains_key(&segs[0])) => return Some(classify_external(&segs, arch, &shown)),
            // a relative path: through a child module of the use's module
            _ => u.module.clone(),
        }
    };
    let last = segs.pop()?;
    for (k, s) in segs.iter().enumerate() {
        let mut child = base.clone();
        child.push(s.clone());
        if scopes.contains_key(&child) {
            base = child;
            continue;
        }
        // `…::Enum::Variant`
        if k + 1 == segs.len()
            && let Some(vs) = enums.get(&(base.clone(), s.clone()))
        {
            let (_, shape) = vs.iter().find(|(v, _)| *v == last)?;
            let how = format!("the variant `{shown}`");
            let v = match shape {
                VShape::Unit => Some((ValueDef::UnitCtor, how.clone())),
                VShape::Tuple => Some((ValueDef::TupleCtor, how.clone())),
                VShape::Named => None,
            };
            return Some((v, Some(how)));
        }
        return None;
    }
    let sc = scopes.get(&base)?;
    let v = sc.values.get(&last).map(|(d, how)| (*d, format!("{how} (through `use {shown}`)")));
    let t = sc.types.get(&last).map(|how| format!("{how} (through `use {shown}`)"));
    if v.is_none() && t.is_none() {
        return None;
    }
    Some((v, t))
}

/// Reads the module scopes of the printed `mod __sandblaster { .. }` (its
/// `content`) the way rustc resolves them — every item and every `use`
/// binding (renames included, resolved against the printed text itself or,
/// for `::core` paths, classified) — without the print view, and records
/// every name bound twice in one namespace of a module.
fn read_scopes(content: &[syn::Item], arch: &crate::target::Arch) -> PrintedScopes {
    let mut scopes: HashMap<Vec<String>, ModScope> = HashMap::new();
    let mut enums: Enums = HashMap::new();
    let mut uses: Vec<UseBinding> = Vec::new();
    let mut dups: Vec<String> = Vec::new();
    fn walk(items: &[syn::Item], path: Vec<String>, scopes: &mut HashMap<Vec<String>, ModScope>, enums: &mut Enums, uses: &mut Vec<UseBinding>, dups: &mut Vec<String>) {
        let mut sc = ModScope::default();
        let here = module_display(&path);
        let at = format!("`{here}`");
        for it in items {
            match it {
                syn::Item::Const(c) => sc.bind_value(&c.ident.to_string(), ValueDef::Const, format!("the constant `{here}::{}`", c.ident), &at, dups),
                syn::Item::Static(s) => sc.bind_value(&s.ident.to_string(), ValueDef::Static, format!("the static `{here}::{}`", s.ident), &at, dups),
                syn::Item::Fn(f) => sc.bind_value(&f.sig.ident.to_string(), ValueDef::Fn, format!("the function `{here}::{}`", f.sig.ident), &at, dups),
                syn::Item::Struct(s) => {
                    let n = s.ident.to_string();
                    sc.bind_type(&n, format!("the struct `{here}::{n}`"), &at, dups);
                    match &s.fields {
                        syn::Fields::Unit => sc.bind_value(&n, ValueDef::UnitCtor, format!("the unit struct `{here}::{n}`"), &at, dups),
                        syn::Fields::Unnamed(_) => sc.bind_value(&n, ValueDef::TupleCtor, format!("the tuple struct `{here}::{n}`"), &at, dups),
                        syn::Fields::Named(_) => {}
                    }
                }
                syn::Item::Enum(e) => {
                    let n = e.ident.to_string();
                    sc.bind_type(&n, format!("the enum `{here}::{n}`"), &at, dups);
                    let vs = e
                        .variants
                        .iter()
                        .map(|v| {
                            let shape = match &v.fields {
                                syn::Fields::Unit => VShape::Unit,
                                syn::Fields::Unnamed(_) => VShape::Tuple,
                                syn::Fields::Named(_) => VShape::Named,
                            };
                            (v.ident.to_string(), shape)
                        })
                        .collect();
                    enums.insert((path.clone(), n), vs);
                }
                syn::Item::Union(u) => sc.bind_type(&u.ident.to_string(), format!("the union `{here}::{}`", u.ident), &at, dups),
                syn::Item::Type(t) => sc.bind_type(&t.ident.to_string(), format!("the type alias `{here}::{}`", t.ident), &at, dups),
                syn::Item::Trait(t) => sc.bind_type(&t.ident.to_string(), format!("the trait `{here}::{}`", t.ident), &at, dups),
                syn::Item::TraitAlias(t) => sc.bind_type(&t.ident.to_string(), format!("the trait alias `{here}::{}`", t.ident), &at, dups),
                syn::Item::ExternCrate(x) => {
                    let n = x.rename.as_ref().map(|(_, r)| r.to_string()).unwrap_or_else(|| x.ident.to_string());
                    sc.bind_type(&n, format!("the extern crate `{n}`"), &at, dups);
                }
                syn::Item::Mod(m) => {
                    let n = m.ident.to_string();
                    sc.bind_type(&n, format!("the module `{here}::{n}`"), &at, dups);
                    if let Some((_, inner)) = &m.content {
                        let mut p = path.clone();
                        p.push(n);
                        walk(inner, p, scopes, enums, uses, dups);
                    }
                }
                syn::Item::Use(u) => {
                    let mut out = Vec::new();
                    flatten_use(&u.tree, &mut Vec::new(), &mut out);
                    for (p, name) in out {
                        match name {
                            Some(name) => uses.push(UseBinding { module: path.clone(), leading_colon: u.leading_colon.is_some(), path: p, name }),
                            None => sc.glob = true,
                        }
                    }
                }
                syn::Item::Impl(_) => {}
                // macro invocations, foreign blocks, verbatim tokens: may bind anything
                _ => sc.glob = true,
            }
        }
        scopes.insert(path, sc);
    }
    walk(content, vec![], &mut scopes, &mut enums, &mut uses, &mut dups);

    // resolve the `use` bindings (chains through other `use`s: repeat while
    // something new resolves; what never resolves binds "unknown" in both
    // namespaces)
    let mut pending: Vec<usize> = (0..uses.len()).collect();
    loop {
        let before = pending.len();
        pending.retain(|&i| {
            let u = &uses[i];
            match resolve_use(&scopes, &enums, arch, u) {
                Some(r) => {
                    let here = format!("`{}`", module_display(&u.module));
                    scopes.entry(u.module.clone()).or_default().bind_use(&u.name, Some(r), String::new, &here, &mut dups);
                    false
                }
                None => true,
            }
        });
        if pending.is_empty() || pending.len() == before {
            break;
        }
    }
    for i in pending {
        let u = &uses[i];
        let how = format!("the unresolved `use {}{}` as `{}`", if u.leading_colon { "::" } else { "" }, u.path.join("::"), u.name);
        let here = format!("`{}`", module_display(&u.module));
        scopes.entry(u.module.clone()).or_default().bind_use(&u.name, None, || how, &here, &mut dups);
    }
    PrintedScopes { mods: scopes, enums, duplicates: dups }
}

/// Names bound twice in one namespace at the top level of the printed file
/// (`items`: the guard, `mod __sandblaster`, the `pub use` exports), each
/// export resolved against the printed modules (`__sandblaster::…` paths) or
/// classified (`::core` paths): e.g. a root item named `__sandblaster`
/// exported beside the module (rustc E0255).
fn top_level_duplicates(items: &[syn::Item], ps: &PrintedScopes, arch: &crate::target::Arch) -> Vec<String> {
    let here = "the top level of the generated file";
    let mut sc = ModScope::default();
    let mut dups = Vec::new();
    for it in items {
        match it {
            syn::Item::Mod(m) => sc.bind_type(&m.ident.to_string(), format!("the module `{}`", m.ident), here, &mut dups),
            syn::Item::Use(u) => {
                let mut out = Vec::new();
                flatten_use(&u.tree, &mut Vec::new(), &mut out);
                for (p, name) in out {
                    let Some(name) = name else {
                        dups.push(format!("{here}: a glob import (not in the canonical dialect)"));
                        continue;
                    };
                    let shown = format!("{}{}", if u.leading_colon.is_some() { "::" } else { "" }, p.join("::"));
                    let r = if u.leading_colon.is_some() {
                        Some(classify_external(&p, arch, &shown))
                    } else if p.first().map(String::as_str) == Some("__sandblaster") {
                        // `__sandblaster::…` from the crate root (the file is
                        // `include!`d there): `crate::__sandblaster::…`
                        let mut path = vec!["crate".to_string()];
                        path.extend(p.iter().cloned());
                        resolve_use(&ps.mods, &ps.enums, arch, &UseBinding { module: vec![], leading_colon: false, path, name: name.clone() })
                    } else {
                        None
                    };
                    sc.bind_use(&name, r, || format!("the unresolved `use {shown}` as `{name}`"), here, &mut dups);
                }
            }
            _ => {}
        }
    }
    dups
}

/// The identifiers of the printed text compare as rustc compares them: the
/// canonical dialect's identifiers are ASCII (rustc NFC-normalizes
/// identifiers; every ASCII string is its own NFC form), never raw (rustc
/// reads `r#x` as `x`) and never a keyword of some edition that `syn`
/// accepts (`gen`, Rust 2024) — so the reader's spelling comparisons (scopes,
/// bindings, paths) are rustc's identifier equality. One failure per
/// offending identifier.
fn identifier_failures(file: &syn::File) -> Vec<String> {
    fn walk(ts: proc_macro2::TokenStream, seen: &mut HashSet<String>, out: &mut Vec<String>) {
        for tt in ts {
            match tt {
                proc_macro2::TokenTree::Group(g) => walk(g.stream(), seen, out),
                proc_macro2::TokenTree::Ident(id) => {
                    let s = id.to_string();
                    let why = if s.starts_with("r#") {
                        Some("is a raw identifier (rustc reads `r#x` as `x`; the canonical dialect never prints raw identifiers)")
                    } else if !s.is_ascii() {
                        Some("is not ASCII (rustc NFC-normalizes identifiers, so another spelling could be the same name; the canonical dialect's identifiers are ASCII)")
                    } else if s == "gen" {
                        Some("is a reserved keyword (Rust 2024)")
                    } else {
                        None
                    };
                    if let Some(why) = why
                        && seen.insert(s.clone())
                    {
                        out.push(format!("the identifier `{s}` of the printed code {why}"));
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(file.to_token_stream(), &mut HashSet::new(), &mut out);
    out
}

/// What a `use` of a path outside the crate binds (`segs` without the
/// leading `::`): the `::core` definitions generated code re-exports are
/// classified, anything else binds "unknown" in both namespaces.
fn classify_external(segs: &[String], arch: &crate::target::Arch, shown: &str) -> (Option<(ValueDef, String)>, Option<String>) {
    let s: Vec<&str> = segs.iter().map(String::as_str).collect();
    let how = format!("`{shown}`");
    let module = (None, Some(format!("the module {how}")));
    match s.as_slice() {
        ["core" | "std"] | ["core" | "std", "option"] | ["core" | "std", "arch"] => module,
        ["core" | "std", "arch", a] if *a == arch.name() => module,
        ["core" | "std", "option", "Option"] => (None, Some(format!("the enum {how}"))),
        ["core" | "std", "option", "Option", "None"] => (Some((ValueDef::UnitCtor, format!("the unit variant {how}"))), Some(format!("the variant {how}"))),
        ["core" | "std", "option", "Option", "Some"] => (Some((ValueDef::TupleCtor, format!("the tuple variant {how}"))), Some(format!("the variant {how}"))),
        ["core" | "std", "arch", a, name] if *a == arch.name() && intrinsics::lookup(arch, name).is_some() => (Some((ValueDef::Fn, format!("the intrinsic {how}"))), None),
        // vector and mask types: types (a vector type's tuple constructor is
        // conservatively a constructor)
        ["core" | "std", "arch", a, name] if *a == arch.name() && intrinsics::VecTy::from_name(arch, name).is_some() => (Some((ValueDef::TupleCtor, format!("the vector type {how}"))), Some(format!("the vector type {how}"))),
        _ => (Some((ValueDef::Unknown, format!("the external {how}"))), Some(format!("the external {how}"))),
    }
}

/// The names every function of a printed module binds (identifier
/// patterns: parameters, `let`s, arms, `for` variables, temporaries), by
/// function.
struct Bindings(Vec<String>);

impl<'ast> syn::visit::Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
        self.0.push(p.ident.to_string());
        syn::visit::visit_pat_ident(self, p);
    }
    fn visit_item(&mut self, _: &'ast syn::Item) {
        // (items inside bodies are rejected by the lowering)
    }
}

/// The separate shadowing check (see the module docs): no local of the
/// printed text — any identifier pattern of any function, constant or
/// static of any printed module, glue included — has the name of a
/// module-scope name of its module (every namespace: items, `use`
/// bindings) or of a prelude name; and no module-scope name shadows a
/// primitive type the dialect writes unqualified. Independent of the
/// printer: the scopes are read from the printed text ([`read_scopes`]).
fn shadow_failures(content: &[syn::Item], scopes: &HashMap<Vec<String>, ModScope>) -> Vec<String> {
    let mut out = Vec::new();
    fn go(items: &[syn::Item], path: &mut Vec<String>, scopes: &HashMap<Vec<String>, ModScope>, out: &mut Vec<String>) {
        let empty = ModScope { glob: true, ..Default::default() };
        let sc = scopes.get(path).unwrap_or(&empty);
        let here = module_display(path);
        for p in DIALECT_PRIMITIVES {
            if let Some(how) = sc.ty(p) {
                out.push(format!("`{here}`: {how} shadows the primitive type `{p}`, which the canonical dialect writes unqualified"));
            }
        }
        let mut check = |owner: String, visit: &dyn Fn(&mut Bindings)| {
            let mut b = Bindings(vec![]);
            visit(&mut b);
            let mut seen = HashSet::new();
            for n in b.0 {
                if seen.insert(n.clone())
                    && let Some(how) = sc.any(&n)
                {
                    out.push(format!("`{owner}` in `{here}`: the local `{n}` has the name of {how} (a local must not shadow or be shadowed by a module-scope name)"));
                }
            }
        };
        for it in items {
            match it {
                syn::Item::Fn(f) => check(f.sig.ident.to_string(), &|b| syn::visit::Visit::visit_item_fn(b, f)),
                syn::Item::Const(c) => check(c.ident.to_string(), &|b| syn::visit::Visit::visit_expr(b, &c.expr)),
                syn::Item::Static(s) => check(s.ident.to_string(), &|b| syn::visit::Visit::visit_expr(b, &s.expr)),
                syn::Item::Impl(im) => {
                    for ii in &im.items {
                        match ii {
                            syn::ImplItem::Fn(f) => check(format!("{}::{}", toks(&im.self_ty).replace(' ', ""), f.sig.ident), &|b| syn::visit::Visit::visit_impl_item_fn(b, f)),
                            syn::ImplItem::Const(c) => check(c.ident.to_string(), &|b| syn::visit::Visit::visit_expr(b, &c.expr)),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        for it in items {
            if let syn::Item::Mod(m) = it
                && let Some((_, inner)) = &m.content
            {
                path.push(m.ident.to_string());
                go(inner, path, scopes, out);
                path.pop();
            }
        }
    }
    go(content, &mut Vec::new(), scopes, &mut out);
    out
}

// ---------------------------------------------------------------------------
// lowering
// ---------------------------------------------------------------------------

type LR<T> = Result<T, String>;

/// The lowering of the canonical dialect to HIR (see the module docs).
struct Lower<'a> {
    pv: &'a Crate,
    arch: crate::target::Arch,
    /// Printed absolute path (`crate::__sandblaster::m::x`) → item (free
    /// items only: methods are reached through their `<Self>::` path).
    items: HashMap<String, ItemId>,
    /// The canonical spelling of generated names (shared with the printer:
    /// the dialect's form, like the templates). Their *meaning* is checked
    /// independently, from `scopes`.
    genn: crate::canon::GenNames,
    /// The module scopes of the printed text, as rustc sees them
    /// ([`read_scopes`]), by module path under `__sandblaster`.
    scopes: HashMap<Vec<String>, ModScope>,
    /// The variants of every printed enum, as printed ([`read_scopes`]).
    enums: Enums,
    /// The path of the printed module being lowered (under `__sandblaster`).
    cur: Vec<String>,
    /// Items printed `pub` (the boundary) and exported modules (including
    /// the modules exported through re-exports).
    exported: HashSet<ItemId>,
    exported_mods: HashSet<ModId>,
    /// The source's re-exports outside the boundary.
    reexports: &'a [crate::canon::ReExport],
    /// Re-exports found inside modules, as printed.
    reexports_compared: usize,
    /// The printer's fresh-name counter of the current function.
    fresh: u32,
    failures: Vec<String>,
    // ---- current function ----
    locals: Vec<LocalDecl>,
    scope: Vec<LocalId>,
    generics: Vec<String>,
    /// Loop infos of the print view function, in source order.
    loops: Vec<LoopInfo>,
    loop_next: usize,
    ret: Ty,
    /// Tail-loop context: the function and its argument variables.
    tail: Option<(ItemId, Vec<String>)>,
    /// Whether the expression being lowered is in tail position of a tail
    /// loop's body (only there may a `{ …; continue; }` self-call appear:
    /// `continue` elsewhere would abandon the surrounding computation).
    in_tail: bool,
    /// The checked-arithmetic helpers the lowered code calls (E0).
    chk: std::collections::BTreeSet<ChkHelper>,
    span: Span,
}

fn clean(s: &str) -> &str {
    s.strip_prefix("r#").unwrap_or(s)
}

impl<'a> Lower<'a> {
    fn new(pv: &'a Crate, reexports: &'a [crate::canon::ReExport], dispatchers: &[crate::opt::Dispatcher], scopes: PrintedScopes) -> Lower<'a> {
        let mut items = HashMap::new();
        for it in &pv.items {
            if it.ghost {
                continue;
            }
            let mut p = "crate::__sandblaster".to_string();
            for seg in &pv.module(it.module).path.0 {
                p.push_str("::");
                p.push_str(clean(seg));
            }
            p.push_str("::");
            p.push_str(clean(&it.name));
            if matches!(&it.kind, ItemKind::Fn(f) if f.owner.is_some()) {
                // a method: never callable by a free path
                continue;
            }
            items.insert(p, it.id);
        }
        let genn = crate::canon::GenNames::new(pv, reexports, dispatchers);
        let exported = crate::canon::exported_items_with(pv, reexports);
        let exported_mods = crate::canon::exported_modules_with(pv, reexports);
        Lower { pv, arch: pv.target.arch.clone(), items, genn, scopes: scopes.mods, enums: scopes.enums, cur: vec![], exported, exported_mods, reexports, reexports_compared: 0, fresh: 0, failures: vec![], locals: vec![], scope: vec![], generics: vec![], loops: vec![], loop_next: 0, ret: Ty::unit(), tail: None, in_tail: false, chk: Default::default(), span: Span::DUMMY }
    }

    /// The canonical spelling of local `id` (`l{id}_{name}`,
    /// [`crate::canon::GenNames::local`]).
    fn canonical_local_name(&self, id: usize, orig: &str) -> String {
        self.genn.local(id, orig)
    }

    /// The canonical spelling of the next temporary (`t{n}__{what}`,
    /// [`crate::canon::GenNames::temp`]).
    fn next_fresh(&mut self, what: &str) -> String {
        self.fresh += 1;
        self.genn.temp(self.fresh, what)
    }

    /// The scope of the printed module being lowered (a module the reader
    /// did not see resolves every name to "unknown").
    fn cur_scope(&self) -> &ModScope {
        static POISON: std::sync::OnceLock<ModScope> = std::sync::OnceLock::new();
        self.scopes.get(&self.cur).unwrap_or_else(|| POISON.get_or_init(|| ModScope { glob: true, ..Default::default() }))
    }

    /// rustc's reading of the identifier pattern `name` in the current
    /// module: a fresh binding only if `name` resolves to no constant,
    /// static, unit or tuple constructor in the module's scope or the
    /// prelude (a binding may shadow a function). Otherwise the printed
    /// pattern is not the binding of the print view (a capture).
    fn check_binding_name(&self, name: &str) -> LR<()> {
        match self.cur_scope().value(name) {
            Some((def, how)) if def.captures_patterns() => Err(format!("the identifier pattern `{name}` names {how} in scope in `{}`: rustc reads it as {}, not as a binding of the local (a capture)", module_display(&self.cur), def.pattern_reading())),
            _ => Ok(()),
        }
    }

    /// A primitive type name printed unqualified (`u32`, `u32::MAX`,
    /// `<u32>::f`) must denote the primitive: no module-scope type-namespace
    /// name of the current module (items, `use`s) shadows it, and no generic
    /// parameter has its name.
    fn check_primitive(&self, name: &str) -> LR<()> {
        if self.generics.iter().any(|g| g == name) {
            return Err(format!("the primitive type `{name}` is shadowed by a generic parameter of that name"));
        }
        if let Some(how) = self.cur_scope().ty(name) {
            return Err(format!("the primitive type `{name}` is shadowed in `{}` by {how}: rustc would not read `{name}` as the primitive", module_display(&self.cur)));
        }
        Ok(())
    }

    /// The printed visibility of an item (canon `Printer::vis`).
    fn vis_text(v: Vis, exported: bool) -> &'static str {
        match v {
            Vis::Public if exported => "pub",
            Vis::Public | Vis::Crate => "pub(crate)",
            Vis::Super => "pub(super)",
            Vis::Private => "",
        }
    }

    /// Checks a printed visibility against the expected text.
    fn check_vis(got: &syn::Visibility, want: &str) -> LR<()> {
        let g = toks(got).replace(' ', "");
        if g != want {
            return Err(format!("the visibility differs: printed `{g}`, expected `{want}`"));
        }
        Ok(())
    }

    /// The `#[cfg]` attributes printed for an item with `cfg`.
    fn want_cfg(cfg: &Option<String>) -> Vec<String> {
        cfg.iter().map(|c| toks(&syn::parse_str::<syn::Meta>(&format!("cfg({c})")).unwrap_or_else(|_| syn::parse_quote!(cfg(invalid))))).collect()
    }

    fn check_cfg(attrs: &[syn::Attribute], cfg: &Option<String>) -> LR<()> {
        let cfgs = Self::attr_list(attrs, "cfg");
        let want = Self::want_cfg(cfg);
        if cfgs != want {
            return Err(format!("`#[cfg]` differs: {cfgs:?} vs {want:?}"));
        }
        Ok(())
    }

    /// Only `#[doc]` attributes (fields, variants).
    fn only_docs(attrs: &[syn::Attribute], what: &str) -> LR<()> {
        match attrs.iter().find(|a| !a.path().is_ident("doc")) {
            Some(a) => Err(format!("attribute `{}` on {what} is not in the canonical dialect", toks(a))),
            None => Ok(()),
        }
    }

    // ------------------------------------------------------------------
    // modules and items
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn module(&mut self, m: ModId, content: &[syn::Item], lk: &mut Crate, lowered: &mut Vec<ItemId>, o: &Optimized, sm: &SourceMap, st: &mut Stats, root: bool) {
        let module = self.pv.module(m).clone();
        // free items by name; methods by (owner type, name)
        let mut expect_items: HashMap<String, ItemId> = HashMap::new();
        let mut expect_methods: HashMap<(ItemId, String), ItemId> = HashMap::new();
        for &id in &module.items {
            let it = self.pv.item(id);
            if it.ghost {
                continue;
            }
            let printed = match &it.kind {
                ItemKind::Fn(f) => f.kind == FnKind::Exec,
                _ => true,
            };
            if !printed {
                continue;
            }
            let dup = match &it.kind {
                ItemKind::Fn(FnDef { owner: Some(o), .. }) => expect_methods.insert((*o, clean(&it.name).to_string()), id).is_some(),
                _ => expect_items.insert(clean(&it.name).to_string(), id).is_some(),
            };
            if dup {
                self.failures.push(format!("two printed items named `{}` in `{}`", it.name, module.path));
            }
        }
        let mut expect_mods: HashMap<String, ModId> = module.submodules.iter().filter(|c| !self.pv.module(**c).ghost).map(|c| (clean(&self.pv.module(*c).name).to_string(), *c)).collect();
        let dispatchers: HashMap<String, &crate::opt::Dispatcher> = o.dispatchers.iter().filter(|d| d.module == m).map(|d| (d.name.clone(), d)).collect();
        let mut seen_disp: HashSet<String> = HashSet::new();
        // the module's re-exports, as they must be printed (the root's are
        // compared with the top-level exports)
        let mut expect_uses: Vec<(String, String)> = Vec::new();
        if !root {
            for r in self.reexports.iter().filter(|r| r.module == m) {
                if let Some(text) = crate::canon::reexport_text(self.pv, &o.dispatchers, &self.exported_mods, r, 0) {
                    match file_toks(&text) {
                        Ok(w) => expect_uses.push((r.name.clone(), w)),
                        Err(e) => self.failures.push(format!("re-export `{}`: {e}", crate::canon::reexport_site(self.pv, r))),
                    }
                }
            }
        }
        for item in content {
            match item {
                syn::Item::Use(u) => {
                    let got = toks(u);
                    match expect_uses.iter().position(|(_, w)| *w == got) {
                        Some(k) => {
                            expect_uses.remove(k);
                            self.reexports_compared += 1;
                        }
                        None => self.failures.push(format!("unexpected `use` in `{}` (not a re-export of the source, or printed differently): {}", module.path, got.chars().take(120).collect::<String>())),
                    }
                }
                syn::Item::Mod(sm2) if root && sm2.ident == "__arch" => {
                    let Some((_, inner)) = &sm2.content else {
                        self.failures.push("`__arch` without content".into());
                        continue;
                    };
                    let want_attrs = file_toks(&format!("#[cfg(target_arch = {:?})]\nmod x {{}}", self.arch.name())).unwrap_or_default();
                    let got_attrs: String = sm2.attrs.iter().map(toks).collect::<Vec<_>>().join(" ");
                    if got_attrs != want_attrs.trim_end_matches("mod x { }").trim() || Self::check_vis(&sm2.vis, "pub(crate)").is_err() {
                        self.failures.push("the header of `__arch` differs from its template".into());
                    }
                    for h in inner {
                        let syn::Item::Fn(f) = h else {
                            self.failures.push("unexpected item in `__arch`".into());
                            continue;
                        };
                        let name = f.sig.ident.to_string();
                        match intrinsics::lookup_helper(&self.arch, &name) {
                            Some(hid) => match file_toks(&crate::canon::helper_fn_text(self.pv, hid, 0)) {
                                Ok(want) if want == toks(f) => st.glue += 1,
                                _ => self.failures.push(format!("helper `{name}` differs from its template")),
                            },
                            None => self.failures.push(format!("unknown helper `{name}` in `__arch`")),
                        }
                    }
                }
                syn::Item::Mod(dm) if root && dm.ident == "__dispatch" => {
                    let want = file_toks(&crate::canon::dispatch_module(self.pv, &o.sets, 0));
                    match want {
                        Ok(w) if w == toks(dm) => st.glue += 1,
                        _ => self.failures.push("the runtime-detection module differs from its template".into()),
                    }
                }
                syn::Item::Mod(sub) => {
                    let name = sub.ident.to_string();
                    match expect_mods.remove(&name) {
                        Some(c) => {
                            let cm = self.pv.module(c);
                            let want_vis = if self.exported_mods.contains(&c) { "pub" } else { "pub(crate)" };
                            let header = Self::only_docs_or_cfg(&sub.attrs).and_then(|_| Self::check_cfg(&sub.attrs, &cm.cfg)).and_then(|_| Self::check_vis(&sub.vis, want_vis));
                            if let Err(e) = header {
                                self.failures.push(format!("module `{name}`: {e}"));
                            }
                            if sub.unsafety.is_some() {
                                self.failures.push(format!("module `{name}`: `unsafe mod`"));
                            }
                            match &sub.content {
                                Some((_, inner)) => {
                                    self.cur.push(name.clone());
                                    self.module(c, inner, lk, lowered, o, sm, st, false);
                                    self.cur.pop();
                                }
                                None => self.failures.push(format!("module `{name}` has no inline content")),
                            }
                        }
                        None => self.failures.push(format!("unexpected module `{name}` in `{}`", module.path)),
                    }
                }
                syn::Item::Fn(f) if dispatchers.contains_key(&f.sig.ident.to_string()) => {
                    let name = f.sig.ident.to_string();
                    let d = dispatchers[&name];
                    match file_toks(&crate::canon::dispatcher_item_text(self.pv, sm, d, self.reexports, &o.dispatchers)) {
                        Ok(w) if w == toks(f) => {
                            st.glue += 1;
                            seen_disp.insert(name);
                        }
                        _ => self.failures.push(format!("dispatcher `{name}` differs from its template")),
                    }
                }
                syn::Item::Fn(f) => {
                    let name = f.sig.ident.to_string();
                    match expect_items.remove(&name) {
                        Some(id) => match self.item_fn(id, &f.attrs, &f.sig, &f.block, &f.vis, false) {
                            Ok(fd) => {
                                lk.items[id.0 as usize].kind = ItemKind::Fn(fd);
                                lowered.push(id);
                            }
                            Err(e) => self.failures.push(format!("`{}`: {e}", self.pv.item(id).path)),
                        },
                        None => self.failures.push(format!("unexpected function `{name}` in `{}`", module.path)),
                    }
                }
                syn::Item::Impl(im) => {
                    let owner = match self.impl_header(im) {
                        Ok(o) => o,
                        Err(e) => {
                            self.failures.push(format!("impl block in `{}`: {e}", module.path));
                            continue;
                        }
                    };
                    for ii in &im.items {
                        let syn::ImplItem::Fn(f) = ii else {
                            self.failures.push("unexpected impl item".into());
                            continue;
                        };
                        if f.defaultness.is_some() {
                            self.failures.push("`default fn` in an impl block".into());
                            continue;
                        }
                        let name = f.sig.ident.to_string();
                        match expect_methods.remove(&(owner, name.clone())) {
                            Some(id) => match self.item_fn(id, &f.attrs, &f.sig, &f.block, &f.vis, true) {
                                Ok(fd) => {
                                    lk.items[id.0 as usize].kind = ItemKind::Fn(fd);
                                    lowered.push(id);
                                }
                                Err(e) => self.failures.push(format!("`{}`: {e}", self.pv.item(id).path)),
                            },
                            None => self.failures.push(format!("unexpected method `{name}` of `{}`", self.pv.item(owner).path)),
                        }
                    }
                }
                syn::Item::Const(c) => {
                    let name = c.ident.to_string();
                    match expect_items.remove(&name) {
                        Some(id) => match self.item_const(id, c) {
                            Ok(cd) => {
                                lk.items[id.0 as usize].kind = ItemKind::Const(cd);
                                lowered.push(id);
                            }
                            Err(e) => self.failures.push(format!("`{}`: {e}", self.pv.item(id).path)),
                        },
                        None => self.failures.push(format!("unexpected const `{name}`")),
                    }
                }
                syn::Item::Struct(s) => {
                    let name = s.ident.to_string();
                    match expect_items.remove(&name) {
                        Some(id) => {
                            if let Err(e) = self.item_struct(id, s) {
                                self.failures.push(format!("`{}`: {e}", self.pv.item(id).path));
                            }
                        }
                        None => self.failures.push(format!("unexpected struct `{name}`")),
                    }
                }
                syn::Item::Enum(en) => {
                    let name = en.ident.to_string();
                    match expect_items.remove(&name) {
                        Some(id) => {
                            if let Err(e) = self.item_enum(id, en) {
                                self.failures.push(format!("`{}`: {e}", self.pv.item(id).path));
                            }
                        }
                        None => self.failures.push(format!("unexpected enum `{name}`")),
                    }
                }
                syn::Item::Type(t) => {
                    let name = t.ident.to_string();
                    match expect_items.remove(&name) {
                        Some(id) => {
                            self.generics.clear();
                            let ok = matches!(&self.pv.item(id).kind, ItemKind::TypeAlias(a) if self.ty(&t.ty).ok().as_ref() == Some(&a.ty));
                            if !ok || !t.generics.params.is_empty() {
                                self.failures.push(format!("type alias `{name}` differs"));
                            }
                            if let Err(e) = Self::check_attrs(&t.attrs).and_then(|_| self.item_header(id, &t.attrs, &t.vis)) {
                                self.failures.push(format!("type alias `{name}`: {e}"));
                            }
                        }
                        None => self.failures.push(format!("unexpected type alias `{name}`")),
                    }
                }
                other => self.failures.push(format!("unexpected item in `{}`: {}", module.path, toks(other).chars().take(80).collect::<String>())),
            }
        }
        for (n, _) in expect_items {
            self.failures.push(format!("`{}::{n}` is not printed", module.path));
        }
        for ((o, n), _) in expect_methods {
            self.failures.push(format!("method `{}::{n}` is not printed", self.pv.item(o).path));
        }
        for (n, _) in expect_mods {
            self.failures.push(format!("module `{}::{n}` is not printed", module.path));
        }
        for (n, _) in expect_uses {
            self.failures.push(format!("the re-export `{}::{n}` of the source is not printed", module.path));
        }
        for n in dispatchers.keys() {
            if !seen_disp.contains(n) {
                self.failures.push(format!("dispatcher `{n}` is not printed"));
            }
        }
    }

    /// Only `#[doc]` and `#[cfg]` attributes (modules).
    fn only_docs_or_cfg(attrs: &[syn::Attribute]) -> LR<()> {
        match attrs.iter().find(|a| !a.path().is_ident("doc") && !a.path().is_ident("cfg")) {
            Some(a) => Err(format!("attribute `{}` is not in the canonical dialect", toks(a))),
            None => Ok(()),
        }
    }

    /// Checks an impl block's header against the printer's (canon
    /// `Printer::impl_block`): inherent (no trait), safe, no `where`, only
    /// `#[cfg]` attributes, type parameters `T: ::core::marker::Copy`, self
    /// type the owner applied to exactly those parameters. Returns the owner
    /// and leaves the impl's type parameters in `self.generics`.
    fn impl_header(&mut self, im: &syn::ItemImpl) -> LR<ItemId> {
        if im.trait_.is_some() {
            return Err("trait impls are not in the canonical dialect".into());
        }
        if im.unsafety.is_some() || im.defaultness.is_some() || im.generics.where_clause.is_some() {
            return Err("`unsafe`, `default` or `where` on an impl block".into());
        }
        if let Some(a) = im.attrs.iter().find(|a| !a.path().is_ident("cfg")) {
            return Err(format!("attribute `{}` on an impl block", toks(a)));
        }
        let mut names = Vec::new();
        for gp in &im.generics.params {
            match gp {
                syn::GenericParam::Lifetime(l) if l.attrs.is_empty() && l.bounds.is_empty() => {}
                syn::GenericParam::Type(t) if t.attrs.is_empty() && t.default.is_none() && toks(&t.bounds).replace(' ', "") == "::core::marker::Copy" => names.push(t.ident.to_string()),
                _ => return Err(format!("impl generic parameter `{}` is not in the canonical dialect", toks(gp))),
            }
        }
        self.generics = names.clone();
        let st = self.ty(&im.self_ty)?;
        let Ty::Adt(owner, args) = st else { return Err("impl of a type other than a user struct or enum".into()) };
        let want: Vec<Ty> = names.iter().enumerate().map(|(i, n)| Ty::Param(i as u32, n.clone())).collect();
        if args != want {
            return Err("the self type must apply the owner to the impl's type parameters in order".into());
        }
        // every method printed in this block must belong to `owner`, have
        // these impl parameters and the block's `cfg`
        let cfgs = Self::attr_list(&im.attrs, "cfg");
        for ii in &im.items {
            let syn::ImplItem::Fn(f) = ii else { continue };
            let name = f.sig.ident.to_string();
            let Some(it) = self.pv.items.iter().find(|it| !it.ghost && clean(&it.name) == name && matches!(&it.kind, ItemKind::Fn(g) if g.owner == Some(owner))) else { continue };
            let ItemKind::Fn(g) = &it.kind else { continue };
            let impl_names: Vec<&str> = g.generics.iter().take(names.len()).map(|x| x.name.as_str()).collect();
            if impl_names != names.iter().map(String::as_str).collect::<Vec<_>>() {
                return Err(format!("the impl parameters of method `{name}` differ"));
            }
            if Self::want_cfg(&it.cfg) != cfgs {
                return Err(format!("the `#[cfg]` of the impl block differs from method `{name}`'s"));
            }
        }
        Ok(owner)
    }

    fn attr_list(attrs: &[syn::Attribute], name: &str) -> Vec<String> {
        attrs.iter().filter(|a| a.path().is_ident(name)).map(|a| toks(&a.meta)).collect()
    }

    fn target_features(attrs: &[syn::Attribute]) -> LR<Vec<String>> {
        let mut v = Vec::new();
        for a in attrs.iter().filter(|a| a.path().is_ident("target_feature")) {
            let mut got = None;
            a.parse_nested_meta(|m| {
                if m.path.is_ident("enable") {
                    let s: syn::LitStr = m.value()?.parse()?;
                    got = Some(s.value());
                }
                Ok(())
            })
            .map_err(|e| format!("bad target_feature: {e}"))?;
            v.extend(got.ok_or("target_feature without enable")?.split(',').map(|s| s.to_string()));
        }
        Ok(v)
    }

    /// Attributes allowed on printed items (anything else — `no_mangle`,
    /// `export_name`, `link_section`, … — is rejected).
    fn check_attrs(attrs: &[syn::Attribute]) -> LR<()> {
        for a in attrs {
            let ok = ["doc", "cfg", "allow", "inline", "must_use", "target_feature", "derive"].iter().any(|n| a.path().is_ident(n));
            if !ok {
                return Err(format!("attribute `{}` is not in the canonical dialect", toks(a)));
            }
            if a.path().is_ident("allow") && toks(a).contains("unsafe_op_in_unsafe_fn") {
                return Err("unexpected lint attribute".into());
            }
        }
        Ok(())
    }

    fn item_fn(&mut self, id: ItemId, attrs: &[syn::Attribute], sig: &syn::Signature, block: &syn::Block, vis: &syn::Visibility, in_impl: bool) -> LR<FnDef> {
        Self::check_attrs(attrs)?;
        // no attribute below the item (`#[cfg]` on a statement, arm, field,
        // parameter or expression would change what rustc compiles)
        no_inner_attrs(sig, block)?;
        let it = self.pv.item(id).clone();
        let ItemKind::Fn(f) = &it.kind else { return Err("not a function".into()) };
        self.span = it.span;
        self.fresh = 0;
        Self::check_vis(vis, Self::vis_text(it.vis, self.exported.contains(&id)))?;
        if f.receiver.is_some() && !in_impl {
            return Err("a method printed outside an `impl` block".into());
        }
        // attributes that change code generation must match
        if Self::target_features(attrs)? != f.target_features {
            return Err("`#[target_feature]` differs".into());
        }
        // a method's `cfg` is on its impl block (checked by `impl_header`)
        Self::check_cfg(attrs, if in_impl { &None } else { &it.cfg })?;
        if sig.unsafety.is_some() != f.has_requires() {
            return Err("`unsafe fn` must be exactly the functions with `requires`".into());
        }
        if sig.constness.is_some() || sig.asyncness.is_some() || sig.abi.is_some() || sig.variadic.is_some() {
            return Err("unexpected signature qualifiers".into());
        }
        // generics: lifetimes and `T: ::core::marker::Copy`
        let skip = match f.owner {
            Some(owner) => match &self.pv.item(owner).kind {
                ItemKind::Struct(s) => s.generics.len(),
                ItemKind::Enum(e) => e.generics.len(),
                _ => 0,
            },
            None => 0,
        };
        let own: Vec<String> = sig.generics.type_params().map(|t| t.ident.to_string()).collect();
        let want: Vec<String> = f.generics.iter().skip(skip).map(|g| g.name.clone()).collect();
        if own != want {
            return Err("generic parameters differ".into());
        }
        self.generics = f.generics.iter().map(|g| g.name.clone()).collect();
        self.locals = f.locals.clone();
        self.scope.clear();
        self.loops = collect_loops(f);
        self.loop_next = 0;
        self.ret = f.ret.clone();
        self.tail = None;
        let ret = match &sig.output {
            syn::ReturnType::Default => Ty::unit(),
            syn::ReturnType::Type(_, t) => self.ty(t)?,
        };
        if ret != f.ret {
            return Err("the return type differs".into());
        }
        let mut out = f.clone();
        out.ensures = None;
        let inputs: Vec<&syn::FnArg> = sig.inputs.iter().collect();
        // `#[ghost]` parameters are not printed (DESIGN.md §15.3): printed
        // input `k` is the `k`-th other parameter of the print view
        let printed_params: Vec<usize> = (0..f.params.len()).filter(|k| !f.params[*k].ghost).collect();
        if inputs.len() != printed_params.len() {
            return Err("parameter count differs".into());
        }
        if printed_params.len() != f.params.len() && f.recursion == Recursion::Tail {
            return Err("a tail-recursive function with `#[ghost]` parameters".into());
        }
        // the canonical tail loop: `mut aK__arg` parameters
        let arg_names: Vec<String> = (0..f.params.len()).map(|k| self.genn.arg(k)).collect();
        let tail_loop = inputs.iter().enumerate().all(|(k, a)| matches!(a, syn::FnArg::Typed(pt) if matches!(&*pt.pat, syn::Pat::Ident(pi) if pi.ident.to_string().starts_with(&format!("a{k}__arg")) && pi.mutability.is_some() && pi.by_ref.is_none() && pi.subpat.is_none()))) && !inputs.is_empty();
        if tail_loop && f.recursion != Recursion::Tail {
            return Err("a tail loop for a function that is not tail recursive".into());
        }
        if tail_loop {
            let mut tys = Vec::new();
            for (k, a) in inputs.iter().enumerate() {
                let syn::FnArg::Typed(pt) = a else { unreachable!() };
                let syn::Pat::Ident(pi) = &*pt.pat else { unreachable!() };
                // a parameter pattern is a pattern: it must bind (rustc's
                // reading), and be spelled canonically
                let name = pi.ident.to_string();
                self.check_binding_name(&name)?;
                if name != arg_names[k] {
                    return Err(format!("tail-loop argument `{name}`: the canonical spelling is `{}`", arg_names[k]));
                }
                let t = self.ty(&pt.ty)?;
                if t != f.params[k].ty {
                    return Err(format!("the type of parameter {k} differs"));
                }
                tys.push(t);
            }
            // loop { let P_k: T_k = a_k__arg; …; BODY }
            let [syn::Stmt::Expr(syn::Expr::Loop(lp), None)] = block.stmts.as_slice() else { return Err("a tail-loop function must consist of one `loop`".into()) };
            let stmts = &lp.body.stmts;
            if stmts.len() != f.params.len() + 1 {
                return Err("malformed tail loop (parameter rebinding)".into());
            }
            for (k, s) in stmts[..f.params.len()].iter().enumerate() {
                let syn::Stmt::Local(l) = s else { return Err("malformed tail loop (parameter rebinding)".into()) };
                let (pat, ty) = self.typed_pat(&l.pat)?;
                if ty != tys[k] {
                    return Err("malformed tail loop (parameter type)".into());
                }
                let init = l.init.as_ref().ok_or("malformed tail loop")?;
                if toks(&init.expr) != arg_names[k] || init.diverge.is_some() {
                    return Err("malformed tail loop (parameter rebinding)".into());
                }
                let p = self.pat(pat, &ty)?;
                out.params[k].pat = p;
            }
            self.tail = Some((id, arg_names));
            self.in_tail = true;
            // `return BODY;` with every self-call a `{ …; continue; }` block
            let syn::Stmt::Expr(syn::Expr::Return(r), Some(_)) = &stmts[f.params.len()] else { return Err("malformed tail loop (body)".into()) };
            let body = r.expr.as_deref().ok_or("malformed tail loop (body)")?;
            let b = self.expr(body)?;
            self.tail = None;
            self.in_tail = false;
            if b.ty != f.ret && !b.ty.is_never() {
                return Err("tail-loop body of another type".into());
            }
            out.body = FnBody::Exec(b);
        } else {
            for (k, a) in inputs.iter().enumerate() {
                let pt = match a {
                    syn::FnArg::Typed(pt) => pt,
                    syn::FnArg::Receiver(r) => {
                        // `self` / `&self`: the parameter-0 local named `self`
                        if !in_impl {
                            return Err("a `self` parameter outside an `impl` block".into());
                        }
                        if k != 0 || r.mutability.is_some() || r.colon_token.is_some() || (r.reference.is_some() != matches!(f.receiver, Some(Receiver::ByRef))) || f.receiver.is_none() {
                            return Err("the receiver differs".into());
                        }
                        let PatKind::Binding { local, .. } = &f.params[0].pat.kind else { return Err("receiver pattern".into()) };
                        if self.locals[local.0 as usize].name != "self" {
                            return Err("receiver local".into());
                        }
                        self.scope.push(*local);
                        continue;
                    }
                };
                let pk = printed_params[k];
                let t = self.ty(&pt.ty)?;
                if t != f.params[pk].ty {
                    return Err(format!("the type of parameter {k} differs"));
                }
                let p = self.pat(&pt.pat, &t)?;
                out.params[pk].pat = p;
            }
            let body = self.block_expr(block, None)?;
            out.body = FnBody::Exec(body);
        }
        if self.loop_next != self.loops.len() {
            return Err(format!("{} loop(s) printed, {} in the print view", self.loop_next, self.loops.len()));
        }
        Ok(out)
    }

    fn item_const(&mut self, id: ItemId, c: &syn::ItemConst) -> LR<ConstDef> {
        Self::check_attrs(&c.attrs)?;
        self.item_header(id, &c.attrs, &c.vis)?;
        let mut af = AttrFinder(None);
        syn::visit::Visit::visit_expr(&mut af, &c.expr);
        if let Some(a) = af.0 {
            return Err(format!("attribute `{a}` inside a constant initializer"));
        }
        if !c.generics.params.is_empty() {
            return Err("generic constants are not in the canonical dialect".into());
        }
        let ItemKind::Const(cd) = &self.pv.item(id).kind else { return Err("not a const".into()) };
        self.generics.clear();
        self.locals = cd.locals.clone();
        self.scope.clear();
        self.loops.clear();
        self.loop_next = 0;
        self.tail = None;
        self.span = self.pv.item(id).span;
        let t = self.ty(&c.ty)?;
        if t != cd.ty {
            return Err("the type differs".into());
        }
        let init = self.expr(&c.expr)?;
        if init.ty != cd.ty {
            return Err("the initializer has another type".into());
        }
        let mut out = cd.clone();
        out.init = init;
        Ok(out)
    }

    fn derives_of(attrs: &[syn::Attribute]) -> Derives {
        let mut d = Derives::default();
        for a in attrs.iter().filter(|a| a.path().is_ident("derive")) {
            let _ = a.parse_nested_meta(|m| {
                let p = toks(&m.path).replace(' ', "");
                match p.as_str() {
                    "::core::clone::Clone" => d.clone = true,
                    "::core::marker::Copy" => d.copy = true,
                    "::core::cmp::PartialEq" => d.partial_eq = true,
                    "::core::cmp::Eq" => d.eq = true,
                    "::core::fmt::Debug" => d.debug = true,
                    _ => {}
                }
                Ok(())
            });
        }
        d
    }

    fn fields_of(&mut self, fields: &syn::Fields) -> LR<Vec<(Option<String>, Ty)>> {
        fields.iter().map(|f| Ok((f.ident.as_ref().map(|i| clean(&i.to_string()).to_string()), self.ty(&f.ty)?))).collect()
    }

    /// Visibility and `#[cfg]` of a non-function item.
    fn item_header(&self, id: ItemId, attrs: &[syn::Attribute], vis: &syn::Visibility) -> LR<()> {
        let it = self.pv.item(id);
        Self::check_vis(vis, Self::vis_text(it.vis, self.exported.contains(&id)))?;
        Self::check_cfg(attrs, &it.cfg)
    }

    fn item_struct(&mut self, id: ItemId, s: &syn::ItemStruct) -> LR<()> {
        Self::check_attrs(&s.attrs)?;
        self.item_header(id, &s.attrs, &s.vis)?;
        let ItemKind::Struct(sd) = &self.pv.item(id).kind else { return Err("not a struct".into()) };
        self.generics = sd.generics.iter().map(|g| g.name.clone()).collect();
        if Self::derives_of(&s.attrs) != sd.derives {
            return Err("derives differ".into());
        }
        // field visibility (canon: the field's visibility under the
        // struct's export status) and attributes (docs only)
        let exported = self.exported.contains(&id);
        if s.fields.len() != sd.fields.len() {
            return Err("fields differ".into());
        }
        for (f, fd) in s.fields.iter().zip(&sd.fields) {
            Self::only_docs(&f.attrs, "a field")?;
            Self::check_vis(&f.vis, Self::vis_text(fd.vis, exported)).map_err(|e| format!("field `{}`: {e}", fd.name.as_deref().unwrap_or("_")))?;
        }
        let got = self.fields_of(&s.fields)?;
        let want: Vec<(Option<String>, Ty)> = sd.fields.iter().map(|f| (f.name.as_ref().map(|n| clean(n).to_string()), f.ty.clone())).collect();
        if got != want {
            return Err("fields differ".into());
        }
        Ok(())
    }

    fn item_enum(&mut self, id: ItemId, e: &syn::ItemEnum) -> LR<()> {
        Self::check_attrs(&e.attrs)?;
        self.item_header(id, &e.attrs, &e.vis)?;
        for v in &e.variants {
            Self::only_docs(&v.attrs, "a variant")?;
            for f in &v.fields {
                if !f.attrs.is_empty() || !matches!(f.vis, syn::Visibility::Inherited) {
                    return Err(format!("attributes or visibility on a field of variant `{}`", v.ident));
                }
            }
        }
        let ItemKind::Enum(ed) = &self.pv.item(id).kind else { return Err("not an enum".into()) };
        self.generics = ed.generics.iter().map(|g| g.name.clone()).collect();
        if Self::derives_of(&e.attrs) != ed.derives {
            return Err("derives differ".into());
        }
        if e.variants.len() != ed.variants.len() {
            return Err("variants differ".into());
        }
        for (v, vd) in e.variants.iter().zip(&ed.variants) {
            if v.ident != clean(&vd.name) || v.discriminant.is_some() {
                return Err("variants differ".into());
            }
            let got = self.fields_of(&v.fields)?;
            let want: Vec<(Option<String>, Ty)> = vd.fields.iter().map(|f| (f.name.as_ref().map(|n| clean(n).to_string()), f.ty.clone())).collect();
            if got != want {
                return Err(format!("fields of `{}` differ", vd.name));
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // types
    // ------------------------------------------------------------------

    fn ty(&mut self, t: &syn::Type) -> LR<Ty> {
        match t {
            syn::Type::Paren(p) => self.ty(&p.elem),
            syn::Type::Group(g) => self.ty(&g.elem),
            syn::Type::Tuple(tt) => Ok(Ty::Tuple(tt.elems.iter().map(|e| self.ty(e)).collect::<LR<_>>()?)),
            syn::Type::Array(a) => {
                let e = self.ty(&a.elem)?;
                let n = usize_lit(&a.len).ok_or("array length must be a `usize` literal")?;
                Ok(Ty::array(e, n))
            }
            syn::Type::Slice(s) => Ok(Ty::Slice(Box::new(self.ty(&s.elem)?))),
            syn::Type::Reference(r) => {
                if r.mutability.is_some() {
                    return Err("`&mut` types are not in the canonical dialect".into());
                }
                Ok(Ty::reference(self.ty(&r.elem)?))
            }
            syn::Type::Path(p) if p.qself.is_none() => self.ty_path(&p.path),
            _ => Err(format!("unsupported type `{}`", toks(t))),
        }
    }

    fn ty_path(&mut self, p: &syn::Path) -> LR<Ty> {
        let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        if p.leading_colon.is_none() && segs.len() == 1 {
            let n = segs[0].as_str();
            if !matches!(p.segments[0].arguments, syn::PathArguments::None) {
                return Err(format!("generic arguments on `{n}`"));
            }
            // rustc's order: generic parameters, then the module scope, then
            // the primitive types (which the module scope must not shadow)
            if let Some(i) = self.generics.iter().position(|g| g == n) {
                return Ok(Ty::Param(i as u32, n.to_string()));
            }
            let prim = match n {
                "bool" => Some(Ty::Bool),
                "i32" => Some(Ty::I32),
                _ => UintTy::from_name(n).map(Ty::Uint),
            };
            if let Some(t) = prim {
                self.check_primitive(n)?;
                return Ok(t);
            }
            return Err(format!("unknown type `{n}`"));
        }
        let joined = segs.join("::");
        if p.leading_colon.is_some() && joined == "core::option::Option" {
            let args = type_args(p.segments.last().unwrap())?;
            let [a] = args.as_slice() else { return Err("`Option` takes one type".into()) };
            return Ok(Ty::option(self.ty(a)?));
        }
        if p.leading_colon.is_some() && segs.len() == 4 && segs[0] == "core" && segs[1] == "arch" {
            let v = intrinsics::VecTy::from_name(&self.arch, &segs[3]).ok_or_else(|| format!("unknown vector type `{}`", segs[3]))?;
            if v.path() != format!("::{joined}") {
                return Err("vector type path differs".into());
            }
            return Ok(Ty::Vector(v));
        }
        if p.leading_colon.is_none() && segs.first().map(String::as_str) == Some("crate") {
            let id = *self.items.get(&joined).ok_or_else(|| format!("unknown type `{joined}`"))?;
            let args = type_args(p.segments.last().unwrap())?;
            let args = args.iter().map(|a| self.ty(a)).collect::<LR<Vec<_>>>()?;
            return match &self.pv.item(id).kind {
                ItemKind::Struct(_) | ItemKind::Enum(_) => Ok(Ty::Adt(id, args)),
                ItemKind::TypeAlias(a) if args.is_empty() => Ok(a.ty.clone()),
                _ => Err(format!("`{joined}` is not a type")),
            };
        }
        Err(format!("unsupported type path `{}`", toks(p)))
    }

    // ------------------------------------------------------------------
    // locals
    // ------------------------------------------------------------------

    /// The local of a printed name `l{id}_{name}` (validated against the
    /// locals table).
    fn local_of(&self, name: &str) -> LR<LocalId> {
        if name == "self" {
            return self.locals.iter().position(|d| d.name == "self").map(|i| LocalId(i as u32)).ok_or_else(|| "`self` outside a method".to_string());
        }
        let rest = name.strip_prefix('l').ok_or_else(|| format!("`{name}` is not a canonical local name"))?;
        let (num, orig) = rest.split_once('_').ok_or_else(|| format!("`{name}` is not a canonical local name"))?;
        let _ = orig;
        let id: u32 = num.parse().map_err(|_| format!("`{name}` is not a canonical local name"))?;
        if num != id.to_string() {
            return Err(format!("`{name}` is not a canonical local name"));
        }
        let decl = self.locals.get(id as usize).ok_or_else(|| format!("`{name}`: no local #{id}"))?;
        // exactly the printer's spelling: rustc resolves the identifier, so a
        // re-spelled use could name an item (red team F4)
        let want = self.canonical_local_name(id as usize, &decl.name);
        if name != want {
            return Err(format!("`{name}`: local #{id} is printed `{want}`"));
        }
        Ok(LocalId(id))
    }

    fn bind(&mut self, name: &str, mutable: bool, by_ref: bool, ty: &Ty) -> LR<LocalId> {
        let l = self.local_of(name)?;
        let decl = &self.locals[l.0 as usize];
        if decl.mutable != mutable {
            return Err(format!("`{name}`: mutability differs from the declaration"));
        }
        let bty = if by_ref { Ty::reference(ty.clone()) } else { ty.clone() };
        if decl.ty != bty {
            return Err(format!("`{name}`: bound at `{}`, declared `{}`", self.pv.ty_str(&bty), self.pv.ty_str(&decl.ty)));
        }
        self.scope.push(l);
        Ok(l)
    }

    fn use_local(&self, name: &str) -> LR<(LocalId, Ty)> {
        let l = self.local_of(name)?;
        if !self.scope.contains(&l) {
            return Err(format!("`{name}` is used outside the scope of its binding"));
        }
        Ok((l, self.locals[l.0 as usize].ty.clone()))
    }

    fn e(&self, kind: ExprKind, ty: Ty) -> Expr {
        Expr::new(kind, ty, self.span)
    }

    // ------------------------------------------------------------------
    // patterns
    // ------------------------------------------------------------------

    fn typed_pat<'p>(&mut self, p: &'p syn::Pat) -> LR<(&'p syn::Pat, Ty)> {
        match p {
            syn::Pat::Type(pt) => Ok((&pt.pat, self.ty(&pt.ty)?)),
            _ => Err("`let` without a type annotation".into()),
        }
    }

    fn pat(&mut self, p: &syn::Pat, ty: &Ty) -> LR<Pat> {
        let span = self.span;
        let mk = |kind: PatKind| Pat { kind, ty: ty.clone(), span };
        match p {
            syn::Pat::Paren(pp) => self.pat(&pp.pat, ty),
            syn::Pat::Wild(_) => Ok(mk(PatKind::Wild)),
            syn::Pat::Or(o) => {
                if o.leading_vert.is_some() {
                    return Err("leading `|` in an or-pattern".into());
                }
                let alts = o.cases.iter().map(|c| self.pat(c, ty)).collect::<LR<Vec<_>>>()?;
                Ok(mk(PatKind::Or(alts)))
            }
            syn::Pat::Ident(pi) => {
                let name = pi.ident.to_string();
                if pi.subpat.as_ref().is_some_and(|(_, s)| matches!(**s, syn::Pat::Rest(_))) {
                    return Err("`x @ ..` outside a slice pattern".into());
                }
                let by_ref = pi.by_ref.is_some();
                self.check_binding_name(&name)?;
                let sub = match &pi.subpat {
                    Some((_, s)) => Some(Box::new(self.pat(s, ty)?)),
                    None => None,
                };
                let l = self.bind(&name, pi.mutability.is_some(), by_ref, ty)?;
                Ok(mk(PatKind::Binding { local: l, mode: if by_ref { BindingMode::ByRef } else { BindingMode::ByValue }, sub }))
            }
            syn::Pat::Lit(l) => match &l.lit {
                syn::Lit::Bool(b) if *ty == Ty::Bool => Ok(mk(PatKind::Lit(Lit::Bool(b.value)))),
                syn::Lit::Int(i) => {
                    let (v, t) = int_lit(i)?;
                    if t != *ty {
                        return Err("literal pattern of another type".into());
                    }
                    Ok(mk(PatKind::Lit(Lit::Int(v))))
                }
                _ => Err("unsupported literal pattern".into()),
            },
            syn::Pat::Range(r) => {
                if !matches!(r.limits, syn::RangeLimits::Closed(_)) {
                    return Err("range patterns are `a..=b`".into());
                }
                let lo = r.start.as_deref().ok_or("open range pattern")?;
                let hi = r.end.as_deref().ok_or("open range pattern")?;
                let (lo, t1) = expr_int_lit(lo)?;
                let (hi, t2) = expr_int_lit(hi)?;
                if t1 != *ty || t2 != *ty {
                    return Err("range pattern of another type".into());
                }
                Ok(mk(PatKind::Range { lo, hi }))
            }
            syn::Pat::Tuple(tp) => {
                let Ty::Tuple(ts) = ty else { return Err("tuple pattern of a non-tuple".into()) };
                if tp.elems.len() != ts.len() {
                    return Err("tuple pattern arity".into());
                }
                let ps = tp.elems.iter().zip(ts).map(|(p, t)| self.pat(p, t)).collect::<LR<Vec<_>>>()?;
                Ok(mk(PatKind::Tuple(ps)))
            }
            syn::Pat::Reference(r) => {
                if r.mutability.is_some() {
                    return Err("`&mut` pattern".into());
                }
                let Ty::Ref(inner) = ty else { return Err("reference pattern of a non-reference".into()) };
                let sub = self.pat(&r.pat, inner)?;
                Ok(mk(PatKind::Deref { pat: Box::new(sub), implicit: true }))
            }
            syn::Pat::Slice(sp) => {
                let (elem, len) = match ty {
                    Ty::Array(t, n) => ((**t).clone(), Some(*n)),
                    Ty::Slice(t) => ((**t).clone(), None),
                    _ => return Err("slice pattern of a non-slice".into()),
                };
                let is_rest = |p: &syn::Pat| matches!(p, syn::Pat::Rest(_)) || matches!(p, syn::Pat::Ident(pi) if pi.subpat.as_ref().is_some_and(|(_, s)| matches!(**s, syn::Pat::Rest(_))));
                let elems: Vec<&syn::Pat> = sp.elems.iter().collect();
                let rp = elems.iter().position(|e| is_rest(e));
                let (pre, post): (&[&syn::Pat], &[&syn::Pat]) = match rp {
                    Some(r) => (&elems[..r], &elems[r + 1..]),
                    None => (&elems[..], &[]),
                };
                let fixed = (pre.len() + post.len()) as u64;
                let prefix = pre.iter().map(|p| self.pat(p, &elem)).collect::<LR<Vec<_>>>()?;
                let rest = match rp {
                    None => None,
                    Some(r) => match elems[r] {
                        syn::Pat::Rest(_) => Some(None),
                        syn::Pat::Ident(pi) => {
                            let sub_ty = match len {
                                Some(n) => Ty::array(elem.clone(), n.checked_sub(fixed).ok_or("slice pattern longer than the array")?),
                                None => Ty::Slice(Box::new(elem.clone())),
                            };
                            let by_ref = pi.by_ref.is_some();
                            self.check_binding_name(&pi.ident.to_string())?;
                            let l = self.bind(&pi.ident.to_string(), pi.mutability.is_some(), by_ref, &sub_ty)?;
                            Some(Some(Box::new(Pat { kind: PatKind::Binding { local: l, mode: if by_ref { BindingMode::ByRef } else { BindingMode::ByValue }, sub: None }, ty: sub_ty, span: self.span })))
                        }
                        _ => unreachable!(),
                    },
                };
                let suffix = post.iter().map(|p| self.pat(p, &elem)).collect::<LR<Vec<_>>>()?;
                Ok(mk(PatKind::Slice { prefix, rest, suffix }))
            }
            syn::Pat::Path(pp) => {
                let (ctor, targs) = self.ctor_path(&pp.path, pp.qself.is_some())?;
                self.check_ctor_ty(ctor, &targs, ty)?;
                Ok(mk(PatKind::Ctor { ctor, ty_args: targs, fields: vec![] }))
            }
            syn::Pat::TupleStruct(ts) => {
                let (ctor, targs) = self.ctor_path(&ts.path, ts.qself.is_some())?;
                self.check_ctor_ty(ctor, &targs, ty)?;
                let ftys = self.ctor_field_tys(ctor, ty)?;
                if ts.elems.len() != ftys.len() {
                    return Err("constructor pattern arity".into());
                }
                let mut fields = Vec::new();
                for (k, (p, ft)) in ts.elems.iter().zip(&ftys).enumerate() {
                    if matches!(p, syn::Pat::Wild(_)) {
                        continue;
                    }
                    fields.push((k as u32, self.pat(p, ft)?));
                }
                Ok(mk(PatKind::Ctor { ctor, ty_args: targs, fields }))
            }
            syn::Pat::Struct(sp) => {
                let (ctor, targs) = self.ctor_path(&sp.path, sp.qself.is_some())?;
                self.check_ctor_ty(ctor, &targs, ty)?;
                let ftys = self.ctor_field_tys(ctor, ty)?;
                let names = self.ctor_field_names(ctor);
                let mut fields = Vec::new();
                for fp in &sp.fields {
                    let syn::Member::Named(n) = &fp.member else { return Err("numeric field patterns".into()) };
                    let k = names.iter().position(|x| x.as_deref() == Some(clean(&n.to_string()))).ok_or("unknown field in pattern")?;
                    fields.push((k as u32, self.pat(&fp.pat, &ftys[k])?));
                }
                Ok(mk(PatKind::Ctor { ctor, ty_args: targs, fields }))
            }
            _ => Err(format!("unsupported pattern `{}`", toks(p))),
        }
    }

    /// A constructor path: `::core::option::Option::Some`/`None` (with an
    /// optional turbofish), `crate::__sandblaster::m::S` / `…::E::V` (with an
    /// optional turbofish on the type).
    fn ctor_path(&mut self, p: &syn::Path, qself: bool) -> LR<(Ctor, Vec<Ty>)> {
        if qself {
            return Err("qualified constructor path".into());
        }
        let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
        let joined = segs.join("::");
        if p.leading_colon.is_some() && (joined == "core::option::Option::Some" || joined == "core::option::Option::None") {
            let args = type_args(&p.segments[2])?;
            let targs = args.iter().map(|a| self.ty(a)).collect::<LR<Vec<_>>>()?;
            let c = if segs[3] == "Some" { Ctor::Some } else { Ctor::None };
            if !type_args(&p.segments[3])?.is_empty() {
                return Err("turbofish on the variant".into());
            }
            return Ok((c, targs));
        }
        if p.leading_colon.is_none() && segs.first().map(String::as_str) == Some("crate") {
            if let Some(id) = self.items.get(&joined).copied()
                && matches!(self.pv.item(id).kind, ItemKind::Struct(_))
            {
                let args = type_args(p.segments.last().unwrap())?;
                let targs = args.iter().map(|a| self.ty(a)).collect::<LR<Vec<_>>>()?;
                return Ok((Ctor::Struct(id), targs));
            }
            // enum variant
            let (tpath, v) = joined.rsplit_once("::").ok_or("bad path")?;
            let id = self.items.get(tpath).copied().ok_or_else(|| format!("unknown constructor `{joined}`"))?;
            let ItemKind::Enum(e) = &self.pv.item(id).kind else { return Err(format!("`{tpath}` is not an enum")) };
            let vi = e.variants.iter().position(|x| clean(&x.name) == v).ok_or_else(|| format!("unknown variant `{joined}`"))?;
            let n = p.segments.len();
            let args = type_args(&p.segments[n - 2])?;
            let targs = args.iter().map(|a| self.ty(a)).collect::<LR<Vec<_>>>()?;
            return Ok((Ctor::Variant(id, vi as u32), targs));
        }
        Err(format!("unsupported constructor path `{}`", toks(p)))
    }

    fn check_ctor_ty(&self, c: Ctor, targs: &[Ty], ty: &Ty) -> LR<()> {
        let ok = match (c, ty) {
            (Ctor::Some | Ctor::None, Ty::Option(t)) => targs.is_empty() || targs == [(**t).clone()],
            (Ctor::Struct(id) | Ctor::Variant(id, _), Ty::Adt(id2, args)) => id == *id2 && (targs.is_empty() || targs == args.as_slice()),
            _ => false,
        };
        if ok { Ok(()) } else { Err("constructor pattern of another type".into()) }
    }

    fn ctor_field_tys(&self, c: Ctor, ty: &Ty) -> LR<Vec<Ty>> {
        match (c, ty) {
            (Ctor::Some, Ty::Option(t)) => Ok(vec![(**t).clone()]),
            (Ctor::None, _) => Ok(vec![]),
            (Ctor::Struct(id), Ty::Adt(_, args)) => match &self.pv.item(id).kind {
                ItemKind::Struct(s) => Ok(s.fields.iter().map(|f| f.ty.subst(args)).collect()),
                _ => Err("not a struct".into()),
            },
            (Ctor::Variant(id, v), Ty::Adt(_, args)) => match &self.pv.item(id).kind {
                ItemKind::Enum(e) => Ok(e.variants[v as usize].fields.iter().map(|f| f.ty.subst(args)).collect()),
                _ => Err("not an enum".into()),
            },
            _ => Err("constructor of another type".into()),
        }
    }

    fn ctor_field_names(&self, c: Ctor) -> Vec<Option<String>> {
        match c {
            Ctor::Struct(id) => match &self.pv.item(id).kind {
                ItemKind::Struct(s) => s.fields.iter().map(|f| f.name.as_ref().map(|n| clean(n).to_string())).collect(),
                _ => vec![],
            },
            Ctor::Variant(id, v) => match &self.pv.item(id).kind {
                ItemKind::Enum(e) => e.variants[v as usize].fields.iter().map(|f| f.name.as_ref().map(|n| clean(n).to_string())).collect(),
                _ => vec![],
            },
            _ => vec![None],
        }
    }

    fn adt_ty(&self, c: Ctor, targs: &[Ty]) -> Ty {
        match c {
            Ctor::Some | Ctor::None => Ty::option(targs.first().cloned().unwrap_or(Ty::Error)),
            Ctor::Struct(id) | Ctor::Variant(id, _) => Ty::Adt(id, targs.to_vec()),
        }
    }
}

/// Finds the first attribute in a syntax tree.
struct AttrFinder(Option<String>);

impl<'ast> syn::visit::Visit<'ast> for AttrFinder {
    fn visit_attribute(&mut self, a: &'ast syn::Attribute) {
        if self.0.is_none() {
            self.0 = Some(toks(a));
        }
    }
}

/// The canonical dialect has no attribute below the item level: rustc
/// removes syntax under a false `#[cfg]` (statements, match arms, struct
/// fields and patterns, parameters, expressions) before type checking, so
/// such an attribute would make the compiled code differ from the lowered
/// one (red team F1/F1b); no other attribute is printed there either.
fn no_inner_attrs(sig: &syn::Signature, block: &syn::Block) -> LR<()> {
    let mut af = AttrFinder(None);
    syn::visit::Visit::visit_generics(&mut af, &sig.generics);
    for a in &sig.inputs {
        syn::visit::Visit::visit_fn_arg(&mut af, a);
    }
    syn::visit::Visit::visit_block(&mut af, block);
    match af.0 {
        Some(a) => Err(format!("attribute `{a}` inside a function (not in the canonical dialect)")),
        None => Ok(()),
    }
}

/// Every loop of a function, in source order (their infos).
fn collect_loops(f: &FnDef) -> Vec<LoopInfo> {
    struct V(Vec<LoopInfo>);
    impl crate::visit::Visitor for V {
        fn loop_(&mut self, l: &Loop) {
            self.0.push(l.info.clone());
            crate::visit::walk_loop(self, l);
        }
    }
    let mut v = V(vec![]);
    crate::visit::walk_fn(&mut v, f);
    v.0.sort_by_key(|i| i.index);
    v.0
}

fn type_args(seg: &syn::PathSegment) -> LR<Vec<syn::Type>> {
    match &seg.arguments {
        syn::PathArguments::None => Ok(vec![]),
        syn::PathArguments::AngleBracketed(a) => {
            let mut v = Vec::new();
            for g in &a.args {
                match g {
                    syn::GenericArgument::Type(t) => v.push(t.clone()),
                    syn::GenericArgument::Lifetime(_) => {}
                    _ => return Err("unexpected generic argument".into()),
                }
            }
            Ok(v)
        }
        _ => Err("parenthesized generic arguments".into()),
    }
}

/// Const generic arguments (`::<4>`) of a path segment.
fn const_args(seg: &syn::PathSegment) -> LR<Vec<i64>> {
    match &seg.arguments {
        syn::PathArguments::None => Ok(vec![]),
        syn::PathArguments::AngleBracketed(a) => {
            let mut v = Vec::new();
            for g in &a.args {
                let e = match g {
                    syn::GenericArgument::Const(e) => e.clone(),
                    syn::GenericArgument::Type(syn::Type::Path(tp)) if tp.path.get_ident().is_none() => return Err("unexpected type argument".into()),
                    _ => return Err("unexpected generic argument".into()),
                };
                let neg = matches!(&e, syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)));
                let inner = match &e {
                    syn::Expr::Unary(u) if neg => (*u.expr).clone(),
                    other => other.clone(),
                };
                let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) = inner else { return Err("const argument must be an integer literal".into()) };
                if !i.suffix().is_empty() {
                    return Err("const argument must be unsuffixed".into());
                }
                let n: i64 = i.base10_parse().map_err(|e| e.to_string())?;
                v.push(if neg { -n } else { n });
            }
            Ok(v)
        }
        _ => Err("parenthesized generic arguments".into()),
    }
}

fn int_lit(i: &syn::LitInt) -> LR<(u128, Ty)> {
    let t = match i.suffix() {
        "i32" => Ty::I32,
        s => Ty::Uint(UintTy::from_name(s).ok_or("every integer literal of the canonical dialect is suffixed")?),
    };
    let v: u128 = i.base10_parse().map_err(|e| e.to_string())?;
    if let Ty::Uint(u) = &t
        && v > u.max_value()
    {
        return Err("literal out of range".into());
    }
    Ok((v, t))
}

fn expr_int_lit(e: &syn::Expr) -> LR<(u128, Ty)> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => int_lit(i),
        _ => Err("integer literal expected".into()),
    }
}

fn usize_lit(e: &syn::Expr) -> Option<u64> {
    let (v, t) = expr_int_lit(e).ok()?;
    (t == Ty::usize()).then_some(v as u64)
}

// ---------------------------------------------------------------------------
// expressions and statements
// ---------------------------------------------------------------------------

/// The unchecked forms of generated mode (inside `unsafe { .. }`).
enum Unchecked {
    Index(Expr),
    Range(Expr),
    Call(Expr),
}

impl Lower<'_> {
    fn block_ty(b: &Block) -> Ty {
        match &b.tail {
            Some(t) => t.ty.clone(),
            None => {
                if b.stmts.last().is_some_and(|s| matches!(&s.kind, StmtKind::Expr(e) if e.ty.is_never())) {
                    Ty::Never
                } else {
                    Ty::unit()
                }
            }
        }
    }

    fn block(&mut self, b: &syn::Block) -> LR<Block> {
        let saved = self.scope.len();
        let mut stmts = Vec::new();
        let mut tail = None;
        let n = b.stmts.len();
        for (k, s) in b.stmts.iter().enumerate() {
            // (a trailing `unsafe { place = v; }` is an unchecked store
            // statement, not the block's value: red team R1a)
            if k + 1 == n
                && let syn::Stmt::Expr(e, None) = s
                && !is_unchecked_store(e)
            {
                tail = Some(Box::new(self.expr(e)?));
                break;
            }
            let saved_tail = std::mem::replace(&mut self.in_tail, false);
            let st = self.stmt(s);
            self.in_tail = saved_tail;
            if let Some(st) = st? {
                stmts.push(st);
            }
        }
        self.scope.truncate(saved);
        Ok(Block { stmts, tail, span: self.span })
    }

    fn block_expr(&mut self, b: &syn::Block, _expected: Option<&Ty>) -> LR<Expr> {
        let bl = self.block(b)?;
        let t = Self::block_ty(&bl);
        Ok(self.e(ExprKind::Block(bl), t))
    }

    fn stmt(&mut self, s: &syn::Stmt) -> LR<Option<Stmt>> {
        let span = self.span;
        let st = |kind| Some(Stmt { kind, span });
        match s {
            syn::Stmt::Local(l) => {
                let (p, ty) = self.typed_pat(&l.pat)?;
                let init = l.init.as_ref().ok_or("`let` without an initializer")?;
                let e = self.expr(&init.expr)?;
                if e.ty != ty && !e.ty.is_never() {
                    return Err(format!("`let` of type `{}` initialized with `{}`", self.pv.ty_str(&ty), self.pv.ty_str(&e.ty)));
                }
                let els = match &init.diverge {
                    Some((_, b)) => {
                        let syn::Expr::Block(eb) = &**b else { return Err("`let … else` without a block".into()) };
                        let bl = self.block(&eb.block)?;
                        if Self::block_ty(&bl) != Ty::Never {
                            return Err("the `else` block of `let … else` must diverge".into());
                        }
                        Some(bl)
                    }
                    None => None,
                };
                let pat = self.pat(p, &ty)?;
                Ok(st(StmtKind::Let { pat, init: e, els }))
            }
            syn::Stmt::Macro(m) => {
                let e = self.mac(&m.mac)?;
                Ok(st(StmtKind::Expr(e)))
            }
            syn::Stmt::Item(_) => Err("items inside function bodies are not in the canonical dialect".into()),
            syn::Stmt::Expr(e, _) => {
                let e = strip_paren(e);
                match e {
                    syn::Expr::Assign(a) => {
                        if let Some(k) = self.chk_compound(a)? {
                            return Ok(st(k));
                        }
                        let v = self.expr(&a.right)?;
                        let place = self.place(&a.left)?;
                        Ok(st(StmtKind::Assign { place, value: v }))
                    }
                    syn::Expr::Binary(b) if compound_op(&b.op).is_some() => {
                        let op = compound_op(&b.op).unwrap();
                        let v = self.expr(&b.right)?;
                        let place = self.place(&b.left)?;
                        Ok(st(StmtKind::CompoundAssign { op, place, value: v }))
                    }
                    syn::Expr::Unsafe(u) if u.block.stmts.len() == 1 && matches!(&u.block.stmts[0], syn::Stmt::Expr(syn::Expr::Assign(_) | syn::Expr::Binary(_), Some(_))) => {
                        // an unchecked place: `unsafe { *get_unchecked_mut(..) = v; }`
                        let syn::Stmt::Expr(inner, _) = &u.block.stmts[0] else { unreachable!() };
                        let r = self.stmt(&syn::Stmt::Expr(inner.clone(), Some(Default::default())))?;
                        match &r {
                            Some(Stmt { kind: StmtKind::Assign { place, .. } | StmtKind::CompoundAssign { place, .. }, .. }) if place.projs.iter().any(|p| matches!(p, Proj::Index(_))) => Ok(r),
                            _ => Err("`unsafe` around an assignment without unchecked indexing".into()),
                        }
                    }
                    syn::Expr::Call(c) if self.is_copy_from_slice(c) => self.copy_from_slice(c).map(st),
                    _ => {
                        let x = self.expr(e)?;
                        Ok(st(StmtKind::Expr(x)))
                    }
                }
            }
        }
    }

    /// The E0 form of a checked compound assignment `P op= V` (canon,
    /// *Canonical dialect*): `P = { let tN__v: T = V; crate::__rt::chk::<op>_<w>(P, tN__v) }`,
    /// the last argument `tN__v as u32` for a shift amount of another width.
    /// rustc evaluates it as the elaboration evaluates `P op= V` — `V`, then
    /// the value of `P` (whose indices are pure, SEMANTICS.md §4), the
    /// operation, the store — so it lowers to the compound assignment. The
    /// temporary is the printer's next fresh name, the helper's first
    /// argument is `P` token for token, its width is `P`'s. `None`: not this
    /// shape (an ordinary assignment, where a temporary is never a binding).
    fn chk_compound(&mut self, a: &syn::ExprAssign) -> LR<Option<StmtKind>> {
        let syn::Expr::Block(b) = strip_paren(&a.right) else { return Ok(None) };
        let [syn::Stmt::Local(l), syn::Stmt::Expr(syn::Expr::Call(c), None)] = b.block.stmts.as_slice() else { return Ok(None) };
        let syn::Expr::Path(fp) = strip_paren(&c.func) else { return Ok(None) };
        let segs: Vec<String> = fp.path.segments.iter().map(|s| s.ident.to_string()).collect();
        if fp.qself.is_some() || fp.path.leading_colon.is_some() || segs.len() != 4 || segs[..3] != ["crate", "__rt", "chk"] {
            return Ok(None);
        }
        let syn::Pat::Type(pt) = &l.pat else { return Ok(None) };
        let syn::Pat::Ident(pi) = &*pt.pat else { return Ok(None) };
        let name = pi.ident.to_string();
        if !(name.starts_with('t') && name.contains("__v")) {
            return Ok(None);
        }
        // the shape is this one: anything else is a failure
        if b.label.is_some() || pi.mutability.is_some() || pi.by_ref.is_some() || pi.subpat.is_some() || fp.path.segments.iter().any(|s| !matches!(s.arguments, syn::PathArguments::None)) {
            return Err("malformed checked compound assignment".into());
        }
        let h = ChkHelper::parse(&segs[3]).ok_or_else(|| format!("unknown checked-arithmetic helper `{}`", segs[3]))?;
        // exactly the printer's fresh name (never shadowing), and a binding
        // in rustc (not a constant pattern)
        let want = self.next_fresh("v");
        if name != want {
            return Err(format!("malformed checked compound assignment: temporary `{name}`, the printer's is `{want}`"));
        }
        self.check_binding_name(&name)?;
        let init = l.init.as_ref().ok_or("malformed checked compound assignment")?;
        if init.diverge.is_some() {
            return Err("malformed checked compound assignment".into());
        }
        let vt = self.ty(&pt.ty)?;
        let v = self.expr(&init.expr)?;
        if v.ty != vt {
            return Err(format!("checked compound assignment: a value of type `{}` bound as `{}`", self.pv.ty_str(&v.ty), self.pv.ty_str(&vt)));
        }
        let place = self.place(&a.left)?;
        // the helper's arguments: the assigned place, then the temporary
        // (converted to `u32` for a shift amount of another width)
        if c.args.len() != 2 || toks(&c.args[0]) != toks(&a.left) {
            return Err(format!("checked compound assignment: the first argument of `{}` must be the assigned place", h.name()));
        }
        let arg_ok = match strip_paren(&c.args[1]) {
            syn::Expr::Path(p) if toks(p) == name => vt == Ty::Uint(h.rhs()),
            syn::Expr::Cast(cast) if h.is_shift() => matches!(strip_paren(&cast.expr), syn::Expr::Path(p) if toks(p) == name) && self.ty(&cast.ty)? == Ty::u32() && matches!(vt, Ty::Uint(w) if w != UintTy::U32),
            _ => false,
        };
        if !arg_ok || place.ty != Ty::Uint(h.w) {
            return Err(format!("checked compound assignment: the arguments of `{}` differ from `({}, {})`", h.name(), h.w.name(), h.rhs().name()));
        }
        self.chk.insert(h);
        Ok(Some(StmtKind::CompoundAssign { op: h.bin_op(), place, value: v }))
    }

    fn is_copy_from_slice(&self, c: &syn::ExprCall) -> bool {
        matches!(strip_paren(&c.func), syn::Expr::Path(p) if p.qself.is_some() && p.path.segments.last().is_some_and(|s| s.ident == "copy_from_slice"))
    }

    /// `<[T]>::copy_from_slice(TARGET, SRC)` with `TARGET` one of `&mut d`,
    /// `&mut d[a..b]`, `unsafe { <[T]>::get_unchecked_mut((&mut d as &mut
    /// [T]), a..b) }`.
    fn copy_from_slice(&mut self, c: &syn::ExprCall) -> LR<StmtKind> {
        let syn::Expr::Path(p) = strip_paren(&c.func) else { unreachable!() };
        let q = p.qself.as_ref().unwrap();
        let et = match self.ty(&q.ty)? {
            Ty::Slice(t) => *t,
            _ => return Err("copy_from_slice on a non-slice".into()),
        };
        if p.path.segments.len() != 1 || c.args.len() != 2 {
            return Err("malformed copy_from_slice".into());
        }
        let src = self.expr(&c.args[1])?;
        if src.ty != Ty::slice_ref(et.clone()) {
            return Err("copy_from_slice source must be `&[T]`".into());
        }
        let target = strip_paren(&c.args[0]);
        let (dst, range) = match target {
            syn::Expr::Reference(r) if r.mutability.is_some() => match strip_paren(&r.expr) {
                syn::Expr::Path(_) => (self.dst_local(&r.expr, &et)?, None),
                _ => return Err("copy_from_slice into an indexed place must be unchecked in generated code".into()),
            },
            syn::Expr::Unsafe(u) => {
                let [syn::Stmt::Expr(inner, None)] = u.block.stmts.as_slice() else { return Err("malformed unchecked copy target".into()) };
                let syn::Expr::Call(gc) = strip_paren(inner) else { return Err("malformed unchecked copy target".into()) };
                let syn::Expr::Path(gp) = strip_paren(&gc.func) else { return Err("malformed unchecked copy target".into()) };
                if !self.is_ufcs(gp, "get_unchecked_mut", &et)? || gc.args.len() != 2 {
                    return Err("malformed unchecked copy target".into());
                }
                // (&mut d as &mut [T])
                let syn::Expr::Cast(cast) = strip_paren(&gc.args[0]) else { return Err("unchecked copy target must be `(&mut d as &mut [T])`".into()) };
                let syn::Expr::Reference(r) = strip_paren(&cast.expr) else { return Err("unchecked copy target must be `(&mut d as &mut [T])`".into()) };
                if r.mutability.is_none() || toks(&cast.ty).replace(' ', "") != format!("&mut[{}]", crate::canon::type_text(self.pv, &et).replace(' ', "")) {
                    return Err("unchecked copy target must be `(&mut d as &mut [T])`".into());
                }
                let dst = self.dst_local(&r.expr, &et)?;
                let syn::Expr::Range(rg) = strip_paren(&gc.args[1]) else { return Err("unchecked copy target needs a range".into()) };
                if !matches!(rg.limits, syn::RangeLimits::HalfOpen(_)) {
                    return Err("`..=` ranges are not in the canonical dialect".into());
                }
                let lo = rg.start.as_deref().map(|x| self.expr(x)).transpose()?;
                let hi = rg.end.as_deref().map(|x| self.expr(x)).transpose()?;
                (dst, Some((lo, hi)))
            }
            _ => return Err("malformed copy_from_slice target".into()),
        };
        Ok(StmtKind::CopyFromSlice { dst, range, src })
    }

    /// The `let mut` array local written by `copy_from_slice`.
    fn dst_local(&self, e: &syn::Expr, et: &Ty) -> LR<LocalId> {
        let syn::Expr::Path(p) = strip_paren(e) else { return Err("copy_from_slice destination must be a local".into()) };
        let name = p.path.get_ident().ok_or("copy_from_slice destination must be a local")?.to_string();
        let (l, ty) = self.use_local(&name)?;
        if !self.locals[l.0 as usize].mutable || !matches!(&ty, Ty::Array(t, _) if **t == *et) {
            return Err("copy_from_slice destination must be a `let mut` array".into());
        }
        Ok(l)
    }

    fn place(&mut self, e: &syn::Expr) -> LR<Place> {
        match strip_paren(e) {
            syn::Expr::Path(p) => {
                let name = p.path.get_ident().ok_or("assignment to a non-local")?.to_string();
                let (l, ty) = self.use_local(&name)?;
                if !self.locals[l.0 as usize].mutable {
                    return Err(format!("assignment to the immutable `{name}`"));
                }
                Ok(Place { local: l, projs: vec![], ty, span: self.span })
            }
            syn::Expr::Field(f) => {
                let mut pl = self.place(&f.base)?;
                let (index, name, fty) = self.field_of(&pl.ty, &f.member)?;
                pl.projs.push(Proj::Field { index, name });
                pl.ty = fty;
                Ok(pl)
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                // `*<[T]>::get_unchecked_mut((&mut P as &mut [T]), I)`
                let syn::Expr::Call(gc) = strip_paren(&u.expr) else { return Err("unsupported place".into()) };
                let syn::Expr::Path(gp) = strip_paren(&gc.func) else { return Err("unsupported place".into()) };
                let Some(q) = &gp.qself else { return Err("unsupported place".into()) };
                let et = match self.ty(&q.ty)? {
                    Ty::Slice(t) => *t,
                    _ => return Err("unsupported place".into()),
                };
                if !self.is_ufcs(gp, "get_unchecked_mut", &et)? || gc.args.len() != 2 {
                    return Err("unsupported place".into());
                }
                let syn::Expr::Cast(cast) = strip_paren(&gc.args[0]) else { return Err("unchecked place must be `(&mut P as &mut [T])`".into()) };
                let syn::Expr::Reference(r) = strip_paren(&cast.expr) else { return Err("unchecked place must be `(&mut P as &mut [T])`".into()) };
                if r.mutability.is_none() || toks(&cast.ty).replace(' ', "") != format!("&mut[{}]", crate::canon::type_text(self.pv, &et).replace(' ', "")) {
                    return Err("unchecked place must be `(&mut P as &mut [T])`".into());
                }
                let mut pl = self.place(&r.expr)?;
                let Ty::Array(t, _) = &pl.ty else { return Err("unchecked index of a non-array place".into()) };
                if **t != et {
                    return Err("unchecked place element type differs".into());
                }
                let idx = self.expr(&gc.args[1])?;
                if idx.ty != Ty::usize() {
                    return Err("index must be `usize`".into());
                }
                pl.ty = et;
                pl.projs.push(Proj::Index(idx));
                Ok(pl)
            }
            _ => Err(format!("unsupported place `{}`", toks(e))),
        }
    }

    fn field_of(&self, t: &Ty, m: &syn::Member) -> LR<(u32, Option<String>, Ty)> {
        match (t, m) {
            (Ty::Tuple(ts), syn::Member::Unnamed(i)) => {
                let k = i.index as usize;
                Ok((k as u32, None, ts.get(k).cloned().ok_or("tuple index out of range")?))
            }
            (Ty::Adt(id, args), _) => {
                let ItemKind::Struct(s) = &self.pv.item(*id).kind else { return Err("field of a non-struct".into()) };
                let k = match m {
                    syn::Member::Named(n) => s.fields.iter().position(|f| f.name.as_deref().map(clean) == Some(clean(&n.to_string()))).ok_or("unknown field")?,
                    syn::Member::Unnamed(i) => i.index as usize,
                };
                let f = s.fields.get(k).ok_or("unknown field")?;
                Ok((k as u32, f.name.clone(), f.ty.subst(args)))
            }
            _ => Err(format!("field access on `{}`", self.pv.ty_str(t))),
        }
    }

    fn mac(&mut self, m: &syn::Macro) -> LR<Expr> {
        if toks(&m.path).replace(' ', "") == "::core::unreachable" && m.tokens.is_empty() {
            return Ok(self.e(ExprKind::Unreachable, Ty::Never));
        }
        Err(format!("macro `{}` is not in the canonical dialect", toks(&m.path)))
    }

    /// Whether `p` is `<[T]>::name` (UFCS on a slice of `et`).
    fn is_ufcs(&mut self, p: &syn::ExprPath, name: &str, et: &Ty) -> LR<bool> {
        let Some(q) = &p.qself else { return Ok(false) };
        if q.position != 0 || p.path.segments.len() != 1 || p.path.segments[0].ident != name || !matches!(p.path.segments[0].arguments, syn::PathArguments::None) {
            return Ok(false);
        }
        Ok(self.ty(&q.ty)? == Ty::Slice(Box::new(et.clone())))
    }

    /// Lowers `e`; tail position is kept only through blocks' tail
    /// expressions, `if` branches and match arm bodies.
    fn expr(&mut self, e: &syn::Expr) -> LR<Expr> {
        let keeps_tail = matches!(strip_paren(e), syn::Expr::Block(_) | syn::Expr::If(_) | syn::Expr::Match(_) | syn::Expr::Return(_));
        if !keeps_tail && self.in_tail {
            self.in_tail = false;
            let r = self.expr_inner(e);
            self.in_tail = true;
            return r;
        }
        self.expr_inner(e)
    }

    /// Lowers `e` in a non-tail position.
    fn expr_nt(&mut self, e: &syn::Expr) -> LR<Expr> {
        let saved = std::mem::replace(&mut self.in_tail, false);
        let r = self.expr_inner(e);
        self.in_tail = saved;
        r
    }

    fn expr_inner(&mut self, e: &syn::Expr) -> LR<Expr> {
        match e {
            syn::Expr::Paren(p) => self.expr(&p.expr),
            syn::Expr::Group(g) => self.expr(&g.expr),
            syn::Expr::Lit(l) => match &l.lit {
                syn::Lit::Bool(b) => Ok(self.e(ExprKind::Lit(Lit::Bool(b.value)), Ty::Bool)),
                syn::Lit::Int(i) => {
                    let (v, t) = int_lit(i)?;
                    Ok(self.e(ExprKind::Lit(Lit::Int(v)), t))
                }
                _ => Err("unsupported literal".into()),
            },
            syn::Expr::Path(p) => self.path_expr(p),
            syn::Expr::Call(c) => self.call(c),
            syn::Expr::Struct(s) => {
                let (ctor, targs) = self.ctor_path(&s.path, s.qself.is_some())?;
                let ty = self.adt_ty(ctor, &targs);
                let ftys = self.ctor_field_tys(ctor, &ty)?;
                let names = self.ctor_field_names(ctor);
                let mut fields = Vec::new();
                for fv in &s.fields {
                    let k = match &fv.member {
                        syn::Member::Named(n) => names.iter().position(|x| x.as_deref() == Some(clean(&n.to_string()))).ok_or("unknown field")?,
                        syn::Member::Unnamed(i) => i.index as usize,
                    };
                    let v = self.expr(&fv.expr)?;
                    if v.ty != ftys[k] {
                        return Err("struct field of another type".into());
                    }
                    fields.push((k as u32, v));
                }
                let base = match &s.rest {
                    Some(b) => Some(Box::new(self.expr(b)?)),
                    None => None,
                };
                Ok(self.e(ExprKind::Adt { ctor, ty_args: targs, fields, base }, ty))
            }
            syn::Expr::Tuple(t) => {
                let es = t.elems.iter().map(|x| self.expr(x)).collect::<LR<Vec<_>>>()?;
                let ty = Ty::Tuple(es.iter().map(|x| x.ty.clone()).collect());
                Ok(self.e(ExprKind::Tuple(es), ty))
            }
            syn::Expr::Array(a) => {
                let es = a.elems.iter().map(|x| self.expr(x)).collect::<LR<Vec<_>>>()?;
                let et = es.first().map(|x| x.ty.clone()).ok_or("empty array literals are not in the canonical dialect")?;
                if es.iter().any(|x| x.ty != et) {
                    return Err("array elements of different types".into());
                }
                let n = es.len() as u64;
                Ok(self.e(ExprKind::Array(es), Ty::array(et, n)))
            }
            syn::Expr::Repeat(r) => {
                let el = self.expr(&r.expr)?;
                let n = usize_lit(&r.len).ok_or("repeat count must be a `usize` literal")?;
                let t = Ty::array(el.ty.clone(), n);
                Ok(self.e(ExprKind::Repeat { elem: Box::new(el), count: n }, t))
            }
            syn::Expr::Field(f) => {
                let b = self.expr(&f.base)?;
                let (index, name, t) = self.field_of(&b.ty, &f.member)?;
                Ok(self.e(ExprKind::Field { base: Box::new(b), index, name }, t))
            }
            syn::Expr::Index(ix) => {
                let b = self.expr(&ix.expr)?;
                match &*ix.index {
                    syn::Expr::Range(r) => Err(format!("checked range `{}` in generated code (must be unchecked)", toks(r))),
                    idx => {
                        let i = self.expr(idx)?;
                        let et = match &b.ty {
                            Ty::Array(t, _) | Ty::Slice(t) => (**t).clone(),
                            _ => return Err("index of a non-array".into()),
                        };
                        Ok(self.e(ExprKind::Index { base: Box::new(b), index: Box::new(i) }, et))
                    }
                }
            }
            syn::Expr::Reference(r) => {
                if r.mutability.is_some() {
                    return Err("`&mut` outside the unchecked forms".into());
                }
                if let syn::Expr::Index(ix) = strip_paren(&r.expr)
                    && matches!(&*ix.index, syn::Expr::Range(_))
                {
                    return Err("checked ranges are not printed in generated code".into());
                }
                let x = self.expr(&r.expr)?;
                let t = Ty::reference(x.ty.clone());
                Ok(self.e(ExprKind::Ref(Box::new(x)), t))
            }
            syn::Expr::Unary(u) => {
                let x = self.expr(&u.expr)?;
                match u.op {
                    syn::UnOp::Deref(_) => match x.ty.clone() {
                        Ty::Ref(t) => Ok(self.e(ExprKind::Deref(Box::new(x)), *t)),
                        _ => Err("dereference of a non-reference".into()),
                    },
                    syn::UnOp::Not(_) => {
                        let t = x.ty.clone();
                        Ok(self.e(ExprKind::Unary(UnOp::Not, Box::new(x)), t))
                    }
                    syn::UnOp::Neg(_) => Err("negation is ghost-only".into()),
                    _ => Err("unsupported unary operator".into()),
                }
            }
            syn::Expr::Binary(b) => {
                let op = bin_op(&b.op).ok_or("compound assignment in expression position")?;
                let l = self.expr(&b.left)?;
                let r = self.expr(&b.right)?;
                let t = if op.is_comparison() || matches!(op, BinOp::And | BinOp::Or) { Ty::Bool } else { l.ty.clone() };
                Ok(self.e(ExprKind::Binary(op, Box::new(l), Box::new(r)), t))
            }
            syn::Expr::Cast(c) => {
                let x = self.expr(&c.expr)?;
                let t = self.ty(&c.ty)?;
                match &t {
                    Ty::Ref(inner) if matches!(**inner, Ty::Slice(_)) => {
                        let ok = matches!((&x.ty, &**inner), (Ty::Ref(a), Ty::Slice(e)) if matches!(&**a, Ty::Array(ae, _) if ae == e));
                        if !ok {
                            return Err("unsizing cast of a non-array reference".into());
                        }
                        Ok(self.e(ExprKind::Coerce(Coercion::Unsize, Box::new(x)), t))
                    }
                    _ => Ok(self.e(ExprKind::Cast(Box::new(x), t.clone()), t)),
                }
            }
            syn::Expr::If(i) => {
                let c = self.expr_nt(&i.cond)?;
                let then = self.block_expr(&i.then_branch, None)?;
                let els = match &i.else_branch {
                    Some((_, x)) => Some(Box::new(self.expr(x)?)),
                    None => None,
                };
                let t = match &els {
                    None => Ty::unit(),
                    Some(x) => {
                        if then.ty.is_never() {
                            x.ty.clone()
                        } else {
                            then.ty.clone()
                        }
                    }
                };
                Ok(self.e(ExprKind::If { cond: Box::new(c), then: Box::new(then), els }, t))
            }
            syn::Expr::Match(m) => {
                let s = self.expr_nt(&m.expr)?;
                let mut arms = Vec::new();
                for a in &m.arms {
                    let saved = self.scope.len();
                    let pat = self.pat(&a.pat, &s.ty)?;
                    if pat.has_or() {
                        return Err("or-patterns in match arms are printed expanded".into());
                    }
                    let guard = match &a.guard {
                        Some((_, g)) => {
                            let g = self.expr_nt(g)?;
                            if g.ty != Ty::Bool {
                                return Err("a guard must be a `bool`".into());
                            }
                            Some(g)
                        }
                        None => None,
                    };
                    let body = self.expr(&a.body)?;
                    self.scope.truncate(saved);
                    arms.push(Arm { pat, guard, body, span: self.span });
                }
                let t = arms.iter().map(|a| a.body.ty.clone()).find(|t| !t.is_never()).unwrap_or(Ty::Never);
                Ok(self.e(ExprKind::Match { scrut: Box::new(s), arms, source: MatchSource::Match }, t))
            }
            syn::Expr::Block(b) => {
                if b.label.is_some() {
                    return Err("labels are not in the canonical dialect".into());
                }
                if let Some((fid, names)) = self.tail.clone()
                    && is_continue_shape(&b.block)
                {
                    if !self.in_tail {
                        return Err("a tail-loop self-call (`continue`) outside tail position".into());
                    }
                    let saved = std::mem::replace(&mut self.in_tail, false);
                    let r = self.continue_block(&b.block, fid, &names);
                    self.in_tail = saved;
                    if let Some(call) = r? {
                        return Ok(call);
                    }
                    return Err("malformed tail-loop self-call".into());
                }
                self.block_expr(&b.block, None)
            }
            syn::Expr::Unsafe(u) => match self.unchecked(&u.block)? {
                Unchecked::Index(x) | Unchecked::Range(x) | Unchecked::Call(x) => Ok(x),
            },
            syn::Expr::Return(r) => {
                // the operand of `return` is in tail position of the function
                let saved = std::mem::replace(&mut self.in_tail, self.tail.is_some());
                let x = match &r.expr {
                    Some(x) => self.expr(x).map(|x| Some(Box::new(x))),
                    None => Ok(None),
                };
                self.in_tail = saved;
                let x = x?;
                Ok(self.e(ExprKind::Return(x), Ty::Never))
            }
            syn::Expr::Try(t) => {
                let x = self.expr(&t.expr)?;
                let Ty::Option(inner) = &x.ty else { return Err("`?` on a non-Option".into()) };
                let inner = (**inner).clone();
                Ok(self.e(ExprKind::Try(Box::new(x)), inner))
            }
            syn::Expr::Macro(m) => self.mac(&m.mac),
            syn::Expr::ForLoop(f) => self.for_loop(f),
            syn::Expr::While(w) => self.while_loop(w),
            _ => Err(format!("`{}` is not in the canonical dialect", toks(e).chars().take(60).collect::<String>())),
        }
    }

    /// The next loop's info from the print view (validated against the
    /// printed body by the caller).
    fn next_loop(&mut self) -> LR<LoopInfo> {
        let info = self.loops.get(self.loop_next).cloned().ok_or("more loops printed than in the print view")?;
        self.loop_next += 1;
        Ok(info)
    }

    fn check_loop_info(&self, info: &LoopInfo, body: &Block, extra: &[&Expr]) -> LR<()> {
        // assigned outer locals must be exactly the print view's
        let e = Expr::new(ExprKind::Block(body.clone()), Ty::unit(), self.span);
        let assigned: std::collections::BTreeSet<LocalId> = crate::elab::exec::assigned_in(&e).into_iter().filter(|l| self.scope.contains(l)).collect();
        let want: std::collections::BTreeSet<LocalId> = info.mutated.iter().copied().collect();
        if assigned != want {
            return Err(format!("loop #{} assigns {:?}, the print view {:?}", info.index, assigned, want));
        }
        // every outer local read is a helper parameter
        struct R<'s>(&'s [LocalId], Vec<LocalId>);
        impl crate::visit::Visitor for R<'_> {
            fn expr(&mut self, e: &Expr) {
                if let ExprKind::Local(l) = &e.kind
                    && self.0.contains(l)
                {
                    self.1.push(*l);
                }
                crate::visit::walk_expr(self, e);
            }
        }
        let mut r = R(&self.scope, vec![]);
        crate::visit::Visitor::expr(&mut r, &e);
        for x in extra {
            crate::visit::Visitor::expr(&mut r, x);
        }
        for l in r.1 {
            if !info.read.contains(&l) && !info.mutated.contains(&l) {
                return Err(format!("loop #{} reads local #{} which is not a helper parameter", info.index, l.0));
            }
        }
        Ok(())
    }

    fn for_loop(&mut self, f: &syn::ExprForLoop) -> LR<Expr> {
        if f.label.is_some() {
            return Err("labels are not in the canonical dialect".into());
        }
        let info = self.next_loop()?;
        let syn::Expr::Range(r) = strip_paren(&f.expr) else { return Err("`for` over a non-range".into()) };
        let lo = self.expr(r.start.as_deref().ok_or("open range")?)?;
        let hi = self.expr(r.end.as_deref().ok_or("open range")?)?;
        let inclusive = matches!(r.limits, syn::RangeLimits::Closed(_));
        if lo.ty != hi.ty || lo.ty.as_uint().is_none() {
            return Err("range bounds must be unsigned of one type".into());
        }
        let saved = self.scope.len();
        let var = match &*f.pat {
            syn::Pat::Wild(_) => None,
            syn::Pat::Ident(pi) if pi.subpat.is_none() && pi.by_ref.is_none() => {
                self.check_binding_name(&pi.ident.to_string())?;
                Some(self.bind(&pi.ident.to_string(), pi.mutability.is_some(), false, &lo.ty)?)
            }
            _ => return Err("`for` pattern must be a binding or `_`".into()),
        };
        let body = self.block(&f.body)?;
        self.scope.truncate(saved);
        // (the bounds are evaluated before the loop, outside its helper)
        self.check_loop_info(&info, &body, &[])?;
        let l = Loop { kind: LoopKind::ForRange { var, lo, hi, inclusive }, body, info, span: self.span };
        Ok(self.e(ExprKind::Loop(Box::new(l)), Ty::unit()))
    }

    fn while_loop(&mut self, w: &syn::ExprWhile) -> LR<Expr> {
        if w.label.is_some() {
            return Err("labels are not in the canonical dialect".into());
        }
        let info = self.next_loop()?;
        let cond = self.expr(&w.cond)?;
        let body = self.block(&w.body)?;
        self.check_loop_info(&info, &body, &[&cond])?;
        let l = Loop { kind: LoopKind::While { cond }, body, info, span: self.span };
        Ok(self.e(ExprKind::Loop(Box::new(l)), Ty::unit()))
    }

    /// A tail loop's self-call: `{ let tN__next = v; …; aK__arg = tN__next;
    /// …; continue; }`.
    fn continue_block(&mut self, b: &syn::Block, fid: ItemId, names: &[String]) -> LR<Option<Expr>> {
        let n = names.len();
        if b.stmts.len() != 2 * n + 1 || !matches!(b.stmts.last(), Some(syn::Stmt::Expr(syn::Expr::Continue(c), Some(_))) if c.label.is_none()) {
            return Ok(None);
        }
        let mut temps = Vec::new();
        let mut vals = Vec::new();
        for s in &b.stmts[..n] {
            let syn::Stmt::Local(l) = s else { return Ok(None) };
            let syn::Pat::Ident(pi) = &l.pat else { return Ok(None) };
            let name = pi.ident.to_string();
            if !(name.starts_with('t') && name.contains("__next")) || pi.mutability.is_some() || pi.by_ref.is_some() || pi.subpat.is_some() {
                return Ok(None);
            }
            // exactly the printer's fresh names, in order: pairwise distinct
            // and never shadowing (red team F2)
            let want = self.next_fresh("next");
            if name != want {
                return Err(format!("malformed continue block: temporary `{name}`, the printer's is `{want}`"));
            }
            // …and a binding in rustc (not a constant pattern: `let` of a
            // constant of the argument's type would be a refutable pattern)
            self.check_binding_name(&name)?;
            let init = l.init.as_ref().ok_or("malformed continue block")?;
            if init.diverge.is_some() {
                return Ok(None);
            }
            // every value is computed before any rebinding
            vals.push(self.expr(&init.expr)?);
            temps.push(name);
        }
        for (k, s) in b.stmts[n..2 * n].iter().enumerate() {
            let syn::Stmt::Expr(syn::Expr::Assign(a), Some(_)) = s else { return Err("malformed continue block".into()) };
            if toks(&a.left) != names[k] || toks(&a.right) != temps[k] {
                return Err("malformed continue block (rebinding)".into());
            }
        }
        let f = self.pv.fn_def(fid).ok_or("tail function")?;
        for (v, p) in vals.iter().zip(&f.params) {
            if v.ty != p.ty {
                return Err("self-call argument of another type".into());
            }
        }
        let targs: Vec<Ty> = f.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect();
        Ok(Some(self.e(ExprKind::Call { callee: Callee::Item(fid, targs), args: vals }, f.ret.clone())))
    }

    /// `unsafe { .. }` forms of generated mode.
    fn unchecked(&mut self, b: &syn::Block) -> LR<Unchecked> {
        let [syn::Stmt::Expr(inner, None)] = b.stmts.as_slice() else { return Err("`unsafe` block outside the generated-mode forms".into()) };
        match strip_paren(inner) {
            // *<[T]>::get_unchecked(X, I)
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => {
                let syn::Expr::Call(c) = strip_paren(&u.expr) else { return Err("`unsafe` block outside the generated-mode forms".into()) };
                let (et, base) = self.unchecked_base(c, "get_unchecked")?;
                let idx = self.expr(&c.args[1])?;
                if idx.ty != Ty::usize() {
                    return Err("index must be `usize`".into());
                }
                Ok(Unchecked::Index(self.e(ExprKind::Index { base: Box::new(base), index: Box::new(idx) }, et)))
            }
            syn::Expr::Call(c) if matches!(strip_paren(&c.func), syn::Expr::Path(p) if p.qself.is_some() && p.path.segments.last().is_some_and(|s| s.ident == "get_unchecked")) => {
                let (et, base) = self.unchecked_base(c, "get_unchecked")?;
                let syn::Expr::Range(r) = strip_paren(&c.args[1]) else { return Err("unchecked range expected".into()) };
                if !matches!(r.limits, syn::RangeLimits::HalfOpen(_)) {
                    return Err("`..=` ranges are not in the canonical dialect".into());
                }
                let lo = r.start.as_deref().map(|x| self.expr(x)).transpose()?.map(Box::new);
                let hi = r.end.as_deref().map(|x| self.expr(x)).transpose()?.map(Box::new);
                Ok(Unchecked::Range(self.e(ExprKind::SliceRange { base: Box::new(base), lo, hi }, Ty::slice_ref(et))))
            }
            syn::Expr::Call(c) => {
                let call = self.call_inner(c, true)?;
                match &call.kind {
                    ExprKind::Call { callee: Callee::Item(id, _), .. } if self.pv.fn_def(*id).is_some_and(|f| f.has_requires()) => Ok(Unchecked::Call(call)),
                    _ => Err("`unsafe` around a call of a function without `requires`".into()),
                }
            }
            _ => Err("`unsafe` block outside the generated-mode forms".into()),
        }
    }

    /// The base of `<[T]>::name(X, _)`: `X` is `(&B as &[T])` for an array
    /// place `B`, or `&B` for a slice place `B`. Returns `T` and `B`.
    fn unchecked_base(&mut self, c: &syn::ExprCall, name: &str) -> LR<(Ty, Expr)> {
        let syn::Expr::Path(p) = strip_paren(&c.func) else { return Err("malformed unchecked access".into()) };
        let q = p.qself.as_ref().ok_or("malformed unchecked access")?;
        let et = match self.ty(&q.ty)? {
            Ty::Slice(t) => *t,
            _ => return Err("malformed unchecked access".into()),
        };
        if !self.is_ufcs(p, name, &et)? || c.args.len() != 2 {
            return Err("malformed unchecked access".into());
        }
        let x = strip_paren(&c.args[0]);
        let base = match x {
            syn::Expr::Cast(cast) => {
                let syn::Expr::Reference(r) = strip_paren(&cast.expr) else { return Err("unchecked base must be `(&B as &[T])`".into()) };
                if r.mutability.is_some() || self.ty(&cast.ty)? != Ty::slice_ref(et.clone()) {
                    return Err("unchecked base must be `(&B as &[T])`".into());
                }
                let b = self.expr(&r.expr)?;
                if !matches!(&b.ty, Ty::Array(t, _) if **t == et) {
                    return Err("unchecked array base of another type".into());
                }
                b
            }
            syn::Expr::Reference(r) if r.mutability.is_none() => {
                let b = self.expr(&r.expr)?;
                if b.ty != Ty::Slice(Box::new(et.clone())) {
                    return Err("unchecked slice base of another type".into());
                }
                b
            }
            _ => return Err("malformed unchecked base".into()),
        };
        Ok((et, base))
    }

    fn path_expr(&mut self, p: &syn::ExprPath) -> LR<Expr> {
        if p.qself.is_some() {
            return Err("qualified path in value position".into());
        }
        if let Some(id) = p.path.get_ident() {
            let name = id.to_string();
            let (l, t) = self.use_local(&name)?;
            return Ok(self.e(ExprKind::Local(l), t));
        }
        let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
        if p.path.leading_colon.is_none() && segs.len() == 2
            && let Some(w) = UintTy::from_name(&segs[0])
        {
            // `u32::MAX` is the primitive's only if nothing in scope named
            // `u32` (a module with a `MAX`) takes the path
            self.check_primitive(&segs[0])?;
            if p.path.segments.iter().any(|s| !matches!(s.arguments, syn::PathArguments::None)) {
                return Err("generic arguments on an integer constant".into());
            }
            let (c, t) = match segs[1].as_str() {
                "MAX" => (BuiltinConst::Max(w), Ty::Uint(w)),
                "MIN" => (BuiltinConst::Min(w), Ty::Uint(w)),
                "BITS" => (BuiltinConst::Bits(w), Ty::u32()),
                _ => return Err("unknown integer constant".into()),
            };
            return Ok(self.e(ExprKind::BuiltinConst(c), t));
        }
        let joined = segs.join("::");
        if p.path.leading_colon.is_none()
            && let Some(id) = self.items.get(&joined).copied()
            && let ItemKind::Const(c) = &self.pv.item(id).kind
        {
            return Ok(self.e(ExprKind::Const(id), c.ty.clone()));
        }
        // unit constructors
        let (ctor, targs) = self.ctor_path(&p.path, false)?;
        let ty = self.adt_ty(ctor, &targs);
        if !self.ctor_field_tys(ctor, &ty)?.is_empty() {
            return Err("constructor used without its fields".into());
        }
        Ok(self.e(ExprKind::Adt { ctor, ty_args: targs, fields: vec![], base: None }, ty))
    }

    fn call(&mut self, c: &syn::ExprCall) -> LR<Expr> {
        self.call_inner(c, false)
    }

    fn call_inner(&mut self, c: &syn::ExprCall, in_unsafe: bool) -> LR<Expr> {
        let syn::Expr::Path(p) = strip_paren(&c.func) else { return Err("call of a non-path".into()) };
        let args = c.args.iter().map(|a| self.expr(a)).collect::<LR<Vec<_>>>()?;
        if let Some(q) = &p.qself {
            return self.ufcs_call(q, &p.path, args);
        }
        let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
        let joined = segs.join("::");
        // intrinsics
        if p.path.leading_colon.is_some() && segs.len() == 4 && segs[0] == "core" && segs[1] == "arch" {
            if segs[2] != self.arch.name() {
                return Err("intrinsic of another architecture".into());
            }
            let info = intrinsics::lookup(&self.arch, &segs[3]).ok_or_else(|| format!("unknown intrinsic `{}`", segs[3]))?;
            if info.pointer_args {
                return Err(format!("pointer-taking intrinsic `{}` outside the helpers", info.name));
            }
            let imms = const_args(&p.path.segments[3])?;
            if imms.len() != info.imms.len() || info.imms.iter().zip(&imms).any(|(r, v)| *v < r.lo || *v > r.hi) {
                return Err(format!("immediates of `{}`", info.name));
            }
            if args.len() != info.params.len() || args.iter().zip(&info.params).any(|(a, t)| a.ty != *t) {
                return Err(format!("arguments of `{}`", info.name));
            }
            return Ok(self.e(ExprKind::Call { callee: Callee::Intrinsic(info.id, imms), args }, info.ret.clone()));
        }
        // load/store helpers
        if p.path.leading_colon.is_none() && segs.len() == 4 && segs[0] == "crate" && segs[1] == "__sandblaster" && segs[2] == "__arch" {
            let h = intrinsics::lookup_helper(&self.arch, &segs[3]).ok_or_else(|| format!("unknown helper `{}`", segs[3]))?;
            let info = intrinsics::helper(h);
            if args.len() != info.params.len() || args.iter().zip(&info.params).any(|(a, t)| a.ty != *t) {
                return Err(format!("arguments of helper `{}`", info.name));
            }
            return Ok(self.e(ExprKind::Call { callee: Callee::Helper(h), args }, info.ret.clone()));
        }
        // checked-arithmetic helpers (E0): the checked primitive (an
        // `Erased` slot in generated mode), operands in order, at exactly
        // the helper's width
        if p.path.leading_colon.is_none() && segs.len() == 4 && segs[0] == "crate" && segs[1] == "__rt" && segs[2] == "chk" {
            let h = ChkHelper::parse(&segs[3]).ok_or_else(|| format!("unknown checked-arithmetic helper `{}`", segs[3]))?;
            if p.path.segments.iter().any(|s| !matches!(s.arguments, syn::PathArguments::None)) {
                return Err(format!("generic arguments on the checked-arithmetic helper `{}`", segs[3]));
            }
            if args.len() != 2 || args[0].ty != Ty::Uint(h.w) || args[1].ty != Ty::Uint(h.rhs()) {
                let got: Vec<String> = args.iter().map(|a| self.pv.ty_str(&a.ty)).collect();
                return Err(format!("arguments of `{}`: `({}, {})` expected, `({})` printed", h.name(), h.w.name(), h.rhs().name(), got.join(", ")));
            }
            self.chk.insert(h);
            let mut it = args.into_iter();
            let (a, b) = (it.next().unwrap(), it.next().unwrap());
            return Ok(self.e(ExprKind::Binary(h.bin_op(), Box::new(a), Box::new(b)), Ty::Uint(h.w)));
        }
        // user functions
        if p.path.leading_colon.is_none()
            && let Some(id) = self.items.get(&joined).copied()
            && let ItemKind::Fn(f) = &self.pv.item(id).kind
        {
            if f.has_requires() && !in_unsafe {
                return Err(format!("call of `{joined}` (which has `requires`) outside `unsafe`"));
            }
            let targs = type_args(p.path.segments.last().unwrap())?.iter().map(|t| self.ty(t)).collect::<LR<Vec<_>>>()?;
            if targs.len() != f.generics.len() {
                return Err(format!("type arguments of `{joined}`"));
            }
            // (the arguments of `#[ghost]` parameters are not printed)
            let vparams: Vec<&Param> = f.params.iter().filter(|p| !p.ghost).collect();
            if args.len() != vparams.len() || args.iter().zip(&vparams).any(|(a, p)| a.ty != p.ty.subst(&targs)) {
                return Err(format!("arguments of `{joined}`"));
            }
            let ret = f.ret.subst(&targs);
            return Ok(self.e(ExprKind::Call { callee: Callee::Item(id, targs), args }, ret));
        }
        // constructors
        let (ctor, targs) = self.ctor_path(&p.path, false)?;
        let ty = self.adt_ty(ctor, &targs);
        let ftys = self.ctor_field_tys(ctor, &ty)?;
        if args.len() != ftys.len() || args.iter().zip(&ftys).any(|(a, t)| a.ty != *t) {
            return Err("constructor arguments".into());
        }
        let fields = args.into_iter().enumerate().map(|(k, a)| (k as u32, a)).collect();
        Ok(self.e(ExprKind::Adt { ctor, ty_args: targs, fields, base: None }, ty))
    }

    /// `<Q>::name::<..>(args)`: builtin methods (§3.4) and methods of user
    /// types. The builtin's canonical spelling must print back exactly.
    fn ufcs_call(&mut self, q: &syn::QSelf, path: &syn::Path, args: Vec<Expr>) -> LR<Expr> {
        let qt = self.ty(&q.ty)?;
        let last = path.segments.last().ok_or("empty path")?;
        let name = last.ident.to_string();
        // user methods: `<crate::…::S<T>>::f::<U>`
        if let Ty::Adt(owner, oargs) = &qt {
            if q.position != 0 || path.segments.len() != 1 {
                return Err("malformed method path".into());
            }
            // rustc resolves a type-relative path on an enum to a variant of
            // that name before any associated function: `<E>::A(..)` with a
            // variant `A` constructs it (the printed enum's variants, and the
            // print view's, which `item_enum` compares with them)
            let oit = self.pv.item(*owner);
            let key = (self.pv.module(oit.module).path.0.iter().map(|x| clean(x).to_string()).collect::<Vec<_>>(), clean(&oit.name).to_string());
            let printed_variant = self.enums.get(&key).is_some_and(|vs| vs.iter().any(|(v, _)| *v == name));
            let view_variant = matches!(&oit.kind, ItemKind::Enum(e) if e.variants.iter().any(|v| clean(&v.name) == name));
            if printed_variant || view_variant {
                return Err(format!("`<{}>::{name}` names the variant `{name}` of the enum in rustc (in a type-relative path a variant comes before an associated function), not the method `{name}` (a capture)", toks(&q.ty).replace(' ', "")));
            }
            let id = self.pv.items.iter().find(|it| !it.ghost && clean(&it.name) == name && matches!(&it.kind, ItemKind::Fn(f) if f.owner == Some(*owner))).map(|it| it.id).ok_or_else(|| format!("unknown method `{name}`"))?;
            let f = self.pv.fn_def(id).unwrap();
            let own = type_args(last)?.iter().map(|t| self.ty(t)).collect::<LR<Vec<_>>>()?;
            let mut targs = oargs.clone();
            targs.extend(own);
            let vparams: Vec<&Param> = f.params.iter().filter(|p| !p.ghost).collect();
            if targs.len() != f.generics.len() || args.len() != vparams.len() || args.iter().zip(&vparams).any(|(a, p)| a.ty != p.ty.subst(&targs)) {
                return Err(format!("arguments of method `{name}`"));
            }
            if f.has_requires() {
                return Err(format!("call of `{name}` (which has `requires`) outside `unsafe`"));
            }
            let ret = f.ret.subst(&targs);
            return Ok(self.e(ExprKind::Call { callee: Callee::Item(id, targs), args }, ret));
        }
        let (b, targs) = match &qt {
            Ty::Uint(w) => (Builtin::Int(IntMethod::from_name(&name).ok_or_else(|| format!("unknown integer method `{name}`"))?, *w), vec![]),
            Ty::Slice(t) => {
                let n = const_args(last).ok().and_then(|v| v.first().copied()).map(|x| x as u64);
                let m = SliceMethod::from_name(&name, if SliceMethod::takes_const(&name) { n } else { None }).ok_or_else(|| format!("unknown slice method `{name}`"))?;
                (Builtin::Slice(m), vec![(**t).clone()])
            }
            Ty::Array(t, n) if name == "as_slice" => (Builtin::Array(ArrayMethod::AsSlice(*n)), vec![(**t).clone()]),
            Ty::Option(t) => (Builtin::Option(OptionMethod::from_name(&name).ok_or_else(|| format!("unknown Option method `{name}`"))?), vec![(**t).clone()]),
            _ => return Err(format!("method `{name}` on `{}`", self.pv.ty_str(&qt))),
        };
        // the spelling must be the canonical one
        let pt = |t: &Ty| crate::canon::type_text(self.pv, t);
        let want = b.path(&targs, &pt).ok_or("operator builtin in UFCS form")?;
        let got = format!("<{}{}>::{}", toks(&q.ty), if q.position > 0 { format!(" as {}", toks(&path_prefix(path, q.position))) } else { String::new() }, toks(&last_segment_path(path)));
        let norm = |s: &str| s.replace(' ', "");
        if norm(&got) != norm(&want) {
            return Err(format!("builtin spelled `{got}`, canonical `{want}`"));
        }
        let sig = b.sig(&targs);
        if args.len() != sig.params.len() || args.iter().zip(&sig.params).any(|(a, t)| a.ty != *t) {
            return Err(format!("arguments of `{want}`"));
        }
        Ok(self.e(ExprKind::Call { callee: Callee::Builtin(b, targs), args }, sig.ret))
    }
}

/// `unsafe { place = v; }` / `unsafe { place op= v; }` (an unchecked store,
/// printed without a trailing `;`).
fn is_unchecked_store(e: &syn::Expr) -> bool {
    let syn::Expr::Unsafe(u) = strip_paren(e) else { return false };
    match u.block.stmts.as_slice() {
        [syn::Stmt::Expr(syn::Expr::Assign(_), Some(_))] => true,
        [syn::Stmt::Expr(syn::Expr::Binary(b), Some(_))] => compound_op(&b.op).is_some(),
        _ => false,
    }
}

/// Whether a block ends in `continue;` (a tail-loop self-call candidate).
fn is_continue_shape(b: &syn::Block) -> bool {
    matches!(b.stmts.last(), Some(syn::Stmt::Expr(syn::Expr::Continue(_), _)))
}

/// The first `n` segments of a path (the trait of a qualified path).
fn path_prefix(p: &syn::Path, n: usize) -> syn::Path {
    let mut q = p.clone();
    q.segments = p.segments.iter().take(n).cloned().collect();
    q
}

/// The last segment of a path, as a path.
fn last_segment_path(p: &syn::Path) -> syn::Path {
    let mut q = p.clone();
    q.leading_colon = None;
    q.segments = p.segments.last().cloned().into_iter().collect();
    q
}

fn strip_paren(e: &syn::Expr) -> &syn::Expr {
    match e {
        syn::Expr::Paren(p) => strip_paren(&p.expr),
        syn::Expr::Group(g) => strip_paren(&g.expr),
        _ => e,
    }
}

fn bin_op(op: &syn::BinOp) -> Option<BinOp> {
    use syn::BinOp as B;
    Some(match op {
        B::Add(_) => BinOp::Add,
        B::Sub(_) => BinOp::Sub,
        B::Mul(_) => BinOp::Mul,
        B::Div(_) => BinOp::Div,
        B::Rem(_) => BinOp::Rem,
        B::And(_) => BinOp::And,
        B::Or(_) => BinOp::Or,
        B::BitXor(_) => BinOp::BitXor,
        B::BitAnd(_) => BinOp::BitAnd,
        B::BitOr(_) => BinOp::BitOr,
        B::Shl(_) => BinOp::Shl,
        B::Shr(_) => BinOp::Shr,
        B::Eq(_) => BinOp::Eq,
        B::Lt(_) => BinOp::Lt,
        B::Le(_) => BinOp::Le,
        B::Ne(_) => BinOp::Ne,
        B::Ge(_) => BinOp::Ge,
        B::Gt(_) => BinOp::Gt,
        _ => return None,
    })
}

fn compound_op(op: &syn::BinOp) -> Option<BinOp> {
    use syn::BinOp as B;
    Some(match op {
        B::AddAssign(_) => BinOp::Add,
        B::SubAssign(_) => BinOp::Sub,
        B::MulAssign(_) => BinOp::Mul,
        B::DivAssign(_) => BinOp::Div,
        B::RemAssign(_) => BinOp::Rem,
        B::BitXorAssign(_) => BinOp::BitXor,
        B::BitAndAssign(_) => BinOp::BitAnd,
        B::BitOrAssign(_) => BinOp::BitOr,
        B::ShlAssign(_) => BinOp::Shl,
        B::ShrAssign(_) => BinOp::Shr,
        _ => return None,
    })
}
