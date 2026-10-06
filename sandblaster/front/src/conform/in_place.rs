//! The lift conformance check of in-place lifted modules (DESIGN.md §2.1
//! "in place", §1.1 item 8).
//!
//! An in-place module is one of the host crate's own files: it names the
//! crate's other modules and its dependencies, so it cannot be compiled on
//! its own as the harness of an emitted module is. Its harness is instead
//! a **copy of the host crate** (every file under `src/`, byte for byte,
//! with the harness appended), built by `cargo` with the host's own
//! dependencies at the versions of the host workspace's `Cargo.lock`:
//!
//! * each in-place file gets a child module
//!   (`__sandblaster_conformance_access`) holding what needs the file's
//!   private items: the readers and writers of the data types it defines
//!   (their fields may be private) and the harness functions of the
//!   functions it defines (which may be private), each calling the
//!   original as the source spells it (`super::..`);
//! * the lowest common ancestor module of the in-place files gets the
//!   shared harness module (`__sandblaster_conformance`): the reader of
//!   the inputs, the writers of every other type, and `run`, which reads
//!   the cases file and calls each harness function; `run` is re-exported
//!   up to the crate root (`pub use`), where the harness binary calls it;
//! * the lifted crate is monomorphic at the declared instances of the open
//!   traits (`#[lift(in_place, instance = "Family: crate::mmr::Family")]`),
//!   the host's items are generic: the harness spells each generic data
//!   type of the in-place files (and of the host models' counterparts) at
//!   those instances, read from the source's generic parameters and their
//!   bounds, and substitutes the instances for the source's type
//!   parameters in the paths it writes;
//! * a host model (`#[lift(host)] mod host;` in the DSL module `m`) models
//!   the host's `m::Name` (the DSL re-exports it there, as the host does).
//!
//! The copy is built with the build's features (`CARGO_FEATURE_*`), with
//! overflow checks and debug assertions (cargo's `dev` profile), in its own
//! target directory beside the check's other files (a nested build of the
//! host crate: the copy has no build script, so it does not verify itself
//! again). The inputs, the kernel evaluations and the comparison are the
//! check's ([`super`]); the cache key also covers everything the copy
//! compiles or is configured by ([`host_inputs`]: every file under the
//! host's `src/`, the host manifest, the workspace lock and manifest, the
//! features, the files of every path dependency, cargo, its configuration
//! files and the environment that changes its build).

use super::*;

/// The shared harness module (in the lowest common ancestor module).
const COMMON: &str = HARNESS_MOD;
/// The per-file harness module (in each in-place file).
const ACCESS: &str = "__sandblaster_conformance_access";
/// The function the harness binary calls (re-exported to the crate root).
const RUN: &str = "__sandblaster_conformance_run";
/// Wall-clock limit of building the copy of the host crate (the first
/// build compiles the host's dependencies, and a dependency verified by
/// sandblaster in its own build script — commonware-codec for the storage
/// crate — is verified again in the copy's target directory; later builds
/// reuse that directory).
const BUILD_TIMEOUT: Duration = Duration::from_secs(4 * 3600);

/// How the harness of an in-place crate spells the source's items.
#[derive(Clone, Debug, Default)]
pub(super) struct Spell {
    /// Lifted module name → its module path in the host crate.
    modules: BTreeMap<String, Vec<String>>,
    /// The lowest common ancestor of the in-place modules: the home of the
    /// shared harness module.
    lca: Vec<String>,
    /// A generic data type (host path, `crate::a::b::Name`) → its type
    /// arguments at the declared instances (absolute paths).
    type_args: HashMap<String, Vec<String>>,
    /// A type parameter of the in-place files (`F`) → its instance.
    params: HashMap<String, String>,
    /// The names of the host-model modules (`host`).
    host_mods: HashSet<String>,
}

impl Spell {
    fn path_of(segs: &[String]) -> String {
        if segs.is_empty() { "crate".into() } else { format!("crate::{}", segs.join("::")) }
    }

    /// The path of the shared harness module.
    fn common(&self) -> String {
        format!("{}::{COMMON}", Self::path_of(&self.lca))
    }

    /// The path of the harness module of the in-place file at `segs`.
    fn access(segs: &[String]) -> String {
        format!("{}::{ACCESS}", Self::path_of(segs))
    }

    /// Whether `module` (a lifted path without `crate::`) is an in-place module.
    fn in_place_module(&self, module: &str) -> Option<&Vec<String>> {
        self.modules.values().find(|s| s.join("::") == module)
    }

    /// Substitutes the instances for the source's type parameters in a
    /// type or path as the source writes it (`Position<F>` →
    /// `Position<crate::mmr::Family>`).
    fn subst(&self, written: &str) -> String {
        let Ok(mut t) = syn::parse_str::<syn::Type>(written) else { return written.to_string() };
        struct S<'a>(&'a HashMap<String, String>);
        impl syn::visit_mut::VisitMut for S<'_> {
            fn visit_type_mut(&mut self, t: &mut syn::Type) {
                if let syn::Type::Path(p) = t
                    && p.qself.is_none()
                    && p.path.leading_colon.is_none()
                    && p.path.segments.len() == 1
                    && matches!(p.path.segments[0].arguments, syn::PathArguments::None)
                    && let Some(inst) = self.0.get(&p.path.segments[0].ident.to_string())
                    && let Ok(n) = syn::parse_str::<syn::Type>(inst)
                {
                    *t = n;
                    return;
                }
                syn::visit_mut::visit_type_mut(self, t);
            }
        }
        syn::visit_mut::VisitMut::visit_type_mut(&mut S(&self.params), &mut t);
        // a generic data type written without its arguments (`Position` in
        // `impl<F: Family> From<Location<F>> for Position<F>`, as the lift
        // records the self type) gets its instance arguments
        struct A<'a>(&'a HashMap<String, Vec<String>>);
        impl syn::visit_mut::VisitMut for A<'_> {
            fn visit_type_path_mut(&mut self, p: &mut syn::TypePath) {
                syn::visit_mut::visit_type_path_mut(self, p);
                let Some(last) = p.path.segments.last_mut() else { return };
                if !matches!(last.arguments, syn::PathArguments::None) {
                    return;
                }
                let name = last.ident.to_string();
                let mut hits = self.0.iter().filter(|(k, _)| k.rsplit("::").next() == Some(name.as_str()));
                if let (Some((_, args)), None) = (hits.next(), hits.next())
                    && let Ok(a) = syn::parse_str::<syn::AngleBracketedGenericArguments>(&format!("<{}>", args.join(", ")))
                {
                    last.arguments = syn::PathArguments::AngleBracketed(a);
                }
            }
        }
        syn::visit_mut::VisitMut::visit_type_mut(&mut A(&self.type_args), &mut t);
        quote::ToTokens::to_token_stream(&t).to_string().replace(' ', "")
    }
}

/// `written` (a type) with every host model's DSL path replaced by the
/// library type rustc's MIR has for it (`LiftFacts::mir_host_types`).
fn real_paths(written: &str, host_types: &[(String, String, Option<String>)]) -> String {
    let Ok(mut t) = syn::parse_str::<syn::Type>(written) else { return written.to_string() };
    struct R<'a>(&'a [(String, String, Option<String>)]);
    impl syn::visit_mut::VisitMut for R<'_> {
        fn visit_type_mut(&mut self, t: &mut syn::Type) {
            if let syn::Type::Path(p) = t
                && p.qself.is_none()
            {
                let s = quote::ToTokens::to_token_stream(&p.path).to_string().replace(' ', "");
                if let Some((_, r, _)) = self.0.iter().find(|(d, _, _)| *d == s)
                    && let Ok(n) = syn::parse_str::<syn::Type>(r)
                {
                    *t = n;
                    return;
                }
            }
            syn::visit_mut::visit_type_mut(self, t);
        }
    }
    syn::visit_mut::VisitMut::visit_type_mut(&mut R(host_types), &mut t);
    quote::ToTokens::to_token_stream(&t).to_string().replace(' ', "")
}

/// The module path of a host source file (relative to `src/`):
/// `a/b.rs` and `a/b/mod.rs` are `a::b`, `lib.rs` the crate root.
fn module_segments(rel: &Path) -> Option<Vec<String>> {
    let comps: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    let (last, dir) = comps.split_last()?;
    let mut segs = dir.to_vec();
    match last.as_str() {
        "lib.rs" if dir.is_empty() => {}
        "mod.rs" if !dir.is_empty() => {}
        // `src/mod.rs` declares no module of its own
        "mod.rs" => return None,
        f => segs.push(f.strip_suffix(".rs")?.to_string()),
    }
    Some(segs)
}

/// The file of the host module `segs` (under `src`): `a/b.rs`, else
/// `a/b/mod.rs`; `lib.rs` for the crate root.
fn module_file(src: &Path, segs: &[String]) -> Option<PathBuf> {
    if segs.is_empty() {
        let p = src.join("lib.rs");
        return p.exists().then_some(p);
    }
    let (last, dir) = segs.split_last()?;
    let base = dir.iter().fold(src.to_path_buf(), |p, c| p.join(c));
    [base.join(format!("{last}.rs")), base.join(last).join("mod.rs")].into_iter().find(|p| p.exists())
}

/// The type arguments of the generic data types of `text` at the declared
/// instances (`trait` → instance, matched by the bound's last segment):
/// `(name, arguments)`, and each type parameter's instance.
fn instance_args(text: &str, inst: &[(String, String)], out: &mut Vec<(String, Vec<String>)>, params: &mut HashMap<String, String>) {
    let Ok(file) = syn::parse_file(text) else { return };
    let inst_of = |b: &syn::TypeParamBound| -> Option<String> {
        let syn::TypeParamBound::Trait(t) = b else { return None };
        let last = t.path.segments.last()?.ident.to_string();
        inst.iter().find(|(tr, _)| tr.rsplit("::").next() == Some(last.as_str())).map(|(_, p)| p.clone())
    };
    let mut visit = |ident: Option<&syn::Ident>, g: &syn::Generics, params: &mut HashMap<String, String>| {
        let mut args = Vec::new();
        for p in &g.params {
            match p {
                syn::GenericParam::Type(tp) => {
                    let mut found = tp.bounds.iter().find_map(inst_of);
                    if found.is_none()
                        && let Some(w) = &g.where_clause
                    {
                        for pred in &w.predicates {
                            if let syn::WherePredicate::Type(pt) = pred
                                && quote::ToTokens::to_token_stream(&pt.bounded_ty).to_string() == tp.ident.to_string()
                            {
                                found = found.or_else(|| pt.bounds.iter().find_map(inst_of));
                            }
                        }
                    }
                    match found {
                        Some(i) => {
                            params.entry(tp.ident.to_string()).or_insert_with(|| i.clone());
                            args.push(i);
                        }
                        None => return,
                    }
                }
                // lifetimes and const parameters: not an instance the lift declares
                _ => return,
            }
        }
        if let Some(ident) = ident
            && !args.is_empty()
        {
            out.push((ident.to_string(), args));
        }
    };
    for item in &file.items {
        match item {
            syn::Item::Struct(s) => visit(Some(&s.ident), &s.generics, params),
            syn::Item::Enum(e) => visit(Some(&e.ident), &e.generics, params),
            // a trait generic over an open trait (`Hasher<F: Family>`):
            // `<S as Hasher>::m` is called at the instance (`Hasher<mmr::Family>`)
            syn::Item::Trait(t) => visit(Some(&t.ident), &t.generics, params),
            syn::Item::Impl(i) => visit(None, &i.generics, params),
            syn::Item::Fn(f) => visit(None, &f.sig.generics, params),
            _ => {}
        }
    }
}

/// The checkers of the preconditions of the entries' functions
/// (`f__req(x̄) -> bool`, the mutation engine's: `crate::mutate::clone`),
/// added to a copy of the crate: the copy, each function's checker, and
/// for a function with a panic contract the checker of its domain (its
/// `requires` before the no-panic clause, `f__dom`; `None`: every input).
#[allow(clippy::type_complexity)]
fn precondition_checkers(krate: &Crate, entries: &[&ConformEntry]) -> (Crate, HashMap<ItemId, ItemId>, HashMap<ItemId, Option<ItemId>>) {
    let mut k = krate.clone();
    let (mut map, mut dom) = (HashMap::new(), HashMap::new());
    let add = |k: &mut Crate, id: ItemId, suffix: &str, chk: FnDef| {
        let it = krate.item(id);
        let nid = ItemId(k.items.len() as u32);
        k.items.push(Item { id: nid, name: format!("{}{suffix}", it.name), path: crate::mutate::clone::clone_path(&it.path, suffix), module: it.module, vis: Vis::Private, ghost: true, span: it.span, docs: vec![], allow: vec![], cfg: None, kind: ItemKind::Fn(chk) });
        nid
    };
    for e in entries {
        let Some(id) = krate.find(&e.lifted) else { continue };
        let Some(f) = krate.fn_def(id) else { continue };
        if f.requires.is_empty() {
            continue;
        }
        let Some(chk) = crate::mutate::clone::requires_checker(f) else { continue };
        let nid = add(&mut k, id, "__req", chk);
        map.insert(id, nid);
        if let Some(np) = f.nopanic_clause() {
            let mut fd = f.clone();
            fd.requires.truncate(np);
            fd.panics = false;
            match (np, crate::mutate::clone::requires_checker(&fd)) {
                (0, _) => {
                    dom.insert(id, None);
                }
                (_, Some(chk)) => {
                    let did = add(&mut k, id, "__dom", chk);
                    dom.insert(id, Some(did));
                }
                _ => {}
            }
        }
    }
    (k, map, dom)
}

/// Elaborates the checkers (and what they refer to) of the copy `k`.
fn elaborate_checkers(k: &Crate, checkers: &[(ItemId, ItemId)]) -> elab::Output {
    let mut filter: std::collections::BTreeSet<ItemId> = std::collections::BTreeSet::new();
    let mut work: Vec<ItemId> = checkers.iter().map(|c| c.1).collect();
    while let Some(x) = work.pop() {
        if filter.insert(x) {
            work.extend(elab::order::refs(k, x));
        }
    }
    let opts = elab::Options { items: Some(std::sync::Arc::new(filter)), ..elab::Options::default() };
    let mut chain = elab::ProverChain::standard();
    elab::elaborate(k, &mut chain, &opts)
}

impl Gen<'_> {
    /// Whether `args` meet the precondition of `p`'s function (its checker
    /// `chk`, evaluated by the kernel in the checkers' environment).
    pub(super) fn meets_pre(&self, chk: GlobalId, p: &Plan<'_>, args: &[J]) -> Result<bool, String> {
        let Some(pre) = self.pre_out else { return Err("no precondition checkers".into()) };
        let conv = Conv { env: &pre.env, krate: self.krate, adts: &pre.adts };
        let mut tms: Vec<(Rel, Tm)> = Vec::new();
        for (t, j) in p.params.iter().zip(args) {
            tms.push((Rel::Rel, conv.term(t, j)?));
        }
        let term = mk::apps(mk::global(chk), tms);
        let v = crate::driver::stage::eval_reference(&pre.env, &term, STEPS)?;
        match conv.json(&Ty::Bool, &v)? {
            J::Bool(b) => Ok(b),
            other => Err(format!("the precondition checker gave {}", other.render())),
        }
    }

    /// The in-place spelling of a data type (`None`: not in-place mode, or
    /// a type the common rules spell).
    pub(super) fn ip_adt_paths(&self, id: ItemId, args: &[Ty]) -> Option<Result<(String, String), String>> {
        let ip = self.ip.as_ref()?;
        let item = self.krate.item(id);
        let path = item.path.to_string();
        let name = item.name.clone();
        if path == "crate::__lift::Ordering" {
            return Some(Ok(("::core::cmp::Ordering".into(), "::core::cmp::Ordering".into())));
        }
        // the lift prelude's `Range<T>` is core's (its `start`/`end` fields, §19.10)
        if path == "crate::__lift::Range" {
            let targs = match args.iter().map(|a| self.rust_ty(a)).collect::<Result<Vec<_>, _>>() {
                Ok(a) => a,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok((format!("::core::ops::Range<{}>", targs.join(", ")), format!("::core::ops::Range::<{}>", targs.join(", ")))));
        }
        let module = path.strip_prefix("crate::")?.rsplit_once("::").map(|(m, _)| m.to_string()).unwrap_or_default();
        let generic = |host: &str| -> Result<(String, String), String> {
            let targs: Vec<String> = match ip.type_args.get(host) {
                Some(a) => a.clone(),
                None => args.iter().map(|a| self.rust_ty(a)).collect::<Result<Vec<_>, _>>()?,
            };
            Ok(if targs.is_empty() { (host.to_string(), host.to_string()) } else { (format!("{host}<{}>", targs.join(", ")), format!("{host}::<{}>", targs.join(", "))) })
        };
        if ip.in_place_module(&module).is_some() {
            return Some(generic(&path));
        }
        // a host model (`m::host::Name` models the host's `m::Name`)
        if let Some((parent, last)) = module.rsplit_once("::").map(|(p, l)| (p.to_string(), l.to_string())).or_else(|| Some((String::new(), module.clone())))
            && ip.host_mods.contains(&last)
        {
            let host = if parent.is_empty() { format!("crate::{name}") } else { format!("crate::{parent}::{name}") };
            return Some(generic(&host));
        }
        None
    }

    /// Whether the data type `id` is a host model's (in an in-place harness:
    /// its Rust counterpart is the host's own type).
    pub(super) fn ip_host_model(&self, id: ItemId) -> bool {
        let Some(ip) = &self.ip else { return false };
        let path = self.krate.item(id).path.to_string();
        path.strip_prefix("crate::").and_then(|p| p.rsplit_once("::")).map(|(m, _)| m.rsplit("::").next().unwrap_or(m)).is_some_and(|last| ip.host_mods.contains(last))
    }

    /// The module that holds the reader and writer of `t` in an in-place
    /// harness: the file that defines a data type of an in-place module
    /// (its fields may be private there), else the shared module; empty
    /// outside in-place mode.
    pub(super) fn ip_home(&self, t: &Ty) -> String {
        let Some(ip) = &self.ip else { return String::new() };
        if let Ty::Adt(id, _) = t.peel_refs() {
            let path = self.krate.item(*id).path.to_string();
            if let Some(module) = path.strip_prefix("crate::").and_then(|p| p.rsplit_once("::")).map(|(m, _)| m)
                && let Some(segs) = ip.in_place_module(module)
            {
                return Spell::access(segs);
            }
        }
        ip.common()
    }

    /// The harness's conversion `__cv` (an in-place harness with library
    /// newtypes of host models, [`newtype_code`]): an argument of a type
    /// holding an array is passed through it (the identity, or the newtype's
    /// constructor where the original takes the library type).
    pub(super) fn ip_cv(&self, t: &Ty) -> Option<String> {
        let ip = self.ip.as_ref()?;
        fn has_array(t: &Ty) -> bool {
            match t {
                Ty::Array(..) => true,
                Ty::Ref(x) | Ty::Option(x) | Ty::Seq(x) | Ty::Slice(x) => has_array(x),
                Ty::Tuple(ts) => ts.iter().any(has_array),
                _ => false,
            }
        }
        (has_array(t) && self.c.lift_facts.mir_host_types.iter().any(|x| x.2.is_some())).then(|| format!("{}::__cv", ip.common()))
    }

    /// Whether `t` is the lift prelude's `PhantomData`.
    pub(super) fn is_phantom(&self, t: &Ty) -> bool {
        matches!(t.peel_refs(), Ty::Adt(id, _) if self.krate.item(*id).path.to_string() == "crate::__lift::PhantomData")
    }

    /// Whether a struct of this path is one of the checked modules' own
    /// (its produced values are candidate inputs).
    pub(super) fn own_type(&self, path: &str) -> bool {
        match &self.ip {
            Some(ip) => path.strip_prefix("crate::").and_then(|p| p.rsplit_once("::")).is_some_and(|(m, _)| ip.in_place_module(m).is_some()),
            None => path.starts_with(&format!("crate::{}::", self.module)),
        }
    }

    /// The harness's expression for the original of `e` in an in-place
    /// harness (it is called from the harness module of its own file):
    /// the source's spelling with the instances for its type parameters.
    pub(super) fn ip_callee(&self, e: &ConformEntry) -> Option<Result<String, String>> {
        let ip = self.ip.as_ref()?;
        let segs = ip.modules.get(&e.module)?;
        let q = |x: &str| self.qualify_src_ty(&ip.subst(x));
        let turbofish = |g: Vec<String>| if g.is_empty() { String::new() } else { format!("::<{}>", g.join(", ")) };
        Some(match &e.callee {
            ConformCallee::Free { modpath, name, generics } => {
                if !modpath.is_empty() {
                    return Some(Err(format!("the function is in the inline module `{}` (not visible to the harness; it is checked through its callers)", modpath.join("::"))));
                }
                Ok(format!("super::{name}{}", turbofish(generics.iter().map(|x| q(x)).collect())))
            }
            ConformCallee::Inherent { base, generics, method, .. } => {
                let g = if generics.is_empty() { ip.type_args.get(&format!("{}::{base}", Spell::path_of(segs))).cloned().unwrap_or_default() } else { generics.iter().map(|x| q(x)).collect() };
                Ok(format!("super::{base}{}::{method}", turbofish(g)))
            }
            ConformCallee::Trait { modpath, self_ty, trait_path, method } => match self.qualify_trait(&ip.subst(trait_path), modpath) {
                Ok(tr) => Ok(format!("<{} as {tr}>::{method}", q(self_ty))),
                Err(e) => Err(e),
            },
        })
    }
}

/// Runs the check for the in-place lifted modules `infos` of the checked
/// crate `c` on its elaboration `out`: one harness, a copy of the host
/// crate (module docs).
pub fn check_in_place(out: &mut elab::Output, krate: &Crate, c: &Checked, infos: &[&LiftedInfo], cfg: &Config) -> Report {
    let t0 = Instant::now();
    let mut rep = Report { edition: cfg.edition.clone(), ..Default::default() };
    if let Some(h) = c.lift_facts.test_hook {
        rep.notes.push(format!("the lift ran with the test hook `{h:?}` (a deliberately wrong rule)"));
    }
    let done = |mut rep: Report| {
        rep.elapsed = t0.elapsed();
        rep
    };
    let Some(manifest) = cfg.manifest_dir.clone() else {
        rep.errors.push("the in-place modules' harness is a copy of the host crate, and no host crate directory was given (the check runs in a build: `compile_lifted`)".into());
        return done(rep);
    };
    let abs = |p: &Path| crate::loader::normalize(&std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()));
    let src_dir = abs(&manifest.join("src"));
    // the in-place files: their host module paths
    let mut ip = Spell { host_mods: c.lifted.iter().filter(|l| l.host).map(|l| l.name.rsplit("::").next().unwrap_or(&l.name).to_string()).collect(), ..Default::default() };
    let mut files: Vec<(Vec<String>, PathBuf, String)> = Vec::new();
    for info in infos {
        let path = abs(c.sm.path(info.file));
        let Some(segs) = path.strip_prefix(&src_dir).ok().and_then(module_segments) else {
            rep.errors.push(format!("the in-place module `{}` reads `{}`, which is not a module file under `{}`", info.name, path.display(), src_dir.display()));
            return done(rep);
        };
        let Some(text) = c.sm.get(info.file).map(|f| f.text.clone()) else {
            rep.errors.push(format!("the source of `{}` is not in the source map", info.name));
            return done(rep);
        };
        if text.contains(COMMON) {
            rep.errors.push(format!("the source of `{}` mentions `{COMMON}`, the harness module's name", info.name));
            return done(rep);
        }
        ip.modules.insert(info.name.clone(), segs.clone());
        files.push((segs, path, text));
    }
    if files.is_empty() {
        return done(rep);
    }
    // the lowest common ancestor module
    let mut lca = files[0].0.clone();
    for (s, _, _) in &files[1..] {
        let n = lca.iter().zip(s).take_while(|(a, b)| a == b).count();
        lca.truncate(n);
    }
    ip.lca = lca;
    // the instances: the generic data types of the in-place files and of
    // the host models' counterparts
    let mut targs: Vec<(String, Vec<String>)> = Vec::new();
    for (segs, _, text) in &files {
        let mut found = Vec::new();
        instance_args(text, &c.lift_facts.open_instances, &mut found, &mut ip.params);
        for (n, a) in found {
            targs.push((format!("{}::{n}", Spell::path_of(segs)), a));
        }
    }
    for item in krate.items.iter() {
        let path = item.path.to_string();
        let Some((module, _)) = path.strip_prefix("crate::").and_then(|p| p.rsplit_once("::")) else { continue };
        let (parent, last) = module.rsplit_once("::").unwrap_or(("", module));
        if !ip.host_mods.contains(last) || targs.iter().any(|(k, _)| k.ends_with(&format!("::{}", item.name))) {
            continue;
        }
        let psegs: Vec<String> = parent.split("::").filter(|s| !s.is_empty()).map(str::to_string).collect();
        if let Some(f) = module_file(&src_dir, &psegs)
            && let Ok(text) = std::fs::read_to_string(&f)
        {
            let mut found = Vec::new();
            instance_args(&text, &c.lift_facts.open_instances, &mut found, &mut HashMap::new());
            for (n, a) in found.into_iter().filter(|(n, _)| *n == item.name) {
                targs.push((format!("{}::{n}", Spell::path_of(&psegs)), a));
            }
        }
    }
    // a host model's path is the library type rustc's MIR has for it
    // (`crate::merkle::host::Sha256` → `::commonware_cryptography::Sha256`)
    let host_types = &c.lift_facts.mir_host_types;
    for (_, a) in targs.iter_mut() {
        for x in a.iter_mut() {
            *x = real_paths(x, host_types);
        }
    }
    for v in ip.params.values_mut() {
        *v = real_paths(v, host_types);
    }
    ip.type_args = targs.into_iter().collect();
    // the entries
    let names: HashSet<&str> = infos.iter().map(|i| i.name.as_str()).collect();
    // (a function returning `impl Trait` is compared only on its panic
    // contract's panic region: without one it is reported as skipped)
    let has_panic_contract = |e: &ConformEntry| krate.find(&e.lifted).and_then(|id| krate.fn_def(id)).is_some_and(|f| f.nopanic_clause().is_some());
    let entries: Vec<&ConformEntry> = c.lift_facts.conform.iter().filter(|e| names.contains(e.module.as_str()) && (!e.opaque_ret || has_panic_contract(e))).collect();
    for sk in c.lift_facts.conform_skipped.iter().filter(|s| names.contains(s.module.as_str())) {
        rep.entries.push(EntryReport { lifted: sk.lifted.clone(), callee: "(none)".into(), skipped: Some(sk.why.clone()), ..Default::default() });
    }
    for e in c.lift_facts.conform.iter().filter(|e| names.contains(e.module.as_str()) && e.opaque_ret && !has_panic_contract(e)) {
        rep.entries.push(EntryReport { lifted: e.lifted.clone(), callee: "(none)".into(), skipped: Some(super::OPAQUE_SKIP.into()), ..Default::default() });
    }
    // rustc (the key and the report) and cargo
    let rv = match Command::new(&cfg.rustc).arg("-vV").output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            rep.errors.push(format!("`{} -vV` failed: {}", cfg.rustc.display(), String::from_utf8_lossy(&o.stderr).trim()));
            return done(rep);
        }
        Err(e) => {
            rep.errors.push(format!("cannot run `{}`: {e}", cfg.rustc.display()));
            return done(rep);
        }
    };
    rep.rustc = rv.lines().find_map(|l| l.strip_prefix("release: ")).unwrap_or("?").to_string();
    let HostInputs { host, tree, text: host_text, .. } = match host_inputs(cfg) {
        Ok(h) => h,
        Err(e) => {
            rep.errors.push(e);
            return done(rep);
        }
    };
    // the cache key: the check, the toolchain, everything the copy compiles
    // or is configured by ([`host_inputs`]), the DSL crate's items
    let mut k = format!("{VERSION} in-place\ntoolchain {}\nedition {}\nrustc {}\n", hex(&sha256(cfg.toolchain_id.as_bytes())), cfg.edition, hex(&sha256(rv.as_bytes())));
    k.push_str(&host_text);
    for l in c.lifted.iter().filter(|l| l.host) {
        k.push_str(&format!("host {} {}\n", l.name, hex(&sha256(c.sm.get(l.file).map(|f| f.text.as_bytes()).unwrap_or_default()))));
    }
    k.push_str(&format!("entries {}\n", hex(&sha256(format!("{entries:?}{:?}{:?}{:?}{:?}", c.lift_facts.instances, c.lift_facts.open_instances, c.lift_facts.test_hook, c.lift_facts.mir_host_types).as_bytes()))));
    k.push_str(&format!("budget {INITIAL} {EVALS} {ROUNDS} {STEPS} {SEED} {}\n", super::LITERAL_CASES));
    k.push_str(&super::literal_key(c));
    k.push_str(&super::items_key(krate));
    rep.key = hex(&sha256(k.as_bytes()));
    let key_path = cfg.work_dir.join("conformance.key");
    if let Some(r) = super::recorded_pass(c, &key_path, &rep.key) {
        r.replay(&mut rep);
        rep.cached = true;
        return done(rep);
    }
    let _ = std::fs::remove_file(&key_path);
    if let Err(e) = std::fs::create_dir_all(&cfg.work_dir) {
        rep.errors.push(format!("cannot create `{}`: {e}", cfg.work_dir.display()));
        return done(rep);
    }
    // the precondition checkers (a filtered elaboration of a copy of the crate)
    let (pk, pmap, dmap) = precondition_checkers(krate, &entries);
    let pre_out = if pmap.is_empty() { None } else { Some(elaborate_checkers(&pk, &pmap.iter().map(|(a, b)| (*a, *b)).chain(dmap.iter().filter_map(|(a, b)| Some((*a, (*b)?)))).collect::<Vec<_>>())) };
    // the literal reading of every function read from MIR (amendment (f))
    let lits = super::literal::prepare(out, c, &entries, &mut rep);
    let first = infos[0];
    let mut g = Gen::new(out, krate, c, first);
    g.ip = Some(ip);
    if let Some(po) = &pre_out {
        for (f, chk) in &pmap {
            if let Some(&gl) = po.fn_globals.get(chk) {
                g.pre.insert(*f, gl);
            } else {
                rep.notes.push(format!("the precondition checker of `{}` did not elaborate: it is checked through its callers", krate.item(*f).path));
            }
        }
        // (a panic contract's domain: its panic region is compared too)
        for (f, d) in &dmap {
            match d.map(|d| po.fn_globals.get(&d).copied()) {
                None => {
                    g.pre_dom.insert(*f, None);
                }
                Some(Some(gl)) => {
                    g.pre_dom.insert(*f, Some(gl));
                }
                Some(None) => rep.notes.push(format!("the domain checker of `{}`'s panic contract did not elaborate: its panics are not compared with rustc", krate.item(*f).path)),
            }
        }
        g.pre_out = Some(po);
    }
    let plans = g.plans(&entries, &mut rep);
    let cases = g.run(&plans, &mut rep);
    rep.cases = cases.len();
    if rep.errors.is_empty() {
        match harness_in_place(&g, &plans, &cases, &files, &tree, &host, cfg) {
            Ok(outputs) => {
                let rustc = compare(&g, &plans, &cases, &outputs, &mut rep);
                let panics = super::literal::compare(&g, &plans, &cases, &rustc, &lits, &mut rep);
                super::panic_coverage(krate, &entries, &panics, &mut rep);
            }
            Err(e) => rep.errors.push(e),
        }
    }
    let rep = done(rep);
    if rep.passed() {
        super::record_pass(c, &key_path, &rep);
    }
    rep
}

/// The host side of an in-place check's inputs ([`host_inputs`]).
pub struct HostInputs {
    host: HostCrate,
    /// Every file under the host's `src/` (relative path, bytes).
    tree: Vec<(PathBuf, Vec<u8>)>,
    /// One line per input (part of the check's key and of the in-place
    /// verdict key, `driver::in_place`).
    pub text: String,
    /// The paths a build script watches so that an edit of an input outside
    /// the host crate re-runs it (`cargo::rerun-if-changed`): the workspace
    /// manifest and lock, and the top-level entries of every path
    /// dependency that its digest reads.
    pub watch: Vec<PathBuf>,
}

/// Everything the harness — a copy of the host crate, built by `cargo` —
/// compiles or is configured by, besides the toolchain and `rustc` (which
/// the keys cover through the verifier context): every file under the
/// host's `src/`, the copy's manifest (the host's dependencies and
/// features, from `cargo metadata`), the workspace lock and manifest, the
/// features the copy enables, the files of every **path dependency** in the
/// closure of the host's normal and build dependencies (the copy compiles
/// them from their current sources; every file of the package directory
/// but the top-level `tests/`, `benches/`, `examples/` and `target/`,
/// nested packages, dot files and documents nothing includes, as the
/// toolchain identity reads the toolchain's own crates
/// ([`package_digest`]) — registry dependencies are pinned by the lock),
/// `cargo -V`, the cargo configuration files that apply to the copy's
/// build, and the environment variables that change how cargo builds it
/// (`RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_PROFILE_*`,
/// `CARGO_BUILD_*` but the job count, `CARGO_TARGET_*` but the target
/// directory, `CARGO_UNSTABLE_*`, `RUSTC_BOOTSTRAP`; [`Config::build_env`]).
pub fn host_inputs(cfg: &Config) -> Result<HostInputs, String> {
    let manifest = cfg.manifest_dir.clone().ok_or("the in-place modules' harness is a copy of the host crate, and no host crate directory was given (the check runs in a build: `compile_lifted`)")?;
    let host = HostCrate::read(cfg, &manifest)?;
    let src_dir = crate::loader::normalize(&std::path::absolute(manifest.join("src")).unwrap_or_else(|_| manifest.join("src")));
    let mut tree = Vec::new();
    walk(&src_dir, &src_dir, &mut tree)?;
    let mut watch: Vec<PathBuf> = vec![manifest.join("Cargo.toml")];
    watch.extend([host.ws_root.join("Cargo.toml"), host.ws_root.join("Cargo.lock")]);
    let mut t = String::new();
    for (rel, bytes) in &tree {
        t.push_str(&format!("src {} {}\n", rel.display(), hex(&sha256(bytes))));
    }
    t.push_str(&format!("manifest {}\nlock {}\nfeatures {:?}\nworkspace-manifest {}\n", hex(&sha256(host.manifest.as_bytes())), hex(&sha256(host.lock.as_bytes())), host.features, hex(&sha256(host.ws_manifest.as_bytes()))));
    for (dir, name) in &host.path_deps {
        t.push_str(&format!("path-dep {name} {} {}\n", dir.display(), package_digest(dir, &mut watch)?));
    }
    let cv = Command::new(&cfg.cargo).arg("-V").env_remove("RUSTC_WRAPPER").output().map_err(|e| format!("cannot run `{} -V`: {e}", cfg.cargo.display()))?;
    t.push_str(&format!("cargo {}\n", hex(&sha256(&cv.stdout))));
    for f in cargo_configs(&cfg.work_dir.join("crate")) {
        if let Ok(bytes) = std::fs::read(&f) {
            t.push_str(&format!("cargo-config {} {}\n", f.display(), hex(&sha256(&bytes))));
        }
    }
    let mut env: Vec<&(String, String)> = cfg.build_env.iter().filter(|(k, _)| affects_cargo(k)).collect();
    env.sort();
    for (k, v) in env {
        t.push_str(&format!("env {k} {}\n", hex(&sha256(v.as_bytes()))));
    }
    watch.retain(|p| p.exists());
    Ok(HostInputs { host, tree, text: t, watch })
}

/// Whether the environment variable `k` changes how cargo builds the copy
/// ([`host_inputs`]; a job count or a target directory only changes where
/// and how fast).
pub fn affects_cargo(k: &str) -> bool {
    matches!(k, "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS" | "RUSTC_BOOTSTRAP")
        || k.starts_with("CARGO_PROFILE_")
        || k.starts_with("CARGO_UNSTABLE_")
        || (k.starts_with("CARGO_BUILD_") && k != "CARGO_BUILD_JOBS")
        || (k.starts_with("CARGO_TARGET_") && k != "CARGO_TARGET_DIR")
}

/// The cargo configuration files that apply to a build run in `dir`:
/// `.cargo/config.toml` and `.cargo/config` in `dir` and each ancestor,
/// and in `$CARGO_HOME` (else `~/.cargo`).
fn cargo_configs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let abs = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut d = Some(abs.as_path());
    while let Some(x) = d {
        for n in ["config.toml", "config"] {
            out.push(x.join(".cargo").join(n));
        }
        d = x.parent();
    }
    if let Some(home) = std::env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo"))) {
        for n in ["config.toml", "config"] {
            out.push(home.join(n));
        }
    }
    out.into_iter().filter(|p| p.is_file()).collect()
}

/// The digest of a path dependency's package directory ([`host_inputs`]):
/// every file by relative path, length and SHA-256, but the top-level
/// `tests/`, `benches/`, `examples/` and `target/`, dot files, nested
/// packages (a directory with its own `Cargo.toml`: a dependency on it is
/// in the closure on its own) and documents (`*.md`) — then every file a
/// hashed Rust file names by a literal path (`include_str!("..")`,
/// `include_bytes!("..")`, `include!("..")`, `#[path = ".."]`) that is not
/// hashed already, such as a `README.md` a crate's docs include. That is
/// the toolchain identity's recipe (the facade's `toolchain_id.rs`), so a
/// document or test edit in a path dependency (the sandblaster crates are
/// one, through the build dependency) keeps the verdict. The top-level
/// entries it reads, and the included files, are added to `watch`.
pub fn package_digest(dir: &Path, watch: &mut Vec<PathBuf>) -> Result<String, String> {
    fn go(base: &Path, dir: &Path, top: bool, files: &mut Vec<(String, PathBuf, Vec<u8>)>, watch: &mut Vec<PathBuf>) -> Result<(), String> {
        let mut ents: Vec<PathBuf> = std::fs::read_dir(dir).map_err(|e| format!("cannot list `{}`: {e}", dir.display()))?.flatten().map(|e| e.path()).collect();
        ents.sort();
        for p in ents {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if name.starts_with('.') || (top && matches!(name.as_str(), "tests" | "benches" | "examples" | "target")) {
                continue;
            }
            let md = std::fs::metadata(&p).map_err(|e| format!("cannot stat `{}`: {e}", p.display()))?;
            if md.is_dir() {
                if !p.join("Cargo.toml").is_file() {
                    if top {
                        watch.push(p.clone());
                    }
                    go(base, &p, false, files, watch)?;
                }
            } else if md.is_file() && !name.ends_with(".md") {
                if top {
                    watch.push(p.clone());
                }
                let bytes = std::fs::read(&p).map_err(|e| format!("cannot read `{}`: {e}", p.display()))?;
                let rel = p.strip_prefix(base).unwrap_or(&p).display().to_string();
                files.push((rel, p, bytes));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    go(dir, dir, true, &mut files, watch)?;
    let mut t = String::new();
    for (rel, _, bytes) in &files {
        t.push_str(&format!("file {rel} {} {}\n", bytes.len(), hex(&sha256(bytes))));
    }
    // the files the Rust sources include by a literal path, transitively
    let base = crate::loader::normalize(dir);
    let mut hashed: std::collections::BTreeSet<PathBuf> = files.iter().map(|(_, p, _)| crate::loader::normalize(p)).collect();
    let mut queue: Vec<(PathBuf, Vec<u8>)> = files.into_iter().map(|(_, p, b)| (p, b)).collect();
    let mut extra: Vec<(String, PathBuf, Vec<u8>)> = Vec::new();
    while let Some((p, bytes)) = queue.pop() {
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let parent = p.parent().unwrap_or(Path::new("."));
        for lit in literal_includes(&String::from_utf8_lossy(&bytes)) {
            let q = crate::loader::normalize(&parent.join(&lit));
            // a missing target is a comment or a string: the compiler would
            // refuse a real include of it
            if q.is_file() && hashed.insert(q.clone()) {
                let b = std::fs::read(&q).map_err(|e| format!("cannot read `{}`: {e}", q.display()))?;
                extra.push((relative_to(&q, &base), q.clone(), b.clone()));
                watch.push(q.clone());
                queue.push((q, b));
            }
        }
    }
    extra.sort();
    for (rel, _, bytes) in &extra {
        t.push_str(&format!("include {rel} {} {}\n", bytes.len(), hex(&sha256(bytes))));
    }
    Ok(hex(&sha256(t.as_bytes())))
}

/// The literal paths a Rust source names as `include_str!("p")`,
/// `include_bytes!("p")`, `include!("p")` or `#[path = "p"]`
/// ([`package_digest`]; the toolchain identity's `literal_includes`).
pub fn literal_includes(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in ["include_str!(\"", "include_bytes!(\"", "include!(\"", "#[path = \""] {
        let mut rest = text;
        while let Some(i) = rest.find(pat) {
            rest = &rest[i + pat.len()..];
            if let Some(j) = rest.find('"') {
                let lit = &rest[..j];
                if !lit.is_empty() && !lit.contains('\\') {
                    out.push(lit.to_string());
                }
            }
        }
    }
    out
}

/// `path` relative to `base` (both normalized), `/`-separated, with `..`
/// for the components of `base` it is not under.
fn relative_to(path: &Path, base: &Path) -> String {
    let p: Vec<_> = path.components().collect();
    let b: Vec<_> = base.components().collect();
    let common = p.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut parts: Vec<String> = std::iter::repeat_n("..".to_string(), b.len() - common).collect();
    parts.extend(p[common..].iter().map(|c| c.as_os_str().to_string_lossy().into_owned()));
    parts.join("/")
}

/// The harness code of the library newtypes rustc's MIR has for host
/// models read as their field (`LiftFacts::mir_host_types`: SHA-256's
/// `Digest([u8; 32])` for `host::Digest = [u8; 32]`): `__cv`, the identity
/// or the newtype's constructor (the original takes the library type where
/// the lifted function takes the field's), and each newtype's writer (its
/// field's).
fn newtype_code(g: &Gen<'_>) -> String {
    let news: Vec<&(String, String, Option<String>)> = g.c.lift_facts.mir_host_types.iter().filter(|t| t.2.is_some()).collect();
    if news.is_empty() {
        return String::new();
    }
    let mut s = String::from("    pub trait __Cv<A> { fn cv(a: A) -> Self; }
    impl<A> __Cv<A> for A { fn cv(a: A) -> A { a } }
    pub fn __cv<A, B: __Cv<A>>(a: A) -> B { B::cv(a) }
");
    for (dsl, rust, field) in news {
        let Some(id) = g.krate.items.iter().find(|i| i.path.to_string() == *dsl).map(|i| i.id) else { continue };
        let ItemKind::TypeAlias(ta) = &g.krate.item(id).kind else { continue };
        let Ok(ft) = g.rust_ty(&ta.ty) else { continue };
        let f = field.clone().unwrap_or_default();
        let (build, get) = if f.chars().all(|c| c.is_ascii_digit()) { (format!("{rust}(a)"), format!("self.{f}")) } else { (format!("{rust} {{ {f}: a }}"), format!("self.{f}")) };
        s.push_str(&format!("    impl __Cv<{ft}> for {rust} {{ fn cv(a: {ft}) -> Self {{ {build} }} }}
    impl __W for {rust} {{ fn w(&self, o: &mut ::std::string::String) {{ __W::w(&{get}, o); }} }}
"));
    }
    s
}

/// Every file under `dir` (relative path, bytes), sorted.
fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<(), String> {
    let mut ents: Vec<_> = std::fs::read_dir(dir).map_err(|e| format!("cannot read `{}`: {e}", dir.display()))?.filter_map(Result::ok).collect();
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out)?;
        } else if let Ok(rel) = p.strip_prefix(root) {
            out.push((rel.to_path_buf(), std::fs::read(&p).map_err(|e| format!("cannot read `{}`: {e}", p.display()))?));
        }
    }
    Ok(())
}

/// The host crate as the copy needs it: a manifest with the host's
/// dependencies and features (`cargo metadata`), the workspace lock, the
/// library's crate name and the features to enable.
struct HostCrate {
    manifest: String,
    lock: String,
    lib_name: String,
    features: Option<Vec<String>>,
    /// The workspace manifest (path dependencies inherit from it) and root.
    ws_manifest: String,
    ws_root: PathBuf,
    /// The closure of the host's normal and build path dependencies:
    /// package directory (normalized) → package name.
    path_deps: BTreeMap<PathBuf, String>,
}

/// The packages of `cargo metadata --no-deps` on `manifest` (a workspace
/// member's lists every member): directory (normalized) → name and the
/// directories of its normal and build path dependencies.
fn metadata_packages(cfg: &Config, manifest: &Path) -> Result<(J, BTreeMap<PathBuf, (String, Vec<PathBuf>)>), String> {
    let o = Command::new(&cfg.cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline", "--manifest-path"])
        .arg(manifest)
        .env_remove("RUSTC_WRAPPER")
        .output()
        .map_err(|e| format!("cannot run `{} metadata`: {e}", cfg.cargo.display()))?;
    if !o.status.success() {
        return Err(format!("`cargo metadata` on `{}` failed: {}", manifest.display(), String::from_utf8_lossy(&o.stderr).lines().take(10).collect::<Vec<_>>().join("\n")));
    }
    let meta = J::parse(&String::from_utf8_lossy(&o.stdout)).map_err(|e| format!("cannot read `cargo metadata`: {e}"))?;
    let mut pkgs = BTreeMap::new();
    if let Some(J::Arr(ps)) = jget(&meta, "packages") {
        for p in ps {
            let Some(m) = jstr(p, "manifest_path") else { continue };
            let dir = crate::loader::normalize(Path::new(m).parent().unwrap_or(Path::new(m)));
            pkgs.insert(dir, (jstr(p, "name").unwrap_or_default().to_string(), path_dep_dirs(p)));
        }
    }
    Ok((meta, pkgs))
}

/// The directories of the normal and build path dependencies of the
/// package `p` (a `cargo metadata` package; dev-dependencies are not
/// compiled into the library).
fn path_dep_dirs(p: &J) -> Vec<PathBuf> {
    match jget(p, "dependencies") {
        Some(J::Arr(ds)) => ds.iter().filter(|d| jstr(d, "kind") != Some("dev")).filter_map(|d| jstr(d, "path")).map(|x| crate::loader::normalize(Path::new(x))).collect(),
        _ => vec![],
    }
}

fn jget<'j>(j: &'j J, k: &str) -> Option<&'j J> {
    match j {
        J::Obj(kv) => kv.iter().find(|(x, _)| x == k).map(|(_, v)| v),
        _ => None,
    }
}

fn jstr<'j>(j: &'j J, k: &str) -> Option<&'j str> {
    match jget(j, k) {
        Some(J::Str(s)) => Some(s),
        _ => None,
    }
}

fn jbool(j: &J, k: &str, d: bool) -> bool {
    match jget(j, k) {
        Some(J::Bool(b)) => *b,
        _ => d,
    }
}

fn jstrs(j: &J, k: &str) -> Vec<String> {
    match jget(j, k) {
        Some(J::Arr(xs)) => xs.iter().filter_map(|x| if let J::Str(s) = x { Some(s.clone()) } else { None }).collect(),
        _ => vec![],
    }
}

impl HostCrate {
    fn read(cfg: &Config, manifest_dir: &Path) -> Result<HostCrate, String> {
        let mpath = manifest_dir.join("Cargo.toml");
        let (meta, mut known) = metadata_packages(cfg, &mpath)?;
        let want = crate::loader::normalize(&mpath);
        let pkg = match jget(&meta, "packages") {
            Some(J::Arr(ps)) => ps.iter().find(|p| jstr(p, "manifest_path").is_some_and(|m| crate::loader::normalize(Path::new(m)) == want)),
            _ => None,
        }
        .ok_or_else(|| format!("`cargo metadata` does not list the package of `{}`", mpath.display()))?;
        let name = jstr(pkg, "name").unwrap_or("host").to_string();
        let edition = jstr(pkg, "edition").unwrap_or(&cfg.edition).to_string();
        let lib_name = match jget(pkg, "targets") {
            Some(J::Arr(ts)) => ts.iter().find(|t| jstrs(t, "kind").iter().any(|k| k == "lib")).and_then(|t| jstr(t, "name")).map(|s| s.replace('-', "_")),
            _ => None,
        }
        .ok_or_else(|| format!("the host package `{name}` has no library target (the harness calls the in-place modules through it)"))?;
        let ws_root = jstr(&meta, "workspace_root").map(PathBuf::from).unwrap_or_else(|| manifest_dir.to_path_buf());
        let ws_manifest = std::fs::read_to_string(ws_root.join("Cargo.toml")).unwrap_or_default();
        // the closure of the host's normal and build path dependencies (a
        // package outside the workspace is read with its own metadata)
        let host_dir = crate::loader::normalize(want.parent().unwrap_or(&want));
        let mut path_deps: BTreeMap<PathBuf, String> = BTreeMap::new();
        let mut work = path_dep_dirs(pkg);
        while let Some(d) = work.pop() {
            if d == host_dir || path_deps.contains_key(&d) {
                continue;
            }
            if !known.contains_key(&d) {
                let (_, more) = metadata_packages(cfg, &d.join("Cargo.toml"))?;
                known.extend(more);
            }
            let (name, deps) = known.get(&d).ok_or_else(|| format!("the path dependency `{}` of the host is not a package `cargo metadata` lists", d.display()))?;
            path_deps.insert(d.clone(), name.clone());
            work.extend(deps.iter().cloned());
        }
        if ws_manifest.lines().any(|l| l.trim_start().starts_with("[patch") || l.trim_start().starts_with("[replace")) {
            return Err(format!("the workspace manifest `{}` patches dependencies (`[patch]`/`[replace]`): the harness's copy of the host crate does not reproduce that yet", ws_root.join("Cargo.toml").display()));
        }
        let lock = std::fs::read_to_string(ws_root.join("Cargo.lock")).unwrap_or_default();
        let q = |s: &str| format!("{s:?}");
        let mut m = format!(
            "# the host crate `{name}` as the lift conformance check's harness builds it (generated)\n[package]\nname = {}\nversion = \"0.0.0\"\nedition = {}\npublish = false\nbuild = false\nautobins = false\nautoexamples = false\nautotests = false\nautobenches = false\n\n[lib]\nname = {}\npath = \"src/lib.rs\"\n\n[[bin]]\nname = \"sandblaster_conformance\"\npath = \"harness_main.rs\"\n\n[workspace]\n\n[profile.dev]\ndebug = 0\n",
            q(&name),
            q(&edition),
            q(&lib_name)
        );
        let mut tables: BTreeMap<String, Vec<String>> = BTreeMap::new();
        if let Some(J::Arr(deps)) = jget(pkg, "dependencies") {
            for d in deps {
                if !matches!(jget(d, "kind"), None | Some(J::Null)) {
                    continue;
                }
                let dn = jstr(d, "name").unwrap_or_default();
                let key = jstr(d, "rename").unwrap_or(dn);
                let mut parts = vec![format!("package = {}", q(dn)), format!("version = {}", q(jstr(d, "req").unwrap_or("*")))];
                if let Some(p) = jstr(d, "path") {
                    parts.push(format!("path = {}", q(p)));
                } else if let Some(s) = jstr(d, "source")
                    && !s.starts_with("registry+")
                    && !s.starts_with("sparse+")
                {
                    return Err(format!("the host dependency `{dn}` comes from `{s}`: the harness's copy of the host crate reproduces registry and path dependencies only"));
                }
                if let Some(r) = jstr(d, "registry") {
                    parts.push(format!("registry-index = {}", q(r)));
                }
                parts.push(format!("default-features = {}", jbool(d, "uses_default_features", true)));
                let fs = jstrs(d, "features");
                if !fs.is_empty() {
                    parts.push(format!("features = [{}]", fs.iter().map(|f| q(f)).collect::<Vec<_>>().join(", ")));
                }
                if jbool(d, "optional", false) {
                    parts.push("optional = true".into());
                }
                let table = match jstr(d, "target") {
                    Some(t) => format!("target.{}.dependencies", q(t)),
                    None => "dependencies".into(),
                };
                tables.entry(table).or_default().push(format!("{} = {{ {} }}", q(key), parts.join(", ")));
            }
        }
        for (t, lines) in &tables {
            m.push_str(&format!("\n[{t}]\n{}\n", lines.join("\n")));
        }
        let mut feats: Vec<String> = Vec::new();
        if let Some(J::Obj(fs)) = jget(pkg, "features") {
            m.push_str("\n[features]\n");
            for (f, v) in fs {
                let xs: Vec<String> = match v {
                    J::Arr(xs) => xs.iter().filter_map(|x| if let J::Str(s) = x { Some(q(s)) } else { None }).collect(),
                    _ => vec![],
                };
                m.push_str(&format!("{} = [{}]\n", q(f), xs.join(", ")));
                feats.push(f.clone());
            }
        }
        // the build's features (`CARGO_FEATURE_*` names), else the defaults
        let features = cfg.features.as_ref().filter(|fs| !fs.is_empty()).map(|enabled| {
            let norm = |f: &str| f.to_uppercase().replace('-', "_");
            feats.iter().filter(|f| enabled.iter().any(|e| *e == norm(f))).cloned().collect::<Vec<_>>()
        });
        Ok(HostCrate { manifest: m, lock, lib_name, features, ws_manifest, ws_root, path_deps })
    }
}

/// Writes the copy of the host crate with the harness, builds it with
/// cargo and runs it; returns its output line by case.
fn harness_in_place(g: &Gen<'_>, plans: &[Plan<'_>], cases: &[Case], files: &[(Vec<String>, PathBuf, String)], tree: &[(PathBuf, Vec<u8>)], host: &HostCrate, cfg: &Config) -> Result<Vec<String>, String> {
    let Some(ip) = &g.ip else { return Err("not an in-place harness".into()) };
    let mut em = Emit { g, readers: BTreeMap::new(), writers: BTreeMap::new() };
    // the harness functions, in the modules of their files
    let mut entry_code: BTreeMap<String, String> = BTreeMap::new();
    let mut arms = Vec::new();
    for (pi, p) in plans.iter().enumerate() {
        let segs = ip.modules.get(&p.e.module).ok_or_else(|| format!("`{}` is not in an in-place module", p.e.lifted))?;
        let home = Spell::access(segs);
        entry_code.entry(home.clone()).or_default().push_str(&entry_fn(&mut em, g, pi, p, "pub ")?);
        arms.push(format!("{pi} => {home}::__e{pi}(&mut t)"));
    }
    // the code of each module: readers, writers, harness functions
    let common = ip.common();
    let mut code: BTreeMap<String, String> = BTreeMap::new();
    for (_, c, home) in em.readers.values() {
        code.entry(home.clone()).or_default().push_str(c);
    }
    for (c, home) in em.writers.values() {
        code.entry(home.clone()).or_default().push_str(c);
    }
    for (home, c) in entry_code {
        code.entry(home).or_default().push_str(&c);
    }
    let prelude = PRELUDE.replace("    impl __W for ::bytes::TryGetError {\n        fn w(&self, o: &mut ::std::string::String) { o.push_str(\"null\"); }\n    }\n", "");
    let mut shared = format!("\n#[doc(hidden)]\n#[allow(warnings, missing_docs, clippy::all)]\npub mod {COMMON} {{{prelude}");
    shared.push_str("    impl<A: ?Sized> __W for ::core::marker::PhantomData<A> {\n        fn w(&self, o: &mut ::std::string::String) { o.push_str(\"null\"); }\n    }\n");
    shared.push_str(&newtype_code(g));
    shared.push_str(code.get(&common).map(String::as_str).unwrap_or(""));
    shared.push_str(&format!(
        r#"    pub fn run() {{
        ::std::panic::set_hook(::std::boxed::Box::new(|_| {{}}));
        let path = ::std::env::args().nth(1).expect("cases file");
        let text = ::std::fs::read_to_string(path).expect("cases file");
        let mut out = ::std::string::String::new();
        for line in text.lines() {{
            let mut t = __T(line.split_ascii_whitespace());
            let case = t.n();
            let entry = t.n() as usize;
            let r = ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| match entry {{ {}, _ => ::core::unreachable!() }}));
            match r {{
                ::core::result::Result::Ok(s) => out.push_str(&::std::format!("{{}}\t{{}}\n", case, s)),
                ::core::result::Result::Err(p) => {{
                    let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<::std::string::String>().cloned()).unwrap_or_default();
                    out.push_str(&::std::format!("{{}}\tPANIC\t{{}}\n", case, msg.replace('\n', " ")));
                }}
            }}
        }}
        ::std::print!("{{}}", out);
    }}
}}
#[doc(hidden)]
#[allow(warnings, missing_docs, clippy::all)]
pub use self::{COMMON}::run as {RUN};
"#,
        if arms.is_empty() { "_ if false => ::std::string::String::new()".to_string() } else { arms.join(", ") }
    ));
    // the copy of the host crate
    let dir = &cfg.work_dir;
    let krate_dir = dir.join("crate");
    let src = krate_dir.join("src");
    let _ = std::fs::remove_dir_all(&src);
    let mut texts: BTreeMap<PathBuf, Vec<u8>> = tree.iter().map(|(r, b)| (r.clone(), b.clone())).collect();
    let src_root = cfg.manifest_dir.as_ref().map(|m| { let s = m.join("src"); crate::loader::normalize(&std::path::absolute(&s).unwrap_or(s)) }).unwrap_or_default();
    let mut append = |segs: &[String], text: &str| -> Result<(), String> {
        let f = module_file(&src_root, segs).ok_or_else(|| format!("no file of the host module `{}`", Spell::path_of(segs)))?;
        let rel = f.strip_prefix(&src_root).map_err(|_| format!("`{}` is not under `{}`", f.display(), src_root.display()))?.to_path_buf();
        let e = texts.get_mut(&rel).ok_or_else(|| format!("`{}` is not in the copy", rel.display()))?;
        e.extend_from_slice(text.as_bytes());
        Ok(())
    };
    for (segs, path, _) in files {
        let home = Spell::access(segs);
        let body = code.get(&home).map(String::as_str).unwrap_or("");
        let text = format!("\n#[doc(hidden)]\n#[allow(warnings, missing_docs, clippy::all)]\npub mod {ACCESS} {{\n    #![allow(warnings)]\n    use {common}::{{__T, __W}};\n{body}}}\n");
        // (the file itself, as the verifier read it: the copy is its bytes)
        let _ = path;
        append(segs, &text)?;
    }
    append(&ip.lca, &shared)?;
    // `run` re-exported up to the crate root
    for i in (0..ip.lca.len()).rev() {
        let parent = &ip.lca[..i];
        append(parent, &format!("\n#[doc(hidden)]\n#[allow(warnings, missing_docs, clippy::all)]\npub use self::{}::{RUN};\n", ip.lca[i]))?;
    }
    for (rel, bytes) in &texts {
        let p = src.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("cannot create `{}`: {e}", d.display()))?;
        }
        std::fs::write(&p, bytes).map_err(|e| format!("cannot write `{}`: {e}", p.display()))?;
    }
    let w = |name: &str, text: &str| std::fs::write(krate_dir.join(name), text).map_err(|e| format!("cannot write `{}`: {e}", krate_dir.join(name).display()));
    w("Cargo.toml", &host.manifest)?;
    if !host.lock.is_empty() {
        w("Cargo.lock", &host.lock)?;
    }
    w("harness_main.rs", &format!("fn main() {{\n    {}::{RUN}();\n}}\n", host.lib_name))?;
    // the cases
    let mut text = String::new();
    for (ci, c) in cases.iter().enumerate() {
        let p = &plans[c.plan];
        let mut toks = vec![ci.to_string(), c.plan.to_string()];
        for (t, a) in p.params.iter().zip(&c.args) {
            tokens(g, t, a, &mut toks)?;
        }
        text.push_str(&toks.join(" "));
        text.push('\n');
    }
    std::fs::write(dir.join("cases.txt"), &text).map_err(|e| format!("cannot write the cases: {e}"))?;
    // build the copy (its own target directory; the build's jobserver)
    let target = dir.join("target");
    let mut cmd = Command::new(&cfg.cargo);
    cmd.current_dir(&krate_dir).args(["build", "--offline", "--bin", "sandblaster_conformance", "--manifest-path", "Cargo.toml", "--target-dir"]).arg(&target);
    match &host.features {
        Some(fs) => {
            cmd.arg("--no-default-features");
            if !fs.is_empty() {
                cmd.arg("--features").arg(fs.join(","));
            }
        }
        None => {}
    }
    for k in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "OUT_DIR", "TARGET", "HOST"] {
        cmd.env_remove(k);
    }
    let log = dir.join("build.log");
    let log_file = std::fs::File::create(&log).map_err(|e| format!("cannot create `{}`: {e}", log.display()))?;
    let mut child = cmd.stdout(Stdio::null()).stderr(Stdio::from(log_file)).spawn().map_err(|e| format!("cannot run `{} build`: {e}", cfg.cargo.display()))?;
    let t = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => break,
            Ok(Some(st)) => {
                let text = std::fs::read_to_string(&log).unwrap_or_default();
                let errs: Vec<&str> = text.lines().filter(|l| l.starts_with("error") || l.trim_start().starts_with("-->")).take(40).collect();
                return Err(format!("the harness (a copy of the host crate in `{}`) did not build ({st}): {}", krate_dir.display(), errs.join("\n")));
            }
            Ok(None) if t.elapsed() > BUILD_TIMEOUT => {
                let _ = child.kill();
                return Err(format!("the harness did not build within {}s", BUILD_TIMEOUT.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("waiting for cargo: {e}")),
        }
    }
    let exe = target.join("debug").join(if cfg!(windows) { "sandblaster_conformance.exe" } else { "sandblaster_conformance" });
    run_harness(&exe, dir, cases.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_paths_of_host_files() {
        let s = |p: &str| module_segments(Path::new(p)).map(|v| v.join("::"));
        assert_eq!(s("lib.rs"), Some(String::new()));
        assert_eq!(s("a.rs"), Some("a".into()));
        assert_eq!(s("a/mod.rs"), Some("a".into()));
        assert_eq!(s("a/b/mod.rs"), Some("a::b".into()));
        assert_eq!(s("a/b/c.rs"), Some("a::b::c".into()));
        // negative twins: not module files
        assert_eq!(s("mod.rs"), None);
        assert_eq!(s("a/notes.txt"), None);
        assert_eq!(s("a/lib.rs"), Some("a::lib".into()));
    }

    #[test]
    fn instances_of_generic_types() {
        let inst = vec![("crate::merkle::Family".to_string(), "crate::merkle::mmr::Family".to_string())];
        let mut out = Vec::new();
        let mut params = HashMap::new();
        instance_args("pub struct Position<F: Family>(u64, PhantomData<F>);\npub struct Plain(u64);\npub enum E<G> where G: super::Family { A(G) }\nimpl<H: Family> Position<H> {}\n", &inst, &mut out, &mut params);
        assert_eq!(out, vec![("Position".to_string(), vec!["crate::merkle::mmr::Family".to_string()]), ("E".to_string(), vec!["crate::merkle::mmr::Family".to_string()])]);
        assert_eq!(params.get("H").map(String::as_str), Some("crate::merkle::mmr::Family"));
        // negative twin: a parameter bound by no declared instance is not spelled
        let mut out2 = Vec::new();
        instance_args("pub struct Q<T: Clone>(T);\npub struct R<'a>(&'a u8);\n", &inst, &mut out2, &mut HashMap::new());
        assert!(out2.is_empty(), "{out2:?}");
    }

    #[test]
    fn instances_replace_type_parameters() {
        let mut ip = Spell::default();
        ip.params.insert("F".into(), "crate::mmr::Family".into());
        assert_eq!(ip.subst("Position<F>"), "Position<crate::mmr::Family>");
        assert_eq!(ip.subst("crate::merkle::Family"), "crate::merkle::Family");
        // negative twin: a type named like no parameter stays
        assert_eq!(ip.subst("Foo<G>"), "Foo<G>");
        // a generic type written bare gets its instance arguments; one
        // that has them, or is unknown, stays
        ip.type_args.insert("crate::merkle::position::Position".into(), vec!["crate::mmr::Family".into()]);
        assert_eq!(ip.subst("Position"), "Position<crate::mmr::Family>");
        assert_eq!(ip.subst("TryFrom<Position>"), "TryFrom<Position<crate::mmr::Family>>");
        assert_eq!(ip.subst("Position<u8>"), "Position<u8>");
        assert_eq!(ip.subst("Other"), "Other");
    }

    #[test]
    fn a_trait_generic_over_an_open_trait_gets_its_instance() {
        let inst = vec![("crate::merkle::Family".to_string(), "crate::merkle::mmr::Family".to_string())];
        let mut out = Vec::new();
        instance_args("pub trait Hasher<F: Family>: Clone { fn h(&self); }\npub trait Plain { fn p(&self); }\n", &inst, &mut out, &mut HashMap::new());
        assert_eq!(out, vec![("Hasher".to_string(), vec!["crate::merkle::mmr::Family".to_string()])]);
    }

    #[test]
    fn host_models_are_spelled_as_the_library_types_mir_has_for_them() {
        let map = vec![("crate::merkle::host::Sha256".to_string(), "::commonware_cryptography::Sha256".to_string(), None), ("crate::merkle::host::Digest".to_string(), "::commonware_cryptography::sha256::Digest".to_string(), Some("0".to_string()))];
        assert_eq!(real_paths("crate::merkle::hasher::Standard<crate::merkle::host::Sha256>", &map), "crate::merkle::hasher::Standard<::commonware_cryptography::Sha256>");
        assert_eq!(real_paths("crate::merkle::host::Digest", &map), "::commonware_cryptography::sha256::Digest");
        // negative twins: another path, or one that only starts like a model's, stays
        assert_eq!(real_paths("crate::merkle::host::Sha256x", &map), "crate::merkle::host::Sha256x");
        assert_eq!(real_paths("crate::merkle::Bagging", &map), "crate::merkle::Bagging");
    }

    #[test]
    fn arguments_holding_arrays_are_converted_element_by_element() {
        let d = Ty::Array(Box::new(Ty::Uint(UintTy::U8)), 32);
        assert_eq!(cv_expr("cv", &d, "a"), "cv(a)");
        let pair = Ty::Tuple(vec![Ty::Uint(UintTy::U64), d.clone()]);
        assert_eq!(cv_expr("cv", &Ty::Option(Box::new(Ty::Seq(Box::new(pair)))), "a"), "a.map(|x| x.into_iter().map(|x| { let (x0, x1,) = x; (x0, cv(x1),) }).collect::<::std::vec::Vec<_>>())");
        assert_eq!(cv_expr("cv", &Ty::Ref(Box::new(Ty::Slice(Box::new(d)))), "a"), "a.into_iter().map(|x| cv(x)).collect::<::std::vec::Vec<_>>()");
        // negative twin: a value without arrays is passed as it is
        assert_eq!(cv_expr("cv", &Ty::Seq(Box::new(Ty::Uint(UintTy::U8))), "a"), "a");
    }
}
