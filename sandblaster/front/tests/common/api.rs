//! An independent reader of a crate's **public API**, for comparing a
//! generated crate with its DSL source: every public path from the crate
//! root (through `pub mod`s and `pub use` re-exports, renames included),
//! with the kind of what it names and the definition it names.
//!
//! It does not use the front end: it parses the files with `syn`, evaluates
//! item `cfg`s for a target (`cfg(sandblaster)` is false: ghost modules are
//! never compiled), drops ghost items (`#[spec]`, `#[lemma]`, `#[law]`,
//! `#[proof]`), resolves `use` paths itself (to a fixpoint, so imports of
//! imports work) and walks the public bindings. For generated code the
//! definitions are named relative to `__sandblaster`, so they compare with the
//! source's.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use sandblaster_front::target::TargetInfo;
use syn::punctuated::Punctuated;

/// One public name of a crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Entry {
    /// The public path from the crate root (`config::hash_chunk`).
    pub path: String,
    /// What it is: `fn/<arity>`, `const`, `type`, `mod`, `variant`,
    /// `extern`, `struct{<pub fields>}[<derives>]`, `enum{<variants>}[<derives>]`.
    pub kind: String,
    /// What it denotes: the defining module path and name
    /// (`sha256::hash_32`), or an external path (`core::option::Option`).
    pub def: String,
}

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path == self.def {
            write!(f, "{} ({})", self.path, self.kind)
        } else {
            write!(f, "{} = {} ({})", self.path, self.def, self.kind)
        }
    }
}

/// The public API of the DSL crate rooted at `root` (files read by `read`).
pub fn source_api(root: &Path, read: &dyn Fn(&Path) -> Option<String>, target: &TargetInfo) -> BTreeSet<Entry> {
    let mut t = Tree::new(target, None);
    let text = read(root).unwrap_or_else(|| panic!("cannot read {}", root.display()));
    let file = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", root.display()));
    let dir = root.parent().unwrap_or(Path::new("")).to_path_buf();
    t.add_module(None, String::new(), file.items, Some((dir, true)), read);
    t.api()
}

/// The public API of a generated file (the `include!`d crate root: `mod
/// __sandblaster { .. }` and the top-level `pub use` exports), without the
/// one item every generated crate adds: `SANDBLASTER_SPEC_ROOT`, the root of
/// its `SPEC.lock` (DESIGN.md §15.6).
pub fn generated_api(code: &str, target: &TargetInfo) -> BTreeSet<Entry> {
    let mut t = Tree::new(target, Some("__sandblaster"));
    let file = syn::parse_file(code).expect("generated code parses");
    t.add_module(None, String::new(), file.items, None, &|_| None);
    let mut api = t.api();
    api.retain(|e| !(e.path == "SANDBLASTER_SPEC_ROOT" && e.kind == "const"));
    api
}

/// Reads files from the disk.
pub fn disk(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

/// A readable diff of two APIs (`-` only in `a`, `+` only in `b`).
pub fn diff(a: &BTreeSet<Entry>, b: &BTreeSet<Entry>) -> String {
    let mut s = String::new();
    for e in a.difference(b) {
        s.push_str(&format!("  - {e}\n"));
    }
    for e in b.difference(a) {
        s.push_str(&format!("  + {e}\n"));
    }
    s
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum D {
    Mod(usize),
    /// An item of a module, by name.
    Item(usize, String),
    Variant(usize, String, String),
    Ext(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ns {
    Type,
    Value,
}

struct Use {
    module: usize,
    segs: Vec<String>,
    leading_colon: bool,
    bind: Option<String>,
    public: bool,
}

struct Impl {
    module: usize,
    self_ty: syn::Path,
    /// `(name, kind)` of its `pub` functions.
    fns: Vec<(String, String)>,
}

struct Module {
    path: Vec<String>,
    parent: Option<usize>,
    /// Item name → kind, and whether it is a variant-bearing enum.
    kinds: BTreeMap<String, String>,
    variants: BTreeMap<String, Vec<String>>,
    types: BTreeMap<String, (D, bool)>,
    values: BTreeMap<String, (D, bool)>,
}

struct Tree<'t> {
    target: &'t TargetInfo,
    /// Generated code: the module whose name is left out of definitions.
    strip: Option<&'static str>,
    mods: Vec<Module>,
    uses: Vec<Use>,
    impls: Vec<Impl>,
}

impl<'t> Tree<'t> {
    fn new(target: &'t TargetInfo, strip: Option<&'static str>) -> Tree<'t> {
        Tree { target, strip, mods: vec![], uses: vec![], impls: vec![] }
    }

    fn cfg_true(&self, attrs: &[syn::Attribute]) -> bool {
        attrs.iter().filter(|a| a.path().is_ident("cfg")).all(|a| {
            let m: syn::Meta = a.parse_args().expect("cfg predicate");
            self.pred(&m)
        })
    }

    fn pred(&self, m: &syn::Meta) -> bool {
        match m {
            syn::Meta::Path(p) if p.is_ident("sandblaster") => false,
            // the profile: only the private checked-arithmetic helpers of
            // generated code (`mod __rt`, plan O2) depend on it, never the
            // public API; read as a build without debug assertions
            syn::Meta::Path(p) if p.is_ident("debug_assertions") => false,
            syn::Meta::NameValue(nv) => {
                let key = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
                let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(v), .. }) = &nv.value else { panic!("cfg value {}", nv.to_token_stream()) };
                let v = v.value();
                match key.as_str() {
                    "target_arch" => v == self.target.arch.name(),
                    "target_endian" => (v == "little") == self.target.little_endian,
                    "target_pointer_width" => v == self.target.pointer_width.to_string(),
                    "target_feature" => self.target.features.contains(&v),
                    _ => panic!("unknown cfg `{}`", nv.to_token_stream()),
                }
            }
            syn::Meta::List(l) => {
                let args: Vec<syn::Meta> = l.parse_args_with(Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).expect("cfg list").into_iter().collect();
                match l.path.get_ident().map(|i| i.to_string()).as_deref() {
                    Some("all") => args.iter().all(|a| self.pred(a)),
                    Some("any") => args.iter().any(|a| self.pred(a)),
                    Some("not") => !self.pred(&args[0]),
                    _ => panic!("unknown cfg `{}`", l.to_token_stream()),
                }
            }
            other => panic!("unknown cfg `{}`", other.to_token_stream()),
        }
    }

    /// Adds a module with `items`; `file` is `(directory for child files,
    /// mod.rs-like)` for file modules (source), `None` for inline ones.
    fn add_module(&mut self, parent: Option<usize>, name: String, items: Vec<syn::Item>, file: Option<(PathBuf, bool)>, read: &dyn Fn(&Path) -> Option<String>) -> usize {
        let idx = self.mods.len();
        let mut path = parent.map(|p| self.mods[p].path.clone()).unwrap_or_default();
        if parent.is_some() {
            path.push(name.clone());
        }
        self.mods.push(Module { path, parent, kinds: BTreeMap::new(), variants: BTreeMap::new(), types: BTreeMap::new(), values: BTreeMap::new() });
        // the directory of this module's child files
        let child_dir = file.as_ref().map(|(dir, mod_rs)| if *mod_rs || parent.is_none() { dir.clone() } else { dir.join(&name) });
        for item in items {
            let attrs: &[syn::Attribute] = match &item {
                syn::Item::Fn(x) => &x.attrs,
                syn::Item::Const(x) => &x.attrs,
                syn::Item::Struct(x) => &x.attrs,
                syn::Item::Enum(x) => &x.attrs,
                syn::Item::Type(x) => &x.attrs,
                syn::Item::Mod(x) => &x.attrs,
                syn::Item::Use(x) => &x.attrs,
                syn::Item::Impl(x) => &x.attrs,
                _ => continue,
            };
            if !self.cfg_true(attrs) || ghost(attrs) {
                continue;
            }
            match item {
                syn::Item::Fn(f) => self.define(idx, Ns::Value, f.sig.ident.to_string(), fn_kind(&f.sig), &f.vis),
                syn::Item::Const(c) => self.define(idx, Ns::Value, c.ident.to_string(), "const".into(), &c.vis),
                syn::Item::Type(t) => self.define(idx, Ns::Type, t.ident.to_string(), "type".into(), &t.vis),
                syn::Item::Struct(s) => {
                    let fields: Vec<String> = s.fields.iter().enumerate().filter(|(_, f)| is_pub(&f.vis)).map(|(k, f)| f.ident.as_ref().map(|i| i.to_string()).unwrap_or(k.to_string())).collect();
                    self.define(idx, Ns::Type, s.ident.to_string(), format!("struct{{{}}}[{}]", fields.join(","), derives(&s.attrs)), &s.vis);
                }
                syn::Item::Enum(e) => {
                    let vs: Vec<String> = e.variants.iter().map(|v| v.ident.to_string()).collect();
                    self.mods[idx].variants.insert(e.ident.to_string(), vs.clone());
                    self.define(idx, Ns::Type, e.ident.to_string(), format!("enum{{{}}}[{}]", vs.join(","), derives(&e.attrs)), &e.vis);
                }
                syn::Item::Mod(m) => {
                    let cname = m.ident.to_string();
                    let child = match (m.content, &child_dir) {
                        (Some((_, inner)), _) => self.add_module(Some(idx), cname.clone(), inner, None, read),
                        (None, Some(dir)) => {
                            let given = m.attrs.iter().find(|a| a.path().is_ident("path")).map(|a| match &a.meta {
                                syn::Meta::NameValue(syn::MetaNameValue { value: syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }), .. }) => s.value(),
                                _ => panic!("#[path]"),
                            });
                            let (p, mod_rs) = match given {
                                Some(g) => (file.as_ref().unwrap().0.join(g), true),
                                None => {
                                    let a = dir.join(format!("{cname}.rs"));
                                    if read(&a).is_some() { (a, false) } else { (dir.join(&cname).join("mod.rs"), true) }
                                }
                            };
                            let text = read(&p).unwrap_or_else(|| panic!("cannot read {}", p.display()));
                            let f = syn::parse_file(&text).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
                            let d = p.parent().unwrap().to_path_buf();
                            self.add_module(Some(idx), cname.clone(), f.items, Some((d, mod_rs)), read)
                        }
                        (None, None) => panic!("file module `{cname}` in inline code"),
                    };
                    self.mods[idx].types.insert(cname, (D::Mod(child), is_pub(&m.vis)));
                }
                syn::Item::Use(u) => {
                    let mut out = Vec::new();
                    flatten(&u.tree, &mut vec![], &mut out);
                    for (segs, bind) in out {
                        self.uses.push(Use { module: idx, segs, leading_colon: u.leading_colon.is_some(), bind, public: is_pub(&u.vis) });
                    }
                }
                syn::Item::Impl(im) => {
                    assert!(im.trait_.is_none(), "trait impl");
                    let syn::Type::Path(tp) = &*im.self_ty else { panic!("impl self type") };
                    let fns = im.items.iter().filter_map(|ii| match ii {
                        syn::ImplItem::Fn(f) if is_pub(&f.vis) && !ghost(&f.attrs) => Some((f.sig.ident.to_string(), fn_kind(&f.sig))),
                        _ => None,
                    }).collect();
                    self.impls.push(Impl { module: idx, self_ty: tp.path.clone(), fns });
                }
                _ => {}
            }
        }
        idx
    }

    fn define(&mut self, m: usize, ns: Ns, name: String, kind: String, vis: &syn::Visibility) {
        self.mods[m].kinds.insert(name.clone(), kind);
        let b = (D::Item(m, name.clone()), is_pub(vis));
        match ns {
            Ns::Type => self.mods[m].types.insert(name, b),
            Ns::Value => self.mods[m].values.insert(name, b),
        };
    }

    /// Resolves the prefix `segs` of a path used in module `m` to a
    /// container (module, enum or external path).
    fn container(&self, m: usize, segs: &[String], leading_colon: bool) -> Option<D> {
        let mut cur: Option<D> = None;
        for (k, s) in segs.iter().enumerate() {
            let next = match (&cur, s.as_str()) {
                (None, _) if leading_colon => D::Ext(ext_root(s)),
                (None, "crate") => D::Mod(0),
                (None, "self") => D::Mod(m),
                (None, "super") => D::Mod(self.mods[m].parent?),
                (None, name) => match self.mods[m].types.get(name) {
                    Some((d, _)) => d.clone(),
                    None if k == 0 && matches!(name, "core" | "std" | "sandblaster" | "alloc") => D::Ext(ext_root(name)),
                    None => return None,
                },
                (Some(D::Mod(x)), "super") => D::Mod(self.mods[*x].parent?),
                (Some(D::Mod(x)), "self") => D::Mod(*x),
                (Some(D::Mod(x)), name) => self.mods[*x].types.get(name)?.0.clone(),
                (Some(D::Ext(p)), name) => D::Ext(format!("{p}::{name}")),
                _ => return None,
            };
            cur = Some(next);
        }
        cur
    }

    /// What name `last` of container `c` (or of module `m`'s scope when
    /// `c` is `None`) denotes, per namespace.
    fn lookup(&self, m: usize, c: Option<&D>, last: &str) -> Vec<(Ns, D)> {
        let scope = |x: usize| {
            let mut v = Vec::new();
            if let Some((d, _)) = self.mods[x].types.get(last) {
                v.push((Ns::Type, d.clone()));
            }
            if let Some((d, _)) = self.mods[x].values.get(last) {
                v.push((Ns::Value, d.clone()));
            }
            v
        };
        match c {
            None => {
                let v = scope(m);
                if v.is_empty() && matches!(last, "core" | "std" | "sandblaster" | "alloc") { vec![(Ns::Type, D::Ext(ext_root(last)))] } else { v }
            }
            Some(D::Mod(x)) => scope(*x),
            Some(D::Item(x, e)) => match self.mods[*x].variants.get(e) {
                Some(vs) if vs.iter().any(|v| v == last) => vec![(Ns::Type, D::Variant(*x, e.clone(), last.to_string()))],
                _ => vec![],
            },
            Some(D::Ext(p)) => vec![(Ns::Type, D::Ext(format!("{p}::{last}")))],
            Some(D::Variant(..)) => vec![],
        }
    }

    fn resolve_uses(&mut self) {
        let mut pending: Vec<usize> = (0..self.uses.len()).collect();
        loop {
            let before = pending.len();
            let mut next = Vec::new();
            for i in pending {
                if !self.try_use(i) {
                    next.push(i);
                }
            }
            pending = next;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        let bad: Vec<String> = pending.iter().map(|&i| format!("{} in `{}`", self.uses[i].segs.join("::"), self.mods[self.uses[i].module].path.join("::"))).collect();
        assert!(bad.is_empty(), "unresolved imports: {bad:?}");
    }

    fn try_use(&mut self, i: usize) -> bool {
        let u = &self.uses[i];
        let (m, public) = (u.module, u.public);
        let n = u.segs.len();
        let last = u.segs[n - 1].clone();
        if last == "*" {
            // globs: only of external modules (the prelude, `core::arch::..`)
            let c = self.container(m, &u.segs[..n - 1], u.leading_colon);
            assert!(matches!(c, Some(D::Ext(_)) | None), "glob import of a crate module: {}", u.segs.join("::"));
            return c.is_some();
        }
        let (found, bind) = if last == "self" {
            let Some(c) = self.container(m, &u.segs[..n - 1], u.leading_colon) else { return false };
            (vec![(Ns::Type, c)], u.bind.clone().unwrap_or(u.segs[n - 2].clone()))
        } else {
            let c = if n == 1 {
                if u.leading_colon { Some(D::Ext(ext_root(&last))) } else { None }
            } else {
                match self.container(m, &u.segs[..n - 1], u.leading_colon) {
                    Some(c) => Some(c),
                    None => return false,
                }
            };
            let found = match &c {
                Some(D::Ext(_)) if n == 1 => vec![(Ns::Type, c.clone().unwrap())],
                _ => self.lookup(m, c.as_ref(), &last),
            };
            (found, u.bind.clone().unwrap_or(last))
        };
        if found.is_empty() {
            return false;
        }
        if bind == "_" {
            return true;
        }
        for (ns, d) in found {
            let tbl = match ns {
                Ns::Type => &mut self.mods[m].types,
                Ns::Value => &mut self.mods[m].values,
            };
            match tbl.get(&bind) {
                Some((prev, _)) if *prev != d => panic!("`{bind}` bound twice in `{}`", self.mods[m].path.join("::")),
                Some(_) => {}
                None => {
                    tbl.insert(bind.clone(), (d, public));
                }
            }
        }
        true
    }

    /// The definition path of `d` (generated code: relative to `__sandblaster`).
    fn def_path(&self, d: &D) -> String {
        let mp = |x: usize| {
            let p = &self.mods[x].path;
            let p: &[String] = match (self.strip, p.first()) {
                (Some(s), Some(f)) if f == s => &p[1..],
                _ => p,
            };
            p.join("::")
        };
        let join = |a: String, b: &str| if a.is_empty() { b.to_string() } else { format!("{a}::{b}") };
        match d {
            D::Mod(x) => mp(*x),
            D::Item(x, n) => join(mp(*x), n),
            D::Variant(x, e, v) => join(join(mp(*x), e), v),
            D::Ext(p) => p.clone(),
        }
    }

    fn kind(&self, d: &D) -> String {
        match d {
            D::Mod(_) => "mod".into(),
            D::Item(x, n) => self.mods[*x].kinds[n].clone(),
            D::Variant(..) => "variant".into(),
            D::Ext(_) => "extern".into(),
        }
    }

    fn api(mut self) -> BTreeSet<Entry> {
        self.resolve_uses();
        // inherent functions by their type
        let mut methods: BTreeMap<D, Vec<(String, String)>> = BTreeMap::new();
        for im in &self.impls {
            let segs: Vec<String> = im.self_ty.segments.iter().map(|s| s.ident.to_string()).collect();
            let n = segs.len();
            let c = if n == 1 { None } else { Some(self.container(im.module, &segs[..n - 1], im.self_ty.leading_colon.is_some()).expect("impl self type")) };
            let d = self.lookup(im.module, c.as_ref(), &segs[n - 1]).into_iter().find(|(ns, _)| *ns == Ns::Type).expect("impl self type").1;
            methods.entry(d).or_default().extend(im.fns.iter().cloned());
        }
        let mut out = BTreeSet::new();
        let mut stack = vec![0usize];
        self.walk(0, "", &methods, &mut stack, &mut out);
        out
    }

    fn walk(&self, m: usize, prefix: &str, methods: &BTreeMap<D, Vec<(String, String)>>, stack: &mut Vec<usize>, out: &mut BTreeSet<Entry>) {
        let mut names: Vec<(&String, &D)> = Vec::new();
        for (n, (d, public)) in self.mods[m].types.iter().chain(self.mods[m].values.iter()) {
            if *public && !names.iter().any(|(n2, d2)| *n2 == n && *d2 == d) {
                names.push((n, d));
            }
        }
        for (name, d) in names {
            let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}::{name}") };
            let def = self.def_path(d);
            out.insert(Entry { path: path.clone(), kind: self.kind(d), def: def.clone() });
            match d {
                D::Mod(c) if !stack.contains(c) => {
                    stack.push(*c);
                    self.walk(*c, &path, methods, stack, out);
                    stack.pop();
                }
                D::Item(x, e) => {
                    for v in self.mods[*x].variants.get(e).into_iter().flatten() {
                        out.insert(Entry { path: format!("{path}::{v}"), kind: "variant".into(), def: format!("{def}::{v}") });
                    }
                    for (f, k) in methods.get(d).into_iter().flatten() {
                        out.insert(Entry { path: format!("{path}::{f}"), kind: k.clone(), def: format!("{def}::{f}") });
                    }
                }
                _ => {}
            }
        }
    }
}

fn ext_root(s: &str) -> String {
    if s == "std" { "core".into() } else { s.to_string() }
}

fn is_pub(v: &syn::Visibility) -> bool {
    matches!(v, syn::Visibility::Public(_))
}

/// Ghost items (never compiled by rustc, DESIGN.md §2).
fn ghost(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| ["spec", "lemma", "law", "proof"].iter().any(|g| a.path().is_ident(g)))
}

fn fn_kind(sig: &syn::Signature) -> String {
    format!("{}fn/{}", if sig.unsafety.is_some() { "unsafe " } else { "" }, sig.inputs.len())
}

/// The derived traits, by their last path segment, sorted.
fn derives(attrs: &[syn::Attribute]) -> String {
    let mut v: Vec<String> = Vec::new();
    for a in attrs.iter().filter(|a| a.path().is_ident("derive")) {
        let ps: Punctuated<syn::Path, syn::Token![,]> = a.parse_args_with(Punctuated::parse_terminated).expect("derive list");
        v.extend(ps.iter().map(|p| p.segments.last().unwrap().ident.to_string()));
    }
    v.sort();
    v.join(",")
}

/// Flattens a use tree into `(segments, rename)` (a glob ends in `*`).
fn flatten(t: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(Vec<String>, Option<String>)>) {
    match t {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            flatten(&p.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let mut s = prefix.clone();
            s.push(n.ident.to_string());
            out.push((s, None));
        }
        syn::UseTree::Rename(r) => {
            let mut s = prefix.clone();
            s.push(r.ident.to_string());
            out.push((s, Some(r.rename.to_string())));
        }
        syn::UseTree::Glob(_) => {
            let mut s = prefix.clone();
            s.push("*".into());
            out.push((s, None));
        }
        syn::UseTree::Group(g) => {
            for x in &g.items {
                flatten(x, prefix, out);
            }
        }
    }
}
