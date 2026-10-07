//! Module loader (DESIGN.md §2, §3.1 "mod name;").
//!
//! Starting from the DSL root (`sandblaster/mod.rs`), the loader parses every
//! file with `syn`, follows `mod name;` declarations and builds the module
//! tree:
//!
//! * `mod name;` declared in a `mod.rs`-like file (the root, a `mod.rs`, or a
//!   `#[path]` module) resolves to `dir/name.rs` or `dir/name/mod.rs` (both
//!   existing is an error, as in rustc); declared in `dir/x.rs` it resolves to
//!   `dir/x/name.rs` or `dir/x/name/mod.rs`.
//! * `#[path = "X.rs"]` is accepted **only** on `#[cfg(sandblaster)]` (ghost)
//!   modules (§2); the path is relative to the declaring file's directory.
//! * Inline modules (`mod m { .. }`) are rejected.
//!
//! # `cfg` evaluation and ghost tracking
//!
//! Every item's `#[cfg(..)]` attributes are evaluated here:
//!
//! * `#[cfg(sandblaster)]` (exactly) marks the item **ghost**: it is checked
//!   but never compiled by rustc (§2). Items of a ghost module are ghost.
//! * Any other mention of `sandblaster` inside a `cfg` is rejected (rustc and
//!   the checker would see different code).
//! * Target predicates (`target_arch`, `target_endian`,
//!   `target_pointer_width`, `target_feature`, combined with
//!   `all`/`any`/`not`) are evaluated against the [`TargetInfo`]; items whose
//!   predicate is false are dropped (exactly rustc's view of the build
//!   target). True predicates are kept (as text).
//!   Ghost proof code is never dropped silently
//!   ([`Loader::dropped_ghost_item`]): a `#[law]` removed by a target
//!   predicate is an error (laws are checked on every target), a removed
//!   `#[lemma]`/`#[proof]` or ghost module is a warning (an error for a
//!   module that declares laws), and a predicate false on every target
//!   (`any()`) on a ghost item is an error.
//! * Other predicates (`test`, `debug_assertions`, `feature = ..`) and
//!   `#[cfg_attr]` are rejected (`#[cfg_attr(sandblaster, sandblaster::critical)]`
//!   with the explanation that §15 is always on, DESIGN.md §15.8).
//!
//! # Vector files (DESIGN.md §15.7)
//!
//! `#[examples(file = "..", ..)]` on a function (free or in an inherent
//! `impl`) names a test-vector file relative to the declaring file's
//! directory. The loader reads it through the same [`FileProvider`] and
//! registers it in the [`SourceMap`] (so it is a build input, printed as
//! `cargo::rerun-if-changed`), recording it per module
//! ([`LoadedModule::data_files`], keyed by the path as written). A missing
//! file is a `load` error. Its records are parsed later (S1).
//!
//! # Identifiers
//!
//! Every identifier of the loaded source (items after `cfg` evaluation,
//! attributes, `proof!` blocks and contracts included, and every inner
//! attribute) is a plain ASCII identifier: never raw, never outside ASCII
//! and never a keyword of some edition (`gen`) ([`check_identifiers`]), so
//! name equality is spelling equality in every later phase.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::spanned::Spanned;

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::span::{FileId, SourceMap, Span};
use crate::target::TargetInfo;

/// Source of file contents (the real file system, or an in-memory map for
/// tests).
pub trait FileProvider {
    fn read(&self, path: &Path) -> io::Result<String>;
    fn exists(&self, path: &Path) -> bool;
    /// Every `.rs` file under `dir`, recursively, sorted (module mode's
    /// scan of the host crate's `src/`, DESIGN.md §2.1). Providers that
    /// cannot list report an error, which fails a module-mode build.
    fn list_rs(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        let _ = dir;
        Err(io::Error::new(io::ErrorKind::Unsupported, "this file provider cannot list directories"))
    }
}

/// The real file system.
pub struct RealFs;

impl FileProvider for RealFs {
    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
    fn exists(&self, path: &Path) -> bool {
        path.is_file()
    }
    fn list_rs(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        fn walk(d: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
            for e in std::fs::read_dir(d)? {
                let e = e?;
                let p = e.path();
                let ft = e.file_type()?;
                if ft.is_dir() {
                    walk(&p, out)?;
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
            Ok(())
        }
        let mut out = Vec::new();
        walk(dir, &mut out)?;
        out.sort();
        Ok(out)
    }
}

/// An in-memory file system (paths are compared after lexical
/// normalization).
#[derive(Default, Clone)]
pub struct MemFs {
    files: HashMap<PathBuf, String>,
}

impl MemFs {
    pub fn new() -> MemFs {
        MemFs::default()
    }
    /// Builds a file system from `(path, contents)` pairs.
    pub fn from_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> MemFs {
        let mut fs = MemFs::new();
        for (p, c) in files {
            fs.insert(p, c);
        }
        fs
    }
    pub fn insert(&mut self, path: impl AsRef<Path>, contents: impl Into<String>) {
        self.files.insert(normalize(path.as_ref()), contents.into());
    }
}

impl FileProvider for MemFs {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.files.get(&normalize(path)).cloned().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such file"))
    }
    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(&normalize(path))
    }
    fn list_rs(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        let d = normalize(dir);
        let mut out: Vec<PathBuf> = self.files.keys().filter(|p| p.starts_with(&d) && p.extension().is_some_and(|x| x == "rs")).cloned().collect();
        out.sort();
        Ok(out)
    }
}

/// Lexically normalizes `a/./b/../c` to `a/c`.
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// One item of a loaded module after `cfg` evaluation.
#[derive(Clone)]
pub struct LoadedItem {
    pub item: syn::Item,
    /// `#[cfg(sandblaster)]` on the item, or inside a ghost module.
    pub ghost: bool,
    /// Target `cfg` predicates (true for the target), as source text.
    pub cfg: Option<String>,
    /// For `mod name;` items: index of the child module.
    pub child: Option<usize>,
}

/// One loaded module.
#[derive(Clone)]
pub struct LoadedModule {
    pub name: String,
    pub parent: Option<usize>,
    pub file: FileId,
    pub ghost: bool,
    /// Visibility of the `mod` declaration (root: private).
    pub vis: syn::Visibility,
    /// Span of the declaration (root: file start).
    pub decl_span: Span,
    /// Outer attributes of the declaration (docs etc.).
    pub decl_attrs: Vec<syn::Attribute>,
    /// Inner attributes of the file (`#![..]`, `//!`).
    pub inner_attrs: Vec<syn::Attribute>,
    pub items: Vec<LoadedItem>,
    pub cfg: Option<String>,
    /// Vector files of `#[examples(file = "..")]` attributes of this
    /// module's items, by the path as written.
    pub data_files: HashMap<String, FileId>,
    /// Declared `#[lift]` (existing Rust lifted as-is, [`crate::lift`]), or
    /// a lift prelude module: its items are the lift's output, never printed
    /// (the build emits the source file itself).
    pub lifted: bool,
}

/// The loaded module tree; `modules[0]` is the root.
pub struct Loaded {
    pub modules: Vec<LoadedModule>,
    /// The `#[lift]` modules, in declaration order (module-mode emission).
    pub lifted: Vec<crate::lift::LiftedInfo>,
    /// What the lift assumed and left out ([`crate::lift::LiftFacts`]).
    pub lift_facts: crate::lift::LiftFacts,
}

/// Loads the module tree rooted at `root` (a path to the DSL root file).
/// Every file read is added to `sm`. Errors are pushed to `diags`; loading
/// continues past errors where possible.
pub fn load(root: &Path, fs: &dyn FileProvider, target: &TargetInfo, sm: &mut SourceMap, diags: &mut Diagnostics) -> Option<Loaded> {
    let mut l = Loader { fs, target, sm, diags, modules: Vec::new(), seen: HashSet::new(), data: HashMap::new(), last_drop: None, lift_sources: Vec::new(), lifted_info: Vec::new(), lift_facts: Default::default() };
    let root_file = l.parse_file(root, Span::DUMMY)?;
    let root_id = root_file.0;
    l.add_module(
        "crate".into(),
        None,
        root_file,
        root.to_path_buf(),
        true,
        false,
        syn::Visibility::Inherited,
        Span { file: root_id, lo: (1, 0), hi: (1, 0) },
        vec![],
        None,
    );
    l.finish_lift();
    let loaded = Loaded { modules: l.modules, lifted: l.lifted_info, lift_facts: l.lift_facts };
    check_identifiers(&loaded, l.diags);
    Some(loaded)
}

/// Keywords reserved by some Rust edition that `syn` accepts as
/// identifiers: `gen` (Rust 2024). The generated code is compiled in the
/// including crate's edition, so it cannot use them as names.
const RESERVED_IDENTS: &[&str] = &["gen"];

/// Every identifier of the source compares as rustc compares it: rustc
/// reads the raw identifier `r#x` as the identifier `x` and NFC-normalizes
/// identifiers (`y\u{e9}` and `ye\u{301}` are one identifier), while the
/// resolver, the type checker, the printer's name allocator and the round
/// trip key names by their spelling. So the DSL's identifiers are plain
/// ASCII identifiers — never raw, never outside ASCII (every ASCII string is
/// its own NFC form) and never a keyword of some edition (`gen`) — and name
/// equality is spelling equality everywhere (red team: an NFD `pub use`
/// renamed like an NFC local, and a raw variant `r#A` next to an associated
/// function `A`, were different names to the checker and one name to
/// rustc). Checked on the token streams of every loaded item (attributes,
/// `proof!` blocks and contracts included) and every inner attribute.
fn check_identifiers(loaded: &Loaded, diags: &mut Diagnostics) {
    fn walk(ts: proc_macro2::TokenStream, file: FileId, seen: &mut HashSet<String>, diags: &mut Diagnostics) {
        for tt in ts {
            match tt {
                proc_macro2::TokenTree::Group(g) => walk(g.stream(), file, seen, diags),
                proc_macro2::TokenTree::Ident(id) => {
                    let s = id.to_string();
                    let why = if let Some(bare) = s.strip_prefix("r#") {
                        Some((format!("raw identifier `{s}`"), format!("rustc reads `{s}` as the identifier `{bare}`, which the checker would treat as a different name; sandblaster identifiers are never raw (rename it)")))
                    } else if !s.is_ascii() {
                        Some((format!("non-ASCII identifier `{s}`"), "rustc NFC-normalizes identifiers, so differently encoded spellings of it would be one name to rustc and different names to the checker; sandblaster identifiers are ASCII (rename it)".to_string()))
                    } else if RESERVED_IDENTS.contains(&s.as_str()) {
                        Some((format!("`{s}` is a reserved keyword (Rust 2024)"), "the generated code cannot use it as an identifier (rename it)".to_string()))
                    } else {
                        None
                    };
                    if let Some((msg, note)) = why
                        && seen.insert(s)
                    {
                        diags.push(Diagnostic::error(DiagKind::Unsupported, Span::from_pm2(file, id.span()), msg).note(note));
                    }
                }
                _ => {}
            }
        }
    }
    for m in &loaded.modules {
        let mut seen = HashSet::new();
        for a in &m.inner_attrs {
            walk(a.to_token_stream(), m.file, &mut seen, diags);
        }
        for it in &m.items {
            walk(it.item.to_token_stream(), m.file, &mut seen, diags);
        }
    }
}

struct Loader<'a> {
    fs: &'a dyn FileProvider,
    target: &'a TargetInfo,
    sm: &'a mut SourceMap,
    diags: &'a mut Diagnostics,
    modules: Vec<LoadedModule>,
    seen: HashSet<PathBuf>,
    /// Vector files read so far (normalized path → file).
    data: HashMap<PathBuf, FileId>,
    /// Why [`Loader::eval_cfgs`] last dropped an item: the predicate that
    /// is false on this target, and whether it is false on every target
    /// (no target predicate in it, like `any()`).
    last_drop: Option<(String, bool)>,
    /// `#[lift]` modules, lifted after the whole tree is loaded.
    lift_sources: Vec<crate::lift::LiftSource>,
    lifted_info: Vec<crate::lift::LiftedInfo>,
    lift_facts: crate::lift::LiftFacts,
}

/// Whether an attribute path names the `examples` annotation.
fn is_examples_path(p: &syn::Path) -> bool {
    let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
    match segs.as_slice() {
        [n] => n == "examples",
        [r, n] => r == "sandblaster" && n == "examples",
        [r, m, n] => r == "sandblaster" && (m == "prelude" || m == "ghost") && n == "examples",
        _ => false,
    }
}

/// The `file = ".."` literal of an `#[examples(..)]` attribute.
fn examples_file(a: &syn::Attribute) -> Option<syn::LitStr> {
    if !is_examples_path(a.path()) {
        return None;
    }
    let args = a.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).ok()?;
    args.iter().find_map(|m| match m {
        syn::Meta::NameValue(nv) if nv.path.is_ident("file") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    })
}

impl Loader<'_> {
    /// Reads the vector files named by `#[examples(file = "..")]` on the
    /// functions of `item` (relative to `base`, the declaring file's
    /// directory) into `out`.
    fn data_files(&mut self, file: FileId, base: &Path, item: &syn::Item, out: &mut HashMap<String, FileId>) {
        let attrs: Vec<&syn::Attribute> = match item {
            syn::Item::Fn(f) => f.attrs.iter().collect(),
            syn::Item::Impl(im) => im
                .items
                .iter()
                .flat_map(|ii| match ii {
                    syn::ImplItem::Fn(f) => f.attrs.iter().collect::<Vec<_>>(),
                    _ => vec![],
                })
                .collect(),
            _ => vec![],
        };
        for a in attrs {
            let Some(lit) = examples_file(a) else { continue };
            let rel = lit.value();
            if out.contains_key(&rel) {
                continue;
            }
            let full = base.join(&rel);
            let norm = normalize(&full);
            if let Some(id) = self.data.get(&norm) {
                out.insert(rel, *id);
                continue;
            }
            match self.fs.read(&full) {
                Ok(text) => {
                    let id = self.sm.add(full.clone(), text);
                    self.data.insert(norm, id);
                    out.insert(rel, id);
                }
                Err(e) => {
                    self.diags.push(
                        Diagnostic::error(DiagKind::Load, Span::from_pm2(file, lit.span()), format!("cannot read vector file `{}`: {e}", full.display()))
                            .note("`#[examples(file = \"..\")]` paths are relative to the directory of the file that declares them (DESIGN.md §15.7)"),
                    );
                }
            }
        }
    }

    /// Lifts the `#[lift]` modules ([`crate::lift`]) and, when there are any,
    /// adds the lift prelude modules `crate::__lift` (exec: `Result`) and
    /// `crate::__lift_model` (ghost spec: the buffer model).
    fn finish_lift(&mut self) {
        if self.lift_sources.is_empty() {
            return;
        }
        let sources = std::mem::take(&mut self.lift_sources);
        let lifted_names: Vec<String> = sources.iter().map(|s| s.name.clone()).collect();
        // lifted children (`children = ".."`): their `mod` declarations are
        // re-attached to the lifted parent below
        let child_decls: Vec<(usize, Vec<(String, usize)>)> = sources.iter().filter(|s| !s.children.is_empty()).map(|s| (s.module_index, s.children.clone())).collect();
        let (results, fams, facts) = crate::lift::lift(sources, self.diags);
        self.lift_facts = facts;
        // `use` items of non-lifted modules that name a lifted module's generic family
        for mi in 0..self.modules.len() {
            if self.modules[mi].lifted {
                continue;
            }
            for it in self.modules[mi].items.iter_mut() {
                if let syn::Item::Use(u) = &mut it.item {
                    let mentions = u.to_token_stream().to_string();
                    if lifted_names.iter().any(|n| mentions.contains(n.as_str())) {
                        crate::lift::expand_use_families(&mut u.tree, &fams);
                    }
                }
            }
        }
        let dump = std::env::var("SANDBLASTER_LIFT_DUMP").ok();
        for r in results {
            if let Some(d) = &dump {
                let name = &self.modules[r.module_index].name;
                let text: String = r.items.iter().map(|i| quote::ToTokens::to_token_stream(i).to_string() + "\n").collect();
                let _ = std::fs::create_dir_all(d);
                let _ = std::fs::write(Path::new(d).join(format!("{name}.rs")), text);
            }
            let ghost = self.modules[r.module_index].ghost;
            self.modules[r.module_index].items = r.items.into_iter().map(|item| LoadedItem { item, ghost, cfg: None, child: None }).collect();
        }
        for (mi, children) in child_decls {
            let ghost = self.modules[mi].ghost;
            for (name, c) in children {
                let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
                // a private child of the host's file is crate-visible in the
                // model, as the lift makes its private methods (rustc
                // enforces the host's privacy; laws and proofs may name it)
                let vis = match &self.modules[c].vis {
                    syn::Visibility::Inherited => syn::parse_quote!(pub(crate)),
                    v => v.clone(),
                };
                let item: syn::ItemMod = syn::parse_quote!(#vis mod #ident;);
                self.modules[mi].items.push(LoadedItem { item: syn::Item::Mod(item), ghost, cfg: None, child: Some(c) });
            }
        }
        for (name, text, ghost, spec) in [("__lift", crate::lift::PRELUDE_EXEC, false, false), ("__lift_model", crate::lift::PRELUDE_MODEL, true, true)] {
            let path = PathBuf::from(format!("<sandblaster lift prelude>/{name}.rs"));
            let fid = self.sm.add(path, text.to_string());
            let ast = match syn::parse_file(text) {
                Ok(a) => a,
                Err(e) => {
                    self.diags.error(DiagKind::Parse, Span::DUMMY, format!("lift prelude `{name}`: {e}"));
                    continue;
                }
            };
            let c = self.modules.len();
            let decl_attrs: Vec<syn::Attribute> = if spec { vec![syn::parse_quote!(#[spec])] } else { vec![] };
            let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
            let mut item: syn::ItemMod = syn::parse_quote!(mod #ident;);
            item.attrs = decl_attrs.clone();
            if ghost {
                item.attrs.insert(0, syn::parse_quote!(#[cfg(sandblaster)]));
            }
            let items: Vec<LoadedItem> = ast.items.iter().map(|i| LoadedItem { item: i.clone(), ghost, cfg: None, child: None }).collect();
            self.modules.push(LoadedModule { name: name.to_string(), parent: Some(0), file: fid, ghost, vis: syn::Visibility::Inherited, decl_span: Span { file: fid, lo: (1, 0), hi: (1, 0) }, decl_attrs, inner_attrs: ast.attrs.clone(), items, cfg: None, data_files: HashMap::new(), lifted: true });
            self.modules[0].items.push(LoadedItem { item: syn::Item::Mod(item), ghost, cfg: None, child: Some(c) });
        }
    }

    fn parse_file(&mut self, path: &Path, decl: Span) -> Option<(FileId, syn::File)> {
        let norm = normalize(path);
        if !self.seen.insert(norm.clone()) {
            self.diags.error(DiagKind::Load, decl, format!("file `{}` is loaded as a module twice", path.display()));
            return None;
        }
        let text = match self.fs.read(path) {
            Ok(t) => t,
            Err(e) => {
                self.diags.error(DiagKind::Load, decl, format!("cannot read `{}`: {e}", path.display()));
                return None;
            }
        };
        let id = self.sm.add(path.to_path_buf(), text.clone());
        match syn::parse_file(&text) {
            Ok(f) => Some((id, f)),
            Err(e) => {
                self.diags.push(Diagnostic::error(DiagKind::Parse, Span::from_pm2(id, e.span()), format!("parse error: {e}")));
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_module(
        &mut self,
        name: String,
        parent: Option<usize>,
        (file, ast): (FileId, syn::File),
        path: PathBuf,
        mod_rs_like: bool,
        ghost: bool,
        vis: syn::Visibility,
        decl_span: Span,
        decl_attrs: Vec<syn::Attribute>,
        cfg: Option<String>,
    ) -> usize {
        let idx = self.modules.len();
        self.modules.push(LoadedModule { name, parent, file, ghost, vis, decl_span, decl_attrs, inner_attrs: ast.attrs.clone(), items: vec![], cfg, data_files: HashMap::new(), lifted: false });
        let dir = if mod_rs_like {
            path.parent().map(Path::to_path_buf).unwrap_or_default()
        } else {
            let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            path.parent().map(|p| p.join(&stem)).unwrap_or_else(|| PathBuf::from(stem))
        };
        let mut items = Vec::new();
        let mut data_files = HashMap::new();
        let file_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        for item in ast.items {
            let span = Span::from_pm2(file, item.span());
            let attrs = item_attrs(&item);
            let Some((item_ghost, cfg)) = self.eval_cfgs(file, attrs) else {
                if let Some((pred, constant)) = self.last_drop.take() {
                    self.dropped_ghost_item(&item, ghost, &pred, constant, span, &dir, &path);
                }
                continue;
            };
            let ghost_item = ghost || item_ghost;
            self.data_files(file, &file_dir, &item, &mut data_files);
            let mut child = None;
            if let syn::Item::Mod(m) = &item {
                if m.content.is_some() {
                    self.diags.error(DiagKind::Unsupported, span, "inline modules are not supported; declare `mod name;` with a file");
                    continue;
                }
                let path_attr = m.attrs.iter().find(|a| a.path().is_ident("path"));
                // `#[lift(in_place)]`: the lifted source is the host's own file,
                // named by `#[path]` (it is verified where rustc compiles it)
                let in_place_decl = m.attrs.iter().filter(|a| a.path().is_ident("lift")).any(|a| crate::lift::open::parse_lift_opts(a).is_ok_and(|o| o.in_place));
                let child_path = if let Some(pa) = path_attr {
                    if !item_ghost && !ghost && !in_place_decl {
                        self.diags.push(
                            Diagnostic::error(DiagKind::Load, Span::from_pm2(file, pa.span()), "`#[path]` is only allowed on `#[cfg(sandblaster)]` (ghost) modules")
                                .note("exec modules must follow the standard `name.rs` / `name/mod.rs` layout (DESIGN.md §2)"),
                        );
                    }
                    let lit = match &pa.meta {
                        syn::Meta::NameValue(nv) => match &nv.value {
                            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
                            _ => None,
                        },
                        _ => None,
                    };
                    let Some(rel) = lit else {
                        self.diags.error(DiagKind::Load, span, "malformed `#[path = \"..\"]` attribute");
                        continue;
                    };
                    let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
                    Some((base.join(rel), true))
                } else {
                    let name = m.ident.to_string();
                    let a = dir.join(format!("{name}.rs"));
                    let b = dir.join(&name).join("mod.rs");
                    match (self.fs.exists(&a), self.fs.exists(&b)) {
                        (true, true) => {
                            self.diags.error(DiagKind::Load, span, format!("file for module `{name}` found at both `{}` and `{}`", a.display(), b.display()));
                            None
                        }
                        (true, false) => Some((a, false)),
                        (false, true) => Some((b, true)),
                        (false, false) => {
                            self.diags.push(Diagnostic::error(DiagKind::Load, span, format!("file not found for module `{name}`")).note(format!("expected `{}` or `{}`", a.display(), b.display())));
                            None
                        }
                    }
                };
                let Some((child_path, child_mod_rs)) = child_path else { continue };
                let Some(parsed) = self.parse_file(&child_path, span) else { continue };
                let child_mod_rs = child_mod_rs || child_path.file_name().is_some_and(|f| f == "mod.rs");
                let is_lift = m.attrs.iter().any(|a| a.path().is_ident("lift"));
                // `#[lift(unverified = "u128, i16")]`, `#[lift(host)]`, `#[lift(in_place, ..)]`
                // (`crate::lift::open::LiftOpts`)
                let mut opts = crate::lift::open::LiftOpts::default();
                for a in m.attrs.iter().filter(|a| a.path().is_ident("lift")) {
                    match crate::lift::open::parse_lift_opts(a) {
                        Ok(o) => opts.merge(o),
                        Err(e) => self.diags.error(DiagKind::Load, Span::from_pm2(file, a.span()), e),
                    }
                }
                let decl_attrs: Vec<syn::Attribute> = m.attrs.iter().filter(|a| !a.path().is_ident("lift")).cloned().collect();
                if is_lift {
                    // existing Rust, lifted once the whole tree is loaded (attachments may come later)
                    let c = self.add_lifted(m.ident.to_string(), idx, parsed, child_path.clone(), child_mod_rs, ghost_item, m.vis.clone(), span, decl_attrs, cfg.clone(), opts);
                    let mut item = item.clone();
                    if let syn::Item::Mod(mm) = &mut item {
                        mm.attrs.retain(|a| !a.path().is_ident("lift"));
                    }
                    items.push(LoadedItem { item, ghost: ghost_item, cfg, child: Some(c) });
                    continue;
                }
                let c = self.add_module(m.ident.to_string(), Some(idx), parsed, child_path, child_mod_rs, ghost_item, m.vis.clone(), span, decl_attrs, cfg.clone());
                child = Some(c);
            }
            items.push(LoadedItem { item, ghost: ghost_item, cfg, child });
        }
        self.modules[idx].items = items;
        self.modules[idx].data_files = data_files;
        idx
    }

    /// Registers a `#[lift]` module (lifted once the whole tree is loaded)
    /// and returns its index. An out-of-line `mod x;` of its source whose
    /// name the declaration lists in `children = ".."` is lifted too, from
    /// the standard location next to the source (`x.rs` or `x/mod.rs`,
    /// as rustc finds it), with the same options: the child's `mod`
    /// declaration is re-attached to the lifted parent in
    /// [`Loader::finish_lift`]. Every other out-of-line module of a lifted
    /// source is a host module the lift leaves out (listed).
    #[allow(clippy::too_many_arguments)]
    fn add_lifted(
        &mut self,
        name: String,
        parent: usize,
        (cfile, cast): (FileId, syn::File),
        path: PathBuf,
        mod_rs_like: bool,
        ghost: bool,
        vis: syn::Visibility,
        span: Span,
        decl_attrs: Vec<syn::Attribute>,
        cfg: Option<String>,
        opts: crate::lift::open::LiftOpts,
    ) -> usize {
        let c = self.modules.len();
        self.modules.push(LoadedModule { name: name.clone(), parent: Some(parent), file: cfile, ghost, vis, decl_span: span, decl_attrs, inner_attrs: cast.attrs.clone(), items: vec![], cfg: cfg.clone(), data_files: HashMap::new(), lifted: true });
        self.lifted_info.push(crate::lift::LiftedInfo { name: name.clone(), file: cfile, ghost, host: opts.host, unverified: opts.unverified.clone(), in_place: opts.in_place, mir: None });
        let info_index = self.lifted_info.len() - 1;
        // the children to lift with this module, where the host's rustc finds
        // them: an in-place source is the host's own file, which the host
        // declares with a plain `mod` (its `#[path]` is the DSL root's), so
        // its children are next to a `mod.rs`/`lib.rs` and in `<stem>/`
        // beside any other file
        let mod_rs_like = if opts.in_place { path.file_name().is_some_and(|f| f == "mod.rs" || f == "lib.rs") } else { mod_rs_like };
        let dir = if mod_rs_like {
            path.parent().map(Path::to_path_buf).unwrap_or_default()
        } else {
            let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            path.parent().map(|p| p.join(&stem)).unwrap_or_else(|| PathBuf::from(stem))
        };
        let mut children: Vec<(String, usize)> = Vec::new();
        for want in &opts.children {
            let at = cast.items.iter().position(|it| matches!(it, syn::Item::Mod(m) if m.ident == want.as_str()));
            if let Some(i) = at
                && let syn::Item::Mod(m) = &cast.items[i]
                && m.content.is_some()
            {
                self.diags.error(DiagKind::Load, span, format!("the lifted child module `{want}` is declared inline: a lifted child is `mod {want};`"));
                continue;
            }
            let decl = at.and_then(|i| match &cast.items[i] {
                syn::Item::Mod(m) if m.content.is_none() => Some(m.clone()),
                _ => None,
            });
            let Some(m) = decl else {
                self.diags.error(DiagKind::Load, span, format!("`children = \"..\"` names `{want}`, but the lifted source declares no `mod {want};`"));
                continue;
            };
            if m.attrs.iter().any(|a| a.path().is_ident("path")) {
                self.diags.error(DiagKind::Load, span, format!("the lifted child module `{want}` has a `#[path]` attribute in its host source; only the standard layout is supported"));
                continue;
            }
            let a = dir.join(format!("{want}.rs"));
            let b = dir.join(want).join("mod.rs");
            let found = match (self.fs.exists(&a), self.fs.exists(&b)) {
                (true, false) => Some((a.clone(), false)),
                (false, true) => Some((b.clone(), true)),
                _ => None,
            };
            let Some((cpath, cmodrs)) = found else {
                self.diags.error(DiagKind::Load, span, format!("the lifted child module `{want}`: expected exactly one of `{}` and `{}`", a.display(), b.display()));
                continue;
            };
            let Some(parsed) = self.parse_file(&cpath, span) else { continue };
            let mut copts = opts.clone();
            copts.children = vec![];
            // a child reads the same MIR file (found next to the declaration)
            let decl_dir = self.sm.path(self.modules[parent].file).parent().map(Path::to_path_buf).unwrap_or_default();
            for (rel, to) in [(&opts.mir, &mut copts.mir), (&opts.window_mir, &mut copts.window_mir)] {
                if let Some(rel) = rel {
                    let full = decl_dir.join(rel);
                    *to = Some(std::path::absolute(&full).unwrap_or(full).display().to_string());
                }
            }
            let cvis = m.vis.clone();
            let cc = self.add_lifted(want.clone(), c, parsed, cpath, cmodrs, ghost, cvis, span, vec![], cfg.clone(), copts);
            children.push((want.clone(), cc));
        }
        // the module's DSL path (`crate::merkle::mmr`)
        let mut segs = Vec::new();
        let mut at = Some(c);
        while let Some(i) = at {
            segs.push(self.modules[i].name.clone());
            at = self.modules[i].parent;
        }
        segs.reverse();
        let module_path = segs.join("::");
        // `mir = "x.sbmir"`: rustc's MIR of the bodies, next to the declaring file
        let mir = opts.mir.as_ref().and_then(|rel| {
            let decl_dir = self.sm.path(self.modules[parent].file).parent().map(Path::to_path_buf).unwrap_or_default();
            let full = decl_dir.join(rel);
            match self.fs.read(&full) {
                Ok(t) => {
                    self.sm.add(full.clone(), t.clone());
                    self.lifted_info[info_index].mir = Some(full.clone());
                    Some(t)
                }
                Err(e) => {
                    self.diags.error(DiagKind::Load, span, format!("cannot read the MIR file `{}` (`mir = \"{rel}\"`): {e}", full.display()));
                    None
                }
            }
        });
        // `window_mir = "x.window.sbmir"`: the same MIR unoptimized, for the
        // window analysis only, next to the declaring file
        let window_mir = opts.window_mir.as_ref().and_then(|rel| {
            let decl_dir = self.sm.path(self.modules[parent].file).parent().map(Path::to_path_buf).unwrap_or_default();
            let full = decl_dir.join(rel);
            match self.fs.read(&full) {
                Ok(t) => {
                    self.sm.add(full.clone(), t.clone());
                    Some(t)
                }
                Err(e) => {
                    self.diags.error(DiagKind::Load, span, format!("cannot read the window MIR file `{}` (`window_mir = \"{rel}\"`): {e}", full.display()));
                    None
                }
            }
        });
        let path_display = self.sm.path(cfile).display().to_string();
        let text = self.sm.get(cfile).map(|f| f.text.clone()).unwrap_or_default();
        let mir_extra = mir.as_deref().map(|t| self.mir_extra_sources(t, &path_display)).unwrap_or_default();
        let target_arch = self.target.arch.name().to_string();
        let target_features: Vec<String> = self.target.features.iter().cloned().collect();
        let codegen_flags = self.target.codegen_flags.clone();
        self.lift_sources.push(crate::lift::LiftSource { module_index: c, file: cfile, ast: cast, ghost, name, unverified: opts.unverified.clone(), decl_span: span, host: opts.host, opts, children, module_path, mir, window_mir, path_display, text, mir_extra, target_arch, target_features, codegen_flags });
        c
    }

    /// The other files of the host crate that a lifted file's `.sbmir`
    /// names (functions of modules not lifted, which the extraction followed
    /// as callees: the reading takes them as library code), with their
    /// texts: the files beside the lifted one, as its own `(source ..)` line
    /// places the crate's root. The load checks each against its SHA-256
    /// like a lifted file (`mir::load`); one not found stays unknown there.
    fn mir_extra_sources(&mut self, mir: &str, me: &str) -> Vec<(String, Vec<u8>)> {
        let srcs: Vec<&str> = mir.lines().filter_map(|l| l.strip_prefix("(source \"")).filter_map(|r| r.split('"').next()).collect();
        let Some(own) = srcs.iter().find(|p| me.ends_with(&format!("/{p}")) || me == **p) else { return vec![] };
        let base = &me[..me.len() - own.len()];
        srcs.iter().filter(|p| **p != *own).filter_map(|p| self.fs.read(Path::new(&format!("{base}{p}"))).ok().map(|t| (format!("{base}{p}"), t.into_bytes()))).collect()
    }

    /// A ghost item that a target predicate configured out (`pred`; with
    /// `constant`, false on every target). Proof code must not disappear
    /// silently (red team: a false law under `#[cfg(any())]` was never
    /// checked on any target):
    ///
    /// * a `#[law]` is an error: a law is a claim of the crate, checked on
    ///   every target the crate builds for;
    /// * a `#[lemma]` or `#[proof]` is a warning naming it (target-specific
    ///   proofs, e.g. of SIMD code, are legitimate);
    /// * a ghost module is a warning, and an error if its file declares a
    ///   law;
    /// * a predicate false on every target (`any()`, `not(all())`) on any
    ///   ghost item is an error.
    #[allow(clippy::too_many_arguments)]
    fn dropped_ghost_item(&mut self, item: &syn::Item, ghost: bool, pred: &str, constant: bool, span: Span, dir: &Path, path: &Path) {
        let attrs = item_attrs(item);
        let ghost = ghost || attrs.iter().any(|a| a.path().is_ident("cfg") && a.parse_args::<syn::Meta>().is_ok_and(|m| matches!(&m, syn::Meta::Path(p) if p.is_ident("sandblaster"))));
        if !ghost {
            return;
        }
        let annot = |attrs: &[syn::Attribute]| -> Option<&'static str> {
            attrs.iter().find_map(|a| match a.path().segments.last().map(|s| s.ident.to_string()).as_deref() {
                Some("law") => Some("law"),
                Some("lemma") => Some("lemma"),
                Some("proof") => Some("proof"),
                _ => None,
            })
        };
        // (the predicate as written: token spacing removed around parentheses)
        let cfg = format!("#[cfg({})]", pred.replace(" (", "(").replace("( ", "(").replace(" )", ")"));
        if constant {
            let what = match item {
                syn::Item::Fn(f) => format!("`{}`", f.sig.ident),
                syn::Item::Mod(m) => format!("module `{}`", m.ident),
                _ => "this ghost item".into(),
            };
            self.diags.push(Diagnostic::error(DiagKind::Attribute, span, format!("{what} is under `{cfg}`, which is false on every target: it would never be checked")).note("remove the item, or the `cfg`"));
            return;
        }
        match item {
            syn::Item::Fn(f) => match annot(&f.attrs) {
                Some("law") => self.diags.push(
                    Diagnostic::error(DiagKind::Law, span, format!("law `{}` is removed by `{cfg}` on target `{}`: it would not be checked by this build", f.sig.ident, self.target.arch.name()))
                        .note("a law is a claim of the crate and is checked on every target: state it without a target `cfg` (a target-specific fact belongs in a `#[lemma]`)"),
                ),
                Some(k) => self.diags.push(Diagnostic::warning(DiagKind::Attribute, span, format!("`#[{k}] {}` is removed by `{cfg}` on target `{}`: it is not checked by this build", f.sig.ident, self.target.arch.name()))),
                None => {}
            },
            syn::Item::Mod(m) if m.content.is_none() => {
                // the module's file, if it can be found: a law in it is an
                // error, like a law removed by its own `cfg`
                let file = match m.attrs.iter().find(|a| a.path().is_ident("path")).map(|a| &a.meta) {
                    Some(syn::Meta::NameValue(syn::MetaNameValue { value: syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(l), .. }), .. })) => Some(path.parent().map(Path::to_path_buf).unwrap_or_default().join(l.value())),
                    Some(_) => None,
                    None => {
                        let a = dir.join(format!("{}.rs", m.ident));
                        let b = dir.join(m.ident.to_string()).join("mod.rs");
                        if self.fs.exists(&a) { Some(a) } else if self.fs.exists(&b) { Some(b) } else { None }
                    }
                };
                let laws: Vec<String> = file
                    .and_then(|p| self.fs.read(&p).ok())
                    .and_then(|t| syn::parse_file(&t).ok())
                    .map(|f| f.items.iter().filter_map(|i| if let syn::Item::Fn(g) = i { (annot(&g.attrs) == Some("law")).then(|| g.sig.ident.to_string()) } else { None }).collect())
                    .unwrap_or_default();
                if laws.is_empty() {
                    self.diags.push(Diagnostic::warning(DiagKind::Attribute, span, format!("ghost module `{}` is removed by `{cfg}` on target `{}`: nothing in it is checked by this build", m.ident, self.target.arch.name())));
                } else {
                    self.diags.push(
                        Diagnostic::error(DiagKind::Law, span, format!("ghost module `{}` is removed by `{cfg}` on target `{}`, and it declares laws ({}): they would not be checked by this build", m.ident, self.target.arch.name(), laws.join(", ")))
                            .note("laws are claims of the crate and are checked on every target: declare them outside target-gated modules"),
                    );
                }
            }
            _ => {}
        }
    }

    /// Whether a (syntactically valid) predicate is false on every target:
    /// `any()`, and combinations without a target predicate
    /// (`not(all())`, `all(any())`). `None` if it depends on the target.
    fn constant_pred(m: &syn::Meta) -> Option<bool> {
        match m {
            syn::Meta::List(l) => {
                let args = l.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).ok()?;
                let vals: Vec<Option<bool>> = args.iter().map(Self::constant_pred).collect();
                match l.path.to_token_stream().to_string().as_str() {
                    // a known false conjunct / true disjunct decides
                    "all" if vals.contains(&Some(false)) => Some(false),
                    "all" => vals.iter().all(Option::is_some).then_some(true),
                    "any" if vals.contains(&Some(true)) => Some(true),
                    "any" => vals.iter().all(Option::is_some).then_some(false),
                    "not" if vals.len() == 1 => vals[0].map(|v| !v),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Evaluates the `cfg` attributes of an item. Returns `None` if the item
    /// is configured out (with the false predicate in `last_drop` when it
    /// is a target predicate), else `(ghost, target_cfg_text)`.
    fn eval_cfgs(&mut self, file: FileId, attrs: &[syn::Attribute]) -> Option<(bool, Option<String>)> {
        let mut ghost = false;
        let mut texts = Vec::new();
        let mut keep = true;
        let mut dropped: Option<(String, bool)> = None;
        let mut errored = false;
        for a in attrs {
            if a.path().is_ident("cfg_attr") {
                if crate::resolve::is_critical_attr(a) {
                    self.diags.push(crate::resolve::critical_diagnostic(Span::from_pm2(file, a.span())));
                } else {
                    self.diags.error(DiagKind::Attribute, Span::from_pm2(file, a.span()), "`#[cfg_attr]` is not supported");
                }
                continue;
            }
            if !a.path().is_ident("cfg") {
                continue;
            }
            let span = Span::from_pm2(file, a.span());
            let pred: syn::Meta = match a.parse_args() {
                Ok(m) => m,
                Err(e) => {
                    self.diags.error(DiagKind::Attribute, span, format!("malformed cfg: {e}"));
                    continue;
                }
            };
            if matches!(&pred, syn::Meta::Path(p) if p.is_ident("sandblaster")) {
                ghost = true;
                continue;
            }
            match self.eval_pred(&pred, span) {
                Some(v) => {
                    keep &= v;
                    let text = pred.to_token_stream().to_string();
                    if !v && dropped.is_none() {
                        dropped = Some((text.clone(), Self::constant_pred(&pred) == Some(false)));
                    }
                    texts.push(text);
                }
                None => {
                    keep = false;
                    errored = true;
                }
            }
        }
        if !keep {
            // an erroneous predicate is reported already
            self.last_drop = if errored { None } else { dropped };
            return None;
        }
        let cfg = match texts.len() {
            0 => None,
            1 => Some(texts.pop().unwrap()),
            _ => Some(format!("all({})", texts.join(", "))),
        };
        Some((ghost, cfg))
    }

    /// Evaluates a target predicate; `None` after reporting an error.
    fn eval_pred(&mut self, m: &syn::Meta, span: Span) -> Option<bool> {
        match m {
            syn::Meta::Path(p) => {
                let name = p.to_token_stream().to_string();
                if name == "sandblaster" {
                    self.diags.error(DiagKind::Attribute, span, "`sandblaster` may only appear as the whole predicate `#[cfg(sandblaster)]`");
                } else {
                    self.diags.error(DiagKind::Attribute, span, format!("unsupported cfg predicate `{name}` (only target predicates and `sandblaster` are allowed)"));
                }
                None
            }
            syn::Meta::NameValue(nv) => {
                let key = nv.path.to_token_stream().to_string();
                let val = match &nv.value {
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => s.value(),
                    _ => {
                        self.diags.error(DiagKind::Attribute, span, "cfg values must be string literals");
                        return None;
                    }
                };
                let t = self.target;
                Some(match key.as_str() {
                    "target_arch" => t.arch.name() == val,
                    "target_endian" => (val == "little") == t.little_endian && (val == "little" || val == "big"),
                    "target_pointer_width" => t.pointer_width.to_string() == val,
                    "target_feature" => t.features.contains(&val),
                    _ => {
                        self.diags.error(DiagKind::Attribute, span, format!("unsupported cfg key `{key}` (allowed: target_arch, target_endian, target_pointer_width, target_feature)"));
                        return None;
                    }
                })
            }
            syn::Meta::List(l) => {
                let name = l.path.to_token_stream().to_string();
                let args = match l.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated) {
                    Ok(a) => a,
                    Err(e) => {
                        self.diags.error(DiagKind::Attribute, span, format!("malformed cfg: {e}"));
                        return None;
                    }
                };
                let mut vals = Vec::new();
                for a in &args {
                    vals.push(self.eval_pred(a, span)?);
                }
                match name.as_str() {
                    "all" => Some(vals.iter().all(|v| *v)),
                    "any" => Some(vals.iter().any(|v| *v)),
                    "not" if vals.len() == 1 => Some(!vals[0]),
                    _ => {
                        self.diags.error(DiagKind::Attribute, span, format!("unsupported cfg combinator `{name}`"));
                        None
                    }
                }
            }
        }
    }
}

/// Outer attributes of an item.
pub fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_tree_and_ghost_modules() {
        let fs = MemFs::from_files([
            ("r/mod.rs", "#![forbid(unsafe_code)]\nmod a;\npub mod b;\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n#[cfg(target_arch = \"x86_64\")] fn only_x86() {}\n"),
            ("r/a.rs", "mod c;\nfn f() {}\n"),
            ("r/a/c.rs", "fn g() {}\n"),
            ("r/b/mod.rs", "fn h() {}\n"),
            ("r/LAWS.rs", "fn law() {}\n"),
        ]);
        let mut sm = SourceMap::new();
        let mut d = Diagnostics::new();
        let l = load(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin(), &mut sm, &mut d).unwrap();
        assert!(!d.has_errors(), "{}", d.render(&sm));
        let names: Vec<_> = l.modules.iter().map(|m| (m.name.as_str(), m.ghost)).collect();
        assert_eq!(names, vec![("crate", false), ("a", false), ("c", false), ("b", false), ("laws", true)]);
        // the x86-only item is configured out on aarch64
        assert_eq!(l.modules[0].items.len(), 3);
    }

    #[test]
    fn path_only_on_ghost_modules() {
        let fs = MemFs::from_files([("r/mod.rs", "#[path = \"x.rs\"] mod m;\n"), ("r/x.rs", "")]);
        let mut sm = SourceMap::new();
        let mut d = Diagnostics::new();
        load(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin(), &mut sm, &mut d);
        assert!(d.list.iter().any(|x| x.kind == DiagKind::Load && x.msg.contains("#[path]")));
    }
}
